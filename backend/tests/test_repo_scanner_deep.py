import os
import subprocess

from app.engine.repo_scanner import (
    _scan_tree, _ci_docker_checks, _history_secrets, _parse_owner_repo, _dedupe,
    _config_checks, _parse_deps,
)
from app.engine.findings import finding


def write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_extended_secret_patterns(tmp_path):
    # Build fake secrets by concatenation so the literal values never appear in the
    # committed source (which would trip GitHub push protection). At runtime the
    # assembled value is written to a temp file and DOES exercise the scanner.
    stripe = "sk_" + "live_" + "abcdef0123456789ABCDEF01"
    sg = "SG." + "abcdefghij0123456789ab." + "abcdefghij0123456789ABCDEFghij0123456789abc"
    gh = "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
    write(tmp_path, "cfg.py", (
        f'STRIPE = "{stripe}"\n'
        f'SG = "{sg}"\n'
        'DB = "postgres://user:p4ssw0rd@db.host:5432/app"\n'
        f'GH = "{gh}"\n'
    ))
    findings, _ = _scan_tree(str(tmp_path))
    titles = {f["title"] for f in findings}
    assert "Stripe secret key" in titles
    assert "SendGrid API key" in titles
    assert "Database URI with credentials" in titles
    assert "GitHub token" in titles


def test_multi_language_code_rules(tmp_path):
    write(tmp_path, "a.php", "<?php eval($_GET['x']); system($cmd); ?>")
    write(tmp_path, "b.rb", "Marshal.load(data)\neval(x)\n")
    write(tmp_path, "c.java", "Runtime.getRuntime().exec(cmd);\nnew ObjectInputStream(s);")
    write(tmp_path, "d.go", "cfg := &tls.Config{InsecureSkipVerify: true}")
    findings, _ = _scan_tree(str(tmp_path))
    ids = {f["id"] for f in findings}
    assert "code-php-eval" in ids
    assert "code-rb-marshal" in ids
    assert "code-java-deser" in ids
    assert "code-go-tls-skip" in ids


def test_dockerfile_checks(tmp_path):
    write(tmp_path, "Dockerfile", "FROM python:latest\nENV DB_PASSWORD=hunter2\nADD https://x.sh /x\n")
    out = _ci_docker_checks(str(tmp_path))
    ids = {f["id"] for f in out}
    assert "ci-docker-latest" in ids
    assert "ci-docker-secret-env" in ids
    assert "ci-docker-add-url" in ids


def test_github_workflow_checks(tmp_path):
    write(tmp_path, ".github/workflows/ci.yml",
          "on:\n  pull_request_target:\njobs:\n  a:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n")
    out = _ci_docker_checks(str(tmp_path))
    ids = {f["id"] for f in out}
    assert "ci-gha-pr-target" in ids
    assert "ci-gha-script-injection" in ids


def test_history_secret_scan(tmp_path):
    r = str(tmp_path / "repo")
    os.makedirs(r)
    def git(*a):
        subprocess.run(["git", "-C", r, *a], capture_output=True, text=True)
    subprocess.run(["git", "init", "-q", r], capture_output=True)
    git("config", "user.email", "t@t"); git("config", "user.name", "t")
    aws = "AKIA" + "1234567890ABCDEF"
    (tmp_path / "repo" / "app.py").write_text(f'KEY = "{aws}"\n')
    git("add", "."); git("commit", "-qm", "add")
    (tmp_path / "repo" / "app.py").write_text('KEY = os.environ["KEY"]\n')  # removed from tree
    git("add", "."); git("commit", "-qm", "remove")
    hist = _history_secrets(r)
    assert any("git history" in f["title"] for f in hist)
    assert any(f["severity"] == "critical" for f in hist)


def test_parse_owner_repo():
    assert _parse_owner_repo("https://github.com/foo/bar.git") == ("foo", "bar")
    assert _parse_owner_repo("git@github.com:foo/bar.git") == ("foo", "bar")
    assert _parse_owner_repo("https://gitlab.com/foo/bar") is None


def test_dedupe_removes_exact_duplicates():
    f = finding(id="x", title="t", severity="high", category="c", location="a.py", line=1)
    assert len(_dedupe([f, dict(f), f])) == 1


def test_config_checks_security_and_license(tmp_path):
    write(tmp_path, "readme.md", "hi")
    out = _config_checks(str(tmp_path))
    ids = {f["id"] for f in out}
    assert "cfg-no-security-policy" in ids
    assert "cfg-no-license" in ids


def test_config_checks_pass_when_present(tmp_path):
    write(tmp_path, ".gitignore", "*.env")
    write(tmp_path, "SECURITY.md", "report to x")
    write(tmp_path, "LICENSE", "MIT")
    out = _config_checks(str(tmp_path))
    ids = {f["id"] for f in out}
    assert "cfg-no-security-policy" not in ids
    assert "cfg-no-license" not in ids
    assert "cfg-no-gitignore" not in ids


def test_curl_pipe_sh_detected(tmp_path):
    write(tmp_path, "install.sh", "curl https://get.example.com | sudo bash\n")
    findings, _ = _scan_tree(str(tmp_path))
    assert any(f["id"] == "code-curl-pipe-sh" for f in findings)


# ---- noise-reduction filters (avoid false positives) ----

def test_known_example_aws_key_whitelisted(tmp_path):
    write(tmp_path, "src/app.py", 'AWS = "AKIAIOSFODNN7EXAMPLE"\n')
    findings, _ = _scan_tree(str(tmp_path))
    assert not any(f["title"] == "AWS Access Key ID" for f in findings)


def test_code_pattern_inside_string_literal_skipped(tmp_path):
    # 'eval(' appears only inside a string/title -> not live code, should NOT flag
    write(tmp_path, "rules.py", 'RULE = "Use of eval() is dangerous"\nMSG = "call exec() carefully"\n')
    findings, _ = _scan_tree(str(tmp_path))
    assert not any(f["id"].startswith("code-") for f in findings)


def test_code_pattern_in_test_file_skipped(tmp_path):
    write(tmp_path, "tests/test_thing.py", "eval(user_input)\nos.system(cmd)\n")
    findings, _ = _scan_tree(str(tmp_path))
    assert not any(f["id"].startswith("code-") for f in findings)


def test_real_code_pattern_still_detected(tmp_path):
    write(tmp_path, "src/handler.py", "result = eval(request.data)\n")
    findings, _ = _scan_tree(str(tmp_path))
    assert any(f["id"] == "code-py-eval" for f in findings)
