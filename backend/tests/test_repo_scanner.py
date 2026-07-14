from app.engine.repo_scanner import _scan_tree, _config_checks, _looks_placeholder, _parse_deps


def write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_detects_secrets_and_patterns(tmp_path):
    aws = "AKIA" + "1234567890ABCDEF"  # concatenated so the literal isn't in source
    write(tmp_path, "src/app.py", (
        f'AWS = "{aws}"\n'
        'password = "supersecret123"\n'
        'import os, pickle\n'
        'os.system(cmd)\n'
        'eval(user_input)\n'
        'pickle.loads(data)\n'
    ))
    findings, _ = _scan_tree(str(tmp_path))
    titles = {f["title"] for f in findings}
    assert "AWS Access Key ID" in titles
    assert "Hardcoded credential" in titles
    assert "Use of eval()" in titles
    assert "Shell command via os.system" in titles
    assert "Insecure deserialization (pickle)" in titles


def test_committed_env_is_flagged(tmp_path):
    write(tmp_path, ".env", "DB_PASSWORD=hunter2\n")
    findings, _ = _scan_tree(str(tmp_path))
    assert any(f["id"] == "secret-dotenv" for f in findings)


def test_placeholder_secrets_filtered(tmp_path):
    write(tmp_path, "config.py", 'api_key = "your_key_here"\npassword = "changeme"\n')
    findings, _ = _scan_tree(str(tmp_path))
    assert not any(f["id"] == "secret-generic-secret" for f in findings)


def test_placeholder_helper():
    assert _looks_placeholder('key = "your_api_key"') is True
    assert _looks_placeholder('key = "changeme"') is True
    assert _looks_placeholder('key = "aB9$kL2mQ7xR"') is False


def test_config_checks_missing_gitignore(tmp_path):
    write(tmp_path, "readme.md", "hi")
    out = _config_checks(str(tmp_path))
    assert any(f["id"] == "cfg-no-gitignore" for f in out)


def test_parse_dependencies(tmp_path):
    write(tmp_path, "requirements.txt", "django==2.2.0\nflask>=1.0\nrequests==2.25.1\n")
    deps = _parse_deps(str(tmp_path))
    names = {(e, n, v) for (e, n, v) in deps}
    assert ("PyPI", "django", "2.2.0") in names
    assert ("PyPI", "requests", "2.25.1") in names
    # unpinned (>=) is skipped
    assert not any(n == "flask" for (_, n, _) in deps)
