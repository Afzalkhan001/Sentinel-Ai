"""GitHub repository security scanner (deep).

Clones a public repo (with bounded history) and runs deterministic checks:
  - hardcoded secrets across 20+ providers, in the working tree AND git HISTORY
    (catches secrets committed then "removed" but still recoverable)
  - dangerous code patterns across Python/JS/Go/Ruby/PHP/Java
  - CI/CD & container misconfigs (Dockerfile, GitHub Actions)
  - dependency CVEs via OSV.dev, config hygiene, and GitHub repo-health signals
Noise filters (example-key whitelist, test-file + string-literal skipping) keep
false positives low. Optionally adds an LLM security review.
"""
import asyncio
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

import httpx

from ..db import SessionLocal
from ..models_db import RepoScan
from ..providers.registry import get_provider
from .findings import finding, score_findings

PLACEHOLDER_TOKENS = ("changeme", "your_", "yourkey", "your-key", "xxxxx", "placeholder",
                      "<", "***", "...", "todo", "dummy", "redacted", "n/a", "none",
                      "insert_", "example.com", "foo", "bar")

# Well-known documentation / example secrets that are not real leaks.
KNOWN_EXAMPLE_SECRETS = {
    "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLEX",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

# Path hints that indicate test/fixture code, where dangerous patterns are usually intentional.
TEST_PATH_HINTS = ("/test", "test_", "_test", "/tests/", "/spec/", "__tests__", "fixture", "/mock", "/examples/")

# ---- scan limits ----
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__",
             "vendor", ".next", "target", ".idea", ".vscode", "coverage"}
TEXT_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".rb", ".go", ".php", ".cs",
            ".c", ".cpp", ".h", ".rs", ".sh", ".yaml", ".yml", ".json", ".env", ".txt",
            ".cfg", ".ini", ".toml", ".xml", ".html", ".sql", ".tf", ".properties",
            ".kt", ".scala", ".swift", ".pl", ".ps1", ".bat", ".conf", ".dockerfile"}
EXTRA_NAMES = {".env", "Dockerfile", "dockerfile"}  # scanned regardless of extension
MAX_FILES = 3000
MAX_FILE_BYTES = 400_000

# ---- secret detectors: (id, title, severity, regex) ----
SECRET_RULES = [
    ("aws-access-key", "AWS Access Key ID", "critical", r"AKIA[0-9A-Z]{16}"),
    ("aws-secret", "AWS Secret Access Key", "critical",
     r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}['\"]?"),
    ("private-key", "Private key committed", "critical", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("openai-key", "OpenAI API key", "critical", r"sk-(?:proj-)?[A-Za-z0-9]{20,}"),
    ("anthropic-key", "Anthropic API key", "critical", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ("google-key", "Google API key", "high", r"AIza[0-9A-Za-z_\-]{35}"),
    ("google-oauth", "Google OAuth client ID", "medium", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("github-token", "GitHub token", "critical", r"gh[pousr]_[0-9A-Za-z]{36,}"),
    ("gitlab-token", "GitLab token", "critical", r"glpat-[0-9A-Za-z_\-]{20,}"),
    ("slack-token", "Slack token", "high", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("slack-webhook", "Slack webhook URL", "medium", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"),
    ("stripe-key", "Stripe secret key", "critical", r"[rs]k_live_[0-9A-Za-z]{20,}"),
    ("twilio-key", "Twilio API key", "high", r"SK[0-9a-fA-F]{32}"),
    ("sendgrid-key", "SendGrid API key", "critical", r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
    ("mailgun-key", "Mailgun API key", "high", r"key-[0-9a-zA-Z]{32}"),
    ("npm-token", "npm access token", "high", r"npm_[0-9A-Za-z]{36}"),
    ("heroku-key", "Heroku API key", "high", r"(?i)heroku[a-z0-9_ .\-,]{0,25}[=:]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ("bearer-token", "Hardcoded bearer token", "medium", r"(?i)authorization['\"]?\s*[=:]\s*['\"]bearer\s+[A-Za-z0-9._\-]{20,}['\"]"),
    ("jwt", "Hardcoded JWT", "medium", r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("db-uri", "Database URI with credentials", "high",
     r"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+"),
    ("generic-secret", "Hardcoded credential", "high",
     r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[=:]\s*['\"][^'\"\s]{6,}['\"]"),
]

# ---- code pattern rules: (id, title, severity, owasp, {extensions}, regex) ----
CODE_RULES = [
    ("py-eval", "Use of eval()", "high", "CWE-95", {".py"}, r"\beval\s*\("),
    ("py-exec", "Use of exec()", "high", "CWE-95", {".py"}, r"\bexec\s*\("),
    ("py-os-system", "Shell command via os.system", "high", "CWE-78", {".py"}, r"os\.system\s*\("),
    ("py-shell-true", "subprocess with shell=True", "high", "CWE-78", {".py"}, r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True"),
    ("py-pickle", "Insecure deserialization (pickle)", "high", "CWE-502", {".py"}, r"pickle\.loads?\s*\("),
    ("py-yaml", "Unsafe yaml.load()", "medium", "CWE-502", {".py"}, r"yaml\.load\s*\((?![^)]*Loader)"),
    ("py-weak-hash", "Weak hash (md5/sha1)", "medium", "CWE-327", {".py"}, r"hashlib\.(?:md5|sha1)\s*\("),
    ("py-tls-off", "TLS verification disabled", "high", "CWE-295", {".py"}, r"verify\s*=\s*False"),
    ("py-debug", "Debug mode enabled", "medium", "CWE-489", {".py"}, r"(?i)debug\s*=\s*True"),
    ("js-eval", "Use of eval()", "high", "CWE-95", {".js", ".jsx", ".ts", ".tsx"}, r"\beval\s*\("),
    ("js-dangerous-html", "dangerouslySetInnerHTML", "medium", "A03:Injection", {".jsx", ".tsx", ".js", ".ts"}, r"dangerouslySetInnerHTML"),
    ("js-innerhtml", "Direct innerHTML assignment", "medium", "CWE-79", {".js", ".jsx", ".ts", ".tsx", ".html"}, r"\.innerHTML\s*="),
    ("js-doc-write", "document.write()", "low", "CWE-79", {".js", ".jsx", ".ts", ".tsx", ".html"}, r"document\.write\s*\("),
    ("js-child-exec", "child_process exec", "high", "CWE-78", {".js", ".ts"}, r"child_process[\s\S]{0,40}\bexec\s*\("),
    # Go
    ("go-exec", "Command execution via exec.Command", "medium", "CWE-78", {".go"}, r"exec\.Command\s*\("),
    ("go-md5", "Weak hash (md5/sha1)", "medium", "CWE-327", {".go"}, r"(?:md5|sha1)\.New\s*\("),
    ("go-tls-skip", "TLS verification disabled", "high", "CWE-295", {".go"}, r"InsecureSkipVerify\s*:\s*true"),
    # Ruby
    ("rb-eval", "Use of eval()", "high", "CWE-95", {".rb"}, r"\beval\s*\("),
    ("rb-system", "Shell command via system/backticks", "high", "CWE-78", {".rb"}, r"(?:\bsystem\s*\(|`[^`]*#\{)"),
    ("rb-marshal", "Insecure deserialization (Marshal.load)", "high", "CWE-502", {".rb"}, r"Marshal\.load\s*\("),
    # PHP
    ("php-eval", "Use of eval()", "high", "CWE-95", {".php"}, r"\beval\s*\("),
    ("php-system", "Command execution", "high", "CWE-78", {".php"}, r"\b(?:system|shell_exec|exec|passthru|popen)\s*\("),
    ("php-unserialize", "Insecure deserialization (unserialize)", "high", "CWE-502", {".php"}, r"\bunserialize\s*\("),
    ("php-super-global-sql", "Superglobal used near SQL", "high", "A03:Injection", {".php"}, r"(?i)(?:query|exec)\s*\([^)]*\$_(?:GET|POST|REQUEST)"),
    # Java
    ("java-exec", "Runtime.exec command execution", "high", "CWE-78", {".java"}, r"Runtime\.getRuntime\(\)\.exec\s*\("),
    ("java-deser", "Insecure deserialization (ObjectInputStream)", "high", "CWE-502", {".java"}, r"new\s+ObjectInputStream\s*\("),
    ("java-rng", "Insecure RNG (java.util.Random) for security", "low", "CWE-330", {".java"}, r"new\s+Random\s*\("),
    # General
    ("sql-concat", "Possible SQL string concatenation", "high", "A03:Injection", TEXT_EXT,
     r"(?i)(?:select|insert into|update|delete from)\b[^;\n]{0,80}['\"]\s*\+\s*\w"),
    ("cors-wildcard", "Permissive CORS (Access-Control-Allow-Origin: *)", "medium", "A05:SecurityMisconfiguration",
     TEXT_EXT, r"(?i)access-control-allow-origin['\"]?\s*[=:,]\s*['\"]\*['\"]"),
    ("curl-pipe-sh", "Remote script piped to a shell", "high", "CWE-494", TEXT_EXT | {".sh", ""},
     r"(?i)curl\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh"),
]


def _iter_files(root: str):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext and ext not in TEXT_EXT and name not in EXTRA_NAMES and not name.startswith("Dockerfile"):
                continue
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield path, os.path.relpath(path, root).replace("\\", "/")


def _is_test_path(rel: str) -> bool:
    low = "/" + rel.lower()
    return any(h in low for h in TEST_PATH_HINTS)


def _in_string_literal(line: str, col: int) -> bool:
    """Heuristic: True if position `col` sits inside a quoted string on this line
    (odd number of unescaped quotes before it) — used to skip code patterns that are
    actually inside titles/messages/docstrings rather than live code."""
    seg = line[:col]
    dq = len(re.findall(r'(?<!\\)"', seg))
    sq = len(re.findall(r"(?<!\\)'", seg))
    return dq % 2 == 1 or sq % 2 == 1


def _scan_tree(root: str) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    stats = {"files": 0, "languages": set()}
    for path, rel in _iter_files(root):
        stats["files"] += 1
        ext = os.path.splitext(path)[1].lower()
        if ext:
            stats["languages"].add(ext)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        text = "".join(lines)

        # secrets (skip obvious example files)
        is_example = any(x in rel.lower() for x in ("example", "sample", ".dist", "template", "test"))
        for sid, title, sev, pat in SECRET_RULES:
            for m in re.finditer(pat, text):
                if m.group(0) in KNOWN_EXAMPLE_SECRETS:
                    continue
                if sid == "generic-secret" and (is_example or _looks_placeholder(m.group(0))):
                    continue
                ln = text[: m.start()].count("\n") + 1
                findings.append(finding(
                    id=f"secret-{sid}", title=title, severity=sev, category="Secrets",
                    owasp="CWE-798", location=rel, line=ln,
                    evidence=_redact(m.group(0)),
                    description=f"A {title.lower()} appears hardcoded in the repository.",
                    recommendation="Remove the secret, rotate it immediately, and load it from an environment variable or secret manager.",
                ))

        # committed .env with values
        if rel.split("/")[-1] == ".env":
            findings.append(finding(
                id="secret-dotenv", title="Committed .env file", severity="high", category="Secrets",
                owasp="CWE-538", location=rel,
                description="A .env file (which usually holds real secrets) is committed to the repo.",
                recommendation="Delete it from the repo, add `.env` to .gitignore, and rotate any exposed values.",
            ))

        # code patterns (skipped in test/fixture files — patterns there are usually intentional)
        code_is_test = _is_test_path(rel)
        for cid, title, sev, owasp, exts, pat in CODE_RULES:
            if ext not in exts or code_is_test:
                continue
            for m in re.finditer(pat, text):
                ln = text[: m.start()].count("\n") + 1
                col = m.start() - (text.rfind("\n", 0, m.start()) + 1)
                if _in_string_literal(lines[ln - 1] if ln - 1 < len(lines) else "", col):
                    continue  # match is inside a string literal (title/message/doc), not live code
                findings.append(finding(
                    id=f"code-{cid}", title=title, severity=sev, category="Code Pattern",
                    owasp=owasp, location=rel, line=ln,
                    evidence=lines[ln - 1].strip() if ln - 1 < len(lines) else m.group(0),
                    description=f"Potentially unsafe pattern: {title}.",
                    recommendation="Review this line; use a safe alternative and validate/sanitize any external input.",
                ))
    return findings, stats


def _redact(s: str) -> str:
    return s[:6] + "…" + s[-4:] if len(s) > 14 else s[:4] + "…"


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def _looks_placeholder(match: str) -> bool:
    """True if a generic 'password=...' match is clearly a placeholder / not a real secret."""
    low = match.lower()
    if any(tok in low for tok in PLACEHOLDER_TOKENS):
        return True
    q = re.search(r"['\"]([^'\"]+)['\"]", match)
    val = q.group(1) if q else match
    # very low entropy short values (e.g. "aaaaaa", "123456") are unlikely real secrets
    return len(val) < 8 and _entropy(val) < 2.0


def _config_checks(root: str) -> list[dict]:
    out = []
    has = lambda p: os.path.exists(os.path.join(root, p))
    if has("package.json") and not (has("package-lock.json") or has("yarn.lock") or has("pnpm-lock.yaml")):
        out.append(finding(
            id="dep-no-lockfile", title="No dependency lockfile", severity="low", category="Dependencies",
            owasp="A06:VulnerableComponents", location="package.json",
            description="package.json has no lockfile, so dependency versions aren't pinned (supply-chain risk).",
            recommendation="Commit a package-lock.json / yarn.lock and run `npm audit`.",
        ))
    if not has(".gitignore"):
        out.append(finding(
            id="cfg-no-gitignore", title="Missing .gitignore", severity="low", category="Config",
            location="/", description="No .gitignore — secrets and build artifacts can be committed by accident.",
            recommendation="Add a .gitignore covering .env, credentials, and build output.",
        ))
    sec = any(has(p) for p in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"))
    if not sec:
        out.append(finding(
            id="cfg-no-security-policy", title="No security policy (SECURITY.md)", severity="low",
            category="Config", location="/",
            description="No SECURITY.md — researchers have no documented way to report vulnerabilities.",
            recommendation="Add a SECURITY.md describing how to responsibly disclose issues.",
        ))
    if not any(has(p) for p in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING")):
        out.append(finding(
            id="cfg-no-license", title="No LICENSE file", severity="low", category="Config", location="/",
            description="No license file — legal terms of use are undefined.",
            recommendation="Add a LICENSE file appropriate for the project.",
        ))
    if has("requirements.txt") and not any(has(p) for p in ("requirements.lock", "poetry.lock", "Pipfile.lock")):
        out.append(finding(
            id="dep-py-no-lock", title="No pinned Python lockfile", severity="low", category="Dependencies",
            owasp="A06:VulnerableComponents", location="requirements.txt",
            description="Python dependencies aren't fully locked; transitive versions can drift.",
            recommendation="Use a lockfile (poetry.lock / pip-tools) and run `pip-audit`.",
        ))
    return out


# ---- CI / Dockerfile checks: (id, title, severity, owasp, matches-filename, regex) ----
CI_RULES = [
    ("docker-latest", "Unpinned Docker base image (:latest)", "low", "A06:VulnerableComponents",
     lambda n: n.startswith("Dockerfile"), r"(?im)^FROM\s+\S+:latest"),
    ("docker-add-url", "Dockerfile ADD from URL", "medium", "CWE-494",
     lambda n: n.startswith("Dockerfile"), r"(?im)^ADD\s+https?://"),
    ("docker-secret-env", "Secret baked into Docker ENV", "high", "CWE-798",
     lambda n: n.startswith("Dockerfile"), r"(?im)^ENV\s+\w*(?:PASSWORD|SECRET|TOKEN|KEY)\w*\s*=\s*\S+"),
    ("gha-pr-target", "Dangerous 'pull_request_target' workflow trigger", "high", "CWE-829",
     lambda n: n.endswith((".yml", ".yaml")), r"(?im)^\s*pull_request_target\s*:"),
    ("gha-script-injection", "Untrusted input in a workflow run step", "high", "CWE-94",
     lambda n: n.endswith((".yml", ".yaml")), r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review)[^}]*\}\}"),
    ("gha-curl-pipe", "Workflow pipes a remote script to a shell", "high", "CWE-494",
     lambda n: n.endswith((".yml", ".yaml")), r"(?i)curl\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh"),
]


def _ci_docker_checks(root: str) -> list[dict]:
    out = []
    for path, rel in _iter_files(root):
        name = os.path.basename(rel)
        is_docker = name.startswith("Dockerfile")
        is_wf = "/.github/workflows/" in ("/" + rel) or "/workflows/" in ("/" + rel)
        if not (is_docker or is_wf):
            continue
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        for cid, title, sev, owasp, name_ok, pat in CI_RULES:
            if not name_ok(name):
                continue
            m = re.search(pat, text)
            if m:
                ln = text[: m.start()].count("\n") + 1
                out.append(finding(
                    id=f"ci-{cid}", title=title, severity=sev, category="CI/CD & Containers",
                    owasp=owasp, location=rel, line=ln, evidence=m.group(0).strip()[:120],
                    description=f"CI/container misconfiguration: {title}.",
                    recommendation="Pin versions, avoid untrusted input in run steps, and never bake secrets into images.",
                ))
    return out


def _history_secrets(root: str) -> list[dict]:
    """Scan git HISTORY (added lines across recent commits) for secrets that may have been
    committed then removed — they remain recoverable in the repo history."""
    try:
        proc = subprocess.run(
            ["git", "-C", root, "log", "-p", "-U0", "--no-color", "--max-count=400"],
            capture_output=True, text=True, timeout=90, errors="ignore",
        )
    except Exception:  # noqa: BLE001
        return []
    out: list[dict] = []
    seen: set[str] = set()
    commit = ""
    for line in proc.stdout[:6_000_000].splitlines():
        if line.startswith("commit "):
            commit = line.split()[1][:10]
        elif line.startswith("+") and not line.startswith("+++"):
            added = line[1:]
            for sid, title, sev, pat in SECRET_RULES:
                if sid == "generic-secret":
                    continue  # too noisy across history
                m = re.search(pat, added)
                if m:
                    if m.group(0) in KNOWN_EXAMPLE_SECRETS:
                        continue
                    key = f"{sid}:{m.group(0)[:24]}"
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(finding(
                        id=f"history-{sid}", title=f"{title} in git history", severity=sev,
                        category="Secrets (history)", owasp="CWE-540", location=f"commit {commit}",
                        evidence=_redact(m.group(0)),
                        description=f"A {title.lower()} was committed at some point and remains in git history, even if later removed.",
                        recommendation="Rotate the secret now and purge it from history (git filter-repo / BFG).",
                    ))
    return out[:40]


def _parse_deps(root: str) -> list[tuple[str, str, str]]:
    """Return (ecosystem, name, version) for pinned dependencies we can CVE-check."""
    deps: list[tuple[str, str, str]] = []
    req = os.path.join(root, "requirements.txt")
    if os.path.exists(req):
        for line in open(req, encoding="utf-8", errors="ignore"):
            m = re.match(r"\s*([A-Za-z0-9._-]+)\s*==\s*([0-9][\w.\-]*)", line)
            if m:
                deps.append(("PyPI", m.group(1), m.group(2)))
    pkg = os.path.join(root, "package.json")
    if os.path.exists(pkg):
        try:
            data = json.load(open(pkg, encoding="utf-8", errors="ignore"))
            for section in ("dependencies", "devDependencies"):
                for name, ver in (data.get(section) or {}).items():
                    v = re.sub(r"^[\^~>=<\s]+", "", str(ver))
                    if re.match(r"^\d", v):
                        deps.append(("npm", name, v))
        except Exception:  # noqa: BLE001
            pass
    return deps[:80]


def _clone_and_scan(repo_url: str) -> tuple[list[dict], dict, list]:
    tmp = tempfile.mkdtemp(prefix="sentinel_repo_")
    try:
        # Full clone of the default branch (bounded history) so we can scan git HISTORY,
        # not just the current working tree. Falls back to a shallow clone if it's too big.
        proc = subprocess.run(
            ["git", "clone", "--single-branch", "--depth", "500", repo_url, tmp],
            capture_output=True, text=True, timeout=150,
        )
        if proc.returncode != 0:
            proc = subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", repo_url, tmp],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"git clone failed: {proc.stderr.strip()[:200]}")

        findings, stats = _scan_tree(tmp)
        findings += _config_checks(tmp)
        findings += _ci_docker_checks(tmp)
        findings += _history_secrets(tmp)
        deps = _parse_deps(tmp)

        # commit count (depth of history scanned)
        try:
            rc = subprocess.run(["git", "-C", tmp, "rev-list", "--count", "HEAD"],
                                capture_output=True, text=True, timeout=20)
            stats["commits_scanned"] = int(rc.stdout.strip() or 0)
        except Exception:  # noqa: BLE001
            stats["commits_scanned"] = 0
        stats["languages"] = sorted(stats["languages"])
        stats["dependencies"] = len(deps)
        return findings, stats, deps
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _parse_owner_repo(url: str) -> tuple[str, str] | None:
    m = re.search(r"github\.com[:/]+([^/]+)/([^/.]+)", url)
    return (m.group(1), m.group(2)) if m else None


async def _github_metadata(repo_url: str) -> list[dict]:
    """Use the public GitHub API (no auth needed) for repo-level security signals."""
    owner_repo = _parse_owner_repo(repo_url)
    if not owner_repo:
        return []
    owner, repo = owner_repo
    out: list[dict] = []
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "SentinelAI-Scanner"}
    try:
        async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
            r = await client.get(f"https://api.github.com/repos/{owner}/{repo}")
            if r.status_code != 200:
                return []
            data = r.json()
            if data.get("archived"):
                out.append(finding(id="gh-archived", title="Repository is archived", severity="low",
                                   category="Repo Health", location=repo_url,
                                   description="Archived repos receive no security fixes.",
                                   recommendation="Avoid depending on archived projects for anything sensitive."))
            pushed = str(data.get("pushed_at") or "")
            if pushed and pushed < "2024":
                out.append(finding(id="gh-stale", title=f"Repository looks unmaintained (last push {pushed[:10]})",
                                   severity="low", category="Repo Health", location=repo_url,
                                   description="No recent commits — dependencies and code may be outdated/unpatched.",
                                   recommendation="Verify the project is still maintained before relying on it."))
    except Exception:  # noqa: BLE001
        return out
    return out


async def _dependency_cves(deps: list[tuple[str, str, str]]) -> list[dict]:
    """Query OSV.dev (free, no key) for known vulnerabilities in pinned dependencies."""
    out: list[dict] = []
    if not deps:
        return out
    async with httpx.AsyncClient(timeout=15.0) as client:
        async def one(eco, name, ver):
            try:
                r = await client.post("https://api.osv.dev/v1/query",
                                      json={"version": ver, "package": {"name": name, "ecosystem": eco}})
                if r.status_code != 200:
                    return None
                vulns = r.json().get("vulns") or []
                if not vulns:
                    return None
                ids = ", ".join(v.get("id", "") for v in vulns[:4])
                sev = "critical" if any("CRITICAL" in json.dumps(v.get("severity", "")) for v in vulns) else "high"
                return finding(
                    id=f"dep-cve-{name}", title=f"Vulnerable dependency: {name}@{ver}", severity=sev,
                    category="Dependencies", owasp="A06:VulnerableComponents", location=f"{eco}:{name}",
                    evidence=f"{len(vulns)} known advisory(ies): {ids}",
                    description=f"{name}@{ver} has {len(vulns)} known security advisory(ies) in the OSV database.",
                    recommendation=f"Upgrade {name} to a patched version and run a dependency audit.")
            except Exception:  # noqa: BLE001
                return None
        sem = asyncio.Semaphore(10)
        async def guarded(d):
            async with sem:
                return await one(*d)
        results = await asyncio.gather(*[guarded(d) for d in deps])
    return [r for r in results if r]


AI_SYSTEM = (
    "You are a senior application-security engineer reviewing code for vulnerabilities. "
    "Report only real, high-confidence security issues. Reply with strict JSON only."
)


async def _ai_review(reviewer_cfg: dict, repo_url: str, rule_findings: list[dict]) -> list[dict]:
    provider = get_provider(reviewer_cfg["provider"], reviewer_cfg["model_name"],
                            reviewer_cfg.get("api_key"), reviewer_cfg.get("base_url"),
                            reviewer_cfg.get("request_config"))
    summary = "\n".join(f"- {f['severity']} {f['title']} @ {f['location']}:{f['line']}" for f in rule_findings[:40]) or "(none)"
    prompt = (
        f"Repository: {repo_url}\n\n"
        f"Automated rule scan already found these issues:\n{summary}\n\n"
        "Based on these patterns and typical mistakes, list up to 5 ADDITIONAL likely security "
        "weaknesses or systemic risks a reviewer should verify (auth, input validation, secrets "
        "management, injection, access control). For each, be specific.\n"
        'Reply as JSON: {"findings":[{"title":"","severity":"low|medium|high|critical",'
        '"category":"","description":"","recommendation":""}]}'
    )
    completion = await provider.complete(prompt, system=AI_SYSTEM, temperature=0.2, max_tokens=900)
    if completion.error:
        return []
    data = _extract_json(completion.text)
    out = []
    for i, f in enumerate(data.get("findings", [])[:5]):
        out.append(finding(
            id=f"ai-{i}", title=f.get("title", "AI-identified risk")[:120],
            severity=(f.get("severity") or "medium").lower(), category=f.get("category") or "AI Review",
            owasp="", location=repo_url, description=f.get("description", ""),
            recommendation=f.get("recommendation", ""), source="ai",
        ))
    return out


def _extract_json(text: str) -> dict:
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        m = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:  # noqa: BLE001
                pass
    return {}


def _dedupe(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in findings:
        key = (f["id"], f["location"], f["line"], f["evidence"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


async def scan_repo(scan_id: str, repo_url: str, use_ai: bool, reviewer_cfg: dict | None) -> None:
    try:
        findings, stats, deps = await asyncio.to_thread(_clone_and_scan, repo_url)
        # network-backed checks run concurrently
        cve_task = asyncio.create_task(_dependency_cves(deps))
        gh_task = asyncio.create_task(_github_metadata(repo_url))
        for task in (cve_task, gh_task):
            try:
                findings += await task
            except Exception:  # noqa: BLE001
                pass
        findings = _dedupe(findings)
        if use_ai and reviewer_cfg and reviewer_cfg.get("api_key"):
            try:
                findings += await _ai_review(reviewer_cfg, repo_url, findings)
            except Exception:  # noqa: BLE001
                pass
        summary = score_findings(findings)
        _persist(scan_id, "completed", summary, stats)
    except Exception as e:  # noqa: BLE001
        _persist(scan_id, "failed", None, None, error=str(e))


def _persist(scan_id, status, summary, stats, error=None):
    db = SessionLocal()
    try:
        s = db.get(RepoScan, scan_id)
        if not s:
            return
        s.status = status
        if summary:
            s.score = summary["score"]
            s.risk_level = summary["risk_level"]
            s.total_findings = summary["total"]
            s.severity_counts = summary["severity_counts"]
            s.category_breakdown = summary["category_breakdown"]
            s.findings = summary["findings"]
        if stats:
            s.stats = stats
        if error:
            s.error = error
        s.completed_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()
