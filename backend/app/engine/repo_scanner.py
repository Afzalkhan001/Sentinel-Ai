"""GitHub repository security scanner.

Shallow-clones a public repo and runs deterministic rule checks:
  - hardcoded secrets / committed credentials
  - dangerous code patterns (eval, shell=True, pickle, weak crypto, ...)
  - dependency / config hygiene (committed .env, missing lockfile, ...)
Optionally sends suspicious source to a registered LLM for a deeper AI review.
"""
import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

from ..db import SessionLocal
from ..models_db import RepoScan
from ..providers.registry import get_provider
from .findings import finding, score_findings

# ---- scan limits ----
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__",
             "vendor", ".next", "target", ".idea", ".vscode", "coverage"}
TEXT_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".rb", ".go", ".php", ".cs",
            ".c", ".cpp", ".h", ".rs", ".sh", ".yaml", ".yml", ".json", ".env", ".txt",
            ".cfg", ".ini", ".toml", ".xml", ".html", ".sql", ".tf", ".properties"}
MAX_FILES = 2500
MAX_FILE_BYTES = 400_000

# ---- secret detectors: (id, title, severity, regex) ----
SECRET_RULES = [
    ("aws-access-key", "AWS Access Key ID", "critical", r"AKIA[0-9A-Z]{16}"),
    ("private-key", "Private key committed", "critical", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("openai-key", "OpenAI API key", "critical", r"sk-(?:proj-)?[A-Za-z0-9]{20,}"),
    ("google-key", "Google API key", "high", r"AIza[0-9A-Za-z_\-]{35}"),
    ("github-token", "GitHub token", "critical", r"gh[pousr]_[0-9A-Za-z]{36,}"),
    ("slack-token", "Slack token", "high", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("jwt", "Hardcoded JWT", "medium", r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("generic-secret", "Hardcoded credential", "high",
     r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[=:]\s*['\"][^'\"\s]{6,}['\"]"),
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
    ("sql-concat", "Possible SQL string concatenation", "high", "A03:Injection", TEXT_EXT,
     r"(?i)(?:select|insert into|update|delete from)\b[^;\n]{0,80}['\"]\s*\+\s*\w"),
]


def _iter_files(root: str):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext and ext not in TEXT_EXT and name != ".env":
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
                if is_example and sid == "generic-secret":
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

        # code patterns
        for cid, title, sev, owasp, exts, pat in CODE_RULES:
            if ext not in exts:
                continue
            for m in re.finditer(pat, text):
                ln = text[: m.start()].count("\n") + 1
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
    return out


def _clone_and_scan(repo_url: str) -> tuple[list[dict], dict]:
    tmp = tempfile.mkdtemp(prefix="sentinel_repo_")
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", repo_url, tmp],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"git clone failed: {proc.stderr.strip()[:200]}")
        findings, stats = _scan_tree(tmp)
        findings += _config_checks(tmp)
        stats["languages"] = sorted(stats["languages"])
        return findings, stats
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


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


async def scan_repo(scan_id: str, repo_url: str, use_ai: bool, reviewer_cfg: dict | None) -> None:
    try:
        findings, stats = await asyncio.to_thread(_clone_and_scan, repo_url)
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
