"""Website security scanner (authorized, non-destructive).

Passive checks: security headers, HTTPS/TLS, cookie flags, info disclosure,
exposed sensitive files (/.git, /.env, ...). Optional safe active probes
(one reflected-XSS canary + one SQL-error probe per query parameter) run only
when the caller confirms authorization. Nothing destructive, rate-limited.
"""
import asyncio
import json
import re
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from ..db import SessionLocal
from ..models_db import WebScan
from ..providers.registry import get_provider
from .findings import finding, score_findings

UA = "SentinelAI-Scanner/1.0 (+authorized security testing)"
TIMEOUT = 15.0

SECURITY_HEADERS = [
    ("content-security-policy", "Content-Security-Policy", "medium",
     "No CSP — the site is more exposed to XSS and data-injection.", "Add a restrictive Content-Security-Policy header."),
    ("x-frame-options", "X-Frame-Options / frame-ancestors", "medium",
     "Missing clickjacking protection.", "Send X-Frame-Options: DENY or a CSP frame-ancestors directive."),
    ("x-content-type-options", "X-Content-Type-Options", "low",
     "Missing — browsers may MIME-sniff responses.", "Send X-Content-Type-Options: nosniff."),
    ("referrer-policy", "Referrer-Policy", "low",
     "Missing — full URLs may leak to third parties.", "Send Referrer-Policy: strict-origin-when-cross-origin."),
    ("permissions-policy", "Permissions-Policy", "low",
     "Missing — browser features aren't restricted.", "Send a Permissions-Policy header."),
]

EXPOSED_PATHS = [
    ("/.git/config", "Exposed .git directory", "critical", r"\[core\]|repositoryformatversion"),
    ("/.env", "Exposed .env file", "critical", r"(?im)^[A-Z0-9_]+="),
    ("/.DS_Store", "Exposed .DS_Store", "low", r"Bud1|\x00\x00\x00"),
    ("/server-status", "Exposed Apache server-status", "high", r"Apache Server Status"),
    ("/phpinfo.php", "Exposed phpinfo()", "high", r"phpinfo\(\)|PHP Version"),
    ("/.well-known/security.txt", "security.txt present", "info", r"Contact:"),
    ("/wp-config.php.bak", "Backup config exposed", "critical", r"DB_PASSWORD|define\("),
]

SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysqli?_", r"valid MySQL result", r"PostgreSQL.*ERROR",
    r"ORA-\d{5}", r"Microsoft OLE DB Provider for SQL Server", r"Unclosed quotation mark",
    r"SQLite/JDBCDriver", r"sqlite3.OperationalError", r"psql: error",
]

XSS_MARKER = "sntlXSS7331"


def _normalize(url: str) -> str:
    if not re.match(r"^https?://", url):
        url = "https://" + url
    return url


async def _passive(client: httpx.AsyncClient, url: str) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    parsed = urlparse(url)
    resp = await client.get(url)
    headers = {k.lower(): v for k, v in resp.headers.items()}

    # HTTPS / HSTS
    if parsed.scheme != "https":
        findings.append(finding(id="web-no-https", title="Site not served over HTTPS", severity="high",
                                category="Transport", owasp="A02:CryptographicFailures", location=url,
                                description="Traffic is unencrypted and can be intercepted.",
                                recommendation="Serve the site over HTTPS and redirect HTTP to HTTPS."))
    elif "strict-transport-security" not in headers:
        findings.append(finding(id="web-no-hsts", title="Missing HSTS header", severity="medium",
                                category="Transport", owasp="A05:SecurityMisconfiguration", location=url,
                                description="No Strict-Transport-Security header — downgrade attacks are possible.",
                                recommendation="Send Strict-Transport-Security with a long max-age."))

    # security headers
    for key, title, sev, desc, rec in SECURITY_HEADERS:
        if key not in headers:
            findings.append(finding(id=f"web-hdr-{key}", title=f"Missing {title}", severity=sev,
                                    category="Headers", owasp="A05:SecurityMisconfiguration", location=url,
                                    description=desc, recommendation=rec))

    # info disclosure
    for h in ("server", "x-powered-by", "x-aspnet-version"):
        if h in headers and re.search(r"\d", headers[h]):
            findings.append(finding(id=f"web-info-{h}", title=f"Version disclosure via {h} header",
                                    severity="low", category="Info Disclosure", owasp="A05:SecurityMisconfiguration",
                                    location=url, evidence=f"{h}: {headers[h]}",
                                    description="Server/framework version is disclosed, aiding targeted attacks.",
                                    recommendation=f"Remove or obfuscate the {h} response header."))

    # cookie flags
    for raw in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []:
        low = raw.lower()
        name = raw.split("=", 1)[0]
        missing = [f for f in ("secure", "httponly") if f not in low]
        if "samesite" not in low:
            missing.append("samesite")
        if missing:
            findings.append(finding(id=f"web-cookie-{name}", title=f"Cookie '{name}' missing flags: {', '.join(missing)}",
                                    severity="medium", category="Cookies", owasp="A05:SecurityMisconfiguration",
                                    location=url, evidence=raw[:120],
                                    description="Session cookies lack protective flags.",
                                    recommendation="Set Secure, HttpOnly, and SameSite on sensitive cookies."))

    meta = {"status": resp.status_code, "server": headers.get("server", "unknown"),
            "final_url": str(resp.url)}
    return findings, meta


async def _exposed_paths(client: httpx.AsyncClient, url: str) -> list[dict]:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    out = []
    for path, title, sev, sig in EXPOSED_PATHS:
        try:
            r = await client.get(base + path)
        except Exception:  # noqa: BLE001
            continue
        if r.status_code == 200 and re.search(sig, r.text[:4000]):
            if sev == "info":
                continue  # security.txt present is good, not a finding
            out.append(finding(id=f"web-exposed-{path.strip('/').replace('/', '-')}", title=title,
                               severity=sev, category="Exposed Files", owasp="A01:BrokenAccessControl",
                               location=base + path,
                               description=f"{title} is publicly reachable and may leak sensitive data.",
                               recommendation="Block access to this path at the web server / restrict directory access."))
    return out


async def _active_probes(client: httpx.AsyncClient, url: str) -> list[dict]:
    """Safe, non-destructive: one reflected-XSS canary + one SQL-error probe per param."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    out = []
    if not params:
        return out
    for pname in params:
        # reflected XSS canary
        xss_val = f'{XSS_MARKER}"><svg>'
        q = {k: v[0] for k, v in params.items()}
        q[pname] = xss_val
        test_url = urlunparse(parsed._replace(query=urlencode(q)))
        try:
            r = await client.get(test_url)
            if f'{XSS_MARKER}"><svg>' in r.text:
                out.append(finding(id=f"web-xss-{pname}", title=f"Reflected XSS in parameter '{pname}'",
                                   severity="high", category="Injection", owasp="A03:Injection",
                                   location=test_url,
                                   description="A canary payload was reflected unescaped in the response.",
                                   recommendation="Context-encode all user input on output and add a CSP."))
        except Exception:  # noqa: BLE001
            pass
        # SQL error probe
        q2 = {k: v[0] for k, v in params.items()}
        q2[pname] = q2[pname] + "'"
        test_url2 = urlunparse(parsed._replace(query=urlencode(q2)))
        try:
            r2 = await client.get(test_url2)
            if any(re.search(p, r2.text) for p in SQL_ERRORS):
                out.append(finding(id=f"web-sqli-{pname}", title=f"Possible SQL injection in '{pname}'",
                                   severity="critical", category="Injection", owasp="A03:Injection",
                                   location=test_url2,
                                   description="Appending a single quote produced a database error, suggesting unsanitized input.",
                                   recommendation="Use parameterized queries / prepared statements."))
        except Exception:  # noqa: BLE001
            pass
    return out


AI_SYSTEM = "You are a web application penetration tester. Report only real, high-confidence issues. Reply with strict JSON only."


async def _ai_review(reviewer_cfg: dict, url: str, meta: dict, rule_findings: list[dict]) -> list[dict]:
    provider = get_provider(reviewer_cfg["provider"], reviewer_cfg["model_name"],
                            reviewer_cfg.get("api_key"), reviewer_cfg.get("base_url"),
                            reviewer_cfg.get("request_config"))
    summary = "\n".join(f"- {f['severity']} {f['title']}" for f in rule_findings[:30]) or "(none)"
    prompt = (f"Target: {url}\nServer: {meta.get('server')}\n\nAutomated checks found:\n{summary}\n\n"
              "List up to 4 ADDITIONAL likely web security weaknesses worth manually verifying "
              "(auth, session, access control, business logic). Be specific.\n"
              'Reply as JSON: {"findings":[{"title":"","severity":"low|medium|high|critical","category":"","description":"","recommendation":""}]}')
    completion = await provider.complete(prompt, system=AI_SYSTEM, temperature=0.2, max_tokens=800)
    if completion.error:
        return []
    data = _extract_json(completion.text)
    out = []
    for i, f in enumerate(data.get("findings", [])[:4]):
        out.append(finding(id=f"web-ai-{i}", title=f.get("title", "AI-identified risk")[:120],
                           severity=(f.get("severity") or "medium").lower(), category=f.get("category") or "AI Review",
                           location=url, description=f.get("description", ""),
                           recommendation=f.get("recommendation", ""), source="ai"))
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


async def scan_web(scan_id: str, url: str, authorized: bool, use_ai: bool, reviewer_cfg: dict | None) -> None:
    url = _normalize(url)
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True,
                                     headers={"User-Agent": UA}, verify=True) as client:
            findings, meta = await _passive(client, url)
            findings += await _exposed_paths(client, url)
            if authorized:
                findings += await _active_probes(client, url)
        if use_ai and reviewer_cfg and reviewer_cfg.get("api_key"):
            try:
                findings += await _ai_review(reviewer_cfg, url, meta, findings)
            except Exception:  # noqa: BLE001
                pass
        summary = score_findings(findings)
        _persist(scan_id, "completed", summary, meta)
    except Exception as e:  # noqa: BLE001
        _persist(scan_id, "failed", None, None, error=str(e))


def _persist(scan_id, status, summary, meta, error=None):
    db = SessionLocal()
    try:
        s = db.get(WebScan, scan_id)
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
        if meta:
            s.stats = meta
        if error:
            s.error = error
        s.completed_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()
