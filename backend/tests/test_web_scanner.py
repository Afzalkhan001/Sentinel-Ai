import asyncio

import httpx

from app.engine import web_scanner as ws


class FakeClient:
    """Minimal async httpx-like client that returns responses from a handler(url)."""
    def __init__(self, handler):
        self.handler = handler

    async def get(self, url):
        return self.handler(url)


def resp(url, status=200, headers=None, text="", cookies=None):
    h = httpx.Headers(headers or {})
    if cookies:
        for c in cookies:
            h = httpx.Headers(list(h.multi_items()) + [("set-cookie", c)])
    return httpx.Response(status, headers=h, text=text, request=httpx.Request("GET", url))


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_normalize_adds_https():
    assert ws._normalize("example.com").startswith("https://")
    assert ws._normalize("http://x.com") == "http://x.com"


def test_missing_security_headers_flagged():
    client = FakeClient(lambda u: resp(u, headers={}))
    findings, _ = run(ws._passive(client, "https://example.com"))
    titles = {f["title"] for f in findings}
    assert "Missing Content-Security-Policy" in titles
    assert "Missing HSTS header" in titles
    assert any("X-Frame-Options" in t for t in titles)


def test_present_headers_not_flagged():
    hdrs = {
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }
    client = FakeClient(lambda u: resp(u, headers=hdrs))
    findings, _ = run(ws._passive(client, "https://example.com"))
    header_findings = [f for f in findings if f["category"] in ("Headers", "Transport")]
    assert header_findings == []


def test_http_scheme_flagged():
    client = FakeClient(lambda u: resp(u, headers={}))
    findings, _ = run(ws._passive(client, "http://example.com"))
    assert any(f["id"] == "web-no-https" for f in findings)


def test_insecure_cookie_flagged():
    client = FakeClient(lambda u: resp(u, headers={}, cookies=["sid=abc; Path=/"]))
    findings, _ = run(ws._passive(client, "https://example.com"))
    assert any(f["category"] == "Cookies" for f in findings)


def test_version_disclosure_flagged():
    client = FakeClient(lambda u: resp(u, headers={"server": "Apache/2.4.29"}))
    findings, _ = run(ws._passive(client, "https://example.com"))
    assert any(f["id"] == "web-info-server" for f in findings)


def test_active_probe_reflected_xss():
    from urllib.parse import parse_qs, urlparse

    def handler(url):
        # a vulnerable app decodes the param and reflects it raw
        params = parse_qs(urlparse(str(url)).query)
        reflected = " ".join(v for vals in params.values() for v in vals)
        return resp(url, text=f"you searched for {reflected}")
    findings = run(ws._active_probes(FakeClient(handler), "https://example.com/?q=hi"))
    assert any(f["id"].startswith("web-xss") for f in findings)


def test_active_probe_sql_error():
    from urllib.parse import parse_qs, urlparse

    def handler(url):
        vals = " ".join(v for vs in parse_qs(urlparse(str(url)).query).values() for v in vs)
        if "'" in vals:
            return resp(url, text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL")
        return resp(url, text="ok")
    findings = run(ws._active_probes(FakeClient(handler), "https://example.com/?id=1"))
    assert any(f["id"].startswith("web-sqli") for f in findings)


def test_active_probe_no_false_positive():
    client = FakeClient(lambda u: resp(u, text="totally benign page"))
    findings = run(ws._active_probes(client, "https://example.com/?q=1"))
    assert findings == []


def test_active_probe_skipped_without_params():
    client = FakeClient(lambda u: resp(u, text="anything"))
    assert run(ws._active_probes(client, "https://example.com/")) == []
