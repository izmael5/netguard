"""
Web-layer checks.

Entirely passive/non-intrusive: it looks at what a normal browser would
see (response headers, TLS certificate, robots.txt) and flags common
misconfigurations. It does not attempt SQL injection, XSS, auth bypass,
or any other active attack technique.
"""
import ssl
import socket
import datetime
import requests
from urllib.parse import urlparse
from scanner.authorization import require_authorization

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS; missing allows downgrade attacks.",
    "Content-Security-Policy": "Mitigates XSS/data injection; missing widens attack surface.",
    "X-Content-Type-Options": "Prevents MIME sniffing; should be 'nosniff'.",
    "X-Frame-Options": "Mitigates clickjacking; missing allows framing.",
    "Referrer-Policy": "Controls referrer leakage to third parties.",
    "Permissions-Policy": "Restricts access to browser features/APIs.",
}

# Paths that, if publicly reachable, commonly indicate accidental exposure.
# We only check whether a GET returns 200 — we don't act on the contents.
COMMON_EXPOSED_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/wp-config.php.bak",
    "/backup.zip", "/.aws/credentials", "/config.php.bak",
    "/.DS_Store", "/server-status", "/phpinfo.php",
]


def _host_from_target(target: str) -> str:
    if "://" not in target:
        target = "https://" + target
    return urlparse(target).netloc.split(":")[0]


def check_headers(base_url: str, timeout=10):
    findings = []
    try:
        resp = requests.get(base_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return [{"category": "connectivity", "finding": "Request failed",
                  "severity": "INFO", "detail": str(exc)}]

    findings.append({
        "category": "server_banner", "finding": "Server header",
        "severity": "INFO",
        "detail": resp.headers.get("Server", "not disclosed"),
    })

    for header, explanation in SECURITY_HEADERS.items():
        if header not in resp.headers:
            findings.append({
                "category": "missing_header",
                "finding": f"Missing {header}",
                "severity": "MEDIUM",
                "detail": explanation,
            })

    cookies_no_secure = [c.name for c in resp.cookies if not c.secure]
    if cookies_no_secure:
        findings.append({
            "category": "cookies", "finding": "Cookies set without Secure flag",
            "severity": "LOW", "detail": ", ".join(cookies_no_secure),
        })
    return findings


def check_tls(host: str, port: int = 443, timeout=8):
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.datetime.utcnow()).days
                severity = "HIGH" if days_left < 7 else ("MEDIUM" if days_left < 30 else "INFO")
                findings.append({
                    "category": "tls", "finding": "Certificate expiry",
                    "severity": severity, "detail": f"{days_left} days remaining (expires {not_after.date()})",
                })
                findings.append({
                    "category": "tls", "finding": "TLS protocol negotiated",
                    "severity": "INFO", "detail": ssock.version(),
                })
    except (socket.error, ssl.SSLError, socket.timeout) as exc:
        findings.append({
            "category": "tls", "finding": "TLS check failed",
            "severity": "INFO", "detail": str(exc),
        })
    return findings


def check_exposed_paths(base_url: str, timeout=6):
    findings = []
    for path in COMMON_EXPOSED_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=False)
            if resp.status_code == 200:
                findings.append({
                    "category": "exposed_path",
                    "finding": f"Publicly reachable: {path}",
                    "severity": "HIGH",
                    "detail": f"HTTP {resp.status_code} - review whether this should be public.",
                })
        except requests.RequestException:
            continue
    return findings


def run_web_scan(target: str):
    require_authorization(_host_from_target(target) or target)
    base_url = target if "://" in target else f"https://{target}"
    host = _host_from_target(base_url)

    findings = []
    findings += check_headers(base_url)
    findings += check_tls(host)
    findings += check_exposed_paths(base_url)
    return findings
