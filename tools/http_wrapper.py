"""HTTP fingerprinting & header analysis."""
from __future__ import annotations
import requests
from bs4 import BeautifulSoup

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy",
]

def http_probe(url: str, timeout: int = 10) -> dict:
    result: dict = {"url": url, "reachable": False}
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True,
                         headers={"User-Agent": "BugHunterAI/1.0"})
        soup = BeautifulSoup(r.text, "html.parser")
        result.update({
            "reachable": True,
            "status_code": r.status_code,
            "server": r.headers.get("Server", ""),
            "powered_by": r.headers.get("X-Powered-By", ""),
            "title": soup.title.string if soup.title else "",
            "missing_security_headers": [h for h in SECURITY_HEADERS if h not in r.headers],
        })
    except Exception as e:
        result["error"] = str(e)
    return result
