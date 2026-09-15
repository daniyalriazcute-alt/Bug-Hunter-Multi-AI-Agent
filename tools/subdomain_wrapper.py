"""Subdomain enumeration using subfinder."""
from __future__ import annotations
import shutil
import subprocess
from config import DEFAULT_TIMEOUT

def enumerate_subdomains(domain: str) -> list[str]:
    if not shutil.which("subfinder"):
        return [domain]
    try:
        proc = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=DEFAULT_TIMEOUT, check=False,
        )
        subs = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
        return sorted(set(subs + [domain]))
    except Exception:
        return [domain]
