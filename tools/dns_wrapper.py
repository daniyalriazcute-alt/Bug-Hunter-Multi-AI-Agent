"""DNS enumeration using dnspython."""
from __future__ import annotations
import dns.resolver

def dns_lookup(domain: str) -> dict:
    out: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            out[rtype] = [str(r) for r in answers]
        except Exception:
            out[rtype] = []
    return out
