"""WHOIS lookup wrapper."""
from __future__ import annotations
import whois

def whois_lookup(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        return {
            "registrar": str(w.registrar or ""),
            "creation_date": str(w.creation_date or ""),
            "expiration_date": str(w.expiration_date or ""),
            "name_servers": [str(n) for n in (w.name_servers or [])],
            "org": str(w.org or ""),
            "country": str(w.country or ""),
        }
    except Exception as e:
        return {"error": str(e)}
