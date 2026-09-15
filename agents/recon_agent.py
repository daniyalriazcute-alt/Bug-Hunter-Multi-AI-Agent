"""Agent 1 — Reconnaissance."""
from __future__ import annotations
import json
from state import BugHunterState
from tools.dns_wrapper import dns_lookup
from tools.whois_wrapper import whois_lookup
from tools.subdomain_wrapper import enumerate_subdomains
from tools.nmap_wrapper import nmap_scan
from tools.http_wrapper import http_probe
from utils.logger import append_log, append_error
from utils.llm import call_llm

RECON_SYSTEM_PROMPT = """You are the RECONNAISSANCE AGENT in an authorized
bug-bounty pipeline. Given raw recon JSON, produce a short prioritized summary:
- Identify the most interesting attack surfaces.
- Rank the top 3 things a vulnerability analyst should check first.
Return plain text, max 200 words. No code. No exploit instructions."""

def recon_node(state: BugHunterState) -> BugHunterState:
    target = state["target"].strip()
    append_log(state, "recon", f"Starting reconnaissance on {target}")
    state["progress"] = 0.10

    recon: dict = {"target": target}
    append_log(state, "recon", "Resolving DNS records…")
    recon["dns"] = dns_lookup(target)
    state["progress"] = 0.20

    append_log(state, "recon", "Querying WHOIS…")
    recon["whois"] = whois_lookup(target)
    state["progress"] = 0.30

    append_log(state, "recon", "Enumerating subdomains…")
    recon["subdomains"] = enumerate_subdomains(target)
    state["progress"] = 0.45

    append_log(state, "recon", "Running nmap top-ports scan…")
    recon["nmap"] = nmap_scan(target)
    state["progress"] = 0.65

    append_log(state, "recon", "Fingerprinting HTTP service…")
    recon["http"] = http_probe(f"http://{target}")
    state["progress"] = 0.75

    try:
        summary = call_llm(
            RECON_SYSTEM_PROMPT,
            "Raw recon data (truncated):\n" + json.dumps(recon, default=str)[:6000],
        )
        recon["ai_priority_summary"] = summary
        append_log(state, "recon", "AI prioritization complete", "success")
    except Exception as e:
        append_error(state, f"recon LLM failed: {e}")
        recon["ai_priority_summary"] = ""

    state["recon_data"] = recon
    state["progress"] = 0.80
    append_log(state, "recon", "Reconnaissance complete", "success")
    return state
