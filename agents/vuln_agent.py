"""Agent 2 — Vulnerability Analysis."""
from __future__ import annotations
import json
from state import BugHunterState
from tools.nuclei_wrapper import nuclei_scan
from utils.logger import append_log, append_error
from utils.llm import call_llm

VULN_SYSTEM_PROMPT = """You are the VULNERABILITY ANALYSIS AGENT.
You receive (a) recon data and (b) raw nuclei findings.
Produce a STRICT JSON array of at most 5 objects with keys:
  vuln_id, type, severity, cvss, endpoint, evidence, cve_ref, description, remediation.
Rank by exploitability. Output ONLY the JSON array — no prose."""

def vuln_node(state: BugHunterState) -> BugHunterState:
    append_log(state, "vuln", "Analyzing recon data for vulnerabilities…")
    target = state["target"]
    recon = state.get("recon_data", {})

    raw_findings: list[dict] = []
    web_url = f"http://{target}"
    append_log(state, "vuln", f"Running nuclei on {web_url} (safe templates)…")
    try:
        raw_findings = nuclei_scan(web_url)
        append_log(state, "vuln", f"Nuclei returned {len(raw_findings)} raw hit(s)")
    except Exception as e:
        append_error(state, f"nuclei failed: {e}")

    missing = recon.get("http", {}).get("missing_security_headers", [])
    heuristic_findings = []
    if missing:
        heuristic_findings.append({
            "vuln_id": "HDR-001",
            "type": "Missing Security Headers",
            "severity": "Low",
            "cvss": 3.1,
            "endpoint": web_url,
            "evidence": ", ".join(missing),
            "cve_ref": "N/A",
            "description": "HTTP responses omit recommended security headers.",
            "remediation": "Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options.",
        })

    payload = {
        "recon_summary": recon.get("ai_priority_summary", ""),
        "nuclei_raw": raw_findings[:25],
        "heuristics": heuristic_findings,
    }

    try:
        raw = call_llm(VULN_SYSTEM_PROMPT,
                       "Input JSON:\n" + json.dumps(payload, default=str)[:8000])
        cleaned = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        vulns = json.loads(cleaned)
        if not isinstance(vulns, list):
            raise ValueError("LLM did not return JSON array")
    except Exception as e:
        append_error(state, f"vuln LLM parse failed: {e}")
        vulns = heuristic_findings

    for v in vulns:
        v.setdefault("vuln_id", "VULN-???")
        v.setdefault("severity", "Info")
        v.setdefault("cvss", 0.0)
        v.setdefault("endpoint", web_url)

    state["vulnerabilities"] = vulns
    state["progress"] = 0.60
    append_log(state, "vuln", f"Identified {len(vulns)} finding(s)", "success")
    return state
