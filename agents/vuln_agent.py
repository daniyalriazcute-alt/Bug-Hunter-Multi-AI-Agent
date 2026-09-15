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

    # --- Nuclei scan (auto-downloaded binary) ---
    append_log(state, "vuln", "Ensuring nuclei binary is available…")
    try:
        raw_findings = nuclei_scan(web_url)
        # Filter out internal error entries
        real_hits = [f for f in raw_findings if "error" not in f]
        errors = [f for f in raw_findings if "error" in f]
        if real_hits:
            append_log(state, "vuln", f"Nuclei returned {len(real_hits)} finding(s)", "success")
        elif errors:
            append_log(state, "vuln", f"Nuclei unavailable: {errors[0]['error']}", "warn")
        else:
            append_log(state, "vuln", "Nuclei ran but found nothing", "info")
    except Exception as e:  # noqa: BLE001
        append_error(state, f"nuclei failed: {e}")
        append_log(state, "vuln", f"Nuclei error: {e}", "warn")

    # --- Heuristic: missing security headers ---
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
            "description": "HTTP responses omit recommended security headers, "
                           "weakening defense-in-depth against clickjacking, "
                           "MIME-sniffing, and protocol downgrade attacks.",
            "remediation": "Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options, "
                           "Referrer-Policy, and Permissions-Policy headers.",
        })

    # --- Heuristic: outdated server versions from nmap ---
    nmap_hosts = recon.get("nmap", {}).get("hosts", {})
    for host_ip, host_data in nmap_hosts.items():
        for port in host_data.get("ports", []):
            product = (port.get("product") or "").lower()
            version = port.get("version") or ""
            if "apache" in product and version.startswith("2.4.7"):
                heuristic_findings.append({
                    "vuln_id": f"CVE-APACHE-{port['port']}",
                    "type": "Outdated Apache HTTP Server",
                    "severity": "High",
                    "cvss": 7.5,
                    "endpoint": f"http://{target}:{port['port']}",
                    "evidence": f"Apache {version} (released 2013) detected on port {port['port']}",
                    "cve_ref": "CVE-2017-7659, CVE-2019-0211",
                    "description": "Apache 2.4.7 is over a decade old and contains "
                                   "multiple publicly disclosed vulnerabilities including "
                                   "privilege escalation and DoS.",
                    "remediation": "Upgrade Apache to the latest stable release.",
                })
            if "openssh" in product and version.startswith("6.6"):
                heuristic_findings.append({
                    "vuln_id": f"CVE-SSH-{port['port']}",
                    "type": "Outdated OpenSSH Server",
                    "severity": "High",
                    "cvss": 7.4,
                    "endpoint": f"ssh://{target}:{port['port']}",
                    "evidence": f"OpenSSH {version} detected on port {port['port']}",
                    "cve_ref": "CVE-2016-0777, CVE-2016-0778, CVE-2015-5600",
                    "description": "OpenSSH 6.6.x is vulnerable to information leak "
                                   "(roaming), user enumeration, and authentication bypass.",
                    "remediation": "Upgrade OpenSSH to the latest stable release.",
                })

    # --- LLM correlation ---
    payload = {
        "recon_summary": recon.get("ai_priority_summary", ""),
        "nuclei_raw": [f for f in raw_findings if "error" not in f][:25],
        "heuristics": heuristic_findings,
    }

    try:
        raw = call_llm(
            VULN_SYSTEM_PROMPT,
            "Input JSON:\n" + json.dumps(payload, default=str)[:8000],
        )
        cleaned = (raw.strip()
                   .removeprefix("```json").removeprefix("```")
                   .removesuffix("```").strip())
        vulns = json.loads(cleaned)
        if not isinstance(vulns, list):
            raise ValueError("LLM did not return JSON array")
        append_log(state, "vuln", f"LLM returned {len(vulns)} correlated finding(s)")
    except Exception as e:  # noqa: BLE001
        append_error(state, f"vuln LLM parse failed: {e}")
        append_log(state, "vuln", "LLM failed — falling back to heuristics", "warn")
        vulns = heuristic_findings

    # Fallback: if LLM returned empty but we have heuristics, merge them
    if not vulns and heuristic_findings:
        vulns = heuristic_findings

    # Ensure required keys
    for v in vulns:
        v.setdefault("vuln_id", "VULN-???")
        v.setdefault("severity", "Info")
        v.setdefault("cvss", 0.0)
        v.setdefault("endpoint", web_url)
        v.setdefault("cve_ref", "N/A")
        v.setdefault("description", "N/A")
        v.setdefault("evidence", "N/A")
        v.setdefault("remediation", "Apply vendor patches and hardening best practices.")

    state["vulnerabilities"] = vulns
    state["progress"] = 0.60
    append_log(state, "vuln", f"Identified {len(vulns)} finding(s)", "success")
    return state
