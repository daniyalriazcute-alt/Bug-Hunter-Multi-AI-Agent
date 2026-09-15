"""Agent 2 — Vulnerability Analysis."""
from __future__ import annotations
import json
from state import BugHunterState
from tools.nuclei_wrapper import nuclei_scan
from utils.logger import append_log, append_error
from utils.llm import call_llm

VULN_SYSTEM_PROMPT = """You are the VULNERABILITY ANALYSIS AGENT.

CRITICAL RULES:
1. ONLY report vulnerabilities that are DIRECTLY supported by evidence in the input JSON.
2. NEVER invent vulnerabilities. If you cannot point to specific evidence (a port, a
   version, an HTTP response, a nuclei finding), DO NOT report it.
3. DO NOT use phrases like "potential", "could be", "if X were true", "may allow".
4. If the input JSON contains no real evidence, return [] (empty array).
5. The target domain is FIXED. NEVER change it. Your findings MUST reference the
   exact target given below.
6. Do NOT report timeouts, missing ports, or unreachable services as vulnerabilities.

You receive (a) the target, (b) recon data, (c) raw nuclei findings.
Produce a STRICT JSON array of at most 5 objects with keys:
  vuln_id, type, severity, cvss, endpoint, evidence, cve_ref, description, remediation.

Every finding MUST cite specific evidence copied verbatim from the input.
Output ONLY the JSON array — no prose, no markdown, no code fences."""


def vuln_node(state: BugHunterState) -> BugHunterState:
    append_log(state, "vuln", "Analyzing recon data for vulnerabilities…")
    target = state["target"]
    recon = state.get("recon_data", {})

    raw_findings: list[dict] = []
    web_url = f"http://{target}"

    # ── 1. Nuclei scan with explicit status tracking ──────────────────────
    append_log(state, "vuln", "Checking nuclei binary…")
    nuclei_status = "not_attempted"
    nuclei_real_hits: list[dict] = []

    try:
        raw_findings = nuclei_scan(web_url)
        real_hits = [f for f in raw_findings if "error" not in f]
        err_hits = [f for f in raw_findings if "error" in f]

        if err_hits and not real_hits:
            nuclei_status = "failed"
            err_msg = err_hits[0].get("error", "unknown error")
            append_log(state, "vuln", f"❌ Nuclei FAILED: {err_msg}", "error")
            append_error(state, f"Nuclei failed: {err_msg}")
        elif real_hits:
            nuclei_status = "success"
            nuclei_real_hits = real_hits
            append_log(
                state, "vuln",
                f"✅ Nuclei returned {len(real_hits)} finding(s)", "success",
            )
        else:
            nuclei_status = "no_findings"
            append_log(state, "vuln", "Nuclei ran but found 0 findings", "info")
    except Exception as e:
        nuclei_status = "failed"
        append_log(state, "vuln", f"❌ Nuclei exception: {e}", "error")
        append_error(state, f"Nuclei exception: {e}")
        raw_findings = []

    # ── 2. Heuristics (always run) ────────────────────────────────────────
    heuristic_findings: list[dict] = []

    # 2a. Missing security headers
    missing = recon.get("http", {}).get("missing_security_headers", [])
    if missing:
        heuristic_findings.append({
            "vuln_id": "HDR-001",
            "type": "Missing Security Headers",
            "severity": "Low",
            "cvss": 3.1,
            "endpoint": web_url,
            "evidence": f"HTTP response missing headers: {', '.join(missing)}",
            "cve_ref": "N/A",
            "description": "HTTP responses omit recommended security headers, "
                           "weakening defense-in-depth.",
            "remediation": "Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options.",
        })

    # 2b. Outdated software from nmap banners
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
                    "evidence": f"Apache {version} detected on port {port['port']}",
                    "cve_ref": "CVE-2017-7659, CVE-2019-0211",
                    "description": "Apache 2.4.7 is over a decade old with known CVEs.",
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
                    "description": "OpenSSH 6.6.x is vulnerable to info leak and auth bypass.",
                    "remediation": "Upgrade OpenSSH to the latest stable release.",
                })

    # ── 3. Anti-hallucination guard ───────────────────────────────────────
    recon_has_data = bool(
        nmap_hosts
        or recon.get("http", {}).get("reachable")
        or recon.get("dns", {}).get("A")
    )

    if not recon_has_data and not nuclei_real_hits and not heuristic_findings:
        append_log(
            state, "vuln",
            "⚠️ No usable data from recon or nuclei — skipping LLM to prevent hallucination",
            "warn",
        )
        state["vulnerabilities"] = [{
            "vuln_id": "INFO-001",
            "type": "Insufficient Data",
            "severity": "Info",
            "cvss": 0.0,
            "endpoint": web_url,
            "cve_ref": "N/A",
            "description": "Recon and nuclei both returned no usable data.",
            "evidence": f"nuclei_status={nuclei_status}, recon_keys={list(recon.keys())}",
            "remediation": "Verify target reachability and tool installation.",
        }]
        state["progress"] = 0.60
        return state

    # ── 4. LLM correlation ────────────────────────────────────────────────
    payload = {
        "target": target,
        "nuclei_status": nuclei_status,
        "recon_summary": recon.get("ai_priority_summary", ""),
        "nuclei_findings": nuclei_real_hits[:25],
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
    except Exception as e:
        append_error(state, f"vuln LLM parse failed: {e}")
        append_log(state, "vuln", "LLM failed — using heuristics only", "warn")
        vulns = heuristic_findings

    if not vulns:
        vulns = heuristic_findings

    # Ensure required keys exist
    for v in vulns:
        v.setdefault("vuln_id", "VULN-???")
        v.setdefault("severity", "Info")
        v.setdefault("cvss", 0.0)
        v.setdefault("endpoint", web_url)
        v.setdefault("cve_ref", "N/A")
        v.setdefault("evidence", "N/A")
        v.setdefault("remediation", "Apply vendor patches and hardening best practices.")

    state["vulnerabilities"] = vulns
    state["progress"] = 0.60
    append_log(state, "vuln", f"Identified {len(vulns)} finding(s)", "success")
    return state
