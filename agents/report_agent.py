"""Agent 4 — Report Generation."""
from __future__ import annotations
from state import BugHunterState
from utils.logger import append_log, append_error
from utils.llm import call_llm
from utils.pdf_generator import build_pdf

REPORT_SYSTEM_PROMPT = """You are the REPORT GENERATION AGENT.
Write a 120-180 word non-technical EXECUTIVE SUMMARY for a security assessment.
Include: overall risk posture, number/severity of findings, and a one-sentence
business impact. Plain text only, no markdown headers."""

def report_node(state: BugHunterState) -> BugHunterState:
    append_log(state, "report", "Generating executive summary via LLM…")

    vulns = state.get("vulnerabilities", [])
    poc = state.get("poc_results", [])

    try:
        summary = call_llm(
            REPORT_SYSTEM_PROMPT,
            f"Findings count: {len(vulns)}\n"
            f"Severities: {[v.get('severity') for v in vulns]}\n"
            f"PoC proven: {sum(1 for p in poc if p.get('exploitation_success'))}",
        )
    except Exception as e:
        append_error(state, f"report LLM failed: {e}")
        summary = f"Assessment identified {len(vulns)} finding(s)."

    append_log(state, "report", "Building PDF report…")
    try:
        path = build_pdf(
            target=state["target"],
            executive_summary=summary,
            vulnerabilities=vulns,
            poc_results=poc,
            recon_data=state.get("recon_data", {}),
        )
        state["report_path"] = path
        append_log(state, "report", f"PDF saved to {path}", "success")
    except Exception as e:
        append_error(state, f"PDF build failed: {e}")
        state["report_path"] = ""

    state["progress"] = 1.0
    return state
