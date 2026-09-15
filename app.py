"""Streamlit UI for Bug Hunter Multi-AI Agent system."""
from __future__ import annotations
import os
import streamlit as st

from config import LEGAL_BANNER, GROQ_MODEL
from graph import BUG_HUNTER_GRAPH

# Optional: pre-warm nuclei so the first scan isn't slowed by the download
try:
    from tools.nuclei_installer import ensure_nuclei
    ensure_nuclei()
except Exception:
    pass  # silent — agent will retry later if needed

st.set_page_config(
    page_title="Bug Hunter Multi-AI",
    page_icon="🐛",
    layout="wide",
)

# ─── Session state init ─────────────────────────────────────────────────────
if "state" not in st.session_state:
    st.session_state.state = {}
if "running" not in st.session_state:
    st.session_state.running = False

# ─── Header ─────────────────────────────────────────────────────────────────
st.title("🐛 Bug Hunter Multi-AI Agent")
st.caption(f"Powered by Groq · Model: `{GROQ_MODEL}` · LangGraph Orchestration")
st.error(LEGAL_BANNER)

# ─── Sidebar ────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")

    target = st.text_input(
        "🎯 Target (domain or IP)",
        placeholder="e.g. scanme.nmap.org",
        help="Only use targets you own or have written permission to test.",
    )

    authorization = st.checkbox(
        "✅ I confirm I have authorization to test this target",
        value=False,
    )

    exploit_consent = st.checkbox(
        "💥 Enable Exploit/PoC Agent (safe-mode)",
        value=False,
        help="Runs non-destructive PoC checks. Blocked payloads are filtered.",
    )

    st.divider()

    run_btn = st.button(
        "🚀 Run Pipeline",
        type="primary",
        use_container_width=True,
        disabled=not (target and authorization),
    )

    if st.button("🗑️ Reset", use_container_width=True):
        st.session_state.state = {}
        st.session_state.running = False
        st.rerun()

    st.divider()
    st.markdown("**Pipeline Stages**")
    st.markdown("1. 🔍 Recon\n2. 🎯 Vuln Analysis\n3. 💥 Exploit (PoC)\n4. 📄 Report")

# ─── Run pipeline ───────────────────────────────────────────────────────────
if run_btn and not st.session_state.running:
    st.session_state.running = True
    st.session_state.state = {
        "target": target.strip(),
        "authorization_confirmed": True,
        "exploit_consent": exploit_consent,
        "logs": [],
        "errors": [],
        "progress": 0.0,
    }

    progress_bar = st.progress(0.0, text="Starting pipeline…")
    status_box = st.status("Running Bug Hunter pipeline…", expanded=True)

    try:
        for step_output in BUG_HUNTER_GRAPH.stream(st.session_state.state):
            for node_name, partial in step_output.items():
                st.session_state.state.update(partial)
                prog = st.session_state.state.get("progress", 0.0)
                progress_bar.progress(min(prog, 1.0), text=f"Completed: {node_name}")

                logs = partial.get("logs", [])
                for log in logs[-3:]:
                    status_box.write(f"**[{log['agent']}]** {log['message']}")

        status_box.update(label="✅ Pipeline complete!", state="complete", expanded=False)
        progress_bar.progress(1.0, text="Done")
    except Exception as e:
        status_box.update(label=f"❌ Pipeline failed: {e}", state="error")
        st.session_state.state.setdefault("errors", []).append(str(e))
    finally:
        st.session_state.running = False

# ─── Results tabs ───────────────────────────────────────────────────────────
state = st.session_state.state

tab_recon, tab_vuln, tab_exploit, tab_report, tab_logs = st.tabs(
    ["🔍 Recon", "🎯 Vulnerabilities", "💥 Exploits", "📄 Report", "📜 Logs"]
)

with tab_recon:
    st.subheader("Reconnaissance Results")
    recon = state.get("recon_data")
    if recon:
        st.json(recon)
        if recon.get("ai_priority_summary"):
            st.info(f"**AI Priority Summary:**\n\n{recon['ai_priority_summary']}")
    else:
        st.info("Run the pipeline to see recon results.")

with tab_vuln:
    st.subheader("Identified Vulnerabilities")
    vulns = state.get("vulnerabilities", [])
    if vulns:
        st.dataframe(vulns, use_container_width=True)
    else:
        st.info("No vulnerabilities identified yet.")

with tab_exploit:
    st.subheader("Proof-of-Concept Results")
    pocs = state.get("poc_results", [])
    if pocs:
        for p in pocs:
            status = "✅ PROVEN" if p.get("exploitation_success") else "⚠️ Inconclusive"
            with st.expander(f"{p.get('vuln_id')} — {status}"):
                st.write(f"**Steps:** {p.get('poc_steps')}")
                st.code(p.get("payload_used", ""), language="text")
                st.write(f"**Evidence:** {p.get('response_evidence')}")
    else:
        st.info("No PoC results. Enable the Exploit agent in the sidebar and rerun.")

with tab_report:
    st.subheader("Security Report")
    report_path = state.get("report_path")
    if report_path and os.path.exists(report_path):
        with open(report_path, "rb") as f:
            st.download_button(
                "📥 Download PDF Report",
                data=f.read(),
                file_name=os.path.basename(report_path),
                mime="application/pdf",
                type="primary",
            )
        st.success(f"Report generated: `{report_path}`")
    else:
        st.info("No report available yet.")

with tab_logs:
    st.subheader("Execution Logs")
    logs = state.get("logs", [])
    if logs:
        for log in logs:
            icon = {"info": "ℹ️", "warn": "⚠️", "error": "❌", "success": "✅"}.get(
                log["level"], "•"
            )
            st.write(
                f"{icon} **[{log['agent']}]** `{log['timestamp']}` — {log['message']}"
            )
    errors = state.get("errors", [])
    if errors:
        st.error("**Errors:**\n" + "\n".join(f"- {e}" for e in errors))
