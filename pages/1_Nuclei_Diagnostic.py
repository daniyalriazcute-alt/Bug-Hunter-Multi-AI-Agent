"""Temporary diagnostic page to verify nuclei works."""
import subprocess
import streamlit as st
from tools.nuclei_installer import get_nuclei_path

st.title("🔬 Nuclei Diagnostic")

if st.button("Check Nuclei"):
    path = get_nuclei_path()
    st.write(f"**Binary path:** `{path}`")

    if not path:
        st.error("Nuclei not available!")
    else:
        result = subprocess.run(
            [path, "-version"],
            capture_output=True, text=True, timeout=15,
        )
        st.success("Nuclei is installed")
        st.code(result.stdout + result.stderr or "(no output)")

        st.write("**Running test scan on scanme.nmap.org…**")
        scan = subprocess.run(
            [path, "-u", "http://scanme.nmap.org",
             "-severity", "low,medium,high",
             "-silent", "-no-color",
             "-timeout", "5", "-rate-limit", "20",
             "-disable-update-check", "-no-interactsh"],
            capture_output=True, text=True, timeout=120,
        )
        st.write(f"**Exit code:** {scan.returncode}")
        st.write(f"**stdout ({len(scan.stdout)} chars):**")
        st.code(scan.stdout[:3000] or "(empty)")
        st.write(f"**stderr ({len(scan.stderr)} chars):**")
        st.code(scan.stderr[:3000] or "(empty)")

st.divider()
st.caption("Delete this file after debugging — it's not for production.")
