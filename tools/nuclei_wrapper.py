"""Nuclei wrapper — MINIMAL test version."""
from __future__ import annotations
import json
import subprocess
from config import NUCLEI_SCAN_TIMEOUT
from tools.nuclei_installer import get_nuclei_path


def nuclei_scan(url: str, severity: str = "low,medium,high,critical") -> list[dict]:
    """Minimal nuclei scan — only tech detection templates (~3 sec)."""
    nuclei_bin = get_nuclei_path()
    if not nuclei_bin:
        return [{"error": "nuclei binary not available"}]

    cmd = [
        nuclei_bin,
        "-u", url,
        "-t", "http/technologies/",          # ← only tech templates
        "-jsonl",
        "-silent",
        "-no-color",
        "-timeout", "3",
        "-rate-limit", "100",
        "-disable-update-check",
        "-no-interactsh",
    ]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=NUCLEI_SCAN_TIMEOUT, check=False,
        )

        findings: list[dict] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if proc.returncode != 0 and not findings:
            err = (proc.stderr or "unknown").strip()[:300]
            return [{"error": f"nuclei exit {proc.returncode}: {err}"}]
        return findings

    except subprocess.TimeoutExpired:
        return [{"error": f"nuclei timed out after {NUCLEI_SCAN_TIMEOUT}s"}]
    except Exception as e:
        return [{"error": str(e)}]
