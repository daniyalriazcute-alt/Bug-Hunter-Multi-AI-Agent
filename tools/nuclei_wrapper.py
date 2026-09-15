"""Nuclei wrapper — safe templates only. Assumes binary+templates are ready."""
from __future__ import annotations
import json
import subprocess
from config import NUCLEI_SCAN_TIMEOUT, NUCLEI_RATE_LIMIT
from tools.nuclei_installer import get_nuclei_path

SAFE_EXCLUDE_TAGS = "dos,fuzz,intrusive,brute-force"


def nuclei_scan(url: str, severity: str = "low,medium,high,critical") -> list[dict]:
    """Run nuclei. Returns finding dicts, or [{'error': ...}] on failure."""
    nuclei_bin = get_nuclei_path()
    if not nuclei_bin:
        return [{"error": "nuclei binary not available"}]

    cmd = [
        nuclei_bin,
        "-u", url,
        "-severity", severity,
        "-exclude-tags", SAFE_EXCLUDE_TAGS,
        "-jsonl",
        "-silent",
        "-no-color",
        "-timeout", "5",                    # per-request timeout
        "-rate-limit", str(NUCLEI_RATE_LIMIT),
        "-disable-update-check",
        "-no-interactsh",
        "-no-color",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NUCLEI_SCAN_TIMEOUT,
            check=False,
        )

        # Non-zero exit + no stdout = real failure
        if proc.returncode != 0 and not proc.stdout.strip():
            err = (proc.stderr or "unknown error").strip()[:300]
            return [{"error": f"nuclei exit {proc.returncode}: {err}"}]

        findings: list[dict] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return findings

    except subprocess.TimeoutExpired:
        return [{"error": f"nuclei timed out after {NUCLEI_SCAN_TIMEOUT}s"}]
    except Exception as e:
        return [{"error": str(e)}]
