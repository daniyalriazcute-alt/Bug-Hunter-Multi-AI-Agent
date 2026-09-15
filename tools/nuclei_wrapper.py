"""Nuclei wrapper — safe templates only."""
from __future__ import annotations
import json
import shutil
import subprocess
from config import DEFAULT_TIMEOUT

SAFE_EXCLUDE_TAGS = "dos,fuzz,intrusive,brute-force"

def nuclei_scan(url: str, severity: str = "low,medium,high,critical") -> list[dict]:
    if not shutil.which("nuclei"):
        return [{"error": "nuclei binary not found in PATH"}]
    try:
        proc = subprocess.run(
            ["nuclei", "-u", url, "-severity", severity,
             "-exclude-tags", SAFE_EXCLUDE_TAGS,
             "-jsonl", "-silent", "-no-color", "-timeout", "5",
             "-rate-limit", "20"],
            capture_output=True, text=True, timeout=DEFAULT_TIMEOUT, check=False,
        )
        findings = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return findings
    except Exception as e:
        return [{"error": str(e)}]
