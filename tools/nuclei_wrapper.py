"""Nuclei wrapper — safe templates only. Auto-downloads binary if needed."""
from __future__ import annotations
import json
import subprocess
from config import DEFAULT_TIMEOUT
from tools.nuclei_installer import get_nuclei_path

SAFE_EXCLUDE_TAGS = "dos,fuzz,intrusive,brute-force"


def nuclei_scan(url: str, severity: str = "low,medium,high,critical") -> list[dict]:
    """Run nuclei with a safe template filter and return JSON findings."""
    nuclei_bin = get_nuclei_path()
    if not nuclei_bin:
        return [{"error": "nuclei binary unavailable (download failed)"}]

    try:
        proc = subprocess.run(
            [
                nuclei_bin,
                "-u", url,
                "-severity", severity,
                "-exclude-tags", SAFE_EXCLUDE_TAGS,
                "-jsonl",
                "-silent",
                "-no-color",
                "-timeout", "5",
                "-rate-limit", "20",
                "-disable-update-check",
                "-no-interactsh",       # don't call external interactsh server
            ],
            capture_output=True,
            text=True,
            timeout=DEFAULT_TIMEOUT,
            check=False,
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
        return findings

    except subprocess.TimeoutExpired:
        return [{"error": "nuclei timed out"}]
    except Exception as e:  # noqa: BLE001
        return [{"error": str(e)}]
