"""Nuclei wrapper — safe templates only. Auto-downloads binary if needed."""
from __future__ import annotations
import json
import subprocess
from config import DEFAULT_TIMEOUT
from tools.nuclei_installer import get_nuclei_path

SAFE_EXCLUDE_TAGS = "dos,fuzz,intrusive,brute-force"


def nuclei_scan(url: str, severity: str = "low,medium,high,critical") -> list[dict]:
    """
    Run nuclei with a safe template filter.
    Returns:
      - List of finding dicts on success
      - [{"error": "..."}] on failure
    """
    nuclei_bin = get_nuclei_path()

    if not nuclei_bin:
        return [{"error": "nuclei binary not available (download failed)"}]

    # Quick version sanity check
    try:
        ver_proc = subprocess.run(
            [nuclei_bin, "-version"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if ver_proc.returncode not in (0, 1):  # nuclei returns 1 for -version sometimes
            return [{"error": f"nuclei -version exited with code {ver_proc.returncode}"}]
    except Exception as e:
        return [{"error": f"version check failed: {e}"}]

    # Ensure templates are present (download on first run)
    try:
        subprocess.run(
            [nuclei_bin, "-update-templates", "-silent", "-no-color"],
            capture_output=True, text=True, timeout=180, check=False,
        )
    except Exception:
        pass  # not fatal; nuclei will use any locally-available templates

    # Actual scan
    cmd = [
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
        "-no-interactsh",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=DEFAULT_TIMEOUT * 4,  # nuclei may be slower than other tools
            check=False,
        )

        # nuclei returns non-zero if any error occurred
        if proc.returncode != 0 and not proc.stdout.strip():
            err = (proc.stderr or "unknown error").strip()[:300]
            return [{"error": f"nuclei exit code {proc.returncode}: {err}"}]

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
    except Exception as e:
        return [{"error": str(e)}]
