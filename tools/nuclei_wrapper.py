"""Nuclei wrapper — fast safe-mode scan using targeted templates."""
from __future__ import annotations
import json
import subprocess
from config import NUCLEI_SCAN_TIMEOUT, NUCLEI_RATE_LIMIT
from tools.nuclei_installer import get_nuclei_path

# Only run these fast, high-signal template categories
NUCLEI_TAGS = ",".join([
    "cve",              # Known CVEs
    "exposure",         # Exposed files / misconfigs
    "misconfig",        # Misconfigurations
    "default-login",    # Default credentials
    "tech",             # Technology detection
    "xss",              # Cross-site scripting
    "sqli",             # SQL injection
])

# Aggressive templates to skip entirely
SAFE_EXCLUDE_TAGS = "dos,fuzz,intrusive,brute-force,headless"


def nuclei_scan(url: str, severity: str = "low,medium,high,critical") -> list[dict]:
    """Run a fast nuclei scan with a curated template subset."""
    nuclei_bin = get_nuclei_path()
    if not nuclei_bin:
        return [{"error": "nuclei binary not available"}]

    cmd = [
        nuclei_bin,
        "-u", url,
        "-severity", severity,
        "-tags", NUCLEI_TAGS,
        "-exclude-tags", SAFE_EXCLUDE_TAGS,
        "-jsonl",
        "-silent",
        "-no-color",
        "-timeout", "3",                       # per-request timeout (fast)
        "-retries", "1",                       # one retry max
        "-rate-limit", str(NUCLEI_RATE_LIMIT),
        "-bulk-size", "25",                    # parallel requests
        "-concurrency", "25",                  # parallel templates
        "-disable-update-check",
        "-no-interactsh",
        "-stats",                              # print stats to stderr
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NUCLEI_SCAN_TIMEOUT,
            check=False,
        )

        if proc.returncode != 0 and not proc.stdout.strip():
            err = (proc.stderr or "unknown").strip()[:300]
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
        return [{
            "error": f"nuclei timed out after {NUCLEI_SCAN_TIMEOUT}s "
                     f"(try reducing templates or increasing timeout)"
        }]
    except Exception as e:
        return [{"error": str(e)}]
