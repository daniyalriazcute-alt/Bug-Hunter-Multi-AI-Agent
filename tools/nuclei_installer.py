"""Download the nuclei binary + templates at runtime."""
from __future__ import annotations
import platform
import shutil
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path

import requests

from config import NUCLEI_TEMPLATE_TIMEOUT

NUCLEI_VERSION = "3.3.7"
BIN_DIR = Path.home() / ".local" / "bin"
NUCLEI_BIN = BIN_DIR / "nuclei"


def _github_latest_version() -> str | None:
    try:
        r = requests.get(
            "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest",
            timeout=20,
            headers={"Accept": "application/vnd.github+json"},
        )
        r.raise_for_status()
        return r.json().get("tag_name", "").lstrip("v") or None
    except Exception:
        return None


def _detect_asset_name(version: str) -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "linux":
        arch = "arm64" if machine in ("aarch64", "arm64") else "amd64"
        return f"nuclei_{version}_linux_{arch}.zip"
    if system == "darwin":
        arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
        return f"nuclei_{version}_macOS_{arch}.zip"
    if system == "windows":
        return f"nuclei_{version}_windows_amd64.zip"
    raise RuntimeError(f"Unsupported platform: {system}/{machine}")


def _download_and_extract(version: str) -> bool:
    asset = _detect_asset_name(version)
    url = (f"https://github.com/projectdiscovery/nuclei/releases/download/"
           f"v{version}/{asset}")
    archive_path = BIN_DIR / asset

    with requests.get(url, stream=True, timeout=120) as r:
        r.raise_for_status()
        with open(archive_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=65536):
                f.write(chunk)

    extracted = False
    if asset.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as z:
            for name in z.namelist():
                if name.endswith("nuclei") or name.endswith("nuclei.exe"):
                    with z.open(name) as src, open(NUCLEI_BIN, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    extracted = True
                    break
    archive_path.unlink(missing_ok=True)
    return extracted


def _ensure_templates(nuclei_path: str) -> bool:
    """Download nuclei templates (once). Returns True if templates are ready."""
    templates_dir = Path.home() / "nuclei-templates"
    # Fast path: templates already exist
    if templates_dir.exists() and any(templates_dir.glob("**/*.yaml")):
        return True

    try:
        proc = subprocess.run(
            [nuclei_path, "-update-templates", "-silent", "-no-color"],
            capture_output=True, text=True,
            timeout=NUCLEI_TEMPLATE_TIMEOUT, check=False,
        )
        return proc.returncode == 0 or templates_dir.exists()
    except Exception:
        return False


def ensure_nuclei() -> str | None:
    """Ensure nuclei binary + templates are available."""
    # Already in PATH?
    existing = shutil.which("nuclei")
    if existing:
        _ensure_templates(existing)  # idempotent
        return existing

    # Already downloaded?
    if NUCLEI_BIN.exists():
        _ensure_templates(str(NUCLEI_BIN))
        return str(NUCLEI_BIN)

    try:
        BIN_DIR.mkdir(parents=True, exist_ok=True)

        try:
            if not _download_and_extract(NUCLEI_VERSION):
                raise RuntimeError("extraction failed")
        except Exception:
            latest = _github_latest_version()
            if not latest or latest == NUCLEI_VERSION:
                return None
            if not _download_and_extract(latest):
                return None

        NUCLEI_BIN.chmod(
            NUCLEI_BIN.stat().st_mode
            | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )

        subprocess.run([str(NUCLEI_BIN), "-version"],
                       capture_output=True, timeout=15, check=False)

        # Download templates NOW (during app startup, not during first scan)
        _ensure_templates(str(NUCLEI_BIN))
        return str(NUCLEI_BIN)

    except Exception:
        return None


def get_nuclei_path() -> str | None:
    return shutil.which("nuclei") or (
        str(NUCLEI_BIN) if NUCLEI_BIN.exists() else ensure_nuclei()
    )
