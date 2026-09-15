"""Download the nuclei binary at runtime (for platforms without apt package)."""
from __future__ import annotations
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path

import requests

NUCLEI_VERSION = "3.3.7"  # pin a known-good release
BIN_DIR = Path.home() / ".local" / "bin"
NUCLEI_BIN = BIN_DIR / "nuclei"

# GitHub release URL pattern
_RELEASE_BASE = (
    f"https://github.com/projectdiscovery/nuclei/releases/download/"
    f"v{NUCLEI_VERSION}"
)


def _detect_asset_name() -> str:
    """Return the correct nuclei release asset for this platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        arch = "arm64" if machine in ("aarch64", "arm64") else "amd64"
        return f"nuclei_{NUCLEI_VERSION}_linux_{arch}.zip"
    if system == "darwin":
        arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
        return f"nuclei_{NUCLEI_VERSION}_macOS_{arch}.zip"
    if system == "windows":
        return f"nuclei_{NUCLEI_VERSION}_windows_amd64.zip"
    raise RuntimeError(f"Unsupported platform: {system}/{machine}")


def ensure_nuclei() -> str | None:
    """
    Ensure nuclei is available. Returns path to binary, or None on failure.
    Downloads it once if missing.
    """
    # Already in PATH?
    existing = shutil.which("nuclei")
    if existing:
        return existing

    # Already downloaded to ~/.local/bin?
    if NUCLEI_BIN.exists():
        return str(NUCLEI_BIN)

    # Try to download
    try:
        BIN_DIR.mkdir(parents=True, exist_ok=True)
        asset = _detect_asset_name()
        url = f"{_RELEASE_BASE}/{asset}"
        archive_path = BIN_DIR / asset

        # Download
        with requests.get(url, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(archive_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=65536):
                    f.write(chunk)

        # Extract
        if asset.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as z:
                for name in z.namelist():
                    if name.endswith("nuclei") or name.endswith("nuclei.exe"):
                        with z.open(name) as src, open(NUCLEI_BIN, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        break
        elif asset.endswith(".tar.gz"):
            with tarfile.open(archive_path, "r:gz") as t:
                for member in t.getmembers():
                    if member.name.endswith("nuclei"):
                        member.name = "nuclei"
                        t.extract(member, path=BIN_DIR)
                        break

        # chmod +x
        NUCLEI_BIN.chmod(
            NUCLEI_BIN.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )
        archive_path.unlink(missing_ok=True)

        # Sanity check
        subprocess.run(
            [str(NUCLEI_BIN), "-version"],
            capture_output=True, timeout=15, check=False,
        )
        return str(NUCLEI_BIN)

    except Exception:  # noqa: BLE001
        return None


def get_nuclei_path() -> str | None:
    """Convenience: PATH lookup or downloaded binary."""
    return shutil.which("nuclei") or (
        str(NUCLEI_BIN) if NUCLEI_BIN.exists() else ensure_nuclei()
    )
