"""Global configuration for Bug Hunter Multi-AI Agent system."""
from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ─── LLM ────────────────────────────────────────────────────────────────────
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
LLM_TEMPERATURE: float = 0.2
LLM_MAX_TOKENS: int = 4096
LLM_MAX_RETRIES: int = 4
LLM_BACKOFF_BASE: float = 1.5

# ─── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR: Path = Path(__file__).parent
REPORT_DIR: Path = BASE_DIR / os.getenv("REPORT_DIR", "reports")
REPORT_DIR.mkdir(exist_ok=True, parents=True)

# ─── Recon ──────────────────────────────────────────────────────────────────
MAX_RECON_PORTS: int = int(os.getenv("MAX_RECON_PORTS", "1000"))
DEFAULT_TIMEOUT: int = 30  # seconds per external tool call

# ─── Nuclei (specific timeouts) ─────────────────────────────────────────────
NUCLEI_TEMPLATE_TIMEOUT: int = int(os.getenv("NUCLEI_TEMPLATE_TIMEOUT", "300"))
NUCLEI_SCAN_TIMEOUT: int = int(os.getenv("NUCLEI_SCAN_TIMEOUT", "120"))
NUCLEI_RATE_LIMIT: int = int(os.getenv("NUCLEI_RATE_LIMIT", "150"))

# ─── Severity mapping (CVSS v3.1) ───────────────────────────────────────────
SEVERITY_RANGES = {
    "Critical": (9.0, 10.0),
    "High":     (7.0, 8.9),
    "Medium":   (4.0, 6.9),
    "Low":      (0.1, 3.9),
    "Info":     (0.0, 0.0),
}

SEVERITY_COLORS = {
    "Critical": "#7B1FA2",
    "High":     "#D32F2F",
    "Medium":   "#F57C00",
    "Low":      "#FBC02D",
    "Info":     "#0288D1",
}

# ─── Safety ─────────────────────────────────────────────────────────────────
LEGAL_BANNER: str = (
    "⚠️ LEGAL NOTICE: Only test systems you own or have explicit written "
    "permission to test. Unauthorized access is illegal."
)

FORBIDDEN_PAYLOAD_PATTERNS = [
    "rm -rf", "mkfs", "dd if=", "shutdown", "reboot",
    ":(){:|:&};:", "DROP TABLE", "DELETE FROM",
    "fork bomb", "nc -e", "/etc/shadow", "/etc/passwd",
    "cmd.exe", "powershell -enc",
]

RATE_LIMIT_SECONDS: float = 1.5
