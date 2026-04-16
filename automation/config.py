"""
Configuration for the Vulnerability Remediation System.
All secrets are read from environment variables — never hardcoded.
"""

import os
from pathlib import Path

# GitHub Configuration
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "ishi-gupta/superset")
ENGINE_REPO = os.environ.get("ENGINE_REPO", "ishi-gupta/vuln-remediation-system")
GITHUB_API_BASE = "https://api.github.com"

# Devin API Configuration
DEVIN_API_KEY = os.environ.get("DEVIN_API_KEY", "")
DEVIN_API_BASE = "https://api.devin.ai/v3"
DEVIN_ORG_ID = os.environ.get("DEVIN_ORG_ID", "")
DEVIN_PLAYBOOK_ID = os.environ.get(
    "DEVIN_PLAYBOOK_ID", "playbook-d0bb41a95a3e49a992ba4bd28fa09139"
)

# Scanning Configuration
MAX_ISSUES_PER_RUN = int(os.environ.get("MAX_ISSUES_PER_RUN", "50"))

# Dashboard Configuration
DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "8000"))

# Paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR.parent / "data"
STATE_FILE = DATA_DIR / "state.json"
REPORTS_DIR = DATA_DIR / "reports"

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Labels used for GitHub Issues
SEVERITY_LABELS = ["critical", "high", "medium", "low"]
SCAN_TYPE_LABELS = ["sast", "sca", "secret-detection", "container", "iac"]
SYSTEM_LABELS = ["security", "automated", "remediation-started", "remediation-failed"]

# Structured output schema for Devin sessions
STRUCTURED_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "issue_number": {"type": "integer"},
        "status": {
            "type": "string",
            "enum": ["fixed", "partial", "failed", "needs_review"],
        },
        "pr_url": {"type": "string"},
        "fix_description": {"type": "string"},
        "files_changed": {"type": "array", "items": {"type": "string"}},
        "tests_passed": {"type": "boolean"},
    },
    "required": ["issue_number", "status"],
}
