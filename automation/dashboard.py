"""
Observability Dashboard — FastAPI backend for the Vulnerability Remediation System.

Serves API endpoints for metrics, findings, issues, sessions, and adversarial results,
plus the built React frontend from dashboard/dist/.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from automation.config import (
    DATA_DIR,
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    GITHUB_API_BASE,
    GITHUB_REPO,
    GITHUB_TOKEN,
    STATE_FILE,
)
from automation.models import SystemState

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Vulnerability Remediation Dashboard",
    description="Observability dashboard for the vulnerability remediation system",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).parent.parent / "dashboard" / "dist"
ADVERSARIAL_RESULTS_FILE = DATA_DIR / "adversarial_results.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_state() -> SystemState:
    """Load the current system state from disk."""
    return SystemState.load(str(STATE_FILE))


def _github_headers() -> dict[str, str]:
    """Build headers for GitHub API requests."""
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


def _fetch_github_issues() -> list[dict[str, Any]]:
    """Fetch issues from the target GitHub repo."""
    if not GITHUB_TOKEN:
        return []

    issues: list[dict[str, Any]] = []
    page = 1
    per_page = 100

    while True:
        url = f"{GITHUB_API_BASE}/repos/{GITHUB_REPO}/issues"
        params = {
            "state": "all",
            "labels": "security,automated",
            "per_page": per_page,
            "page": page,
        }
        try:
            resp = requests.get(url, headers=_github_headers(), params=params, timeout=15)
            resp.raise_for_status()
            batch = resp.json()
        except Exception:
            logger.exception("Failed to fetch GitHub issues (page %d)", page)
            break

        if not batch:
            break

        for raw in batch:
            labels = [l["name"] for l in raw.get("labels", [])]
            severity = "medium"
            for sev in ("critical", "high", "medium", "low"):
                if sev in labels:
                    severity = sev
                    break

            scan_type = "sast"
            for st in ("sast", "sca", "secret-detection", "container", "iac"):
                if st in labels:
                    scan_type = st
                    break

            issues.append({
                "number": raw["number"],
                "title": raw["title"],
                "state": raw["state"],
                "severity": severity,
                "scan_type": scan_type,
                "labels": labels,
                "created_at": raw["created_at"],
                "closed_at": raw.get("closed_at"),
                "url": raw["html_url"],
                "has_remediation": "remediation-started" in labels,
                "remediation_failed": "remediation-failed" in labels,
            })

        if len(batch) < per_page:
            break
        page += 1

    return issues


def _load_adversarial_results() -> dict[str, Any]:
    """Load adversarial test results from disk and normalize to frontend format.

    The frontend expects:
      - overall_detection_rate: float (0.0–1.0+)
      - categories: list of {name, total, detected, missed, rate}

    The raw file may use:
      - summary.overall_detection_rate_pct (percentage)
      - categories as a dict keyed by category name
    """
    try:
        with open(ADVERSARIAL_RESULTS_FILE) as f:
            raw = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

    # Already in frontend format
    if "overall_detection_rate" in raw and isinstance(raw.get("categories"), list):
        return raw

    # Transform from raw test-harness format
    summary = raw.get("summary", {})
    cats_raw = raw.get("categories", {})

    overall_pct = summary.get("overall_detection_rate_pct", 0)
    overall_rate = overall_pct / 100.0  # convert 233.3 → 2.333

    categories: list[dict[str, Any]] = []
    if isinstance(cats_raw, dict):
        for name, info in cats_raw.items():
            expected = info.get("expected_total", 0)
            detected = info.get("detected", 0)
            missed = max(0, expected - detected)
            rate = (info.get("detection_rate_pct", 0)) / 100.0
            display_name = name.replace("_", " ").title()
            categories.append({
                "name": display_name,
                "total": expected,
                "detected": detected,
                "missed": missed,
                "rate": rate,
            })

    return {
        "overall_detection_rate": overall_rate,
        "categories": categories,
    }


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/metrics")
async def metrics() -> dict[str, Any]:
    state = _load_state()

    total_scans = len(state.scan_runs)
    total_findings = len(state.findings)
    issues_created = sum(r.get("issue_number", 0) > 0 for r in state.remediation_records)
    active_sessions = len([s for s in state.active_sessions if s.get("status") == "in_progress"])

    # Severity breakdown from findings
    severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in state.findings:
        sev = f.get("severity", "medium")
        if sev in severity_breakdown:
            severity_breakdown[sev] += 1

    # Remediation status
    remediation_status = {"fixed": 0, "partial": 0, "failed": 0, "in_progress": 0, "pending": 0}
    for r in state.remediation_records:
        status = r.get("status", "pending")
        if status in remediation_status:
            remediation_status[status] += 1

    # Success rate
    total_remediations = sum(remediation_status.values())
    success_rate = 0.0
    if total_remediations > 0:
        success_rate = round((remediation_status["fixed"] / total_remediations) * 100, 1)

    # Scan history
    scan_history = []
    for run in state.scan_runs:
        scan_history.append({
            "scan_id": run.get("scan_id", ""),
            "timestamp": run.get("timestamp", ""),
            "total_findings": run.get("total_findings", 0),
            "critical": run.get("critical", 0),
            "high": run.get("high", 0),
            "medium": run.get("medium", 0),
            "low": run.get("low", 0),
        })

    # Recent remediations (last 10)
    recent_remediations = sorted(
        state.remediation_records,
        key=lambda r: r.get("updated_at", ""),
        reverse=True,
    )[:10]

    adversarial_results = _load_adversarial_results()

    return {
        "overview": {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "issues_created": issues_created,
            "active_sessions": active_sessions,
            "success_rate": success_rate,
        },
        "severity_breakdown": severity_breakdown,
        "remediation_status": remediation_status,
        "scan_history": scan_history,
        "recent_remediations": recent_remediations,
        "adversarial_results": adversarial_results,
    }


@app.get("/api/findings")
async def findings() -> dict[str, Any]:
    state = _load_state()
    return {"findings": state.findings}


@app.get("/api/issues")
async def issues() -> dict[str, Any]:
    issue_list = _fetch_github_issues()
    return {"issues": issue_list}


@app.get("/api/sessions")
async def sessions() -> dict[str, Any]:
    state = _load_state()
    return {"sessions": state.active_sessions}


@app.get("/api/adversarial")
async def adversarial() -> dict[str, Any]:
    results = _load_adversarial_results()
    if not results:
        return {
            "message": "No adversarial test results available yet. Run the adversarial test suite to generate results.",
            "results": {},
        }
    return {"results": results}


# ---------------------------------------------------------------------------
# Frontend serving
# ---------------------------------------------------------------------------

if FRONTEND_DIR.exists():
    # Serve static assets (JS, CSS, images)
    assets_dir = FRONTEND_DIR / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str) -> FileResponse:
        """Catch-all route — serve index.html for SPA routing."""
        file_path = (FRONTEND_DIR / full_path).resolve()
        if file_path.is_file() and file_path.is_relative_to(FRONTEND_DIR.resolve()):
            return FileResponse(str(file_path))
        return FileResponse(str(FRONTEND_DIR / "index.html"))
