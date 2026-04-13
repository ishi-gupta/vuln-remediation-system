"""
Observability Dashboard Backend — FastAPI server that provides:
- Real-time system metrics (scan results, remediation status, detection rates)
- API endpoints for the React frontend
- Serves static frontend files
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from automation.config import STATE_FILE, DATA_DIR, GITHUB_TOKEN, GITHUB_API_BASE, GITHUB_REPO
from automation.models import SystemState

import requests

app = FastAPI(
    title="Vulnerability Remediation Dashboard",
    description="Observability dashboard for the AI-assisted vulnerability remediation system",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Helper Functions ────────────────────────────────────────────────

def load_state() -> SystemState:
    return SystemState.load(str(STATE_FILE))


def get_github_issues(repo: str, token: str, labels: str = "security,automated") -> list[dict]:
    """Fetch issues from GitHub for live dashboard data."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    all_issues = []
    for state in ["open", "closed"]:
        page = 1
        while True:
            resp = requests.get(
                f"{GITHUB_API_BASE}/repos/{repo}/issues",
                headers=headers,
                params={"state": state, "labels": labels, "per_page": 100, "page": page},
            )
            if resp.status_code != 200:
                break
            issues = resp.json()
            if not issues:
                break
            all_issues.extend(issues)
            page += 1
    return all_issues


# ── API Routes ──────────────────────────────────────────────────────

@app.get("/api/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/metrics")
def get_metrics():
    """
    Main metrics endpoint — returns everything the dashboard needs.
    This is the single source of truth for the frontend.
    """
    state = load_state()

    # Aggregate scan runs
    total_scans = len(state.scan_runs)
    total_findings = sum(r.get("total_findings", 0) for r in state.scan_runs)
    total_critical = sum(r.get("critical", 0) for r in state.scan_runs)
    total_high = sum(r.get("high", 0) for r in state.scan_runs)
    total_medium = sum(r.get("medium", 0) for r in state.scan_runs)
    total_low = sum(r.get("low", 0) for r in state.scan_runs)

    # Remediation stats
    remediation_records = state.remediation_records
    fixed = sum(1 for r in remediation_records if r.get("status") == "fixed")
    partial = sum(1 for r in remediation_records if r.get("status") == "partial")
    failed = sum(1 for r in remediation_records if r.get("status") == "failed")
    in_progress = len(state.active_sessions)
    pending = total_findings - fixed - partial - failed - in_progress

    # Success rate
    completed = fixed + partial + failed
    success_rate = round((fixed / completed) * 100, 1) if completed > 0 else 0.0

    # Detection rate from adversarial tests (if available)
    adversarial_path = DATA_DIR / "adversarial_results.json"
    adversarial = {}
    if adversarial_path.exists():
        with open(adversarial_path) as f:
            adversarial = json.load(f)

    return {
        "overview": {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "issues_created": sum(r.get("issues_created", 0) for r in state.scan_runs),
            "active_sessions": in_progress,
            "success_rate": success_rate,
        },
        "severity_breakdown": {
            "critical": total_critical,
            "high": total_high,
            "medium": total_medium,
            "low": total_low,
        },
        "remediation_status": {
            "fixed": fixed,
            "partial": partial,
            "failed": failed,
            "in_progress": in_progress,
            "pending": max(0, pending),
        },
        "scan_history": state.scan_runs[-20:],  # Last 20 scans
        "recent_remediations": remediation_records[-20:],
        "adversarial_results": adversarial,
    }


@app.get("/api/findings")
def get_findings():
    """Get all findings from the latest scan."""
    state = load_state()
    return {"findings": state.findings}


@app.get("/api/issues")
def get_issues():
    """Get live issues from GitHub."""
    token = GITHUB_TOKEN
    repo = GITHUB_REPO
    if not token:
        return {"issues": [], "error": "GITHUB_TOKEN not set"}

    issues = get_github_issues(repo, token)

    simplified = []
    for issue in issues:
        labels = [l["name"] for l in issue.get("labels", [])]
        severity = "unknown"
        for s in ["critical", "high", "medium", "low"]:
            if s in labels:
                severity = s
                break

        scan_type = "unknown"
        for t in ["sast", "sca", "secret-detection"]:
            if t in labels:
                scan_type = t
                break

        simplified.append({
            "number": issue["number"],
            "title": issue["title"],
            "state": issue["state"],
            "severity": severity,
            "scan_type": scan_type,
            "labels": labels,
            "created_at": issue["created_at"],
            "closed_at": issue.get("closed_at"),
            "url": issue["html_url"],
            "has_remediation": "remediation-started" in labels,
            "remediation_failed": "remediation-failed" in labels,
        })

    return {"issues": simplified, "total": len(simplified)}


@app.get("/api/sessions")
def get_sessions():
    """Get active and completed Devin sessions."""
    state = load_state()
    return {
        "active": state.active_sessions,
        "completed": state.remediation_records,
    }


@app.get("/api/adversarial")
def get_adversarial_results():
    """Get adversarial test suite results."""
    adversarial_path = DATA_DIR / "adversarial_results.json"
    if not adversarial_path.exists():
        return {"results": None, "message": "No adversarial test results available yet."}

    with open(adversarial_path) as f:
        data = json.load(f)
    return {"results": data}


# ── Serve Frontend (production) ────────────────────────────────────

FRONTEND_DIR = Path(__file__).parent.parent / "dashboard" / "dist"

if FRONTEND_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIR / "assets")), name="assets")

    @app.get("/{path:path}")
    def serve_frontend(path: str):
        file_path = FRONTEND_DIR / path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(FRONTEND_DIR / "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
