"""
Observability Dashboard — FastAPI backend for the Vulnerability Remediation System.

Serves API endpoints for metrics, findings, issues, sessions, and adversarial results,
plus the built React frontend from dashboard/dist/.
"""

import json
import logging
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from automation.config import (
    DATA_DIR,
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    DEVIN_API_KEY,
    DEVIN_API_BASE,
    GITHUB_API_BASE,
    GITHUB_REPO,
    GITHUB_TOKEN,
    STATE_FILE,
)
from automation.models import SystemState, RemediationRecord, RemediationStatus

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
# In-memory job tracker (for background scan / adversarial tasks)
# ---------------------------------------------------------------------------

_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()


def _create_job(job_type: str) -> str:
    """Create a new tracked job and return its ID."""
    job_id = f"{job_type}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    with _jobs_lock:
        _jobs[job_id] = {
            "id": job_id,
            "type": job_type,
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "result": None,
            "error": None,
            "logs": [],
        }
    return job_id


def _update_job(job_id: str, **kwargs: Any) -> None:
    """Update a job's fields."""
    with _jobs_lock:
        if job_id in _jobs:
            _jobs[job_id].update(kwargs)


def _log_job(job_id: str, message: str) -> None:
    """Append a log line to a job."""
    with _jobs_lock:
        if job_id in _jobs:
            _jobs[job_id]["logs"].append({
                "time": datetime.now(timezone.utc).isoformat(),
                "message": message,
            })


def _finish_job(job_id: str, status: str = "completed", result: Any = None, error: str | None = None) -> None:
    """Mark a job as finished."""
    with _jobs_lock:
        if job_id in _jobs:
            _jobs[job_id]["status"] = status
            _jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
            _jobs[job_id]["result"] = result
            _jobs[job_id]["error"] = error


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
    """Load adversarial test results from disk."""
    try:
        with open(ADVERSARIAL_RESULTS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


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
# Action Endpoints — trigger scan, adversarial, and orchestration
# ---------------------------------------------------------------------------

@app.get("/api/jobs")
async def get_jobs() -> dict[str, Any]:
    """Return all tracked background jobs."""
    with _jobs_lock:
        return {"jobs": list(_jobs.values())}


def _run_scan_background(job_id: str, repo: str) -> None:
    """Background thread: scan a repo, persist findings, create issues."""
    try:
        from automation.scanner import scan_repo
        from automation.issue_creator import create_github_issues

        _log_job(job_id, f"Cloning and scanning {repo}...")
        findings, scan_run = scan_repo(repo)
        _log_job(job_id, f"Scan complete: {scan_run.total_findings} findings ({scan_run.duration_seconds:.1f}s)")

        # Persist to state.json
        state = _load_state()
        state.scan_runs.append(scan_run.to_dict())
        existing_ids = {f.get("finding_id") for f in state.findings}
        new_count = 0
        for finding in findings:
            fd = finding.to_dict()
            if fd["finding_id"] not in existing_ids:
                state.findings.append(fd)
                existing_ids.add(fd["finding_id"])
                new_count += 1
        state.save(str(STATE_FILE))
        _log_job(job_id, f"Persisted {new_count} new findings to state.json")

        # Create GitHub issues
        issues_created = []
        if GITHUB_TOKEN and findings:
            _log_job(job_id, "Creating GitHub issues...")
            issues_created = create_github_issues(findings, repo=repo)
            _log_job(job_id, f"Created {len(issues_created)} GitHub issues")

            # Persist remediation records
            if issues_created:
                state = _load_state()
                existing_issue_numbers = {
                    r.get("issue_number") for r in state.remediation_records
                }
                for issue in issues_created:
                    if issue["issue_number"] not in existing_issue_numbers:
                        record = RemediationRecord(
                            finding_id=issue["finding_id"],
                            issue_number=issue["issue_number"],
                            issue_url=issue["issue_url"],
                            status=RemediationStatus.PENDING,
                        )
                        state.remediation_records.append(record.to_dict())
                        existing_issue_numbers.add(issue["issue_number"])
                state.save(str(STATE_FILE))
        else:
            _log_job(job_id, "Skipping issue creation (no GITHUB_TOKEN or no findings)")

        _finish_job(job_id, status="completed", result={
            "total_findings": scan_run.total_findings,
            "critical": scan_run.critical,
            "high": scan_run.high,
            "medium": scan_run.medium,
            "low": scan_run.low,
            "new_findings": new_count,
            "issues_created": len(issues_created),
        })
    except Exception as e:
        logger.exception("Scan job %s failed", job_id)
        _finish_job(job_id, status="failed", error=str(e))


@app.post("/api/scan")
async def trigger_scan() -> dict[str, Any]:
    """Trigger a vulnerability scan of the target repo in the background."""
    repo = GITHUB_REPO
    if not repo:
        return JSONResponse(status_code=400, content={"error": "GITHUB_REPO not configured"})

    job_id = _create_job("scan")
    thread = threading.Thread(target=_run_scan_background, args=(job_id, repo), daemon=True)
    thread.start()

    return {"job_id": job_id, "status": "running", "repo": repo}


def _run_orchestrator_background(job_id: str, repo: str) -> None:
    """Background thread: fetch open security issues and trigger Devin sessions."""
    try:
        from automation.orchestrator import trigger_remediation

        _log_job(job_id, f"Fetching open security issues from {repo}...")

        # Fetch open issues with security+automated labels
        issues: list[dict[str, Any]] = []
        page = 1
        while True:
            resp = requests.get(
                f"{GITHUB_API_BASE}/repos/{repo}/issues",
                headers=_github_headers(),
                params={"state": "open", "labels": "security,automated", "per_page": 100, "page": page},
                timeout=15,
            )
            resp.raise_for_status()
            batch = resp.json()
            if not batch:
                break
            issues.extend(batch)
            if len(batch) < 100:
                break
            page += 1

        # Filter out issues that already have remediation started
        actionable = [
            i for i in issues
            if not any(l["name"] == "remediation-started" for l in i.get("labels", []))
        ]
        _log_job(job_id, f"Found {len(issues)} security issues, {len(actionable)} need remediation")

        if not actionable:
            _finish_job(job_id, status="completed", result={"sessions_created": 0, "message": "No issues need remediation"})
            return

        sessions_created = 0
        state = _load_state()

        for issue in actionable[:5]:  # Cap at 5 concurrent
            _log_job(job_id, f"Triggering Devin session for issue #{issue['number']}: {issue['title'][:60]}")
            record = trigger_remediation(
                issue=issue,
                repo=repo,
                token=GITHUB_TOKEN,
                api_key=DEVIN_API_KEY,
            )
            if record:
                state.active_sessions.append(record.to_dict())
                sessions_created += 1
                _log_job(job_id, f"  → Session created: {record.devin_session_id}")
            else:
                _log_job(job_id, f"  → Failed to create session for issue #{issue['number']}")

        state.save(str(STATE_FILE))
        _finish_job(job_id, status="completed", result={"sessions_created": sessions_created})

    except Exception as e:
        logger.exception("Orchestrator job %s failed", job_id)
        _finish_job(job_id, status="failed", error=str(e))


@app.post("/api/orchestrate")
async def trigger_orchestration() -> dict[str, Any]:
    """Trigger Devin remediation sessions for open security issues."""
    if not DEVIN_API_KEY:
        return JSONResponse(status_code=400, content={"error": "DEVIN_API_KEY not configured"})
    if not GITHUB_TOKEN:
        return JSONResponse(status_code=400, content={"error": "GITHUB_TOKEN not configured"})

    repo = GITHUB_REPO
    job_id = _create_job("orchestrate")
    thread = threading.Thread(target=_run_orchestrator_background, args=(job_id, repo), daemon=True)
    thread.start()

    return {"job_id": job_id, "status": "running", "repo": repo}


def _run_adversarial_background(job_id: str, repo: str) -> None:
    """Background thread: generate buggy PRs on the target repo via Devin."""
    try:
        from automation.adversarial_generator import (
            create_adversarial_session,
            generate_round_id,
            SCANNER_CAPABILITIES,
        )

        round_id = generate_round_id()
        _log_job(job_id, f"Starting adversarial generation (round {round_id})")
        _log_job(job_id, f"Target repo: {repo}")
        _log_job(job_id, f"Categories: {', '.join(SCANNER_CAPABILITIES.keys())}")

        session_record = create_adversarial_session(
            round_id=round_id,
            num_files=3,
            api_key=DEVIN_API_KEY,
        )

        if session_record:
            _log_job(job_id, f"Devin session created: {session_record.get('session_url', 'N/A')}")
            _finish_job(job_id, status="completed", result={
                "round_id": round_id,
                "session_id": session_record.get("session_id"),
                "session_url": session_record.get("session_url"),
                "categories": list(SCANNER_CAPABILITIES.keys()),
            })
        else:
            _finish_job(job_id, status="failed", error="Failed to create Devin session. Check DEVIN_API_KEY.")

    except Exception as e:
        logger.exception("Adversarial job %s failed", job_id)
        _finish_job(job_id, status="failed", error=str(e))


@app.post("/api/adversarial/generate")
async def trigger_adversarial() -> dict[str, Any]:
    """Trigger adversarial buggy PR generation via Devin."""
    if not DEVIN_API_KEY:
        return JSONResponse(status_code=400, content={"error": "DEVIN_API_KEY not configured"})

    repo = GITHUB_REPO
    job_id = _create_job("adversarial")
    thread = threading.Thread(target=_run_adversarial_background, args=(job_id, repo), daemon=True)
    thread.start()

    return {"job_id": job_id, "status": "running", "repo": repo}


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
