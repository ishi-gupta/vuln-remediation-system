"""
Observability Dashboard — FastAPI backend for the Vulnerability Remediation System.

Serves API endpoints for metrics, findings, issues, sessions, and adversarial results,
plus the built React frontend from dashboard/dist/.
"""

import copy
import json
import logging
import threading
import uuid
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
    ENGINE_REPO,
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
    job_id = f"{job_type}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
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
# State file lock (prevents concurrent read-modify-write corruption)
# ---------------------------------------------------------------------------

_state_lock = threading.Lock()

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
            "state": "open",
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

    if not isinstance(raw, dict):
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
# Action Endpoints — trigger scan, adversarial, and orchestration
# ---------------------------------------------------------------------------

@app.get("/api/jobs")
async def get_jobs() -> dict[str, Any]:
    """Return all tracked background jobs."""
    with _jobs_lock:
        return {"jobs": copy.deepcopy(list(_jobs.values()))}


def _run_scan_background(job_id: str, repo: str) -> None:
    """Background thread: trigger the scan.yml GitHub Action and poll for completion."""
    try:
        import time as _time

        engine_repo = ENGINE_REPO
        workflow_file = "scan.yml"
        headers = _github_headers()

        # 1. Trigger the scan workflow via workflow_dispatch
        _log_job(job_id, f"Triggering scan workflow on {engine_repo} for target {repo}...")
        dispatch_resp = requests.post(
            f"{GITHUB_API_BASE}/repos/{engine_repo}/actions/workflows/{workflow_file}/dispatches",
            headers=headers,
            json={"ref": "main", "inputs": {"target_repo": repo}},
            timeout=15,
        )
        if dispatch_resp.status_code not in (204,):
            raise RuntimeError(
                f"Failed to trigger scan workflow: HTTP {dispatch_resp.status_code} — {dispatch_resp.text[:300]}"
            )
        _log_job(job_id, "Scan workflow triggered successfully")

        # 2. Wait briefly for GitHub to register the run, then find it
        _time.sleep(5)
        run_id = None
        for _attempt in range(10):
            runs_resp = requests.get(
                f"{GITHUB_API_BASE}/repos/{engine_repo}/actions/workflows/{workflow_file}/runs",
                headers=headers,
                params={"per_page": 5, "event": "workflow_dispatch"},
                timeout=15,
            )
            if runs_resp.status_code == 200:
                runs = runs_resp.json().get("workflow_runs", [])
                for run in runs:
                    if run["status"] in ("queued", "in_progress"):
                        run_id = run["id"]
                        break
                if run_id:
                    break
            _time.sleep(3)

        if not run_id:
            raise RuntimeError("Could not find the triggered workflow run")

        run_url = f"https://github.com/{engine_repo}/actions/runs/{run_id}"
        _log_job(job_id, f"Workflow run started: {run_url}")

        # 3. Poll until the workflow completes
        poll_interval = 15
        max_polls = 120  # up to 30 minutes
        for _poll in range(max_polls):
            _time.sleep(poll_interval)
            status_resp = requests.get(
                f"{GITHUB_API_BASE}/repos/{engine_repo}/actions/runs/{run_id}",
                headers=headers,
                timeout=15,
            )
            if status_resp.status_code != 200:
                _log_job(job_id, f"Warning: failed to poll run status (HTTP {status_resp.status_code})")
                continue

            run_data = status_resp.json()
            status = run_data.get("status", "unknown")
            conclusion = run_data.get("conclusion")

            if status == "completed":
                if conclusion == "success":
                    _log_job(job_id, "Scan workflow completed successfully")
                    _log_job(job_id, f"Results: {run_url}")
                    _finish_job(job_id, status="completed", result={
                        "workflow_run_id": run_id,
                        "workflow_url": run_url,
                        "conclusion": conclusion,
                    })
                else:
                    _log_job(job_id, f"Scan workflow finished with conclusion: {conclusion}")
                    _finish_job(job_id, status="failed", error=f"Workflow conclusion: {conclusion}", result={
                        "workflow_run_id": run_id,
                        "workflow_url": run_url,
                        "conclusion": conclusion,
                    })
                return

            _log_job(job_id, f"Workflow status: {status} (polling...)")

        # Timed out
        _finish_job(job_id, status="failed", error="Timed out waiting for workflow to complete", result={
            "workflow_run_id": run_id,
            "workflow_url": run_url,
        })

    except Exception as e:
        logger.exception("Scan job %s failed", job_id)
        _finish_job(job_id, status="failed", error=str(e))


@app.post("/api/scan")
async def trigger_scan() -> dict[str, Any]:
    """Trigger a vulnerability scan via the scan.yml GitHub Action."""
    repo = GITHUB_REPO
    if not repo:
        return JSONResponse(status_code=400, content={"error": "GITHUB_REPO not configured"})
    if not GITHUB_TOKEN:
        return JSONResponse(status_code=400, content={"error": "GITHUB_TOKEN not configured"})

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
        records = []

        # Perform network I/O outside the lock to avoid starving other jobs
        for issue in actionable[:5]:  # Cap at 5 concurrent
            _log_job(job_id, f"Triggering Devin session for issue #{issue['number']}: {issue['title'][:60]}")
            record = trigger_remediation(
                issue=issue,
                repo=repo,
                token=GITHUB_TOKEN,
                api_key=DEVIN_API_KEY,
            )
            if record:
                records.append(record)
                sessions_created += 1
                _log_job(job_id, f"  → Session created: {record.devin_session_id}")
            else:
                _log_job(job_id, f"  → Failed to create session for issue #{issue['number']}")

        # Brief lock only for state persistence
        if records:
            with _state_lock:
                state = _load_state()
                for record in records:
                    state.active_sessions.append(record.to_dict())
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
    if not repo:
        return JSONResponse(status_code=400, content={"error": "GITHUB_REPO not configured"})
    job_id = _create_job("orchestrate")
    thread = threading.Thread(target=_run_orchestrator_background, args=(job_id, repo), daemon=True)
    thread.start()

    return {"job_id": job_id, "status": "running", "repo": repo}


def _run_adversarial_background(job_id: str, repo: str) -> None:
    """Background thread: generate buggy PRs on the target repo via Devin."""
    try:
        from automation.adversarial_generator import (
            VULNERABILITY_CATEGORIES,
            plan_bugs,
            spawn_baby_devins,
        )

        categories = list(VULNERABILITY_CATEGORIES.keys())
        _log_job(job_id, f"Starting adversarial generation for {repo}")
        _log_job(job_id, f"Categories: {', '.join(categories)}")

        # Plan 3 bugs across all categories
        bug_specs = plan_bugs(categories=categories, count=3, target_repo=repo)
        _log_job(job_id, f"Planned {len(bug_specs)} adversarial bugs")

        for spec in bug_specs:
            _log_job(job_id, f"  → {spec['bug_id']}: {spec['category']} / {spec['pattern_name']}")

        # Spawn Baby Devin sessions to plant the bugs
        sessions = spawn_baby_devins(bug_specs, api_key=DEVIN_API_KEY, max_concurrent=5)

        spawned = [s for s in sessions if s["status"] == "spawned"]
        failed = [s for s in sessions if s["status"] == "failed_to_spawn"]

        for s in spawned:
            _log_job(job_id, f"Session spawned: {s['bug_id']} → {s.get('session_url', 'N/A')}")
        for s in failed:
            _log_job(job_id, f"Session failed: {s['bug_id']}")

        if spawned:
            _finish_job(job_id, status="completed", result={
                "bugs_planned": len(bug_specs),
                "sessions_spawned": len(spawned),
                "sessions_failed": len(failed),
                "sessions": spawned,
                "categories": categories,
            })
        else:
            _finish_job(job_id, status="failed", error="No Devin sessions could be created. Check DEVIN_API_KEY.")

    except Exception as e:
        logger.exception("Adversarial job %s failed", job_id)
        _finish_job(job_id, status="failed", error=str(e))


@app.post("/api/adversarial/generate")
async def trigger_adversarial() -> dict[str, Any]:
    """Trigger adversarial buggy PR generation via Devin."""
    if not DEVIN_API_KEY:
        return JSONResponse(status_code=400, content={"error": "DEVIN_API_KEY not configured"})

    repo = GITHUB_REPO
    if not repo:
        return JSONResponse(status_code=400, content={"error": "GITHUB_REPO not configured"})
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
