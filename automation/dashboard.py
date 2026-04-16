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

# ---------------------------------------------------------------------------
# In-memory job tracker (for background scan tasks)
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


def _fetch_github_issues(state: str = "all") -> list[dict[str, Any]]:
    """Fetch issues from the target GitHub repo.

    Args:
        state: Issue state filter — "open", "closed", or "all" (default).
    """
    if not GITHUB_TOKEN:
        return []

    issues: list[dict[str, Any]] = []
    page = 1
    per_page = 100

    while True:
        url = f"{GITHUB_API_BASE}/repos/{GITHUB_REPO}/issues"
        params = {
            "state": state,
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


def _fetch_scan_workflow_runs(limit: int = 50) -> list[dict[str, Any]]:
    """Fetch scan.yml workflow runs from GitHub Actions API.

    Each run represents a scan execution.  Returns newest-first.
    """
    if not GITHUB_TOKEN:
        return []

    runs: list[dict[str, Any]] = []
    page = 1
    per_page = min(limit, 100)

    while len(runs) < limit:
        url = f"{GITHUB_API_BASE}/repos/{ENGINE_REPO}/actions/workflows/scan.yml/runs"
        params = {"per_page": per_page, "page": page}
        try:
            resp = requests.get(url, headers=_github_headers(), params=params, timeout=15)
            resp.raise_for_status()
            batch = resp.json().get("workflow_runs", [])
        except Exception:
            logger.exception("Failed to fetch workflow runs (page %d)", page)
            break

        if not batch:
            break

        for run in batch:
            runs.append({
                "run_id": run["id"],
                "status": run["status"],
                "conclusion": run.get("conclusion"),
                "created_at": run["created_at"],
                "updated_at": run["updated_at"],
                "event": run.get("event", ""),
                "url": run["html_url"],
            })
            if len(runs) >= limit:
                break

        if len(batch) < per_page:
            break
        page += 1

    return runs


def _derive_scan_history(all_issues: list[dict[str, Any]], workflow_runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Derive scan history by matching workflow runs with issues created around that time.

    Groups issues by the hour they were created to approximate per-scan severity
    breakdowns, then matches each group to the nearest workflow run.
    """
    from collections import defaultdict

    # Group issues by creation hour (YYYY-MM-DD HH)
    hour_buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for issue in all_issues:
        created = issue.get("created_at", "")
        if len(created) >= 13:
            hour_key = created[:13]  # "2026-04-15T19" → bucket by hour
            hour_buckets[hour_key].append(issue)

    # Build scan history entries from workflow runs
    scan_history: list[dict[str, Any]] = []

    # If we have workflow runs, use them as the timeline and attach severity counts
    if workflow_runs:
        for run in workflow_runs:
            if run.get("conclusion") != "success":
                continue

            run_created = run.get("created_at", "")
            run_hour = run_created[:13] if len(run_created) >= 13 else ""

            # Find issues created within the same hour as this run
            matched_issues = hour_buckets.get(run_hour, [])

            # Also check the next hour (scan may take a few minutes)
            if run_hour:
                try:
                    dt = datetime.fromisoformat(run_created.replace("Z", "+00:00"))
                    from datetime import timedelta
                    next_hour = (dt + timedelta(hours=1)).isoformat()[:13]
                    matched_issues = matched_issues + hour_buckets.get(next_hour, [])
                except (ValueError, TypeError):
                    pass

            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for issue in matched_issues:
                sev = issue.get("severity", "medium")
                if sev in severity_counts:
                    severity_counts[sev] += 1

            scan_history.append({
                "scan_id": str(run.get("run_id", "")),
                "timestamp": run_created,
                "total_findings": len(matched_issues),
                **severity_counts,
            })
    else:
        # Fallback: derive scan runs purely from issue creation date clusters
        for hour_key in sorted(hour_buckets.keys()):
            bucket = hour_buckets[hour_key]
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for issue in bucket:
                sev = issue.get("severity", "medium")
                if sev in severity_counts:
                    severity_counts[sev] += 1

            scan_history.append({
                "scan_id": hour_key,
                "timestamp": bucket[0].get("created_at", ""),
                "total_findings": len(bucket),
                **severity_counts,
            })

    # Sort chronologically (oldest first for chart display)
    scan_history.sort(key=lambda x: x.get("timestamp", ""))
    return scan_history


def _fetch_pull_requests(state: str = "all", limit: int = 100) -> list[dict[str, Any]]:
    """Fetch pull requests from the target Superset repo."""
    if not GITHUB_TOKEN:
        return []

    prs: list[dict[str, Any]] = []
    page = 1
    per_page = min(limit, 100)

    while len(prs) < limit:
        url = f"{GITHUB_API_BASE}/repos/{GITHUB_REPO}/pulls"
        params = {"state": state, "per_page": per_page, "page": page}
        try:
            resp = requests.get(url, headers=_github_headers(), params=params, timeout=15)
            resp.raise_for_status()
            batch = resp.json()
        except Exception:
            logger.exception("Failed to fetch PRs (page %d)", page)
            break

        if not batch:
            break

        for pr in batch:
            prs.append({
                "number": pr["number"],
                "title": pr["title"],
                "state": pr["state"],
                "merged": pr.get("merged_at") is not None,
                "branch": pr["head"]["ref"],
                "url": pr["html_url"],
                "created_at": pr["created_at"],
                "updated_at": pr["updated_at"],
                "merged_at": pr.get("merged_at"),
            })
            if len(prs) >= limit:
                break

        if len(batch) < per_page:
            break
        page += 1

    return prs


def _derive_remediation_records(
    all_issues: list[dict[str, Any]],
    pull_requests: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Derive remediation records from GitHub issues and PRs.

    Matches issues that have `remediation-started` label with fix PRs
    using the ``fix/issue-N`` branch naming convention.
    """
    import re

    # Build a map of issue_number → PR for quick lookup
    pr_by_issue: dict[int, dict[str, Any]] = {}
    for pr in pull_requests:
        branch = pr.get("branch", "")
        match = re.match(r"fix/issue-(\d+)", branch)
        if match:
            issue_num = int(match.group(1))
            pr_by_issue[issue_num] = pr

    records: list[dict[str, Any]] = []
    for issue in all_issues:
        labels = issue.get("labels", [])
        has_remediation = "remediation-started" in labels
        remediation_failed = "remediation-failed" in labels

        if not has_remediation and not remediation_failed:
            continue

        issue_num = issue["number"]
        pr = pr_by_issue.get(issue_num)

        # Determine status
        if issue.get("state") == "closed" and not remediation_failed:
            status = "fixed"
        elif remediation_failed:
            status = "failed"
        else:
            status = "in_progress"

        records.append({
            "finding_id": f"gh-issue-{issue_num}",
            "issue_number": issue_num,
            "issue_url": issue.get("url", ""),
            "status": status,
            "pr_url": pr["url"] if pr else "",
            "fix_description": pr["title"] if pr else "",
            "updated_at": issue.get("closed_at") or issue.get("created_at", ""),
        })

    # Sort by updated_at descending
    records.sort(key=lambda r: r.get("updated_at", ""), reverse=True)
    return records


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/metrics")
async def metrics() -> dict[str, Any]:
    # All data derived from GitHub API — no state.json dependency for core
    # metrics.  This ensures the dashboard works even when scanning runs
    # remotely via GitHub Actions.
    all_issues = _fetch_github_issues(state="all")
    workflow_runs = _fetch_scan_workflow_runs(limit=50)
    pull_requests = _fetch_pull_requests(state="all", limit=100)

    total_findings = len(all_issues)
    open_issues = len([i for i in all_issues if i.get("state") == "open"])
    closed_issues = len([i for i in all_issues if i.get("state") == "closed"])

    # Severity breakdown from GitHub issues
    severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for issue in all_issues:
        sev = issue.get("severity", "medium")
        if sev in severity_breakdown:
            severity_breakdown[sev] += 1

    # Remediation status derived from issue state + labels
    remediation_status = {"fixed": 0, "partial": 0, "failed": 0, "in_progress": 0, "pending": 0}
    for issue in all_issues:
        if issue.get("state") == "closed" and not issue.get("remediation_failed"):
            remediation_status["fixed"] += 1
        elif issue.get("remediation_failed"):
            remediation_status["failed"] += 1
        elif issue.get("has_remediation"):
            remediation_status["in_progress"] += 1
        else:
            remediation_status["pending"] += 1

    # Active sessions = issues currently being remediated
    active_sessions = remediation_status["in_progress"]

    # Success rate based on issues that entered remediation
    remediated_total = (
        remediation_status["fixed"]
        + remediation_status["failed"]
        + remediation_status["in_progress"]
    )
    success_rate = 0.0
    if remediated_total > 0:
        success_rate = round((remediation_status["fixed"] / remediated_total) * 100, 1)

    # Scan history derived from workflow runs + issue creation clusters
    scan_history = _derive_scan_history(all_issues, workflow_runs)

    # Total scans from workflow runs
    total_scans = len([r for r in workflow_runs if r.get("conclusion") == "success"])

    # Recent remediations derived from GitHub issues + PRs
    recent_remediations = _derive_remediation_records(all_issues, pull_requests)[:10]

    return {
        "overview": {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "open_issues": open_issues,
            "closed_issues": closed_issues,
            "active_sessions": active_sessions,
            "success_rate": success_rate,
        },
        "severity_breakdown": severity_breakdown,
        "remediation_status": remediation_status,
        "scan_history": scan_history,
        "recent_remediations": recent_remediations,
    }


@app.get("/api/findings")
async def findings() -> dict[str, Any]:
    # Findings are now derived from GitHub issues (the source of truth)
    all_issues = _fetch_github_issues(state="all")
    return {"findings": all_issues}


@app.get("/api/issues")
async def issues() -> dict[str, Any]:
    issue_list = _fetch_github_issues(state="open")
    return {"issues": issue_list}


@app.get("/api/sessions")
async def sessions() -> dict[str, Any]:
    # Derive active sessions from issues with remediation-started label
    all_issues = _fetch_github_issues(state="open")
    active = [
        {
            "issue_number": i["number"],
            "issue_url": i["url"],
            "status": "failed" if i.get("remediation_failed") else "in_progress",
        }
        for i in all_issues
        if i.get("has_remediation") or i.get("remediation_failed")
    ]
    return {"sessions": active}



# ---------------------------------------------------------------------------
# Action Endpoints — trigger scan and orchestration
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

    from automation.config import DEVIN_ORG_ID
    if not DEVIN_ORG_ID:
        return JSONResponse(status_code=400, content={"error": "DEVIN_ORG_ID not configured (required for Devin API)"})

    repo = GITHUB_REPO
    if not repo:
        return JSONResponse(status_code=400, content={"error": "GITHUB_REPO not configured"})
    job_id = _create_job("orchestrate")
    thread = threading.Thread(target=_run_orchestrator_background, args=(job_id, repo), daemon=True)
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
