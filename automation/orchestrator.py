"""
Remediation Orchestrator — watches for new security issues in the target repo
and triggers Devin API sessions to fix them. Tracks status in data/state.json.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

import requests

from automation.config import (
    GITHUB_TOKEN,
    GITHUB_API_BASE,
    GITHUB_REPO,
    DEVIN_API_KEY,
    DEVIN_API_BASE,
    DEVIN_ORG_ID,
    DEVIN_PLAYBOOK_ID,
    STATE_FILE,
    STRUCTURED_OUTPUT_SCHEMA,
)
from automation.models import RemediationRecord, RemediationStatus, SystemState

logger = logging.getLogger(__name__)

PLAYBOOK_PROMPT = """You are remediating a security vulnerability. Follow these steps:

1. Read the GitHub Issue linked below to understand the vulnerability.
2. Clone the repository: {repo}
3. Navigate to the affected file and line number mentioned in the issue.
4. Understand the vulnerability type (the issue includes CWE/CVE references).
5. Apply the recommended fix from the issue description.
6. Check for similar patterns elsewhere in the file.
7. Run any existing tests to make sure nothing breaks.
8. Create a PR with:
   - Title: "Fix {issue_title}"
   - Body: Description of the fix, link to issue #{issue_number}
   - Reference: "Fixes #{issue_number}"

Issue URL: {issue_url}
Issue Title: {issue_title}
Issue Body:
{issue_body}
"""


def _github_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }


def get_new_security_issues(repo: str, token: str) -> list[dict]:
    """
    Get security issues that haven't been picked up for remediation yet.

    Fetches issues with labels ``security,automated`` but filters out any that
    already carry ``remediation-started`` or ``remediation-failed``.
    """
    headers = _github_headers(token)

    resp = requests.get(
        f"{GITHUB_API_BASE}/repos/{repo}/issues",
        headers=headers,
        params={
            "state": "open",
            "labels": "security,automated",
            "per_page": 100,
            "sort": "created",
            "direction": "asc",
        },
    )

    if resp.status_code != 200:
        logger.error("Failed to fetch issues: %s", resp.status_code)
        return []

    issues = resp.json()

    new_issues = []
    for issue in issues:
        label_names = [label["name"] for label in issue.get("labels", [])]
        if "remediation-started" not in label_names and "remediation-failed" not in label_names:
            new_issues.append(issue)

    return new_issues


def add_label(repo: str, issue_number: int, label: str, token: str) -> None:
    """Add a label to a GitHub issue."""
    headers = _github_headers(token)
    resp = requests.post(
        f"{GITHUB_API_BASE}/repos/{repo}/issues/{issue_number}/labels",
        headers=headers,
        json={"labels": [label]},
    )
    if resp.status_code not in (200, 201):
        logger.warning(
            "Failed to add label '%s' to issue #%d: %s",
            label,
            issue_number,
            resp.status_code,
        )


def comment_on_issue(repo: str, issue_number: int, body: str, token: str) -> None:
    """Add a comment to a GitHub issue."""
    headers = _github_headers(token)
    resp = requests.post(
        f"{GITHUB_API_BASE}/repos/{repo}/issues/{issue_number}/comments",
        headers=headers,
        json={"body": body},
    )
    if resp.status_code not in (200, 201):
        logger.warning(
            "Failed to comment on issue #%d: %s",
            issue_number,
            resp.status_code,
        )


def create_devin_session(
    prompt: str, api_key: str, org_id: Optional[str] = None,
    playbook_id: Optional[str] = None,
) -> Optional[dict]:
    """
    Create a new Devin session via the v3 API.

    Uses ``/v3/organizations/{org_id}/sessions`` which requires a service-user
    key with the ``ManageOrgSessions`` permission.

    When a ``playbook_id`` is provided the session is linked to the Devin
    Playbook so the agent receives the full remediation procedure.  The
    structured-output JSON schema is always sent so Devin returns
    machine-readable results (issue_number, status, pr_url, etc.).

    v3 endpoint: POST /v3/organizations/{org_id}/sessions
    """
    org_id = org_id or DEVIN_ORG_ID
    if not org_id:
        logger.error("DEVIN_ORG_ID is required for v3 API.")
        return None

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload: dict = {
        "prompt": prompt,
        "structured_output_schema": STRUCTURED_OUTPUT_SCHEMA,
    }

    if playbook_id:
        payload["playbook_id"] = playbook_id

    resp = requests.post(
        f"{DEVIN_API_BASE}/organizations/{org_id}/sessions",
        headers=headers,
        json=payload,
    )

    if resp.status_code in (200, 201):
        return resp.json()

    logger.error(
        "Failed to create Devin session: %s - %s",
        resp.status_code,
        resp.text[:300],
    )
    return None


def get_session_status(
    session_id: str, api_key: str, org_id: Optional[str] = None
) -> Optional[dict]:
    """Check the status of a Devin session via the v3 API.

    v3 endpoint: GET /v3/organizations/{org_id}/sessions/{devin_id}
    The devin_id must be prefixed with 'devin-'.
    """
    org_id = org_id or DEVIN_ORG_ID
    if not org_id:
        logger.error("DEVIN_ORG_ID is required for v3 API.")
        return None

    # v3 API expects session IDs prefixed with 'devin-'
    devin_id = session_id if session_id.startswith("devin-") else f"devin-{session_id}"

    headers = {
        "Authorization": f"Bearer {api_key}",
    }

    resp = requests.get(
        f"{DEVIN_API_BASE}/organizations/{org_id}/sessions/{devin_id}",
        headers=headers,
    )

    if resp.status_code == 200:
        return resp.json()

    logger.warning("Failed to get session %s status: %s", session_id, resp.status_code)
    return None


def trigger_remediation(
    issue: dict,
    repo: str,
    token: str,
    api_key: str,
) -> Optional[RemediationRecord]:
    """Trigger a Devin session to remediate a single issue."""
    issue_number = issue["number"]
    issue_title = issue["title"]
    issue_url = issue["html_url"]
    issue_body = issue.get("body", "") or ""

    # 1. Mark the issue as being worked on
    add_label(repo, issue_number, "remediation-started", token)

    # 2. Comment on issue
    comment_on_issue(
        repo,
        issue_number,
        "Automated remediation session triggered. Devin is working on a fix.",
        token,
    )

    # 3. Build the prompt for Devin
    prompt = PLAYBOOK_PROMPT.format(
        repo=f"https://github.com/{repo}",
        issue_title=issue_title,
        issue_number=issue_number,
        issue_url=issue_url,
        issue_body=issue_body[:3000],  # Truncate to avoid exceeding limits
    )

    # 4. Create Devin session with the attached playbook
    session = create_devin_session(
        prompt, api_key, DEVIN_ORG_ID, playbook_id=DEVIN_PLAYBOOK_ID
    )
    if not session:
        add_label(repo, issue_number, "remediation-failed", token)
        comment_on_issue(
            repo,
            issue_number,
            "Failed to create automated remediation session. Manual review needed.",
            token,
        )
        return None

    session_id = session.get("session_id", session.get("id", ""))
    session_url = session.get("url", f"https://app.devin.ai/sessions/{session_id}")

    # 5. Comment with Devin session link
    comment_on_issue(
        repo,
        issue_number,
        f"Devin session started: {session_url}",
        token,
    )

    record = RemediationRecord(
        finding_id=f"issue-{issue_number}",
        issue_number=issue_number,
        issue_url=issue_url,
        status=RemediationStatus.IN_PROGRESS,
        devin_session_id=session_id,
    )

    logger.info(
        "Triggered remediation for issue #%d: session %s",
        issue_number,
        session_id,
    )
    return record


def poll_active_sessions(
    state: SystemState, api_key: str, org_id: str, token: str, repo: str
) -> None:
    """Check status of all active Devin sessions and update state."""
    completed_indices: list[int] = []

    for idx, session_info in enumerate(state.active_sessions):
        session_id = session_info.get("devin_session_id", "")
        issue_number = session_info.get("issue_number", 0)

        if not session_id or session_info.get("status") in ("fixed", "failed"):
            completed_indices.append(idx)
            continue

        status_data = get_session_status(session_id, api_key, org_id)
        if not status_data:
            continue

        session_status = status_data.get("status", "")

        # v3 statuses: "exit" = completed, "error" / "suspended" = terminal
        status_detail = status_data.get("status_detail", "")

        if session_status == "exit" or (
            session_status == "running" and status_detail == "finished"
        ):
            # Check structured output for PR URL and fix status
            structured_output = status_data.get("structured_output", {}) or {}
            pr_url = structured_output.get("pr_url", "")
            # v3 API returns pull_requests as a list
            if not pr_url:
                pull_requests = status_data.get("pull_requests") or []
                if pull_requests:
                    pr_url = pull_requests[0].get("pr_url", "")
            fix_status = structured_output.get("status", "needs_review")

            session_info["status"] = fix_status
            session_info["pr_url"] = pr_url
            session_info["updated_at"] = datetime.now(timezone.utc).isoformat()

            if pr_url:
                comment_on_issue(
                    repo,
                    issue_number,
                    f"Devin has created a fix PR: {pr_url}\n\nStatus: **{fix_status}**",
                    token,
                )
            else:
                comment_on_issue(
                    repo,
                    issue_number,
                    f"Devin session completed with status: **{fix_status}**. No PR was created.",
                    token,
                )
                if fix_status == "failed":
                    add_label(repo, issue_number, "remediation-failed", token)

            # Move from active to remediation records
            state.remediation_records.append(session_info)
            completed_indices.append(idx)

        elif session_status in ("error", "suspended"):
            session_info["status"] = "failed"
            session_info["updated_at"] = datetime.now(timezone.utc).isoformat()
            add_label(repo, issue_number, "remediation-failed", token)
            comment_on_issue(
                repo,
                issue_number,
                f"Automated remediation session {session_status}. Manual review needed.",
                token,
            )
            state.remediation_records.append(session_info)
            completed_indices.append(idx)

    # Remove completed sessions from active list (iterate in reverse to keep indices valid)
    for idx in sorted(completed_indices, reverse=True):
        state.active_sessions.pop(idx)


def run_orchestrator(
    repo: Optional[str] = None,
    token: Optional[str] = None,
    api_key: Optional[str] = None,
    max_concurrent: int = 5,
    poll_interval: int = 60,
    one_shot: bool = False,
) -> None:
    """
    Main orchestration loop.

    Args:
        repo: Target GitHub repo (owner/repo).
        token: GitHub personal access token.
        api_key: Devin API key.
        max_concurrent: Max simultaneous Devin sessions.
        poll_interval: Seconds between poll cycles.
        one_shot: If True, run once and exit (don't loop).
    """
    repo = repo or GITHUB_REPO
    token = token or GITHUB_TOKEN
    api_key = api_key or DEVIN_API_KEY

    org_id = DEVIN_ORG_ID

    if not token or not api_key:
        logger.error("GITHUB_TOKEN and DEVIN_API_KEY must both be set.")
        return
    if not org_id:
        logger.error("DEVIN_ORG_ID must be set for the v3 API.")
        return

    state = SystemState.load(str(STATE_FILE))

    while True:
        logger.info("Polling for new issues in %s ...", repo)

        # Check active sessions
        if state.active_sessions:
            logger.info(
                "Checking %d active sessions ...", len(state.active_sessions)
            )
            poll_active_sessions(state, api_key, org_id, token, repo)

        # Get new issues
        new_issues = get_new_security_issues(repo, token)
        active_count = len(state.active_sessions)
        available_slots = max(0, max_concurrent - active_count)

        logger.info(
            "%d new issues, %d active sessions, %d slots available",
            len(new_issues),
            active_count,
            available_slots,
        )

        # Trigger remediation for new issues (up to available slots)
        for issue in new_issues[:available_slots]:
            record = trigger_remediation(issue, repo, token, api_key)
            if record:
                state.active_sessions.append(record.to_dict())

        # Persist state
        state.save(str(STATE_FILE))

        if one_shot:
            break

        logger.info("Sleeping %ds ...", poll_interval)
        time.sleep(poll_interval)


if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="[orchestrator] %(levelname)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Orchestrate vulnerability remediation via Devin AI"
    )
    parser.add_argument(
        "--repo", default=None, help="Target GitHub repo (owner/repo)"
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=5,
        help="Max concurrent Devin sessions (default: 5)",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=60,
        help="Seconds between poll cycles (default: 60)",
    )
    parser.add_argument(
        "--one-shot",
        action="store_true",
        help="Run once and exit (don't loop)",
    )
    args = parser.parse_args()

    run_orchestrator(
        repo=args.repo,
        max_concurrent=args.max_concurrent,
        poll_interval=args.poll_interval,
        one_shot=args.one_shot,
    )
