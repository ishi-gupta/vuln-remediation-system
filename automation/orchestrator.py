"""
Remediation Orchestrator — watches for new security issues in the target repo
and triggers Devin API sessions to fix them.
"""

import json
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
    STATE_FILE,
    STRUCTURED_OUTPUT_SCHEMA,
)
from automation.models import RemediationRecord, RemediationStatus, SystemState


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


def get_new_security_issues(repo: str, token: str) -> list[dict]:
    """Get security issues that haven't been picked up for remediation yet."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }

    # Get issues with 'security' and 'automated' labels but NOT 'remediation-started'
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
        print(f"[orchestrator] Failed to fetch issues: {resp.status_code}")
        return []

    issues = resp.json()

    # Filter out issues that already have 'remediation-started'
    new_issues = []
    for issue in issues:
        label_names = [l["name"] for l in issue.get("labels", [])]
        if "remediation-started" not in label_names and "remediation-failed" not in label_names:
            new_issues.append(issue)

    return new_issues


def add_label(repo: str, issue_number: int, label: str, token: str) -> None:
    """Add a label to a GitHub issue."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    requests.post(
        f"{GITHUB_API_BASE}/repos/{repo}/issues/{issue_number}/labels",
        headers=headers,
        json={"labels": [label]},
    )


def comment_on_issue(repo: str, issue_number: int, body: str, token: str) -> None:
    """Add a comment to a GitHub issue."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    requests.post(
        f"{GITHUB_API_BASE}/repos/{repo}/issues/{issue_number}/comments",
        headers=headers,
        json={"body": body},
    )


def create_devin_session(prompt: str, api_key: str) -> Optional[dict]:
    """Create a new Devin session via the API."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "prompt": prompt,
    }

    resp = requests.post(
        f"{DEVIN_API_BASE}/sessions",
        headers=headers,
        json=payload,
    )

    if resp.status_code in (200, 201):
        data = resp.json()
        return data
    else:
        print(f"[orchestrator] Failed to create Devin session: {resp.status_code} - {resp.text[:300]}")
        return None


def get_session_status(session_id: str, api_key: str) -> Optional[dict]:
    """Check the status of a Devin session."""
    headers = {
        "Authorization": f"Bearer {api_key}",
    }

    resp = requests.get(
        f"{DEVIN_API_BASE}/sessions/{session_id}",
        headers=headers,
    )

    if resp.status_code == 200:
        return resp.json()
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
    issue_body = issue.get("body", "")

    # Mark the issue as being worked on
    add_label(repo, issue_number, "remediation-started", token)

    # Comment on the issue
    comment_on_issue(
        repo,
        issue_number,
        f"Automated remediation session triggered. Devin is working on a fix.",
        token,
    )

    # Build the prompt for Devin
    prompt = PLAYBOOK_PROMPT.format(
        repo=f"https://github.com/{repo}",
        issue_title=issue_title,
        issue_number=issue_number,
        issue_url=issue_url,
        issue_body=issue_body[:3000],  # Truncate to avoid exceeding limits
    )

    # Create Devin session
    session = create_devin_session(prompt, api_key)
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

    print(f"[orchestrator] Triggered remediation for issue #{issue_number}: session {session_id}")
    return record


def poll_active_sessions(state: SystemState, api_key: str, token: str, repo: str) -> None:
    """Check status of all active Devin sessions and update state."""
    for session_info in state.active_sessions:
        session_id = session_info.get("devin_session_id", "")
        issue_number = session_info.get("issue_number", 0)

        if not session_id or session_info.get("status") in ("fixed", "failed"):
            continue

        status_data = get_session_status(session_id, api_key)
        if not status_data:
            continue

        session_status = status_data.get("status", "")

        if session_status in ("finished", "stopped"):
            # Check structured output
            structured_output = status_data.get("structured_output", {})
            pr_url = structured_output.get("pr_url", "")
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

        elif session_status == "error":
            session_info["status"] = "failed"
            session_info["updated_at"] = datetime.now(timezone.utc).isoformat()
            add_label(repo, issue_number, "remediation-failed", token)
            comment_on_issue(
                repo,
                issue_number,
                "Automated remediation session encountered an error. Manual review needed.",
                token,
            )
            state.remediation_records.append(session_info)

    # Remove completed sessions from active list
    state.active_sessions = [
        s for s in state.active_sessions
        if s.get("status") not in ("fixed", "partial", "failed", "needs_review")
    ]


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
        repo: Target GitHub repo.
        token: GitHub token.
        api_key: Devin API key.
        max_concurrent: Max simultaneous Devin sessions.
        poll_interval: Seconds between poll cycles.
        one_shot: If True, run once and exit (don't loop).
    """
    repo = repo or GITHUB_REPO
    token = token or GITHUB_TOKEN
    api_key = api_key or DEVIN_API_KEY

    if not token or not api_key:
        print("[orchestrator] ERROR: GITHUB_TOKEN and DEVIN_API_KEY must be set.")
        return

    state = SystemState.load(str(STATE_FILE))

    while True:
        print(f"\n[orchestrator] Polling for new issues in {repo}...")

        # Check active sessions
        if state.active_sessions:
            print(f"[orchestrator] Checking {len(state.active_sessions)} active sessions...")
            poll_active_sessions(state, api_key, token, repo)

        # Get new issues
        new_issues = get_new_security_issues(repo, token)
        active_count = len(state.active_sessions)
        available_slots = max(0, max_concurrent - active_count)

        print(f"[orchestrator] {len(new_issues)} new issues, {active_count} active sessions, {available_slots} slots available")

        # Trigger remediation for new issues
        for issue in new_issues[:available_slots]:
            record = trigger_remediation(issue, repo, token, api_key)
            if record:
                state.active_sessions.append(record.to_dict())

        # Save state
        state.save(str(STATE_FILE))

        if one_shot:
            break

        print(f"[orchestrator] Sleeping {poll_interval}s...")
        time.sleep(poll_interval)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Orchestrate vulnerability remediation")
    parser.add_argument("--repo", default=None, help="Target GitHub repo (owner/repo)")
    parser.add_argument("--max-concurrent", type=int, default=5, help="Max concurrent Devin sessions")
    parser.add_argument("--poll-interval", type=int, default=60, help="Seconds between poll cycles")
    parser.add_argument("--one-shot", action="store_true", help="Run once and exit")
    args = parser.parse_args()

    run_orchestrator(
        repo=args.repo,
        max_concurrent=args.max_concurrent,
        poll_interval=args.poll_interval,
        one_shot=args.one_shot,
    )
