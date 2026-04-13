"""
Issue Creator — takes scan_results.json (output from scanner) and creates
GitHub Issues in the target repository.

No standalone markdown report — the dashboard is the presentation layer.
"""

import json
import logging
from typing import Optional

import requests

from automation.config import (
    GITHUB_TOKEN,
    GITHUB_API_BASE,
    GITHUB_REPO,
    MAX_ISSUES_PER_RUN,
    SEVERITY_LABELS,
    SCAN_TYPE_LABELS,
    SYSTEM_LABELS,
)
from automation.models import VulnerabilityFinding, Severity, ScanType

logger = logging.getLogger(__name__)

# Label colours — kept in sync with the dashboard expectations.
LABEL_COLORS: dict[str, str] = {
    "security": "d73a4a",
    "automated": "0075ca",
    "sast": "e4e669",
    "sca": "f9d0c4",
    "secret-detection": "b60205",
    "container": "bfdadc",
    "iac": "c5def5",
    "critical": "b60205",
    "high": "d93f0b",
    "medium": "fbca04",
    "low": "0e8a16",
    "remediation-started": "5319e7",
    "remediation-failed": "b60205",
}


def _github_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }


def ensure_labels_exist(repo: str, token: str) -> None:
    """Create required labels in the GitHub repo if they don't already exist."""
    headers = _github_headers(token)

    for label_name, color in LABEL_COLORS.items():
        resp = requests.post(
            f"{GITHUB_API_BASE}/repos/{repo}/labels",
            headers=headers,
            json={"name": label_name, "color": color},
        )
        if resp.status_code == 201:
            logger.info("Created label: %s", label_name)
        elif resp.status_code == 422:
            pass  # Label already exists
        else:
            logger.warning(
                "Could not create label %s: %s", label_name, resp.status_code
            )


def get_existing_issue_titles(repo: str, token: str) -> set[str]:
    """Get titles of existing open issues with security+automated labels to avoid duplicates."""
    headers = _github_headers(token)
    titles: set[str] = set()
    page = 1
    while True:
        resp = requests.get(
            f"{GITHUB_API_BASE}/repos/{repo}/issues",
            headers=headers,
            params={
                "state": "open",
                "labels": "security,automated",
                "per_page": 100,
                "page": page,
            },
        )
        if resp.status_code != 200:
            logger.warning("Failed to fetch existing issues: %s", resp.status_code)
            break
        issues = resp.json()
        if not issues:
            break
        for issue in issues:
            titles.add(issue["title"])
        page += 1
    return titles


def filter_by_severity(
    findings: list[VulnerabilityFinding],
    min_severity: str,
) -> list[VulnerabilityFinding]:
    """
    Filter findings to only include those at or above the minimum severity.

    Severity order: critical > high > medium > low.
    """
    severity_rank = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }
    min_rank = severity_rank.get(Severity(min_severity.lower()), 3)
    return [f for f in findings if severity_rank.get(f.severity, 3) <= min_rank]


def create_github_issues(
    findings: list[VulnerabilityFinding],
    repo: Optional[str] = None,
    token: Optional[str] = None,
    max_issues: Optional[int] = None,
    min_severity: Optional[str] = None,
) -> list[dict]:
    """
    Create GitHub Issues for each finding.

    Returns a list of dicts with keys: finding_id, issue_number, issue_url, title.
    """
    repo = repo or GITHUB_REPO
    token = token or GITHUB_TOKEN
    max_issues = max_issues if max_issues is not None else MAX_ISSUES_PER_RUN

    if not token:
        logger.error("No GITHUB_TOKEN set. Skipping issue creation.")
        return []

    # Apply severity filter before creating issues
    if min_severity:
        original_count = len(findings)
        findings = filter_by_severity(findings, min_severity)
        logger.info(
            "Severity filter '%s': %d -> %d findings",
            min_severity, original_count, len(findings),
        )

    headers = _github_headers(token)

    # Ensure all required labels exist in the repo
    ensure_labels_exist(repo, token)

    # Get existing issues to avoid duplicates
    existing_titles = get_existing_issue_titles(repo, token)
    logger.info("Found %d existing security issues", len(existing_titles))

    created_issues: list[dict] = []
    skipped = 0

    # Sort by severity (critical first)
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }
    sorted_findings = sorted(
        findings, key=lambda f: severity_order.get(f.severity, 3)
    )

    for finding in sorted_findings[:max_issues]:
        title = finding.to_issue_title()

        # Deduplicate against existing open issues
        if title in existing_titles:
            skipped += 1
            continue

        body = finding.to_issue_body(repo)
        labels = finding.to_issue_labels()

        resp = requests.post(
            f"{GITHUB_API_BASE}/repos/{repo}/issues",
            headers=headers,
            json={
                "title": title,
                "body": body,
                "labels": labels,
            },
        )

        if resp.status_code == 201:
            issue_data = resp.json()
            created_issues.append(
                {
                    "finding_id": finding.finding_id,
                    "issue_number": issue_data["number"],
                    "issue_url": issue_data["html_url"],
                    "title": title,
                }
            )
            logger.info(
                "Created issue #%d: %s", issue_data["number"], title
            )
        else:
            logger.error(
                "Failed to create issue: %s - %s",
                resp.status_code,
                resp.text[:200],
            )

    logger.info(
        "Created %d issues, skipped %d duplicates",
        len(created_issues),
        skipped,
    )
    return created_issues


def load_findings_from_json(path: str) -> list[VulnerabilityFinding]:
    """Load VulnerabilityFinding objects from a scan_results.json file."""
    with open(path) as f:
        data = json.load(f)

    findings: list[VulnerabilityFinding] = []
    for fd in data.get("findings", []):
        fd_copy = {k: v for k, v in fd.items() if k != "finding_id"}
        fd_copy["scan_type"] = ScanType(fd_copy["scan_type"])
        fd_copy["severity"] = Severity(fd_copy["severity"])
        findings.append(VulnerabilityFinding(**fd_copy))
    return findings


if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="[issue_creator] %(levelname)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Create GitHub Issues from scan results"
    )
    parser.add_argument(
        "--input", required=True, help="Path to scan_results.json"
    )
    parser.add_argument(
        "--repo", default=None, help="Target GitHub repo (owner/repo)"
    )
    parser.add_argument(
        "--max-issues",
        type=int,
        default=MAX_ISSUES_PER_RUN,
        help=f"Max issues to create (default: {MAX_ISSUES_PER_RUN})",
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Only create issues for findings at or above this severity level",
    )
    args = parser.parse_args()

    findings = load_findings_from_json(args.input)
    logger.info("Loaded %d findings from %s", len(findings), args.input)

    issues = create_github_issues(
        findings, repo=args.repo, max_issues=args.max_issues,
        min_severity=args.min_severity,
    )
    print(f"\nCreated {len(issues)} GitHub Issues")
