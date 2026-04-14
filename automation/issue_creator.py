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
)
from automation.models import VulnerabilityFinding, Severity, ScanType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Quality scoring (severity × confidence)
# ---------------------------------------------------------------------------

QUALITY_SCORES: dict[tuple[str, str], int] = {
    ("critical", "high"): 10,
    ("critical", "medium"): 9,
    ("critical", "low"): 7,
    ("high", "high"): 9,
    ("high", "medium"): 7,
    ("high", "low"): 4,
    ("medium", "high"): 7,
    ("medium", "medium"): 5,
    ("medium", "low"): 2,
    ("low", "high"): 4,
    ("low", "medium"): 2,
    ("low", "low"): 1,
}
DEFAULT_MIN_QUALITY_SCORE = 5


def quality_score(finding: VulnerabilityFinding) -> int:
    """Compute a composite quality score from severity and confidence."""
    key = (finding.severity.value, finding.confidence.lower())
    return QUALITY_SCORES.get(key, 3)


def filter_by_quality(
    findings: list[VulnerabilityFinding],
    min_score: int = DEFAULT_MIN_QUALITY_SCORE,
) -> list[VulnerabilityFinding]:
    """Filter findings to only include those meeting the minimum quality score."""
    return [f for f in findings if quality_score(f) >= min_score]


def filter_by_severity(
    findings: list[VulnerabilityFinding],
    min_severity: str = "LOW",
) -> list[VulnerabilityFinding]:
    """Filter findings by minimum severity level (backward-compatible helper)."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    threshold = severity_order.get(min_severity.lower(), 3)
    return [
        f for f in findings
        if severity_order.get(f.severity.value, 3) <= threshold
    ]


# ---------------------------------------------------------------------------
# Grouping related findings
# ---------------------------------------------------------------------------


def group_findings(
    findings: list[VulnerabilityFinding],
) -> dict[str, list[VulnerabilityFinding]]:
    """Group findings by vulnerability type."""
    groups: dict[str, list[VulnerabilityFinding]] = {}
    for f in findings:
        group_key = f"{f.scanner}:{f.severity.value}:{f.cwe_id or f.title[:60]}"
        groups.setdefault(group_key, []).append(f)
    return groups


def _grouped_issue_title(
    findings: list[VulnerabilityFinding],
) -> str:
    """Generate a stable GitHub Issue title for a group of related findings.

    The title intentionally omits the finding count and file path so that
    deduplication (which matches on exact title) works correctly across scans
    even when the number of affected locations changes.
    """
    first = findings[0]
    severity_tag = f"[{first.severity.value.upper()}]"
    vuln_id = first.cve_id or first.cwe_id or first.scanner
    return f"{severity_tag} {vuln_id}: {first.title}"


def _grouped_issue_body(
    findings: list[VulnerabilityFinding],
    repo: str,
) -> str:
    """Generate a GitHub Issue body for a group of related findings."""
    first = findings[0]
    lines = [
        f"## Vulnerability: {first.title}",
        "",
        f"**Scanner:** {first.scanner}",
        f"**Type:** {first.scan_type.value}",
        f"**Severity:** {first.severity.value.upper()}",
        f"**Confidence:** {first.confidence}",
    ]

    if first.cwe_id:
        cwe_num = first.cwe_id.split("-")[-1]
        lines.append(
            f"**CWE:** [{first.cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)"
        )
    if first.cve_id:
        lines.append(
            f"**CVE:** [{first.cve_id}](https://nvd.nist.gov/vuln/detail/{first.cve_id})"
        )

    lines.append("")
    lines.append("### Description")
    lines.append(first.description)

    lines.append("")
    lines.append(f"### Affected Locations (found in {len(findings)} locations)")
    lines.append("")
    lines.append("| File | Line |")
    lines.append("|------|------|")
    for f in findings:
        file_url = f"https://github.com/{repo}/blob/main/{f.file_path}"
        if f.line_number:
            file_url += f"#L{f.line_number}"
        line_num = str(f.line_number) if f.line_number else "—"
        lines.append(f"| [{f.file_path}]({file_url}) | {line_num} |")

    if first.remediation:
        lines.append("")
        lines.append("### Recommended Fix")
        lines.append(first.remediation)

    if first.reference_url:
        lines.append("")
        lines.append("### References")
        lines.append(f"- {first.reference_url}")

    lines.append("")
    lines.append("---")
    lines.append(
        "*This issue was automatically created by the Vulnerability Remediation System.*"
    )
    return "\n".join(lines)


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


def create_github_issues(
    findings: list[VulnerabilityFinding],
    repo: Optional[str] = None,
    token: Optional[str] = None,
    max_issues: Optional[int] = None,
    min_quality_score: int = DEFAULT_MIN_QUALITY_SCORE,
) -> list[dict]:
    """
    Create GitHub Issues for each finding, grouped by vulnerability type.

    Applies quality-score filtering before grouping and issue creation.

    Returns a list of dicts with keys: finding_id, issue_number, issue_url, title.
    """
    repo = repo or GITHUB_REPO
    token = token or GITHUB_TOKEN
    max_issues = max_issues if max_issues is not None else MAX_ISSUES_PER_RUN

    if not token:
        logger.error("No GITHUB_TOKEN set. Skipping issue creation.")
        return []

    headers = _github_headers(token)

    # --- Quality-score filtering ---
    before_count = len(findings)
    findings = filter_by_quality(findings, min_score=min_quality_score)
    filtered_out = before_count - len(findings)
    if filtered_out:
        logger.info(
            "Filtered out %d findings below quality score %d (kept %d)",
            filtered_out,
            min_quality_score,
            len(findings),
        )

    # Ensure all required labels exist in the repo
    ensure_labels_exist(repo, token)

    # Get existing issues to avoid duplicates
    existing_titles = get_existing_issue_titles(repo, token)
    logger.info("Found %d existing security issues", len(existing_titles))

    created_issues: list[dict] = []
    skipped = 0

    # --- Group related findings into single issues ---
    groups = group_findings(findings)

    # Sort groups by highest severity (critical first)
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }
    sorted_groups = sorted(
        groups.values(),
        key=lambda g: severity_order.get(g[0].severity, 3),
    )

    for group in sorted_groups:
        if len(created_issues) >= max_issues:
            break

        title = _grouped_issue_title(group)

        # Deduplicate against existing open issues
        if title in existing_titles:
            skipped += 1
            continue

        body = _grouped_issue_body(group, repo)
        labels = group[0].to_issue_labels()

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
                    "finding_id": group[0].finding_id,
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
        "Created %d issues (%d groups), skipped %d duplicates",
        len(created_issues),
        len(sorted_groups),
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
        "--min-quality-score",
        type=int,
        default=DEFAULT_MIN_QUALITY_SCORE,
        help=f"Minimum quality score to include a finding (default: {DEFAULT_MIN_QUALITY_SCORE})",
    )
    parser.add_argument(
        "--min-severity",
        type=str,
        default=None,
        help="Minimum severity level (critical/high/medium/low). Applied before quality scoring.",
    )
    args = parser.parse_args()

    findings = load_findings_from_json(args.input)
    logger.info("Loaded %d findings from %s", len(findings), args.input)

    # Apply severity filter if specified (backward compatibility)
    if args.min_severity:
        findings = filter_by_severity(findings, min_severity=args.min_severity)
        logger.info(
            "After severity filter (>=%s): %d findings",
            args.min_severity,
            len(findings),
        )

    issues = create_github_issues(
        findings,
        repo=args.repo,
        max_issues=args.max_issues,
        min_quality_score=args.min_quality_score,
    )
    print(f"\nCreated {len(issues)} GitHub Issues")
