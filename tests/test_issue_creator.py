"""
Unit tests for automation/issue_creator.py — quality scoring, filtering, and grouping.
"""

import pytest

from automation.issue_creator import (
    QUALITY_SCORES,
    filter_by_quality,
    group_findings,
    quality_score,
    _grouped_issue_title,
    _grouped_issue_body,
)
from automation.models import ScanType, Severity, VulnerabilityFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    severity: Severity = Severity.HIGH,
    confidence: str = "high",
    scanner: str = "bandit",
    title: str = "Test finding",
    cwe_id: str = "CWE-78",
    file_path: str = "app.py",
    line_number: int = 10,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scanner=scanner,
        scan_type=ScanType.SAST,
        severity=severity,
        title=title,
        description="Test description",
        file_path=file_path,
        line_number=line_number,
        cwe_id=cwe_id,
        confidence=confidence,
        remediation="Fix the code.",
    )


# ---------------------------------------------------------------------------
# quality_score()
# ---------------------------------------------------------------------------


class TestQualityScore:
    """Tests for the quality_score() function."""

    @pytest.mark.parametrize(
        "severity,confidence,expected",
        [
            (Severity.CRITICAL, "high", 10),
            (Severity.CRITICAL, "medium", 9),
            (Severity.CRITICAL, "low", 7),
            (Severity.HIGH, "high", 9),
            (Severity.HIGH, "medium", 7),
            (Severity.HIGH, "low", 4),
            (Severity.MEDIUM, "high", 7),
            (Severity.MEDIUM, "medium", 5),
            (Severity.MEDIUM, "low", 2),
            (Severity.LOW, "high", 4),
            (Severity.LOW, "medium", 2),
            (Severity.LOW, "low", 1),
        ],
    )
    def test_all_severity_confidence_combinations(
        self, severity: Severity, confidence: str, expected: int
    ) -> None:
        finding = _make_finding(severity=severity, confidence=confidence)
        assert quality_score(finding) == expected

    def test_unknown_confidence_returns_default(self) -> None:
        finding = _make_finding(confidence="unknown")
        assert quality_score(finding) == 3  # default fallback

    def test_case_insensitive_confidence(self) -> None:
        finding = _make_finding(severity=Severity.HIGH, confidence="HIGH")
        assert quality_score(finding) == 9

    def test_all_quality_scores_table_entries_present(self) -> None:
        """Verify every severity × confidence combo is in the table."""
        severities = ["critical", "high", "medium", "low"]
        confidences = ["high", "medium", "low"]
        for sev in severities:
            for conf in confidences:
                assert (sev, conf) in QUALITY_SCORES


# ---------------------------------------------------------------------------
# filter_by_quality()
# ---------------------------------------------------------------------------


class TestFilterByQuality:
    """Tests for the filter_by_quality() function."""

    def test_filters_low_quality(self) -> None:
        findings = [
            _make_finding(severity=Severity.HIGH, confidence="high"),    # score 9
            _make_finding(severity=Severity.LOW, confidence="low"),      # score 1
            _make_finding(severity=Severity.MEDIUM, confidence="medium"),  # score 5
        ]
        result = filter_by_quality(findings, min_score=5)
        assert len(result) == 2
        assert all(quality_score(f) >= 5 for f in result)

    def test_default_threshold(self) -> None:
        findings = [
            _make_finding(severity=Severity.HIGH, confidence="low"),     # score 4
            _make_finding(severity=Severity.MEDIUM, confidence="high"),  # score 7
        ]
        result = filter_by_quality(findings)
        assert len(result) == 1
        assert result[0].severity == Severity.MEDIUM

    def test_threshold_zero_keeps_all(self) -> None:
        findings = [
            _make_finding(severity=Severity.LOW, confidence="low"),  # score 1
        ]
        result = filter_by_quality(findings, min_score=0)
        assert len(result) == 1

    def test_threshold_too_high_filters_all(self) -> None:
        findings = [
            _make_finding(severity=Severity.CRITICAL, confidence="high"),  # score 10
        ]
        result = filter_by_quality(findings, min_score=11)
        assert len(result) == 0

    def test_empty_list(self) -> None:
        assert filter_by_quality([]) == []

    def test_boundary_score_included(self) -> None:
        """Finding with score exactly equal to threshold should be included."""
        finding = _make_finding(severity=Severity.MEDIUM, confidence="medium")  # score 5
        result = filter_by_quality([finding], min_score=5)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# group_findings()
# ---------------------------------------------------------------------------


class TestGroupFindings:
    """Tests for the group_findings() function."""

    def test_same_vuln_type_grouped(self) -> None:
        f1 = _make_finding(file_path="a.py", line_number=1)
        f2 = _make_finding(file_path="b.py", line_number=2)
        f3 = _make_finding(file_path="c.py", line_number=3)
        groups = group_findings([f1, f2, f3])
        assert len(groups) == 1
        key = list(groups.keys())[0]
        assert len(groups[key]) == 3

    def test_different_vuln_types_separate_groups(self) -> None:
        f1 = _make_finding(cwe_id="CWE-78", title="Shell injection")
        f2 = _make_finding(cwe_id="CWE-89", title="SQL injection")
        groups = group_findings([f1, f2])
        assert len(groups) == 2

    def test_different_severities_separate_groups(self) -> None:
        f1 = _make_finding(severity=Severity.HIGH, cwe_id="CWE-78")
        f2 = _make_finding(severity=Severity.MEDIUM, cwe_id="CWE-78")
        groups = group_findings([f1, f2])
        assert len(groups) == 2

    def test_different_scanners_separate_groups(self) -> None:
        f1 = _make_finding(scanner="bandit", cwe_id="CWE-78")
        f2 = _make_finding(scanner="semgrep", cwe_id="CWE-78")
        groups = group_findings([f1, f2])
        assert len(groups) == 2

    def test_empty_list(self) -> None:
        assert group_findings([]) == {}

    def test_single_finding(self) -> None:
        f = _make_finding()
        groups = group_findings([f])
        assert len(groups) == 1
        assert len(list(groups.values())[0]) == 1

    def test_group_key_uses_title_when_no_cwe(self) -> None:
        f1 = _make_finding(cwe_id="", title="Hardcoded password")
        f2 = _make_finding(cwe_id="", title="Hardcoded password")
        groups = group_findings([f1, f2])
        assert len(groups) == 1


# ---------------------------------------------------------------------------
# _grouped_issue_title()
# ---------------------------------------------------------------------------


class TestGroupedIssueTitle:
    """Tests for the grouped issue title generator."""

    def test_single_finding_stable_title(self) -> None:
        f = _make_finding()
        title = _grouped_issue_title([f])
        # Title uses stable format (no file path or count)
        assert "[HIGH]" in title
        assert "CWE-78" in title
        assert f.file_path not in title

    def test_multiple_findings_stable_title(self) -> None:
        findings = [
            _make_finding(file_path="a.py"),
            _make_finding(file_path="b.py"),
            _make_finding(file_path="c.py"),
        ]
        title = _grouped_issue_title(findings)
        # Title must NOT include count so dedup stays stable across scans
        assert "(3 locations)" not in title
        assert "[HIGH]" in title
        assert "CWE-78" in title

    def test_title_stable_across_different_counts(self) -> None:
        two = [_make_finding(file_path="a.py"), _make_finding(file_path="b.py")]
        three = two + [_make_finding(file_path="c.py")]
        assert _grouped_issue_title(two) == _grouped_issue_title(three)

    def test_title_uses_cve_if_present(self) -> None:
        f1 = _make_finding(cwe_id="", file_path="a.py")
        f1 = VulnerabilityFinding(
            scanner="pip-audit",
            scan_type=ScanType.SCA,
            severity=Severity.HIGH,
            title="Vuln in flask",
            description="",
            file_path="a.py",
            cve_id="CVE-2024-001",
        )
        f2 = VulnerabilityFinding(
            scanner="pip-audit",
            scan_type=ScanType.SCA,
            severity=Severity.HIGH,
            title="Vuln in flask",
            description="",
            file_path="b.py",
            cve_id="CVE-2024-001",
        )
        title = _grouped_issue_title([f1, f2])
        assert "CVE-2024-001" in title


# ---------------------------------------------------------------------------
# _grouped_issue_body()
# ---------------------------------------------------------------------------


class TestGroupedIssueBody:
    """Tests for the grouped issue body generator."""

    def test_body_contains_location_table(self) -> None:
        findings = [
            _make_finding(file_path="a.py", line_number=10),
            _make_finding(file_path="b.py", line_number=20),
        ]
        body = _grouped_issue_body(findings, "owner/repo")
        assert "| File | Line |" in body
        assert "a.py" in body
        assert "b.py" in body
        assert "found in 2 locations" in body

    def test_body_contains_description(self) -> None:
        findings = [_make_finding()]
        body = _grouped_issue_body(findings, "owner/repo")
        assert "### Description" in body
        assert "Test description" in body

    def test_body_contains_remediation(self) -> None:
        findings = [_make_finding()]
        body = _grouped_issue_body(findings, "owner/repo")
        assert "### Recommended Fix" in body
        assert "Fix the code." in body

    def test_body_contains_cwe_link(self) -> None:
        findings = [_make_finding(cwe_id="CWE-78")]
        body = _grouped_issue_body(findings, "owner/repo")
        assert "CWE-78" in body
        assert "cwe.mitre.org" in body

    def test_body_contains_auto_created_notice(self) -> None:
        findings = [_make_finding()]
        body = _grouped_issue_body(findings, "owner/repo")
        assert "automatically created by the Vulnerability Remediation System" in body
