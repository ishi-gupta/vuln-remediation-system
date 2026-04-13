"""
Unit tests for automation/models.py — VulnerabilityFinding, ScanRun, SystemState, etc.
"""

import json
import os
import tempfile

import pytest

from automation.models import (
    RemediationRecord,
    RemediationStatus,
    ScanRun,
    ScanType,
    Severity,
    SystemState,
    VulnerabilityFinding,
)


# ---------------------------------------------------------------------------
# VulnerabilityFinding
# ---------------------------------------------------------------------------

class TestVulnerabilityFinding:
    """Tests for the VulnerabilityFinding dataclass."""

    @pytest.fixture
    def sample_sast_finding(self):
        return VulnerabilityFinding(
            scanner="bandit",
            scan_type=ScanType.SAST,
            severity=Severity.HIGH,
            title="Possible SQL injection via string-based query construction",
            description="SQL injection vector detected",
            file_path="superset/views/core.py",
            line_number=142,
            code_snippet='query = "SELECT * FROM " + user_input',
            cwe_id="CWE-89",
            confidence="high",
            remediation="Use parameterized queries.",
            reference_url="https://bandit.readthedocs.io/en/latest/plugins/b608.html",
        )

    @pytest.fixture
    def sample_sca_finding(self):
        return VulnerabilityFinding(
            scanner="pip-audit",
            scan_type=ScanType.SCA,
            severity=Severity.HIGH,
            title="CVE-2024-12345: Vulnerability in flask",
            description="Remote code execution in Flask < 2.3.5",
            file_path="requirements/base.txt",
            cve_id="CVE-2024-12345",
            package_name="flask",
            installed_version="2.3.2",
            fixed_version="2.3.5",
            reference_url="https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
        )

    @pytest.fixture
    def sample_secret_finding(self):
        return VulnerabilityFinding(
            scanner="gitleaks",
            scan_type=ScanType.SECRET_DETECTION,
            severity=Severity.HIGH,
            title="Leaked secret: AWS Access Key",
            description="An AWS Access Key was detected in the codebase.",
            file_path="config/settings.py",
            line_number=15,
            code_snippet="AKIA...",
            confidence="high",
            remediation="Remove the secret and rotate it immediately.",
        )

    # -- finding_id --

    def test_finding_id_is_deterministic(self, sample_sast_finding):
        """Same finding should always produce the same ID."""
        id1 = sample_sast_finding.finding_id
        id2 = sample_sast_finding.finding_id
        assert id1 == id2

    def test_finding_id_is_16_chars(self, sample_sast_finding):
        assert len(sample_sast_finding.finding_id) == 16

    def test_finding_id_differs_for_different_findings(self, sample_sast_finding, sample_sca_finding):
        assert sample_sast_finding.finding_id != sample_sca_finding.finding_id

    def test_finding_id_differs_by_line_number(self):
        """Two findings in the same file but different lines should have different IDs."""
        f1 = VulnerabilityFinding(
            scanner="bandit", scan_type=ScanType.SAST, severity=Severity.MEDIUM,
            title="Issue", description="", file_path="foo.py", line_number=10,
        )
        f2 = VulnerabilityFinding(
            scanner="bandit", scan_type=ScanType.SAST, severity=Severity.MEDIUM,
            title="Issue", description="", file_path="foo.py", line_number=20,
        )
        assert f1.finding_id != f2.finding_id

    def test_finding_id_same_when_severity_differs(self):
        """finding_id should NOT include severity — dedup is by location+type."""
        f1 = VulnerabilityFinding(
            scanner="bandit", scan_type=ScanType.SAST, severity=Severity.HIGH,
            title="Issue", description="", file_path="foo.py", line_number=10,
        )
        f2 = VulnerabilityFinding(
            scanner="bandit", scan_type=ScanType.SAST, severity=Severity.LOW,
            title="Issue", description="", file_path="foo.py", line_number=10,
        )
        # Same file, line, title, scan_type → same finding_id regardless of severity
        assert f1.finding_id == f2.finding_id

    # -- to_issue_title --

    def test_issue_title_sast(self, sample_sast_finding):
        title = sample_sast_finding.to_issue_title()
        assert "[HIGH]" in title
        assert "CWE-89" in title
        assert "superset/views/core.py" in title

    def test_issue_title_sca(self, sample_sca_finding):
        title = sample_sca_finding.to_issue_title()
        assert "[HIGH]" in title
        assert "CVE-2024-12345" in title

    def test_issue_title_no_file_path(self):
        f = VulnerabilityFinding(
            scanner="bandit", scan_type=ScanType.SAST, severity=Severity.LOW,
            title="General issue", description="",
        )
        title = f.to_issue_title()
        assert "[LOW]" in title
        assert "General issue" in title

    # -- to_issue_body --

    def test_issue_body_contains_metadata(self, sample_sast_finding):
        body = sample_sast_finding.to_issue_body("ishi-gupta/superset")
        assert "## Vulnerability:" in body
        assert "**Scanner:** bandit" in body
        assert "**Type:** sast" in body
        assert "**Severity:** HIGH" in body
        assert "CWE-89" in body
        assert "### Code" in body
        assert "### Recommended Fix" in body

    def test_issue_body_sca_contains_package_info(self, sample_sca_finding):
        body = sample_sca_finding.to_issue_body("ishi-gupta/superset")
        assert "### Affected Package" in body
        assert "`flask`" in body
        assert "`2.3.2`" in body
        assert "`2.3.5`" in body
        assert "CVE-2024-12345" in body

    def test_issue_body_contains_github_link(self, sample_sast_finding):
        body = sample_sast_finding.to_issue_body("ishi-gupta/superset")
        assert "https://github.com/ishi-gupta/superset/blob/main/superset/views/core.py#L142" in body

    def test_issue_body_contains_auto_created_notice(self, sample_sast_finding):
        body = sample_sast_finding.to_issue_body("ishi-gupta/superset")
        assert "automatically created by the Vulnerability Remediation System" in body

    # -- to_issue_labels --

    def test_issue_labels_sast(self, sample_sast_finding):
        labels = sample_sast_finding.to_issue_labels()
        assert "security" in labels
        assert "automated" in labels
        assert "sast" in labels
        assert "high" in labels

    def test_issue_labels_sca(self, sample_sca_finding):
        labels = sample_sca_finding.to_issue_labels()
        assert "sca" in labels

    def test_issue_labels_secret(self, sample_secret_finding):
        labels = sample_secret_finding.to_issue_labels()
        assert "secret-detection" in labels

    # -- to_dict --

    def test_to_dict_serializable(self, sample_sast_finding):
        d = sample_sast_finding.to_dict()
        # Should be JSON-serializable
        json_str = json.dumps(d)
        assert json_str
        # Enums should be string values
        assert d["severity"] == "high"
        assert d["scan_type"] == "sast"
        assert "finding_id" in d

    def test_to_dict_round_trip(self, sample_sast_finding):
        d = sample_sast_finding.to_dict()
        json_str = json.dumps(d)
        loaded = json.loads(json_str)
        assert loaded["scanner"] == "bandit"
        assert loaded["title"] == sample_sast_finding.title


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    """Tests for the deduplicate() function in scanner.py."""

    def test_dedup_removes_exact_duplicates(self):
        from automation.scanner import deduplicate

        f1 = VulnerabilityFinding(
            scanner="bandit", scan_type=ScanType.SAST, severity=Severity.HIGH,
            title="SQL injection", description="", file_path="foo.py", line_number=10,
        )
        f2 = VulnerabilityFinding(
            scanner="bandit", scan_type=ScanType.SAST, severity=Severity.HIGH,
            title="SQL injection", description="", file_path="foo.py", line_number=10,
        )
        result = deduplicate([f1, f2])
        assert len(result) == 1

    def test_dedup_keeps_higher_severity(self):
        from automation.scanner import deduplicate

        f_low = VulnerabilityFinding(
            scanner="bandit", scan_type=ScanType.SAST, severity=Severity.LOW,
            title="Issue", description="", file_path="foo.py", line_number=10,
        )
        f_high = VulnerabilityFinding(
            scanner="bandit", scan_type=ScanType.SAST, severity=Severity.HIGH,
            title="Issue", description="", file_path="foo.py", line_number=10,
        )
        result = deduplicate([f_low, f_high])
        assert len(result) == 1
        assert result[0].severity == Severity.HIGH

    def test_dedup_keeps_higher_severity_reversed_order(self):
        from automation.scanner import deduplicate

        f_high = VulnerabilityFinding(
            scanner="bandit", scan_type=ScanType.SAST, severity=Severity.HIGH,
            title="Issue", description="", file_path="foo.py", line_number=10,
        )
        f_low = VulnerabilityFinding(
            scanner="bandit", scan_type=ScanType.SAST, severity=Severity.LOW,
            title="Issue", description="", file_path="foo.py", line_number=10,
        )
        result = deduplicate([f_high, f_low])
        assert len(result) == 1
        assert result[0].severity == Severity.HIGH

    def test_dedup_preserves_different_findings(self):
        from automation.scanner import deduplicate

        f1 = VulnerabilityFinding(
            scanner="bandit", scan_type=ScanType.SAST, severity=Severity.HIGH,
            title="SQL injection", description="", file_path="foo.py", line_number=10,
        )
        f2 = VulnerabilityFinding(
            scanner="bandit", scan_type=ScanType.SAST, severity=Severity.MEDIUM,
            title="XSS", description="", file_path="bar.py", line_number=20,
        )
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_dedup_empty_list(self):
        from automation.scanner import deduplicate

        result = deduplicate([])
        assert result == []

    def test_dedup_critical_beats_all(self):
        from automation.scanner import deduplicate

        findings = [
            VulnerabilityFinding(
                scanner="bandit", scan_type=ScanType.SAST, severity=sev,
                title="Issue", description="", file_path="foo.py", line_number=10,
            )
            for sev in [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        ]
        result = deduplicate(findings)
        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# ScanRun
# ---------------------------------------------------------------------------

class TestScanRun:
    def test_scan_run_to_dict(self):
        sr = ScanRun(
            scan_id="abc123",
            target_repo="ishi-gupta/superset",
            scanners_used=["bandit", "semgrep"],
            total_findings=42,
            critical=2,
            high=10,
            medium=20,
            low=10,
            duration_seconds=45.2,
        )
        d = sr.to_dict()
        assert d["scan_id"] == "abc123"
        assert d["total_findings"] == 42
        assert d["critical"] == 2
        assert json.dumps(d)  # serializable

    def test_scan_run_math_consistency(self):
        """critical + high + medium + low should equal total_findings in a properly constructed ScanRun."""
        sr = ScanRun(
            scan_id="x", target_repo="r",
            total_findings=10, critical=1, high=2, medium=3, low=4,
        )
        assert sr.critical + sr.high + sr.medium + sr.low == sr.total_findings


# ---------------------------------------------------------------------------
# RemediationRecord
# ---------------------------------------------------------------------------

class TestRemediationRecord:
    def test_remediation_record_defaults(self):
        rr = RemediationRecord(
            finding_id="abc123",
            issue_number=42,
            issue_url="https://github.com/ishi-gupta/superset/issues/42",
        )
        assert rr.status == RemediationStatus.PENDING
        assert rr.devin_session_id == ""
        assert rr.pr_url == ""
        assert rr.tests_passed is False
        assert rr.files_changed == []

    def test_remediation_record_to_dict(self):
        rr = RemediationRecord(
            finding_id="abc123",
            issue_number=42,
            issue_url="https://github.com/ishi-gupta/superset/issues/42",
            status=RemediationStatus.FIXED,
            pr_url="https://github.com/ishi-gupta/superset/pull/43",
            tests_passed=True,
        )
        d = rr.to_dict()
        assert d["status"] == "fixed"
        assert d["tests_passed"] is True
        assert json.dumps(d)


# ---------------------------------------------------------------------------
# SystemState
# ---------------------------------------------------------------------------

class TestSystemState:
    def test_save_and_load_round_trip(self):
        state = SystemState(
            scan_runs=[{"scan_id": "s1", "total_findings": 5}],
            findings=[{"finding_id": "f1", "title": "test"}],
            remediation_records=[{"finding_id": "f1", "status": "pending"}],
            active_sessions=[],
        )
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp_path = f.name

        try:
            state.save(tmp_path)
            loaded = SystemState.load(tmp_path)
            assert len(loaded.scan_runs) == 1
            assert loaded.scan_runs[0]["scan_id"] == "s1"
            assert len(loaded.findings) == 1
            assert len(loaded.remediation_records) == 1
        finally:
            os.unlink(tmp_path)

    def test_load_missing_file_returns_empty(self):
        state = SystemState.load("/tmp/nonexistent_state_file_12345.json")
        assert state.scan_runs == []
        assert state.findings == []

    def test_load_corrupt_json_returns_empty(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json")
            tmp_path = f.name
        try:
            state = SystemState.load(tmp_path)
            assert state.scan_runs == []
        finally:
            os.unlink(tmp_path)

    def test_empty_state_save_and_load(self):
        state = SystemState()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp_path = f.name
        try:
            state.save(tmp_path)
            loaded = SystemState.load(tmp_path)
            assert loaded.scan_runs == []
            assert loaded.findings == []
            assert loaded.remediation_records == []
            assert loaded.active_sessions == []
        finally:
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Enum values
# ---------------------------------------------------------------------------

class TestEnums:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"

    def test_scan_type_values(self):
        assert ScanType.SAST.value == "sast"
        assert ScanType.SCA.value == "sca"
        assert ScanType.SECRET_DETECTION.value == "secret-detection"
        assert ScanType.CONTAINER.value == "container"
        assert ScanType.IAC.value == "iac"

    def test_remediation_status_values(self):
        assert RemediationStatus.PENDING.value == "pending"
        assert RemediationStatus.IN_PROGRESS.value == "in_progress"
        assert RemediationStatus.FIXED.value == "fixed"
        assert RemediationStatus.PARTIAL.value == "partial"
        assert RemediationStatus.FAILED.value == "failed"
        assert RemediationStatus.NEEDS_REVIEW.value == "needs_review"
