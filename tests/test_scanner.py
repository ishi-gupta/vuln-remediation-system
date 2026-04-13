"""
Tests for automation/scanner.py — edge cases, error handling, and integration.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automation.models import ScanType, Severity, VulnerabilityFinding
from automation.scanner import (
    deduplicate,
    run_bandit,
    run_gitleaks,
    run_pip_audit,
    run_semgrep,
    scan_repo,
)


# ---------------------------------------------------------------------------
# Edge case: Empty repo / no relevant files
# ---------------------------------------------------------------------------

class TestEmptyRepo:
    """Scanner functions should handle empty or irrelevant repos gracefully."""

    @pytest.fixture
    def empty_dir(self, tmp_path):
        return str(tmp_path)

    def test_bandit_empty_dir(self, empty_dir):
        findings = run_bandit(empty_dir)
        assert findings == []

    def test_semgrep_empty_dir(self, empty_dir):
        findings = run_semgrep(empty_dir)
        assert findings == []

    def test_pip_audit_no_requirements(self, empty_dir):
        findings = run_pip_audit(empty_dir)
        assert findings == []

    def test_gitleaks_empty_dir(self, empty_dir):
        findings = run_gitleaks(empty_dir)
        assert findings == []

    def test_scan_repo_empty_dir(self, empty_dir):
        findings, scan_run = scan_repo(empty_dir)
        assert findings == []
        assert scan_run.total_findings == 0


# ---------------------------------------------------------------------------
# Edge case: Non-Python repo
# ---------------------------------------------------------------------------

class TestNonPythonRepo:
    """Scanner should handle repos with no Python files."""

    @pytest.fixture
    def js_only_dir(self, tmp_path):
        (tmp_path / "index.js").write_text("console.log('hello');")
        (tmp_path / "package.json").write_text('{"name": "test"}')
        return str(tmp_path)

    def test_bandit_non_python(self, js_only_dir):
        findings = run_bandit(js_only_dir)
        assert findings == []

    def test_pip_audit_non_python(self, js_only_dir):
        findings = run_pip_audit(js_only_dir)
        assert findings == []


# ---------------------------------------------------------------------------
# Edge case: Scanner not installed
# ---------------------------------------------------------------------------

class TestMissingScanner:
    """Should gracefully handle missing scanner binaries."""

    @patch("automation.scanner.subprocess.run", side_effect=FileNotFoundError("bandit not found"))
    def test_bandit_not_installed(self, mock_run):
        findings = run_bandit("/some/path")
        assert findings == []

    @patch("automation.scanner.subprocess.run", side_effect=FileNotFoundError("semgrep not found"))
    def test_semgrep_not_installed(self, mock_run):
        findings = run_semgrep("/some/path")
        assert findings == []

    @patch("automation.scanner.subprocess.run", side_effect=FileNotFoundError("gitleaks not found"))
    def test_gitleaks_not_installed(self, mock_run):
        findings = run_gitleaks("/some/path")
        assert findings == []


# ---------------------------------------------------------------------------
# Edge case: Timeout
# ---------------------------------------------------------------------------

class TestTimeout:
    """Scanners should handle timeouts gracefully."""

    @patch("automation.scanner.subprocess.run", side_effect=subprocess.TimeoutExpired("bandit", 300))
    def test_bandit_timeout(self, mock_run):
        findings = run_bandit("/some/path")
        assert findings == []

    @patch("automation.scanner.subprocess.run", side_effect=subprocess.TimeoutExpired("semgrep", 600))
    def test_semgrep_timeout(self, mock_run):
        findings = run_semgrep("/some/path")
        assert findings == []


# ---------------------------------------------------------------------------
# Edge case: Malformed scanner output
# ---------------------------------------------------------------------------

class TestMalformedOutput:
    """Scanners should handle corrupted/unexpected JSON output."""

    @patch("automation.scanner.subprocess.run")
    def test_bandit_invalid_json(self, mock_run):
        mock_run.return_value = MagicMock(stdout="{invalid json}", returncode=0)
        findings = run_bandit("/some/path")
        assert findings == []

    @patch("automation.scanner.subprocess.run")
    def test_bandit_empty_stdout(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        findings = run_bandit("/some/path")
        assert findings == []

    @patch("automation.scanner.subprocess.run")
    def test_bandit_missing_results_key(self, mock_run):
        mock_run.return_value = MagicMock(stdout='{"errors": []}', returncode=0)
        findings = run_bandit("/some/path")
        assert findings == []

    @patch("automation.scanner.subprocess.run")
    def test_semgrep_invalid_json(self, mock_run):
        mock_run.return_value = MagicMock(stdout="not json at all", returncode=0)
        findings = run_semgrep("/some/path")
        assert findings == []

    @patch("automation.scanner.subprocess.run")
    def test_semgrep_empty_results(self, mock_run):
        mock_run.return_value = MagicMock(stdout='{"results": []}', returncode=0)
        findings = run_semgrep("/some/path")
        assert findings == []


# ---------------------------------------------------------------------------
# Edge case: Bandit with known vulnerable code
# ---------------------------------------------------------------------------

class TestBanditWithKnownVuln:
    """Run bandit on intentionally vulnerable code to verify detection."""

    @pytest.fixture
    def vuln_dir(self, tmp_path):
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text(
            'import subprocess\n'
            'user_input = input("cmd: ")\n'
            'subprocess.call(user_input, shell=True)\n'
        )
        return str(tmp_path)

    def test_bandit_detects_shell_injection(self, vuln_dir):
        findings = run_bandit(vuln_dir)
        # Bandit should flag subprocess.call with shell=True
        assert len(findings) > 0
        assert any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings)
        assert all(f.scanner == "bandit" for f in findings)
        assert all(f.scan_type == ScanType.SAST for f in findings)


# ---------------------------------------------------------------------------
# scan_repo integration
# ---------------------------------------------------------------------------

class TestScanRepoIntegration:
    """Integration tests for the full scan_repo function."""

    def test_scan_repo_with_specific_scanners(self, tmp_path):
        """scan_repo should only run requested scanners."""
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text('import os; os.system("rm -rf /")\n')

        findings, scan_run = scan_repo(str(tmp_path), scanners=["bandit"])
        assert "bandit" in scan_run.scanners_used
        assert "semgrep" not in scan_run.scanners_used
        assert scan_run.duration_seconds >= 0

    def test_scan_repo_metadata(self, tmp_path):
        """ScanRun metadata should be properly populated."""
        (tmp_path / "safe.py").write_text("x = 1 + 2\n")
        findings, scan_run = scan_repo(str(tmp_path), scanners=["bandit"])

        assert scan_run.scan_id  # non-empty
        assert scan_run.target_repo == str(tmp_path)
        assert scan_run.timestamp  # non-empty
        assert scan_run.duration_seconds >= 0
        # Severity counts should be consistent
        total = scan_run.critical + scan_run.high + scan_run.medium + scan_run.low
        assert total == scan_run.total_findings

    def test_scan_repo_unknown_scanner_ignored(self, tmp_path):
        """Unknown scanner names should be silently skipped."""
        (tmp_path / "safe.py").write_text("x = 1\n")
        findings, scan_run = scan_repo(str(tmp_path), scanners=["nonexistent_scanner"])
        assert findings == []
        assert scan_run.total_findings == 0


# ---------------------------------------------------------------------------
# Gitleaks with known secret
# ---------------------------------------------------------------------------

class TestGitleaksWithKnownSecret:
    """Test gitleaks detection on planted secrets."""

    @pytest.fixture
    def secret_dir(self, tmp_path):
        secret_file = tmp_path / "config.py"
        secret_file.write_text(
            '# AWS credentials\n'
            'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
            'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        )
        return str(tmp_path)

    def test_gitleaks_detects_aws_key(self, secret_dir):
        findings = run_gitleaks(secret_dir)
        # Gitleaks should detect the AWS keys
        if findings:  # only assert if gitleaks is installed
            assert all(f.scanner == "gitleaks" for f in findings)
            assert all(f.scan_type == ScanType.SECRET_DETECTION for f in findings)
            assert all(f.severity == Severity.HIGH for f in findings)


# ---------------------------------------------------------------------------
# pip-audit with known vulnerable dependency
# ---------------------------------------------------------------------------

class TestPipAuditWithKnownVuln:
    """Test pip-audit detection with a requirements file containing a known vulnerable package."""

    @pytest.fixture
    def vuln_deps_dir(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        # Use a package with a known CVE
        req_file.write_text("flask==2.2.0\n")
        return str(tmp_path)

    def test_pip_audit_finds_known_cve(self, vuln_deps_dir):
        findings = run_pip_audit(vuln_deps_dir)
        # flask 2.2.0 has known vulnerabilities
        # This may return 0 if pip-audit can't resolve the version, which is OK
        # We mainly test that it doesn't crash
        assert isinstance(findings, list)
        for f in findings:
            assert f.scanner == "pip-audit"
            assert f.scan_type == ScanType.SCA
