"""
Data models for vulnerability findings, remediation records, and system metrics.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import hashlib
import json


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanType(str, Enum):
    SAST = "sast"
    SCA = "sca"
    SECRET_DETECTION = "secret-detection"
    CONTAINER = "container"
    IAC = "iac"


class RemediationStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    PARTIAL = "partial"
    FAILED = "failed"
    NEEDS_REVIEW = "needs_review"


@dataclass
class VulnerabilityFinding:
    """A single vulnerability finding from a scanner."""

    scanner: str
    scan_type: ScanType
    severity: Severity
    title: str
    description: str
    file_path: str = ""
    line_number: int = 0
    code_snippet: str = ""
    cwe_id: str = ""
    cve_id: str = ""
    confidence: str = "medium"
    remediation: str = ""
    reference_url: str = ""
    package_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""

    @property
    def finding_id(self) -> str:
        """Generate a unique ID for deduplication."""
        key = f"{self.scan_type}:{self.file_path}:{self.line_number}:{self.cwe_id or self.cve_id}:{self.title}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_issue_title(self) -> str:
        """Generate a GitHub Issue title."""
        severity_tag = f"[{self.severity.value.upper()}]"
        vuln_id = self.cve_id or self.cwe_id or self.scanner
        if self.file_path:
            return f"{severity_tag} {vuln_id}: {self.title} in {self.file_path}"
        return f"{severity_tag} {vuln_id}: {self.title}"

    def to_issue_body(self, repo: str) -> str:
        """Generate a GitHub Issue body in markdown."""
        lines = [
            f"## Vulnerability: {self.title}",
            "",
            f"**Scanner:** {self.scanner}",
            f"**Type:** {self.scan_type.value}",
            f"**Severity:** {self.severity.value.upper()}",
            f"**Confidence:** {self.confidence}",
        ]

        if self.cwe_id:
            lines.append(f"**CWE:** [{self.cwe_id}](https://cwe.mitre.org/data/definitions/{self.cwe_id.split('-')[-1]}.html)")
        if self.cve_id:
            lines.append(f"**CVE:** [{self.cve_id}](https://nvd.nist.gov/vuln/detail/{self.cve_id})")

        lines.append("")
        lines.append("### Description")
        lines.append(self.description)

        if self.file_path:
            lines.append("")
            lines.append("### Location")
            file_url = f"https://github.com/{repo}/blob/main/{self.file_path}"
            if self.line_number:
                file_url += f"#L{self.line_number}"
            lines.append(f"**File:** [{self.file_path}]({file_url})")
            if self.line_number:
                lines.append(f"**Line:** {self.line_number}")

        if self.code_snippet:
            lines.append("")
            lines.append("### Code")
            lines.append("```python")
            lines.append(self.code_snippet)
            lines.append("```")

        if self.package_name:
            lines.append("")
            lines.append("### Affected Package")
            lines.append(f"**Package:** `{self.package_name}`")
            lines.append(f"**Installed Version:** `{self.installed_version}`")
            if self.fixed_version:
                lines.append(f"**Fixed Version:** `{self.fixed_version}`")

        if self.remediation:
            lines.append("")
            lines.append("### Recommended Fix")
            lines.append(self.remediation)

        if self.reference_url:
            lines.append("")
            lines.append("### References")
            lines.append(f"- {self.reference_url}")

        lines.append("")
        lines.append("---")
        lines.append("*This issue was automatically created by the Vulnerability Remediation System.*")

        return "\n".join(lines)

    def to_issue_labels(self) -> list[str]:
        """Generate labels for the GitHub Issue."""
        labels = ["security", "automated", self.scan_type.value, self.severity.value]
        return labels

    def to_dict(self) -> dict:
        """Convert to a JSON-serializable dictionary."""
        d = asdict(self)
        d["finding_id"] = self.finding_id
        d["scan_type"] = self.scan_type.value
        d["severity"] = self.severity.value
        return d


@dataclass
class RemediationRecord:
    """Tracks the remediation of a specific finding."""

    finding_id: str
    issue_number: int
    issue_url: str
    status: RemediationStatus = RemediationStatus.PENDING
    devin_session_id: str = ""
    pr_url: str = ""
    fix_description: str = ""
    files_changed: list[str] = field(default_factory=list)
    tests_passed: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class ScanRun:
    """Represents a single scan execution."""

    scan_id: str
    target_repo: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scanners_used: list[str] = field(default_factory=list)
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    issues_created: int = 0
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SystemState:
    """The complete state of the system, persisted to state.json."""

    scan_runs: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    remediation_records: list[dict] = field(default_factory=list)
    active_sessions: list[dict] = field(default_factory=list)

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(asdict(self), f, indent=2, default=str)

    @classmethod
    def load(cls, path: str) -> "SystemState":
        try:
            with open(path) as f:
                data = json.load(f)
            return cls(**data)
        except (FileNotFoundError, json.JSONDecodeError):
            return cls()
