"""
Vulnerability Scanner — runs Bandit, Semgrep, pip-audit, and Gitleaks against a target repo.
Normalizes all results into a common finding format.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from automation.models import VulnerabilityFinding, Severity, ScanType, ScanRun


# ---------------------------------------------------------------------------
# Gitleaks post-processing allowlist
# ---------------------------------------------------------------------------

# Patterns for paths that are known-safe (documentation, config examples).
# These are applied as post-processing filters so that gitleaks still scans
# everything — we just discard findings from known-noise paths.
_GITLEAKS_ALLOWLIST_PATTERNS: list[re.Pattern[str]] = []


def _load_gitleaks_allowlist() -> list[re.Pattern[str]]:
    """Load gitleaks path allowlist patterns from .gitleaks.toml (cached)."""
    if _GITLEAKS_ALLOWLIST_PATTERNS:
        return _GITLEAKS_ALLOWLIST_PATTERNS

    config_path = Path(__file__).parent / ".gitleaks.toml"
    if not config_path.exists():
        return _GITLEAKS_ALLOWLIST_PATTERNS

    try:
        import tomllib
    except ModuleNotFoundError:
        # Python < 3.11 fallback — try third-party package
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:
            return _GITLEAKS_ALLOWLIST_PATTERNS

    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
        for pattern_str in data.get("allowlist", {}).get("paths", []):
            _GITLEAKS_ALLOWLIST_PATTERNS.append(re.compile(pattern_str))
    except Exception:
        pass  # If config is malformed, scan without filtering

    return _GITLEAKS_ALLOWLIST_PATTERNS


def _is_gitleaks_allowed(file_path: str, patterns: list[re.Pattern[str]]) -> bool:
    """Check whether a file path matches any gitleaks allowlist pattern."""
    for pattern in patterns:
        if pattern.search(file_path):
            return True
    return False


def clone_repo(repo_url: str, dest: str) -> str:
    """Clone a GitHub repo to a local directory."""
    if not repo_url.startswith("http"):
        repo_url = f"https://github.com/{repo_url}.git"
    subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, dest],
        check=True,
        capture_output=True,
        text=True,
    )
    return dest


def run_bandit(repo_path: str) -> list[VulnerabilityFinding]:
    """Run Bandit (Python SAST) and return normalized findings."""
    findings = []
    try:
        result = subprocess.run(
            ["bandit", "-r", repo_path, "-f", "json", "-ll", "--quiet"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.stdout:
            data = json.loads(result.stdout)
            for item in data.get("results", []):
                severity_map = {
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                }
                sev = severity_map.get(item.get("issue_severity", "LOW"), Severity.LOW)
                confidence = item.get("issue_confidence", "MEDIUM").lower()

                rel_path = os.path.relpath(item.get("filename", ""), repo_path)
                cwe_id = ""
                cwe_data = item.get("issue_cwe", {})
                if cwe_data:
                    cwe_id = f"CWE-{cwe_data.get('id', '')}"

                findings.append(VulnerabilityFinding(
                    scanner="bandit",
                    scan_type=ScanType.SAST,
                    severity=sev,
                    title=item.get("issue_text", "Unknown"),
                    description=item.get("issue_text", ""),
                    file_path=rel_path,
                    line_number=item.get("line_number", 0),
                    code_snippet=item.get("code", "").strip(),
                    cwe_id=cwe_id,
                    confidence=confidence,
                    remediation=f"Review and fix the {item.get('test_id', '')} finding. See https://bandit.readthedocs.io/en/latest/plugins/{item.get('test_id', '').lower()}.html",
                    reference_url=item.get("more_info", ""),
                ))
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[bandit] Error: {e}")
    return findings


def run_semgrep(repo_path: str) -> list[VulnerabilityFinding]:
    """Run Semgrep (multi-language SAST) and return normalized findings."""
    findings = []
    try:
        # Build config args: use curated rulesets for targeted, low-noise detection
        config_args = ["--config", "p/security-audit", "--config", "p/secrets", "--config", "p/owasp-top-ten"]
        custom_rules = Path(__file__).parent / "rules"
        if custom_rules.is_dir():
            config_args.extend(["--config", str(custom_rules)])

        # Copy .semgrepignore to target repo so semgrep picks it up.
        # Save any existing file so we can restore it afterwards.
        semgrepignore_src = Path(__file__).parent / ".semgrepignore"
        target_semgrepignore = Path(repo_path) / ".semgrepignore"
        original_semgrepignore: Optional[bytes] = None
        had_original_semgrepignore = target_semgrepignore.exists()

        if had_original_semgrepignore:
            original_semgrepignore = target_semgrepignore.read_bytes()

        try:
            if semgrepignore_src.exists():
                shutil.copy2(semgrepignore_src, target_semgrepignore)

            result = subprocess.run(
                [
                    "semgrep", "scan",
                    *config_args,
                    "--json",
                    repo_path,
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )
        finally:
            # Restore or clean up .semgrepignore in the target repo
            if had_original_semgrepignore and original_semgrepignore is not None:
                target_semgrepignore.write_bytes(original_semgrepignore)
            elif not had_original_semgrepignore and target_semgrepignore.exists():
                target_semgrepignore.unlink()

        print(f"[semgrep] returncode={result.returncode}")
        if result.stderr:
            print(f"[semgrep] stderr: {result.stderr[:500]}")
        output = result.stdout or result.stderr
        if output:
            data = json.loads(output)
            for item in data.get("results", []):
                extra = item.get("extra", {})
                metadata = extra.get("metadata", {})

                severity_map = {
                    "ERROR": Severity.HIGH,
                    "WARNING": Severity.MEDIUM,
                    "INFO": Severity.LOW,
                }
                sev = severity_map.get(extra.get("severity", "WARNING"), Severity.MEDIUM)

                # Check metadata for more accurate severity
                impact = metadata.get("impact", "").upper()
                if impact == "HIGH":
                    sev = Severity.HIGH
                elif impact == "MEDIUM":
                    sev = Severity.MEDIUM
                elif impact == "LOW":
                    sev = Severity.LOW

                rel_path = os.path.relpath(item.get("path", ""), repo_path)
                cwe_list = metadata.get("cwe", [])
                cwe_id = cwe_list[0] if cwe_list else ""
                if isinstance(cwe_id, str) and ":" in cwe_id:
                    cwe_id = cwe_id.split(":")[0].strip()

                confidence = metadata.get("confidence", "MEDIUM")

                findings.append(VulnerabilityFinding(
                    scanner="semgrep",
                    scan_type=ScanType.SAST,
                    severity=sev,
                    title=extra.get("message", item.get("check_id", "Unknown")),
                    description=extra.get("message", ""),
                    file_path=rel_path,
                    line_number=item.get("start", {}).get("line", 0),
                    code_snippet=extra.get("lines", "").strip(),
                    cwe_id=cwe_id,
                    confidence=confidence.lower(),
                    remediation=metadata.get("fix", "Review the flagged code pattern."),
                    reference_url=metadata.get("source", ""),
                ))
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[semgrep] Error: {e}")
    return findings


def run_pip_audit(repo_path: str) -> list[VulnerabilityFinding]:
    """Run pip-audit (Python SCA) and return normalized findings."""
    findings = []
    req_files = list(Path(repo_path).rglob("requirements*.txt"))
    req_dir_files = list(Path(repo_path).rglob("requirements/*.txt"))
    setup_files = list(Path(repo_path).rglob("setup.cfg"))
    pyproject_files = list(Path(repo_path).rglob("pyproject.toml"))

    # Deduplicate in case both globs match the same file
    targets = list(dict.fromkeys(req_files + req_dir_files + setup_files + pyproject_files))
    if not targets:
        return findings

    for target in targets[:3]:  # Limit to avoid excessive scanning
        try:
            cmd = ["pip-audit", "-f", "json", "--desc"]
            if target.name.startswith("requirements"):
                cmd.extend(["-r", str(target)])
            else:
                cmd.extend(["--path", str(target.parent)])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            output = result.stdout
            if output:
                data = json.loads(output)
                deps = data if isinstance(data, list) else data.get("dependencies", [])
                for dep in deps:
                    for vuln in dep.get("vulns", []):
                        vuln_id = vuln.get("id", "")
                        severity_str = vuln.get("fix_versions", [])
                        # pip-audit doesn't always include severity; default to HIGH for CVEs
                        sev = Severity.HIGH

                        description = vuln.get("description", f"Vulnerability {vuln_id} in {dep.get('name', 'unknown')}")
                        fix_versions = vuln.get("fix_versions", [])
                        fix_version = fix_versions[0] if fix_versions else ""

                        findings.append(VulnerabilityFinding(
                            scanner="pip-audit",
                            scan_type=ScanType.SCA,
                            severity=sev,
                            title=f"{vuln_id}: Vulnerability in {dep.get('name', 'unknown')}",
                            description=description,
                            file_path=str(target.relative_to(repo_path)),
                            cve_id=vuln_id if vuln_id.startswith("CVE") else "",
                            remediation=f"Upgrade {dep.get('name', 'unknown')} to version {fix_version}" if fix_version else "No fix available yet.",
                            reference_url=f"https://nvd.nist.gov/vuln/detail/{vuln_id}" if vuln_id.startswith("CVE") else f"https://osv.dev/vulnerability/{vuln_id}",
                            package_name=dep.get("name", ""),
                            installed_version=dep.get("version", ""),
                            fixed_version=fix_version,
                        ))
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[pip-audit] Error scanning {target}: {e}")
    return findings


def run_gitleaks(repo_path: str) -> list[VulnerabilityFinding]:
    """Run Gitleaks (secret detection) and return normalized findings."""
    findings = []
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        subprocess.run(
            [
                "gitleaks", "detect",
                "--source", repo_path,
                "--no-git",
                "--report-format", "json",
                "--report-path", tmp_path,
                "--no-banner",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        if os.path.exists(tmp_path):
            with open(tmp_path) as f:
                content = f.read()
            if content.strip():
                data = json.loads(content)
                # Post-process: filter out known-safe documentation patterns
                gitleaks_allowlist_patterns = _load_gitleaks_allowlist()
                for item in data:
                    rel_path = item.get("File", "")
                    if _is_gitleaks_allowed(rel_path, gitleaks_allowlist_patterns):
                        continue
                    findings.append(VulnerabilityFinding(
                        scanner="gitleaks",
                        scan_type=ScanType.SECRET_DETECTION,
                        severity=Severity.HIGH,
                        title=f"Leaked secret: {item.get('Description', 'Unknown secret type')}",
                        description=f"A {item.get('Description', 'secret')} was detected in the codebase. Rule: {item.get('RuleID', 'unknown')}",
                        file_path=rel_path,
                        line_number=item.get("StartLine", 0),
                        code_snippet=item.get("Match", "")[:200],  # Truncate to avoid leaking full secret
                        confidence="high",
                        remediation="Remove the secret from the code and rotate it immediately. Use environment variables or a secret manager instead.",
                    ))
    except subprocess.TimeoutExpired:
        print(f"[gitleaks] Warning: scan timed out after 300s")
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[gitleaks] Error: {e}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
    return findings


def deduplicate(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    """Remove duplicate findings (same file + line + vulnerability type)."""
    seen: dict[str, VulnerabilityFinding] = {}
    for f in findings:
        fid = f.finding_id
        if fid not in seen:
            seen[fid] = f
        else:
            # Keep the one with higher severity
            severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
            if severity_order.get(f.severity, 3) < severity_order.get(seen[fid].severity, 3):
                seen[fid] = f
    return list(seen.values())


def scan_repo(
    repo: str,
    clone_dir: Optional[str] = None,
    scanners: Optional[list[str]] = None,
) -> tuple[list[VulnerabilityFinding], ScanRun]:
    """
    Run all scanners against a repository and return deduplicated findings.

    Args:
        repo: GitHub repo in "owner/repo" format, or a local path.
        clone_dir: Optional directory to clone into. If None, uses a temp dir.
        scanners: Optional list of scanner names to run. Defaults to all.

    Returns:
        Tuple of (findings list, scan run metadata).
    """
    start_time = time.time()
    scan_id = hashlib.sha256(f"{repo}:{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:12]

    # Determine repo path
    if os.path.isdir(repo):
        repo_path = repo
    else:
        if clone_dir is None:
            clone_dir = tempfile.mkdtemp(prefix="vuln-scan-")
        repo_path = clone_repo(repo, clone_dir)

    available_scanners = {
        "bandit": run_bandit,
        "semgrep": run_semgrep,
        "pip-audit": run_pip_audit,
        "gitleaks": run_gitleaks,
    }

    if scanners is None:
        scanners = list(available_scanners.keys())

    all_findings: list[VulnerabilityFinding] = []
    scanners_used = []

    for scanner_name in scanners:
        if scanner_name in available_scanners:
            print(f"[scanner] Running {scanner_name}...")
            results = available_scanners[scanner_name](repo_path)
            print(f"[scanner] {scanner_name}: {len(results)} findings")
            all_findings.extend(results)
            scanners_used.append(scanner_name)

    # Deduplicate
    unique_findings = deduplicate(all_findings)
    duration = time.time() - start_time

    # Build scan run metadata
    scan_run = ScanRun(
        scan_id=scan_id,
        target_repo=repo,
        scanners_used=scanners_used,
        total_findings=len(unique_findings),
        critical=sum(1 for f in unique_findings if f.severity == Severity.CRITICAL),
        high=sum(1 for f in unique_findings if f.severity == Severity.HIGH),
        medium=sum(1 for f in unique_findings if f.severity == Severity.MEDIUM),
        low=sum(1 for f in unique_findings if f.severity == Severity.LOW),
        duration_seconds=round(duration, 2),
    )

    print(f"[scanner] Done. {len(unique_findings)} unique findings in {duration:.1f}s")
    return unique_findings, scan_run


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scan a repository for vulnerabilities")
    parser.add_argument("--target", required=True, help="GitHub repo (owner/repo) or local path")
    parser.add_argument("--output", default="scan_results.json", help="Output file path")
    parser.add_argument("--scanners", nargs="+", default=None, help="Scanners to run (bandit semgrep pip-audit gitleaks)")
    args = parser.parse_args()

    findings, scan_run = scan_repo(args.target, scanners=args.scanners)

    output = {
        "scan_run": scan_run.to_dict(),
        "findings": [f.to_dict() for f in findings],
    }

    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nResults written to {args.output}")
    print(f"Total: {scan_run.total_findings} | Critical: {scan_run.critical} | High: {scan_run.high} | Medium: {scan_run.medium} | Low: {scan_run.low}")
