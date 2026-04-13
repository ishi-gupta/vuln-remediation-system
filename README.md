# Vulnerability Remediation System

Event-driven vulnerability remediation system with AI-assisted automation using Devin.

## What This Does

1. **Scans** `ishi-gupta/superset` for security vulnerabilities (SAST, SCA, secrets)
2. **Creates GitHub Issues** for each finding with CVE/CWE IDs and severity labels
3. **Triggers Devin AI sessions** to automatically fix the vulnerabilities
4. **Tracks everything** on a live observability dashboard
5. **Validates the scanner** using an adversarial test suite

## Quick Start

### Run the Scanner
```bash
pip install bandit semgrep pip-audit
python -m automation.scanner --target ishi-gupta/superset --output scan_results.json
```

### Run Specific Scanners
```bash
python -m automation.scanner --target ishi-gupta/superset --scanners bandit semgrep
```

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** — full system design, all 6 components, data flow, tech stack
- **[Build Plan](docs/PLAN.md)** — what's built, what's pending, how to test, environment variables

## Related Repos

| Repo | Role |
|------|------|
| [ishi-gupta/superset](https://github.com/ishi-gupta/superset) | Target repo (gets scanned, issues + fix PRs land here) |
| [ishi-gupta/vuln-test-suite](https://github.com/ishi-gupta/vuln-test-suite) | Adversarial test suite (validates scanner detection rate) |
