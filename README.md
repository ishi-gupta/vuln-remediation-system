# Vulnerability Remediation System

Event-driven vulnerability remediation system with AI-assisted automation using Devin.

## What This Does

1. **Scans** `ishi-gupta/superset` for security vulnerabilities (SAST, SCA, secrets)
2. **Creates GitHub Issues** for each finding with CVE/CWE IDs and severity labels
3. **Triggers Devin AI sessions** to automatically fix the vulnerabilities
4. **Tracks everything** on a live observability dashboard
5. **Stress-tests the scanner** with AI-generated adversarial bugs

## The 3 Repos

| Repo | Role |
|------|------|
| [ishi-gupta/superset](https://github.com/ishi-gupta/superset) | **Target** — gets scanned, issues + fix PRs land here |
| **ishi-gupta/vuln-remediation-system** (this repo) | **Brain** — scanner, issue creator, orchestrator, dashboard |
| [ishi-gupta/vuln-test-suite](https://github.com/ishi-gupta/vuln-test-suite) | **Red Team** — adversarial test suite that validates scanner detection |

## How the Adversarial Suite Works

The adversarial test suite simulates **real engineers accidentally introducing security bugs**. It uses a two-tier Devin architecture:

1. **God Agent (parent Devin session)** — Plans a batch of realistic bugs across vulnerability categories (SQL injection, XSS, command injection, etc.). Decides which types of mistakes to simulate and how they should look like natural code a developer might write.

2. **Baby Devins (child sessions)** — Each child session acts as a "careless engineer." It writes a small, realistic piece of buggy code — complete with comments, error handling, and logging — that contains a specific vulnerability. It creates a PR on the target repo explaining what the bug is and why a developer might write it that way.

3. **The scanner picks up the new PRs** → creates issues on the dashboard → the remediation orchestrator sends more Devin agents to fix them → the cycle continues.

This creates a continuous adversarial loop: bugs get planted → the scanner catches them → Devin fixes them → the dashboard tracks the full lifecycle.

The test suite also includes a **ground truth evaluator** that measures the scanner's detection rate per vulnerability category, identifying blind spots (e.g., which CWE categories the scanner misses).

## Quick Start

### Run the Scanner
```bash
pip install bandit semgrep pip-audit
python -m automation.scanner --target ishi-gupta/superset --output scan_results.json
```

### Create GitHub Issues
```bash
export GITHUB_TOKEN=ghp_...
python -m automation.issue_creator --input scan_results.json --repo ishi-gupta/superset
```

### Launch the Dashboard
```bash
cd dashboard && npm install && npm run build && cd ..
python -m uvicorn automation.dashboard:app --host 0.0.0.0 --port 8000
```

### Trigger Remediation
```bash
export DEVIN_API_KEY=...
python -m automation.orchestrator --repo ishi-gupta/superset --one-shot
```

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** — full system design, all 6 components, data flow, tech stack
- **[Build Plan](docs/PLAN.md)** — what's built, what's pending, how to test, environment variables
- **[Test Report](docs/TEST_REPORT.md)** — comprehensive test results, bugs found, detection rates
