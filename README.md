# Vulnerability Remediation System

Event-driven vulnerability remediation system with AI-assisted automation using Devin.

## What This Does

1. **Scans** `ishi-gupta/superset` for security vulnerabilities (SAST, SCA, secrets)
2. **Creates GitHub Issues** for each finding with CVE/CWE IDs and severity labels
3. **Triggers Devin AI sessions** to automatically fix the vulnerabilities
4. **Tracks everything** on a live observability dashboard

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌──────────────┐
│   Scanner    │────▶│  Issue Creator   │────▶│  Orchestrator    │────▶│  Dashboard   │
│              │     │                  │     │                  │     │              │
│ • Bandit     │     │ • GitHub Issues  │     │ • Devin v3 API   │     │ • Metrics    │
│ • Semgrep    │     │ • Severity labels│     │ • Session mgmt   │     │ • Issues     │
│ • pip-audit  │     │ • Deduplication  │     │ • Status polling │     │ • Sessions   │
│ • Gitleaks   │     │ • CWE/CVE refs   │     │ • Auto-labeling  │     │ • Charts     │
└──────────────┘     └──────────────────┘     └──────────────────┘     └──────────────┘
```

**Event-driven flow:** Scan results trigger issue creation → new issues trigger Devin sessions → session status updates the dashboard. Can run via CLI, Docker, or GitHub Actions (scheduled daily or on push).

## The 3 Repos

| Repo | Role |
|------|------|
| [ishi-gupta/superset](https://github.com/ishi-gupta/superset) | **Target** — gets scanned, issues + fix PRs land here |
| **ishi-gupta/vuln-remediation-system** (this repo) | **Brain** — scanner, issue creator, orchestrator, dashboard |
| [ishi-gupta/vuln-test-suite](https://github.com/ishi-gupta/vuln-test-suite) | **Red Team** — adversarial test suite that validates scanner detection |

## Quick Start (Docker)

```bash
# 1. Clone the repo
git clone https://github.com/ishi-gupta/vuln-remediation-system.git
cd vuln-remediation-system

# 2. Configure environment
cp .env.example .env
# Edit .env with your GITHUB_TOKEN, DEVIN_API_KEY, and DEVIN_ORG_ID

# 3. Start the dashboard
docker compose up dashboard

# 4. Run the full pipeline
docker compose run scanner              # Scan for vulnerabilities
docker compose run issue-creator         # Create GitHub issues
docker compose run orchestrator          # Trigger Devin remediation
```

Dashboard is available at **http://localhost:8000** after `docker compose up dashboard`.

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | Yes | GitHub PAT with `repo` scope ([create one](https://github.com/settings/tokens/new?scopes=repo)) |
| `GITHUB_REPO` | No | Target repo (default: `ishi-gupta/superset`) |
| `DEVIN_API_KEY` | Yes* | Devin Service User API key ([create one](https://app.devin.ai/settings)) |
| `DEVIN_ORG_ID` | Yes* | Devin organization ID |
| `SCAN_SEVERITY_THRESHOLD` | No | Minimum severity to report (default: `LOW`) |
| `MAX_ISSUES_PER_RUN` | No | Max issues created per scan (default: `50`) |

*Required only for the orchestrator (Devin remediation).

## Quick Start (without Docker)

```bash
# Install dependencies
pip install -e ".[scanners]"

# Run the scanner
python -m automation.scanner --target ishi-gupta/superset --output data/scan_results.json

# Create GitHub issues
export GITHUB_TOKEN=ghp_...
python -m automation.issue_creator --input data/scan_results.json --repo ishi-gupta/superset

# Launch the dashboard
uvicorn automation.dashboard:app --host 0.0.0.0 --port 8000

# Trigger Devin remediation
export DEVIN_API_KEY=cog_...
export DEVIN_ORG_ID=org-...
python -m automation.orchestrator --repo ishi-gupta/superset --one-shot
```

## GitHub Actions (CI/CD)

The system includes GitHub Actions workflows for automated operation:

- **`scan.yml`** — Runs daily at midnight UTC (or on push/PR). Scans the target repo and creates GitHub issues.
- **`remediate.yml`** — Manually triggered. Runs the orchestrator to create Devin sessions for open security issues.
- **`test.yml`** — Runs unit tests on every push/PR.

## Scanner Tools

| Tool | Type | What It Detects |
|------|------|-----------------|
| [Bandit](https://bandit.readthedocs.io/) | SAST | Python security anti-patterns (eval, exec, SQL injection, etc.) |
| [Semgrep](https://semgrep.dev/) | SAST | Multi-language vulnerability patterns using `--config auto` |
| [pip-audit](https://pypi.org/project/pip-audit/) | SCA | Known CVEs in Python dependencies |
| [Gitleaks](https://gitleaks.io/) | Secrets | Hardcoded API keys, passwords, tokens |

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** — full system design, all 6 components, data flow, tech stack
- **[Build Plan](docs/PLAN.md)** — what's built, what's pending, how to test, environment variables
- **[Test Report](docs/TEST_REPORT.md)** — comprehensive test results, bugs found, detection rates
