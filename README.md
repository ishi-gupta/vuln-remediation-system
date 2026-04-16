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

## Repositories

| Repo | Role |
|------|------|
| [ishi-gupta/superset](https://github.com/ishi-gupta/superset) | **Target** — gets scanned, issues + fix PRs land here |
| **ishi-gupta/vuln-remediation-system** (this repo) | **Brain** — scanner, issue creator, orchestrator, dashboard |

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

## Components in Detail

### Component 1: Vulnerability Scanner (`automation/scanner.py`)

Runs 4 industry-standard tools and normalizes all output into one JSON format:

| Scanner | Type | What it finds | Identifiers |
|---------|------|--------------|-------------|
| **Bandit** | SAST (Static Analysis) | Python-specific bugs: SQL injection, command injection, weak crypto, etc. | CWE IDs |
| **Semgrep** | SAST (Pattern Matching) | Multi-language vulnerabilities with taint analysis (tracks data from user input to dangerous operations) | CWE IDs |
| **pip-audit** | SCA (Dependency Scan) | Known vulnerabilities in Python packages (checks NVD database) | CVE IDs |
| **Gitleaks** | Secret Detection | Hardcoded API keys, passwords, tokens, private keys | Rule IDs |

**What SAST means:** It reads your source code and looks for patterns that are known to be dangerous — like building a SQL query by concatenating user input.

**What SCA means:** It reads your `requirements.txt` / `pyproject.toml` and checks if any of your dependencies have published security advisories (CVEs).

**What taint analysis means (Semgrep):** It traces data flow — if user input touches variable A, which gets assigned to variable B, which gets passed to a SQL query, Semgrep flags it even though the dangerous operation is several steps removed from the input.

### Component 2: Issue Creator (`automation/issue_creator.py`)

Takes scanner output and creates GitHub Issues in the target repo. Each issue includes:
- **Severity labels** (`critical`, `high`, `medium`, `low`)
- **Type labels** (`sast`, `sca`, `secret-detection`)
- **CWE IDs** (for code vulnerabilities) linked to [MITRE](https://cwe.mitre.org/)
- **CVE IDs** (for dependency vulnerabilities) linked to [NVD](https://nvd.nist.gov/)
- **File path + line number + code snippet**
- **Remediation advice** (what to do to fix it)
- **Deduplication** — won't create duplicate issues for already-reported findings

### Component 3: Remediation Orchestrator (`automation/orchestrator.py`)

Watches GitHub Issues and automatically triggers Devin AI sessions to fix them:

1. Polls for issues labeled `security` + `automated` (without `remediation-started`)
2. Adds `remediation-started` label to the issue
3. Creates a Devin session with a detailed prompt about the vulnerability
4. Comments on the issue with the Devin session link
5. When Devin finishes, comments with the fix PR link
6. If the session fails, adds `remediation-failed` label

Supports structured output — Devin returns machine-readable JSON with `issue_number`, `status`, `pr_url`, `fix_description`, etc.

### Component 4: Observability Dashboard (`automation/dashboard.py` + `dashboard/`)

**Backend (FastAPI):**
| Endpoint | What it returns |
|----------|----------------|
| `GET /api/metrics` | Overview stats, severity breakdown, remediation progress, scan history |
| `GET /api/issues` | Live issues from GitHub API with labels and metadata |
| `GET /api/sessions` | Active and completed Devin remediation sessions |
| `GET /api/health` | Health check |

**Frontend (React + TypeScript + Tailwind + Recharts):**
- **Overview tab:** Stat cards, severity pie chart, remediation progress bar, scan history
- **Issues tab:** Live table of GitHub security issues with severity/type badges

### Component 5: GitHub Actions Workflows (`.github/workflows/`)

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| `scan.yml` | Push to main, PR, daily cron, manual | Scans Superset → creates GitHub Issues |
| `remediate.yml` | Manual (workflow_dispatch) | Runs orchestrator to trigger Devin sessions for open issues |
| `test.yml` | Every push/PR | Lint checks, import verification, unit tests |

---

## GitHub Actions Secrets Required

| Secret | Used by | How to get it |
|--------|---------|--------------|
| `GH_PAT` | scan.yml, remediate.yml | [GitHub Settings → Personal Access Tokens](https://github.com/settings/tokens) — needs `repo` scope |
| `DEVIN_API_KEY` | remediate.yml | [Devin API Keys](https://app.devin.ai/settings/api-keys) |

Both are already configured in this repo's settings.

---

## Environment Variables

| Variable | Required for | Default | Description |
|----------|-------------|---------|-------------|
| `GITHUB_TOKEN` | Issue Creator, Orchestrator, Dashboard | — | GitHub PAT with `repo` scope |
| `GITHUB_REPO` | All | `ishi-gupta/superset` | Target repo to scan |
| `DEVIN_API_KEY` | Orchestrator | — | Devin API key |
| `MAX_ISSUES_PER_RUN` | Issue Creator | `50` | Max GitHub Issues created per scan |
| `DASHBOARD_HOST` | Dashboard | `0.0.0.0` | Dashboard bind address |
| `DASHBOARD_PORT` | Dashboard | `8000` | Dashboard port |

---

## Repo Structure

```
vuln-remediation-system/
├── automation/                        # Python package — all backend logic
│   ├── __init__.py
│   ├── config.py                      # Reads env vars, defines constants
│   ├── models.py                      # Shared data models (VulnerabilityFinding, ScanRun, etc.)
│   ├── scanner.py                     # Component 1: runs Bandit + Semgrep + pip-audit + Gitleaks
│   ├── issue_creator.py               # Component 2: creates GitHub Issues from scan findings
│   ├── orchestrator.py                # Component 3: watches issues → triggers Devin sessions
│   ├── dashboard.py                   # Component 4 backend: FastAPI API
│   └── rules/
│       └── python_xss.yml            # Custom Semgrep rules for XSS detection
│
├── dashboard/                         # Component 4 frontend: React + TypeScript + Tailwind
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── index.css
│       └── App.tsx
│
├── .github/workflows/                 # CI/CD automation
│   ├── scan.yml                       # Auto-scan on push/PR/daily/manual
│   ├── remediate.yml                  # Trigger Devin remediation sessions
│   └── test.yml                       # Lint + import checks + unit tests
│
├── tests/                             # Unit tests (93 passing)
├── data/                              # Runtime data (gitignored)
├── docs/
│   ├── ARCHITECTURE.md                # Detailed system architecture
│   └── PLAN.md                        # Build plan and status
│
├── pyproject.toml                     # Python package config
├── .gitignore
└── README.md                          # This file
```

---

## Data Models

All findings from all scanners are normalized into a common format. See `automation/models.py`.

```
VulnerabilityFinding:
  scanner          # "bandit", "semgrep", "pip-audit", "gitleaks"
  scan_type        # "sast", "sca", "secret-detection"
  severity         # "critical", "high", "medium", "low"
  title            # Human-readable title
  description      # Detailed description
  file_path        # Relative path to the vulnerable file
  line_number      # Line number of the vulnerability
  code_snippet     # The vulnerable code
  cwe_id           # e.g., "CWE-89" (for SAST findings)
  cve_id           # e.g., "CVE-2024-12345" (for SCA findings)
  package_name     # (SCA only) e.g., "flask"
  installed_version # (SCA only) e.g., "2.2.0"
  fixed_version    # (SCA only) e.g., "2.3.1"
  remediation      # What to do to fix it
  reference_url    # Link to NVD, MITRE, or scanner docs
```

---

## How the Pieces Connect

1. **Scanner → Issue Creator:** Scanner outputs `scan_results.json`. Issue Creator reads it and creates GitHub Issues.
2. **Issue Creator → Orchestrator:** Orchestrator watches for new issues with `security` + `automated` labels.
3. **Orchestrator → Devin API:** Creates sessions with detailed prompts. Devin clones the repo, reads the issue, writes a fix, creates a PR.
4. **Devin → GitHub:** Fix PRs auto-close the security issues via `Fixes #N` in the PR body.
5. **Dashboard → GitHub + Devin APIs:** Reads live data from GitHub (issues, PRs) and Devin (session status) to show metrics.
6. **GitHub Actions:** Automates the scan → issue → remediation pipeline on every push/PR/daily.

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Language | Python 3.11+ | Superset is Python, all scanners are Python |
| SAST | Bandit, Semgrep | Bandit = Python-specific, Semgrep = multi-language + taint analysis |
| SCA | pip-audit | Python dependency CVE database |
| Secrets | Gitleaks | Industry standard, fast regex-based scanning |
| API Framework | FastAPI | Typed, auto-docs at `/docs`, async |
| Frontend | React 18 + TypeScript + Vite | Modern, fast hot-reload |
| Styling | Tailwind CSS | Utility-first, no custom CSS needed |
| Charts | Recharts | React-native charting library |
| CI/CD | GitHub Actions | Native to GitHub, free for public repos |
| AI Remediation | Devin API | Creates sessions to auto-fix vulnerabilities |
| Issue Tracking | GitHub Issues | Native PR auto-close via `Fixes #N` |

---

## Testing

```bash
# Run unit tests (93 tests)
pip install pytest
python -m pytest tests/ -v

```

---

## Related Documentation

- [Architecture (detailed)](docs/ARCHITECTURE.md) — full component specs, data flow, decision log
- [Build Plan](docs/PLAN.md) — what's built, what's pending, environment setup
