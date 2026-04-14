# Vulnerability Remediation System

An **event-driven vulnerability remediation system** that scans code for security bugs, auto-creates GitHub Issues, triggers AI (Devin) to fix them, and tracks everything on a live dashboard. It also has an AI-powered red team that generates new adversarial test code to continuously stress-test the scanner.

---

## How It Works (The Big Picture)

```
 You push code to ishi-gupta/superset
              │
              ▼
 ┌──────────────────────────┐
 │   VULNERABILITY SCANNER  │  ← Runs automatically on push, PR, daily cron, or on-demand
 │   Bandit + Semgrep +     │
 │   pip-audit + Gitleaks   │
 └────────────┬─────────────┘
              │
       scan_results.json
              │
              ▼
 ┌──────────────────────────┐
 │     ISSUE CREATOR        │  ← Creates GitHub Issues with CVE/CWE IDs, severity labels,
 │  Deduplicates, labels,   │    code snippets, and remediation advice
 │  links to NVD/MITRE      │
 └────────────┬─────────────┘
              │
    GitHub Issues in superset
              │
              ▼
 ┌──────────────────────────┐
 │  REMEDIATION ORCHESTRATOR│  ← Watches for new security issues
 │  Triggers Devin sessions │    Spins up Devin AI to write fix PRs
 │  Tracks progress         │    Comments on issues with session links + PR links
 └────────────┬─────────────┘
              │
              ▼
 ┌──────────────────────────┐
 │   OBSERVABILITY DASHBOARD│  ← Live metrics: findings by severity, remediation
 │   FastAPI + React        │    success rate, scan history, issue tracking
 └──────────────────────────┘

              +

 ┌──────────────────────────┐
 │  ADVERSARIAL RED TEAM    │  ← On-demand: Devin generates NEW sneaky vulnerable code,
 │  AI-generated test code  │    scanner runs against it, detection rate measured
 │  with answer keys        │    Proves the scanner actually catches things
 └──────────────────────────┘
```

---

## The 3 Repos

| Repo | Role | What happens here |
|------|------|-------------------|
| [`ishi-gupta/superset`](https://github.com/ishi-gupta/superset) | **Target** | Gets scanned. Security issues and fix PRs land here. |
| [`ishi-gupta/vuln-remediation-system`](https://github.com/ishi-gupta/vuln-remediation-system) | **Brain** (this repo) | All automation: scanner, issue creator, orchestrator, dashboard, adversarial generator |
| [`ishi-gupta/vuln-test-suite`](https://github.com/ishi-gupta/vuln-test-suite) | **Red Team** | Intentionally vulnerable code used to test the scanner's detection rate |

---

## Quick Start

### 1. Run the Scanner

```bash
# Clone this repo
git clone https://github.com/ishi-gupta/vuln-remediation-system.git
cd vuln-remediation-system

# Install dependencies
pip install -e ".[scanners]"

# Scan a repo (local path or GitHub owner/repo)
python -m automation.scanner --target ishi-gupta/superset --output scan_results.json

# Scan with specific scanners only
python -m automation.scanner --target ishi-gupta/superset --scanners bandit semgrep
```

### 2. Create GitHub Issues from Findings

```bash
export GITHUB_TOKEN="your-github-pat"
python -m automation.issue_creator --input scan_results.json --repo ishi-gupta/superset
```

### 3. Start the Dashboard

```bash
export GITHUB_TOKEN="your-github-pat"

# Backend (FastAPI)
python -m automation.dashboard
# → http://localhost:8000

# Frontend (React)
cd dashboard && npm install && npm run dev
# → http://localhost:5173
```

### 4. Run the Orchestrator (AI Remediation)

```bash
export GITHUB_TOKEN="your-github-pat"
export DEVIN_API_KEY="your-devin-api-key"

# One-shot: process all open security issues, then exit
python -m automation.orchestrator --repo ishi-gupta/superset --one-shot

# Continuous: poll every 60 seconds
python -m automation.orchestrator --repo ishi-gupta/superset --poll-interval 60
```

### 5. Run Adversarial Testing (AI Red Team)

```bash
export DEVIN_API_KEY="your-devin-api-key"

# Generate new adversarial code via Devin (on-demand)
python -m automation.adversarial_generator --mode generate --num-files 3

# Evaluate scanner against the test suite
python -m automation.adversarial_generator --mode evaluate \
  --test-suite ../vuln-test-suite \
  --scanner-repo .

# Full cycle: generate → wait for Devin → evaluate
python -m automation.adversarial_generator --mode full \
  --num-files 3 \
  --test-suite ../vuln-test-suite \
  --scanner-repo .
```

---

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
| `GET /api/adversarial` | Adversarial test results (detection rate by category) |
| `GET /api/health` | Health check |

**Frontend (React + TypeScript + Tailwind + Recharts):**
- **Overview tab:** Stat cards, severity pie chart, remediation progress bar, scan history
- **Issues tab:** Live table of GitHub security issues with severity/type badges
- **Adversarial Testing tab:** Detection rate by vulnerability category

### Component 5: Adversarial Red Team (`automation/adversarial_generator.py`)

An AI-powered red team that stress-tests the scanner. Instead of a static test suite, it uses **Devin to creatively generate new vulnerable code** that tries to evade detection:

**How it works:**
1. You trigger it on-demand (GitHub Actions button or CLI)
2. It reads what patterns the scanner detects (Bandit rules, Semgrep patterns, Gitleaks regexes)
3. Spins up a Devin session with a creative prompt: "generate sneaky vulnerable code targeting these detection patterns"
4. Devin generates Python files with intentional vulnerabilities + an answer key
5. Devin pushes to `ishi-gupta/vuln-test-suite`
6. The scanner runs against the new code
7. Detection rate is computed and fed to the dashboard

**Why this is better than a static test suite:**
- New code is generated each time — not the same patterns repeated
- Devin tries evasion techniques (obfuscated patterns, indirect data flows, multi-step taint)
- Detection rate trends over time show if the scanner is improving or regressing

### Component 6: GitHub Actions Workflows (`.github/workflows/`)

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| `scan.yml` | Push to main, PR, daily cron, manual | Scans Superset → creates GitHub Issues |
| `remediate.yml` | Manual (workflow_dispatch) | Runs orchestrator to trigger Devin sessions for open issues |
| `adversarial.yml` | Manual (workflow_dispatch) | Spins up Devin to generate adversarial code → evaluates scanner |
| `test.yml` | Every push/PR | Lint checks, import verification, unit tests |

---

## GitHub Actions Secrets Required

| Secret | Used by | How to get it |
|--------|---------|--------------|
| `GH_PAT` | scan.yml, remediate.yml | [GitHub Settings → Personal Access Tokens](https://github.com/settings/tokens) — needs `repo` scope |
| `DEVIN_API_KEY` | remediate.yml, adversarial.yml | [Devin API Keys](https://app.devin.ai/settings/api-keys) |

Both are already configured in this repo's settings.

---

## Environment Variables

| Variable | Required for | Default | Description |
|----------|-------------|---------|-------------|
| `GITHUB_TOKEN` | Issue Creator, Orchestrator, Dashboard | — | GitHub PAT with `repo` scope |
| `GITHUB_REPO` | All | `ishi-gupta/superset` | Target repo to scan |
| `DEVIN_API_KEY` | Orchestrator, Adversarial Generator | — | Devin API key |
| `SCAN_SEVERITY_THRESHOLD` | Scanner | `LOW` | Minimum severity to report |
| `MAX_ISSUES_PER_RUN` | Issue Creator | `50` | Max GitHub Issues created per scan |
| `DASHBOARD_HOST` | Dashboard | `0.0.0.0` | Dashboard bind address |
| `DASHBOARD_PORT` | Dashboard | `8000` | Dashboard port |
| `TEST_SUITE_REPO` | Adversarial Generator | `ishi-gupta/vuln-test-suite` | Target test suite repo |

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
│   ├── adversarial_generator.py       # Component 5: AI red team via Devin API
│   └── rules/
│       └── python_xss.yml            # Custom Semgrep rules for XSS detection (8 patterns)
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
│   ├── adversarial.yml                # On-demand adversarial red team
│   └── test.yml                       # Lint + import checks + unit tests
│
├── tests/                             # Unit tests (57 passing)
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

## Adversarial Test Suite (`ishi-gupta/vuln-test-suite`)

The test suite contains intentionally vulnerable code across 7 categories:

| Category | CWE | # Planted | Detection Tools |
|----------|-----|-----------|----------------|
| SQL Injection | CWE-89 | 5 | Bandit, Semgrep |
| XSS | CWE-79 | 4 | Semgrep (custom rules) |
| Command Injection | CWE-78 | 5 | Bandit, Semgrep |
| Path Traversal | CWE-22 | 4 | Bandit, Semgrep |
| Hardcoded Secrets | CWE-798 | 5 | Gitleaks, Semgrep |
| Weak Cryptography | CWE-327 | 4 | Bandit, Semgrep |
| Insecure Deserialization | CWE-502 | 4 | Bandit, Semgrep |
| Vulnerable Dependencies | CWE-1035 | 5 | pip-audit |
| **Total** | | **36** | |

**Current detection rate: 72-81%** (varies by category)

Each vulnerability has a ground truth entry in `test_harness/expected_findings.json` so detection rates can be computed automatically.

The adversarial generator (`automation/adversarial_generator.py`) can generate **new rounds** of test code via Devin, with increasingly creative evasion techniques.

---

## How the Pieces Connect

1. **Scanner → Issue Creator:** Scanner outputs `scan_results.json`. Issue Creator reads it and creates GitHub Issues.
2. **Issue Creator → Orchestrator:** Orchestrator watches for new issues with `security` + `automated` labels.
3. **Orchestrator → Devin API:** Creates sessions with detailed prompts. Devin clones the repo, reads the issue, writes a fix, creates a PR.
4. **Devin → GitHub:** Fix PRs auto-close the security issues via `Fixes #N` in the PR body.
5. **Dashboard → GitHub + Devin APIs:** Reads live data from GitHub (issues, PRs) and Devin (session status) to show metrics.
6. **Adversarial Generator → Devin API:** Creates sessions that generate new vulnerable code in the test suite.
7. **Adversarial Generator → Scanner:** Runs the scanner against the test suite and computes detection rates.
8. **GitHub Actions:** Automates the scan → issue → remediation pipeline on every push/PR/daily.

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
# Run unit tests (57 tests)
pip install pytest
python -m pytest tests/ -v

# Run adversarial evaluation
python -m automation.adversarial_generator --mode evaluate \
  --test-suite ../vuln-test-suite \
  --scanner-repo .
```

---

## Related Documentation

- [Architecture (detailed)](docs/ARCHITECTURE.md) — full component specs, data flow, decision log
- [Build Plan](docs/PLAN.md) — what's built, what's pending, environment setup
- [Adversarial Test Suite README](https://github.com/ishi-gupta/vuln-test-suite/blob/main/README.md) — how the red team repo works
