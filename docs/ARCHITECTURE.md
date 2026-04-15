# Architecture — Vulnerability Remediation System

## Overview

This is an **event-driven vulnerability remediation system** that:
1. Scans a target GitHub repo for security vulnerabilities
2. Creates GitHub Issues for each finding
3. Triggers Devin AI sessions to automatically fix them
4. Tracks everything on an observability dashboard
5. Validates the scanner using an adversarial test suite

**Target repo:** `ishi-gupta/superset` (fork of Apache Superset)

---

## The 3 Repos

| Repo | Role | Who touches it |
|------|------|----------------|
| `ishi-gupta/superset` | **Target** — gets scanned, issues land here, fix PRs land here | Automation only |
| `ishi-gupta/vuln-remediation-system` | **Brain** — all automation code, dashboard, orchestrator | This repo |
| `ishi-gupta/vuln-test-suite` | **Red Team** — intentionally vulnerable code to test the scanner | Separate repo |

---

## The 6 Components

### Component 1: Vulnerability Scanner (`automation/scanner.py`)

**What it does:** Clones the target repo, runs 4 scanners, normalizes all output into one common JSON format.

**Scanners:**
| Scanner | Type | What it finds |
|---------|------|--------------|
| Bandit | SAST | Python source code vulnerabilities (SQL injection, command injection, weak crypto, etc.) |
| Semgrep | SAST | Multi-language vulnerability patterns with taint analysis |
| pip-audit | SCA | Known CVEs in Python dependencies |
| Gitleaks | Secret Detection | Hardcoded API keys, passwords, tokens |

**Input:** A GitHub repo (e.g., `ishi-gupta/superset`) or local path
**Output:** `scan_results.json` containing normalized findings

**CLI:**
```bash
python -m automation.scanner --target ishi-gupta/superset --output scan_results.json
python -m automation.scanner --target /path/to/local/repo --scanners bandit semgrep
```

**Status:** ✅ Built (`automation/scanner.py`)

---

### Component 2: Issue Creator (`automation/issue_creator.py`)

**What it does:** Takes `scan_results.json` → creates GitHub Issues in the target repo.

Each issue includes:
- Severity labels (`critical`, `high`, `medium`, `low`)
- Type labels (`sast`, `sca`, `secret-detection`)
- CWE IDs (for SAST findings) linked to MITRE
- CVE IDs (for SCA findings) linked to NVD
- File path + line number + code snippet
- Remediation advice
- Deduplication (won't create duplicate issues)

**No standalone markdown report** — the dashboard is the presentation layer.

**CLI:**
```bash
python -m automation.issue_creator --input scan_results.json --repo ishi-gupta/superset
```

**Status:** 🔨 Built (uncommitted, needs update to remove MD report code)

---

### Component 3: Remediation Orchestrator (`automation/orchestrator.py`)

**What it does:** Watches GitHub Issues → triggers Devin API sessions → tracks session status → updates issues.

**Flow:**
1. Polls for issues with `security,automated` labels (without `remediation-started`)
2. Adds `remediation-started` label
3. Creates a Devin session with a prompt describing the vulnerability
4. Comments on the issue with the Devin session link
5. Polls session status → when complete, comments with the fix PR link
6. If failed, adds `remediation-failed` label

**Modes:**
- Polling loop (default): checks every N seconds
- One-shot: runs once and exits (for CI)
- GitHub Actions trigger: runs on issue creation

**CLI:**
```bash
python -m automation.orchestrator --repo ishi-gupta/superset --one-shot
python -m automation.orchestrator --repo ishi-gupta/superset --poll-interval 60
```

**Status:** 🔨 Built (uncommitted)

---

### Component 4: Observability Dashboard

**Backend:** FastAPI (`automation/dashboard.py`)
- `GET /api/metrics` — overview stats, severity breakdown, remediation progress, scan history
- `GET /api/issues` — live issues from GitHub API
- `GET /api/sessions` — active and completed Devin sessions
- `GET /api/adversarial` — adversarial test results
- `GET /api/health` — health check

**Frontend:** React + TypeScript + Tailwind + Recharts (`dashboard/`)
- **Overview tab:** stat cards, severity pie chart, remediation progress, scan history bar chart
- **Issues tab:** live table from GitHub, severity/type badges
- **Adversarial Testing tab:** detection rate by vulnerability category

**Status:** 🔨 Backend built (uncommitted). Frontend partially built (uncommitted). **Dashboard design not yet approved by user.**

---

### Component 5: Adversarial Test Suite (`ishi-gupta/vuln-test-suite`)

**What it does:** Simulates real engineers accidentally introducing security bugs, then measures whether the scanner catches them.

**How it works — the two-tier Devin architecture:**

1. **God Agent (parent Devin session)** — Plans a batch of realistic bugs across vulnerability categories. Decides which types of mistakes to simulate and how they should look like natural code a developer might write.

2. **Baby Devins (child sessions)** — Each child session acts as a "careless engineer." It writes a small, realistic piece of buggy code — complete with comments, error handling, and logging — that contains a specific vulnerability. It creates a PR on the target repo explaining what the bug is and why a developer might write it that way.

3. **The scanner picks up the new PRs** → creates issues → the dashboard updates → the remediation orchestrator sends more Devin agents to fix them.

**Vulnerability categories:**
| Category | CWE | Example Pattern |
|----------|-----|-----------------|
| SQL Injection | CWE-89 | String concatenation in queries |
| XSS | CWE-79 | Unescaped user input in HTML |
| Command Injection | CWE-78 | `os.system()` with user input |
| Path Traversal | CWE-22 | `open()` with user-controlled paths |
| Hardcoded Secrets | CWE-798 | API keys and passwords in source |
| Weak Cryptography | CWE-327 | MD5/SHA1 for security purposes |
| Insecure Deserialization | CWE-502 | `pickle.loads()` on untrusted data |

**Evaluation:**
- `test_harness/expected_findings.json` — ground truth (what SHOULD be detected)
- `test_harness/evaluate.py` — compares scan results to ground truth with ±5 line tolerance
- Outputs `adversarial_results.json` with detection rate per category → feeds into the dashboard's Adversarial Testing tab

**Status:** ✅ Built — 36 planted vulnerabilities across 7 categories, 72% overall detection rate.

---

### Component 6: GitHub Actions Workflows

Two workflows:
- `scan.yml` — triggered on push to main, PR opened/updated, daily cron, manual dispatch → runs scanner → creates issues
- `remediate.yml` — triggered on issue labeled `security` → runs orchestrator in one-shot mode

**Status:** ❌ Not started.

---

## Data Flow

```
                    ┌─────────────────────────┐
                    │   ishi-gupta/superset    │
                    │      (target repo)       │
                    └──────────┬──────────────┘
                               │
                    ┌──────────▼──────────────┐
                    │     SCANNER (Comp 1)     │
                    │  Bandit + Semgrep +      │
                    │  pip-audit + Gitleaks    │
                    └──────────┬──────────────┘
                               │
                        scan_results.json
                               │
                    ┌──────────▼──────────────┐
                    │  ISSUE CREATOR (Comp 2)  │
                    │  Creates GitHub Issues   │
                    │  with CVE/CWE + labels   │
                    └──────────┬──────────────┘
                               │
                     GitHub Issues created
                               │
                    ┌──────────▼──────────────┐
                    │  ORCHESTRATOR (Comp 3)   │
                    │  Watches issues →        │
                    │  Triggers Devin sessions │
                    └──────────┬──────────────┘
                               │
                      Devin creates fix PRs
                               │
                    ┌──────────▼──────────────┐
                    │   DASHBOARD (Comp 4)     │
                    │  Shows metrics, status,  │
                    │  success rate, issues    │
                    └─────────────────────────┘

        ┌──────────────────────────────────┐
        │  ADVERSARIAL TEST SUITE (Comp 5) │
        │  Plants known vulns → runs       │
        │  scanner → measures detection    │
        │  rate → feeds dashboard          │
        └──────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Language | Python 3.11+ | Superset is Python, scanners are Python |
| SAST | Bandit, Semgrep | Bandit = Python-specific, Semgrep = multi-language + taint |
| SCA | pip-audit | Python dependency CVE database |
| Secrets | Gitleaks | Industry standard, fast |
| API Framework | FastAPI | Typed, auto-docs, async |
| Frontend | React 18 + TypeScript + Vite | Modern, fast |
| Styling | Tailwind CSS | Utility-first |
| Charts | Recharts | React-native charting |
| CI/CD | GitHub Actions | Native to GitHub |
| Remediation | Devin API | AI-assisted fixes |
| Issue Tracking | GitHub Issues | Native PR auto-close |

---

## Shared Data Models

All findings from all scanners are normalized into a common `VulnerabilityFinding` format. See `automation/models.py` for the full definition.

**Key fields:**
```
VulnerabilityFinding:
  scanner: str          # "bandit", "semgrep", "pip-audit", "gitleaks"
  scan_type: ScanType   # "sast", "sca", "secret-detection"
  severity: Severity    # "critical", "high", "medium", "low"
  title: str
  description: str
  file_path: str
  line_number: int
  code_snippet: str
  cwe_id: str           # e.g., "CWE-89" (for SAST)
  cve_id: str           # e.g., "CVE-2024-12345" (for SCA)
  package_name: str     # (for SCA)
  installed_version: str
  fixed_version: str
  remediation: str
  reference_url: str
```

---

## Environment Variables

| Variable | Required for | Description |
|----------|-------------|-------------|
| `GITHUB_TOKEN` | Issue Creator, Orchestrator, Dashboard | GitHub PAT with `repo` scope |
| `GITHUB_REPO` | All | Target repo, default: `ishi-gupta/superset` |
| `DEVIN_API_KEY` | Orchestrator | Devin API key |
| `MAX_ISSUES_PER_RUN` | Issue Creator | Max issues per scan, default: `50` |
| `DASHBOARD_HOST` | Dashboard | Default: `0.0.0.0` |
| `DASHBOARD_PORT` | Dashboard | Default: `8000` |

---

## Repo Structure

```
vuln-remediation-system/
├── automation/                 # Python package — all backend logic
│   ├── __init__.py
│   ├── config.py              # Reads env vars
│   ├── models.py              # Shared data models
│   ├── scanner.py             # Component 1: vulnerability scanner
│   ├── issue_creator.py       # Component 2: GitHub Issue creator
│   ├── orchestrator.py        # Component 3: Devin API orchestrator
│   ├── dashboard.py           # Component 4 backend: FastAPI
│   └── evaluate.py            # Runs adversarial tests
│
├── dashboard/                  # Component 4 frontend: React app
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── index.css
│       └── App.tsx
│
├── playbooks/                  # Devin playbook for remediation
│   └── remediate-vuln.md
│
├── .github/workflows/          # CI/CD
│   ├── scan.yml
│   └── remediate.yml
│
├── data/                       # Runtime data (gitignored)
│
├── docs/                       # Documentation
│   ├── ARCHITECTURE.md         # This file
│   └── PLAN.md                 # Build plan and status
│
├── pyproject.toml
├── .gitignore
└── README.md
```

---

## Scan Triggers

| Event | What happens | Full or incremental? |
|-------|-------------|---------------------|
| Push to main | Scanner runs on full repo | Full |
| PR opened/updated | Scanner runs on changed files | Incremental |
| Daily cron (midnight UTC) | Scanner runs on full repo (catches new CVEs) | Full |
| Manual (workflow_dispatch) | Scanner runs on full repo | Full |

---

## Open Decisions (Awaiting User Input)

1. **Dashboard design** — layout, metrics, visual style (3 tabs proposed: Overview / Issues / Adversarial Testing)
2. **Adversarial test categories** — which vulnerability types, how many samples per category
3. **Parallel work sessions** — how to split remaining work across agents
4. **Testing strategy** — unit, integration, adversarial, E2E demo
