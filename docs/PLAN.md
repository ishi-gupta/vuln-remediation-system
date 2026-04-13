# Build Plan & Status

## Project Goal

Build a presentation-ready, event-driven vulnerability remediation system that:
1. Automatically detects security vulnerabilities in `ishi-gupta/superset`
2. Creates GitHub Issues for each finding (with CVE/CWE IDs)
3. Triggers Devin AI sessions to remediate them
4. Displays everything on a live observability dashboard
5. Validates the scanner using an adversarial test suite with known vulnerabilities

---

## Build Status

| Component | Status | Notes |
|-----------|--------|-------|
| Vulnerability Scanner | ✅ Built | `automation/scanner.py` — Bandit, Semgrep, pip-audit, Gitleaks |
| Shared Models | ✅ Built | `automation/models.py` — VulnerabilityFinding, ScanRun, etc. |
| Config | ✅ Built | `automation/config.py` — reads from env vars |
| Issue Creator | 🔨 Built (uncommitted) | `automation/issue_creator.py` — needs update: remove MD report, keep GitHub Issues only |
| Orchestrator | 🔨 Built (uncommitted) | `automation/orchestrator.py` — Devin API integration |
| Dashboard Backend | 🔨 Built (uncommitted) | `automation/dashboard.py` — FastAPI |
| Dashboard Frontend | 🔨 Partial (uncommitted) | `dashboard/src/App.tsx` — React, needs design approval |
| Adversarial Test Suite | ❌ Not started | Separate repo: `ishi-gupta/vuln-test-suite` |
| GitHub Actions | ❌ Not started | `scan.yml` + `remediate.yml` |
| Devin Playbook | ❌ Not started | `playbooks/remediate-vuln.md` |
| Docs (schemas, interfaces) | ❌ Not started | `docs/schemas.md`, `docs/interfaces.md` |

---

## Decisions Made

| Decision | Choice | Reason |
|----------|--------|--------|
| Repo structure | 3 separate repos | Keeps Superset fork clean, automation reusable |
| Issue tracking | GitHub Issues (not Linear) | Native PR auto-close, zero extra setup |
| Report format | Dashboard only (no standalone MD report) | Dashboard is the presentation layer |
| Scanners | Core 3: SAST + SCA + Secrets | Can add DAST/Container/IaC later |
| SAST tools | Bandit + Semgrep | Bandit = Python-specific, Semgrep = multi-lang + taint |
| SCA tool | pip-audit | Python dependency CVE database |
| Secret tool | Gitleaks | Industry standard |
| Frontend stack | React + TypeScript + Vite + Tailwind + Recharts | Modern, fast, presentation-ready |
| Backend stack | FastAPI | Typed, auto-docs, async |

---

## Decisions Pending (Awaiting User Input)

1. **Dashboard design** — layout, metrics, visual style
2. **Adversarial test categories** — which vulnerability types, samples per category
3. **Parallel work sessions** — how to split remaining work across agents
4. **Testing strategy** — what counts as "working"

---

## How to Test the Scanner

### Prerequisites
```bash
pip install bandit semgrep pip-audit
# Gitleaks: download binary from https://github.com/gitleaks/gitleaks/releases
```

### Run Against a Repo
```bash
# Scan a GitHub repo
python -m automation.scanner --target ishi-gupta/superset --output scan_results.json

# Scan a local directory
python -m automation.scanner --target /path/to/repo --output scan_results.json

# Run specific scanners only
python -m automation.scanner --target ishi-gupta/superset --scanners bandit semgrep --output scan_results.json
```

### Expected Output Format
The scanner outputs `scan_results.json`:
```json
{
  "scan_run": {
    "scan_id": "abc123",
    "target_repo": "ishi-gupta/superset",
    "timestamp": "2026-04-13T00:00:00",
    "scanners_used": ["bandit", "semgrep", "pip-audit", "gitleaks"],
    "total_findings": 42,
    "critical": 2,
    "high": 10,
    "medium": 20,
    "low": 10,
    "duration_seconds": 45.2
  },
  "findings": [
    {
      "finding_id": "a1b2c3d4e5f6",
      "scanner": "bandit",
      "scan_type": "sast",
      "severity": "high",
      "title": "Possible SQL injection via string-based query construction",
      "description": "...",
      "file_path": "superset/views/core.py",
      "line_number": 142,
      "code_snippet": "query = \"SELECT * FROM \" + user_input",
      "cwe_id": "CWE-89",
      "cve_id": "",
      "confidence": "high",
      "remediation": "Use parameterized queries instead of string concatenation.",
      "reference_url": "https://bandit.readthedocs.io/en/latest/..."
    },
    {
      "finding_id": "f6e5d4c3b2a1",
      "scanner": "pip-audit",
      "scan_type": "sca",
      "severity": "high",
      "title": "CVE-2026-12345: Vulnerability in flask",
      "description": "...",
      "file_path": "requirements.txt",
      "line_number": 0,
      "cve_id": "CVE-2026-12345",
      "package_name": "flask",
      "installed_version": "2.3.2",
      "fixed_version": "2.3.5",
      "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"
    }
  ]
}
```

---

## How Everything Connects (The Full Pipeline)

```
Push to ishi-gupta/superset
        │
        ▼
GitHub Actions: scan.yml triggers
        │
        ▼
Scanner runs (Bandit + Semgrep + pip-audit + Gitleaks)
        │
        ▼
scan_results.json produced
        │
        ▼
Issue Creator reads JSON → creates GitHub Issues
        │
        ▼
GitHub Actions: remediate.yml triggers on new issue
        │
        ▼
Orchestrator reads issue → calls Devin API
        │
        ▼
Devin creates a fix PR referencing the issue
        │
        ▼
PR merges → issue auto-closes (GitHub native)
        │
        ▼
Dashboard shows it all in real time
```

---

## Environment Variables Required

| Variable | Required for | How to get it |
|----------|-------------|---------------|
| `GITHUB_TOKEN` | Issue Creator, Orchestrator, Dashboard | GitHub Settings → PAT with `repo` scope |
| `DEVIN_API_KEY` | Orchestrator | Devin Settings → API Keys |
| `GITHUB_REPO` | All (default: `ishi-gupta/superset`) | Set if targeting a different repo |

---

## For New Agents Working on This Repo

1. Read this file first for full context
2. Read `docs/ARCHITECTURE.md` for detailed component specs
3. The scanner (`automation/scanner.py`) is the first component to test
4. All data models are in `automation/models.py` — any component you build should use these
5. Config is in `automation/config.py` — all secrets come from environment variables
6. Check "Decisions Pending" above — some components are blocked on user approval
