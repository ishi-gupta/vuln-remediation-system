"""
Adversarial Test Generator — uses the Devin API to spin up creative red-team
sessions that generate new vulnerable code targeting the scanner's detection
patterns.

The flow:
1. Reads what the scanner detects (Bandit rules, Semgrep patterns, Gitleaks regex)
2. Spins up a Devin session with a creative prompt to generate NEW vulnerable code
3. Devin pushes the code + answer key to ishi-gupta/vuln-test-suite
4. The scanner auto-runs against it and evaluates detection rate
5. Results feed into the dashboard

Run on-demand:
    python -m automation.adversarial_generator --mode generate
    python -m automation.adversarial_generator --mode evaluate
    python -m automation.adversarial_generator --mode full  # generate + evaluate
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

from automation.config import (
    DEVIN_API_KEY,
    DEVIN_API_BASE,
    GITHUB_TOKEN,
    GITHUB_API_BASE,
    DATA_DIR,
)

logger = logging.getLogger(__name__)

TEST_SUITE_REPO = os.environ.get("TEST_SUITE_REPO", "ishi-gupta/vuln-test-suite")
REMEDIATION_REPO = os.environ.get("REMEDIATION_REPO", "ishi-gupta/vuln-remediation-system")

# Categories the scanner currently detects, with CWE IDs and tool coverage
SCANNER_CAPABILITIES = {
    "sql_injection": {
        "cwe": "CWE-89",
        "scanners": ["bandit", "semgrep"],
        "description": "SQL injection via string concatenation, f-strings, .format(), variable assignment",
        "bandit_rules": ["B608 (hardcoded_sql_expressions)"],
        "semgrep_patterns": ["python.django.security.injection.sql", "python.flask.security.injection.sql-injection"],
    },
    "xss": {
        "cwe": "CWE-79",
        "scanners": ["semgrep"],
        "description": "Cross-site scripting via unescaped user input in HTML responses",
        "semgrep_patterns": ["python.flask.security.xss", "python.django.security.audit.xss"],
        "custom_rules": "automation/rules/python_xss.yml",
    },
    "command_injection": {
        "cwe": "CWE-78",
        "scanners": ["bandit", "semgrep"],
        "description": "OS command injection via os.system(), subprocess with shell=True, exec(), eval()",
        "bandit_rules": ["B605 (start_process_with_a_shell)", "B602 (subprocess_popen_with_shell_equals_true)", "B307 (eval)"],
    },
    "path_traversal": {
        "cwe": "CWE-22",
        "scanners": ["bandit", "semgrep"],
        "description": "Directory traversal via open() with user-controlled paths, os.path.join with ../",
    },
    "hardcoded_secrets": {
        "cwe": "CWE-798",
        "scanners": ["gitleaks", "semgrep"],
        "description": "API keys, passwords, tokens, private keys hardcoded in source code",
        "gitleaks_rules": ["generic-api-key", "aws-access-key-id", "github-pat", "private-key"],
    },
    "weak_crypto": {
        "cwe": "CWE-327",
        "scanners": ["bandit", "semgrep"],
        "description": "MD5/SHA1 for passwords, random.choice() for tokens instead of secrets module",
        "bandit_rules": ["B303 (md5)", "B311 (random)"],
    },
    "insecure_deserialization": {
        "cwe": "CWE-502",
        "scanners": ["bandit", "semgrep"],
        "description": "pickle.loads(), yaml.load() without SafeLoader, eval() for JSON, marshal.loads()",
        "bandit_rules": ["B301 (pickle)", "B506 (yaml_load)"],
    },
}

ADVERSARIAL_PROMPT = """You are an AI red-team agent. Your job is to generate NEW, creative vulnerable Python code
that tests the limits of a vulnerability scanner.

## Context
You are working with a vulnerability scanner that uses these tools:
- **Bandit** (Python SAST) — checks for known dangerous function calls
- **Semgrep** (pattern matching SAST) — uses AST patterns and taint analysis
- **pip-audit** (SCA) — checks Python dependencies for known CVEs
- **Gitleaks** (secret detection) — regex-based secret scanning

## Your Mission
Generate **{num_files} new Python files** with intentionally vulnerable code. Be CREATIVE:
- Don't just write obvious `os.system(user_input)` — try obfuscated patterns
- Use indirect variable flows (taint through multiple assignments)
- Mix vulnerability types within a single file (realistic code has multiple issues)
- Make some vulnerabilities subtle enough that the scanner MIGHT miss them
- Include both easy-to-detect AND hard-to-detect patterns

## Categories to Cover
{categories_detail}

## Required Output Format
For EACH vulnerable file you create:

1. Create the Python file at `vulnerable_code/generated/round_{round_id}/<filename>.py`
2. Add corresponding entries to a NEW answer key file at `test_harness/generated/round_{round_id}_expected.json`

The answer key must follow this exact format:
```json
{{
  "round_id": "{round_id}",
  "generated_at": "<ISO timestamp>",
  "generator": "devin-adversarial",
  "vulnerabilities": [
    {{
      "id": "gen_{round_id}_001",
      "category": "<category_name>",
      "cwe_id": "<CWE-XX>",
      "file": "vulnerable_code/generated/round_{round_id}/<filename>.py",
      "line": <line_number>,
      "severity": "critical|high|medium|low",
      "description": "<what the vulnerability is>",
      "expected_scanners": ["<which scanners should catch it>"],
      "difficulty": "easy|medium|hard",
      "evasion_technique": "<how this tries to evade detection, or 'none' for straightforward patterns>"
    }}
  ]
}}
```

## Important Rules
- Each file should have 3-7 vulnerabilities
- Include a mix of difficulty levels (easy, medium, hard)
- Include at least one vulnerability per category listed above
- Use realistic-looking code (Flask routes, Django views, data processing functions)
- Add comments marking each vulnerability like: `# VULN: gen_{round_id}_XXX - <category>`
- Do NOT use any real secrets — use obviously-fake but realistically-formatted ones
- Commit and push your changes to `{test_suite_repo}` on main branch

## Repository
Clone and work in: https://github.com/{test_suite_repo}

Make sure to create the directories if they don't exist:
- `vulnerable_code/generated/round_{round_id}/`
- `test_harness/generated/`
"""


def build_categories_detail(categories: Optional[list[str]] = None) -> str:
    """Build a detailed description of vulnerability categories for the prompt."""
    if categories is None:
        categories = list(SCANNER_CAPABILITIES.keys())

    lines = []
    for cat_name in categories:
        cap = SCANNER_CAPABILITIES.get(cat_name)
        if not cap:
            continue
        lines.append(f"### {cat_name.replace('_', ' ').title()} ({cap['cwe']})")
        lines.append(f"Detected by: {', '.join(cap['scanners'])}")
        lines.append(f"Description: {cap['description']}")
        if "bandit_rules" in cap:
            lines.append(f"Bandit rules: {', '.join(cap['bandit_rules'])}")
        if "semgrep_patterns" in cap:
            lines.append(f"Semgrep patterns: {', '.join(cap['semgrep_patterns'])}")
        if "gitleaks_rules" in cap:
            lines.append(f"Gitleaks rules: {', '.join(cap['gitleaks_rules'])}")
        lines.append("")
    return "\n".join(lines)


def generate_round_id() -> str:
    """Generate a unique round ID based on timestamp."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def create_adversarial_session(
    round_id: str,
    num_files: int = 3,
    categories: Optional[list[str]] = None,
    api_key: Optional[str] = None,
) -> Optional[dict]:
    """
    Spin up a Devin session to generate new adversarial vulnerable code.

    Returns the session info dict or None on failure.
    """
    api_key = api_key or DEVIN_API_KEY
    if not api_key:
        logger.error("DEVIN_API_KEY not set. Cannot create adversarial session.")
        return None

    categories_detail = build_categories_detail(categories)

    prompt = ADVERSARIAL_PROMPT.format(
        num_files=num_files,
        round_id=round_id,
        categories_detail=categories_detail,
        test_suite_repo=TEST_SUITE_REPO,
    )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "prompt": prompt,
    }

    resp = requests.post(
        f"{DEVIN_API_BASE}/sessions",
        headers=headers,
        json=payload,
    )

    if resp.status_code in (200, 201):
        session_data = resp.json()
        session_id = session_data.get("session_id", session_data.get("id", ""))
        session_url = session_data.get("url", f"https://app.devin.ai/sessions/{session_id}")

        logger.info("Created adversarial session: %s", session_url)
        logger.info("Round ID: %s, generating %d files", round_id, num_files)

        # Save session info
        session_record = {
            "round_id": round_id,
            "session_id": session_id,
            "session_url": session_url,
            "num_files": num_files,
            "categories": categories or list(SCANNER_CAPABILITIES.keys()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "in_progress",
        }

        _save_session_record(session_record)
        return session_record

    logger.error(
        "Failed to create adversarial session: %s - %s",
        resp.status_code,
        resp.text[:300],
    )
    return None


def _save_session_record(record: dict) -> None:
    """Save an adversarial session record to the data directory."""
    records_file = DATA_DIR / "adversarial_sessions.json"
    records = []
    if records_file.exists():
        with open(records_file) as f:
            records = json.load(f)
    records.append(record)
    with open(records_file, "w") as f:
        json.dump(records, f, indent=2)


def check_session_status(session_id: str, api_key: Optional[str] = None) -> Optional[str]:
    """Check if a Devin session is finished."""
    api_key = api_key or DEVIN_API_KEY
    headers = {"Authorization": f"Bearer {api_key}"}

    resp = requests.get(f"{DEVIN_API_BASE}/sessions/{session_id}", headers=headers)
    if resp.status_code == 200:
        return resp.json().get("status", "unknown")
    return None


def wait_for_session(session_id: str, timeout: int = 1800, poll_interval: int = 30) -> str:
    """Wait for a session to complete. Returns final status."""
    logger.info("Waiting for session %s (timeout: %ds)...", session_id, timeout)
    start = time.time()
    while time.time() - start < timeout:
        status = check_session_status(session_id)
        if status in ("finished", "stopped", "error", "expired", "blocked"):
            logger.info("Session %s completed with status: %s", session_id, status)
            return status
        logger.info("Session %s status: %s (elapsed: %.0fs)", session_id, status, time.time() - start)
        time.sleep(poll_interval)
    logger.warning("Session %s timed out after %ds", session_id, timeout)
    return "timeout"


def run_evaluation(
    test_suite_path: str,
    scanner_repo_path: str,
    round_id: Optional[str] = None,
) -> dict:
    """
    Run the scanner against the test suite and evaluate results.

    If round_id is specified, only evaluate that round's generated code.
    Otherwise, evaluate all code in the test suite.
    """
    logger.info("Running evaluation against %s", test_suite_path)

    # Run the scanner
    scan_output = DATA_DIR / "adversarial_scan_results.json"
    target = str(Path(test_suite_path).resolve())

    cmd = [
        sys.executable, "-m", "automation.scanner",
        "--target", target,
        "--output", str(scan_output),
        "--no-persist-state",
    ]

    result = subprocess.run(
        cmd,
        cwd=scanner_repo_path,
        capture_output=True,
        text=True,
        timeout=600,
    )

    logger.info("Scanner stdout: %s", result.stdout[-500:] if result.stdout else "")
    if result.stderr:
        logger.info("Scanner stderr: %s", result.stderr[-500:])

    if not scan_output.exists():
        logger.error("Scanner did not produce output")
        return {"error": "Scanner failed"}

    with open(scan_output) as f:
        scan_results = json.load(f)

    # Load expected findings
    expected_path = Path(test_suite_path) / "test_harness" / "expected_findings.json"
    if not expected_path.exists():
        logger.error("Expected findings not found: %s", expected_path)
        return {"error": "Expected findings not found"}

    # Also load any generated round expectations
    generated_dir = Path(test_suite_path) / "test_harness" / "generated"
    all_expected = []

    with open(expected_path) as f:
        base_expected = json.load(f)
        all_expected.extend(base_expected.get("vulnerabilities", []))

    if generated_dir.exists():
        for gen_file in sorted(generated_dir.glob("round_*_expected.json")):
            if round_id and round_id not in gen_file.name:
                continue
            with open(gen_file) as f:
                gen_data = json.load(f)
                all_expected.extend(gen_data.get("vulnerabilities", []))

    # Evaluate
    findings = scan_results.get("findings", [])
    total_expected = len(all_expected)
    detected = 0
    missed = []
    category_stats: dict[str, dict] = {}

    for exp in all_expected:
        cat = exp.get("category", "unknown")
        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "detected": 0, "missed": []}
        category_stats[cat]["total"] += 1

        # Check if any finding matches this expected vulnerability
        exp_file = exp.get("file", "")
        exp_line = exp.get("line", 0)
        found = False
        for finding in findings:
            f_file = finding.get("file_path", "")
            f_line = finding.get("line_number", 0)
            # Match if same file and within 5 lines (scanners sometimes report nearby lines)
            if exp_file and f_file and (exp_file in f_file or f_file in exp_file):
                if abs(f_line - exp_line) <= 5:
                    found = True
                    break

        if found:
            detected += 1
            category_stats[cat]["detected"] += 1
        else:
            missed.append(exp)
            category_stats[cat]["missed"].append(exp)

    detection_rate = detected / total_expected if total_expected > 0 else 0

    results = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "round_id": round_id or "all",
        "total_planted": total_expected,
        "total_detected": detected,
        "total_missed": total_expected - detected,
        "overall_detection_rate": round(detection_rate, 4),
        "scanner_findings_count": len(findings),
        "categories": [
            {
                "name": cat,
                "total": stats["total"],
                "detected": stats["detected"],
                "rate": round(stats["detected"] / stats["total"], 4) if stats["total"] > 0 else 0,
                "missed_details": [
                    {
                        "id": m.get("id", ""),
                        "description": m.get("description", ""),
                        "file": m.get("file", ""),
                        "line": m.get("line", 0),
                        "difficulty": m.get("difficulty", "unknown"),
                    }
                    for m in stats["missed"]
                ],
            }
            for cat, stats in sorted(category_stats.items())
        ],
    }

    # Save results
    results_file = DATA_DIR / "adversarial_results.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)

    logger.info("Detection rate: %.1f%% (%d/%d)", detection_rate * 100, detected, total_expected)
    return results


def run_full_cycle(
    num_files: int = 3,
    categories: Optional[list[str]] = None,
    wait: bool = True,
    test_suite_path: Optional[str] = None,
    scanner_repo_path: Optional[str] = None,
) -> dict:
    """
    Run a full adversarial cycle: generate → wait → pull → evaluate.

    Returns the evaluation results.
    """
    round_id = generate_round_id()

    # Step 1: Create Devin session to generate adversarial code
    logger.info("Step 1: Creating adversarial Devin session (round %s)...", round_id)
    session = create_adversarial_session(round_id, num_files, categories)
    if not session:
        return {"error": "Failed to create adversarial session"}

    result = {
        "round_id": round_id,
        "session": session,
    }

    if not wait:
        logger.info("Session created. Not waiting (--no-wait). Check session: %s", session["session_url"])
        return result

    # Step 2: Wait for Devin to finish generating
    logger.info("Step 2: Waiting for Devin to generate adversarial code...")
    final_status = wait_for_session(session["session_id"])
    result["session_status"] = final_status

    if final_status not in ("finished", "stopped"):
        logger.error("Session did not complete successfully: %s", final_status)
        return result

    # Step 3: Pull latest test suite
    if test_suite_path:
        logger.info("Step 3: Pulling latest test suite...")
        subprocess.run(
            ["git", "pull", "origin", "main"],
            cwd=test_suite_path,
            capture_output=True,
        )

    # Step 4: Evaluate
    if test_suite_path and scanner_repo_path:
        logger.info("Step 4: Evaluating scanner against new adversarial code...")
        eval_results = run_evaluation(test_suite_path, scanner_repo_path, round_id)
        result["evaluation"] = eval_results

    return result


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="[adversarial] %(levelname)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Adversarial test generator — AI red team for the vulnerability scanner"
    )
    parser.add_argument(
        "--mode",
        choices=["generate", "evaluate", "full"],
        default="full",
        help="Mode: generate (create Devin session), evaluate (run scanner), full (both)",
    )
    parser.add_argument(
        "--num-files",
        type=int,
        default=3,
        help="Number of vulnerable files to generate (default: 3)",
    )
    parser.add_argument(
        "--categories",
        nargs="+",
        default=None,
        help="Vulnerability categories to target (default: all). Accepts space-separated or comma-separated values.",
    )
    parser.add_argument(
        "--test-suite",
        default=None,
        help="Path to local vuln-test-suite repo",
    )
    parser.add_argument(
        "--scanner-repo",
        default=None,
        help="Path to local vuln-remediation-system repo",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Don't wait for the Devin session to finish (just create it)",
    )
    parser.add_argument(
        "--round-id",
        default=None,
        help="Evaluate a specific round (for --mode evaluate)",
    )
    args = parser.parse_args()

    # Handle comma-separated categories (e.g., from GitHub Actions input)
    if args.categories:
        expanded: list[str] = []
        for cat in args.categories:
            expanded.extend(c.strip() for c in cat.split(",") if c.strip())
        args.categories = expanded

    if args.mode == "generate":
        round_id = generate_round_id()
        session = create_adversarial_session(
            round_id, args.num_files, args.categories
        )
        if session:
            print(f"\nAdversarial session created!")
            print(f"  Round ID:    {round_id}")
            print(f"  Session URL: {session['session_url']}")
            print(f"  Files:       {args.num_files}")
            print(f"  Categories:  {', '.join(session['categories'])}")
            if not args.no_wait:
                print(f"\nWaiting for session to complete...")
                status = wait_for_session(session["session_id"])
                print(f"  Final status: {status}")

    elif args.mode == "evaluate":
        test_suite = args.test_suite
        scanner_repo = args.scanner_repo
        if not test_suite or not scanner_repo:
            print("ERROR: --test-suite and --scanner-repo are required for evaluate mode")
            sys.exit(1)
        results = run_evaluation(test_suite, scanner_repo, args.round_id)
        if "error" in results:
            print(f"ERROR: {results['error']}")
            sys.exit(1)
        print(f"\nDetection rate: {results.get('overall_detection_rate', 0):.1%}")
        print(f"Detected: {results.get('total_detected', 0)}/{results.get('total_planted', 0)}")
        for cat in results.get("categories", []):
            print(f"  {cat['name']:30s} {cat['detected']}/{cat['total']} ({cat['rate']:.0%})")

    elif args.mode == "full":
        results = run_full_cycle(
            num_files=args.num_files,
            categories=args.categories,
            wait=not args.no_wait,
            test_suite_path=args.test_suite,
            scanner_repo_path=args.scanner_repo,
        )
        if "evaluation" in results:
            eval_r = results["evaluation"]
            if "error" in eval_r:
                print(f"Evaluation error: {eval_r['error']}")
                sys.exit(1)
            print(f"\n{'='*60}")
            print(f"ADVERSARIAL TEST RESULTS (Round {results['round_id']})")
            print(f"{'='*60}")
            print(f"Detection rate: {eval_r.get('overall_detection_rate', 0):.1%}")
            print(f"Detected: {eval_r.get('total_detected', 0)}/{eval_r.get('total_planted', 0)}")
        elif "error" in results:
            print(f"Error: {results['error']}")
        else:
            print(f"Session created: {results.get('session', {}).get('session_url', 'unknown')}")


if __name__ == "__main__":
    main()
