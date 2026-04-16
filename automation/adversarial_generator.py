"""
Adversarial Generator — uses Devin sessions to simulate careless engineers
introducing realistic security bugs into a target repo.

Two-tier architecture:
  1. God Agent (this script, --plan mode): Plans a batch of bugs across
     vulnerability categories, then spawns child Devin sessions.
  2. Baby Devins (child sessions): Each acts as a "careless engineer,"
     writing a small piece of realistic buggy code and creating a PR.

Usage:
    # Plan bugs and spawn child sessions to plant them
    python -m automation.adversarial_generator \
        --repo ishi-gupta/superset \
        --count 5 \
        --categories sql_injection command_injection xss

    # Dry run — just print the bug specs without creating sessions
    python -m automation.adversarial_generator \
        --repo ishi-gupta/superset \
        --count 3 \
        --dry-run
"""

import argparse
import json
import logging
import os
import random
import sys
from datetime import datetime, timezone
from typing import Optional

import requests

from automation.config import (
    DEVIN_API_KEY,
    DEVIN_API_BASE,
    DEVIN_ORG_ID,
    DATA_DIR,
)

# Playbook for adversarial baby Devin sessions
ADVERSARIAL_PLAYBOOK_ID = os.environ.get(
    "ADVERSARIAL_PLAYBOOK_ID", "playbook-b281fb97e83646bb80ca8686564f7fa9"
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Vulnerability category definitions
# ---------------------------------------------------------------------------

VULNERABILITY_CATEGORIES = {
    "sql_injection": {
        "cwe_id": "CWE-89",
        "severity": "high",
        "description": "SQL Injection — user input concatenated into SQL queries",
        "patterns": [
            {
                "name": "string_concat_select",
                "description": "String concatenation in a SELECT query",
                "hint": "Write a function that builds a SQL SELECT query by concatenating user input directly into the query string. Use simple string concatenation (+) with a variable that comes from a function parameter. Add a docstring, logging, and error handling so it looks like production code.",
            },
            {
                "name": "fstring_insert",
                "description": "f-string used to build an INSERT statement",
                "hint": "Write a function that inserts data into a database using an f-string to build the INSERT statement. Include proper connection handling and a try/except block. The vulnerability should be in the f-string interpolation of user-provided values.",
            },
            {
                "name": "format_where_clause",
                "description": ".format() used in a WHERE clause",
                "hint": "Write a search/filter function that uses str.format() to build a WHERE clause with multiple conditions. Include pagination logic (LIMIT/OFFSET) to make it look realistic. The vulnerability is in the .format() call with user input.",
            },
            {
                "name": "dynamic_table_name",
                "description": "User-controlled table name in query",
                "hint": "Write a generic data export function that takes a table name as a parameter and queries it. The function should look like a utility/admin tool. The vulnerability is that the table name is not validated or parameterized.",
            },
            {
                "name": "multiline_query_builder",
                "description": "Query built across multiple lines obscuring the injection",
                "hint": "Write a report generation function that builds a complex SQL query across multiple lines using += to append conditions. Include date range filtering and sorting. The vulnerability is hidden in the multi-line string building.",
            },
        ],
    },
    "command_injection": {
        "cwe_id": "CWE-78",
        "severity": "critical",
        "description": "Command Injection — user input passed to OS commands",
        "patterns": [
            {
                "name": "os_system_ping",
                "description": "os.system() with user-controlled host",
                "hint": "Write a network health check function that pings a user-provided hostname using os.system(). Include timeout handling and result logging. Make it look like a monitoring utility.",
            },
            {
                "name": "subprocess_shell_true",
                "description": "subprocess with shell=True and user input",
                "hint": "Write a file processing function that uses subprocess.call() with shell=True to run a command on a user-provided file path. Include file existence checks and proper error handling.",
            },
            {
                "name": "os_popen_grep",
                "description": "os.popen() with user-controlled search pattern",
                "hint": "Write a log search function that uses os.popen() to grep through log files with a user-provided search pattern. Include result parsing and formatting.",
            },
            {
                "name": "backtick_eval_config",
                "description": "eval() of user-provided configuration expression",
                "hint": "Write a configuration parser that uses eval() to process dynamic config values. The function should look like it handles math expressions or conditional config (e.g., '2 * num_cpus'). Include validation that looks thorough but misses the core issue.",
            },
            {
                "name": "subprocess_pipe_chain",
                "description": "Piped subprocess commands with user input",
                "hint": "Write a data processing function that pipes multiple commands together using subprocess with shell=True, incorporating user-provided filtering or transformation parameters.",
            },
        ],
    },
    "xss": {
        "cwe_id": "CWE-79",
        "severity": "high",
        "description": "Cross-Site Scripting — unescaped user input in HTML output",
        "patterns": [
            {
                "name": "direct_html_concat",
                "description": "Direct HTML string concatenation with user input",
                "hint": "Write a Flask/web handler function that builds an HTML response by concatenating user input directly into an HTML string. Include proper HTTP headers and status codes to make it look production-ready. The vulnerability is in the unescaped user input in the HTML.",
            },
            {
                "name": "template_render_unsafe",
                "description": "render_template_string with user input",
                "hint": "Write a Flask endpoint that uses render_template_string() with user-provided template content or variables. Include authentication checks and logging. The vulnerability is in passing unescaped data to the template.",
            },
            {
                "name": "json_to_script_tag",
                "description": "User data serialized into a <script> tag",
                "hint": "Write a function that generates an HTML page with embedded JavaScript data by serializing user-provided values into a <script> tag using json.dumps or string formatting. The vulnerability is in the lack of HTML entity encoding.",
            },
            {
                "name": "markup_bypass",
                "description": "markupsafe.Markup() wrapping untrusted input",
                "hint": "Write a function that uses markupsafe.Markup() to mark user-provided HTML as safe, bypassing Jinja2 auto-escaping. The function should look like it's trying to allow 'safe' HTML formatting but actually allows XSS.",
            },
        ],
    },
    "path_traversal": {
        "cwe_id": "CWE-22",
        "severity": "high",
        "description": "Path Traversal — user input used to construct file paths",
        "patterns": [
            {
                "name": "open_user_path",
                "description": "open() with user-controlled filename",
                "hint": "Write a file download/view endpoint that opens a file based on a user-provided filename. Include content-type detection and streaming. The vulnerability is in using the filename directly without path validation.",
            },
            {
                "name": "path_join_unsanitized",
                "description": "os.path.join() with unsanitized user input",
                "hint": "Write a file upload handler that uses os.path.join() with a base directory and a user-provided filename. Include file size checks and extension validation, but miss the path traversal via ../. The os.path.join behavior with absolute paths makes this subtle.",
            },
            {
                "name": "write_to_user_path",
                "description": "Writing data to a user-specified file path",
                "hint": "Write a configuration save function that writes settings to a user-specified file path. Include proper JSON formatting and backup logic. The vulnerability is in not restricting where files can be written.",
            },
            {
                "name": "listdir_user_input",
                "description": "os.listdir() with user-controlled directory",
                "hint": "Write a directory browsing API that lists files in a user-specified directory. Include filtering by extension and pagination. The vulnerability is in not restricting which directories can be listed.",
            },
        ],
    },
    "hardcoded_secrets": {
        "cwe_id": "CWE-798",
        "severity": "critical",
        "description": "Hardcoded Secrets — credentials and API keys in source code",
        "patterns": [
            {
                "name": "api_key_constant",
                "description": "API key stored as a Python constant",
                "hint": "Write a third-party API client class with an API key stored as a class constant or module-level variable. Include proper request methods, retry logic, and error handling. The secret should look like a real API key (e.g., sk-proj-...).",
            },
            {
                "name": "db_password_config",
                "description": "Database password in a config dictionary",
                "hint": "Write a database configuration module with connection parameters in a dictionary, including a hardcoded password. Include connection pooling setup and SSL configuration to make it look like a real config file.",
            },
            {
                "name": "jwt_secret_inline",
                "description": "JWT signing secret hardcoded in auth code",
                "hint": "Write a JWT token generation function with the signing secret hardcoded as a string. Include proper claims, expiration handling, and token validation. The secret should be a realistic-looking random string.",
            },
            {
                "name": "aws_credentials",
                "description": "AWS access key and secret key in source",
                "hint": "Write an S3 upload utility with AWS credentials hardcoded. Include bucket configuration, content-type detection, and presigned URL generation. Use realistic-looking (but fake) AWS key formats.",
            },
            {
                "name": "webhook_url_with_token",
                "description": "Webhook URL containing an auth token",
                "hint": "Write a notification sender that POSTs to a webhook URL with an embedded authentication token. Include message formatting, retry logic, and rate limiting.",
            },
        ],
    },
    "weak_crypto": {
        "cwe_id": "CWE-327",
        "severity": "medium",
        "description": "Weak Cryptography — use of broken or risky algorithms",
        "patterns": [
            {
                "name": "md5_password_hash",
                "description": "MD5 used for password hashing",
                "hint": "Write a user registration/authentication module that uses hashlib.md5() to hash passwords. Include salt generation, but use MD5 instead of bcrypt/argon2. Add login verification logic to make it look complete.",
            },
            {
                "name": "sha1_signature",
                "description": "SHA1 used for message signing",
                "hint": "Write a webhook signature verification function that uses SHA1 for HMAC signing. Include timing-safe comparison and proper header parsing, but the underlying algorithm is weak.",
            },
            {
                "name": "random_token_generation",
                "description": "random module used for security tokens",
                "hint": "Write a password reset token generator that uses random.choice() or random.randint() instead of secrets module. Include token expiration and storage logic. The vulnerability is using a non-cryptographic PRNG.",
            },
            {
                "name": "ecb_mode_encryption",
                "description": "AES in ECB mode for encryption",
                "hint": "Write an encryption utility that uses AES in ECB mode for encrypting sensitive data. Include key derivation and base64 encoding. The vulnerability is using ECB mode which doesn't provide semantic security.",
            },
        ],
    },
    "insecure_deserialization": {
        "cwe_id": "CWE-502",
        "severity": "critical",
        "description": "Insecure Deserialization — untrusted data deserialized unsafely",
        "patterns": [
            {
                "name": "pickle_loads_request",
                "description": "pickle.loads() on data from an HTTP request",
                "hint": "Write a data import endpoint that accepts serialized Python objects via pickle.loads(). Include content-type checking and size limits. The vulnerability is in deserializing untrusted pickle data.",
            },
            {
                "name": "yaml_unsafe_load",
                "description": "yaml.load() without SafeLoader",
                "hint": "Write a YAML configuration parser that uses yaml.load() without specifying Loader=yaml.SafeLoader. Include schema validation after loading, but the vulnerability is in the unsafe load itself.",
            },
            {
                "name": "eval_json_alternative",
                "description": "eval() used instead of json.loads()",
                "hint": "Write a data parsing function that uses eval() to parse what looks like JSON data (but could be arbitrary Python). Include input sanitization that looks thorough but is bypassable. Add a comment like 'handles edge cases json.loads misses'.",
            },
            {
                "name": "marshal_loads",
                "description": "marshal.loads() on untrusted data",
                "hint": "Write a code caching/loading system that uses marshal.loads() to deserialize cached bytecode from a file or network source. Include version checking and cache invalidation.",
            },
        ],
    },
}

# ---------------------------------------------------------------------------
# Bug spec generation (God Agent planning)
# ---------------------------------------------------------------------------


def plan_bugs(
    categories: list[str],
    count: int,
    target_repo: str,
) -> list[dict]:
    """
    Plan a batch of adversarial bugs to plant.

    The God Agent selects vulnerability patterns and creates detailed specs
    for each child Devin session ("Baby Devin") to implement.

    Returns a list of bug specs, each containing:
      - category, cwe_id, severity
      - pattern name and description
      - detailed implementation hints for the child session
      - target repo information
    """
    available_categories = categories or list(VULNERABILITY_CATEGORIES.keys())

    # Validate categories
    invalid = [c for c in available_categories if c not in VULNERABILITY_CATEGORIES]
    if invalid:
        logger.error("Unknown categories: %s", invalid)
        logger.info("Valid categories: %s", list(VULNERABILITY_CATEGORIES.keys()))
        sys.exit(1)

    bug_specs: list[dict] = []

    # Distribute bugs across categories as evenly as possible
    cats_cycle = available_categories * ((count // len(available_categories)) + 1)
    selected_cats = cats_cycle[:count]

    # Track which patterns we've used per category to avoid repeats
    used_patterns: dict[str, list[int]] = {cat: [] for cat in available_categories}

    for i, cat_name in enumerate(selected_cats):
        cat = VULNERABILITY_CATEGORIES[cat_name]
        patterns = cat["patterns"]

        # Pick a pattern we haven't used yet (or cycle if we've used them all)
        available_indices = [
            j for j in range(len(patterns)) if j not in used_patterns[cat_name]
        ]
        if not available_indices:
            used_patterns[cat_name] = []
            available_indices = list(range(len(patterns)))

        pattern_idx = random.choice(available_indices)
        used_patterns[cat_name].append(pattern_idx)
        pattern = patterns[pattern_idx]

        bug_id = f"adv_{cat_name[:4]}_{i + 1:03d}"

        bug_specs.append({
            "bug_id": bug_id,
            "category": cat_name,
            "cwe_id": cat["cwe_id"],
            "severity": cat["severity"],
            "pattern_name": pattern["name"],
            "pattern_description": pattern["description"],
            "implementation_hint": pattern["hint"],
            "target_repo": target_repo,
            "planned_at": datetime.now(timezone.utc).isoformat(),
        })

    return bug_specs


# ---------------------------------------------------------------------------
# Baby Devin prompt generation
# ---------------------------------------------------------------------------

BABY_DEVIN_PROMPT = """You are simulating a software developer who accidentally introduces a security vulnerability while writing code. Your job is to write realistic, production-quality code that contains a specific security bug.

## Your Task

**Repository:** https://github.com/{target_repo}
**Vulnerability Category:** {category_display} ({cwe_id})
**Pattern:** {pattern_description}

## Instructions

1. Clone the repository.
2. Create a new Python file in a location that makes sense for the codebase (e.g., a utility module, a helper function, a new endpoint). Name it something natural — NOT "vulnerable_code" or "insecure_*.py".
3. Write a small, realistic function or class (30–80 lines) that:
   - Looks like normal code a real developer would write
   - Has proper docstrings, type hints, logging, and error handling
   - Contains exactly ONE security vulnerability of the specified type
   - Includes a subtle comment like "TODO: review security" or "FIXME: validate input" near the vulnerable line (simulating a developer who noticed but didn't fix it)
4. The code should NOT be obviously malicious — it should look like an honest mistake.

## Specific Guidance

{implementation_hint}

## Create a PR

Create a PR with:
- **Branch name:** `feature/{pattern_name}`
- **Title:** A natural-sounding feature title (NOT mentioning vulnerabilities), e.g., "Add network health check utility" or "Add data export helper"
- **Body:** Include:
  - A brief description of what the code does (the feature, not the bug)
  - Under a "## Security Note" section, explain what the vulnerability is, its CWE ID ({cwe_id}), and why a developer might write it this way
  - Add the label `adversarial` to the PR if possible

## Important

- Write code that fits naturally in the target codebase
- Do NOT use variable names like "malicious", "unsafe", "vulnerable", "exploit"
- DO use realistic variable names, function names, and module names
- The vulnerability should be the kind of thing that passes code review if reviewers aren't security-focused
"""


def generate_baby_devin_prompt(bug_spec: dict) -> str:
    """Generate the prompt for a child Devin session from a bug spec."""
    category_display = bug_spec["category"].replace("_", " ").title()
    return BABY_DEVIN_PROMPT.format(
        target_repo=bug_spec["target_repo"],
        category_display=category_display,
        cwe_id=bug_spec["cwe_id"],
        pattern_description=bug_spec["pattern_description"],
        implementation_hint=bug_spec["implementation_hint"],
        pattern_name=bug_spec["pattern_name"],
    )


# ---------------------------------------------------------------------------
# Devin session creation
# ---------------------------------------------------------------------------


def create_devin_session(
    prompt: str,
    api_key: str,
    org_id: Optional[str] = None,
    playbook_id: Optional[str] = None,
) -> Optional[dict]:
    """Create a Devin session to plant a bug via the v3 API.

    Uses ``/v3/organizations/{org_id}/sessions`` which requires a service-user
    key with the ``ManageOrgSessions`` permission.
    """
    org_id = org_id or DEVIN_ORG_ID
    if not org_id:
        logger.error("DEVIN_ORG_ID is required for v3 API.")
        return None

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload: dict = {
        "prompt": prompt,
    }

    if playbook_id:
        payload["playbook_id"] = playbook_id

    resp = requests.post(
        f"{DEVIN_API_BASE}/organizations/{org_id}/sessions",
        headers=headers,
        json=payload,
        timeout=60,
    )

    if resp.status_code in (200, 201):
        return resp.json()

    logger.error(
        "Failed to create Devin session: %s - %s",
        resp.status_code,
        resp.text[:300],
    )
    return None


def spawn_baby_devins(
    bug_specs: list[dict],
    api_key: str,
    org_id: Optional[str] = None,
    playbook_id: Optional[str] = None,
    max_concurrent: int = 5,
) -> list[dict]:
    """
    Spawn child Devin sessions to plant bugs.

    Each session gets a prompt describing one specific vulnerability to
    introduce. Returns a list of session records for tracking.
    """
    sessions: list[dict] = []

    for i, spec in enumerate(bug_specs):
        if i >= max_concurrent:
            logger.warning(
                "Reached max concurrent sessions (%d). Remaining %d bugs not spawned.",
                max_concurrent,
                len(bug_specs) - i,
            )
            break

        prompt = generate_baby_devin_prompt(spec)
        logger.info(
            "Spawning Baby Devin %d/%d: %s (%s)",
            i + 1,
            len(bug_specs),
            spec["pattern_name"],
            spec["category"],
        )

        session = create_devin_session(
            prompt, api_key, org_id=org_id, playbook_id=playbook_id,
        )
        if session:
            session_id = session.get("session_id", session.get("id", ""))
            session_url = session.get(
                "url", f"https://app.devin.ai/sessions/{session_id}"
            )
            sessions.append({
                "bug_id": spec["bug_id"],
                "category": spec["category"],
                "cwe_id": spec["cwe_id"],
                "pattern_name": spec["pattern_name"],
                "session_id": session_id,
                "session_url": session_url,
                "status": "spawned",
                "spawned_at": datetime.now(timezone.utc).isoformat(),
            })
            logger.info("  -> Session: %s", session_url)
        else:
            sessions.append({
                "bug_id": spec["bug_id"],
                "category": spec["category"],
                "cwe_id": spec["cwe_id"],
                "pattern_name": spec["pattern_name"],
                "session_id": "",
                "session_url": "",
                "status": "failed_to_spawn",
                "spawned_at": datetime.now(timezone.utc).isoformat(),
            })

    return sessions


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Adversarial Generator — simulate careless engineers introducing security bugs"
    )
    parser.add_argument(
        "--repo",
        default="ishi-gupta/superset",
        help="Target repo to plant bugs in (default: ishi-gupta/superset)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of bugs to plan (default: 5)",
    )
    parser.add_argument(
        "--categories",
        nargs="*",
        default=None,
        help="Vulnerability categories to use (default: all). "
        f"Options: {', '.join(VULNERABILITY_CATEGORIES.keys())}",
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=5,
        help="Max concurrent Devin sessions (default: 5)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan bugs and print specs without creating sessions",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output file for bug specs / session records (default: data/adversarial_plan.json)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="[adversarial] %(levelname)s: %(message)s",
    )

    # Plan the bugs
    logger.info(
        "Planning %d adversarial bugs for %s ...", args.count, args.repo
    )
    bug_specs = plan_bugs(
        categories=args.categories or [],
        count=args.count,
        target_repo=args.repo,
    )

    output_path = args.output or str(DATA_DIR / "adversarial_plan.json")

    if args.dry_run:
        # Just print the plan
        print("\n" + "=" * 60)
        print("ADVERSARIAL BUG PLAN (DRY RUN)")
        print("=" * 60)
        for i, spec in enumerate(bug_specs):
            print(f"\n--- Bug {i + 1}/{len(bug_specs)} ---")
            print(f"  ID:       {spec['bug_id']}")
            print(f"  Category: {spec['category']}")
            print(f"  CWE:      {spec['cwe_id']}")
            print(f"  Severity: {spec['severity']}")
            print(f"  Pattern:  {spec['pattern_name']}")
            print(f"  Desc:     {spec['pattern_description']}")
            print(f"  Target:   {spec['target_repo']}")

        # Save plan to file
        with open(output_path, "w") as f:
            json.dump({"plan": bug_specs, "sessions": []}, f, indent=2)
        print(f"\nPlan saved to: {output_path}")

        # Also print a sample prompt
        print("\n" + "=" * 60)
        print("SAMPLE BABY DEVIN PROMPT (Bug 1)")
        print("=" * 60)
        if bug_specs:
            print(generate_baby_devin_prompt(bug_specs[0]))
        else:
            print("(no bugs planned — nothing to show)")

        return 0

    # Spawn Baby Devins
    api_key = args.__dict__.get("api_key") or DEVIN_API_KEY
    if not api_key:
        logger.error(
            "DEVIN_API_KEY is required to spawn sessions. "
            "Use --dry-run to plan without spawning."
        )
        return 1

    sessions = spawn_baby_devins(
        bug_specs,
        api_key,
        org_id=DEVIN_ORG_ID,
        playbook_id=ADVERSARIAL_PLAYBOOK_ID,
        max_concurrent=args.max_concurrent,
    )

    # Save results
    result = {
        "plan": bug_specs,
        "sessions": sessions,
        "target_repo": args.repo,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    # Print summary
    spawned = sum(1 for s in sessions if s["status"] == "spawned")
    failed = sum(1 for s in sessions if s["status"] == "failed_to_spawn")

    print("\n" + "=" * 60)
    print("ADVERSARIAL GENERATOR RESULTS")
    print("=" * 60)
    print(f"Bugs planned:    {len(bug_specs)}")
    print(f"Sessions spawned: {spawned}")
    print(f"Failed to spawn: {failed}")
    print(f"\nResults saved to: {output_path}")

    if sessions:
        print("\nSessions:")
        for s in sessions:
            status_icon = "✓" if s["status"] == "spawned" else "✗"
            print(
                f"  {status_icon} {s['bug_id']} ({s['category']}): {s.get('session_url', 'N/A')}"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
