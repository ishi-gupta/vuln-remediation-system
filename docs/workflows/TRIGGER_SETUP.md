# Trigger Vulnerability Scan Workflow

Drop this workflow file into any repository you want scanned automatically
by the [vuln-remediation-system](https://github.com/ishi-gupta/vuln-remediation-system).

## Setup

1. Copy `trigger-vuln-scan.yml` to `.github/workflows/` in the target repo
2. Ensure the target repo has a `GH_PAT` secret with `repo` scope that can
   trigger workflows in `ishi-gupta/vuln-remediation-system`

## How It Works

On every push or PR, this workflow sends a `repository_dispatch` event to
`vuln-remediation-system` with the target repo name in the payload. The
scanner then checks out, scans, and (on non-PR events) files GitHub Issues
for any findings.

## Example Workflow File

```yaml
# .github/workflows/trigger-vuln-scan.yml
name: Trigger Vulnerability Scan

on:
  push:
    branches: [main, master]
  pull_request:

permissions:
  contents: read

jobs:
  trigger-scan:
    name: Trigger Vulnerability Scan
    runs-on: ubuntu-latest
    steps:
      - name: Dispatch scan request
        uses: peter-evans/repository-dispatch@v3
        with:
          token: ${{ secrets.GH_PAT }}
          repository: ishi-gupta/vuln-remediation-system
          event-type: trigger-vuln-scan
          client-payload: >-
            {
              "target_repo": "${{ github.repository }}",
              "trigger_ref": "${{ github.ref }}",
              "trigger_sha": "${{ github.sha }}",
              "trigger_event": "${{ github.event_name }}"
            }
```
