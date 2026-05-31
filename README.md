# Vercelsior

**Open-source security scanner and configuration auditor for Vercel.**

[![CI](https://github.com/Su1ph3r/vercelsior/actions/workflows/ci.yml/badge.svg)](https://github.com/Su1ph3r/vercelsior/actions/workflows/ci.yml)
[![Release](https://github.com/Su1ph3r/vercelsior/actions/workflows/release.yml/badge.svg)](https://github.com/Su1ph3r/vercelsior/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/Su1ph3r/vercelsior)](https://goreportcard.com/report/github.com/Su1ph3r/vercelsior)

Vercelsior is to Vercel what [Prowler](https://github.com/prowler-cloud/prowler) is to AWS and [ScoutSuite](https://github.com/nccgroup/ScoutSuite) is to multi-cloud. It audits your Vercel account, team, and project configurations for security misconfigurations, compliance gaps, and attack surface exposure.

Single binary. Zero dependencies. Linux, macOS, Windows.

*If you're here after the [April 2026 Vercel security incident](https://vercel.com/kb/bulletin/vercel-april-2026-security-incident), see [`CHECK_REFERENCE.md`](./CHECK_REFERENCE.md) for the applicable checks.*

---

## Modes

Vercelsior tests Vercel security from three angles, each its own subcommand:

| Command | Input | Perspective | Status |
|---------|-------|-------------|--------|
| `vercelsior scan` | API token | **CSPM** — audit account/team/project config from the inside | ✅ Available |
| `vercelsior probe <url>` | a URL | **DAST** — black-box test a deployed site (CVE-2025-29927 middleware bypass, source maps, header hygiene) from the outside, no token | ✅ Available |
| `vercelsior project [path]` | local repo | **IaC/SAST** — scan `vercel.json`, `next.config.*`, `package.json`, `.env*` pre-deploy, no token | ✅ Available |

Running `vercelsior` with no subcommand (or with a leading flag, e.g. `vercelsior --token ...`) is an alias for `vercelsior scan`, so existing usage and CI pipelines are unaffected. Together the three modes test Vercel security from the **inside** (token), the **repo** (pre-deploy), and the **outside** (deployed URL) — the only tool that does all three.

### Project mode (local IaC/SAST)

Scan a project repository before deploy — no token, runs in CI on every PR:

```sh
vercelsior project ./my-app
vercelsior project . -f sarif -o ./results   # GitHub code scanning on PRs
```

Checks: **Next.js CVE** matrix against the `next` version in `package.json` (incl. CVE-2025-29927), **committed/client-exposed secrets** in `.env*` (hardcoded values, `NEXT_PUBLIC_`/`VITE_`/etc. leakage, `.gitignore` coverage), risky **`next.config.*`** flags (`productionBrowserSourceMaps`, `ignoreBuildErrors`, `ignoreDuringBuilds`, `poweredByHeader`), and **`vercel.json`** issues (external redirects/rewrites, missing security headers).

### Probe mode (black-box DAST)

Test a deployed URL from the outside — no token, the attacker's perspective:

```sh
vercelsior probe https://my-app.vercel.app
vercelsior probe my-app.vercel.app/dashboard -f sarif -o ./results
```

Checks: **CVE-2025-29927** Next.js middleware auth bypass (sends the `x-middleware-subrequest` header and only reports a finding when a blocked baseline flips to a 2xx — no false claims), exposed JavaScript **source maps** (`/_next/static/**/*.js.map`), **security headers** (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), and **technology disclosure** (`X-Powered-By`). All egress runs through the same SSRF-guarded, redirect-pinned client as `--live`, with same-host enforcement on discovered URLs.

> Only probe targets you are authorized to test.

---

## What It Finds

**160+ checks across the three modes** — 140+ account/team checks in `scan` (20 categories, below), plus the `probe` (DAST) and `project` (IaC/SAST) checks listed in [their sections above](#modes) and detailed in [`CHECK_REFERENCE.md`](./CHECK_REFERENCE.md).

The `scan` mode (CSPM) covers:

- Leaked API tokens, tokens without expiration, overprivileged scopes
- Disabled WAF/firewall, missing OWASP rules, no rate limiting
- `NEXT_PUBLIC_` environment variables leaking secrets into client-side JavaScript
- Sensitive credentials stored as plain text or exposed to preview environments
- Next.js deployments running versions with known CVEs (CVE-2025-29927, CVE-2025-55182, CVE-2025-49826, CVE-2025-59471, CVE-2025-59472)
- SSRF detection in rewrite/redirect destinations pointing to internal IPs or cloud metadata
- Client-exposed secrets via framework prefixes (VITE_, GATSBY_, REACT_APP_, NUXT_PUBLIC_)
- WAF rules in detect-only mode providing no active protection
- Dangling A records pointing to Vercel IPs enabling subdomain takeover
- Webhook endpoints missing signing secrets
- Subdomain takeover risks from dangling CNAMEs and orphaned aliases
- Missing deployment protection, unprotected preview URLs, disabled fork protection
- No log drains, no webhooks, no security event monitoring
- Missing security headers (CSP, HSTS, X-Frame-Options) via live HTTP probing
- Unprotected sourcemaps exposing original source code
- Missing SPF, DMARC, CAA, and DNSSEC records
- Weak TLS certificates, missing mTLS for backend connections
- Open redirects, wildcard routes proxying to external origins
- Vercel storage (KV, Postgres, Blob) credentials in preview environments
- Unprotected cron job endpoints missing CRON_SECRET validation

Every finding includes:
- **Risk score** (1-10) with written rationale explaining the score
- **Proof of concept evidence** showing the actual API request and response that proves the misconfiguration
- **Verification command** (curl/CLI) to independently confirm the finding
- **Remediation commands** and documentation links

---

## Install

### Go Install

```sh
go install github.com/Su1ph3r/vercelsior/cmd/vercelsior@latest
```

### Binary Download

Pre-built binaries for Linux (amd64/arm64), macOS (amd64/arm64), and Windows (amd64) are available on the [Releases](https://github.com/Su1ph3r/vercelsior/releases) page.

### Homebrew (macOS / Linux)

```sh
brew install Su1ph3r/tap/vercelsior
```

### Scoop (Windows)

```powershell
scoop bucket add su1ph3r https://github.com/Su1ph3r/scoop-bucket
scoop install vercelsior
```

### Docker

```sh
docker run --rm -e VERCEL_TOKEN ghcr.io/su1ph3r/vercelsior --min-severity HIGH
```

### Build From Source

```sh
git clone https://github.com/Su1ph3r/vercelsior.git
cd vercelsior
make build      # or: go build -o vercelsior ./cmd/vercelsior/
```

---

## Quick Start

```sh
# --- scan (account CSPM, needs a token) ---
export VERCEL_TOKEN="your-api-token"
vercelsior scan                          # run all checks (bare `vercelsior` also works)
vercelsior scan --team-slug my-team      # scope to a team
vercelsior scan --min-severity HIGH      # only critical + high findings
vercelsior scan --live                   # add live security-header probing
vercelsior scan -f html -o ./reports     # HTML report only
vercelsior scan --diff ./reports/prev.json   # compare with a previous scan

# --- probe (black-box DAST, no token) ---
vercelsior probe https://my-app.vercel.app

# --- project (local IaC/SAST, no token) ---
vercelsior project ./my-app
```

---

## Token Permissions

Create a token at **Vercel Dashboard > Settings > Tokens** with:
- **Read** access to all resources
- **Team** scope if scanning a team

Vercelsior never writes to or modifies your Vercel configuration. If the token lacks permissions for certain endpoints, those checks produce explicit permission-denied findings in the report and a summary of skipped endpoints is printed.

---

## Output Formats

### HTML Report

Interactive dark-themed report with:
- Posture score ring (0-100)
- Findings grouped by category, sorted by severity
- Collapsible findings with PoC evidence, verification commands, and remediation
- Filter by status (fail/warn/pass)

### JSON Report

Machine-readable output with full finding data including risk scores, PoC evidence (request + response), remediation commands, and resource details. Designed for CI/CD integration and SIEM ingestion.

### Markdown Report

Portable text report suitable for pull requests, wikis, and documentation.

### SARIF Report

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) output for **GitHub Code Scanning** and generic SAST tooling. Findings appear in your repository's **Security → Code scanning** tab, with per-finding `security-severity` scores (driven by Vercelsior's 1–10 risk score) and stable fingerprints so persisting findings aren't re-reported as new across scans.

```sh
vercelsior -f sarif -o ./results
```

### Scan Diff

Compare two scans to track remediation progress:

```sh
vercelsior --diff ./previous-scan.json
```

Outputs new findings, resolved findings, and posture score delta in both Markdown and JSON.

---

## CLI Reference

```
vercelsior <command> [options]
vercelsior [options]            # alias for 'scan' (legacy form)

Commands:
  scan       Audit a Vercel account/team via the API (CSPM)
  probe      Black-box test a deployed Vercel URL (no token)
  project    Scan a local Vercel project (no token, pre-deploy)
  version    Print the version
  help       Show help; 'help <command>' for command options
```

The options below apply to `scan` (and the legacy bare form).

| Flag | Description |
|------|-------------|
| `-t`, `--token` | Vercel API token (or `VERCEL_TOKEN` env var) |
| `--team-id` | Scope to a team by ID |
| `--team`, `--team-slug` | Scope to a team by slug |
| `-o`, `--output` | Output directory (default: current directory) |
| `-f`, `--format` | Comma-separated: `html`, `json`, `md`, `sarif` (default: `html,json,md`) |
| `--live` | Enable live HTTP header probing against production domains |
| `--min-severity` | Minimum severity to report: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `--checks` | Run only these check IDs (comma-separated) |
| `--skip-checks` | Skip these check IDs (comma-separated) |
| `--category` | Run only these categories (comma-separated) |
| `--no-color` | Disable colored terminal output |
| `-c`, `--config` | Config file path (default: `.vercelsior`) |
| `--diff` | Compare with a previous JSON report |
| `--record` | Record API responses to a directory (for offline testing) |
| `--replay` | Replay API responses from a directory (offline mode) |
| `-v`, `--version` | Show version |
| `-h`, `--help` | Show help |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed (or filtered below `--min-severity`) |
| `2` | One or more findings at or above the severity threshold |

---

## Configuration File

Vercelsior reads `.vercelsior` from the current directory (or the path given by `--config`).

```
# Suppress accepted risks
suppress: iam-015
suppress: dom-010

# Severity threshold
min_severity: HIGH

# Skip categories
skip_category: Infrastructure
skip_category: Sandboxes

# Run only specific checks
check: njs-001
check: sec-001
```

CLI flags override config file values.

---

## Check Categories

| Category | Checks | Description |
|----------|--------|-------------|
| Identity & Access Management | 13 | API tokens, SSO/SAML, team roles, access groups |
| Firewall & WAF | 11+ | OWASP CRS, managed rules, bot protection, rate limiting, IP rules, detect-only mode |
| Secrets & Environment Variables | 11 | Plain text detection, NEXT_PUBLIC_ leaks, client-exposure prefixes, entropy analysis, cross-env exposure |
| Deployment Protection | 12 | Fork protection, sourcemaps, deployment gates, Node.js version, CORS |
| Domains & Certificates | 12 | Verification, expiry, DNS hygiene, SPF/DMARC/CAA/DNSSEC, transfer lock |
| Logging & Monitoring | 9 | Log drains, webhooks, webhook signing, security event coverage, audit events |
| Integrations | 6 | Permission scope, staleness, project-level access |
| Infrastructure | 8 | Secure Compute, Edge Config, remote caching, static IPs |
| Preview & Build Security | 6 | Preview protection, build command injection, deploy hooks, bypass secrets |
| Framework Security | 3 | NEXT_PUBLIC_ secrets, Next.js CVE detection, framework identification |
| Subdomain Takeover | 3 | Dangling CNAME detection, dangling A record detection, orphaned alias detection |
| Git & Source Control | 3 | Personal vs organization repos, protected scopes, branch filtering |
| Feature Flags | 2 | Security-sensitive flag names, production overrides |
| Certificates & TLS | 3 | Certificate expiry, weak key algorithms, mTLS |
| Routes & Redirects | 4 | Open redirects, external origin proxying, wildcard routes, SSRF detection |
| Security Headers | 6 | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Storage & Data | 3 | Vercel KV/Postgres/Blob access controls, cron job protection |
| Rolling Releases | 2 | Approval gates, monitoring verification |
| Sandboxes | 2 | Network policies, staleness |
| Deployment Verification | 3 | Check coverage, rubber-stamp detection, rerun abuse |

See [CHECK_REFERENCE.md](CHECK_REFERENCE.md) for the full list of checks with IDs, risk scores, and descriptions.

---

## Scoring

**Per-finding risk score (1-10):** Assigned based on exploitability, impact, and likelihood specific to the Vercel platform. Each score includes a written rationale.

**Posture score (0-100):** Calculated as weighted risk across all findings. FAIL findings contribute full risk score, WARN findings contribute half. A clean account scores 100.

```
posture = 100 - (sum_of_fail_scores + sum_of_warn_scores * 0.5) / (total_checks * 10) * 100
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Vercel Security Audit
on:
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Install
        run: go install github.com/Su1ph3r/vercelsior/cmd/vercelsior@latest

      - name: Scan
        env:
          VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
        run: vercelsior --team-slug my-team --min-severity HIGH -f json,html -o ./results

      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vercelsior-report
          path: ./results/
```

Set `--min-severity CRITICAL` to fail only on critical findings.

### GitHub Code Scanning (SARIF)

Surface findings directly in the repository's **Security** tab:

```yaml
name: Vercel Security Audit
on:
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch:

permissions:
  security-events: write   # required to upload SARIF

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Scan
        env:
          VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
        run: |
          docker run --rm -e VERCEL_TOKEN -v "$PWD/results:/results" \
            ghcr.io/su1ph3r/vercelsior --team-slug my-team -f sarif -o /results

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./results
```

---

## Testing

Vercelsior includes an API recording/replay system for offline testing:

```sh
# Record real API responses
vercelsior --token TOKEN --record test/fixtures/baseline

# Run offline against recorded responses
vercelsior --replay test/fixtures/baseline

# Run integration tests
go test ./test/integration/ -v
```

See [test/README.md](test/README.md) for the full test setup guide.

---

## Contributing

1. Fork the repo and create a branch
2. Run tests: `go test ./...`
3. Follow existing check module conventions in `internal/checks/`
4. Submit a pull request

Open an issue first for larger changes.

---

## License

[MIT](LICENSE)
