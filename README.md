# Vercelsior

**Open-source security scanner and configuration auditor for Vercel.**

Vercelsior is to Vercel what [Prowler](https://github.com/prowler-cloud/prowler) is to AWS and [ScoutSuite](https://github.com/nccgroup/ScoutSuite) is to multi-cloud. It audits your Vercel account, team, and project configurations for security misconfigurations, compliance gaps, and attack surface exposure.

Single binary. Zero dependencies. Linux, macOS, Windows.

---

## What It Finds

**130+ security checks** across **20 categories**:

- Leaked API tokens, tokens without expiration, overprivileged scopes
- Disabled WAF/firewall, missing OWASP rules, no rate limiting
- `NEXT_PUBLIC_` environment variables leaking secrets into client-side JavaScript
- Sensitive credentials stored as plain text or exposed to preview environments
- Next.js deployments running versions with known CVEs (CVE-2025-29927, CVE-2025-55182)
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
go install github.com/su1ph/vercelsior/cmd/vercelsior@latest
```

### Binary Download

Pre-built binaries for Linux (amd64/arm64), macOS (amd64/arm64), and Windows (amd64) are available on the [Releases](https://github.com/su1ph/vercelsior/releases) page.

### Build From Source

```sh
git clone https://github.com/su1ph/vercelsior.git
cd vercelsior
go build -o vercelsior ./cmd/vercelsior/
```

---

## Quick Start

```sh
# Set your Vercel API token
export VERCEL_TOKEN="your-api-token"

# Run all checks
vercelsior

# Scope to a team
vercelsior --team-slug my-team

# Only critical and high findings
vercelsior --min-severity HIGH

# Include live security header probing
vercelsior --live

# Output HTML report only
vercelsior -f html -o ./reports

# Compare with a previous scan
vercelsior --diff ./reports/previous-scan.json
```

---

## Token Permissions

Create a token at **Vercel Dashboard > Settings > Tokens** with:
- **Read** access to all resources
- **Team** scope if scanning a team

Vercelsior never writes to or modifies your Vercel configuration. If the token lacks permissions for certain endpoints, those checks are skipped gracefully and a summary of skipped endpoints is printed.

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

### Scan Diff

Compare two scans to track remediation progress:

```sh
vercelsior --diff ./previous-scan.json
```

Outputs new findings, resolved findings, and posture score delta in both Markdown and JSON.

---

## CLI Reference

```
vercelsior [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-t`, `--token` | Vercel API token (or `VERCEL_TOKEN` env var) |
| `--team-id` | Scope to a team by ID |
| `--team`, `--team-slug` | Scope to a team by slug |
| `-o`, `--output` | Output directory (default: current directory) |
| `-f`, `--format` | Comma-separated: `html`, `json`, `md` (default: all) |
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
| Firewall & WAF | 10+ | OWASP CRS, managed rules, bot protection, rate limiting, IP rules |
| Secrets & Environment Variables | 10 | Plain text detection, NEXT_PUBLIC_ leaks, entropy analysis, cross-env exposure |
| Deployment Protection | 12 | Fork protection, sourcemaps, deployment gates, Node.js version, CORS |
| Domains & Certificates | 12 | Verification, expiry, DNS hygiene, SPF/DMARC/CAA/DNSSEC, transfer lock |
| Logging & Monitoring | 8 | Log drains, webhooks, security event coverage, audit events |
| Integrations | 6 | Permission scope, staleness, project-level access |
| Infrastructure | 8 | Secure Compute, Edge Config, remote caching, static IPs |
| Preview & Build Security | 6 | Preview protection, build command injection, deploy hooks, bypass secrets |
| Framework Security | 3 | NEXT_PUBLIC_ secrets, Next.js CVE detection, framework identification |
| Subdomain Takeover | 2 | Dangling CNAME detection, orphaned alias detection |
| Git & Source Control | 3 | Personal vs organization repos, protected scopes, branch filtering |
| Feature Flags | 2 | Security-sensitive flag names, production overrides |
| Certificates & TLS | 3 | Certificate expiry, weak key algorithms, mTLS |
| Routes & Redirects | 3 | Open redirects, external origin proxying, wildcard routes |
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
        run: go install github.com/su1ph/vercelsior/cmd/vercelsior@latest

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
