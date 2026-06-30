# Changelog

## Unreleased

### Changed: false-positive reduction

Tightened heuristic detections that fired on benign-but-matching input. Name
matching now uses word/segment boundaries instead of unanchored substrings
(shared helpers in `internal/checks/matching.go`):

- **sec-001** no longer flags public locators like `NEXTAUTH_URL` as plain-text
  secrets; value-shape and an allowlist distinguish locators from credentials.
- **sto-001/003** (takeover) match the real `vercel-dns.com` CNAME target and
  honor wildcard/apex domain coverage, so legitimately-served subdomains and
  unrelated hosts (e.g. `vercelstatus.com`) are no longer flagged.
- **infra-040/041**, **stor-002**, **flag-001** match whole name segments, so
  `monkey` / `oauth-routes` / `NEXT_PUBLIC_API_URL` no longer match.
- **prev-003** stops flagging bare shell metacharacters in build commands;
  it flags `eval` / `sh -c` and `curl | sh` instead.
- **route-004** is now scoped to cloud-metadata destinations (SSRF to IMDS,
  including AWS IMDSv6 `fd00:ec2::254`) on rewrites/proxies only; private and
  loopback destinations move to the new low-severity **route-007**.
- Severity recalibration: **iam-010** (SAML, an Enterprise feature) and
  **dom-001** (unverified domain) downgraded to Low; **flag-002** scoped to
  security-sensitive flags and downgraded to Medium; **fw-003** aggregates
  per-category findings and reports unconfirmed (absent) categories as
  low-severity **fw-003-unconfirmed**; **iam-014** and **dep-001** only fire on
  a confirmed state (explicit policy `off`; a project with a connected Git repo).

### Fixed

- **dom-024** now detects DMARC records published under the absolute name
  (`_dmarc.example.com`) or by `v=DMARC1` value, not only the relative `_dmarc`
  name, so a present DMARC record is no longer reported as missing.
- **stor-001/002** again detect the `POSTGRES_URL_NON_POOLING` storage binding
  (and now `POSTGRES_PRISMA_URL` / `KV_REST_API_READ_ONLY_TOKEN`).

## v1.0.0 — 2026-05-31

The trifecta release. Vercelsior becomes a three-mode Vercel security tool —
**`scan`** (account CSPM via the API), **`probe`** (black-box DAST against a
deployed URL), and **`project`** (local IaC/SAST, pre-deploy) — plus SARIF 2.1.0
output, a full release pipeline (goreleaser, multi-arch Docker, SBOMs), and
GitHub Code Scanning support. Fully backward compatible: the legacy
`vercelsior [flags]` invocation still runs `scan` unchanged.

### Added
- **Subcommand architecture.** The CLI now routes `scan`, `project`, `probe`,
  `version`, and `help` subcommands (zero new dependencies). `scan` is the
  existing account/team API audit (CSPM). **Fully backward compatible:**
  invoking `vercelsior` with no subcommand or a leading flag (e.g.
  `vercelsior --token ...`, `VERCEL_TOKEN=... vercelsior`) still runs `scan`
  exactly as before. `run`/`route` are unit-tested for the legacy and explicit
  forms.
- **Probe mode (`vercelsior probe <url>`) — black-box DAST.** Tests a deployed
  URL from the outside with no token. Checks: **CVE-2025-29927** Next.js
  middleware auth bypass (compares a blocked baseline against the
  `x-middleware-subrequest` bypass header and only reports when protection is
  observably skipped — scoped to Next.js targets to avoid false claims),
  exposed JavaScript **source maps**, **security headers** (CSP/HSTS/
  X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy),
  and **technology disclosure** (X-Powered-By). New `internal/prober` package
  (16 unit tests via an injectable `Fetcher`, no network in tests) emits the
  standard `models.ScanResult`, so all reporters (incl. SARIF) work unchanged.
  All egress reuses the SSRF-guarded, redirect-pinned probe client via a new
  `client.Probe` method, with same-host enforcement on discovered URLs.
- **Project mode (`vercelsior project [path]`) — local IaC/SAST.** Static
  analysis of a project repo with no token, for pre-deploy / shift-left CI.
  Checks: **Next.js CVE** matrix against the `next` version in package.json,
  **committed/client-exposed secrets** in `.env*` (hardcoded values,
  `NEXT_PUBLIC_`/`VITE_`/etc. leakage, `.gitignore` coverage), risky
  **next.config.*** flags (`productionBrowserSourceMaps`, `ignoreBuildErrors`,
  `ignoreDuringBuilds`, `poweredByHeader`), and **vercel.json** issues
  (external redirects/rewrites, missing security headers). New `internal/project`
  package reads through `io/fs` (tested with `fstest.MapFS`, no real FS) and a
  shared `internal/nextjs` package holds the version/CVE logic. Conservative
  secret detection (strong token shapes + sensitive-name-plus-real-value +
  entropy) to minimize false positives.
- **The trifecta is complete:** Vercelsior now tests Vercel security from the
  inside (`scan`), the repo (`project`), and the outside (`probe`).
- **SARIF 2.1.0 output (`-f sarif`).** New `internal/reporter/sarif.go` emits a
  GitHub Code Scanning-compatible SARIF log. Findings (FAIL/WARN/ERROR; PASS
  excluded) become results with severity→level mapping, per-finding
  `security-severity` derived from the 1–10 risk score, deterministic rule
  ordering, and stable `partialFingerprints` (SHA-256 of check + resource) so a
  persisting finding is tracked across scans rather than re-reported as new.
  Non-source cloud findings get a synthetic `vercel/<category>/<resource>`
  artifact URI plus a logical location naming the resource.
- **Release automation.** `.goreleaser.yml` + `.github/workflows/release.yml`
  produce cross-platform binaries (linux/darwin/windows × amd64/arm64),
  archives, `checksums.txt`, CycloneDX SBOMs, a multi-arch GHCR Docker image
  (`ghcr.io/su1ph3r/vercelsior`), and Homebrew/Scoop manifests on tagged
  releases.
- **Docker images.** `Dockerfile` (build-from-source) and `Dockerfile.goreleaser`
  (release image), Alpine-based with `ca-certificates`.
- **golangci-lint in CI.** New `lint` job + `.golangci.yml` (govet, staticcheck,
  errcheck, ineffassign, unused, gofmt, goimports, misspell, unconvert,
  bodyclose). Tests now run with `-race`.
- **Build-version stamping.** `main.version` is now injected via
  `-ldflags -X main.version=...`; `make build`, Docker, and goreleaser all stamp
  the version, and it is recorded in SARIF output.

### Changed
- **Single Next.js CVE source of truth.** The CVE matrix and version parser
  previously existed in two copies (the scan path and project mode). Both now
  consume `internal/nextjs` (`Match`/`ParseVersion`), so a CVE is added once.
  Behavior preserved; the matrix is covered by an integrity guard plus per-CVE
  matrix tests (95% statement coverage).

### Fixed
- **`takeover` false-positive CRITICALs.** A swallowed per-project
  `ListProjectDomains` error dropped that project's domains from the "claimed"
  set, turning its own CNAMEs/aliases into bogus dangling-takeover findings
  (`sto-001` CRITICAL / `sto-002` HIGH). `collectProjectDomains` now propagates
  the error; `Run` emits a distinct `sto-001-error` and skips the negative
  checks rather than asserting against an incomplete set.
- **Case-insensitive `--checks`/`--skip-checks`.** CheckID filtering matched
  case-sensitively while IDs are emitted lowercase, so the documented uppercase
  form (`--skip-checks IAM-001`) silently no-opped (and an uppercase allowlist
  dropped every finding). `canonicalCheckID` now folds case before the alias
  lookup.
- **Probe checks no longer assert safety when they cannot run.** The
  CVE-2025-29927 and source-map probes returned PASS ("not exploitable" /
  "clean") when every probe/fetch errored (e.g. a WAF tarpitting the bypass
  header); they now return ERROR when nothing could be evaluated.
- **Project mode distinguishes unreadable from absent files.** A permission/IO
  error on `package.json`/`.env*`/`next.config.*`/`vercel.json` is now an ERROR
  finding instead of being treated as "file absent" (silent skip).
- **`iam-005` no longer fails open** on an object-shaped `scopes` payload
  (extracted as the tested `isFullAccessScopes` helper).
- **SPF detection** (`dom-023`) no longer false-positives on a TXT value of
  exactly `v=spf1`.
- **`chk-002`** reports the number of deployments actually inspected, not the
  full recent-deployment count.
- **Terminal summary now prints the `Errors` count** when non-zero, so a
  coverage gap (checks that could not run) is visible rather than only inflating
  the posture score.
- **Probe PoC evidence truncation is UTF-8-safe** (`internal/prober`), matching
  the client's existing rune-boundary handling.
- **SSRF guard hardened** beyond the v0.1.4 work: blocks CGNAT `100.64.0.0/10`,
  `0.0.0.0/8`, protocol/benchmark ranges, and the IPv4 embedded in NAT64
  (`64:ff9b::/96`) / 6to4 (`2002::/16`) addresses, while still allowing
  public IPv4 wrapped in those transitions.
- **Packaging:** anchored the `.gitignore` binary patterns (`/vercelsior`) so
  they no longer match the `cmd/vercelsior/` source directory — without this a
  fresh clone / CI / release build would omit the package's source files.

### Removed
- Dead code: unused `evidence()` helper in `internal/checks/base.go` and unused
  `findFinding()` test helper.

## v0.1.4

Hardening release: 33 issues addressed across security, correctness, resource management, and reporting. No user-facing breaking changes — legacy CheckIDs still match via a compatibility alias map.

### Security
- **SSRF — DNS rebinding TOCTOU closed in `--live` header probe.** `ProbeHeaders` previously performed its allowlist check and the dial as two independent DNS lookups. A hostile authoritative DNS could return a public IP on the first resolution and `127.0.0.1` / `169.254.169.254` / an RFC 1918 address on the second, pointing the probe at internal endpoints. The dialer now resolves once via `net.DefaultResolver.LookupIPAddr`, validates every returned IP, and dials the pinned IP directly. `CheckRedirect` returns `http.ErrUseLastResponse` so 3xx responses cannot re-enter the resolver for a different host. TLS SNI and the `Host` header continue to use the URL's original hostname so certificate validation works normally. (CWE-918, CWE-367)
- **Recorder no longer writes secrets to disk.** `--record DIR` response bodies are walked and values whose keys match `value`, `decryptedValue`, `token`, `bearerToken`, `accessToken`, `refreshToken`, `secret`, `signingSecret`, `privateKey`, `password`, `leakedUrl`, or `inviteCode` are replaced with `[REDACTED]`. Response headers `Set-Cookie`, `X-Vercel-Id`, `X-Vercel-Trace`, and `X-Amz-Request-Id` are also scrubbed. Contributors who record fixtures against a live account no longer leak plain-text env var values, token metadata, or session cookies when committing the fixtures. Redaction is case-insensitive and preserves JSON `null` literals. (CWE-200)
- **Replay path-traversal defense-in-depth.** `safeRecordingPath` rejects keys containing `/`, `\`, or `..`, and confirms the resolved absolute path is inside the recording directory. (CWE-22)
- **Pooled probe client.** `ProbeHeaders` previously built a fresh `http.Transport` per call; N projects produced N independent connection pools and background goroutines held ~90s by keep-alive. A single client is now constructed lazily via `sync.Once` and reused across every probe.

### Correctness
- **`stor-001` false-negative fixed.** `hasTrustedIPs` previously defaulted to `true` for any non-nil `trustedIps` object, suppressing the finding when Vercel returned an empty object or an object without an `addresses` array. It now defaults to `false` and flips to `true` only when a non-empty `addresses` array is present.
- **Scanner suppression order.** Suppression is now applied **before** the min-severity filter, so a suppressed check below the threshold appears as `[SUPPRESSED] Pass` instead of being silently dropped.
- **Silent non-403 API errors eliminated.** Eight check modules previously only handled `IsPermissionDenied(err)` and swallowed every other error (5xx, rate-limit, DNS, timeout), producing silent audit gaps. A shared `apiErrorFinding` helper now emits an INFO-severity ERROR finding for each non-403 failure in `firewall.go`, `routes.go`, `preview.go`, `verification.go`, `iam.go`, `git.go`, `logging.go`, `rolling.go`, `sandbox.go`, `tls.go`, `storage.go`, and `headers.go`.
- **JSON list-response parsing.** Nine list endpoints (`ListLogDrains`, `ListEdgeConfigs`, `ListEdgeConfigTokens`, `ListSecureComputeNetworks`, `ListSharedEnvVars`, `ListCertificates`, `ListBulkRedirects`, `ListProjectRoutes`, `ListSandboxes`, plus `ListWebhooks`) now share `parseListResponse`, which surfaces real API errors instead of silently falling back when the expected shape is missing.
- **`getPaginatedMaps` reports malformed items.** Items that fail to unmarshal are counted and logged once per endpoint instead of vanishing silently.
- **Header-probe gaps are visible.** A new `hdr-000` (Info/Error) finding records every domain whose probe failed (SSRF guard, DNS, TLS, timeout). Previously the domain silently disappeared from the audit.
- **`pickProductionDomain` propagates API errors** so the caller distinguishes "project has no domains" from "domain listing failed" and emits the appropriate finding.
- **`iam-015` CheckID collision resolved.** The team-members permission finding previously reused `iam-015` (already claimed by "IP Addresses Visible in Observability"), which collided in the scanner's `CheckID|ResourceID` dedup. It now emits `iam-019`.
- **`dom-011` no longer flags `redirectStatusCode == 0`** (missing field) as a non-permanent redirect.
- **`takeover.go` non-permission error uses `sto-001-error`** to avoid colliding with the primary `sto-001` findings under the same `N/A` ResourceID.
- **`parseVersion` rejects malformed patches** (e.g. `15.2.x`, `1.2.3.4`) instead of returning `patch=0`, which could cause false-positive CVE matches.
- **`njs-002` emits an Error finding** when no deployment exposes a framework version, instead of silently implying the project is safe.
- **`GetPaginated` no longer mutates the caller's params map.** Pagination cursors (`limit`, `until`) are written to an internal copy.
- **UTF-8 safe truncation.** Three truncation sites (`reporter/markdown.go:97`, `client/client.go:124` error body, `client/client.go:502` evidence log) now preserve valid UTF-8 on rune boundaries; previously they could split a multi-byte character and emit replacement characters.
- **Scan IDs use nanosecond precision** (`UnixNano`) so two scans started in the same second don't overwrite each other's reports.
- **`os.MkdirAll` error is now fatal** instead of silently producing confusing secondary errors when the output directory is unwritable.
- **Diff report write errors reported.** `WriteDiffMarkdown` / `WriteDiffJSON` errors are now logged instead of discarded.
- **Canceled CheckID typos harmonized.** `inf-030` → `infra-040`, `rol-001` → `roll-001`, `sbx-001` → `sand-001`. User configs that reference the legacy forms continue to match via a compatibility alias map in `internal/config/config.go` — **no action required** for existing `.vercelsior` files.

### Resource Management
- **`saveResponse` closes the original body on read errors.** Previously a read failure in `io.ReadAll` dropped the `ResponseBody` reference without closing it, leaking the underlying TCP connection until keep-alive timeout.

### New Check
- **`hdr-000` — Header Probe Failed** (Info, Error). Surfaces audit gaps caused by probe failures during `--live` mode. Does not affect exit code.

### Test Suite
- 9 new test files across `internal/checks`, `internal/client`, `internal/config`, `internal/models`, `internal/reporter`, and `internal/scanner`, plus an extension to `internal/client/client_test.go`
- 367 test cases total, 0 failures
- Coverage: `models` 97.6%, `config` 94.4%, `client` 46.6%, `reporter` 37.4%, `scanner` 35.4%
- Every behavioral fix has a targeted regression test

### Developer-Facing
- `scanner.Run` filter logic extracted to `applyFilters` and `dedupeFindings` for testability (behavior unchanged)
- Shared helpers added: `utf8SafeTruncate` (in `reporter`, `checks`, and `client`), `apiErrorFinding` (in `checks`), `parseListResponse` (in `client`), `safeRecordingPath` (in `client`), `isDisallowedProbeIP` (in `client`)

## v0.1.3

### Fixed
- Module path in `go.mod` and all import statements corrected from `github.com/su1ph/vercelsior` to `github.com/Su1ph3r/vercelsior`. Previous versions could not be installed via `go install` because the module path did not resolve to the real repository. `go install github.com/Su1ph3r/vercelsior/cmd/vercelsior@latest` now works correctly.

## v0.1.2

### New Checks
- **fw-010** — WAF Rules in Detect-Only Mode: flags OWASP or managed rules set to detect/monitor-only
- **log-024** — Webhook Missing Signing Secret: flags webhook endpoints without signing secrets
- **sec-026** — Client-Exposed Sensitive Environment Variable: detects secrets leaked via framework prefixes (VITE_, GATSBY_, REACT_APP_, NUXT_PUBLIC_)
- **route-004** — Rewrite Destination Points to Internal Target: SSRF detection for rewrites/redirects to internal IPs, localhost, or cloud metadata endpoints
- **sto-003** — Dangling A Record Pointing to Vercel: detects A records to Vercel IPs without a matching project domain

### Expanded CVE Coverage (njs-002)
- Added CVE-2025-55182 (React Server Components deserialization RCE, CVSS 10.0)
- Added CVE-2025-49826 (ISR cache poisoning, CVSS 7.5)
- Added CVE-2025-59471 (Image optimization memory exhaustion, CVSS 5.9)
- Added CVE-2025-59472 (PPR resume endpoint DoS, CVSS 5.9)
- Fixed CVE-2025-29927 false positives for pre-middleware Next.js versions (<12)

### Permission Denied Handling
- HTTP 403 responses now produce explicit per-check permission-denied findings instead of silently skipping checks
- Each check module reports which API endpoints require additional token scopes
- Deduplicated findings for per-project loops (one permission finding per API endpoint, not per project)
- Fixed firewall check false positive: 403 on GetFirewallConfig no longer reports "Firewall Not Configured"

### Bug Fixes
- Fixed SSRF detection bypass via URL userinfo (`@`) syntax in route-004
- Fixed mass false-positive Critical findings when ListProjects fails in subdomain takeover checks
- Fixed OIDC check (dep-009) inverted condition that flagged disabled OIDC as a pass
- Fixed silent failures in secrets, webhook, and deployment visibility checks when API calls error
- Fixed `parseVersion` ambiguity for version "0.x.x" (now uses explicit ok flag)
- Fixed remediation KB `{project_id}` placeholder substitution for env-var-scoped findings
- Added 429 rate-limit responses to evidence log
- Tightened recording file permissions from 0644/0755 to 0600/0700

### Security Hardening
- Added SSRF protection to `ProbeHeaders` via DNS resolution checks blocking private/reserved IPs
- Route SSRF detection uses `net/url.Parse` for correct RFC 3986 handling including IPv6

## v0.1.1

Initial release — Vercel security auditing tool with 130+ checks across 20 categories.
