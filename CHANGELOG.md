# Changelog

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
