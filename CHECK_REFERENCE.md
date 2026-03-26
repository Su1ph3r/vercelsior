# Check Reference

Complete reference of all security checks performed by vercelsior.

## Identity & Access Management

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| iam-001 | Token Without Expiration | FAIL | HIGH | 8.0 | Long-lived tokens without expiry are a persistent credential that can be exploited indefinitely if compromised. |
| iam-002 | Expired Token Not Revoked | FAIL | MEDIUM | 5.0 | Expired tokens indicate poor credential hygiene. |
| iam-003 | Leaked Token Detected | FAIL | CRITICAL | 10.0 | A confirmed credential leak with verified exposure URL. |
| iam-004 | Stale Token | WARN | MEDIUM | 5.0 | Token has not been used in over 90 days. |
| iam-005 | Token With Full Access Scope | WARN | HIGH | 8.0 | Token has no scope restrictions (full access). |
| iam-010 | SSO/SAML Not Configured | FAIL | HIGH | 7.0 | Team does not have SAML/SSO configured. |
| iam-011 | SSO Not Enforced | WARN | MEDIUM | 6.0 | SSO configured but members can bypass it. |
| iam-012 | Email Domain Auto-Join Enabled | WARN | MEDIUM | 6.0 | Anyone with a matching email domain can join the team. |
| iam-013 | Active Invite Code | WARN | MEDIUM | 5.0 | Team has an active invite code that could be shared. |
| iam-014 | Sensitive Env Var Policy Not Enforced | FAIL | HIGH | 7.0 | Team does not enforce a sensitive environment variable policy. |
| iam-015 | IP Addresses Visible in Observability | WARN | LOW | 3.0 | IP addresses are not hidden in observability data. |
| iam-016 | IP Addresses Visible in Log Drains | WARN | LOW | 3.0 | IP addresses are not hidden in log drain output. |
| iam-017 | Excessive Team Owners | WARN | MEDIUM | 5.0 | Team has more than 3 owners. |
| iam-018 | Single Team Owner | WARN | LOW | 2.0 | Team has only one owner, creating a single point of failure. |
| iam-020 | Large Access Group With Broad Project Access | WARN | MEDIUM | 5.0 | Access group has >50 members with access to >10 projects. |
| iam-025 | MFA Not Enforced | WARN | HIGH | 8.0 | Team does not enforce multi-factor authentication. |
| iam-026 | Protected Git Scopes Not Configured | WARN | MEDIUM | 6.0 | Team does not have protected git scopes configured. |
| iam-027 | Access Group With Very Broad Project Access | WARN | HIGH | 8.0 | Access group has access to more than 20 projects. |
| iam-028 | Potential Ghost Account | WARN | MEDIUM | 5.0 | Team member joined >180 days ago with no detected activity. |
| bill-001 | No Spend Management Configured | WARN | MEDIUM | 5.0 | No budget alerts configured to detect abuse or runaway costs. |

## Firewall & WAF

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| fw-001 | Firewall Not Configured | FAIL | HIGH | 8.0 | No WAF means all traffic is uninspected. |
| fw-002 | Firewall Disabled | FAIL | HIGH | 8.0 | WAF exists but is turned off. |
| fw-003 | OWASP Core Rule Set Not Configured | FAIL | HIGH | 7.0 | No OWASP CRS configuration present. |
| fw-003-{cat} | OWASP {Category} Rules Disabled | FAIL | HIGH | 7.0 | Specific OWASP category disabled (sqli, xss, rce, lfi, rfi, gen, ma, sf, sd, php, java). |
| fw-004 | No Managed Rules Configured | FAIL | HIGH | 7.0 | No managed WAF rules configured. |
| fw-004-{key} | Managed Rule: {Name} Disabled | WARN | varies | varies | Specific managed rule set disabled (owasp, bot_protection, ai_bots, vercel_ruleset). |
| fw-005 | No Custom WAF Rules | WARN | LOW | 3.0 | No custom WAF rules for rate limiting or geo-blocking. |
| fw-006 | Overly Broad IP Allow Rule | FAIL | CRITICAL | 9.0 | IP allow rule for 0.0.0.0/0 permits all traffic. |
| fw-007 | Bot Identification Disabled | WARN | MEDIUM | 4.0 | Bot identification not enabled. |
| fw-008 | Firewall Bypass Rules Active | WARN | HIGH | 7.0 | Active bypass rules create holes in WAF coverage. |
| fw-009 | No Rate Limiting Rules | WARN | MEDIUM | 5.0 | No rate limiting rules configured in the WAF. |

## Secrets & Environment Variables

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| sec-001 | Sensitive Env Var Stored as Plain Text | FAIL | CRITICAL | 9.5 | Production secrets stored in plain text. |
| sec-002 | Sensitive Env Var Exposed to Non-Production | WARN | HIGH | 7.0 | Sensitive credentials available in preview/development. |
| sec-003 | Plain Text Environment Variable | WARN | LOW | 2.0 | Non-sensitive variable stored as plain text. |
| sec-004 | System Env Vars Auto-Exposed | WARN | MEDIUM | 4.0 | System environment variables automatically exposed to build. |
| sec-010 | Shared Env Var Linked to Many Projects | WARN | MEDIUM | 5.0 | Shared variable linked to more than 10 projects. |
| sec-011 | Shared Sensitive Env Var in Plain Text | FAIL | CRITICAL | 9.5 | Shared sensitive credentials stored in plain text. |
| sec-020 | Sensitive Env Var Shared Across All Environments | WARN | HIGH | 7.0 | Same secret value used in production, preview, and development. |
| sec-021 | Sensitive Env Var Without Branch Filtering | WARN | MEDIUM | 6.0 | Sensitive variable available on all preview branches. |
| sec-022 | Excessive Environment Variables | WARN | LOW | 3.0 | Project has more than 50 environment variables. |
| sec-023 | High-Entropy Plain Text Value | WARN | MEDIUM | 5.0 | Plain text variable with high entropy suggesting undeclared secret. |

## Deployment Protection

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| dep-001 | Git Fork Protection Disabled | FAIL | HIGH | 8.0 | Fork PRs can execute build-time code with access to secrets. |
| dep-002 | Source Code Publicly Visible | WARN | MEDIUM | 5.0 | Public source code exposes application logic. |
| dep-003 | Sourcemaps Not Protected | WARN | MEDIUM | 5.0 | Unprotected sourcemaps reveal original source code. |
| dep-004 | No Deployment Access Protection | WARN | MEDIUM | 6.0 | No password or SSO protection on deployments. |
| dep-005 | Deployment Protection Bypass Active | WARN | HIGH | 7.0 | Protection bypass rules allow unauthenticated access. |
| dep-006 | Overly Broad Trusted IP Range | FAIL | CRITICAL | 9.0 | Trusted IP range of 0.0.0.0/0 allows all traffic. |
| dep-007 | No Deployment Expiration Policy | WARN | LOW | 3.0 | Old deployments remain accessible indefinitely. |
| dep-008 | Outdated Node.js Version | FAIL | HIGH | 7.0 | End-of-life Node.js version with no security patches. |
| dep-009 | OIDC Token Config | PASS | INFO | 0.0 | OIDC token configuration present. |
| dep-010 | Skew Protection Not Configured | WARN | LOW | 2.0 | No skew protection for consistent deployment serving. |
| dep-011 | Wildcard CORS Allowlist | WARN | MEDIUM | 6.0 | Wildcard CORS allows any origin to make cross-origin requests. |
| dep-020 | Public Deployments Detected | WARN | MEDIUM | 4.0 | Recent deployments with public visibility. |
| dep-030 | Serverless Function Region Not Restricted | WARN | LOW | 4.0 | No region restriction on serverless functions. |
| dep-031 | Functions Running Maximum Duration | WARN | MEDIUM | 5.0 | Serverless functions allowed to run for extended periods. |
| dep-032 | Directory Listing Enabled | FAIL | MEDIUM | 6.0 | Directory listing exposes file structure. |
| dep-033 | Skew Protection Window Excessively Large | WARN | LOW | 3.0 | Skew protection window exceeds 7 days. |
| dep-034 | No OIDC Federation Configured | WARN | MEDIUM | 5.0 | No OIDC token federation for serverless functions. |

## Domains & Certificates

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| dom-001 | Unverified Domain | FAIL | HIGH | 7.0 | Domain not verified, could be claimed by others. |
| dom-002 | Domain Expired | FAIL | CRITICAL | 10.0 | Expired domain can be re-registered by attackers. |
| dom-003 | Domain Expiring Soon | WARN | HIGH | 7.0 | Domain expires within 30 days. |
| dom-004 | Domain Expiring Within 90 Days | WARN | MEDIUM | 4.0 | Domain expires within 90 days. |
| dom-005 | Domain Auto-Renew Disabled | WARN | MEDIUM | 5.0 | Auto-renewal not enabled. |
| dom-006 | Domain Misconfigured | FAIL | HIGH | 6.0 | DNS misconfiguration detected by Vercel. |
| dom-010 | Project Has No Custom Domain | WARN | LOW | 1.0 | Only accessible via .vercel.app subdomain. |
| dom-011 | Non-Permanent Domain Redirect | WARN | LOW | 1.0 | Using non-permanent redirect status code. |
| dom-020 | Wildcard DNS Record | WARN | MEDIUM | 6.0 | Wildcard DNS record creating dangling subdomain risk. |
| dom-021 | CNAME Record on Apex Domain | WARN | LOW | 2.0 | CNAME on apex can cause MX/TXT record conflicts. |
| dom-022 | DMARC Record Present | PASS | INFO | 0.0 | DMARC record configured. |
| dom-023 | No SPF Record | WARN | MEDIUM | 5.0 | Missing SPF record increases email spoofing risk. |
| dom-024 | No DMARC Record | WARN | MEDIUM | 5.0 | No DMARC record allows undetected email spoofing. |
| dom-030 | Domain Missing CAA Record | WARN | MEDIUM | 5.0 | No CAA record to restrict certificate issuance. |
| dom-031 | Domain Transfer Lock Not Enabled | WARN | MEDIUM | 6.0 | Domain can be transferred away without lock. |
| dom-032 | DNSSEC Not Enabled | WARN | MEDIUM | 4.0 | DNS responses can be spoofed without DNSSEC. |

## Logging & Monitoring

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| log-001 | No Log Drains Configured | FAIL | HIGH | 7.0 | No centralized logging configured. |
| log-002 | Log Drain Using HTTP | FAIL | HIGH | 8.0 | Logs sent over unencrypted HTTP. |
| log-003 | Log Drain Not Operational | FAIL | HIGH | 7.0 | Log drain has errored or disabled status. |
| log-010 | No Webhooks Configured | WARN | MEDIUM | 4.0 | No webhooks for security event notifications. |
| log-011 | Webhook Using HTTP | FAIL | HIGH | 8.0 | Webhook sends events over unencrypted HTTP. |
| log-012 | Missing Security Event Webhooks | WARN | MEDIUM | 4.0 | Security-relevant events not covered by webhooks. |
| log-022 | No Audit Event Monitoring | WARN | MEDIUM | 6.0 | No webhooks for audit-relevant events. |

## Integrations

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| int-001 | No Third-Party Integrations | PASS | INFO | 0.0 | No third-party integrations installed. |
| int-002 | Integration With Write Access | WARN | MEDIUM | 6.0 | Third-party integration has write access permissions. |
| int-003 | Integration With Deploy Access | WARN | MEDIUM | 6.0 | Integration has deployment access permissions. |
| int-004 | Stale Integration | WARN | LOW | 3.0 | Integration not updated in over 180 days. |
| int-005 | Deleted Integration Still Listed | WARN | LOW | 2.0 | Deleted integration still present in config. |
| int-006 | Integration Has Access to All Projects | WARN | MEDIUM | 5.0 | Integration scoped to all projects. |

## Infrastructure

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| infra-001 | Overly Broad Secure Compute CIDR | WARN | MEDIUM | 5.0 | Secure Compute network has a broad CIDR range. |
| infra-002 | VPC Peering Connections Present | WARN | MEDIUM | 5.0 | VPC peering creates network-level trust relationships. |
| infra-003 | Secure Compute Network Not Active | WARN | MEDIUM | 4.0 | Secure Compute network is not in active state. |
| infra-010 | Edge Config With Many Tokens | WARN | MEDIUM | 4.0 | Edge Config has more than 10 access tokens. |
| infra-011 | Large Edge Config | WARN | LOW | 2.0 | Edge Config has more than 1000 items. |
| infra-020 | Remote Caching Enabled | WARN | LOW | 2.0 | Cached build artifacts may contain sensitive data. |
| infra-030 | Alias With Protection Bypass | WARN | HIGH | 7.0 | Alias has protection bypass rules. |
| infra-040 | No Static IP for Egress | WARN | LOW | 4.0 | Project connects to backends with no static IP configured. |
| infra-041 | Edge Config May Contain Secrets | WARN | HIGH | 7.0 | Edge Config name suggests sensitive content. |

## Preview & Build Security

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| prev-001 | Preview Deployments Publicly Accessible | FAIL | HIGH | 8.0 | No SSO or password protection on preview deployments. |
| prev-002 | Automation Bypass Secret Configured | WARN | HIGH | 7.0 | VERCEL_AUTOMATION_BYPASS_SECRET can circumvent protection. |
| prev-003 | Build Command Allows Arbitrary Execution | WARN | HIGH | 8.0 | Build commands contain potentially dangerous patterns. |
| prev-004 | Root Directory Points Outside Repository | FAIL | CRITICAL | 9.0 | Path traversal in root directory. |
| prev-005 | No Ignored Build Step in Monorepo Project | WARN | LOW | 3.0 | Monorepo project without build filtering. |
| prev-006 | Deploy Hooks Present | WARN | MEDIUM | 6.0 | Unauthenticated endpoints that trigger deployments. |

## Framework Security

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| njs-001 | NEXT_PUBLIC_ Env Var With Sensitive Name | FAIL | CRITICAL | 10.0 | Sensitive values exposed in client-side JavaScript bundles. |
| njs-002 | Outdated Next.js Version With Known CVEs | FAIL | CRITICAL | 9.0 | Next.js version with known critical CVEs (CVE-2025-29927, etc.). |
| njs-003 | Framework Not Set | WARN | MEDIUM | 4.0 | No framework configured, missing platform protections. |

## Subdomain Takeover

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| sto-001 | Dangling CNAME to Vercel | FAIL | CRITICAL | 9.0 | DNS CNAME pointing to Vercel without a matching project domain. |
| sto-002 | Orphaned Alias | WARN | HIGH | 7.0 | Alias not linked to any active project domain. |

## Git & Source Control

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| git-001 | Git Repository Connected to Personal Account | WARN | MEDIUM | 5.0 | Repository linked to personal account lacking org security controls. |
| git-002 | Protected Git Scopes Not Enforced | WARN | MEDIUM | 6.0 | Team does not restrict which git organizations can connect. |
| git-003 | Auto-Deploy Enabled on All Branches | WARN | MEDIUM | 5.0 | All branches trigger deployments with no filtering. |

## Feature Flags

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| flag-001 | Feature Flag With Security-Sensitive Name | WARN | MEDIUM | 6.0 | Flag name matches sensitive patterns (admin, bypass, debug, etc.). |
| flag-002 | Feature Flag Overrides in Production | WARN | HIGH | 7.0 | Active overrides or rules affecting production. |

## Certificates & TLS

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| tls-001 | Certificate Expired / Expiring Soon | FAIL | CRITICAL-MEDIUM | 6.0-9.0 | TLS certificate expired or expiring within 30 days. |
| tls-002 | No mTLS for Backend Connections | WARN | LOW | 4.0 | No mutual TLS for projects connecting to backend services. |
| tls-003 | Certificate Using Weak Key Algorithm | FAIL | HIGH | 7.0 | Certificate uses RSA-1024, SHA1, MD5, or key <2048 bits. |

## Routes & Redirects

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| route-001 | Open Redirect in Bulk Redirects | FAIL | HIGH | 8.0 | Bulk redirect may enable open redirect attacks. |
| route-002 | Wildcard Route Proxying to External Origin | FAIL | HIGH | 7.0 | Wildcard route proxies traffic to external destination. |
| route-003 | Rewrite Proxying to External Origin | WARN | MEDIUM | 6.0 | Route rewrites to external origin. |

## Security Headers

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| hdr-001 | Missing Content-Security-Policy | FAIL | HIGH | 7.0 | No CSP header (requires --live flag). |
| hdr-002 | Missing Strict-Transport-Security | FAIL | MEDIUM | 6.0 | No HSTS header (requires --live flag). |
| hdr-003 | Missing X-Frame-Options | WARN | MEDIUM | 6.0 | No clickjacking protection (requires --live flag). |
| hdr-004 | Missing X-Content-Type-Options | WARN | MEDIUM | 4.0 | No MIME-sniffing protection (requires --live flag). |
| hdr-005 | Missing Referrer-Policy | WARN | LOW | 3.0 | No Referrer-Policy header (requires --live flag). |
| hdr-006 | Missing Permissions-Policy | WARN | LOW | 3.0 | No Permissions-Policy header (requires --live flag). |

## Rolling Releases

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| roll-001 | Rolling Release Without Approval Gate | WARN | MEDIUM | 6.0 | Rolling releases enabled with no approval gate. |
| roll-002 | Rolling Release Active With No Monitoring | WARN | MEDIUM | 5.0 | Rolling releases enabled without monitoring. |

## Sandboxes

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| sand-001 | Sandbox With Open Network Policy | WARN | MEDIUM | 6.0 | Sandbox allows unrestricted egress traffic. |
| sand-002 | Long-Running Sandbox | WARN | LOW | 4.0 | Sandbox older than 7 days. |

## Deployment Verification

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| chk-001 | No Deployment Checks Configured | WARN | MEDIUM | 5.0 | No deployment checks to verify builds before going live. |
| chk-002 | Deployment Checks Always Passing | WARN | LOW | 4.0 | Checks that never fail may be rubber-stamp checks. |
| chk-003 | Deployment Check Rerequested After Failure | WARN | MEDIUM | 6.0 | Check rerequested and subsequently passed, potential bypass. |

## Storage & Data

| Check ID | Title | Status | Severity | Risk Score | Description |
|----------|-------|--------|----------|------------|-------------|
| stor-001 | Vercel Storage Without IP Restrictions | WARN | MEDIUM | 5.0 | Vercel managed storage has no trusted IPs or Secure Compute. |
| stor-002 | Storage Credentials in Preview Environment | WARN | HIGH | 7.0 | Production storage credentials accessible in preview deployments. |
| cron-001 | Cron Job Endpoint Not Protected | WARN | MEDIUM | 5.0 | Cron-related env vars present but no CRON_SECRET configured. |
