# Vercelsior — Remaining Deferred Checks

Only items blocked on API access constraints remain.

## Needs Marketplace API (Integration-Provider Only)

These endpoints are only accessible to integration providers, not standard API token holders.

- [ ] **mkt-001** (7.0) Marketplace Integration With Elevated Permissions
- [ ] **mkt-002** (6.0) Marketplace Integration Permission Upgrade Not Monitored
- [ ] **mkt-003** (5.0) Marketplace Integration Scope Change Unconfirmed

## Dropped

- ~~**infra-042** (3.0) Edge Cache Not Purged~~ — not reliably detectable via API

## Post-1.0 follow-ups

- **Homebrew / Scoop taps**: create `Su1ph3r/homebrew-tap` + `Su1ph3r/scoop-bucket` and add the `HOMEBREW_TAP_GITHUB_TOKEN` secret, then re-enable the `brews`/`scoops` publishers in `.goreleaser.yml` (currently `skip_upload: true`).
- **Project mode**: parse `middleware.ts` for auth-gating patterns vulnerable to CVE-2025-29927; add monorepo support (scan `apps/*` / workspace sub-projects, not just the repo root).
- **Next.js CVE precision**: tighten the CVE-2025-29927 predicate so patched 12.3.5+/13.5.9+ are not flagged (currently all 12.x/13.x match). Matrix lives in `internal/nextjs`.
