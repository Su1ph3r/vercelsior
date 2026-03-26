# Vercelsior Test Setup

## Prerequisites
- Free Vercel account
- Vercel CLI (`npm i -g vercel`)
- A GitHub account (for git integration)

## Step 1: Create Test Project

1. Create a new GitHub repo with a basic Next.js app:
   ```bash
   npx create-next-app@latest vercelsior-test --ts --app --no-tailwind --no-eslint
   cd vercelsior-test
   git init && git add -A && git commit -m "init"
   ```

2. Push to GitHub and import into Vercel via dashboard

## Step 2: Deliberately Misconfigure (for testing)

### Environment Variables
- Add `NEXT_PUBLIC_SECRET_API_KEY` = `sk_test_abc123` (type: plain, targets: all environments)
  - Should trigger: njs-001, sec-001, sec-002, sec-020
- Add `DATABASE_URL` = `postgres://user:pass@host/db` (type: plain, targets: all environments)
  - Should trigger: sec-001, sec-002, sec-003, sec-020, stor-002
- Add `HARMLESS_VAR` = `hello` (type: plain, targets: production only)
  - Should trigger: sec-003

### Security Settings
- Leave firewall DISABLED
  - Should trigger: fw-001
- Leave fork protection OFF
  - Should trigger: dep-001
- Leave deployment protection OFF (no password, no SSO)
  - Should trigger: dep-004, prev-001
- Leave sourcemaps unprotected
  - Should trigger: dep-003

### Token
- Create API token with NO expiration and NO scope restrictions
  - Should trigger: iam-001, iam-005

### Domain/DNS
- Use only the default .vercel.app domain (no custom domain)
  - Should trigger: dom-010

### Logging
- Do NOT configure log drains
  - Should trigger: log-001
- Do NOT configure webhooks
  - Should trigger: log-010

## Step 3: Record API Responses

```bash
# Generate a token at https://vercel.com/account/tokens
export VERCEL_TOKEN=your_token_here

# Record all API responses for offline testing
vercelsior --token $VERCEL_TOKEN --record test/fixtures/baseline
```

## Step 4: Run Tests

```bash
# Run against recorded responses
vercelsior --replay test/fixtures/baseline -o test/output

# Or run the Go test suite
go test ./test/... -v
```

## Step 5: Verify Expected Findings

After recording, run the verification:
```bash
go test ./test/integration/ -v -run TestExpectedFindings
```

## Expected Minimum Findings

With the above setup, vercelsior should produce AT LEAST these findings:

| Check ID | Title | Status |
|----------|-------|--------|
| iam-001 | Token Without Expiration | FAIL |
| iam-005 | Token With Full Access Scope | WARN |
| iam-010 | SSO/SAML Not Configured | FAIL |
| fw-001 | Firewall Not Configured | FAIL |
| sec-001 | Sensitive Env Var Stored as Plain Text | FAIL |
| sec-002 | Sensitive Env Var Exposed to Non-Production | WARN |
| sec-003 | Plain Text Environment Variable | WARN |
| sec-020 | Sensitive Env Var Shared Across All Environments | WARN |
| njs-001 | NEXT_PUBLIC_ Env Var With Sensitive Name | FAIL |
| dep-001 | Git Fork Protection Disabled | FAIL |
| dep-003 | Sourcemaps Not Protected | WARN |
| dep-004 | No Deployment Access Protection | WARN |
| prev-001 | Preview Deployments Publicly Accessible | FAIL |
| dom-010 | Project Has No Custom Domain | WARN |
| log-001 | No Log Drains Configured | FAIL |
| log-010 | No Webhooks Configured | WARN |
| stor-002 | Storage Credentials in Preview Environment | WARN |
