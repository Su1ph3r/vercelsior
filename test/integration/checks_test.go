package integration

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/config"
	"github.com/Su1ph3r/vercelsior/internal/models"
	"github.com/Su1ph3r/vercelsior/internal/scanner"
)

// writeFixture writes a synthetic API response fixture using the same key
// format as the recorder, so the replay transport can find it.
func writeFixture(t *testing.T, dir, method, fullURL, body string) {
	t.Helper()
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		t.Fatalf("writeFixture: bad URL %s: %v", fullURL, err)
	}
	key := client.RequestKey(req)
	filePath := filepath.Join(dir, key+".json")
	rec := map[string]interface{}{
		"status_code": 200,
		"headers":     map[string]string{"Content-Type": "application/json"},
		"body":        body,
	}
	data, _ := json.MarshalIndent(rec, "", "  ")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("writeFixture: write %s: %v", filePath, err)
	}
}

// base is the Vercel API base URL used by the client.
const base = "https://api.vercel.com"

// setupFixtures populates a temp directory with synthetic API responses and
// returns a replay-mode client configured to read from them.
func setupFixtures(t *testing.T) (string, *client.Client) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "fixtures")
	os.MkdirAll(dir, 0755)

	// --- Non-paginated endpoints (no query params added by client) ---

	writeFixture(t, dir, "GET", base+"/v2/user",
		`{"user":{"id":"usr_test","username":"testuser"}}`)

	writeFixture(t, dir, "GET", base+"/v5/user/tokens",
		`{"tokens":[{"id":"tok_001","name":"no-expiry-token","expiresAt":null,"activeAt":1700000000000,"scopes":[]}]}`)

	writeFixture(t, dir, "GET", base+"/v1/drains",
		`{"drains":[]}`)

	writeFixture(t, dir, "GET", base+"/v1/webhooks",
		`[{"id":"hook_nosecret","url":"https://example.com/webhook","events":["deployment.created"]}]`)

	writeFixture(t, dir, "GET", base+"/v1/edge-config",
		`[]`)

	writeFixture(t, dir, "GET", base+"/v1/connect/networks",
		`{"networks":[]}`)

	writeFixture(t, dir, "GET", base+"/v1/env",
		`{"envs":[]}`)

	writeFixture(t, dir, "GET", base+"/v8/artifacts/status",
		`{"status":"disabled"}`)

	writeFixture(t, dir, "GET", base+"/v7/certs",
		`{"certs":[]}`)

	writeFixture(t, dir, "GET", base+"/v1/bulk-redirects?projectId=prj_001",
		`{"redirects":[]}`)

	writeFixture(t, dir, "GET", base+"/v1/sandboxes?project=prj_001",
		`{"sandboxes":[]}`)

	// --- Paginated endpoints (client adds ?limit=100) ---

	writeFixture(t, dir, "GET", base+"/v2/teams?limit=100",
		`{"teams":[],"pagination":{}}`)

	writeFixture(t, dir, "GET", base+"/v10/projects?limit=100",
		`{"projects":[{"id":"prj_001","name":"test-app","framework":"nextjs","nodeVersion":"18.x","gitForkProtection":false,"publicSource":false,"autoExposeSystemEnvs":true,"link":{"type":"github","repoOwnerType":"User"}}],"pagination":{}}`)

	// Project env vars (paginated)
	writeFixture(t, dir, "GET", base+"/v10/projects/prj_001/env?limit=100",
		`{"envs":[{"id":"env_001","key":"NEXT_PUBLIC_SECRET_KEY","type":"plain","target":["production","preview","development"]},{"id":"env_002","key":"DATABASE_URL","type":"plain","target":["production","preview","development"],"value":"postgres://u:p@host/db"},{"id":"env_003","key":"VITE_SECRET_KEY","value":"super-secret","type":"plain","target":["production"]}],"pagination":{}}`)

	// Project domains (paginated)
	writeFixture(t, dir, "GET", base+"/v9/projects/prj_001/domains?limit=100",
		`{"domains":[],"pagination":{}}`)

	// Deployments (paginated, client adds limit=100 but GetPaginated overrides to 100)
	// ListDeployments passes limit=5 for nextjs version check, and limit=50 for public deployments check
	// GetPaginated sets limit=100, but ListDeployments sets its own limit param
	// Looking at the code: ListDeployments calls getPaginatedMaps which calls GetPaginated which sets limit=100
	// BUT ListDeployments passes params with limit already set... GetPaginated overwrites with limit=100
	writeFixture(t, dir, "GET", base+"/v6/deployments?limit=100&projectId=prj_001",
		`{"deployments":[],"pagination":{}}`)
	writeFixture(t, dir, "GET", base+"/v6/deployments?limit=100",
		`{"deployments":[],"pagination":{}}`)
	// ListDeploymentsLimit uses non-paginated single requests with varying limits
	writeFixture(t, dir, "GET", base+"/v6/deployments?limit=1&projectId=prj_001",
		`{"deployments":[],"pagination":{}}`)
	writeFixture(t, dir, "GET", base+"/v6/deployments?limit=5&projectId=prj_001",
		`{"deployments":[{"id":"dpl_001","name":"test-app","meta":{"framework":"nextjs","frameworkVersion":"15.1.3"}}],"pagination":{}}`)
	writeFixture(t, dir, "GET", base+"/v6/deployments?limit=50",
		`{"deployments":[],"pagination":{}}`)

	// Domains (paginated)
	writeFixture(t, dir, "GET", base+"/v5/domains?limit=100",
		`{"domains":[{"name":"example.com"}],"pagination":{}}`)

	// DNS records for example.com (paginated) — dangling A record for sto-003
	writeFixture(t, dir, "GET", base+"/v5/domains/example.com/records?limit=100",
		`{"records":[{"id":"rec_dangling_a","type":"A","name":"orphan","value":"76.76.21.21"}],"pagination":{}}`)

	// Integrations (paginated)
	writeFixture(t, dir, "GET", base+"/v1/integrations/configurations?limit=100&view=account",
		`{"configurations":[],"pagination":{}}`)

	// Access groups (paginated)
	writeFixture(t, dir, "GET", base+"/v1/access-groups?limit=100",
		`{"accessGroups":[],"pagination":{}}`)

	// Aliases (paginated)
	writeFixture(t, dir, "GET", base+"/v4/aliases?limit=100",
		`{"aliases":[],"pagination":{}}`)

	// Feature flags (paginated)
	writeFixture(t, dir, "GET", base+"/v1/projects/prj_001/feature-flags/flags?limit=100",
		`{"data":[],"pagination":{}}`)

	// Project routes
	writeFixture(t, dir, "GET", base+"/v1/projects/prj_001/routes",
		`{"routes":[{"id":"route_ssrf","src":"/api/internal","dest":"http://169.254.169.254/latest/meta-data/"}]}`)

	// Project members (paginated)
	writeFixture(t, dir, "GET", base+"/v1/projects/prj_001/members?limit=100",
		`{"members":[],"pagination":{}}`)

	// Rolling release config
	writeFixture(t, dir, "GET", base+"/v1/projects/prj_001/rolling-release/config",
		`{}`)

	// Firewall config (uses projectId query param)
	writeFixture(t, dir, "GET", base+"/v1/security/firewall/config/active?projectId=prj_001",
		`{"firewallEnabled":true,"crs":{"sqli":{"enabled":true,"action":"log"},"xss":{"enabled":true,"action":"block"},"rce":{"enabled":true,"action":"block"},"lfi":{"enabled":true,"action":"block"},"rfi":{"enabled":true,"action":"block"},"gen":{"enabled":true,"action":"block"},"ma":{"enabled":true,"action":"block"},"sf":{"enabled":true,"action":"block"},"sd":{"enabled":true,"action":"block"},"php":{"enabled":true,"action":"block"},"java":{"enabled":true,"action":"block"}}}`)

	// Firewall bypass
	writeFixture(t, dir, "GET", base+"/v1/security/firewall/bypass?projectId=prj_001",
		`{}`)

	c := client.NewRecordingClient("fake-token", "", "", client.ModeReplay, dir)
	return dir, c
}

// findFinding searches the findings list for a specific check ID.
func findFinding(findings []models.Finding, checkID string) *models.Finding {
	for i := range findings {
		if findings[i].CheckID == checkID {
			return &findings[i]
		}
	}
	return nil
}

// findFindings returns all findings matching a check ID.
func findFindings(findings []models.Finding, checkID string) []models.Finding {
	var matches []models.Finding
	for _, f := range findings {
		if f.CheckID == checkID {
			matches = append(matches, f)
		}
	}
	return matches
}

// runScan is a helper that creates a scanner with the given config and runs it.
func runScan(t *testing.T, c *client.Client, cfg *config.Config) *models.ScanResult {
	t.Helper()
	if cfg == nil {
		cfg = config.New()
	}
	s := scanner.New(c, cfg, nil)
	result, err := s.Run("test-scan")
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	return result
}

// ---------------------------------------------------------------------------
// Test: expected findings from synthetic fixture data
// ---------------------------------------------------------------------------

func TestExpectedFindings(t *testing.T) {
	_, c := setupFixtures(t)
	result := runScan(t, c, nil)

	// These checks MUST fire given our fixture data:
	//   iam-001: token without expiry
	//   iam-005: token with full access scope (empty scopes)
	//   njs-001: NEXT_PUBLIC_SECRET_KEY
	//   njs-002: outdated Next.js 15.1.3 with known CVEs
	//   sec-001: DATABASE_URL stored as plain text (sensitive name)
	//   sec-002: sensitive vars exposed to preview/development
	//   sec-026: VITE_SECRET_KEY uses client-exposure prefix
	//   dep-001: gitForkProtection = false
	//   log-001: no log drains configured
	//   log-024: webhook missing signing secret
	//   fw-010: OWASP sqli rule in log mode instead of block
	//   route-004: route destination points to metadata IP (SSRF)
	//   sto-003: dangling A record pointing to Vercel IP
	//   prev-001: no preview protection

	mustFind := []struct {
		id     string
		status models.Status
	}{
		{"iam-001", models.Fail},   // token without expiry
		{"iam-005", models.Warn},   // full access scope (empty scopes)
		{"njs-001", models.Fail},   // NEXT_PUBLIC_SECRET_KEY
		{"njs-002", models.Fail},   // outdated Next.js with known CVEs
		{"sec-001", models.Fail},   // plain text sensitive var (DATABASE_URL)
		{"sec-026", models.Fail},   // VITE_SECRET_KEY client-exposed
		{"dep-001", models.Fail},   // fork protection disabled
		{"log-001", models.Fail},   // no log drains
		{"log-024", models.Warn},   // webhook missing signing secret
		{"fw-010", models.Warn},    // OWASP rule in detect-only mode
		{"route-004", models.Fail}, // SSRF via internal destination
		{"sto-003", models.Fail},   // dangling A record to Vercel IP
		{"prev-001", models.Fail},  // no preview protection
	}

	for _, tc := range mustFind {
		t.Run(tc.id, func(t *testing.T) {
			matches := findFindings(result.Findings, tc.id)
			found := false
			for _, f := range matches {
				if f.Status == tc.status {
					found = true
					break
				}
			}
			if !found {
				statuses := make([]string, len(matches))
				for i, f := range matches {
					statuses[i] = string(f.Status)
				}
				t.Errorf("expected check %s with status %s; found %d matches with statuses %v",
					tc.id, tc.status, len(matches), statuses)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: sec-002 fires for sensitive vars in preview/development
// ---------------------------------------------------------------------------

func TestSecretExposureToPreview(t *testing.T) {
	_, c := setupFixtures(t)
	result := runScan(t, c, nil)

	matches := findFindings(result.Findings, "sec-002")
	if len(matches) == 0 {
		t.Fatal("expected sec-002 findings for sensitive vars in non-production environments")
	}

	// Both NEXT_PUBLIC_SECRET_KEY and DATABASE_URL should trigger sec-002
	foundPublicKey := false
	foundDBURL := false
	for _, f := range matches {
		if f.ResourceName == "NEXT_PUBLIC_SECRET_KEY" {
			foundPublicKey = true
		}
		if f.ResourceName == "DATABASE_URL" {
			foundDBURL = true
		}
	}
	if !foundPublicKey {
		t.Error("sec-002 should flag NEXT_PUBLIC_SECRET_KEY in preview/development")
	}
	if !foundDBURL {
		t.Error("sec-002 should flag DATABASE_URL in preview/development")
	}
}

// ---------------------------------------------------------------------------
// Test: posture score calculation
// ---------------------------------------------------------------------------

func TestPostureScoreCalculation(t *testing.T) {
	_, c := setupFixtures(t)
	result := runScan(t, c, nil)

	if result.Summary.PostureScore < 0 || result.Summary.PostureScore > 100 {
		t.Errorf("posture score out of range: %.1f", result.Summary.PostureScore)
	}
	if result.Summary.Total == 0 {
		t.Error("expected some findings, got 0")
	}
	if result.Summary.Failed == 0 {
		t.Error("expected some failures, got 0")
	}
	// With our intentionally bad fixture data, score should be well below 100
	if result.Summary.PostureScore >= 100 {
		t.Errorf("posture score should be below 100 with known failures, got %.1f", result.Summary.PostureScore)
	}
}

// ---------------------------------------------------------------------------
// Test: severity counts populated
// ---------------------------------------------------------------------------

func TestSeverityCounts(t *testing.T) {
	_, c := setupFixtures(t)
	result := runScan(t, c, nil)

	if len(result.Summary.SeverityCounts) == 0 {
		t.Error("expected severity counts to be populated")
	}
	// We know we have CRITICAL (njs-001, sec-001) and HIGH (iam-001, dep-001, etc.)
	if result.Summary.SeverityCounts["CRITICAL"] == 0 {
		t.Error("expected at least one CRITICAL severity finding")
	}
	if result.Summary.SeverityCounts["HIGH"] == 0 {
		t.Error("expected at least one HIGH severity finding")
	}
}

// ---------------------------------------------------------------------------
// Test: category counts populated
// ---------------------------------------------------------------------------

func TestCategoryCounts(t *testing.T) {
	_, c := setupFixtures(t)
	result := runScan(t, c, nil)

	if len(result.Summary.CategoryCounts) == 0 {
		t.Error("expected category counts to be populated")
	}
}

// ---------------------------------------------------------------------------
// Test: config suppression
// ---------------------------------------------------------------------------

func TestConfigSuppression(t *testing.T) {
	_, c := setupFixtures(t)
	cfg := config.New()
	cfg.Suppress["iam-001"] = true
	cfg.Suppress["njs-001"] = true

	result := runScan(t, c, cfg)

	for _, f := range result.Findings {
		if f.CheckID == "iam-001" && f.Status == models.Fail {
			t.Error("iam-001 should be suppressed but is still failing")
		}
		if f.CheckID == "njs-001" && f.Status == models.Fail {
			t.Error("njs-001 should be suppressed but is still failing")
		}
	}

	// Suppressed checks should appear as PASS with [SUPPRESSED] prefix
	for _, f := range result.Findings {
		if f.CheckID == "iam-001" && f.Status == models.Pass {
			if len(f.Description) < 12 || f.Description[:12] != "[SUPPRESSED]" {
				t.Errorf("suppressed iam-001 should have [SUPPRESSED] prefix, got: %s", f.Description)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Test: minimum severity filter
// ---------------------------------------------------------------------------

func TestMinSeverityFilter(t *testing.T) {
	_, c := setupFixtures(t)
	cfg := config.New()
	cfg.MinSeverity = "HIGH"

	result := runScan(t, c, cfg)

	for _, f := range result.Findings {
		if f.Status == models.Fail || f.Status == models.Warn {
			sev := string(f.Severity)
			if sev != "CRITICAL" && sev != "HIGH" {
				t.Errorf("finding %s has severity %s but min is HIGH", f.CheckID, sev)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Test: skip check filter
// ---------------------------------------------------------------------------

func TestSkipChecksFilter(t *testing.T) {
	_, c := setupFixtures(t)
	cfg := config.New()
	cfg.SkipChecks["dep-001"] = true
	cfg.SkipChecks["log-001"] = true

	result := runScan(t, c, cfg)

	for _, f := range result.Findings {
		if f.CheckID == "dep-001" {
			t.Error("dep-001 should be skipped but appeared in results")
		}
		if f.CheckID == "log-001" {
			t.Error("log-001 should be skipped but appeared in results")
		}
	}
}

// ---------------------------------------------------------------------------
// Test: category filter
// ---------------------------------------------------------------------------

func TestCategoryFilter(t *testing.T) {
	_, c := setupFixtures(t)
	cfg := config.New()
	cfg.Categories["Identity & Access Management"] = true

	result := runScan(t, c, cfg)

	for _, f := range result.Findings {
		if f.Category != "Identity & Access Management" {
			t.Errorf("finding %s has category %q but only IAM should be included", f.CheckID, f.Category)
		}
	}

	// Should still have IAM findings
	hasIAM := false
	for _, f := range result.Findings {
		if f.Category == "Identity & Access Management" {
			hasIAM = true
			break
		}
	}
	if !hasIAM {
		t.Error("expected IAM findings when category filter includes IAM")
	}
}

// ---------------------------------------------------------------------------
// Test: skip category filter
// ---------------------------------------------------------------------------

func TestSkipCategoryFilter(t *testing.T) {
	_, c := setupFixtures(t)
	cfg := config.New()
	cfg.SkipCategories["Logging & Monitoring"] = true

	result := runScan(t, c, cfg)

	for _, f := range result.Findings {
		if f.Category == "Logging & Monitoring" {
			t.Errorf("finding %s has category Logging & Monitoring which should be skipped", f.CheckID)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: findings are sorted (failures first, then by severity)
// ---------------------------------------------------------------------------

func TestFindingsSorted(t *testing.T) {
	_, c := setupFixtures(t)
	result := runScan(t, c, nil)

	if len(result.Findings) < 2 {
		t.Skip("not enough findings to test sort order")
	}

	statusRank := map[models.Status]int{
		models.Fail: 0, models.Warn: 1, models.Error: 2, models.Pass: 3,
	}

	for i := 1; i < len(result.Findings); i++ {
		prev := result.Findings[i-1]
		curr := result.Findings[i]

		prevRank := statusRank[prev.Status]
		currRank := statusRank[curr.Status]

		if prevRank > currRank {
			t.Errorf("findings not sorted by status: %s (%s) before %s (%s)",
				prev.CheckID, prev.Status, curr.CheckID, curr.Status)
			break
		}

		if prevRank == currRank && prev.Severity.Rank() > curr.Severity.Rank() {
			t.Errorf("findings not sorted by severity within status %s: %s (%s) before %s (%s)",
				prev.Status, prev.CheckID, prev.Severity, curr.CheckID, curr.Severity)
			break
		}
	}
}

// ---------------------------------------------------------------------------
// Test: account info populated from user endpoint
// ---------------------------------------------------------------------------

func TestAccountInfoPopulated(t *testing.T) {
	_, c := setupFixtures(t)
	result := runScan(t, c, nil)

	if result.AccountID != "usr_test" {
		t.Errorf("expected AccountID 'usr_test', got %q", result.AccountID)
	}
	if result.AccountName != "testuser" {
		t.Errorf("expected AccountName 'testuser', got %q", result.AccountName)
	}
}

// ---------------------------------------------------------------------------
// Test: scan timing fields
// ---------------------------------------------------------------------------

func TestScanTimingFields(t *testing.T) {
	_, c := setupFixtures(t)
	result := runScan(t, c, nil)

	if result.ScanID != "test-scan" {
		t.Errorf("expected ScanID 'test-scan', got %q", result.ScanID)
	}
	if result.StartedAt.IsZero() {
		t.Error("StartedAt should not be zero")
	}
	if result.CompletedAt.IsZero() {
		t.Error("CompletedAt should not be zero")
	}
	if result.CompletedAt.Before(result.StartedAt) {
		t.Error("CompletedAt should not be before StartedAt")
	}
}

// ---------------------------------------------------------------------------
// Test: scanner check count
// ---------------------------------------------------------------------------

func TestScannerCheckCount(t *testing.T) {
	cfg := config.New()
	c := client.NewRecordingClient("fake", "", "", client.ModeReplay, t.TempDir())
	s := scanner.New(c, cfg, nil)

	count := s.CheckCount()
	if count == 0 {
		t.Error("expected non-zero check count")
	}

	names := s.CheckNames()
	if len(names) != count {
		t.Errorf("check names length %d != count %d", len(names), count)
	}
}
