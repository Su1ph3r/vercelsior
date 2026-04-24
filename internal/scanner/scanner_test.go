package scanner

import (
	"strings"
	"testing"

	"github.com/Su1ph3r/vercelsior/internal/config"
	"github.com/Su1ph3r/vercelsior/internal/models"
)

func makeFinding(id, cat string, sev models.Severity, status models.Status) models.Finding {
	return models.Finding{
		CheckID:      id,
		Title:        id,
		Category:     cat,
		Severity:     sev,
		Status:       status,
		Description:  id + " description",
		ResourceType: "project",
		ResourceID:   "N/A",
	}
}

// TestApplyFilters_SuppressionBeforeMinSeverity is the regression test for
// F-L2: a suppressed finding below the min-severity threshold must remain
// visible as a [SUPPRESSED] Pass rather than being silently dropped by the
// severity gate.
func TestApplyFilters_SuppressionBeforeMinSeverity(t *testing.T) {
	cfg := config.New()
	cfg.Suppress["iam-001"] = true
	cfg.MinSeverity = "HIGH"

	findings := []models.Finding{
		makeFinding("iam-001", "IAM", models.Low, models.Fail),
	}

	out := applyFilters(cfg, findings)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d; want 1 (suppressed finding must survive severity gate)", len(out))
	}
	if out[0].Status != models.Pass {
		t.Errorf("Status = %q; want Pass (suppressed)", out[0].Status)
	}
	if !strings.HasPrefix(out[0].Description, "[SUPPRESSED]") {
		t.Errorf("Description = %q; want [SUPPRESSED] prefix", out[0].Description)
	}
}

func TestApplyFilters_MinSeverityDropsLowFailures(t *testing.T) {
	cfg := config.New()
	cfg.MinSeverity = "HIGH"
	findings := []models.Finding{
		makeFinding("x-1", "c1", models.Critical, models.Fail),
		makeFinding("x-2", "c1", models.High, models.Fail),
		makeFinding("x-3", "c1", models.Medium, models.Fail),
		makeFinding("x-4", "c1", models.Low, models.Fail),
	}
	out := applyFilters(cfg, findings)
	if len(out) != 2 {
		t.Fatalf("len(out) = %d; want 2 (Critical+High only)", len(out))
	}
	// Pass findings below the threshold are always retained.
	passFindings := []models.Finding{
		makeFinding("y-1", "c1", models.Low, models.Pass),
	}
	out = applyFilters(cfg, passFindings)
	if len(out) != 1 {
		t.Fatalf("pass finding below min-severity dropped: len = %d", len(out))
	}
}

func TestApplyFilters_CategoryGate(t *testing.T) {
	cfg := config.New()
	cfg.SkipCategories["IAM"] = true

	findings := []models.Finding{
		makeFinding("iam-001", "IAM", models.High, models.Fail),
		makeFinding("log-001", "Logging", models.High, models.Fail),
	}
	out := applyFilters(cfg, findings)
	if len(out) != 1 || out[0].CheckID != "log-001" {
		t.Errorf("skip_category=IAM should remove iam-001; got %+v", out)
	}
}

func TestApplyFilters_CheckAllowlist(t *testing.T) {
	cfg := config.New()
	cfg.Checks["fw-001"] = true // allowlist mode

	findings := []models.Finding{
		makeFinding("fw-001", "FW", models.High, models.Fail),
		makeFinding("fw-002", "FW", models.High, models.Fail),
	}
	out := applyFilters(cfg, findings)
	if len(out) != 1 || out[0].CheckID != "fw-001" {
		t.Errorf("allowlist should keep only fw-001; got %+v", out)
	}
}

// TestApplyFilters_SuppressionMarksAsPass verifies the filter converts a
// suppressed finding into [SUPPRESSED] Pass. The legacy-ID→canonical
// aliasing is exercised separately in config/config_test.go.
func TestApplyFilters_SuppressionMarksAsPass(t *testing.T) {
	cfg := config.New()
	cfg.Suppress["iam-001"] = true

	findings := []models.Finding{
		makeFinding("iam-001", "IAM", models.High, models.Fail),
	}
	out := applyFilters(cfg, findings)
	if len(out) != 1 {
		t.Fatalf("len(out) = %d; want 1", len(out))
	}
	if out[0].Status != models.Pass {
		t.Errorf("Status = %q; want Pass", out[0].Status)
	}
	if !strings.Contains(out[0].Description, "[SUPPRESSED]") {
		t.Errorf("Description missing [SUPPRESSED] prefix: %q", out[0].Description)
	}
}

func TestDedupeFindings(t *testing.T) {
	findings := []models.Finding{
		makeFinding("a", "c1", models.High, models.Fail),
		makeFinding("a", "c1", models.High, models.Fail), // exact duplicate
		makeFinding("a", "c1", models.High, models.Pass), // same key, different status — dropped
		makeFinding("b", "c1", models.High, models.Fail),
	}
	// Override ResourceID to simulate a different key.
	findings[3].ResourceID = "other"
	findings = append(findings, makeFinding("b", "c1", models.High, models.Fail)) // collides with findings[3]? No: findings[3] has ResourceID "other"; this has "N/A". So different key.

	out := dedupeFindings(findings)
	// Keys:
	//   a|N/A    (findings[0]) — kept
	//   a|N/A    (findings[1]) — duplicate
	//   a|N/A    (findings[2]) — duplicate
	//   b|other  (findings[3]) — kept
	//   b|N/A    (findings[4]) — kept
	if len(out) != 3 {
		t.Errorf("len(out) = %d; want 3", len(out))
	}
}

func TestScannerCheckCount(t *testing.T) {
	s := New(nil, config.New(), nil)
	if s.CheckCount() < 1 {
		t.Error("expected at least one registered check module")
	}
	if len(s.CheckNames()) != s.CheckCount() {
		t.Error("CheckNames length should match CheckCount")
	}
}
