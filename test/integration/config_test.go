package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/su1ph/vercelsior/internal/config"
)

func TestConfigLoadMissingFile(t *testing.T) {
	cfg, err := config.Load("/nonexistent/path/.vercelsior")
	if err != nil {
		t.Fatal(err)
	}
	// Should return empty config, not error
	if len(cfg.Suppress) != 0 {
		t.Error("expected empty suppress list")
	}
}

func TestConfigLoadAndParse(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".vercelsior")

	content := `# Comment line
suppress: iam-015
suppress: dom-010
min_severity: HIGH
skip_check: dep-007
skip_category: Infrastructure
category: Firewall & WAF
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.IsSuppressed("iam-015") {
		t.Error("iam-015 should be suppressed")
	}
	if !cfg.IsSuppressed("dom-010") {
		t.Error("dom-010 should be suppressed")
	}
	if cfg.IsSuppressed("iam-001") {
		t.Error("iam-001 should not be suppressed")
	}

	if cfg.MinSeverity != "HIGH" {
		t.Errorf("expected min severity HIGH, got %s", cfg.MinSeverity)
	}

	if !cfg.MeetsMinSeverity("CRITICAL") {
		t.Error("CRITICAL should meet HIGH threshold")
	}
	if !cfg.MeetsMinSeverity("HIGH") {
		t.Error("HIGH should meet HIGH threshold")
	}
	if cfg.MeetsMinSeverity("MEDIUM") {
		t.Error("MEDIUM should not meet HIGH threshold")
	}

	if cfg.IsCheckAllowed("dep-007") {
		t.Error("dep-007 should be skipped")
	}
	if !cfg.IsCheckAllowed("dep-001") {
		t.Error("dep-001 should be allowed")
	}

	if !cfg.IsCategoryAllowed("Firewall & WAF") {
		t.Error("Firewall & WAF should be allowed")
	}
	if cfg.IsCategoryAllowed("Identity & Access Management") {
		t.Error("IAM should not be allowed when category filter is set")
	}
}

func TestConfigMerge(t *testing.T) {
	cfg := config.New()
	cfg.Merge("CRITICAL", []string{"iam-001"}, []string{"fw-001"}, []string{"IAM"})

	if cfg.MinSeverity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", cfg.MinSeverity)
	}
	if !cfg.Checks["iam-001"] {
		t.Error("iam-001 should be in checks whitelist")
	}
	if !cfg.SkipChecks["fw-001"] {
		t.Error("fw-001 should be in skip list")
	}
	if !cfg.Categories["IAM"] {
		t.Error("IAM should be in categories")
	}
}
