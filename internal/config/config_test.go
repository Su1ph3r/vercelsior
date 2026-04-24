package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalCheckID(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// Known aliases map to canonical IDs
		{"inf-030", "infra-040"},
		{"rol-001", "roll-001"},
		{"sbx-001", "sand-001"},

		// Canonical IDs pass through unchanged
		{"infra-040", "infra-040"},
		{"roll-001", "roll-001"},
		{"sand-001", "sand-001"},

		// Unknown IDs are returned as-is (no panic, no guess)
		{"unknown-check", "unknown-check"},
		{"", ""},
		{"iam-001", "iam-001"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := canonicalCheckID(tc.input)
			if got != tc.want {
				t.Errorf("canonicalCheckID(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestSuppressLegacyMatchesCanonical verifies that a user who suppressed a
// legacy CheckID continues to match after the check module was fixed to
// emit the canonical form. This is the contract that allowed the CheckID
// rename to land without a breaking change.
func TestSuppressLegacyMatchesCanonical(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vercelsior")
	body := "suppress: inf-030\nsuppress: rol-001\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	// Canonical IDs should be suppressed even though the user wrote the
	// legacy forms in the config file.
	if !cfg.IsSuppressed("infra-040") {
		t.Error("legacy 'inf-030' should suppress canonical 'infra-040'")
	}
	if !cfg.IsSuppressed("roll-001") {
		t.Error("legacy 'rol-001' should suppress canonical 'roll-001'")
	}
	// An unrelated check should not be suppressed.
	if cfg.IsSuppressed("iam-001") {
		t.Error("iam-001 should not be suppressed")
	}
}

// TestSkipCheckWithAliasOnCLI verifies that --skip-checks with a legacy ID
// from the CLI flag path also canonicalizes.
func TestSkipCheckWithAliasOnCLI(t *testing.T) {
	cfg := New()
	cfg.Merge("", nil, []string{"sbx-001"}, nil)

	if !cfg.SkipChecks["sand-001"] {
		t.Error("--skip-checks sbx-001 should map to canonical sand-001")
	}
	// Calling IsCheckAllowed with either form must return the same answer.
	if cfg.IsCheckAllowed("sand-001") {
		t.Error("IsCheckAllowed(sand-001) should be false when skipped")
	}
	if cfg.IsCheckAllowed("sbx-001") {
		t.Error("IsCheckAllowed(sbx-001) should be false when skipped")
	}
}

func TestLoadMissingFileReturnsEmptyConfig(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("Load(nonexistent) err = %v; want nil", err)
	}
	if cfg == nil {
		t.Fatal("cfg = nil; want non-nil")
	}
	if cfg.IsSuppressed("iam-001") {
		t.Error("empty config should not suppress anything")
	}
}

func TestLoadParsesAllDirectives(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vercelsior")
	body := `# comment
suppress: iam-001
min_severity: HIGH
check: fw-001
check: fw-002
skip_check: log-010
category: IAM
skip_category: Logging

# blank line above
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Suppress["iam-001"] {
		t.Error("iam-001 not suppressed")
	}
	if cfg.MinSeverity != "HIGH" {
		t.Errorf("MinSeverity = %q; want HIGH", cfg.MinSeverity)
	}
	if !cfg.Checks["fw-001"] || !cfg.Checks["fw-002"] {
		t.Error("checks allowlist missing fw-001/fw-002")
	}
	if !cfg.SkipChecks["log-010"] {
		t.Error("log-010 not in skip list")
	}
	if !cfg.Categories["IAM"] {
		t.Error("IAM category not allowed")
	}
	if !cfg.SkipCategories["Logging"] {
		t.Error("Logging category not skipped")
	}
}

func TestLoadIgnoresCommentsAndMalformedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vercelsior")
	body := "# this is a comment\nnot a key value line\nsuppress: iam-001\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Suppress["iam-001"] {
		t.Error("expected iam-001 to be suppressed")
	}
}

func TestIsCheckAllowed(t *testing.T) {
	t.Run("empty config allows everything", func(t *testing.T) {
		cfg := New()
		if !cfg.IsCheckAllowed("iam-001") {
			t.Error("empty config should allow iam-001")
		}
	})
	t.Run("allowlist restricts to listed checks", func(t *testing.T) {
		cfg := New()
		cfg.Checks["iam-001"] = true
		if !cfg.IsCheckAllowed("iam-001") {
			t.Error("iam-001 should be allowed")
		}
		if cfg.IsCheckAllowed("iam-002") {
			t.Error("iam-002 should be denied because it's not in the allowlist")
		}
	})
	t.Run("skip list blocks specific checks", func(t *testing.T) {
		cfg := New()
		cfg.SkipChecks["iam-001"] = true
		if cfg.IsCheckAllowed("iam-001") {
			t.Error("iam-001 should be denied")
		}
		if !cfg.IsCheckAllowed("iam-002") {
			t.Error("iam-002 should be allowed")
		}
	})
}

func TestIsCategoryAllowed(t *testing.T) {
	t.Run("empty allowlist permits all", func(t *testing.T) {
		cfg := New()
		if !cfg.IsCategoryAllowed("IAM") {
			t.Error("empty config should allow IAM")
		}
	})
	t.Run("allowlist restricts to listed categories", func(t *testing.T) {
		cfg := New()
		cfg.Categories["IAM"] = true
		if !cfg.IsCategoryAllowed("IAM") {
			t.Error("IAM should be allowed")
		}
		if cfg.IsCategoryAllowed("Logging") {
			t.Error("Logging should be denied")
		}
	})
	t.Run("skip list blocks specific categories", func(t *testing.T) {
		cfg := New()
		cfg.SkipCategories["Logging"] = true
		if cfg.IsCategoryAllowed("Logging") {
			t.Error("Logging should be denied")
		}
	})
}

func TestMeetsMinSeverity(t *testing.T) {
	cfg := New()
	cfg.MinSeverity = "HIGH"
	cases := []struct {
		sev  string
		want bool
	}{
		{"CRITICAL", true},
		{"HIGH", true},
		{"MEDIUM", false},
		{"LOW", false},
		{"INFO", false},
		// case-insensitive
		{"high", true},
		{"medium", false},
	}
	for _, tc := range cases {
		t.Run(tc.sev, func(t *testing.T) {
			if got := cfg.MeetsMinSeverity(tc.sev); got != tc.want {
				t.Errorf("MeetsMinSeverity(%q) = %v; want %v", tc.sev, got, tc.want)
			}
		})
	}
}

func TestMeetsMinSeverityEmpty(t *testing.T) {
	cfg := New()
	// No MinSeverity set → every severity passes.
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", ""} {
		if !cfg.MeetsMinSeverity(sev) {
			t.Errorf("empty MinSeverity should allow %q", sev)
		}
	}
}

func TestMerge(t *testing.T) {
	cfg := New()
	cfg.MinSeverity = "HIGH"
	cfg.Merge("LOW", []string{"iam-001"}, []string{"log-010"}, []string{"IAM"})

	if cfg.MinSeverity != "LOW" {
		t.Errorf("MinSeverity = %q; want LOW (CLI override)", cfg.MinSeverity)
	}
	if !cfg.Checks["iam-001"] {
		t.Error("iam-001 missing from checks")
	}
	if !cfg.SkipChecks["log-010"] {
		t.Error("log-010 missing from skipChecks")
	}
	if !cfg.Categories["IAM"] {
		t.Error("IAM missing from categories")
	}

	// Empty minSev does NOT overwrite the current value.
	cfg.Merge("", nil, nil, nil)
	if cfg.MinSeverity != "LOW" {
		t.Errorf("empty Merge() overwrote MinSeverity to %q; want LOW", cfg.MinSeverity)
	}
}
