package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Su1ph3r/vercelsior/internal/models"
)

func sampleResult() *models.ScanResult {
	r := &models.ScanResult{
		ScanID:      "vercelsior-test",
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
		AccountName: "acme",
		Findings: []models.Finding{
			{
				CheckID: "iam-001", Title: "Token without expiration",
				Category: "Identity & Access Management", Severity: models.High,
				Status: models.Fail, RiskScore: 7.5,
				Rationale:    "Long-lived tokens widen the blast radius of a leak.",
				Description:  "API token has no expiration date.",
				Remediation:  "Rotate the token and set an expiration.",
				ResourceType: "token", ResourceID: "tok_123", ResourceName: "ci-token",
			},
			{
				CheckID: "fw-003", Title: "WAF in detect-only mode",
				Category: "Firewall & WAF", Severity: models.Medium,
				Status: models.Warn, RiskScore: 4.0,
				Description:  "Managed rules are logging but not blocking.",
				ResourceType: "project", ResourceID: "prj_abc", ResourceName: "web",
			},
			{
				CheckID: "dom-002", Title: "Healthy domain",
				Category: "Domains", Severity: models.Info, Status: models.Pass,
				ResourceType: "domain", ResourceID: "example.com",
			},
			{
				CheckID: "iam-009", Title: "Access groups unreadable",
				Category: "Identity & Access Management", Severity: models.High,
				Status: models.Error, Description: "permission denied (HTTP 403)",
				ResourceType: "permission", ResourceID: "N/A",
			},
		},
	}
	r.Compute()
	return r
}

func TestBuildSARIF_Structure(t *testing.T) {
	log := BuildSARIF(sampleResult())

	if log.Version != "2.1.0" {
		t.Errorf("version = %q; want 2.1.0", log.Version)
	}
	if log.Schema == "" {
		t.Error("missing $schema")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d; want 1", len(log.Runs))
	}
	run := log.Runs[0]

	// PASS finding must be excluded; FAIL + WARN + ERROR included (3).
	if len(run.Results) != 3 {
		t.Errorf("results = %d; want 3 (PASS excluded)", len(run.Results))
	}
	// Three distinct check IDs among the reportable findings => 3 rules.
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("rules = %d; want 3", len(run.Tool.Driver.Rules))
	}
}

func TestBuildSARIF_LevelMapping(t *testing.T) {
	log := BuildSARIF(sampleResult())
	byRule := map[string]sarifResult{}
	for _, res := range log.Runs[0].Results {
		byRule[res.RuleID] = res
	}

	if got := byRule["iam-001"].Level; got != "error" {
		t.Errorf("HIGH fail level = %q; want error", got)
	}
	if got := byRule["fw-003"].Level; got != "warning" {
		t.Errorf("MEDIUM warn level = %q; want warning", got)
	}
	// ERROR status always downgrades to note regardless of severity.
	if got := byRule["iam-009"].Level; got != "note" {
		t.Errorf("ERROR level = %q; want note", got)
	}
}

func TestBuildSARIF_RuleIndexValid(t *testing.T) {
	log := BuildSARIF(sampleResult())
	run := log.Runs[0]
	for _, res := range run.Results {
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("ruleIndex %d out of range for %d rules", res.RuleIndex, len(run.Tool.Driver.Rules))
		}
		// The rule the index points to must match the result's ruleId.
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("ruleIndex %d -> %q; want %q", res.RuleIndex, run.Tool.Driver.Rules[res.RuleIndex].ID, res.RuleID)
		}
	}
}

func TestBuildSARIF_SecuritySeverityUsesRiskScore(t *testing.T) {
	log := BuildSARIF(sampleResult())
	for _, rule := range log.Runs[0].Tool.Driver.Rules {
		if rule.ID == "iam-001" && rule.Properties.SecuritySeverity != "7.5" {
			t.Errorf("iam-001 security-severity = %q; want 7.5", rule.Properties.SecuritySeverity)
		}
	}
}

func TestBuildSARIF_ErrorSecuritySeverityNotZero(t *testing.T) {
	// ERROR findings (a check that could not run) must not collapse to
	// security-severity 0.0, which GitHub filters out of the Security tab.
	log := BuildSARIF(sampleResult())
	for _, rule := range log.Runs[0].Tool.Driver.Rules {
		if rule.ID == "iam-009" { // the ERROR-status finding in sampleResult
			if rule.Properties.SecuritySeverity == "0.0" || rule.Properties.SecuritySeverity == "" {
				t.Errorf("ERROR finding security-severity = %q; want a non-zero bucket so it surfaces", rule.Properties.SecuritySeverity)
			}
		}
	}
}

func TestBuildSARIF_Locations(t *testing.T) {
	log := BuildSARIF(sampleResult())
	for _, res := range log.Runs[0].Results {
		if len(res.Locations) == 0 {
			t.Fatalf("result %s has no locations (GitHub requires >=1)", res.RuleID)
		}
		uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if uri == "" {
			t.Errorf("result %s has empty artifact URI", res.RuleID)
		}
		if res.Locations[0].PhysicalLocation.Region.StartLine != 1 {
			t.Errorf("result %s startLine = %d; want 1", res.RuleID, res.Locations[0].PhysicalLocation.Region.StartLine)
		}
	}
}

func TestBuildSARIF_FingerprintStableAndDistinct(t *testing.T) {
	a := BuildSARIF(sampleResult())
	b := BuildSARIF(sampleResult())
	// Same input => identical fingerprints (stable across runs).
	for i := range a.Runs[0].Results {
		fa := a.Runs[0].Results[i].PartialFingerprints["vercelsior/v1"]
		fb := b.Runs[0].Results[i].PartialFingerprints["vercelsior/v1"]
		if fa == "" {
			t.Fatalf("empty fingerprint for %s", a.Runs[0].Results[i].RuleID)
		}
		if fa != fb {
			t.Errorf("fingerprint not stable for %s: %q vs %q", a.Runs[0].Results[i].RuleID, fa, fb)
		}
	}
	// Distinct resources => distinct fingerprints.
	seen := map[string]string{}
	for _, res := range a.Runs[0].Results {
		fp := res.PartialFingerprints["vercelsior/v1"]
		if prev, ok := seen[fp]; ok {
			t.Errorf("fingerprint collision: %s and %s share %q", prev, res.RuleID, fp)
		}
		seen[fp] = res.RuleID
	}
}

func TestWriteSARIF_ValidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	if err := WriteSARIF(sampleResult(), path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if v["version"] != "2.1.0" {
		t.Errorf("serialized version = %v; want 2.1.0", v["version"])
	}
}

func TestSARIFTagSlug(t *testing.T) {
	cases := map[string]string{
		"Identity & Access Management": "identity-access-management",
		"Firewall & WAF":               "firewall-waf",
		"Domains":                      "domains",
		"":                             "general",
	}
	for in, want := range cases {
		if got := sarifTagSlug(in); got != want {
			t.Errorf("sarifTagSlug(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestSARIFRuleName(t *testing.T) {
	cases := map[string]string{
		"iam-001": "Iam001",
		"njs-12":  "Njs12",
		"fw_3":    "Fw3",
	}
	for in, want := range cases {
		got := sarifRuleName(models.Finding{CheckID: in})
		if got != want {
			t.Errorf("sarifRuleName(%q) = %q; want %q", in, got, want)
		}
	}
}
