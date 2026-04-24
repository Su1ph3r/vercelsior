package models

import (
	"math"
	"testing"
)

func TestSeverityRank(t *testing.T) {
	cases := []struct {
		sev  Severity
		rank int
	}{
		{Critical, 0},
		{High, 1},
		{Medium, 2},
		{Low, 3},
		{Info, 4},
		{Severity("unknown"), 5},
	}
	for _, tc := range cases {
		t.Run(string(tc.sev), func(t *testing.T) {
			if got := tc.sev.Rank(); got != tc.rank {
				t.Errorf("Rank(%q) = %d; want %d", tc.sev, got, tc.rank)
			}
		})
	}
}

// Ranks must be strictly increasing so sort.Slice ordering is stable and
// unambiguous across severities.
func TestSeverityRankOrdering(t *testing.T) {
	ordered := []Severity{Critical, High, Medium, Low, Info}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].Rank() >= ordered[i].Rank() {
			t.Errorf("%q (rank %d) not strictly less than %q (rank %d)",
				ordered[i-1], ordered[i-1].Rank(), ordered[i], ordered[i].Rank())
		}
	}
}

func TestRiskRating(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{10.0, "CRITICAL"},
		{9.0, "CRITICAL"},
		{8.99, "HIGH"},
		{7.0, "HIGH"},
		{6.99, "MEDIUM"},
		{4.0, "MEDIUM"},
		{3.99, "LOW"},
		{0.1, "LOW"},
		{0.0, "INFO"},
		{-1.0, "INFO"},
	}
	for _, tc := range cases {
		got := RiskRating(tc.score)
		if got != tc.want {
			t.Errorf("RiskRating(%.2f) = %q; want %q", tc.score, got, tc.want)
		}
	}
}

func TestCompute_PostureScore(t *testing.T) {
	// 1 pass, 1 fail (score 8), 1 warn (score 4).
	// maxRisk = 30, actualRisk = 8 + (4 * 0.5) = 10.
	// posture = 100 * (1 - 10/30) ≈ 66.67
	r := &ScanResult{
		Findings: []Finding{
			{Status: Pass, Severity: Info, Category: "c1"},
			{Status: Fail, Severity: High, RiskScore: 8.0, Category: "c1"},
			{Status: Warn, Severity: Medium, RiskScore: 4.0, Category: "c2"},
		},
	}
	r.Compute()
	wantPosture := 100.0 * (1.0 - 10.0/30.0)
	if math.Abs(r.Summary.PostureScore-wantPosture) > 0.01 {
		t.Errorf("PostureScore = %.2f; want %.2f", r.Summary.PostureScore, wantPosture)
	}
	if r.Summary.Passed != 1 || r.Summary.Failed != 1 || r.Summary.Warnings != 1 {
		t.Errorf("summary counts = (%d,%d,%d); want (1,1,1)",
			r.Summary.Passed, r.Summary.Failed, r.Summary.Warnings)
	}
	if r.Summary.SeverityCounts["HIGH"] != 1 {
		t.Errorf("HIGH count = %d; want 1", r.Summary.SeverityCounts["HIGH"])
	}
	if r.Summary.SeverityCounts["MEDIUM"] != 1 {
		t.Errorf("MEDIUM count = %d; want 1", r.Summary.SeverityCounts["MEDIUM"])
	}
	// Pass findings should NOT contribute to severity counts.
	if _, ok := r.Summary.SeverityCounts["INFO"]; ok {
		t.Error("passed findings should not be counted in SeverityCounts")
	}
}

func TestCompute_EmptyFindings(t *testing.T) {
	r := &ScanResult{}
	r.Compute()
	// With no findings the max risk is zero; the posture score must be
	// 100 (not NaN) to avoid a division-by-zero in the HTML report.
	if r.Summary.PostureScore != 100 {
		t.Errorf("empty PostureScore = %.2f; want 100", r.Summary.PostureScore)
	}
}

func TestCompute_PostureClampedAtZero(t *testing.T) {
	// Contrive a case where the nominal posture would go negative.
	r := &ScanResult{
		Findings: []Finding{
			{Status: Fail, Severity: Critical, RiskScore: 20.0, Category: "c1"}, // score > max/check
		},
	}
	r.Compute()
	if r.Summary.PostureScore < 0 {
		t.Errorf("PostureScore = %.2f; must not be negative", r.Summary.PostureScore)
	}
}

func TestCompute_CategoryCounts(t *testing.T) {
	r := &ScanResult{
		Findings: []Finding{
			{Status: Pass, Category: "IAM"},
			{Status: Pass, Category: "IAM"},
			{Status: Fail, Category: "IAM", RiskScore: 1},
			{Status: Warn, Category: "Logging", RiskScore: 1},
			{Status: Warn, Category: "Logging", RiskScore: 1},
		},
	}
	r.Compute()
	iam := r.Summary.CategoryCounts["IAM"]
	if iam.Pass != 2 || iam.Fail != 1 || iam.Warn != 0 {
		t.Errorf("IAM counts = %+v; want {Pass:2,Fail:1,Warn:0}", iam)
	}
	log := r.Summary.CategoryCounts["Logging"]
	if log.Pass != 0 || log.Fail != 0 || log.Warn != 2 {
		t.Errorf("Logging counts = %+v; want {Pass:0,Fail:0,Warn:2}", log)
	}
}
