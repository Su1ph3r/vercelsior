package nextjs

import "testing"

func TestParseVersion(t *testing.T) {
	cases := []struct {
		name          string
		in            string
		maj, min, pat int
		ok            bool
	}{
		// Standard semver
		{"basic", "15.2.3", 15, 2, 3, true},
		{"v prefix", "v15.2.3", 15, 2, 3, true},
		{"minor only", "14.2", 14, 2, 0, true},
		{"zero patch", "15.0.0", 15, 0, 0, true},

		// npm range operators (project mode reads these from package.json)
		{"caret range", "^15.1.0", 15, 1, 0, true},
		{"tilde range", "~14.2.25", 14, 2, 25, true},
		{"gte", ">=13.0.0", 13, 0, 0, true},
		{"range -> lower bound", ">=14.0.0 <15.0.0", 14, 0, 0, true},

		// Prerelease / build metadata — stripped from patch
		{"prerelease canary", "15.2.0-canary.1", 15, 2, 0, true},
		{"prerelease rc", "14.2.25-rc.1", 14, 2, 25, true},
		{"build metadata", "14.2.25+sha.abc", 14, 2, 25, true},
		{"empty patch after strip", "1.2.-canary", 1, 2, 0, true},

		// Malformed / unpinnable — must reject (ok=false), never guess
		{"four parts", "1.2.3.4", 0, 0, 0, false},
		{"non-numeric patch", "14.2.x", 0, 0, 0, false},
		{"wildcard minor", "15.x", 0, 0, 0, false},
		{"tag latest", "latest", 0, 0, 0, false},
		{"star", "*", 0, 0, 0, false},
		{"empty", "", 0, 0, 0, false},
		{"single part", "15", 0, 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			maj, min, pat, ok := ParseVersion(tc.in)
			if ok != tc.ok {
				t.Fatalf("ParseVersion(%q) ok=%v; want %v", tc.in, ok, tc.ok)
			}
			if ok && (maj != tc.maj || min != tc.min || pat != tc.pat) {
				t.Errorf("ParseVersion(%q) = %d.%d.%d; want %d.%d.%d", tc.in, maj, min, pat, tc.maj, tc.min, tc.pat)
			}
		})
	}
}

func TestParseUint(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"0", 0, true},
		{"15", 15, true},
		{"100", 100, true},
		{"", 0, false},
		{"abc", 0, false},
		{"-1", 0, false},  // no sign support
		{"1.5", 0, false}, // no decimal
		{" 5", 0, false},  // no whitespace
		{"12a", 0, false}, // trailing garbage
	}
	for _, tc := range cases {
		n, ok := parseUint(tc.in)
		if ok != tc.ok {
			t.Errorf("parseUint(%q) ok=%v; want %v", tc.in, ok, tc.ok)
		}
		if ok && n != tc.want {
			t.Errorf("parseUint(%q) = %d; want %d", tc.in, n, tc.want)
		}
	}
}

func findCVE(t *testing.T, id string) CVE {
	t.Helper()
	for _, c := range CVEs {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("CVE %q not found in CVEs", id)
	return CVE{}
}

// TestCVE_2025_29927 — middleware bypass; patched 14.2.25 / 15.2.3; <12 unaffected.
func TestCVE_2025_29927(t *testing.T) {
	cve := findCVE(t, "CVE-2025-29927")
	cases := []struct {
		maj, min, pat int
		want          bool
	}{
		{11, 99, 99, false}, // middleware introduced in 12
		{12, 0, 0, true},
		{13, 5, 0, true},
		{14, 0, 0, true},
		{14, 2, 24, true},
		{14, 2, 25, false}, // patched
		{14, 2, 26, false},
		{15, 0, 0, true},
		{15, 2, 2, true},
		{15, 2, 3, false}, // patched
		{15, 3, 0, false},
		{16, 0, 0, false},
	}
	for _, tc := range cases {
		if got := cve.Vulnerable(tc.maj, tc.min, tc.pat); got != tc.want {
			t.Errorf("29927 %d.%d.%d = %v; want %v", tc.maj, tc.min, tc.pat, got, tc.want)
		}
	}
}

// TestCVE_2025_55182 — RSC deserialization; per-minor patch matrix.
func TestCVE_2025_55182(t *testing.T) {
	cve := findCVE(t, "CVE-2025-55182")
	cases := []struct {
		maj, min, pat int
		want          bool
	}{
		{13, 5, 0, false}, // pre-14, React <19
		{14, 2, 34, true},
		{14, 2, 35, false}, // patched
		{15, 0, 3, false},  // below vulnerable window (starts at 15.0.4)
		{15, 0, 4, true},
		{15, 0, 6, true},
		{15, 0, 7, false}, // patched
		{15, 1, 10, true},
		{15, 1, 11, false}, // patched
		{15, 2, 7, true},
		{15, 2, 8, false}, // patched
		{15, 5, 8, true},
		{15, 5, 9, false}, // patched
		{16, 0, 9, true},
		{16, 0, 10, false}, // patched
		{17, 0, 0, false},  // not yet in matrix
	}
	for _, tc := range cases {
		if got := cve.Vulnerable(tc.maj, tc.min, tc.pat); got != tc.want {
			t.Errorf("55182 %d.%d.%d = %v; want %v", tc.maj, tc.min, tc.pat, got, tc.want)
		}
	}
}

// TestCVE_2025_49826 — ISR cache poisoning; affects 15.1.0–15.1.7.
func TestCVE_2025_49826(t *testing.T) {
	cve := findCVE(t, "CVE-2025-49826")
	cases := []struct {
		maj, min, pat int
		want          bool
	}{
		{15, 0, 9, false},
		{15, 1, 0, true},
		{15, 1, 7, true},
		{15, 1, 8, false}, // patched
		{15, 2, 0, false},
		{14, 2, 0, false},
	}
	for _, tc := range cases {
		if got := cve.Vulnerable(tc.maj, tc.min, tc.pat); got != tc.want {
			t.Errorf("49826 %d.%d.%d = %v; want %v", tc.maj, tc.min, tc.pat, got, tc.want)
		}
	}
}

// TestCVE_2025_59471_59472 — image/PPR DoS; patched 15.5.10 and 16.1.5.
func TestCVE_2025_59471_59472(t *testing.T) {
	for _, id := range []string{"CVE-2025-59471", "CVE-2025-59472"} {
		cve := findCVE(t, id)
		cases := []struct {
			maj, min, pat int
			want          bool
		}{
			{15, 4, 0, true},
			{15, 5, 9, true},
			{15, 5, 10, false}, // patched
			{16, 0, 0, true},
			{16, 1, 4, true},
			{16, 1, 5, false}, // patched
			{14, 2, 25, false},
			{17, 0, 0, false},
		}
		for _, tc := range cases {
			if got := cve.Vulnerable(tc.maj, tc.min, tc.pat); got != tc.want {
				t.Errorf("%s %d.%d.%d = %v; want %v", id, tc.maj, tc.min, tc.pat, got, tc.want)
			}
		}
	}
}

func TestMatch(t *testing.T) {
	// 14.2.0: vulnerable to 29927 (9.1) + 55182 (10.0) -> maxCVSS 10.0.
	ids, maxCVSS, ok := Match("14.2.0")
	if !ok {
		t.Fatal("expected ok for 14.2.0")
	}
	if !contains(ids, "CVE-2025-29927") || !contains(ids, "CVE-2025-55182") {
		t.Errorf("14.2.0 missing expected CVEs; got %v", ids)
	}
	if maxCVSS != 10.0 {
		t.Errorf("maxCVSS = %.1f; want 10.0", maxCVSS)
	}

	// 16.2.0: past every patch threshold -> no CVEs.
	ids, _, ok = Match("16.2.0")
	if !ok {
		t.Fatal("expected ok for 16.2.0")
	}
	if len(ids) != 0 {
		t.Errorf("16.2.0 should have no CVEs; got %v", ids)
	}

	// Range form is accepted (lower bound pinned).
	if ids, _, ok := Match("^14.2.0"); !ok || !contains(ids, "CVE-2025-29927") {
		t.Errorf("^14.2.0 should pin to 14.2.0 and match 29927; ok=%v ids=%v", ok, ids)
	}
}

func TestMatch_Unpinned(t *testing.T) {
	for _, v := range []string{"latest", "15.x", "*", ""} {
		if _, _, ok := Match(v); ok {
			t.Errorf("Match(%q) should report ok=false", v)
		}
	}
}

// TestCVEsTableIntegrity guards the shared matrix: every entry must be
// well-formed, IDs unique, CVSS in (0,10], and the known set present. This is
// the single source of truth consumed by both scan and project mode, so a
// malformed entry would silently degrade both.
func TestCVEsTableIntegrity(t *testing.T) {
	if len(CVEs) == 0 {
		t.Fatal("CVEs table is empty")
	}
	seen := map[string]bool{}
	for _, c := range CVEs {
		if c.ID == "" {
			t.Error("CVE with empty ID")
		}
		if seen[c.ID] {
			t.Errorf("duplicate CVE ID %q", c.ID)
		}
		seen[c.ID] = true
		if c.Description == "" {
			t.Errorf("%s: empty description", c.ID)
		}
		if c.CVSS <= 0 || c.CVSS > 10 {
			t.Errorf("%s: CVSS %.1f out of (0,10]", c.ID, c.CVSS)
		}
		if c.Vulnerable == nil {
			t.Errorf("%s: nil Vulnerable predicate", c.ID)
		}
	}
	for _, want := range []string{
		"CVE-2025-29927", "CVE-2025-55182", "CVE-2025-49826",
		"CVE-2025-59471", "CVE-2025-59472",
	} {
		if !seen[want] {
			t.Errorf("expected CVE %q missing from table", want)
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
