package checks

import "testing"

func TestParseVersion(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantOK    bool
		wantMajor int
		wantMinor int
		wantPatch int
	}{
		// Standard semver
		{"basic", "15.2.3", true, 15, 2, 3},
		{"with v prefix", "v15.2.3", true, 15, 2, 3},
		{"minor only", "14.2", true, 14, 2, 0},
		{"zero patch", "15.0.0", true, 15, 0, 0},

		// Prerelease / build metadata — stripped from patch
		{"prerelease canary", "15.2.0-canary.1", true, 15, 2, 0},
		{"prerelease rc", "14.2.25-rc.1", true, 14, 2, 25},
		{"build metadata", "14.2.25+sha.abc", true, 14, 2, 25},

		// Empty patch after strip is allowed (edge case: "1.2.-canary")
		{"empty patch after strip", "1.2.-canary", true, 1, 2, 0},

		// Malformed — must reject rather than silently return patch=0
		{"four parts", "1.2.3.4", false, 0, 0, 0},
		{"non-numeric patch", "14.2.x", false, 0, 0, 0},
		{"non-numeric major", "latest", false, 0, 0, 0},
		{"non-numeric minor", "15.x", false, 0, 0, 0},
		{"empty", "", false, 0, 0, 0},
		{"single part", "15", false, 0, 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			major, minor, patch, ok := parseVersion(tc.input)
			if ok != tc.wantOK {
				t.Fatalf("parseVersion(%q) ok = %v; want %v", tc.input, ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if major != tc.wantMajor || minor != tc.wantMinor || patch != tc.wantPatch {
				t.Errorf("parseVersion(%q) = (%d.%d.%d); want (%d.%d.%d)",
					tc.input, major, minor, patch, tc.wantMajor, tc.wantMinor, tc.wantPatch)
			}
		})
	}
}

func TestSafeParseInt(t *testing.T) {
	cases := []struct {
		input  string
		wantN  int
		wantOK bool
	}{
		{"0", 0, true},
		{"1", 1, true},
		{"15", 15, true},
		{"100", 100, true},
		{"", 0, false},
		{"abc", 0, false},
		{"-1", 0, false},   // no sign support
		{"1.5", 0, false},  // no decimal
		{" 5", 0, false},   // no whitespace
		{"12a3", 0, false}, // trailing garbage
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			n, ok := safeParseInt(tc.input)
			if ok != tc.wantOK {
				t.Errorf("safeParseInt(%q) ok = %v; want %v", tc.input, ok, tc.wantOK)
			}
			if ok && n != tc.wantN {
				t.Errorf("safeParseInt(%q) = %d; want %d", tc.input, n, tc.wantN)
			}
		})
	}
}

// TestCVE_2025_29927 covers the middleware-bypass patch matrix:
// patched in 14.2.25 and 15.2.3; no versions <12 affected.
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
		got := cve.IsVulnerable(tc.maj, tc.min, tc.pat)
		if got != tc.want {
			t.Errorf("IsVulnerable(%d.%d.%d) = %v; want %v", tc.maj, tc.min, tc.pat, got, tc.want)
		}
	}
}

// TestCVE_2025_55182 covers the per-minor React Server Components patch matrix.
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
		got := cve.IsVulnerable(tc.maj, tc.min, tc.pat)
		if got != tc.want {
			t.Errorf("IsVulnerable(%d.%d.%d) = %v; want %v", tc.maj, tc.min, tc.pat, got, tc.want)
		}
	}
}

func findCVE(t *testing.T, id string) nextjsCVE {
	t.Helper()
	for _, c := range nextjsCVEs {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("CVE %q not found in nextjsCVEs", id)
	return nextjsCVE{}
}
