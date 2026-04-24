package reporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Su1ph3r/vercelsior/internal/models"
)

func TestUtf8SafeTruncate(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		max   int
		want  string
		bytes int
	}{
		{"ascii below", "hello", 10, "hello", 5},
		{"ascii above", "helloworld", 5, "hello", 5},
		{"multi-byte mid-cut", "é", 1, "", 0},
		{"emoji mid-cut", "🔒", 3, "", 0},
		{"negative treated as unlimited", "abc", -1, "abc", 3},
		{"empty", "", 5, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := utf8SafeTruncate(tc.in, tc.max)
			if got != tc.want {
				t.Errorf("utf8SafeTruncate(%q, %d) = %q; want %q", tc.in, tc.max, got, tc.want)
			}
			if len(got) != tc.bytes {
				t.Errorf("byte len = %d; want %d", len(got), tc.bytes)
			}
		})
	}
}

// TestWriteMarkdown_TruncatesLongBodiesSafely exercises the 500-byte cut in
// the PoC rendering path using a body that contains multi-byte characters
// right at the cutoff.
func TestWriteMarkdown_TruncatesLongBodiesSafely(t *testing.T) {
	// Build a body that ends exactly at byte 500 with a split multi-byte
	// rune if truncated naively. We use 498 ASCII bytes + "é" (2 bytes)
	// repeated so byte 500 lands in the middle of an "é" sequence.
	prefix := strings.Repeat("a", 498)
	body := prefix + "éé" // bytes 499+500 are the first and second byte of the first "é"

	result := &models.ScanResult{
		ScanID:      "test",
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
		Findings: []models.Finding{
			{
				CheckID:  "test-001",
				Title:    "Test",
				Category: "Test",
				Severity: models.Medium,
				Status:   models.Fail,
				PocEvidence: []models.PocEvidence{
					{Response: models.PocResponse{Body: body}},
				},
			},
		},
	}
	result.Compute()
	path := filepath.Join(t.TempDir(), "out.md")
	if err := WriteMarkdown(result, path); err != nil {
		t.Fatal(err)
	}

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The output file must be valid UTF-8 despite the aggressive truncation.
	if !isValidUTF8(out) {
		t.Error("markdown report contains invalid UTF-8 (truncation split a rune)")
	}
}

func isValidUTF8(b []byte) bool {
	// Trivially valid ASCII subset check would miss the bug. Use the
	// stdlib.
	for i, r := range string(b) {
		if r == '�' && b[i] != 0xEF { // replacement char is U+FFFD = EF BF BD
			return false
		}
	}
	return true
}

func TestSortedCategories(t *testing.T) {
	cats := map[string][]models.Finding{
		"Zebra":  nil,
		"Alpha":  nil,
		"Middle": nil,
	}
	sorted := sortedCategories(cats)
	want := []string{"Alpha", "Middle", "Zebra"}
	for i, w := range want {
		if sorted[i] != w {
			t.Errorf("sorted[%d] = %q; want %q", i, sorted[i], w)
		}
	}
}

func TestGroupByCategory(t *testing.T) {
	findings := []models.Finding{
		{CheckID: "a", Category: "c1"},
		{CheckID: "b", Category: "c2"},
		{CheckID: "c", Category: "c1"},
	}
	groups := groupByCategory(findings)
	if len(groups["c1"]) != 2 {
		t.Errorf("c1 group size = %d; want 2", len(groups["c1"]))
	}
	if len(groups["c2"]) != 1 {
		t.Errorf("c2 group size = %d; want 1", len(groups["c2"]))
	}
}

func TestStatusIcon(t *testing.T) {
	cases := []struct {
		status models.Status
		want   string
	}{
		{models.Pass, "PASS"},
		{models.Fail, "FAIL"},
		{models.Warn, "WARN"},
		{models.Error, "ERROR"},
		{models.Status("unknown"), "?"},
	}
	for _, tc := range cases {
		if got := statusIcon(tc.status); got != tc.want {
			t.Errorf("statusIcon(%q) = %q; want %q", tc.status, got, tc.want)
		}
	}
}
