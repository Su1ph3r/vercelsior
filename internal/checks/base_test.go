package checks

import (
	"errors"
	"strings"
	"testing"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/models"
)

func TestUtf8SafeTruncate(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		max      int
		want     string
		wantLen  int // expected byte length, -1 to skip
		wantLess bool
	}{
		{"ascii below limit", "hello", 10, "hello", 5, false},
		{"ascii at limit", "hello", 5, "hello", 5, false},
		{"ascii above limit", "helloworld", 5, "hello", 5, false},
		{"empty string", "", 10, "", 0, false},
		{"zero max", "hello", 0, "", 0, false},
		{"negative max", "hello", -1, "hello", 5, false},
		// "é" is 2 bytes (0xC3 0xA9). Truncating at byte 1 splits it.
		{"multi-byte cut mid-rune", "é", 1, "", 0, false},
		// Emoji "🔒" is 4 bytes. Cutting at byte 1/2/3 must trim back.
		{"emoji cut at 1 byte", "🔒", 1, "", 0, false},
		{"emoji cut at 2 bytes", "🔒", 2, "", 0, false},
		{"emoji cut at 3 bytes", "🔒", 3, "", 0, false},
		{"emoji at exact size", "🔒", 4, "🔒", 4, false},
		// Prefix ASCII + emoji — truncating mid-emoji preserves ASCII only.
		{"ascii+emoji cut mid-emoji", "hi🔒", 3, "hi", 2, false},
		// CJK: "漢" is 3 bytes.
		{"cjk cut mid-rune", "漢", 2, "", 0, false},
		{"cjk at exact size", "漢", 3, "漢", 3, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := utf8SafeTruncate(tc.input, tc.max)
			if got != tc.want {
				t.Errorf("utf8SafeTruncate(%q, %d) = %q; want %q", tc.input, tc.max, got, tc.want)
			}
			if tc.wantLen >= 0 && len(got) != tc.wantLen {
				t.Errorf("utf8SafeTruncate(%q, %d) len = %d; want %d", tc.input, tc.max, len(got), tc.wantLen)
			}
		})
	}
}

func TestApiErrorFindingShape(t *testing.T) {
	err := errors.New("boom")
	f := apiErrorFinding("test-001", "Test Failed", "Test Cat", "project", "prj_1", "my-proj", err)

	if f.CheckID != "test-001" {
		t.Errorf("CheckID = %q; want %q", f.CheckID, "test-001")
	}
	if f.Title != "Test Failed" {
		t.Errorf("Title = %q; want %q", f.Title, "Test Failed")
	}
	if f.Category != "Test Cat" {
		t.Errorf("Category = %q; want %q", f.Category, "Test Cat")
	}
	if f.Severity != models.Info {
		t.Errorf("Severity = %q; want Info", f.Severity)
	}
	if f.Status != models.Error {
		t.Errorf("Status = %q; want Error", f.Status)
	}
	if !strings.Contains(f.Description, "Test Failed") || !strings.Contains(f.Description, "boom") {
		t.Errorf("Description = %q; want title and err message", f.Description)
	}
	if f.ResourceType != "project" || f.ResourceID != "prj_1" || f.ResourceName != "my-proj" {
		t.Errorf("Resource fields = (%q,%q,%q); want (project,prj_1,my-proj)",
			f.ResourceType, f.ResourceID, f.ResourceName)
	}
}

func TestPermissionFindingShape(t *testing.T) {
	f := permissionFinding("iam-001", "IAM Denied", "IAM", "no scope")
	if f.CheckID != "iam-001" {
		t.Errorf("CheckID = %q; want iam-001", f.CheckID)
	}
	if f.Status != models.Error {
		t.Errorf("Status = %q; want Error", f.Status)
	}
	if f.Severity != models.High {
		t.Errorf("Severity = %q; want High", f.Severity)
	}
	if f.ResourceType != "permission" || f.ResourceID != "N/A" {
		t.Errorf("Resource fields = (%q,%q); want (permission,N/A)", f.ResourceType, f.ResourceID)
	}
	if f.Remediation == "" {
		t.Error("permissionFinding should include a non-empty Remediation")
	}
}

func TestIsPermissionDenied(t *testing.T) {
	wrapped := errors.Join(errors.New("context"), client.ErrPermissionDenied)
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"exact ErrPermissionDenied", client.ErrPermissionDenied, true},
		{"unrelated error", errors.New("other"), false},
		{"joined with ErrPermissionDenied", wrapped, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsPermissionDenied(tc.err)
			if got != tc.want {
				t.Errorf("IsPermissionDenied(%v) = %v; want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestStrHelper(t *testing.T) {
	cases := []struct {
		name  string
		input interface{}
		want  string
	}{
		{"nil", nil, ""},
		{"string", "hello", "hello"},
		{"empty string", "", ""},
		{"int", 42, ""},
		{"float64", 1.5, ""},
		{"bool", true, ""},
		{"map", map[string]interface{}{}, ""},
		{"slice", []interface{}{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := str(tc.input); got != tc.want {
				t.Errorf("str(%v) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNumHelper(t *testing.T) {
	cases := []struct {
		name  string
		input interface{}
		want  float64
	}{
		{"nil", nil, 0},
		{"float64", 1.5, 1.5},
		{"zero", 0.0, 0},
		{"negative", -2.0, -2.0},
		// JSON decode always gives float64; int/string inputs should be zero.
		{"int (unsupported)", 42, 0},
		{"string (unsupported)", "42", 0},
		{"bool", true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := num(tc.input); got != tc.want {
				t.Errorf("num(%v) = %v; want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestBooleanHelper(t *testing.T) {
	cases := []struct {
		name  string
		input interface{}
		want  bool
	}{
		{"nil", nil, false},
		{"true", true, true},
		{"false", false, false},
		{"string (unsupported)", "true", false},
		{"int", 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := boolean(tc.input); got != tc.want {
				t.Errorf("boolean(%v) = %v; want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestMapValHelper(t *testing.T) {
	m := map[string]interface{}{"key": "value"}
	cases := []struct {
		name   string
		input  interface{}
		wantOK bool
	}{
		{"nil", nil, false},
		{"map", m, true},
		{"slice", []interface{}{}, false},
		{"string", "not a map", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapVal(tc.input)
			if (got != nil) != tc.wantOK {
				t.Errorf("mapVal(%v) nilness = %v; wantOK = %v", tc.input, got == nil, tc.wantOK)
			}
		})
	}
}
