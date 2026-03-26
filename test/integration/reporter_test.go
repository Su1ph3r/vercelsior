package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/su1ph/vercelsior/internal/models"
	"github.com/su1ph/vercelsior/internal/reporter"
)

func runReportScan(t *testing.T) *models.ScanResult {
	t.Helper()
	_, c := setupFixtures(t)
	return runScan(t, c, nil)
}

func TestJSONReportStructure(t *testing.T) {
	result := runReportScan(t)
	outPath := filepath.Join(t.TempDir(), "report.json")

	if err := reporter.WriteJSON(result, outPath); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Check required top-level fields
	requiredFields := []string{"scan_id", "started_at", "completed_at", "summary", "findings"}
	for _, field := range requiredFields {
		if _, ok := parsed[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	// Check summary structure
	summary, ok := parsed["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("summary is not an object")
	}
	for _, f := range []string{"total", "passed", "failed", "warnings", "posture_score"} {
		if _, ok := summary[f]; !ok {
			t.Errorf("summary missing field: %s", f)
		}
	}

	// Check findings array
	findings, ok := parsed["findings"].([]interface{})
	if !ok {
		t.Fatal("findings is not an array")
	}
	if len(findings) == 0 {
		t.Error("expected findings, got 0")
	}

	// Check first finding has required fields
	if len(findings) > 0 {
		first, ok := findings[0].(map[string]interface{})
		if !ok {
			t.Fatal("finding is not an object")
		}
		findingFields := []string{"check_id", "title", "category", "severity", "status", "risk_score", "rationale", "description"}
		for _, f := range findingFields {
			if _, ok := first[f]; !ok {
				t.Errorf("finding missing field: %s", f)
			}
		}
	}
}

func TestMarkdownReportStructure(t *testing.T) {
	result := runReportScan(t)
	outPath := filepath.Join(t.TempDir(), "report.md")

	if err := reporter.WriteMarkdown(result, outPath); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	requiredSections := []string{
		"# Vercelsior Security Audit Report",
		"## Summary",
		"## Findings",
		"Posture Score",
		"Risk Score:",
		"Why this score:",
	}
	for _, section := range requiredSections {
		if !strings.Contains(content, section) {
			t.Errorf("markdown missing section: %s", section)
		}
	}
}

func TestHTMLReportStructure(t *testing.T) {
	result := runReportScan(t)
	outPath := filepath.Join(t.TempDir(), "report.html")

	if err := reporter.WriteHTML(result, outPath); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	requiredElements := []string{
		"<!DOCTYPE html>",
		"<title>Vercelsior Security Report</title>",
		"sior",       // part of the header branding
		"score-ring", // posture score ring section
		"finding",
		"rationale",
		"score-label",
	}
	for _, el := range requiredElements {
		if !strings.Contains(strings.ToLower(content), strings.ToLower(el)) {
			t.Errorf("HTML missing element: %s", el)
		}
	}

	// Verify it's not empty
	if len(content) < 1000 {
		t.Error("HTML report suspiciously small")
	}
}

func TestDiffReport(t *testing.T) {
	result := runReportScan(t)
	dir := t.TempDir()

	// Write "previous" scan
	prevPath := filepath.Join(dir, "previous.json")
	reporter.WriteJSON(result, prevPath)

	// Modify current scan to simulate a change
	result2 := runReportScan(t)
	result2.ScanID = "test-report-2"

	diff, err := reporter.CompareScanResults(result2, prevPath)
	if err != nil {
		t.Fatal(err)
	}

	// Same scan data = no changes
	if diff.TotalNew != 0 {
		t.Errorf("expected 0 new findings comparing identical scans, got %d", diff.TotalNew)
	}
	if diff.TotalResolved != 0 {
		t.Errorf("expected 0 resolved findings, got %d", diff.TotalResolved)
	}

	// Verify diff report generation
	diffMD := filepath.Join(dir, "diff.md")
	if err := reporter.WriteDiffMarkdown(diff, diffMD); err != nil {
		t.Fatal(err)
	}
	diffJSON := filepath.Join(dir, "diff.json")
	if err := reporter.WriteDiffJSON(diff, diffJSON); err != nil {
		t.Fatal(err)
	}

	// Verify files exist and are valid
	mdData, _ := os.ReadFile(diffMD)
	if !strings.Contains(string(mdData), "Vercelsior Scan Diff") {
		t.Error("diff markdown missing header")
	}

	jsonData, _ := os.ReadFile(diffJSON)
	var diffParsed map[string]interface{}
	if err := json.Unmarshal(jsonData, &diffParsed); err != nil {
		t.Errorf("diff JSON invalid: %v", err)
	}
}
