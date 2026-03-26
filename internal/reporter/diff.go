package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/su1ph/vercelsior/internal/models"
)

type DiffResult struct {
	NewFindings      []models.Finding `json:"new_findings"`
	ResolvedFindings []models.Finding `json:"resolved_findings"`
	TotalNew         int              `json:"total_new"`
	TotalResolved    int              `json:"total_resolved"`
	PreviousScanID   string           `json:"previous_scan_id"`
	CurrentScanID    string           `json:"current_scan_id"`
	PostureChange    float64          `json:"posture_change"`
}

func CompareScanResults(current *models.ScanResult, previousPath string) (*DiffResult, error) {
	prevData, err := os.ReadFile(previousPath)
	if err != nil {
		return nil, fmt.Errorf("reading previous report: %w", err)
	}

	var previous models.ScanResult
	if err := json.Unmarshal(prevData, &previous); err != nil {
		return nil, fmt.Errorf("parsing previous report: %w", err)
	}

	diff := &DiffResult{
		PreviousScanID: previous.ScanID,
		CurrentScanID:  current.ScanID,
		PostureChange:  current.Summary.PostureScore - previous.Summary.PostureScore,
	}

	// Build lookup maps using composite key: checkID + resourceID
	prevMap := make(map[string]models.Finding)
	for _, f := range previous.Findings {
		if f.Status == models.Fail || f.Status == models.Warn {
			key := f.CheckID + "|" + f.ResourceID
			prevMap[key] = f
		}
	}

	currMap := make(map[string]models.Finding)
	for _, f := range current.Findings {
		if f.Status == models.Fail || f.Status == models.Warn {
			key := f.CheckID + "|" + f.ResourceID
			currMap[key] = f
		}
	}

	// New findings: in current but not in previous
	for key, f := range currMap {
		if _, existed := prevMap[key]; !existed {
			diff.NewFindings = append(diff.NewFindings, f)
		}
	}

	// Resolved findings: in previous but not in current
	for key, f := range prevMap {
		if _, exists := currMap[key]; !exists {
			diff.ResolvedFindings = append(diff.ResolvedFindings, f)
		}
	}

	diff.TotalNew = len(diff.NewFindings)
	diff.TotalResolved = len(diff.ResolvedFindings)

	return diff, nil
}

func WriteDiffMarkdown(diff *DiffResult, path string) error {
	var b strings.Builder

	b.WriteString("# Vercelsior Scan Diff\n\n")
	b.WriteString(fmt.Sprintf("**Previous Scan:** %s\n", diff.PreviousScanID))
	b.WriteString(fmt.Sprintf("**Current Scan:** %s\n", diff.CurrentScanID))

	changeIcon := "+"
	if diff.PostureChange < 0 {
		changeIcon = ""
	}
	b.WriteString(fmt.Sprintf("**Posture Change:** %s%.1f points\n\n", changeIcon, diff.PostureChange))

	b.WriteString(fmt.Sprintf("## Summary: %d new, %d resolved\n\n", diff.TotalNew, diff.TotalResolved))

	if len(diff.NewFindings) > 0 {
		b.WriteString("## New Findings\n\n")
		for _, f := range diff.NewFindings {
			b.WriteString(fmt.Sprintf("- **[%s]** %s — %s (score: %.1f)\n", f.Severity, f.CheckID, f.Title, f.RiskScore))
			b.WriteString(fmt.Sprintf("  - %s\n", f.Description))
		}
		b.WriteString("\n")
	}

	if len(diff.ResolvedFindings) > 0 {
		b.WriteString("## Resolved Findings\n\n")
		for _, f := range diff.ResolvedFindings {
			b.WriteString(fmt.Sprintf("- ~~[%s] %s — %s~~\n", f.Severity, f.CheckID, f.Title))
		}
		b.WriteString("\n")
	}

	if diff.TotalNew == 0 && diff.TotalResolved == 0 {
		b.WriteString("No changes detected between scans.\n")
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func WriteDiffJSON(diff *DiffResult, path string) error {
	data, err := json.MarshalIndent(diff, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
