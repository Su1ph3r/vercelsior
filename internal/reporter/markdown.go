package reporter

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/Su1ph3r/vercelsior/internal/models"
)

// utf8SafeTruncate cuts s to at most maxBytes while preserving valid UTF-8.
// A naive byte slice can split a multi-byte rune, producing invalid UTF-8
// that corrupts downstream rendering (browsers substitute U+FFFD).
func utf8SafeTruncate(s string, maxBytes int) string {
	if maxBytes < 0 || len(s) <= maxBytes {
		return s
	}
	trimmed := s[:maxBytes]
	for len(trimmed) > 0 && !utf8.ValidString(trimmed) {
		trimmed = trimmed[:len(trimmed)-1]
	}
	return trimmed
}

func WriteMarkdown(result *models.ScanResult, path string) error {
	var b strings.Builder

	b.WriteString("# Vercelsior Security Audit Report\n\n")
	b.WriteString(fmt.Sprintf("**Scan ID:** %s  \n", result.ScanID))
	b.WriteString(fmt.Sprintf("**Account:** %s (%s)  \n", result.AccountName, result.AccountID))
	if result.TeamName != "" {
		b.WriteString(fmt.Sprintf("**Team:** %s (%s)  \n", result.TeamName, result.TeamID))
	}
	b.WriteString(fmt.Sprintf("**Started:** %s  \n", result.StartedAt.Format("2006-01-02 15:04:05 UTC")))
	b.WriteString(fmt.Sprintf("**Completed:** %s  \n\n", result.CompletedAt.Format("2006-01-02 15:04:05 UTC")))

	// Summary
	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Count |\n")
	b.WriteString("|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| Total Checks | %d |\n", result.Summary.Total))
	b.WriteString(fmt.Sprintf("| Passed | %d |\n", result.Summary.Passed))
	b.WriteString(fmt.Sprintf("| Failed | %d |\n", result.Summary.Failed))
	b.WriteString(fmt.Sprintf("| Warnings | %d |\n", result.Summary.Warnings))
	b.WriteString(fmt.Sprintf("| Errors | %d |\n", result.Summary.Errors))
	b.WriteString(fmt.Sprintf("| **Posture Score** | **%.1f / 100** |\n\n", result.Summary.PostureScore))

	// Severity breakdown
	if len(result.Summary.SeverityCounts) > 0 {
		b.WriteString("### Severity Breakdown (Failures + Warnings)\n\n")
		b.WriteString("| Severity | Count |\n")
		b.WriteString("|----------|-------|\n")
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if count, ok := result.Summary.SeverityCounts[sev]; ok && count > 0 {
				b.WriteString(fmt.Sprintf("| %s | %d |\n", sev, count))
			}
		}
		b.WriteString("\n")
	}

	// Category breakdown
	if len(result.Summary.CategoryCounts) > 0 {
		b.WriteString("### Category Breakdown\n\n")
		b.WriteString("| Category | Pass | Fail | Warn |\n")
		b.WriteString("|----------|------|------|------|\n")
		for cat, cc := range result.Summary.CategoryCounts {
			b.WriteString(fmt.Sprintf("| %s | %d | %d | %d |\n", cat, cc.Pass, cc.Fail, cc.Warn))
		}
		b.WriteString("\n")
	}

	// Findings by category
	b.WriteString("## Findings\n\n")

	categories := groupByCategory(result.Findings)
	for _, cat := range sortedCategories(categories) {
		findings := categories[cat]
		b.WriteString(fmt.Sprintf("### %s\n\n", cat))

		for _, f := range findings {
			icon := statusIcon(f.Status)
			b.WriteString(fmt.Sprintf("#### %s [%s] %s\n\n", icon, f.Severity, f.Title))
			b.WriteString(fmt.Sprintf("- **Check ID:** %s\n", f.CheckID))
			b.WriteString(fmt.Sprintf("- **Status:** %s\n", f.Status))
			if f.RiskScore > 0 {
				b.WriteString(fmt.Sprintf("- **Risk Score:** %.1f / 10 (%s)\n", f.RiskScore, models.RiskRating(f.RiskScore)))
			}
			if f.Rationale != "" {
				b.WriteString(fmt.Sprintf("- **Why this score:** %s\n", f.Rationale))
			}
			b.WriteString(fmt.Sprintf("- **Resource:** %s (`%s`)\n", f.ResourceName, f.ResourceID))
			b.WriteString(fmt.Sprintf("- **Description:** %s\n", f.Description))
			if f.Remediation != "" {
				b.WriteString(fmt.Sprintf("- **Remediation:** %s\n", f.Remediation))
			}
			if len(f.Details) > 0 {
				b.WriteString("- **Details:**\n")
				for k, v := range f.Details {
					b.WriteString(fmt.Sprintf("  - %s: %s\n", k, v))
				}
			}
			if f.PocVerification != "" {
				b.WriteString(fmt.Sprintf("- **Verification:** `%s`\n", f.PocVerification))
			}
			if len(f.PocEvidence) > 0 {
				b.WriteString("- **Evidence:**\n")
				for _, poc := range f.PocEvidence {
					b.WriteString(fmt.Sprintf("  - Request: `%s %s`\n", poc.Request.Method, poc.Request.URL))
					b.WriteString(fmt.Sprintf("  - Response: %d\n", poc.Response.StatusCode))
					if len(poc.Response.Body) > 500 {
						b.WriteString(fmt.Sprintf("  ```json\n  %s...\n  ```\n", utf8SafeTruncate(poc.Response.Body, 500)))
					} else if poc.Response.Body != "" {
						b.WriteString(fmt.Sprintf("  ```json\n  %s\n  ```\n", poc.Response.Body))
					}
				}
			}
			if len(f.RemediationCommands) > 0 {
				b.WriteString("- **Fix Commands:**\n")
				for _, cmd := range f.RemediationCommands {
					b.WriteString(fmt.Sprintf("  - [%s] %s: `%s`\n", cmd.Type, cmd.Description, cmd.Command))
				}
			}
			if len(f.RemediationResources) > 0 {
				b.WriteString("- **References:**\n")
				for _, res := range f.RemediationResources {
					b.WriteString(fmt.Sprintf("  - [%s](%s) (%s)\n", res.Title, res.URL, res.Type))
				}
			}
			b.WriteString("\n")
		}
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func statusIcon(s models.Status) string {
	switch s {
	case models.Fail:
		return "FAIL"
	case models.Warn:
		return "WARN"
	case models.Pass:
		return "PASS"
	case models.Error:
		return "ERROR"
	default:
		return "?"
	}
}

func groupByCategory(findings []models.Finding) map[string][]models.Finding {
	cats := make(map[string][]models.Finding)
	for _, f := range findings {
		cats[f.Category] = append(cats[f.Category], f)
	}
	return cats
}

func sortedCategories(cats map[string][]models.Finding) []string {
	keys := make([]string, 0, len(cats))
	for k := range cats {
		keys = append(keys, k)
	}
	// Sort alphabetically
	for i := 0; i < len(keys)-1; i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
