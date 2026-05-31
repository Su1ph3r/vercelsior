package reporter

// SARIF 2.1.0 export — for GitHub Code Scanning and generic SAST/security
// tooling. SARIF (Static Analysis Results Interchange Format) is the OASIS
// standard for security-tool output. GitHub Code Scanning ingests SARIF
// directly via `github/codeql-action/upload-sarif@v3` and renders results in
// the repository's Security tab.
//
// Schema reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// GitHub accepted-subset: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Su1ph3r/vercelsior/internal/models"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	sarifToolURI = "https://github.com/Su1ph3r/vercelsior"
)

// sarifReportVersion is stamped into the tool driver. It is wired from the
// caller (main injects the build version) so SARIF consumers can attribute a
// result set to a specific Vercelsior build. Defaults to "dev" when unset.
var sarifReportVersion = "dev"

// SetSARIFVersion sets the tool version recorded in SARIF output. main() calls
// this once at startup with the build version so reports are attributable.
func SetSARIFVersion(v string) {
	if v != "" {
		sarifReportVersion = v
	}
}

// severityToLevel maps a Vercelsior severity to a SARIF level. SARIF defines
// only three levels (error, warning, note), so CRITICAL and HIGH both collapse
// to "error" and INFO collapses to "note".
func severityToLevel(s models.Severity) string {
	switch s {
	case models.Critical, models.High:
		return "error"
	case models.Medium:
		return "warning"
	default: // Low, Info, unknown
		return "note"
	}
}

// securitySeverity returns the 0-10 string GitHub Code Scanning uses to bucket
// and filter results. Vercelsior's per-finding RiskScore is already a 0-10
// value with a written rationale, so we surface it directly when present and
// fall back to a severity-derived bucket otherwise (e.g. PASS findings carry
// RiskScore 0 but never reach SARIF; ERROR findings may have no score).
func securitySeverity(f models.Finding) string {
	// ERROR findings (a check that could not run — permission denied,
	// unparseable config, all probes failed) carry RiskScore 0 / Info severity
	// but must not collapse to "0.0", which GitHub Code Scanning filters out of
	// the Security tab by default. Surface them in the medium bucket so an
	// operator sees that coverage was lost.
	if f.Status == models.Error {
		return "4.0"
	}
	if f.RiskScore > 0 {
		return fmt.Sprintf("%.1f", f.RiskScore)
	}
	switch f.Severity {
	case models.Critical:
		return "9.5"
	case models.High:
		return "8.0"
	case models.Medium:
		return "5.5"
	case models.Low:
		return "2.5"
	default:
		return "0.0"
	}
}

// SARIF document types. Only the subset GitHub Code Scanning consumes is
// modeled; omitempty keeps the output compact and schema-valid.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
	Props   map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifText       `json:"shortDescription"`
	FullDescription      sarifText       `json:"fullDescription"`
	Help                 sarifText       `json:"help"`
	HelpURI              string          `json:"helpUri,omitempty"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           sarifRuleProps  `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLoc     `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogicalLoc struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// BuildSARIF converts a scan result into a SARIF 2.1.0 log. Only actionable
// findings (FAIL and WARN) become results — PASS findings are excluded so the
// Security tab is not flooded with non-issues, matching how every other
// SARIF-emitting security scanner behaves. ERROR findings (permission denied,
// module panic) are surfaced as "note"-level results so an operator can still
// see that a check could not run.
func BuildSARIF(result *models.ScanResult) sarifLog {
	// Collect the findings worth reporting and assemble a deterministic,
	// deduplicated rule set keyed by CheckID. Rules carry the static metadata
	// (title, description, severity), results carry the per-resource instance.
	type ruleAgg struct {
		index   int
		finding models.Finding // representative finding for rule-level text
	}
	ruleIndex := make(map[string]*ruleAgg)
	var ruleOrder []string

	reportable := make([]models.Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		if f.Status != models.Fail && f.Status != models.Warn && f.Status != models.Error {
			continue
		}
		reportable = append(reportable, f)
		if _, ok := ruleIndex[f.CheckID]; !ok {
			ruleIndex[f.CheckID] = &ruleAgg{finding: f}
			ruleOrder = append(ruleOrder, f.CheckID)
		}
	}

	// Stable rule ordering: by CheckID so a clean diff between two SARIF files
	// reflects real changes, not map-iteration noise.
	sort.Strings(ruleOrder)
	rules := make([]sarifRule, 0, len(ruleOrder))
	for i, id := range ruleOrder {
		agg := ruleIndex[id]
		agg.index = i
		f := agg.finding
		help := f.Remediation
		if help == "" {
			help = f.Description
		}
		rules = append(rules, sarifRule{
			ID:               f.CheckID,
			Name:             sarifRuleName(f),
			ShortDescription: sarifText{Text: f.Title},
			FullDescription:  sarifText{Text: nonEmpty(f.Description, f.Title)},
			Help:             sarifText{Text: nonEmpty(help, f.Title)},
			HelpURI:          sarifToolURI,
			DefaultConfiguration: sarifRuleConfig{
				Level: severityToLevel(f.Severity),
			},
			Properties: sarifRuleProps{
				Tags:             []string{"security", "vercel", sarifTagSlug(f.Category)},
				SecuritySeverity: securitySeverity(f),
			},
		})
	}

	results := make([]sarifResult, 0, len(reportable))
	for _, f := range reportable {
		level := severityToLevel(f.Severity)
		if f.Status == models.Error {
			level = "note"
		}
		results = append(results, sarifResult{
			RuleID:              f.CheckID,
			RuleIndex:           ruleIndex[f.CheckID].index,
			Level:               level,
			Message:             sarifText{Text: sarifMessage(f)},
			Locations:           []sarifLocation{sarifLocationFor(f)},
			PartialFingerprints: map[string]string{"vercelsior/v1": fingerprint(f)},
			Properties: map[string]any{
				"severity":      string(f.Severity),
				"status":        string(f.Status),
				"risk_score":    f.RiskScore,
				"category":      f.Category,
				"resource_type": f.ResourceType,
				"resource_id":   f.ResourceID,
			},
		})
	}

	props := map[string]any{
		"posture_score": result.Summary.PostureScore,
		"scan_id":       result.ScanID,
	}
	if result.AccountName != "" {
		props["account"] = result.AccountName
	}
	if result.TeamName != "" {
		props["team"] = result.TeamName
	}

	return sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Vercelsior",
				Version:        sarifReportVersion,
				InformationURI: sarifToolURI,
				Rules:          rules,
			}},
			Results: results,
			Props:   props,
		}},
	}
}

// WriteSARIF serializes the scan result to a SARIF 2.1.0 file.
func WriteSARIF(result *models.ScanResult, path string) error {
	data, err := json.MarshalIndent(BuildSARIF(result), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// sarifMessage builds the per-result message. It leads with the title and
// appends the rationale (why the score) and resource so a reviewer reading the
// Security tab gets the full context without expanding the rule.
func sarifMessage(f models.Finding) string {
	var b strings.Builder
	b.WriteString(f.Title)
	if f.ResourceName != "" || f.ResourceID != "" {
		res := f.ResourceName
		if res == "" {
			res = f.ResourceID
		}
		fmt.Fprintf(&b, " — %s: %s", nonEmpty(f.ResourceType, "resource"), res)
	}
	if f.Status == models.Error {
		// ERROR findings already carry their reason in Description.
		if f.Description != "" {
			fmt.Fprintf(&b, " (%s)", f.Description)
		}
		return b.String()
	}
	if f.Rationale != "" {
		fmt.Fprintf(&b, ". %s", f.Rationale)
	}
	return b.String()
}

// sarifLocationFor synthesizes a location for a finding. Vercelsior findings
// describe live cloud/account configuration rather than a source file, so
// there is no real path on disk. GitHub Code Scanning nonetheless requires a
// physicalLocation with an artifact URI, so we mint a stable, human-readable
// synthetic URI of the form "vercel/<category>/<resource>" and attach a
// logicalLocation naming the actual resource. The synthetic URI is also what
// groups results under a readable path in the Security tab.
func sarifLocationFor(f models.Finding) sarifLocation {
	res := f.ResourceID
	if res == "" {
		res = f.ResourceName
	}
	if res == "" {
		res = "account"
	}
	uri := "vercel/" + sarifTagSlug(f.Category) + "/" + sarifPathSafe(res)
	loc := sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: uri},
			Region:           sarifRegion{StartLine: 1},
		},
	}
	name := f.ResourceName
	if name == "" {
		name = f.ResourceID
	}
	if name != "" {
		loc.LogicalLocations = []sarifLogicalLoc{{
			Name:               name,
			FullyQualifiedName: f.ResourceType + "/" + name,
			Kind:               "resource",
		}}
	}
	return loc
}

// fingerprint is the stable identity GitHub uses to track a result across
// scans (so a finding that persists is not re-reported as new, and a resolved
// one is marked fixed). It is derived from the check + the specific resource,
// not from volatile fields like the rationale text or risk score, so wording
// tweaks to a check don't churn the alert history.
func fingerprint(f models.Finding) string {
	sum := sha256.Sum256([]byte(f.CheckID + "\x00" + f.ResourceType + "\x00" + f.ResourceID))
	return fmt.Sprintf("%x", sum[:16])
}

// sarifRuleName produces a PascalCase-ish stable rule name from the check ID
// (e.g. "iam-001" -> "Iam001"). GitHub displays ruleId for the alert but uses
// name in some views; keeping it derived from the ID keeps it deterministic.
func sarifRuleName(f models.Finding) string {
	parts := strings.FieldsFunc(f.CheckID, func(r rune) bool { return r == '-' || r == '_' })
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]))
		if len(p) > 1 {
			b.WriteString(p[1:])
		}
	}
	if b.Len() == 0 {
		return f.CheckID
	}
	return b.String()
}

// sarifTagSlug lowercases a category into a slug usable as a tag and path
// segment (e.g. "Identity & Access Management" -> "identity-access-management").
func sarifTagSlug(category string) string {
	if category == "" {
		return "general"
	}
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(category) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteRune('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// sarifPathSafe makes a resource identifier safe to embed in a URI path
// segment without percent-encoding noise, while staying recognizable.
func sarifPathSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "resource"
	}
	return out
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
