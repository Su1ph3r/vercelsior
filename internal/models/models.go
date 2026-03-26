package models

import "time"

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 0
	case High:
		return 1
	case Medium:
		return 2
	case Low:
		return 3
	case Info:
		return 4
	default:
		return 5
	}
}

type Status string

const (
	Pass  Status = "PASS"
	Fail  Status = "FAIL"
	Warn  Status = "WARN"
	Error Status = "ERROR"
)

type RemediationCommand struct {
	Type        string `json:"type"`        // "cli", "api", "console"
	Command     string `json:"command"`     // the actual command
	Description string `json:"description"` // what it does
}

type RemediationResource struct {
	Title string `json:"title"`
	URL   string `json:"url"`
	Type  string `json:"type"` // "documentation", "blog", "guide"
}

type PocRequest struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	// Headers omitted intentionally (contains auth token)
}

type PocResponse struct {
	StatusCode int    `json:"status_code"`
	Body       string `json:"body"` // truncated to 2000 chars
}

type PocEvidence struct {
	Request  PocRequest  `json:"request"`
	Response PocResponse `json:"response"`
	Summary  string      `json:"summary"` // human-readable one-liner of what this proves
}

type Finding struct {
	CheckID                string                `json:"check_id"`
	Title                  string                `json:"title"`
	Category               string                `json:"category"`
	Severity               Severity              `json:"severity"`
	Status                 Status                `json:"status"`
	RiskScore              float64               `json:"risk_score"`
	Rationale              string                `json:"rationale"`
	Description            string                `json:"description"`
	ResourceType           string                `json:"resource_type"`
	ResourceID             string                `json:"resource_id"`
	ResourceName           string                `json:"resource_name"`
	Remediation            string                `json:"remediation"`
	Details                map[string]string     `json:"details,omitempty"`
	PocEvidence            []PocEvidence         `json:"poc_evidence,omitempty"`
	PocVerification        string                `json:"poc_verification,omitempty"`
	RemediationCommands    []RemediationCommand  `json:"remediation_commands,omitempty"`
	RemediationResources   []RemediationResource `json:"remediation_resources,omitempty"`
}

// RiskRating returns the human-readable rating for a risk score.
func RiskRating(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score >= 0.1:
		return "LOW"
	default:
		return "INFO"
	}
}

type Summary struct {
	Total          int                      `json:"total"`
	Passed         int                      `json:"passed"`
	Failed         int                      `json:"failed"`
	Warnings       int                      `json:"warnings"`
	Errors         int                      `json:"errors"`
	PostureScore   float64                  `json:"posture_score"`
	MaxRisk        float64                  `json:"max_risk"`
	ActualRisk     float64                  `json:"actual_risk"`
	SeverityCounts map[string]int           `json:"severity_counts"`
	CategoryCounts map[string]CategoryCount `json:"category_counts"`
}

type CategoryCount struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Warn int `json:"warn"`
}

type ScanResult struct {
	ScanID      string    `json:"scan_id"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	AccountID   string    `json:"account_id"`
	AccountName string    `json:"account_name"`
	TeamID      string    `json:"team_id"`
	TeamName    string    `json:"team_name"`
	Summary     Summary   `json:"summary"`
	Findings    []Finding `json:"findings"`
}

func (r *ScanResult) Compute() {
	r.CompletedAt = time.Now().UTC()
	r.Summary = Summary{
		Total:          len(r.Findings),
		SeverityCounts: make(map[string]int),
		CategoryCounts: make(map[string]CategoryCount),
	}

	var maxRisk, actualRisk float64

	for _, f := range r.Findings {
		switch f.Status {
		case Pass:
			r.Summary.Passed++
		case Fail:
			r.Summary.Failed++
		case Warn:
			r.Summary.Warnings++
		case Error:
			r.Summary.Errors++
		}
		if f.Status == Fail || f.Status == Warn {
			r.Summary.SeverityCounts[string(f.Severity)]++
		}
		cc := r.Summary.CategoryCounts[f.Category]
		switch f.Status {
		case Pass:
			cc.Pass++
		case Fail:
			cc.Fail++
		case Warn:
			cc.Warn++
		}
		r.Summary.CategoryCounts[f.Category] = cc

		// Posture score: every check has a max risk of 10.
		// FAIL contributes full risk score, WARN contributes half.
		maxRisk += 10.0
		switch f.Status {
		case Fail:
			actualRisk += f.RiskScore
		case Warn:
			actualRisk += f.RiskScore * 0.5
		}
	}

	r.Summary.MaxRisk = maxRisk
	r.Summary.ActualRisk = actualRisk
	if maxRisk > 0 {
		r.Summary.PostureScore = 100.0 * (1.0 - actualRisk/maxRisk)
		if r.Summary.PostureScore < 0 {
			r.Summary.PostureScore = 0
		}
	} else {
		r.Summary.PostureScore = 100
	}
}
