package checks

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/models"
)

// utf8SafeTruncate returns s truncated to at most maxBytes bytes, cut on a
// valid UTF-8 rune boundary. If s is already within the limit it is returned
// unchanged. Handles invalid input by repeatedly trimming trailing bytes
// until the result is a valid UTF-8 string.
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

// Check is the interface all audit check modules must implement.
type Check interface {
	Name() string
	Category() string
	Run(c *client.Client) []models.Finding
}

// helper to create a PASS finding (risk score 0, no rationale needed)
func pass(checkID, title, category, desc, resType, resID, resName string) models.Finding {
	return models.Finding{
		CheckID:      checkID,
		Title:        title,
		Category:     category,
		Severity:     models.Info,
		Status:       models.Pass,
		RiskScore:    0,
		Description:  desc,
		ResourceType: resType,
		ResourceID:   resID,
		ResourceName: resName,
	}
}

// helper to create a FAIL finding with risk score and rationale
func fail(checkID, title, category string, sev models.Severity, riskScore float64, rationale, desc, resType, resID, resName, remediation string, details map[string]string) models.Finding {
	return models.Finding{
		CheckID:      checkID,
		Title:        title,
		Category:     category,
		Severity:     sev,
		Status:       models.Fail,
		RiskScore:    riskScore,
		Rationale:    rationale,
		Description:  desc,
		ResourceType: resType,
		ResourceID:   resID,
		ResourceName: resName,
		Remediation:  remediation,
		Details:      details,
	}
}

// helper to create a WARN finding with risk score and rationale
func warn(checkID, title, category string, sev models.Severity, riskScore float64, rationale, desc, resType, resID, resName, remediation string, details map[string]string) models.Finding {
	return models.Finding{
		CheckID:      checkID,
		Title:        title,
		Category:     category,
		Severity:     sev,
		Status:       models.Warn,
		RiskScore:    riskScore,
		Rationale:    rationale,
		Description:  desc,
		ResourceType: resType,
		ResourceID:   resID,
		ResourceName: resName,
		Remediation:  remediation,
		Details:      details,
	}
}

// buildEvidence creates a PocEvidence from the raw API data, extracting only specified fields.
// Fields that are absent from the data are included as null to prove their absence.
func buildEvidence(c *client.Client, apiPath string, rawItem map[string]interface{}, fields []string, summary string) models.PocEvidence {
	extracted := make(map[string]interface{})
	for _, field := range fields {
		if val, ok := rawItem[field]; ok {
			extracted[field] = val
		} else {
			extracted[field] = nil
		}
	}
	body, _ := json.MarshalIndent(extracted, "", "  ")

	return models.PocEvidence{
		Request: models.PocRequest{
			Method: "GET",
			URL:    "https://api.vercel.com" + apiPath,
		},
		Response: models.PocResponse{
			StatusCode: 200,
			Body:       string(body),
		},
		Summary: summary,
	}
}

// buildEvidenceRaw creates a PocEvidence from a pre-formatted body string.
func buildEvidenceRaw(apiPath string, statusCode int, body string, summary string) models.PocEvidence {
	return models.PocEvidence{
		Request: models.PocRequest{
			Method: "GET",
			URL:    "https://api.vercel.com" + apiPath,
		},
		Response: models.PocResponse{
			StatusCode: statusCode,
			Body:       body,
		},
		Summary: summary,
	}
}

func evidence(c *client.Client, path, summary string) []models.PocEvidence {
	ev := c.GetEvidence(path)
	if ev == nil {
		return nil
	}
	return []models.PocEvidence{{
		Request: models.PocRequest{
			Method: ev.Method,
			URL:    "https://api.vercel.com" + path,
		},
		Response: models.PocResponse{
			StatusCode: ev.StatusCode,
			Body:       ev.Body,
		},
		Summary: summary,
	}}
}

func str(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func num(v interface{}) float64 {
	if v == nil {
		return 0
	}
	if n, ok := v.(float64); ok {
		return n
	}
	return 0
}

func boolean(v interface{}) bool {
	if v == nil {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func mapVal(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

// IsPermissionDenied returns true if the error is a 403 permission denied error.
func IsPermissionDenied(err error) bool {
	return err != nil && errors.Is(err, client.ErrPermissionDenied)
}

// permissionFinding creates a standardized ERROR finding for 403 responses.
func permissionFinding(checkID, title, category, desc string) models.Finding {
	return models.Finding{
		CheckID:      checkID,
		Title:        title,
		Category:     category,
		Severity:     models.High,
		Status:       models.Error,
		Description:  desc,
		ResourceType: "permission",
		ResourceID:   "N/A",
		Remediation:  "Ensure your API token has the required scopes for this check. See Vercel API token documentation.",
	}
}

// apiErrorFinding creates a standardized INFO/ERROR finding for non-403 API
// errors. The caller should emit this in the `else` branch of every
// IsPermissionDenied check so transient 5xx/network failures are visible in
// the report instead of silently skipping the check. resourceType describes
// the object kind (e.g. "project"), resourceID/resourceName identify the
// specific instance if available ("N/A" is acceptable for global failures).
func apiErrorFinding(checkID, title, category, resourceType, resourceID, resourceName string, err error) models.Finding {
	return models.Finding{
		CheckID:      checkID,
		Title:        title,
		Category:     category,
		Severity:     models.Info,
		Status:       models.Error,
		Description:  fmt.Sprintf("%s: %v", title, err),
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ResourceName: resourceName,
	}
}
