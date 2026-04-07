package checks

import (
	"fmt"
	"strings"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catHeaders = "Security Headers"

type HeaderChecks struct{}

func (hc *HeaderChecks) Name() string     { return "Headers" }
func (hc *HeaderChecks) Category() string { return catHeaders }

func (hc *HeaderChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	if !c.LiveProbe {
		return findings
	}

	projects, err := c.ListProjects()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"hdr-001", "Header Check — Insufficient Permissions", catHeaders,
				"Cannot list projects: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "hdr-001", Title: "Header Check Failed", Category: catHeaders,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list projects: %v", err),
				ResourceType: "project", ResourceID: "N/A",
			})
		}
		return findings
	}

	for _, proj := range projects {
		projectID := str(proj["id"])
		projectName := str(proj["name"])
		if projectID == "" {
			continue
		}

		domain := hc.pickProductionDomain(c, projectID)
		if domain == "" {
			continue
		}

		headers, err := c.ProbeHeaders("https://" + domain)
		if err != nil {
			// Skip domains that fail to probe
			continue
		}

		resType := "domain"
		resID := domain
		resName := fmt.Sprintf("%s (%s)", domain, projectName)

		// hdr-001: Content-Security-Policy
		if _, ok := headers["content-security-policy"]; !ok {
			findings = append(findings, fail(
				"hdr-001", "Missing Content-Security-Policy", catHeaders, models.High,
				7.0, "CSP is the primary defense against XSS. Without it, injected scripts execute freely in the browser.",
				fmt.Sprintf("Domain '%s' does not return a Content-Security-Policy header.", domain),
				resType, resID, resName,
				"Add a Content-Security-Policy header via vercel.json headers configuration.",
				nil,
			))
		} else {
			findings = append(findings, pass(
				"hdr-001", "Content-Security-Policy Present", catHeaders,
				fmt.Sprintf("Domain '%s' returns a Content-Security-Policy header.", domain),
				resType, resID, resName,
			))
		}

		// hdr-002: Strict-Transport-Security
		if _, ok := headers["strict-transport-security"]; !ok {
			findings = append(findings, fail(
				"hdr-002", "Missing Strict-Transport-Security", catHeaders, models.Medium,
				6.0, "Without HSTS, users on custom domains can be downgraded to HTTP via man-in-the-middle attacks.",
				fmt.Sprintf("Domain '%s' does not return a Strict-Transport-Security header.", domain),
				resType, resID, resName,
				"Add Strict-Transport-Security header with a long max-age (e.g., 31536000).",
				nil,
			))
		} else {
			findings = append(findings, pass(
				"hdr-002", "Strict-Transport-Security Present", catHeaders,
				fmt.Sprintf("Domain '%s' returns a Strict-Transport-Security header.", domain),
				resType, resID, resName,
			))
		}

		// hdr-003: X-Frame-Options or CSP frame-ancestors
		_, hasXFO := headers["x-frame-options"]
		hasFrameAncestors := false
		if csp, ok := headers["content-security-policy"]; ok {
			hasFrameAncestors = strings.Contains(strings.ToLower(csp), "frame-ancestors")
		}
		if !hasXFO && !hasFrameAncestors {
			findings = append(findings, warn(
				"hdr-003", "Missing X-Frame-Options", catHeaders, models.Medium,
				6.0, "Without clickjacking protection, attackers can embed your app in an iframe to steal user interactions.",
				fmt.Sprintf("Domain '%s' has no X-Frame-Options header and no CSP frame-ancestors directive.", domain),
				resType, resID, resName,
				"Add X-Frame-Options: DENY or use CSP frame-ancestors directive.",
				nil,
			))
		} else {
			findings = append(findings, pass(
				"hdr-003", "Clickjacking Protection Present", catHeaders,
				fmt.Sprintf("Domain '%s' has clickjacking protection.", domain),
				resType, resID, resName,
			))
		}

		// hdr-004: X-Content-Type-Options
		if _, ok := headers["x-content-type-options"]; !ok {
			findings = append(findings, warn(
				"hdr-004", "Missing X-Content-Type-Options", catHeaders, models.Medium,
				4.0, "MIME-sniffing can cause browsers to interpret uploaded content as executable scripts.",
				fmt.Sprintf("Domain '%s' does not return an X-Content-Type-Options header.", domain),
				resType, resID, resName,
				"Add X-Content-Type-Options: nosniff header.",
				nil,
			))
		} else {
			findings = append(findings, pass(
				"hdr-004", "X-Content-Type-Options Present", catHeaders,
				fmt.Sprintf("Domain '%s' returns X-Content-Type-Options header.", domain),
				resType, resID, resName,
			))
		}

		// hdr-005: Referrer-Policy
		if _, ok := headers["referrer-policy"]; !ok {
			findings = append(findings, warn(
				"hdr-005", "Missing Referrer-Policy", catHeaders, models.Low,
				3.0, "Without Referrer-Policy, full URLs including tokens in query params leak to third-party origins via the Referer header.",
				fmt.Sprintf("Domain '%s' does not return a Referrer-Policy header.", domain),
				resType, resID, resName,
				"Add Referrer-Policy: strict-origin-when-cross-origin header.",
				nil,
			))
		} else {
			findings = append(findings, pass(
				"hdr-005", "Referrer-Policy Present", catHeaders,
				fmt.Sprintf("Domain '%s' returns a Referrer-Policy header.", domain),
				resType, resID, resName,
			))
		}

		// hdr-006: Permissions-Policy
		if _, ok := headers["permissions-policy"]; !ok {
			findings = append(findings, warn(
				"hdr-006", "Missing Permissions-Policy", catHeaders, models.Low,
				3.0, "Without Permissions-Policy, embedded iframes and third-party scripts can access device APIs like camera and microphone.",
				fmt.Sprintf("Domain '%s' does not return a Permissions-Policy header.", domain),
				resType, resID, resName,
				"Add a Permissions-Policy header to restrict access to sensitive browser APIs.",
				nil,
			))
		} else {
			findings = append(findings, pass(
				"hdr-006", "Permissions-Policy Present", catHeaders,
				fmt.Sprintf("Domain '%s' returns a Permissions-Policy header.", domain),
				resType, resID, resName,
			))
		}
	}

	return findings
}

// pickProductionDomain returns the first production domain for a project,
// or falls back to the first domain available.
func (hc *HeaderChecks) pickProductionDomain(c *client.Client, projectID string) string {
	domains, err := c.ListProjectDomains(projectID)
	if err != nil || len(domains) == 0 {
		return ""
	}

	// Prefer a production domain (one without a git branch configured)
	for _, d := range domains {
		name := str(d["name"])
		if name == "" {
			continue
		}
		branch := str(d["gitBranch"])
		if branch == "" {
			return name
		}
	}

	// Fall back to the first domain
	return str(domains[0]["name"])
}
