package checks

import (
	"fmt"
	"time"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catIntegrations = "Integrations"

type IntegrationChecks struct{}

func (ic *IntegrationChecks) Name() string     { return "Integrations" }
func (ic *IntegrationChecks) Category() string { return catIntegrations }

func (ic *IntegrationChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	integrations, err := c.ListIntegrations()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"int-001", "Integration Check — Insufficient Permissions", catIntegrations,
				"Cannot list integrations: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "int-001", Title: "Integration Check Failed", Category: catIntegrations,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list integrations: %v", err),
				ResourceType: "integration", ResourceID: "N/A",
			})
		}
		return findings
	}

	if len(integrations) == 0 {
		findings = append(findings, pass(
			"int-001", "No Third-Party Integrations", catIntegrations,
			"No third-party integrations are installed.",
			"integration", "N/A", "N/A",
		))
		return findings
	}

	now := time.Now()

	for _, integ := range integrations {
		integID := str(integ["id"])
		integSlug := str(integ["slug"])
		if integSlug == "" {
			integSlug = integID
		}

		// Check: integration scope/permissions
		scopes := integ["scopes"]
		if scopeArr, ok := scopes.([]interface{}); ok {
			hasWriteScope := false
			hasDeployScope := false
			for _, s := range scopeArr {
				scope := str(s)
				if scope == "write" || scope == "admin" {
					hasWriteScope = true
				}
				if scope == "deployment" || scope == "deploy" {
					hasDeployScope = true
				}
			}
			if hasWriteScope {
				findings = append(findings, warn(
					"int-002", "Integration With Write Access", catIntegrations, models.Medium,
					6.0, "Third-party integrations with write access can modify project configuration, environment variables, or deployments if compromised.",
					fmt.Sprintf("Integration '%s' has write access permissions.", integSlug),
					"integration", integID, integSlug,
					"Review whether write access is necessary. Apply least-privilege permissions.",
					nil,
				))
			}
			if hasDeployScope {
				findings = append(findings, warn(
					"int-003", "Integration With Deploy Access", catIntegrations, models.Medium,
					6.0, "Deploy access allows the integration to create deployments, potentially deploying malicious code if the integration is compromised.",
					fmt.Sprintf("Integration '%s' has deployment access permissions.", integSlug),
					"integration", integID, integSlug,
					"Review whether deployment access is necessary for this integration.",
					nil,
				))
			}
		}

		// Check: stale integrations (not updated in 180 days)
		if updatedAt := integ["updatedAt"]; updatedAt != nil && num(updatedAt) > 0 {
			lastUpdated := time.UnixMilli(int64(num(updatedAt)))
			daysSince := int(now.Sub(lastUpdated).Hours() / 24)
			if daysSince > 180 {
				findings = append(findings, warn(
					"int-004", "Stale Integration", catIntegrations, models.Low,
					3.0, "Unused integrations retain their access permissions indefinitely. A compromised stale integration is an unmonitored entry point.",
					fmt.Sprintf("Integration '%s' has not been updated in %d days.", integSlug, daysSince),
					"integration", integID, integSlug,
					"Review whether this integration is still needed. Remove unused integrations to reduce attack surface.",
					map[string]string{"days_since_update": fmt.Sprintf("%d", daysSince)},
				))
			}
		}

		// Check: integration disabled but still present
		if deletedAt := integ["deletedAt"]; deletedAt != nil {
			findings = append(findings, warn(
				"int-005", "Deleted Integration Still Listed", catIntegrations, models.Low,
				2.0, "Configuration remnant from a deleted integration. Low risk but indicates incomplete cleanup.",
				fmt.Sprintf("Integration '%s' appears to be deleted but is still listed.", integSlug),
				"integration", integID, integSlug,
				"Clean up deleted integration configurations.",
				nil,
			))
		}

		// Check: project scope (all projects vs specific)
		projectSelection := str(integ["projectSelection"])
		if projectSelection == "all" {
			findings = append(findings, warn(
				"int-006", "Integration Has Access to All Projects", catIntegrations, models.Medium,
				5.0, "An integration scoped to all projects means a compromise affects every project. Violates least-privilege principle.",
				fmt.Sprintf("Integration '%s' has access to all projects in the team/account.", integSlug),
				"integration", integID, integSlug,
				"Restrict integration access to specific projects that need it.",
				nil,
			))
		}
	}

	return findings
}
