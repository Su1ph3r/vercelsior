package checks

import (
	"fmt"
	"strings"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catFlags = "Feature Flags"

type FeatureFlagChecks struct{}

func (f *FeatureFlagChecks) Name() string     { return "Flags" }
func (f *FeatureFlagChecks) Category() string { return catFlags }

var sensitivePatterns = []string{
	"admin", "bypass", "debug", "internal", "kill-switch", "killswitch",
	"maintenance", "disable-auth", "skip-auth",
}

func (f *FeatureFlagChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		findings = append(findings, models.Finding{
			CheckID: "flag-001", Title: "Project Enumeration", Category: catFlags,
			Severity: models.Info, Status: models.Error,
			Description:  fmt.Sprintf("Failed to list projects: %v", err),
			ResourceType: "project", ResourceID: "N/A",
		})
		return findings
	}

	for _, p := range projects {
		projID := str(p["id"])
		projName := str(p["name"])

		flags, err := c.ListFeatureFlags(projID)
		if err != nil {
			findings = append(findings, models.Finding{
				CheckID: "flag-001", Title: "Feature Flag Enumeration", Category: catFlags,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list feature flags for project '%s': %v", projName, err),
				ResourceType: "project", ResourceID: projID, ResourceName: projName,
			})
			continue
		}

		for _, flag := range flags {
			flagName := str(flag["name"])
			flagKey := str(flag["key"])
			flagID := str(flag["id"])
			if flagID == "" {
				flagID = flagKey
			}
			displayName := flagName
			if displayName == "" {
				displayName = flagKey
			}

			// flag-001: Security-sensitive name check
			combined := strings.ToLower(flagName + " " + flagKey)
			for _, pattern := range sensitivePatterns {
				if strings.Contains(combined, pattern) {
					findings = append(findings, warn(
						"flag-001", "Feature Flag With Security-Sensitive Name", catFlags,
						models.Medium, 6.0,
						"Security-critical flags controlling admin mode, debug mode, or auth bypass can be toggled to weaken security posture if misconfigured.",
						fmt.Sprintf("Project '%s' has flag '%s' matching sensitive pattern '%s'.", projName, displayName, pattern),
						"feature-flag", flagID, displayName,
						"Review security-sensitive feature flags. Ensure they have proper access controls and monitoring.",
						map[string]string{"project": projName, "matched_pattern": pattern},
					))
					break
				}
			}

			// flag-002: Overrides in production
			overrides := flag["overrides"]
			hasOverrides := false
			if overrides != nil {
				switch v := overrides.(type) {
				case []interface{}:
					hasOverrides = len(v) > 0
				case map[string]interface{}:
					hasOverrides = len(v) > 0
				}
			}
			if !hasOverrides {
				rules := flag["rules"]
				if rules != nil {
					if arr, ok := rules.([]interface{}); ok && len(arr) > 0 {
						hasOverrides = true
					}
				}
			}

			if hasOverrides {
				findings = append(findings, warn(
					"flag-002", "Feature Flag Overrides in Production", catFlags,
					models.High, 7.0,
					"Overrides can silently change application behavior in production, potentially disabling security features without deployment.",
					fmt.Sprintf("Project '%s' flag '%s' has active overrides or rules that may affect production.", projName, displayName),
					"feature-flag", flagID, displayName,
					"Review production flag overrides. Ensure they are intentional and monitored.",
					map[string]string{"project": projName},
				))
			}
		}
	}

	return findings
}
