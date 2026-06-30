package checks

import (
	"fmt"
	"strings"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/models"
)

const catFlags = "Feature Flags"

type FeatureFlagChecks struct{}

func (f *FeatureFlagChecks) Name() string     { return "Flags" }
func (f *FeatureFlagChecks) Category() string { return catFlags }

var sensitivePatterns = []string{
	"admin", "bypass", "debug", "internal", "kill-switch", "killswitch",
	"maintenance", "disable-auth", "skip-auth",
}

// matchedSensitiveFlagWord returns the first sensitive pattern that matches the
// flag name or key, or "" if none. Single-word patterns are matched on whole name
// segments (so "administrator-onboarding" and "new-debugger-tab" no longer match
// "admin"/"debug"); compound patterns that already contain a delimiter (e.g.
// "disable-auth") are specific enough to match as a substring.
func matchedSensitiveFlagWord(name, key string) string {
	combined := strings.ToLower(name + " " + key)
	for _, pattern := range sensitivePatterns {
		if strings.ContainsAny(pattern, "-_") {
			if strings.Contains(combined, pattern) {
				return pattern
			}
			continue
		}
		if hasWholeSegment(combined, pattern) {
			return pattern
		}
	}
	return ""
}

func (f *FeatureFlagChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"flag-001", "Project Enumeration — Insufficient Permissions", catFlags,
				"Cannot list projects: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "flag-001", Title: "Project Enumeration", Category: catFlags,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list projects: %v", err),
				ResourceType: "project", ResourceID: "N/A",
			})
		}
		return findings
	}

	for _, p := range projects {
		projID := str(p["id"])
		projName := str(p["name"])

		flags, err := c.ListFeatureFlags(projID)
		if err != nil {
			if IsPermissionDenied(err) {
				findings = append(findings, permissionFinding(
					"flag-001", "Feature Flag Check — Insufficient Permissions", catFlags,
					fmt.Sprintf("Cannot list feature flags for project '%s': API token lacks required permissions.", projName),
				))
			} else {
				findings = append(findings, models.Finding{
					CheckID: "flag-001", Title: "Feature Flag Enumeration", Category: catFlags,
					Severity: models.Info, Status: models.Error,
					Description:  fmt.Sprintf("Failed to list feature flags for project '%s': %v", projName, err),
					ResourceType: "project", ResourceID: projID, ResourceName: projName,
				})
			}
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

			// flag-001: Security-sensitive name check. Match whole name segments
			// (split on -_./ ) rather than substrings, so a flag like
			// "show-admin-contact-link" or "new-debugger-tab" is not flagged for
			// merely containing "admin" or "debug".
			matched := matchedSensitiveFlagWord(flagName, flagKey)
			if matched != "" {
				findings = append(findings, warn(
					"flag-001", "Feature Flag With Security-Sensitive Name", catFlags,
					models.Medium, 6.0,
					"Security-critical flags controlling admin mode, debug mode, or auth bypass can be toggled to weaken security posture if misconfigured.",
					fmt.Sprintf("Project '%s' has flag '%s' matching sensitive pattern '%s'.", projName, displayName, matched),
					"feature-flag", flagID, displayName,
					"Review security-sensitive feature flags. Ensure they have proper access controls and monitoring.",
					map[string]string{"project": projName, "matched_pattern": matched},
				))
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

			// flag-002: Overrides/rules on a SECURITY-SENSITIVE flag. Overrides and
			// rules are the normal mechanism of every feature flag (targeting,
			// gradual rollout), so their mere presence is not a finding. Only flag
			// them when the flag's name is itself security-sensitive (flag-001
			// matched), where a silent override could weaken security posture.
			if hasOverrides && matched != "" {
				findings = append(findings, warn(
					"flag-002", "Overrides on a Security-Sensitive Feature Flag", catFlags,
					models.Medium, 5.0,
					"Overrides can silently change application behavior in production. On a security-sensitive flag, an override could disable a protection without a deployment.",
					fmt.Sprintf("Project '%s' security-sensitive flag '%s' has active overrides or rules that may affect production.", projName, displayName),
					"feature-flag", flagID, displayName,
					"Review production flag overrides. Ensure they are intentional and monitored.",
					map[string]string{"project": projName},
				))
			}
		}
	}

	return findings
}
