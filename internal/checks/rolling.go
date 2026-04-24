package checks

import (
	"fmt"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/models"
)

const catRolling = "Rolling Releases"

type RollingReleaseChecks struct{}

func (r *RollingReleaseChecks) Name() string     { return "Rolling" }
func (r *RollingReleaseChecks) Category() string { return catRolling }

func (r *RollingReleaseChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"roll-001", "Project Enumeration — Insufficient Permissions", catRolling,
				"Cannot list projects: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "roll-001", Title: "Project Enumeration", Category: catRolling,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list projects: %v", err),
				ResourceType: "project", ResourceID: "N/A",
			})
		}
		return findings
	}

	permSeen := make(map[string]bool)

	for _, p := range projects {
		projID := str(p["id"])
		projName := str(p["name"])

		config, err := c.GetRollingReleaseConfig(projID)
		if err != nil {
			if IsPermissionDenied(err) {
				if !permSeen["GetRollingReleaseConfig"] {
					permSeen["GetRollingReleaseConfig"] = true
					// Emit the canonical roll-001 (not the legacy rol-001
					// typo) so suppression/filtering works as users expect.
					// Legacy configs that write rol-001 still match, via the
					// alias in config.canonicalCheckID.
					findings = append(findings, permissionFinding(
						"roll-001", "Rolling Release Check — Insufficient Permissions", catRolling,
						"Cannot read rolling release configuration: API token lacks required permissions. This check was skipped for all projects.",
					))
				}
			} else if !permSeen["GetRollingReleaseConfig_err"] {
				permSeen["GetRollingReleaseConfig_err"] = true
				findings = append(findings, apiErrorFinding(
					"roll-001", "Rolling Release Check Failed", catRolling,
					"project", projID, projName, err,
				))
			}
			continue
		}
		if config == nil {
			continue
		}

		rrConfig := mapVal(config["rollingRelease"])
		if rrConfig == nil {
			continue // not configured
		}

		enabled := boolean(rrConfig["enabled"])
		if !enabled {
			continue
		}

		// roll-001: Rolling Release Without Approval Gate
		stages, _ := rrConfig["stages"].([]interface{})
		hasApproval := false
		for _, s := range stages {
			stage := mapVal(s)
			if stage != nil && boolean(stage["requireApproval"]) {
				hasApproval = true
				break
			}
		}
		if !hasApproval {
			findings = append(findings, warn(
				"roll-001", "Rolling Release Without Approval Gate", catRolling,
				models.Medium, 6.0,
				"Without approval gates, a compromised deployment automatically rolls out to 100% of traffic through canary stages.",
				fmt.Sprintf("Project '%s' has rolling releases enabled with no approval gate on any stage.", projName),
				"project", projID, projName,
				"Add manual approval gates between rolling release stages.",
				map[string]string{"project": projName},
			))
		}

		// roll-002: Rolling Release Active — Verify Monitoring
		findings = append(findings, warn(
			"roll-002", "Rolling Release Active — Verify Monitoring", catRolling,
			models.Low, 3.0,
			"Rolling releases alter traffic distribution during deploys. Monitoring configuration cannot be verified via API — manual review recommended.",
			fmt.Sprintf("Project '%s' has rolling releases enabled. Ensure monitoring is configured for canary deployments.", projName),
			"project", projID, projName,
			"Configure webhook notifications for rolling release events to monitor canary deployments.",
			map[string]string{"project": projName},
		))
	}

	return findings
}
