package checks

import (
	"fmt"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/models"
)

const catVerification = "Deployment Verification"

type VerificationChecks struct{}

func (v *VerificationChecks) Name() string     { return "Verification" }
func (v *VerificationChecks) Category() string { return catVerification }

func (v *VerificationChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"chk-001", "Project Enumeration — Insufficient Permissions", catVerification,
				"Cannot list projects: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "chk-001", Title: "Project Enumeration", Category: catVerification,
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

		// Get the most recent deployment for chk-001
		deployments, err := c.ListDeploymentsLimit(projID, 1)
		if err != nil {
			if IsPermissionDenied(err) && !permSeen["ListDeploymentsLimit"] {
				permSeen["ListDeploymentsLimit"] = true
				findings = append(findings, permissionFinding(
					"ver-001", "Deployment Verification Check — Insufficient Permissions", catVerification,
					"Cannot list deployments: API token lacks required permissions. This check was skipped for all projects.",
				))
			}
			continue
		}
		if len(deployments) == 0 {
			continue
		}

		latestDeploy := deployments[0]
		latestDeployID := str(latestDeploy["uid"])
		if latestDeployID == "" {
			latestDeployID = str(latestDeploy["id"])
		}

		latestChecks, err := c.ListDeploymentChecks(latestDeployID)
		if err != nil {
			if IsPermissionDenied(err) && !permSeen["ListDeploymentChecks"] {
				permSeen["ListDeploymentChecks"] = true
				findings = append(findings, permissionFinding(
					"ver-001", "Deployment Checks — Insufficient Permissions", catVerification,
					"Cannot list deployment checks: API token lacks required permissions. This check was skipped for all projects.",
				))
			}
			continue
		}

		// chk-001: No Deployment Checks Configured
		if len(latestChecks) == 0 {
			f := warn(
				"chk-001", "No Deployment Checks Configured", catVerification,
				models.Medium, 5.0,
				"Deployment checks are a gate before promotion. Without them, malicious or broken deployments go live immediately.",
				fmt.Sprintf("Project '%s' has no deployment checks configured on its most recent deployment.", projName),
				"project", projID, projName,
				"Configure deployment checks to verify builds before they go live.",
				map[string]string{"project": projName},
			)
			f.PocEvidence = []models.PocEvidence{buildEvidenceRaw(
				fmt.Sprintf("/v2/deployments/%s/check-runs", latestDeployID),
				200, `{"checks":[]}`,
				"Deployment checks API returned an empty array for the latest deployment.")}
			findings = append(findings, f)
			continue // no checks means chk-002 is not applicable
		}

		// chk-002: Deployment Checks Always Passing
		// Get recent 5 deployments and check if all checks always succeed
		recentDeploys, err := c.ListDeploymentsLimit(projID, 5)
		if err != nil {
			if IsPermissionDenied(err) && !permSeen["ListDeploymentsLimit"] {
				permSeen["ListDeploymentsLimit"] = true
				findings = append(findings, permissionFinding(
					"ver-001", "Deployment Verification Check — Insufficient Permissions", catVerification,
					"Cannot list deployments: API token lacks required permissions. This check was skipped for all projects.",
				))
			}
			continue
		}
		if len(recentDeploys) == 0 {
			continue
		}

		allSucceeded := true
		totalChecks := 0
		for _, d := range recentDeploys {
			dID := str(d["uid"])
			if dID == "" {
				dID = str(d["id"])
			}
			dChecks, err := c.ListDeploymentChecks(dID)
			if err != nil {
				if IsPermissionDenied(err) && !permSeen["ListDeploymentChecks"] {
					permSeen["ListDeploymentChecks"] = true
					findings = append(findings, permissionFinding(
						"ver-001", "Deployment Checks — Insufficient Permissions", catVerification,
						"Cannot list deployment checks: API token lacks required permissions. This check was skipped for all projects.",
					))
				}
				continue
			}
			for _, chk := range dChecks {
				totalChecks++
				conclusion := str(chk["conclusion"])
				if conclusion != "succeeded" {
					allSucceeded = false
					break
				}
			}
			if !allSucceeded {
				break
			}
		}

		if allSucceeded && totalChecks > 0 {
			findings = append(findings, warn(
				"chk-002", "Deployment Checks Always Passing", catVerification,
				models.Low, 4.0,
				"Checks that never fail may be rubber-stamp checks providing false assurance.",
				fmt.Sprintf("Project '%s' has deployment checks that have succeeded on all recent deployments (%d checks across %d deployments).", projName, totalChecks, len(recentDeploys)),
				"project", projID, projName,
				"Review deployment checks to ensure they perform meaningful validation.",
				map[string]string{"project": projName, "total_checks": fmt.Sprintf("%d", totalChecks)},
			))
		}

		// chk-003: Rerequested checks on failed deployments
		for _, d := range recentDeploys {
			deployID := str(d["uid"])
			if deployID == "" {
				deployID = str(d["id"])
			}
			dChecks, err := c.ListDeploymentChecks(deployID)
			if err != nil {
				// 403s are already surfaced via the permSeen-guarded
				// permissionFinding in the chk-002 loop above; other
				// errors (5xx, network, rate limit) were previously
				// silent so the audit gap now emits a visible Error.
				if !IsPermissionDenied(err) && !permSeen["ListDeploymentChecks_err"] {
					permSeen["ListDeploymentChecks_err"] = true
					findings = append(findings, apiErrorFinding(
						"chk-003", "Deployment Check Enumeration Failed", catVerification,
						"deployment", deployID, projName, err,
					))
				}
				continue
			}
			for _, chk := range dChecks {
				conclusion := str(chk["conclusion"])
				rerequested := boolean(chk["rerequested"])
				if rerequested && conclusion == "succeeded" {
					checkName := str(chk["name"])
					if checkName == "" {
						checkName = str(chk["id"])
					}
					findings = append(findings, warn(
						"chk-003", "Deployment Check Rerequested After Failure", catVerification, models.Medium,
						6.0, "Rerequesting checks until they pass is a deployment verification bypass technique. This may indicate quality gates are being circumvented.",
						fmt.Sprintf("Project '%s': Check '%s' was rerequested and subsequently passed on deployment %s.", projName, checkName, deployID),
						"deployment_check", str(chk["id"]), checkName,
						"Investigate why checks were rerequested. Ensure check rerequests require justification.",
						map[string]string{"project": projName, "deployment": deployID},
					))
				}
			}
		}
	}

	return findings
}
