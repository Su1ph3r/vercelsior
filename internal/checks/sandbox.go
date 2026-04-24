package checks

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/models"
)

const catSandbox = "Sandboxes"

type SandboxChecks struct{}

func (s *SandboxChecks) Name() string     { return "Sandbox" }
func (s *SandboxChecks) Category() string { return catSandbox }

func (s *SandboxChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"sand-001", "Sandbox Check — Insufficient Permissions", catSandbox,
				"Cannot list projects: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "sand-001", Title: "Sandbox Check Failed", Category: catSandbox,
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

		sandboxes, err := c.ListSandboxes(projID)
		if err != nil {
			if IsPermissionDenied(err) {
				if !permSeen["ListSandboxes"] {
					permSeen["ListSandboxes"] = true
					// Canonical sand-001 (not the legacy sbx-001 typo).
					// Legacy configs still match via config.canonicalCheckID.
					findings = append(findings, permissionFinding(
						"sand-001", "Sandbox Check — Insufficient Permissions", catSandbox,
						"Cannot list sandboxes: API token lacks required permissions. This check was skipped for all projects.",
					))
				}
			} else if !permSeen["ListSandboxes_err"] {
				permSeen["ListSandboxes_err"] = true
				projName := str(p["name"])
				findings = append(findings, apiErrorFinding(
					"sand-001", "Sandbox Check Failed", catSandbox,
					"project", projID, projName, err,
				))
			}
			continue
		}

		for _, sb := range sandboxes {
			sbID := str(sb["id"])
			sbName := str(sb["name"])
			if sbName == "" {
				sbName = sbID
			}

			// sand-001: Sandbox With Open Network Policy
			networkPolicy := mapVal(sb["networkPolicy"])
			openPolicy := false
			if networkPolicy == nil {
				openPolicy = true
			} else {
				egress := str(networkPolicy["egress"])
				if egress == "" || egress == "allow-all" {
					openPolicy = true
				}
			}
			if openPolicy {
				findings = append(findings, warn(
					"sand-001", "Sandbox With Open Network Policy", catSandbox,
					models.Medium, 6.0,
					"Sandboxes with unrestricted egress can be used for SSRF, data exfiltration, or as pivot points to internal services.",
					fmt.Sprintf("Sandbox '%s' has no network policy restrictions or allows all egress traffic.", sbName),
					"sandbox", sbID, sbName,
					"Restrict sandbox network policies to only necessary outbound destinations.",
					map[string]string{"sandbox": sbName},
				))
			}

			// sand-002: Long-Running Sandbox
			createdAt := str(sb["createdAt"])
			if createdAt != "" {
				if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
					if time.Since(t) > 7*24*time.Hour {
						findings = append(findings, warn(
							"sand-002", "Long-Running Sandbox", catSandbox,
							models.Low, 4.0,
							"Stale sandboxes with active network access and potential credentials are unmonitored attack surface.",
							fmt.Sprintf("Sandbox '%s' was created on %s and is older than 7 days.", sbName, t.Format("2006-01-02")),
							"sandbox", sbID, sbName,
							"Clean up sandboxes that are no longer actively used.",
							map[string]string{"sandbox": sbName, "created": t.Format("2006-01-02")},
						))
					}
				}
			} else if ts := num(sb["createdAt"]); ts > 0 {
				// Handle Unix timestamp (milliseconds)
				created := time.UnixMilli(int64(ts))
				if time.Since(created) > 7*24*time.Hour {
					findings = append(findings, warn(
						"sand-002", "Long-Running Sandbox", catSandbox,
						models.Low, 4.0,
						"Stale sandboxes with active network access and potential credentials are unmonitored attack surface.",
						fmt.Sprintf("Sandbox '%s' was created on %s and is older than 7 days.", sbName, created.Format("2006-01-02")),
						"sandbox", sbID, sbName,
						"Clean up sandboxes that are no longer actively used.",
						map[string]string{"sandbox": sbName, "created": created.Format("2006-01-02")},
					))
				}
			}
		}
	}

	return findings
}
