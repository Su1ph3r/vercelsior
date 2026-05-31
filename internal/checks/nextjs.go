package checks

import (
	"fmt"
	"strings"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/models"
	"github.com/Su1ph3r/vercelsior/internal/nextjs"
)

const catFramework = "Framework Security"

type NextJSChecks struct{}

func (nc *NextJSChecks) Name() string     { return "NextJS" }
func (nc *NextJSChecks) Category() string { return catFramework }

func (nc *NextJSChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"njs-001", "Next.js Check — Insufficient Permissions", catFramework,
				"Cannot list projects: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "njs-001", Title: "Next.js Check Failed", Category: catFramework,
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

		findings = append(findings, nc.checkPublicEnvVars(c, projID, projName)...)
		findings = append(findings, nc.checkOutdatedVersion(c, projID, projName)...)
		findings = append(findings, nc.checkFrameworkSet(p, projID, projName)...)
	}

	// Also check shared/team-level env vars for NEXT_PUBLIC_ leaks
	sharedEnvs, sharedErr := c.ListSharedEnvVars()
	if sharedErr != nil {
		if IsPermissionDenied(sharedErr) {
			findings = append(findings, permissionFinding(
				"njs-001", "Shared Env Var Check — Insufficient Permissions", catFramework,
				"Cannot list shared environment variables: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, apiErrorFinding(
				"njs-001", "Shared Env Var Check Failed", catFramework,
				"shared_env_var", "N/A", "", sharedErr,
			))
		}
	} else {
		for _, env := range sharedEnvs {
			envKey := str(env["key"])
			envID := str(env["id"])
			if !strings.HasPrefix(envKey, "NEXT_PUBLIC_") {
				continue
			}
			remainder := strings.TrimPrefix(envKey, "NEXT_PUBLIC_")
			if isSensitiveName(remainder) {
				f := fail(
					"njs-001", "NEXT_PUBLIC_ Shared Env Var With Sensitive Name", catFramework, models.Critical,
					10.0,
					"NEXT_PUBLIC_ prefixed variables are embedded in client-side JavaScript bundles at build time. Anyone viewing page source can read them. This is the #1 real-world Vercel security incident.",
					fmt.Sprintf("Shared environment variable '%s' has the NEXT_PUBLIC_ prefix and a sensitive name. This value is exposed in client-side JavaScript for ALL projects.", envKey),
					"shared_env_var", envID, envKey,
					"Remove the NEXT_PUBLIC_ prefix from sensitive variables. Use server-side API routes to access secrets instead of exposing them to the client.",
					map[string]string{"variable": envKey, "scope": "team/shared"},
				)
				f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v1/env", env, []string{"key", "id", "type", "target"}, fmt.Sprintf("Shared NEXT_PUBLIC_ variable '%s' with sensitive name is exposed client-side", envKey))}
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// njs-001: NEXT_PUBLIC_ env vars with sensitive names
func (nc *NextJSChecks) checkPublicEnvVars(c *client.Client, projID, projName string) []models.Finding {
	var findings []models.Finding

	envVars, err := c.ListProjectEnvVars(projID)
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"njs-001", "Public Env Vars Check — Insufficient Permissions", catFramework,
				"Cannot list project environment variables: API token lacks required permissions. This check was skipped.",
			))
		}
		return findings
	}

	for _, env := range envVars {
		envKey := str(env["key"])
		envID := str(env["id"])

		if !strings.HasPrefix(envKey, "NEXT_PUBLIC_") {
			continue
		}

		remainder := strings.TrimPrefix(envKey, "NEXT_PUBLIC_")
		if isSensitiveName(remainder) {
			f := fail(
				"njs-001", "NEXT_PUBLIC_ Env Var With Sensitive Name", catFramework, models.Critical,
				10.0,
				"NEXT_PUBLIC_ prefixed variables are embedded in client-side JavaScript bundles at build time. Anyone viewing page source can read them. This is the #1 real-world Vercel security incident.",
				fmt.Sprintf("Project '%s': Environment variable '%s' has the NEXT_PUBLIC_ prefix and a sensitive name. This value is exposed in client-side JavaScript.", projName, envKey),
				"env_var", envID, envKey,
				"Remove the NEXT_PUBLIC_ prefix from sensitive variables. Use server-side API routes to access secrets instead of exposing them to the client.",
				map[string]string{"project": projName, "project_id": projID, "variable": envKey},
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, fmt.Sprintf("/v10/projects/%s/env", projID), env, []string{"key", "id", "type", "target"}, fmt.Sprintf("NEXT_PUBLIC_ variable '%s' with sensitive name is exposed client-side", envKey))}
			findings = append(findings, f)
		}
	}

	return findings
}

// njs-002: Outdated Next.js version with known CVEs
func (nc *NextJSChecks) checkOutdatedVersion(c *client.Client, projID, projName string) []models.Finding {
	var findings []models.Finding

	deployments, err := c.ListDeploymentsLimit(projID, 5)
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"njs-002", "Next.js Version Check — Insufficient Permissions", catFramework,
				fmt.Sprintf("Cannot list deployments for project '%s': API token lacks required permissions. This check was skipped.", projName),
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "njs-002", Title: "Next.js Version Check Failed", Category: catFramework,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list deployments for project '%s': %v", projName, err),
				ResourceType: "project", ResourceID: projID, ResourceName: projName,
			})
		}
		return findings
	}

	checked := false
	for _, d := range deployments {
		meta := mapVal(d["meta"])
		if meta == nil {
			continue
		}

		framework := str(meta["framework"])
		if framework != "nextjs" && framework != "Next.js" && framework != "next" {
			continue
		}

		version := str(meta["frameworkVersion"])
		if version == "" {
			continue
		}

		// Match against the shared CVE matrix (single source of truth in
		// internal/nextjs, used by both this scan path and project mode).
		matchedCVEs, maxCVSS, ok := nextjs.Match(version)
		if !ok {
			continue
		}

		if len(matchedCVEs) > 0 {
			cveList := strings.Join(matchedCVEs, ", ")
			sev := models.High
			if maxCVSS >= 9.0 {
				sev = models.Critical
			}
			findings = append(findings, fail(
				"njs-002", "Outdated Next.js Version With Known CVEs", catFramework,
				sev, maxCVSS,
				fmt.Sprintf("Next.js %s is affected by %d known CVE(s): %s. The most severe has a CVSS score of %.1f.", version, len(matchedCVEs), cveList, maxCVSS),
				fmt.Sprintf("Project '%s' is running Next.js %s which is affected by: %s.", projName, version, cveList),
				"project", projID, projName,
				"Update Next.js to the latest patched version. See individual CVE advisories for minimum safe versions.",
				map[string]string{
					"nextjs_version": version,
					"cves":           cveList,
					"max_cvss":       fmt.Sprintf("%.1f", maxCVSS),
				},
			))
		} else {
			findings = append(findings, pass(
				"njs-002", "Next.js Version Up To Date", catFramework,
				fmt.Sprintf("Project '%s': Running Next.js %s with no known CVEs.", projName, version),
				"project", projID, projName,
			))
		}

		checked = true
		break // only need to check the most recent deployment with version info
	}

	// If no deployment exposed a framework version we couldn't evaluate the
	// CVE matrix at all — record the gap so the report reflects missing
	// coverage rather than silently implying the project is safe.
	if !checked {
		findings = append(findings, models.Finding{
			CheckID:      "njs-002",
			Title:        "Next.js Version Not Determined",
			Category:     catFramework,
			Severity:     models.Info,
			Status:       models.Error,
			Description:  fmt.Sprintf("Project '%s': No recent deployment exposed a Next.js framework version; CVE check skipped.", projName),
			ResourceType: "project",
			ResourceID:   projID,
			ResourceName: projName,
		})
	}
	return findings
}

// njs-003: Framework not set on project
func (nc *NextJSChecks) checkFrameworkSet(p map[string]interface{}, projID, projName string) []models.Finding {
	var findings []models.Finding

	framework := str(p["framework"])
	if framework == "" {
		findings = append(findings, warn(
			"njs-003", "Framework Not Set", catFramework, models.Medium,
			4.0,
			"Vercel applies framework-specific security mitigations only when the framework is correctly identified. Unknown frameworks miss platform protections.",
			fmt.Sprintf("Project '%s' does not have a framework configured. Vercel cannot apply framework-specific security optimizations.", projName),
			"project", projID, projName,
			"Set the framework in project settings so Vercel can apply framework-specific security optimizations.",
			nil,
		))
	} else {
		findings = append(findings, pass(
			"njs-003", "Framework Configured", catFramework,
			fmt.Sprintf("Project '%s' has framework set to '%s'.", projName, framework),
			"project", projID, projName,
		))
	}

	return findings
}
