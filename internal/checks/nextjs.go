package checks

import (
	"fmt"
	"strings"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/models"
)

const catFramework = "Framework Security"

type nextjsCVE struct {
	ID           string
	Description  string
	CVSS         float64
	IsVulnerable func(major, minor, patch int) bool
}

var nextjsCVEs = []nextjsCVE{
	{
		ID:          "CVE-2025-29927",
		Description: "Next.js middleware authorization bypass",
		CVSS:        9.1,
		IsVulnerable: func(maj, min, pat int) bool {
			// Patched in 14.2.25 and 15.2.3; middleware introduced in 12.0
			if maj < 12 {
				return false
			}
			if maj < 14 {
				return true
			}
			if maj == 14 {
				return min < 2 || (min == 2 && pat < 25)
			}
			if maj == 15 {
				return min < 2 || (min == 2 && pat < 3)
			}
			return false
		},
	},
	{
		ID:          "CVE-2025-55182",
		Description: "React Server Components deserialization RCE (React2Shell)",
		CVSS:        10.0,
		IsVulnerable: func(maj, min, pat int) bool {
			// Complex matrix. Patched per minor series:
			// 14.2.35+, 15.0.7+, 15.1.11+, 15.2.8+, 15.3.8+, 15.4.10+, 15.5.9+, 16.0.10+
			if maj < 14 {
				return false // pre-React 19, not affected
			}
			if maj == 14 {
				return min == 2 && pat < 35
			}
			if maj == 15 {
				switch min {
				case 0:
					return pat >= 4 && pat < 7 // affected from 15.0.4
				case 1:
					return pat < 11
				case 2:
					return pat < 8
				case 3:
					return pat < 8
				case 4:
					return pat < 10
				case 5:
					return pat < 9
				default:
					return false
				}
			}
			if maj == 16 {
				return min == 0 && pat < 10
			}
			return false
		},
	},
	{
		ID:          "CVE-2025-49826",
		Description: "ISR cache poisoning via 204 response",
		CVSS:        7.5,
		IsVulnerable: func(maj, min, pat int) bool {
			// Affects 15.1.0 to 15.1.7
			return maj == 15 && min == 1 && pat < 8
		},
	},
	{
		ID:          "CVE-2025-59471",
		Description: "Image optimization memory exhaustion via /_next/image",
		CVSS:        5.9,
		IsVulnerable: func(maj, min, pat int) bool {
			// Patched in 15.5.10 and 16.1.5
			if maj == 15 {
				return min < 5 || (min == 5 && pat < 10)
			}
			if maj == 16 {
				return min < 1 || (min == 1 && pat < 5)
			}
			return false
		},
	},
	{
		ID:          "CVE-2025-59472",
		Description: "PPR resume endpoint denial of service via zip bomb",
		CVSS:        5.9,
		IsVulnerable: func(maj, min, pat int) bool {
			// Same patch versions as CVE-2025-59471
			if maj == 15 {
				return min < 5 || (min == 5 && pat < 10)
			}
			if maj == 16 {
				return min < 1 || (min == 1 && pat < 5)
			}
			return false
		},
	},
}

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

		major, minor, patch, ok := parseVersion(version)
		if !ok {
			continue
		}

		// Collect all applicable CVEs for this version
		var matchedCVEs []string
		var maxCVSS float64
		for _, cve := range nextjsCVEs {
			if cve.IsVulnerable(major, minor, patch) {
				matchedCVEs = append(matchedCVEs, cve.ID)
				if cve.CVSS > maxCVSS {
					maxCVSS = cve.CVSS
				}
			}
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

// parseVersion extracts major, minor, patch from a semver-like string.
// Returns ok=false if parsing fails.
func parseVersion(v string) (int, int, int, bool) {
	v = strings.TrimPrefix(v, "v")

	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0, 0, false
	}

	major, ok1 := safeParseInt(parts[0])
	minor, ok2 := safeParseInt(parts[1])
	if !ok1 || !ok2 {
		return 0, 0, 0, false
	}

	patch := 0
	if len(parts) >= 3 {
		patchStr := parts[2]
		if idx := strings.IndexAny(patchStr, "-+"); idx >= 0 {
			patchStr = patchStr[:idx]
		}
		// Empty after prerelease strip (e.g. "1.2.-canary") is acceptable
		// and treated as patch=0. Non-numeric patches (e.g. "1.2.x") are
		// not safe to assume — reject the whole version so the caller
		// skips the CVE comparison rather than incorrectly flagging a
		// project as running the oldest possible patch.
		if patchStr != "" {
			p, ok := safeParseInt(patchStr)
			if !ok {
				return 0, 0, 0, false
			}
			patch = p
		}
	}

	return major, minor, patch, true
}

// safeParseInt converts a string to int, returning ok=false for empty or non-numeric strings.
func safeParseInt(s string) (int, bool) {
	if len(s) == 0 {
		return 0, false
	}
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		next := n*10 + int(ch-'0')
		if next < n {
			return 0, false
		}
		n = next
	}
	return n, true
}
