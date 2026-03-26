package checks

import (
	"fmt"
	"strings"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catFramework = "Framework Security"

type NextJSChecks struct{}

func (nc *NextJSChecks) Name() string     { return "NextJS" }
func (nc *NextJSChecks) Category() string { return catFramework }

func (nc *NextJSChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
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
	if sharedErr == nil {
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
				map[string]string{"project": projName, "variable": envKey},
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

		major, minor, patch := parseVersion(version)
		if major == 0 && minor == 0 && patch == 0 {
			continue
		}

		vulnerable := false
		if major < 14 {
			vulnerable = true
		} else if major == 14 {
			if minor < 2 {
				vulnerable = true
			} else if minor == 2 && patch < 25 {
				vulnerable = true
			}
		} else if major == 15 {
			if minor < 2 {
				vulnerable = true
			} else if minor == 2 && patch < 3 {
				vulnerable = true
			}
		}

		if vulnerable {
			findings = append(findings, fail(
				"njs-002", "Outdated Next.js Version With Known CVEs", catFramework, models.Critical,
				9.0,
				"CVE-2025-29927 allows complete middleware authentication bypass. React2Shell (CVE-2025-55182) enables remote code execution. These are actively exploited.",
				fmt.Sprintf("Project '%s': Deployment is running Next.js %s which has known critical CVEs.", projName, version),
				"project", projID, projName,
				"Upgrade Next.js to the latest version. At minimum: 14.2.25+ or 15.2.3+ to patch CVE-2025-29927.",
				map[string]string{"project": projName, "nextjs_version": version},
			))
		} else {
			findings = append(findings, pass(
				"njs-002", "Next.js Version Up To Date", catFramework,
				fmt.Sprintf("Project '%s': Running Next.js %s with no known critical CVEs.", projName, version),
				"project", projID, projName,
			))
		}

		checked = true
		break // only need to check the most recent deployment with version info
	}

	_ = checked
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
// Returns (0,0,0) if parsing fails.
func parseVersion(v string) (int, int, int) {
	// Strip leading "v" if present
	v = strings.TrimPrefix(v, "v")

	// Split on "." and parse up to three parts
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0, 0
	}

	major := parseInt(parts[0])
	minor := parseInt(parts[1])
	patch := 0
	if len(parts) >= 3 {
		// Handle pre-release suffixes like "15.2.3-canary.1"
		patchStr := parts[2]
		if idx := strings.IndexAny(patchStr, "-+"); idx >= 0 {
			patchStr = patchStr[:idx]
		}
		patch = parseInt(patchStr)
	}

	return major, minor, patch
}

// parseInt is a simple string-to-int converter that returns 0 on failure.
func parseInt(s string) int {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}
