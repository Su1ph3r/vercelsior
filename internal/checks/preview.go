package checks

import (
	"fmt"
	"strings"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catPreview = "Preview & Build Security"

type PreviewChecks struct{}

func (pc *PreviewChecks) Name() string     { return "Preview" }
func (pc *PreviewChecks) Category() string { return catPreview }

func (pc *PreviewChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		return findings
	}

	dangerousPatterns := []string{"curl", "wget", "eval", "bash -c", "sh -c", "|", ">", "$(", "`"}

	for _, p := range projects {
		projID := str(p["id"])
		projName := str(p["name"])

		// prev-001: Preview Deployments Publicly Accessible
		ssoProtection := mapVal(p["ssoProtection"])
		pwProtection := mapVal(p["passwordProtection"])

		// deploymentType values: "all", "preview", "all_except_custom_domains",
		// "prod_deployment_urls_and_all_previews", "none", "production", or empty
		// Any value that covers previews means they're protected
		ssoType := str(ssoProtection["deploymentType"])
		pwType := str(pwProtection["deploymentType"])
		hasSSOPreview := ssoProtection != nil && ssoType != "" && ssoType != "none" && ssoType != "production"
		hasPWPreview := pwProtection != nil && pwType != "" && pwType != "none" && pwType != "production"

		if !hasSSOPreview && !hasPWPreview {
			f := fail(
				"prev-001", "Preview Deployments Publicly Accessible", catPreview, models.High,
				8.0, "Preview deployments expose unreleased features and staging data. Attackers can enumerate preview URLs on .vercel.app subdomains.",
				fmt.Sprintf("Project '%s' has no SSO or password protection covering preview deployments.", projName),
				"project", projID, projName,
				"Enable SSO or password protection for preview deployments.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v10/projects", p, []string{"name", "id", "passwordProtection", "ssoProtection"}, "Project has no SSO or password protection for preview deployments")}
			findings = append(findings, f)
		} else {
			findings = append(findings, pass(
				"prev-001", "Preview Deployments Protected", catPreview,
				fmt.Sprintf("Project '%s' has protection enabled for preview deployments.", projName),
				"project", projID, projName,
			))
		}

		// prev-003: Build Command Allows Arbitrary Execution
		buildCmd := str(p["buildCommand"])
		installCmd := str(p["installCommand"])

		var flaggedCmds []string
		for _, pattern := range dangerousPatterns {
			if buildCmd != "" && strings.Contains(buildCmd, pattern) {
				flaggedCmds = append(flaggedCmds, fmt.Sprintf("buildCommand contains '%s'", pattern))
			}
			if installCmd != "" && strings.Contains(installCmd, pattern) {
				flaggedCmds = append(flaggedCmds, fmt.Sprintf("installCommand contains '%s'", pattern))
			}
		}

		if len(flaggedCmds) > 0 {
			findings = append(findings, warn(
				"prev-003", "Build Command Allows Arbitrary Execution", catPreview, models.High,
				8.0, "Dangerous commands in build steps can exfiltrate secrets at build time. Fork PRs with modified build commands are a known attack vector.",
				fmt.Sprintf("Project '%s' has potentially dangerous build commands: %s", projName, strings.Join(flaggedCmds, "; ")),
				"project", projID, projName,
				"Review build commands for shell injection risks. Avoid piping to shell or using eval.",
				map[string]string{"build_command": buildCmd, "install_command": installCmd},
			))
		} else if buildCmd != "" || installCmd != "" {
			findings = append(findings, pass(
				"prev-003", "Build Commands Appear Safe", catPreview,
				fmt.Sprintf("Project '%s' build commands do not contain dangerous patterns.", projName),
				"project", projID, projName,
			))
		}

		// prev-004: Root Directory Points Outside Repository
		rootDir := str(p["rootDirectory"])
		if rootDir != "" && strings.Contains(rootDir, "..") {
			findings = append(findings, fail(
				"prev-004", "Root Directory Points Outside Repository", catPreview, models.Critical,
				9.0, "Path traversal in root directory can expose files outside the intended project scope, potentially leaking secrets from monorepo siblings.",
				fmt.Sprintf("Project '%s' has root directory '%s' which contains path traversal.", projName, rootDir),
				"project", projID, projName,
				"Set root directory to a path within the repository. Never use '..' in root directory.",
				map[string]string{"root_directory": rootDir},
			))
		} else if rootDir != "" {
			findings = append(findings, pass(
				"prev-004", "Root Directory Within Repository", catPreview,
				fmt.Sprintf("Project '%s' root directory '%s' is within the repository.", projName, rootDir),
				"project", projID, projName,
			))
		}

		// Check: VERCEL_AUTOMATION_BYPASS_SECRET in env vars
		envVars, envErr := c.ListProjectEnvVars(projID)
		if envErr == nil {
			for _, env := range envVars {
				envKey := str(env["key"])
				if envKey == "VERCEL_AUTOMATION_BYPASS_SECRET" {
					findings = append(findings, warn(
						"prev-002", "Automation Bypass Secret Configured", catPreview, models.High,
						7.0, "The automation bypass secret permanently circumvents deployment protection. If leaked in CI logs or test configs, anyone can access protected deployments.",
						fmt.Sprintf("Project '%s' has VERCEL_AUTOMATION_BYPASS_SECRET configured. This bypasses deployment protection for automated access.", projName),
						"env_var", str(env["id"]), envKey,
						"Ensure the bypass secret is rotated regularly and never exposed in logs or client-side code. Consider using Vercel's built-in CI/CD bypass instead.",
						map[string]string{"project": projName},
					))
					break
				}
			}
		}

		// prev-005: Ignored Build Step not configured (monorepo optimization)
		link := mapVal(p["link"])
		if link != nil {
			// In monorepos, projects should configure ignoredBuildStep to prevent unnecessary deploys
			rootDir := str(p["rootDirectory"])
			if rootDir != "" && rootDir != "." && rootDir != "/" {
				// Project has a subdirectory root, suggesting monorepo usage
				ignoredBuildStep := p["skipDeploymentsForNewChanges"]
				if ignoredBuildStep == nil {
					ignoredBuildStep = p["ignoredBuildStep"]
				}
				if ignoredBuildStep == nil {
					findings = append(findings, warn(
						"prev-005", "No Ignored Build Step in Monorepo Project", catPreview, models.Low,
						3.0, "Without build filtering, every commit triggers deployments for all projects in a monorepo, increasing attack surface and resource consumption.",
						fmt.Sprintf("Project '%s' uses subdirectory '%s' but has no ignored build step configured.", projName, rootDir),
						"project", projID, projName,
						"Configure the 'Ignored Build Step' setting to skip unnecessary deployments when only other projects in the monorepo changed.",
						map[string]string{"root_directory": rootDir},
					))
				}
			}
		}

		// prev-006: Deploy Hooks Present
		if link != nil {
			if hooks, ok := link["deployHooks"].([]interface{}); ok && len(hooks) > 0 {
				findings = append(findings, warn(
					"prev-006", "Deploy Hooks Present", catPreview, models.Medium,
					6.0, "Deploy hooks are unauthenticated URLs that trigger production deployments. If leaked, anyone can trigger arbitrary builds.",
					fmt.Sprintf("Project '%s' has %d deploy hook(s) configured. These are unauthenticated endpoints that can trigger deployments.", projName, len(hooks)),
					"project", projID, projName,
					"Review deploy hooks and remove any that are no longer needed. Treat hook URLs as secrets.",
					map[string]string{"hook_count": fmt.Sprintf("%d", len(hooks))},
				))
			}
		}
	}

	return findings
}
