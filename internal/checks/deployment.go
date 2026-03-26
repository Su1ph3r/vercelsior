package checks

import (
	"fmt"
	"strings"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catDeployment = "Deployment Protection"

type DeploymentChecks struct{}

func (dc *DeploymentChecks) Name() string     { return "Deployment" }
func (dc *DeploymentChecks) Category() string { return catDeployment }

func (dc *DeploymentChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		return findings
	}

	for _, p := range projects {
		projID := str(p["id"])
		projName := str(p["name"])

		// Check: git fork protection
		gitForkProtection := p["gitForkProtection"]
		if boolean(gitForkProtection) {
			// PASS - explicitly enabled
			findings = append(findings, pass(
				"dep-001", "Git Fork Protection Enabled", catDeployment,
				fmt.Sprintf("Project '%s' has git fork protection enabled.", projName),
				"project", projID, projName,
			))
		} else {
			// FAIL - either false or nil (not configured)
			f := fail(
				"dep-001", "Git Fork Protection Disabled", catDeployment, models.High,
				8.0, "Fork PRs can execute build-time code with access to production secrets. An attacker can submit a malicious fork to steal environment variables.",
				fmt.Sprintf("Project '%s' allows deployments from forked repositories. This can expose secrets to untrusted code.", projName),
				"project", projID, projName,
				"Enable git fork protection to prevent unauthorized code from accessing environment variables during builds.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v10/projects", p, []string{"name", "id", "gitForkProtection"}, "Project has git fork protection disabled")}
			findings = append(findings, f)
		}

		// Check: public source
		if boolean(p["publicSource"]) {
			findings = append(findings, warn(
				"dep-002", "Source Code Publicly Visible", catDeployment, models.Medium,
				5.0, "Public source exposes application logic, internal paths, and potential vulnerabilities to attackers. Useful for reconnaissance.",
				fmt.Sprintf("Project '%s' has public source code enabled. Anyone can view the deployment source.", projName),
				"project", projID, projName,
				"Disable public source unless intentionally open-source.",
				nil,
			))
		}

		// Check: sourcemap protection
		if !boolean(p["protectedSourcemaps"]) {
			f := warn(
				"dep-003", "Sourcemaps Not Protected", catDeployment, models.Medium,
				5.0, "Unprotected sourcemaps reveal original source code including comments, variable names, and application structure.",
				fmt.Sprintf("Project '%s' does not protect sourcemaps. Sourcemaps can reveal original source code.", projName),
				"project", projID, projName,
				"Enable protected sourcemaps to prevent unauthorized access to original source code.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v10/projects", p, []string{"name", "id", "protectedSourcemaps"}, "Sourcemap protection is not enabled")}
			findings = append(findings, f)
		}

		// Check: password protection
		pwProtection := mapVal(p["passwordProtection"])
		ssoProtection := mapVal(p["ssoProtection"])

		hasPasswordProtection := pwProtection != nil && str(pwProtection["deploymentType"]) != ""
		hasSSOProtection := ssoProtection != nil && str(ssoProtection["deploymentType"]) != ""

		if !hasPasswordProtection && !hasSSOProtection {
			findings = append(findings, warn(
				"dep-004", "No Deployment Access Protection", catDeployment, models.Medium,
				6.0, "Unprotected preview deployments expose pre-release features and potentially staging data to anyone with the URL.",
				fmt.Sprintf("Project '%s' has neither password nor SSO protection on deployments.", projName),
				"project", projID, projName,
				"Enable password or SSO protection for preview deployments to prevent unauthorized access.",
				nil,
			))
		} else {
			protTypes := []string{}
			if hasPasswordProtection {
				protTypes = append(protTypes, "password")
			}
			if hasSSOProtection {
				protTypes = append(protTypes, "SSO")
			}
			findings = append(findings, pass(
				"dep-004", "Deployment Access Protection Active", catDeployment,
				fmt.Sprintf("Project '%s' has %s protection enabled.", projName, strings.Join(protTypes, " and ")),
				"project", projID, projName,
			))
		}

		// Check: protection bypass rules
		protBypass := mapVal(p["protectionBypass"])
		if protBypass != nil && len(protBypass) > 0 {
			findings = append(findings, warn(
				"dep-005", "Deployment Protection Bypass Active", catDeployment, models.High,
				7.0, "Protection bypass rules create permanent holes in deployment access control. Anyone with the bypass secret can access protected deployments.",
				fmt.Sprintf("Project '%s' has %d protection bypass rule(s). These allow unauthenticated access to protected deployments.", projName, len(protBypass)),
				"project", projID, projName,
				"Review and remove unnecessary protection bypass rules.",
				map[string]string{"bypass_count": fmt.Sprintf("%d", len(protBypass))},
			))
		}

		// Check: trusted IPs
		trustedIps := mapVal(p["trustedIps"])
		if trustedIps != nil {
			if addrs, ok := trustedIps["addresses"].([]interface{}); ok {
				for _, addr := range addrs {
					if am, ok := addr.(map[string]interface{}); ok {
						ip := str(am["value"])
						if ip == "0.0.0.0/0" || ip == "::/0" {
							findings = append(findings, fail(
								"dep-006", "Overly Broad Trusted IP Range", catDeployment, models.Critical,
								9.0, "A 0.0.0.0/0 trusted IP range disables all IP-based access restrictions. Equivalent to having no trusted IP configuration.",
								fmt.Sprintf("Project '%s' has a trusted IP range of %s which allows all traffic.", projName, ip),
								"project", projID, projName,
								"Restrict trusted IP ranges to specific known IP addresses.",
								map[string]string{"ip_range": ip},
							))
						}
					}
				}
			}
		}

		// Check: deployment expiration
		depExp := mapVal(p["deploymentExpiration"])
		if depExp == nil {
			findings = append(findings, warn(
				"dep-007", "No Deployment Expiration Policy", catDeployment, models.Low,
				3.0, "Old deployments remain accessible indefinitely, expanding the attack surface. Stale deployments may contain known vulnerabilities.",
				fmt.Sprintf("Project '%s' has no deployment expiration policy. Old deployments remain accessible indefinitely.", projName),
				"project", projID, projName,
				"Set a deployment expiration policy to automatically clean up old deployments.",
				nil,
			))
		}

		// Check: Node.js version
		nodeVersion := str(p["nodeVersion"])
		if nodeVersion != "" {
			outdated := map[string]bool{
				"14.x": true, "16.x": true, "12.x": true, "10.x": true,
			}
			if outdated[nodeVersion] {
				findings = append(findings, fail(
					"dep-008", "Outdated Node.js Version", catDeployment, models.High,
					7.0, "End-of-life Node.js versions no longer receive security patches. Known CVEs remain unpatched in the runtime.",
					fmt.Sprintf("Project '%s' uses Node.js %s which is end-of-life and no longer receives security patches.", projName, nodeVersion),
					"project", projID, projName,
					"Upgrade to a supported Node.js LTS version (18.x or 20.x).",
					map[string]string{"node_version": nodeVersion},
				))
			}
		}

		// Check: OIDC token config
		oidcConfig := mapVal(p["oidcTokenConfig"])
		if oidcConfig != nil {
			if !boolean(oidcConfig["enabled"]) {
				findings = append(findings, pass(
					"dep-009", "OIDC Token Config", catDeployment,
					fmt.Sprintf("Project '%s' has OIDC token configuration present.", projName),
					"project", projID, projName,
				))
			}
		}

		// Check: skew protection
		skewMaxAge := num(p["skewProtectionMaxAge"])
		if skewMaxAge == 0 {
			f := warn(
				"dep-010", "Skew Protection Not Configured", catDeployment, models.Low,
				2.0, "Operational consistency concern. No direct security impact but may cause unpredictable behavior during deployments.",
				fmt.Sprintf("Project '%s' does not have skew protection configured. Users may see inconsistent deployments during rollouts.", projName),
				"project", projID, projName,
				"Enable skew protection to ensure consistent deployment serving during updates.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v10/projects", p, []string{"name", "id", "skewProtectionMaxAge"}, "Project has no skew protection configured")}
			findings = append(findings, f)
		}

		// Check: CORS options allowlist
		optionsAllowlist := mapVal(p["optionsAllowlist"])
		if optionsAllowlist != nil {
			if paths, ok := optionsAllowlist["paths"].([]interface{}); ok {
				for _, pathItem := range paths {
					if pm, ok := pathItem.(map[string]interface{}); ok {
						pathVal := str(pm["value"])
						if pathVal == "*" || pathVal == "/**" {
							findings = append(findings, warn(
								"dep-011", "Wildcard CORS Allowlist", catDeployment, models.Medium,
								6.0, "Wildcard CORS allows any origin to make cross-origin requests, potentially enabling CSRF-like attacks or data exfiltration.",
								fmt.Sprintf("Project '%s' has a wildcard CORS options allowlist path: %s", projName, pathVal),
								"project", projID, projName,
								"Restrict CORS allowlist to specific paths that require cross-origin access.",
								map[string]string{"path": pathVal},
							))
						}
					}
				}
			}
		}

		// Check: serverless function region
		sfRegion := str(p["serverlessFunctionRegion"])
		if sfRegion == "" {
			f := warn(
				"dep-030", "Serverless Function Region Not Restricted", catDeployment, models.Low,
				4.0, "Unrestricted regions may violate data residency requirements and increase attack surface across geographies.",
				fmt.Sprintf("Project '%s' has no serverless function region restriction.", projName),
				"project", projID, projName,
				"Set a specific serverless function region for data residency and latency control.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v10/projects", p, []string{"name", "id", "serverlessFunctionRegion"}, "Project has no serverless function region restriction")}
			findings = append(findings, f)
		}

		// Check: function max duration
		if maxDuration := num(p["functionMaxDuration"]); maxDuration >= 900 {
			findings = append(findings, warn(
				"dep-031", "Functions Running Maximum Duration", catDeployment, models.Medium,
				5.0, "Long-running functions are more exploitable for SSRF, crypto mining, and resource abuse.",
				fmt.Sprintf("Project '%s' allows serverless functions to run for %.0f seconds.", projName, maxDuration),
				"project", projID, projName,
				"Reduce function max duration to the minimum needed for your workload.",
				map[string]string{"max_duration": fmt.Sprintf("%.0f", maxDuration)},
			))
		}

		// Check: directory listing
		if boolean(p["directoryListing"]) {
			findings = append(findings, fail(
				"dep-032", "Directory Listing Enabled", catDeployment, models.Medium,
				6.0, "Directory listing exposes file structure, potentially revealing hidden routes, config files, and API endpoints.",
				fmt.Sprintf("Project '%s' has directory listing enabled.", projName),
				"project", projID, projName,
				"Disable directory listing unless explicitly needed.",
				nil,
			))
		}

		// Check: skew protection excessively large
		if skewMaxAge > 604800 {
			findings = append(findings, warn(
				"dep-033", "Skew Protection Window Excessively Large", catDeployment, models.Low,
				3.0, "An excessively large skew window keeps old potentially vulnerable deployments serving traffic far too long.",
				fmt.Sprintf("Project '%s' has skew protection set to %.0f seconds (>7 days).", projName, skewMaxAge),
				"project", projID, projName,
				"Reduce skew protection window to a reasonable duration (e.g., 1 hour).",
				map[string]string{"skew_max_age": fmt.Sprintf("%.0f", skewMaxAge)},
			))
		}

		// Check: OIDC federation not configured
		if oidcConfig == nil || !boolean(oidcConfig["enabled"]) {
			findings = append(findings, warn(
				"dep-034", "No OIDC Federation Configured", catDeployment, models.Medium,
				5.0, "Without OIDC federation, serverless functions must use static credentials to access cloud providers, increasing credential leakage risk.",
				fmt.Sprintf("Project '%s' does not have OIDC token federation configured.", projName),
				"project", projID, projName,
				"Enable OIDC federation to eliminate static cloud provider credentials in serverless functions.",
				nil,
			))
		}
	}

	// Check recent deployments for public access
	deployments, err := c.ListDeployments("", 50)
	if err == nil {
		publicCount := 0
		for _, d := range deployments {
			visibility := str(d["visibility"])
			if visibility == "public" {
				publicCount++
			}
		}
		if publicCount > 0 {
			findings = append(findings, warn(
				"dep-020", "Public Deployments Detected", catDeployment, models.Medium,
				4.0, "Public deployments are accessible to anyone. Acceptable if intentional, but may expose staging or internal tools.",
				fmt.Sprintf("%d recent deployment(s) have public visibility.", publicCount),
				"deployment", "N/A", "N/A",
				"Review public deployments and ensure they are intentionally public.",
				map[string]string{"public_count": fmt.Sprintf("%d", publicCount)},
			))
		}
	}

	return findings
}
