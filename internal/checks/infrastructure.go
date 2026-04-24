package checks

import (
	"fmt"
	"strings"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/models"
)

const catInfra = "Infrastructure"

type InfrastructureChecks struct{}

func (ic *InfrastructureChecks) Name() string     { return "Infrastructure" }
func (ic *InfrastructureChecks) Category() string { return catInfra }

func (ic *InfrastructureChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding
	findings = append(findings, ic.checkSecureCompute(c)...)
	findings = append(findings, ic.checkEdgeConfig(c)...)
	findings = append(findings, ic.checkRemoteCaching(c)...)
	findings = append(findings, ic.checkAliases(c)...)
	findings = append(findings, ic.checkStaticIPs(c)...)
	return findings
}

func (ic *InfrastructureChecks) checkSecureCompute(c *client.Client) []models.Finding {
	var findings []models.Finding

	networks, err := c.ListSecureComputeNetworks()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"infra-001", "Secure Compute Check — Insufficient Permissions", catInfra,
				"Cannot list secure compute networks: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "infra-001", Title: "Secure Compute Check Failed", Category: catInfra,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list secure compute networks: %v", err),
				ResourceType: "network", ResourceID: "N/A",
			})
		}
		return findings
	}

	for _, net := range networks {
		netID := str(net["id"])
		netName := str(net["name"])
		if netName == "" {
			netName = netID
		}

		// Check: CIDR range breadth
		cidr := str(net["cidr"])
		if cidr != "" {
			// Very broad CIDR blocks
			parts := strings.Split(cidr, "/")
			if len(parts) == 2 {
				prefix := parts[1]
				if prefix == "8" || prefix == "16" {
					findings = append(findings, warn(
						"infra-001", "Overly Broad Secure Compute CIDR", catInfra, models.Medium,
						5.0, "A broad CIDR range exposes more internal services than necessary to the compute network, increasing lateral movement risk if compromised.",
						fmt.Sprintf("Secure Compute network '%s' has a broad CIDR range: %s", netName, cidr),
						"network", netID, netName,
						"Use a more restrictive CIDR range for the secure compute network.",
						map[string]string{"cidr": cidr},
					))
				}
			}
		}

		// Check: peering connections
		if peering, ok := net["peeringConnections"].([]interface{}); ok && len(peering) > 0 {
			findings = append(findings, warn(
				"infra-002", "VPC Peering Connections Present", catInfra, models.Medium,
				5.0, "VPC peering creates network-level trust relationships. Untrusted or over-permissive peers can access internal services.",
				fmt.Sprintf("Secure Compute network '%s' has %d VPC peering connection(s). Verify all peers are trusted.", netName, len(peering)),
				"network", netID, netName,
				"Audit all VPC peering connections to ensure they connect only to trusted networks.",
				map[string]string{"peering_count": fmt.Sprintf("%d", len(peering))},
			))
		}

		// Check: network status
		status := str(net["status"])
		if status != "" && status != "active" && status != "ACTIVE" {
			findings = append(findings, warn(
				"infra-003", "Secure Compute Network Not Active", catInfra, models.Medium,
				4.0, "A non-active network may indicate misconfiguration or degraded security posture for services depending on it.",
				fmt.Sprintf("Secure Compute network '%s' has status: %s", netName, status),
				"network", netID, netName,
				"Investigate why the network is not in an active state.",
				map[string]string{"status": status},
			))
		}
	}

	return findings
}

func (ic *InfrastructureChecks) checkEdgeConfig(c *client.Client) []models.Finding {
	var findings []models.Finding

	configs, err := c.ListEdgeConfigs()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"infra-010", "Edge Config Check — Insufficient Permissions", catInfra,
				"Cannot list edge configs: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "infra-010", Title: "Edge Config Check Failed", Category: catInfra,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list edge configs: %v", err),
				ResourceType: "edge_config", ResourceID: "N/A",
			})
		}
		return findings
	}

	permSeen := make(map[string]bool)

	for _, ec := range configs {
		ecID := str(ec["id"])
		ecSlug := str(ec["slug"])
		if ecSlug == "" {
			ecSlug = ecID
		}

		// Check tokens for this edge config
		tokens, err := c.ListEdgeConfigTokens(ecID)
		if err != nil {
			if IsPermissionDenied(err) && !permSeen["ListEdgeConfigTokens"] {
				permSeen["ListEdgeConfigTokens"] = true
				findings = append(findings, permissionFinding(
					"inf-005", "Edge Config Token Check — Insufficient Permissions", catInfra,
					"Cannot list edge config tokens: API token lacks required permissions. This check was skipped for all edge configs.",
				))
			}
			continue
		}

		if len(tokens) > 10 {
			findings = append(findings, warn(
				"infra-010", "Edge Config With Many Tokens", catInfra, models.Medium,
				4.0, "Excessive access tokens expand the credential surface. Each token is a potential compromise vector for Edge Config data.",
				fmt.Sprintf("Edge Config '%s' has %d access tokens. Excessive tokens increase the credential surface.", ecSlug, len(tokens)),
				"edge_config", ecID, ecSlug,
				"Review and revoke unnecessary Edge Config tokens.",
				map[string]string{"token_count": fmt.Sprintf("%d", len(tokens))},
			))
		}

		// Check: edge config name suggests sensitive content
		ecName := ecSlug
		sensitivePatterns := []string{"secret", "key", "token", "password", "credential", "auth", "api-key"}
		for _, pattern := range sensitivePatterns {
			if strings.Contains(strings.ToLower(ecName), pattern) {
				findings = append(findings, warn(
					"infra-041", "Edge Config May Contain Secrets", catInfra, models.High,
					7.0, "Edge Config items are readable at the edge with a connection string. Secrets stored here bypass encryption-at-rest protections available for environment variables.",
					fmt.Sprintf("Edge Config '%s' has a name suggesting it may contain sensitive data.", ecSlug),
					"edge_config", ecID, ecSlug,
					"Store secrets in encrypted environment variables, not Edge Config. Edge Config is designed for non-sensitive runtime configuration.",
					nil,
				))
				break
			}
		}

		// Check: edge config item count (might contain sensitive data)
		if itemCount := num(ec["itemCount"]); itemCount > 1000 {
			findings = append(findings, warn(
				"infra-011", "Large Edge Config", catInfra, models.Low,
				2.0, "Large configs are harder to audit for sensitive data. Low direct risk but increases the chance of unnoticed secret leakage.",
				fmt.Sprintf("Edge Config '%s' has %.0f items. Large configs may contain sensitive data and are harder to audit.", ecSlug, itemCount),
				"edge_config", ecID, ecSlug,
				"Review Edge Config contents for sensitive data. Consider splitting large configs.",
				map[string]string{"item_count": fmt.Sprintf("%.0f", itemCount)},
			))
		}
	}

	return findings
}

func (ic *InfrastructureChecks) checkRemoteCaching(c *client.Client) []models.Finding {
	var findings []models.Finding

	status, err := c.GetArtifactsStatus()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"inf-020", "Remote Caching Check — Insufficient Permissions", catInfra,
				"Cannot check artifacts status: API token lacks required permissions. This check was skipped.",
			))
		}
		return findings
	}
	if status == nil {
		return findings
	}

	cacheStatus := str(status["status"])
	if cacheStatus == "enabled" {
		f := warn(
			"infra-020", "Remote Caching Enabled", catInfra, models.Low,
			2.0, "Cached build artifacts could contain build-time secrets or sensitive output. Low risk if build hygiene is good.",
			"Remote caching is enabled. Cached build artifacts may contain sensitive build-time data.",
			"remote_cache", "N/A", "N/A",
			"Review remote caching configuration. Ensure cached artifacts don't contain secrets or sensitive build output.",
			nil,
		)
		f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v8/artifacts/status", status, []string{"status"}, "Remote caching is enabled")}
		findings = append(findings, f)
	}

	return findings
}

func (ic *InfrastructureChecks) checkAliases(c *client.Client) []models.Finding {
	var findings []models.Finding

	aliases, err := c.ListAliases()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"infra-030", "Alias Check — Insufficient Permissions", catInfra,
				"Cannot list aliases: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "infra-030", Title: "Alias Check Failed", Category: catInfra,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list aliases: %v", err),
				ResourceType: "alias", ResourceID: "N/A",
			})
		}
		return findings
	}

	for _, a := range aliases {
		aliasID := str(a["uid"])
		if aliasID == "" {
			aliasID = str(a["id"])
		}
		aliasName := str(a["alias"])

		// Check: alias with protection bypass
		protBypass := mapVal(a["protectionBypass"])
		if protBypass != nil && len(protBypass) > 0 {
			findings = append(findings, warn(
				"infra-030", "Alias With Protection Bypass", catInfra, models.High,
				7.0, "Protection bypass on an alias allows unauthenticated access to a deployment that should be protected. Circumvents access controls.",
				fmt.Sprintf("Alias '%s' has protection bypass rules that allow unauthenticated access.", aliasName),
				"alias", aliasID, aliasName,
				"Review and remove unnecessary alias protection bypass rules.",
				map[string]string{"bypass_count": fmt.Sprintf("%d", len(protBypass))},
			))
		}
	}

	return findings
}

func (ic *InfrastructureChecks) checkStaticIPs(c *client.Client) []models.Finding {
	var findings []models.Finding
	projects, err := c.ListProjects()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"infra-040", "Static IP Check — Insufficient Permissions", catInfra,
				"Cannot list projects: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "infra-040", Title: "Static IP Check Failed", Category: catInfra,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list projects: %v", err),
				ResourceType: "project", ResourceID: "N/A",
			})
		}
		return findings
	}
	permSeenStatic := make(map[string]bool)

	for _, p := range projects {
		projID := str(p["id"])
		projName := str(p["name"])
		staticIps := mapVal(p["staticIps"])
		if staticIps == nil {
			// Check if project connects to external backends that might need IP allowlisting
			// Simple heuristic: if project has env vars suggesting backend connections, flag it
			envVars, err := c.ListProjectEnvVars(projID)
			if err != nil {
				if IsPermissionDenied(err) {
					if !permSeenStatic["ListProjectEnvVars"] {
						permSeenStatic["ListProjectEnvVars"] = true
						// Canonical infra-040 (not the legacy inf-030 typo).
						// Legacy configs still match via config.canonicalCheckID.
						findings = append(findings, permissionFinding(
							"infra-040", "Static IP Check — Insufficient Permissions", catInfra,
							"Cannot list project environment variables: API token lacks required permissions. This check was skipped for all projects.",
						))
					}
				} else if !permSeenStatic["ListProjectEnvVars_err"] {
					permSeenStatic["ListProjectEnvVars_err"] = true
					findings = append(findings, apiErrorFinding(
						"infra-040", "Static IP Check Failed", catInfra,
						"project", projID, projName, err,
					))
				}
				continue
			}
			hasBackendURL := false
			for _, env := range envVars {
				key := str(env["key"])
				upper := strings.ToUpper(key)
				if strings.Contains(upper, "DATABASE_URL") || strings.Contains(upper, "DB_URL") ||
					strings.Contains(upper, "REDIS_URL") || strings.Contains(upper, "API_URL") ||
					strings.Contains(upper, "BACKEND_URL") {
					hasBackendURL = true
					break
				}
			}
			if hasBackendURL {
				findings = append(findings, warn(
					"infra-040", "No Static IP for Egress", catInfra, models.Low,
					4.0, "Without static IPs, backend services cannot use IP allowlisting for Vercel traffic. Your backends must accept the full Vercel egress IP range.",
					fmt.Sprintf("Project '%s' appears to connect to backend services but has no static IP configured.", projName),
					"project", projID, projName,
					"Configure static IPs for projects that connect to IP-restricted backend services.",
					nil,
				))
			}
		}
	}
	return findings
}
