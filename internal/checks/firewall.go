package checks

import (
	"fmt"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catFirewall = "Firewall & WAF"

type FirewallChecks struct{}

func (fc *FirewallChecks) Name() string     { return "Firewall" }
func (fc *FirewallChecks) Category() string { return catFirewall }

func (fc *FirewallChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"fw-001", "Project Enumeration — Insufficient Permissions", catFirewall,
				"Cannot list projects: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "fw-001", Title: "Project Enumeration", Category: catFirewall,
				Severity: models.Info, Status: models.Error,
				Description: fmt.Sprintf("Failed to list projects: %v", err),
				ResourceType: "project", ResourceID: "N/A",
			})
		}
		return findings
	}

	permSeen := make(map[string]bool)

	for _, p := range projects {
		projID := str(p["id"])
		projName := str(p["name"])

		fwConfig, err := c.GetFirewallConfig(projID)
		if err != nil {
			if IsPermissionDenied(err) && !permSeen["GetFirewallConfig"] {
				permSeen["GetFirewallConfig"] = true
				findings = append(findings, permissionFinding(
					"fw-001", "Firewall Check — Insufficient Permissions", catFirewall,
					"Cannot read firewall configuration: API token lacks required permissions. This check was skipped for all projects.",
				))
			}
			continue
		}
		if fwConfig == nil {
			f := fail(
				"fw-001", "Firewall Not Configured", catFirewall, models.High,
				8.0, "No WAF means all application traffic is uninspected. Common web attacks (SQLi, XSS) have no mitigation layer.",
				fmt.Sprintf("Project '%s' has no firewall/WAF configuration.", projName),
				"project", projID, projName,
				"Enable the Vercel Web Application Firewall for all production projects.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidenceRaw(
				fmt.Sprintf("/v1/security/firewall/config/active?projectId=%s", projID),
				404, `{"error":{"code":"not_found","message":"Config not found"}}`,
				"Firewall configuration endpoint returned 404, confirming no WAF is configured for this project.")}
			findings = append(findings, f)
			continue
		}

		// Check: firewall enabled
		if !boolean(fwConfig["firewallEnabled"]) {
			f := fail(
				"fw-002", "Firewall Disabled", catFirewall, models.High,
				8.0, "WAF exists but is turned off, leaving the application exposed to all web-based attacks without inspection.",
				fmt.Sprintf("Project '%s' has a firewall configuration but it is disabled.", projName),
				"project", projID, projName,
				"Enable the firewall in project security settings.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, fmt.Sprintf("/v1/security/firewall/config/active?projectId=%s", projID), fwConfig, []string{"firewallEnabled"}, "Firewall configuration exists but is disabled")}
			findings = append(findings, f)
		} else {
			findings = append(findings, pass(
				"fw-002", "Firewall Enabled", catFirewall,
				fmt.Sprintf("Project '%s' has the firewall enabled.", projName),
				"project", projID, projName,
			))
		}

		// Check: OWASP CRS rules
		crs := mapVal(fwConfig["crs"])
		if crs == nil {
			findings = append(findings, fail(
				"fw-003", "OWASP Core Rule Set Not Configured", catFirewall, models.High,
				7.0, "Missing OWASP CRS means no baseline protection against the most common web attack categories.",
				fmt.Sprintf("Project '%s' has no OWASP Core Rule Set (CRS) configuration.", projName),
				"project", projID, projName,
				"Enable OWASP CRS rules to protect against common web attacks (SQLi, XSS, RCE, etc.).",
				nil,
			))
		} else {
			owaspCategories := []struct {
				key  string
				name string
			}{
				{"sqli", "SQL Injection"},
				{"xss", "Cross-Site Scripting"},
				{"rce", "Remote Code Execution"},
				{"lfi", "Local File Inclusion"},
				{"rfi", "Remote File Inclusion"},
				{"gen", "General"},
				{"ma", "Multipart Attacks"},
				{"sf", "Session Fixation"},
				{"sd", "Scanner Detection"},
				{"php", "PHP Injection"},
				{"java", "Java Attacks"},
			}
			for _, cat := range owaspCategories {
				rule := mapVal(crs[cat.key])
				if rule == nil || !boolean(rule["enabled"]) {
					findings = append(findings, fail(
						fmt.Sprintf("fw-003-%s", cat.key), fmt.Sprintf("OWASP %s Rules Disabled", cat.name),
						catFirewall, models.High,
						7.0, "Disabling this OWASP category removes protection against a specific, well-known attack class that is actively exploited in the wild.",
						fmt.Sprintf("Project '%s': OWASP %s protection is disabled.", projName, cat.name),
						"project", projID, projName,
						fmt.Sprintf("Enable OWASP %s rules in the firewall CRS configuration.", cat.name),
						map[string]string{"rule_category": cat.key},
					))
				}
			}

			// fw-010: Check if enabled OWASP rules are in block mode
			for _, cat := range owaspCategories {
				rule := mapVal(crs[cat.key])
				if rule == nil || !boolean(rule["enabled"]) {
					continue // already flagged by fw-003
				}
				action := str(rule["action"])
				if action == "" {
					action = str(rule["mode"]) // fallback field name
				}
				if action != "block" {
					if action == "" {
						action = "unknown"
					}
					findings = append(findings, warn(
						"fw-010", "OWASP Rule in Detect-Only Mode", catFirewall,
						models.Medium, 5.0,
						"OWASP rules in detect or log mode provide visibility but do not block malicious requests. Attackers can still exploit vulnerabilities that the rules are designed to prevent.",
						fmt.Sprintf("Project '%s': OWASP %s rules are enabled but in '%s' mode instead of 'block'.", projName, cat.name, action),
						"project", projID, projName,
						"Change the OWASP rule action from detect/log to block for active protection.",
						map[string]string{"rule_category": cat.key, "current_action": action},
					))
				}
			}
		}

		// Check: managed rules
		managed := mapVal(fwConfig["managedRules"])
		if managed != nil {
			managedRuleSets := []struct {
				key       string
				name      string
				sev       models.Severity
				riskScore float64
				rationale string
			}{
				{"owasp", "OWASP Managed Rules", models.High, 7.0, "OWASP managed rules provide baseline protection against common web attacks. Disabling removes this safety net."},
				{"bot_protection", "Bot Protection", models.Medium, 5.0, "Bot protection mitigates automated attacks and scraping. Absence increases exposure to credential stuffing and DDoS."},
				{"ai_bots", "AI Bot Blocking", models.Low, 2.0, "AI bot blocking is a content protection measure. Low direct security impact but relevant for data scraping prevention."},
				{"vercel_ruleset", "Vercel Managed Ruleset", models.Medium, 5.0, "Vercel's managed ruleset includes platform-specific protections updated by Vercel's security team."},
			}
			for _, rs := range managedRuleSets {
				ruleSet := mapVal(managed[rs.key])
				if ruleSet == nil || !boolean(ruleSet["enabled"]) {
					findings = append(findings, warn(
						fmt.Sprintf("fw-004-%s", rs.key),
						fmt.Sprintf("Managed Rule: %s Disabled", rs.name),
						catFirewall, rs.sev,
						rs.riskScore, rs.rationale,
						fmt.Sprintf("Project '%s': %s is not enabled.", projName, rs.name),
						"project", projID, projName,
						fmt.Sprintf("Enable %s in managed rules.", rs.name),
						nil,
					))
				}
			}
		} else {
			findings = append(findings, fail(
				"fw-004", "No Managed Rules Configured", catFirewall, models.High,
				7.0, "No managed WAF rules means no automated protection from Vercel's threat intelligence updates.",
				fmt.Sprintf("Project '%s' has no managed WAF rules configured.", projName),
				"project", projID, projName,
				"Enable managed rules (OWASP, bot protection, Vercel ruleset) for baseline protection.",
				nil,
			))
		}

		// Check: custom rules
		if rules, ok := fwConfig["rules"].([]interface{}); ok {
			if len(rules) == 0 {
				findings = append(findings, warn(
					"fw-005", "No Custom WAF Rules", catFirewall, models.Low,
					3.0, "Custom rules provide application-specific protection like rate limiting. Their absence is a defense-in-depth gap, not a direct vulnerability.",
					fmt.Sprintf("Project '%s' has no custom WAF rules. Consider rate limiting and geo-blocking rules.", projName),
					"project", projID, projName,
					"Add custom rules for rate limiting, geo-blocking, or application-specific protections.",
					nil,
				))
			} else {
				findings = append(findings, pass(
					"fw-005", "Custom WAF Rules Present", catFirewall,
					fmt.Sprintf("Project '%s' has %d custom WAF rule(s).", projName, len(rules)),
					"project", projID, projName,
				))
			}
		}

		// Check: IP rules
		ipRules := mapVal(fwConfig["ips"])
		if ipRules != nil {
			if allows, ok := ipRules["allow"].([]interface{}); ok {
				for _, a := range allows {
					if am, ok := a.(map[string]interface{}); ok {
						cidr := str(am["ip"])
						// Check for overly broad CIDR
						if cidr == "0.0.0.0/0" || cidr == "::/0" {
							findings = append(findings, fail(
								"fw-006", "Overly Broad IP Allow Rule", catFirewall, models.Critical,
								9.0, "A 0.0.0.0/0 allow rule effectively disables IP-based access control. Any attacker on the internet bypasses IP restrictions.",
								fmt.Sprintf("Project '%s' has an IP allow rule for %s which permits all traffic.", projName, cidr),
								"project", projID, projName,
								"Restrict IP allow rules to specific trusted IP ranges.",
								map[string]string{"cidr": cidr},
							))
						}
					}
				}
			}
		}

		// Check: no rate limiting rules
		hasRateLimit := false
		if rules, ok := fwConfig["rules"].([]interface{}); ok {
			for _, rule := range rules {
				if rm, ok := rule.(map[string]interface{}); ok {
					action := str(rm["action"])
					if action == "rate_limit" || action == "rateLimit" {
						hasRateLimit = true
						break
					}
				}
			}
		}
		if !hasRateLimit {
			findings = append(findings, warn(
				"fw-009", "No Rate Limiting Rules", catFirewall, models.Medium,
				5.0, "Without rate limiting, APIs are vulnerable to brute-force attacks, credential stuffing, and resource exhaustion.",
				fmt.Sprintf("Project '%s' has no rate limiting rules configured in the WAF.", projName),
				"project", projID, projName,
				"Add rate limiting rules to protect authentication endpoints and API routes.",
				nil,
			))
		}

		// Check: bot identification
		if !boolean(fwConfig["botIdEnabled"]) {
			findings = append(findings, warn(
				"fw-007", "Bot Identification Disabled", catFirewall, models.Medium,
				4.0, "Without bot identification, automated malicious traffic cannot be distinguished from legitimate users for targeted blocking.",
				fmt.Sprintf("Project '%s' does not have bot identification enabled.", projName),
				"project", projID, projName,
				"Enable bot identification to detect and classify automated traffic.",
				nil,
			))
		}

		// Check: bypass rules
		bypass, bypassErr := c.GetFirewallBypass(projID)
		if bypassErr != nil {
			if IsPermissionDenied(bypassErr) && !permSeen["GetFirewallBypass"] {
				permSeen["GetFirewallBypass"] = true
				findings = append(findings, permissionFinding(
					"fw-020", "Firewall Bypass Check — Insufficient Permissions", catFirewall,
					"Cannot read firewall bypass rules: API token lacks required permissions. This check was skipped for all projects.",
				))
			}
		}
		if bypass != nil {
			if rules, ok := bypass["rules"].([]interface{}); ok && len(rules) > 0 {
				findings = append(findings, warn(
					"fw-008", "Firewall Bypass Rules Active", catFirewall, models.High,
					7.0, "Active bypass rules create holes in WAF coverage. Traffic matching bypass rules skips all security inspection.",
					fmt.Sprintf("Project '%s' has %d active firewall bypass rule(s). These allow traffic to skip WAF inspection.", projName, len(rules)),
					"project", projID, projName,
					"Review and remove unnecessary bypass rules. Bypass rules should be temporary and tightly scoped.",
					map[string]string{"bypass_count": fmt.Sprintf("%d", len(rules))},
				))
			}
		}
	}

	return findings
}
