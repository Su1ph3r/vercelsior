package checks

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/models"
)

const catIAM = "Identity & Access Management"

type IAMChecks struct{}

func (ic *IAMChecks) Name() string     { return "IAM" }
func (ic *IAMChecks) Category() string { return catIAM }

func (ic *IAMChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding
	findings = append(findings, ic.checkTokens(c)...)
	findings = append(findings, ic.checkTeams(c)...)
	findings = append(findings, ic.checkAccessGroups(c)...)
	return findings
}

func (ic *IAMChecks) checkTokens(c *client.Client) []models.Finding {
	var findings []models.Finding
	tokens, err := c.ListTokens()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"iam-001", "Token Enumeration — Insufficient Permissions", catIAM,
				"Cannot list tokens: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "iam-001", Title: "Token Enumeration", Category: catIAM,
				Severity: models.Info, Status: models.Error,
				Description: fmt.Sprintf("Failed to list tokens: %v", err),
				ResourceType: "token", ResourceID: "N/A",
			})
		}
		return findings
	}

	now := time.Now()
	for _, t := range tokens {
		id := str(t["id"])
		name := str(t["name"])
		if name == "" {
			name = id
		}

		// Check: token has no expiry
		expiresAt := t["expiresAt"]
		if expiresAt == nil || num(expiresAt) == 0 {
			f := fail(
				"iam-001", "Token Without Expiration", catIAM, models.High,
				8.0, "Long-lived tokens without expiry are a persistent credential that can be exploited indefinitely if compromised. Network-accessible with no complexity barrier.",
				fmt.Sprintf("Token '%s' has no expiration date set. Long-lived tokens increase the blast radius if compromised.", name),
				"token", id, name,
				"Set an expiration date on all API tokens. Rotate tokens regularly.",
				map[string]string{"token_name": name},
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v5/user/tokens", t, []string{"name", "id", "expiresAt", "createdAt", "activeAt"}, "Token has no expiration date")}
			findings = append(findings, f)
		} else {
			// Check if expired
			expTs := time.UnixMilli(int64(num(expiresAt)))
			if expTs.Before(now) {
				findings = append(findings, fail(
					"iam-002", "Expired Token Not Revoked", catIAM, models.Medium,
					5.0, "Expired tokens cannot be used but indicate poor credential hygiene. The token is already non-functional, limiting direct risk.",
					fmt.Sprintf("Token '%s' expired on %s but has not been deleted.", name, expTs.Format(time.RFC3339)),
					"token", id, name,
					"Delete expired tokens to reduce credential surface area.",
					map[string]string{"expired_at": expTs.Format(time.RFC3339)},
				))
			} else {
				findings = append(findings, pass(
					"iam-001", "Token Has Expiration", catIAM,
					fmt.Sprintf("Token '%s' expires on %s.", name, expTs.Format(time.RFC3339)),
					"token", id, name,
				))
			}
		}

		// Check: token was leaked
		if t["leakedAt"] != nil && num(t["leakedAt"]) > 0 {
			leakedURL := str(t["leakedUrl"])
			f := fail(
				"iam-003", "Leaked Token Detected", catIAM, models.Critical,
				10.0, "A confirmed credential leak with verified exposure URL. Attacker can use this token immediately with no barriers to exploitation.",
				fmt.Sprintf("Token '%s' was detected as leaked by Vercel. Leaked URL: %s", name, leakedURL),
				"token", id, name,
				"Immediately revoke this token and rotate all secrets it had access to. Investigate the leak source.",
				map[string]string{"leaked_url": leakedURL},
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v5/user/tokens", t, []string{"name", "id", "leakedAt", "leakedUrl"}, "Token was detected as leaked")}
			findings = append(findings, f)
		}

		// Check: token staleness (not used in 90 days)
		if activeAt := t["activeAt"]; activeAt != nil && num(activeAt) > 0 {
			lastActive := time.UnixMilli(int64(num(activeAt)))
			daysSince := int(now.Sub(lastActive).Hours() / 24)
			if daysSince > 90 {
				findings = append(findings, warn(
					"iam-004", "Stale Token", catIAM, models.Medium,
					5.0, "Unused tokens expand the credential surface area. While not directly exploitable, they represent unmonitored access paths.",
					fmt.Sprintf("Token '%s' has not been used in %d days.", name, daysSince),
					"token", id, name,
					"Review and revoke tokens that are no longer in use.",
					map[string]string{"days_inactive": fmt.Sprintf("%d", daysSince)},
				))
			}
		}

		// Check: token scope breadth — null/absent scopes means full access
		scopesVal := t["scopes"]
		isFullAccess := false
		if scopesVal == nil {
			isFullAccess = true
		} else if scopeArr, ok := scopesVal.([]interface{}); ok && len(scopeArr) == 0 {
			isFullAccess = true
		}
		if isFullAccess {
			f := warn(
				"iam-005", "Token With Full Access Scope", catIAM, models.High,
				8.0, "Unrestricted token scope means compromise grants full account control. Network-accessible and immediately exploitable.",
				fmt.Sprintf("Token '%s' has no scope restrictions (full access).", name),
				"token", id, name,
				"Apply least-privilege scopes to API tokens.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v5/user/tokens", t, []string{"name", "id", "scopes"}, "Token has no scope restrictions (full access)")}
			findings = append(findings, f)
		}
	}

	if len(tokens) == 0 {
		findings = append(findings, pass(
			"iam-001", "No API Tokens Found", catIAM,
			"No API tokens were found for this account.",
			"token", "N/A", "N/A",
		))
	}

	return findings
}

func (ic *IAMChecks) checkTeams(c *client.Client) []models.Finding {
	var findings []models.Finding
	teams, err := c.ListTeams()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"iam-010", "Team Check — Insufficient Permissions", catIAM,
				"Cannot list teams: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "iam-010", Title: "Team Check Failed", Category: catIAM,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list teams: %v", err),
				ResourceType: "team", ResourceID: "N/A",
			})
		}
		return findings
	}

	permSeen := make(map[string]bool)

	for _, teamSummary := range teams {
		teamID := str(teamSummary["id"])

		// Get full team details (list response lacks some fields)
		team, err := c.GetTeam(teamID)
		if err != nil {
			if IsPermissionDenied(err) && !permSeen["GetTeam"] {
				permSeen["GetTeam"] = true
				findings = append(findings, permissionFinding(
					"iam-010", "Team Detail Check — Insufficient Permissions", catIAM,
					"Cannot get team details: API token lacks required permissions. This check was skipped for all teams.",
				))
			}
			team = teamSummary // fallback to summary
		}
		if team == nil {
			team = teamSummary
		}

		teamName := str(team["name"])
		if teamName == "" {
			teamName = str(team["slug"])
		}

		teamAPIPath := fmt.Sprintf("/v2/teams/%s", teamID)

		// Check: SAML/SSO not configured
		saml := mapVal(team["saml"])
		if saml == nil {
			f := fail(
				"iam-010", "SSO/SAML Not Configured", catIAM, models.High,
				7.0, "Without SSO, there is no centralized authentication enforcement. Members may use weak passwords without MFA.",
				fmt.Sprintf("Team '%s' does not have SAML/SSO configured.", teamName),
				"team", teamID, teamName,
				"Enable SAML SSO for centralized identity management and enforce MFA through your identity provider.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, teamAPIPath, team, []string{"name", "slug", "saml"}, "Team has no SAML/SSO configured")}
			findings = append(findings, f)
		} else {
			// Check if SSO is enforced
			enforced := boolean(saml["enforced"])
			if !enforced {
				findings = append(findings, warn(
					"iam-011", "SSO Not Enforced", catIAM, models.Medium,
					6.0, "SSO exists but bypass is possible. Members can still authenticate with potentially weaker credentials.",
					fmt.Sprintf("Team '%s' has SSO configured but not enforced. Members can bypass SSO.", teamName),
					"team", teamID, teamName,
					"Enforce SSO to prevent members from using password-only authentication.",
					nil,
				))
			} else {
				findings = append(findings, pass(
					"iam-010", "SSO Configured and Enforced", catIAM,
					fmt.Sprintf("Team '%s' has SSO configured and enforced.", teamName),
					"team", teamID, teamName,
				))
			}
		}

		// Check: email domain auto-join
		if emailDomain := str(team["emailDomain"]); emailDomain != "" {
			findings = append(findings, warn(
				"iam-012", "Email Domain Auto-Join Enabled", catIAM, models.Medium,
				6.0, "Anyone with a matching email domain can join the team without approval. Compromised or disposable email accounts could gain access.",
				fmt.Sprintf("Team '%s' allows automatic joining for anyone with an @%s email.", teamName, emailDomain),
				"team", teamID, teamName,
				"Disable email domain auto-join and use explicit invitations or SSO for team membership.",
				map[string]string{"email_domain": emailDomain},
			))
		}

		// Check: active invite codes
		if inviteCode := str(team["inviteCode"]); inviteCode != "" {
			findings = append(findings, warn(
				"iam-013", "Active Invite Code", catIAM, models.Medium,
				5.0, "Invite codes can be shared beyond intended recipients. Lower risk since it requires the code to be leaked.",
				fmt.Sprintf("Team '%s' has an active invite code that could be shared.", teamName),
				"team", teamID, teamName,
				"Delete unused invite codes. Use direct invitations instead.",
				nil,
			))
		}

		// Check: sensitive environment variable policy
		policy := str(team["sensitiveEnvironmentVariablePolicy"])
		if policy == "" || policy == "off" {
			f := fail(
				"iam-014", "Sensitive Env Var Policy Not Enforced", catIAM, models.High,
				7.0, "Without policy enforcement, sensitive values can be stored insecurely or exposed to non-production environments.",
				fmt.Sprintf("Team '%s' does not enforce a sensitive environment variable policy.", teamName),
				"team", teamID, teamName,
				"Enable the sensitive environment variable policy to prevent accidental exposure of secrets.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, teamAPIPath, team, []string{"name", "slug", "sensitiveEnvironmentVariablePolicy"}, "Team does not enforce sensitive environment variable policy")}
			findings = append(findings, f)
		}

		// Check: IP address hiding
		if !boolean(team["hideIpAddresses"]) {
			f := warn(
				"iam-015", "IP Addresses Visible in Observability", catIAM, models.Low,
				3.0, "Privacy concern for GDPR compliance. No direct security exploitation path but may violate regulatory requirements.",
				fmt.Sprintf("Team '%s' does not hide IP addresses in observability data.", teamName),
				"team", teamID, teamName,
				"Enable IP address hiding for privacy compliance (GDPR, etc.).",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, teamAPIPath, team, []string{"name", "slug", "hideIpAddresses", "hideIpAddressesInLogDrains"}, "Team does not hide IP addresses in observability")}
			findings = append(findings, f)
		}

		if !boolean(team["hideIpAddressesInLogDrains"]) {
			f := warn(
				"iam-016", "IP Addresses Visible in Log Drains", catIAM, models.Low,
				3.0, "IP addresses in external log systems expand the data footprint. Privacy/compliance concern rather than direct security risk.",
				fmt.Sprintf("Team '%s' does not hide IP addresses in log drain output.", teamName),
				"team", teamID, teamName,
				"Enable IP address hiding in log drains for privacy compliance.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, teamAPIPath, team, []string{"name", "slug", "hideIpAddresses", "hideIpAddressesInLogDrains"}, "Team does not hide IP addresses in log drains")}
			findings = append(findings, f)
		}

		// Check team members for role distribution
		members, err := c.ListTeamMembers(teamID)
		if err != nil {
			if IsPermissionDenied(err) && !permSeen["ListTeamMembers"] {
				permSeen["ListTeamMembers"] = true
				findings = append(findings, permissionFinding(
					"iam-015", "Team Members Check — Insufficient Permissions", catIAM,
					"Cannot list team members: API token lacks required permissions. This check was skipped for all teams.",
				))
			}
		}
		if err == nil {
			ownerCount := 0
			for _, m := range members {
				role := str(m["role"])
				if role == "OWNER" {
					ownerCount++
				}
			}
			if ownerCount > 3 {
				findings = append(findings, warn(
					"iam-017", "Excessive Team Owners", catIAM, models.Medium,
					5.0, "More owners means more accounts that can make critical changes. Increases the attack surface for social engineering.",
					fmt.Sprintf("Team '%s' has %d owners. Excessive owners increase the risk of unauthorized configuration changes.", teamName, ownerCount),
					"team", teamID, teamName,
					"Reduce the number of team owners to a minimum necessary for operational needs.",
					map[string]string{"owner_count": fmt.Sprintf("%d", ownerCount)},
				))
			}
			if ownerCount == 1 {
				f := warn(
					"iam-018", "Single Team Owner", catIAM, models.Low,
					2.0, "Operational resilience concern. If the single owner account is compromised or locked, recovery is difficult.",
					fmt.Sprintf("Team '%s' has only 1 owner. This creates a single point of failure.", teamName),
					"team", teamID, teamName,
					"Add at least one additional owner for operational resilience.",
					map[string]string{"owner_count": "1"},
				)
				f.PocEvidence = []models.PocEvidence{buildEvidence(c, teamAPIPath, team, []string{"name", "slug", "id"}, "Team has only a single owner")}
				findings = append(findings, f)
			}

			// Check: long-tenured members with basic role (potential stale accounts)
			now := time.Now()
			for _, m := range members {
				memberUID := str(m["uid"])
				memberName := str(m["username"])
				if memberName == "" {
					memberName = str(m["email"])
				}
				if memberName == "" {
					memberName = memberUID
				}
				role := str(m["role"])
				if joinedAt := m["joinedAt"]; joinedAt != nil && num(joinedAt) > 0 {
					joined := time.UnixMilli(int64(num(joinedAt)))
					daysSinceJoin := int(now.Sub(joined).Hours() / 24)
					// Only flag MEMBER role accounts inactive for >365 days
					// Owners/admins are presumably active by virtue of their role
					if daysSinceJoin > 365 && role == "MEMBER" {
						findings = append(findings, warn(
							"iam-028", "Long-Tenured Member Account", catIAM, models.Low,
							3.0, "Member accounts that have existed for over a year with basic role may be stale. Cannot confirm activity via API — manual review recommended.",
							fmt.Sprintf("Team '%s': Member '%s' (role: %s) joined %d days ago.", teamName, memberName, role, daysSinceJoin),
							"team_member", memberUID, memberName,
							"Review long-tenured member accounts. Remove access for anyone who no longer needs it.",
							map[string]string{"days_since_join": fmt.Sprintf("%d", daysSinceJoin), "role": role},
						))
					}
				}
			}
		}
	}

	return findings
}

func (ic *IAMChecks) checkAccessGroups(c *client.Client) []models.Finding {
	var findings []models.Finding
	groups, err := c.ListAccessGroups()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"iam-020", "Access Group Check — Insufficient Permissions", catIAM,
				"Cannot list access groups: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "iam-020", Title: "Access Group Check Failed", Category: catIAM,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list access groups: %v", err),
				ResourceType: "access_group", ResourceID: "N/A",
			})
		}
		return findings
	}

	for _, g := range groups {
		gID := str(g["accessGroupId"])
		if gID == "" {
			gID = str(g["id"])
		}
		gName := str(g["name"])

		membersCount := int(num(g["membersCount"]))
		projectsCount := int(num(g["projectsCount"]))

		// Access group with broad access
		if membersCount > 50 && projectsCount > 10 {
			findings = append(findings, warn(
				"iam-020", "Large Access Group With Broad Project Access", catIAM, models.Medium,
				5.0, "Broad access groups weaken least-privilege. A compromised member account gains access to many projects simultaneously.",
				fmt.Sprintf("Access group '%s' has %d members with access to %d projects.", gName, membersCount, projectsCount),
				"access_group", gID, gName,
				"Review access group membership and project assignments. Apply least-privilege principles.",
				map[string]string{
					"members":  fmt.Sprintf("%d", membersCount),
					"projects": fmt.Sprintf("%d", projectsCount),
				},
			))
		}

		// Check: access group with admin role on many projects
		// We need to check individual project roles but that requires per-group API calls
		// For now, flag groups with very high project counts as a risk
		if projectsCount > 20 {
			findings = append(findings, warn(
				"iam-027", "Access Group With Very Broad Project Access", catIAM, models.High,
				8.0, "An access group spanning many projects means a compromised member account gains wide access. Violates least-privilege principle.",
				fmt.Sprintf("Access group '%s' has access to %d projects.", gName, projectsCount),
				"access_group", gID, gName,
				"Review access group project assignments. Consider splitting into smaller, more targeted groups.",
				map[string]string{"projects": fmt.Sprintf("%d", projectsCount)},
			))
		}
	}

	return findings
}
