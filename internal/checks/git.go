package checks

import (
	"fmt"
	"strings"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catGit = "Git & Source Control"

type GitChecks struct{}

func (gc *GitChecks) Name() string     { return "Git" }
func (gc *GitChecks) Category() string { return catGit }

func (gc *GitChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding
	findings = append(findings, gc.checkProjects(c)...)
	findings = append(findings, gc.checkProtectedGitScopes(c)...)
	return findings
}

// checkProjects runs per-project git checks (git-001, git-003).
func (gc *GitChecks) checkProjects(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"git-001", "Git Check — Insufficient Permissions", catGit,
				"Cannot list projects: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "git-001", Title: "Git Check Failed", Category: catGit,
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

		link := mapVal(p["link"])
		if link == nil {
			continue
		}

		findings = append(findings, gc.checkPersonalAccount(link, projID, projName)...)
		findings = append(findings, gc.checkAutoDeploy(c, link, projID, projName)...)
	}

	return findings
}

// git-001: Git Repository Connected to Personal Account
func (gc *GitChecks) checkPersonalAccount(link map[string]interface{}, projID, projName string) []models.Finding {
	var findings []models.Finding

	linkType := strings.ToLower(str(link["type"]))
	if linkType != "github" && linkType != "gitlab" && linkType != "bitbucket" {
		return findings
	}

	// Try repoOwnerType first (common in Vercel's API response)
	ownerType := str(link["repoOwnerType"])
	org := str(link["org"])

	if ownerType != "" {
		if strings.EqualFold(ownerType, "User") {
			findings = append(findings, warn(
				"git-001", "Git Repository Connected to Personal Account", catGit, models.Medium,
				5.0, "Personal accounts lack organization-level security controls like branch protection, required reviews, and audit logs.",
				fmt.Sprintf("Project '%s' is linked to a personal %s account (owner type: %s).", projName, linkType, ownerType),
				"project", projID, projName,
				"Connect projects to organization-owned repositories for better security controls.",
				map[string]string{"link_type": linkType, "owner_type": ownerType},
			))
		} else {
			findings = append(findings, pass(
				"git-001", "Git Repository Connected to Organization", catGit,
				fmt.Sprintf("Project '%s' is linked to an organization-owned %s repository.", projName, linkType),
				"project", projID, projName,
			))
		}
	} else if org == "" {
		// No org field and no repoOwnerType — likely personal
		// Only flag if we have a repo but clearly no org association
		repoSlug := str(link["repoSlug"])
		if repoSlug != "" && !strings.Contains(repoSlug, "/") {
			// repoSlug without a slash and no org suggests personal account
			findings = append(findings, warn(
				"git-001", "Git Repository Connected to Personal Account", catGit, models.Medium,
				5.0, "Personal accounts lack organization-level security controls like branch protection, required reviews, and audit logs.",
				fmt.Sprintf("Project '%s' appears to be linked to a personal %s account (no organization detected).", projName, linkType),
				"project", projID, projName,
				"Connect projects to organization-owned repositories for better security controls.",
				map[string]string{"link_type": linkType},
			))
		}
		// If we can't determine, skip to avoid false positives
	}

	return findings
}

// git-003: Auto-Deploy Enabled on All Branches
func (gc *GitChecks) checkAutoDeploy(c *client.Client, link map[string]interface{}, projID, projName string) []models.Finding {
	var findings []models.Finding

	productionBranch := str(link["productionBranch"])
	if productionBranch == "" {
		// No production branch configured — can't evaluate deploy filtering
		return findings
	}

	// Check for deploy hooks — their presence doesn't mean filtering exists
	// Look for explicit deploy branch configuration
	deployBranch := str(link["deployBranch"])
	gitDeploy := link["gitDeploy"]

	// If there's a production branch but no deploy branch filtering,
	// all branches may trigger deployments
	if deployBranch == "" && gitDeploy == nil {
		f := warn(
			"git-003", "Auto-Deploy Enabled on All Branches", catGit, models.Medium,
			5.0, "Every branch push creates a deployment, including experimental branches with debug configs, disabled auth, or test backdoors.",
			fmt.Sprintf("Project '%s' has production branch '%s' set but no branch deploy filtering detected. All branches may trigger deployments.", projName, productionBranch),
			"project", projID, projName,
			"Configure branch deploy filtering to limit which branches trigger deployments.",
			map[string]string{"production_branch": productionBranch},
		)
		f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v10/projects", link, []string{"type", "productionBranch", "deployBranch", "gitDeploy"}, "Project has no branch deploy filtering configured")}
		findings = append(findings, f)
	} else {
		findings = append(findings, pass(
			"git-003", "Branch Deploy Filtering Configured", catGit,
			fmt.Sprintf("Project '%s' has branch deploy filtering configured.", projName),
			"project", projID, projName,
		))
	}

	return findings
}

// git-002: Protected Git Scopes Not Enforced
func (gc *GitChecks) checkProtectedGitScopes(c *client.Client) []models.Finding {
	var findings []models.Finding

	teams, err := c.ListTeams()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"git-002", "Protected Git Scopes Check — Insufficient Permissions", catGit,
				"Cannot list teams: API token lacks required permissions. This check was skipped.",
			))
		}
		return findings
	}

	permSeen := make(map[string]bool)

	for _, t := range teams {
		teamID := str(t["id"])
		teamName := str(t["name"])
		if teamName == "" {
			teamName = str(t["slug"])
		}

		// Fetch full team details to get configuration
		team, err := c.GetTeam(teamID)
		if err != nil {
			if IsPermissionDenied(err) && !permSeen["GetTeam"] {
				permSeen["GetTeam"] = true
				findings = append(findings, permissionFinding(
					"git-002", "Protected Git Scopes Check — Insufficient Permissions", catGit,
					"Cannot get team details: API token lacks required permissions. This check was skipped for all teams.",
				))
			}
			continue
		}
		if team == nil {
			continue
		}

		teamAPIPath := fmt.Sprintf("/v2/teams/%s", teamID)

		// Check for protectedGitScopes in team settings
		scopes := team["protectedGitScopes"]
		if scopes == nil {
			f := warn(
				"git-002", "Protected Git Scopes Not Enforced", catGit, models.Medium,
				6.0, "Without protected git scopes, developers can deploy repos to personal Vercel accounts outside team governance, bypassing all team-level security policies.",
				fmt.Sprintf("Team '%s' does not have protected git scopes configured. Developers may connect repositories outside team governance.", teamName),
				"team", teamID, teamName,
				"Configure protected git scopes at the team level to prevent unauthorized repository connections.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, teamAPIPath, team, []string{"name", "id", "protectedGitScopes"}, "Team has no protected git scopes configured")}
			findings = append(findings, f)
			continue
		}

		// Check if it's a slice/array and is empty
		if arr, ok := scopes.([]interface{}); ok && len(arr) == 0 {
			f := warn(
				"git-002", "Protected Git Scopes Not Enforced", catGit, models.Medium,
				6.0, "Without protected git scopes, developers can deploy repos to personal Vercel accounts outside team governance, bypassing all team-level security policies.",
				fmt.Sprintf("Team '%s' has an empty protected git scopes list. No repositories are restricted.", teamName),
				"team", teamID, teamName,
				"Configure protected git scopes at the team level to prevent unauthorized repository connections.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, teamAPIPath, team, []string{"name", "id", "protectedGitScopes"}, "Team has empty protected git scopes list")}
			findings = append(findings, f)
			continue
		}

		findings = append(findings, pass(
			"git-002", "Protected Git Scopes Configured", catGit,
			fmt.Sprintf("Team '%s' has protected git scopes configured.", teamName),
			"team", teamID, teamName,
		))
	}

	return findings
}
