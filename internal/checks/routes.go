package checks

import (
	"fmt"
	"strings"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catRoutes = "Routes & Redirects"

type RouteChecks struct{}

func (r *RouteChecks) Name() string     { return "Routes" }
func (r *RouteChecks) Category() string { return catRoutes }

func (r *RouteChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		findings = append(findings, models.Finding{
			CheckID: "route-003", Title: "Project Enumeration", Category: catRoutes,
			Severity: models.Info, Status: models.Error,
			Description:  fmt.Sprintf("Failed to list projects: %v", err),
			ResourceType: "project", ResourceID: "N/A",
		})
		return findings
	}

	for _, p := range projects {
		projID := str(p["id"])
		projName := str(p["name"])

		// route-001: Open Redirect in Bulk Redirects (per-project)
		redirects, err := c.ListBulkRedirects(projID)
		if err == nil {
			for _, redir := range redirects {
				redirID := str(redir["id"])
				source := str(redir["source"])
				destination := str(redir["destination"])
				displayName := source
				if displayName == "" {
					displayName = redirID
				}

				isOpenRedirect := false
				// Only flag as open redirect if destination uses captured groups/variables
				// that could be attacker-controlled
				hasVariable := strings.Contains(destination, "$") ||
					strings.Contains(destination, ":splat") ||
					strings.Contains(destination, ":path") ||
					strings.Contains(destination, ":match")
				isExternal := strings.HasPrefix(destination, "http://") || strings.HasPrefix(destination, "https://")

				if hasVariable && isExternal {
					// Redirect with captured groups going to external URL = open redirect risk
					isOpenRedirect = true
				}

				if isOpenRedirect {
					findings = append(findings, fail(
						"route-001", "Open Redirect in Bulk Redirects", catRoutes,
						models.High, 8.0,
						"Open redirects allow attackers to craft URLs on your trusted domain that redirect to malicious sites, enabling phishing.",
						fmt.Sprintf("Bulk redirect from '%s' to '%s' may be an open redirect.", source, destination),
						"redirect", redirID, displayName,
						"Review bulk redirects for open redirect vulnerabilities. Avoid redirecting to user-controllable destinations.",
						map[string]string{"source": source, "destination": destination, "project": projName},
					))
				} else {
					findings = append(findings, pass(
						"route-001", "Bulk Redirect Safe", catRoutes,
						fmt.Sprintf("Bulk redirect from '%s' to '%s' appears safe.", source, destination),
						"redirect", redirID, displayName,
					))
				}
			}
		}

		// route-003: Rewrite Proxying to External Origin
		routes, err := c.ListProjectRoutes(projID)
		if err != nil {
			findings = append(findings, models.Finding{
				CheckID: "route-003", Title: "Route Enumeration", Category: catRoutes,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list routes for project '%s': %v", projName, err),
				ResourceType: "project", ResourceID: projID, ResourceName: projName,
			})
			continue
		}

		for _, route := range routes {
			routeID := str(route["id"])
			if routeID == "" {
				routeID = str(route["src"])
			}

			// Check dest or destination field for external URLs
			dest := str(route["dest"])
			if dest == "" {
				dest = str(route["destination"])
			}

			if dest == "" {
				continue
			}

			if strings.HasPrefix(dest, "http://") || strings.HasPrefix(dest, "https://") {
				findings = append(findings, warn(
					"route-003", "Rewrite Proxying to External Origin", catRoutes,
					models.Medium, 6.0,
					"Rewrites that proxy to external origins turn your deployment into an open proxy, enabling SSRF and IP laundering.",
					fmt.Sprintf("Project '%s' has a route rewriting to external origin: %s", projName, dest),
					"route", routeID, str(route["src"]),
					"Review rewrite rules proxying to external origins. Ensure they are necessary and properly restricted.",
					map[string]string{"project": projName, "destination": dest},
				))
			}

			// Check: wildcard route matching external paths
			src := str(route["src"])
			if src == "" {
				src = str(route["source"])
			}
			if src != "" && (strings.Contains(src, "(.*)") || strings.Contains(src, "/:path*") || strings.Contains(src, "/:splat")) {
				if dest != "" && (strings.HasPrefix(dest, "http://") || strings.HasPrefix(dest, "https://")) {
					findings = append(findings, fail(
						"route-002", "Wildcard Route Proxying to External Origin", catRoutes, models.High,
						7.0, "Wildcard routes that proxy to external origins can be exploited for SSRF, enabling attackers to route arbitrary requests through your domain.",
						fmt.Sprintf("Route pattern '%s' proxies wildcard traffic to external destination '%s'.", src, dest),
						"route", str(route["id"]), src,
						"Restrict wildcard route patterns. Avoid proxying user-controllable paths to external origins.",
						map[string]string{"source": src, "destination": dest},
					))
				}
			}
		}
	}

	return findings
}
