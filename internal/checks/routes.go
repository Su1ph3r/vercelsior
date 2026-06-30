package checks

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/models"
)

const catRoutes = "Routes & Redirects"

// destHost extracts the lower-cased hostname from a rewrite/redirect destination,
// or "" if it cannot be parsed.
func destHost(dest string) string {
	parsed, err := url.Parse(dest)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// isMetadataDestination reports whether a destination points at a cloud
// instance-metadata endpoint. This is the genuinely dangerous subset of internal
// destinations: a rewrite that proxies to the metadata service can expose cloud
// credentials (SSRF to IMDS). It is kept separate from generic private/loopback
// destinations, which are usually a deliberate internal proxy rather than a vuln.
func isMetadataDestination(dest string) bool {
	host := destHost(dest)
	if host == "" {
		return false
	}
	if host == "metadata.google.internal" {
		return true
	}
	// Known instance-metadata IPs (AWS/GCP/Azure 169.254.169.254, Alibaba
	// 100.100.100.200) plus the whole link-local range where IMDS lives.
	if host == "169.254.169.254" || host == "100.100.100.200" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	// AWS IPv6 instance-metadata endpoint is a ULA (fd00:ec2::254), so it is not
	// link-local; match it by value to cover every textual form (compressed or
	// expanded). A proxy here is IMDS SSRF, not a benign internal proxy.
	if ip.Equal(awsIMDSv6) {
		return true
	}
	return ip.IsLinkLocalUnicast()
}

// awsIMDSv6 is AWS's IPv6 instance-metadata address (fd00:ec2::254).
var awsIMDSv6 = net.ParseIP("fd00:ec2::254")

// isPrivateDestination reports whether a destination points at a loopback or
// RFC-1918/ULA private address. Such a destination in a static, operator-authored
// route is typically an intentional internal proxy (e.g. Vercel Secure Compute),
// not an attacker-controlled SSRF, so callers should treat it as informational.
// Metadata endpoints are reported by isMetadataDestination instead.
func isPrivateDestination(dest string) bool {
	host := destHost(dest)
	if host == "" || host == "metadata.google.internal" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLinkLocalUnicast() || ip.Equal(awsIMDSv6) { // reported by isMetadataDestination
		return false
	}
	// Unspecified (0.0.0.0 / ::) routes to local/all interfaces on the host and is
	// neither loopback nor RFC-1918 by Go's classifiers, so include it explicitly.
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified()
}

type RouteChecks struct{}

func (r *RouteChecks) Name() string     { return "Routes" }
func (r *RouteChecks) Category() string { return catRoutes }

func (r *RouteChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"route-003", "Project Enumeration — Insufficient Permissions", catRoutes,
				"Cannot list projects: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "route-003", Title: "Project Enumeration", Category: catRoutes,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list projects: %v", err),
				ResourceType: "project", ResourceID: "N/A",
			})
		}
		return findings
	}

	permSeen := make(map[string]bool)

	for _, p := range projects {
		projID := str(p["id"])
		projName := str(p["name"])

		// route-001: Open Redirect in Bulk Redirects (per-project)
		redirects, err := c.ListBulkRedirects(projID)
		if err != nil {
			if IsPermissionDenied(err) {
				if !permSeen["ListBulkRedirects"] {
					permSeen["ListBulkRedirects"] = true
					findings = append(findings, permissionFinding(
						"route-001", "Bulk Redirects Check — Insufficient Permissions", catRoutes,
						"Cannot list bulk redirects: API token lacks required permissions. This check was skipped for all projects.",
					))
				}
			} else {
				findings = append(findings, apiErrorFinding(
					"route-001", "Bulk Redirects Check Failed", catRoutes,
					"project", projID, projName, err,
				))
			}
		}
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

				// A bulk redirect emits a client-side 3xx; the server never fetches
				// the destination, so a redirect to an internal/metadata address is
				// not SSRF. The SSRF check (route-004) is applied to rewrites/proxies
				// below, not here.
			}
		}

		// route-003: Rewrite Proxying to External Origin
		routes, err := c.ListProjectRoutes(projID)
		if err != nil {
			if IsPermissionDenied(err) && !permSeen["ListProjectRoutes"] {
				permSeen["ListProjectRoutes"] = true
				findings = append(findings, permissionFinding(
					"route-003", "Route Enumeration — Insufficient Permissions", catRoutes,
					"Cannot list project routes: API token lacks required permissions. This check was skipped for all projects.",
				))
			} else if !IsPermissionDenied(err) {
				findings = append(findings, models.Finding{
					CheckID: "route-003", Title: "Route Enumeration", Category: catRoutes,
					Severity: models.Info, Status: models.Error,
					Description:  fmt.Sprintf("Failed to list routes for project '%s': %v", projName, err),
					ResourceType: "project", ResourceID: projID, ResourceName: projName,
				})
			}
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

			// route-004: Rewrite Destination Points to Internal Target
			src := str(route["src"])
			if src == "" {
				src = str(route["source"])
			}
			if isMetadataDestination(dest) {
				findings = append(findings, fail(
					"route-004", "Rewrite Destination Points to Cloud Metadata", catRoutes,
					models.High, 8.0,
					"A rewrite/proxy whose destination is a cloud instance-metadata endpoint can be exploited for Server-Side Request Forgery (SSRF), exposing cloud credentials and internal instance data.",
					fmt.Sprintf("Project '%s': route destination '%s' points to a cloud metadata endpoint.", projName, dest),
					"project", projID, projName,
					"Remove the rewrite or change the destination to a public endpoint. A proxy to the metadata service is almost never intentional.",
					map[string]string{"destination": dest, "source": src},
				))
			} else if isPrivateDestination(dest) {
				findings = append(findings, warn(
					"route-007", "Rewrite Destination Points to a Private Address", catRoutes,
					models.Low, 3.0,
					"A rewrite/proxy to a loopback or RFC-1918 private address is usually a deliberate internal proxy (e.g. Vercel Secure Compute), but it is worth confirming the destination is intended and not reachable as an open proxy.",
					fmt.Sprintf("Project '%s': route destination '%s' points to a private/internal address.", projName, dest),
					"project", projID, projName,
					"Confirm this internal proxy is intentional. If internal access is required, prefer Vercel Secure Compute with restricted networking.",
					map[string]string{"destination": dest, "source": src},
				))
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
