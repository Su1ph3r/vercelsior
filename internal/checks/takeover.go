package checks

import (
	"fmt"
	"log"
	"strings"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catTakeover = "Subdomain Takeover"

var vercelIPs = map[string]bool{
	"76.76.21.21": true,
	"76.76.21.98": true,
}

type TakeoverChecks struct{}

func (tc *TakeoverChecks) Name() string     { return "Takeover" }
func (tc *TakeoverChecks) Category() string { return catTakeover }

func (tc *TakeoverChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	// Build a set of all project domains.
	projectDomains := tc.collectProjectDomains(c)
	if projectDomains == nil {
		findings = append(findings, permissionFinding(
			"sto-001", "Takeover Check — Insufficient Permissions",
			catTakeover,
			"Cannot list projects or their domains: API token may lack required permissions. Subdomain takeover checks were skipped to avoid false positives.",
		))
		return findings
	}

	findings = append(findings, tc.checkDanglingCNAME(c, projectDomains)...)
	findings = append(findings, tc.checkDanglingARecord(c, projectDomains)...)
	findings = append(findings, tc.checkOrphanedAliases(c, projectDomains)...)
	return findings
}

// collectProjectDomains returns a set of all domain names attached to projects.
func (tc *TakeoverChecks) collectProjectDomains(c *client.Client) map[string]bool {
	set := make(map[string]bool)

	projects, err := c.ListProjects()
	if err != nil {
		log.Printf("Warning: failed to list projects for takeover check: %v", err)
		return nil
	}

	for _, p := range projects {
		projID := str(p["id"])
		if projID == "" {
			continue
		}
		domains, err := c.ListProjectDomains(projID)
		if err != nil {
			continue
		}
		for _, d := range domains {
			name := str(d["name"])
			if name != "" {
				set[strings.ToLower(name)] = true
			}
		}
	}

	return set
}

// checkDanglingCNAME detects CNAME records pointing to Vercel that have no
// matching project domain (sto-001).
func (tc *TakeoverChecks) checkDanglingCNAME(c *client.Client, projectDomains map[string]bool) []models.Finding {
	var findings []models.Finding

	domains, err := c.ListDomains()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"sto-001", "Dangling CNAME Check — Insufficient Permissions", catTakeover,
				"Cannot list domains: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "sto-001", Title: "Takeover Check Failed", Category: catTakeover,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list domains: %v", err),
				ResourceType: "domain", ResourceID: "N/A",
			})
		}
		return findings
	}

	permSeen := make(map[string]bool)

	for _, d := range domains {
		domainName := str(d["name"])
		if domainName == "" {
			continue
		}

		records, err := c.ListDNSRecords(domainName)
		if err != nil {
			if IsPermissionDenied(err) && !permSeen["ListDNSRecords"] {
				permSeen["ListDNSRecords"] = true
				findings = append(findings, permissionFinding(
					"sto-001", "Dangling CNAME Check — Insufficient Permissions", catTakeover,
					"Cannot list DNS records: API token lacks required permissions. This check was skipped for all domains.",
				))
			}
			continue
		}

		for _, r := range records {
			if str(r["type"]) != "CNAME" {
				continue
			}

			recValue := strings.ToLower(str(r["value"]))
			if !strings.Contains(recValue, "vercel") {
				continue
			}

			recName := str(r["name"])
			var fqdn string
			if recName == "" || recName == "@" {
				fqdn = strings.ToLower(domainName)
			} else {
				fqdn = strings.ToLower(recName + "." + domainName)
			}

			recID := str(r["id"])

			if !projectDomains[fqdn] {
				findings = append(findings, fail(
					"sto-001", "Dangling CNAME to Vercel", catTakeover, models.Critical,
					9.0,
					"A DNS CNAME pointing to Vercel (cname.vercel-dns.com or similar) without a matching project domain can be claimed by any Vercel user, enabling phishing or cookie theft on the parent domain.",
					fmt.Sprintf("CNAME record '%s' (in domain '%s') points to '%s' but no Vercel project claims '%s'.", recName, domainName, str(r["value"]), fqdn),
					"dns_record", recID, fqdn,
					"Either add this subdomain to a Vercel project or remove the CNAME record pointing to Vercel.",
					map[string]string{"cname_target": str(r["value"]), "domain": domainName},
				))
			} else {
				findings = append(findings, pass(
					"sto-001", "CNAME to Vercel Claimed", catTakeover,
					fmt.Sprintf("CNAME record '%s' in domain '%s' points to Vercel and is claimed by a project.", recName, domainName),
					"dns_record", recID, fqdn,
				))
			}
		}
	}

	return findings
}

// checkDanglingARecord detects A records pointing to known Vercel IP addresses
// where the domain is not claimed by any project (sto-003).
func (tc *TakeoverChecks) checkDanglingARecord(c *client.Client, projectDomains map[string]bool) []models.Finding {
	var findings []models.Finding

	domains, err := c.ListDomains()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"sto-003", "A Record Check — Insufficient Permissions", catTakeover,
				"Cannot list domains: API token lacks required permissions. This check was skipped.",
			))
			return findings
		}
		findings = append(findings, models.Finding{
			CheckID: "sto-003", Title: "A Record Check Failed", Category: catTakeover,
			Severity: models.Info, Status: models.Error,
			Description:  fmt.Sprintf("Failed to list domains: %v", err),
			ResourceType: "domain", ResourceID: "N/A",
		})
		return findings
	}
	if len(domains) == 0 {
		return findings
	}

	permSeenA := make(map[string]bool)

	for _, d := range domains {
		domainName := str(d["name"])
		if domainName == "" {
			continue
		}

		records, err := c.ListDNSRecords(domainName)
		if err != nil {
			if IsPermissionDenied(err) && !permSeenA["ListDNSRecords"] {
				permSeenA["ListDNSRecords"] = true
				findings = append(findings, permissionFinding(
					"sto-003", "Dangling A Record Check — Insufficient Permissions", catTakeover,
					"Cannot list DNS records: API token lacks required permissions. This check was skipped for all domains.",
				))
			}
			continue
		}

		for _, r := range records {
			recType := str(r["type"])
			if recType != "A" && recType != "AAAA" {
				continue
			}

			recValue := strings.TrimSuffix(str(r["value"]), ".")
			if !vercelIPs[recValue] {
				continue
			}

			recName := str(r["name"])
			var fqdn string
			if recName == "" || recName == "@" {
				fqdn = strings.ToLower(domainName)
			} else {
				fqdn = strings.ToLower(recName + "." + domainName)
			}

			recID := str(r["id"])

			if !projectDomains[fqdn] {
				f := fail(
					"sto-003", "Dangling A Record Pointing to Vercel", catTakeover,
					models.Critical, 9.0,
					"An A record points to a Vercel IP address but no project claims this domain. An attacker could add this domain to their own Vercel project and serve malicious content.",
					fmt.Sprintf("Domain '%s' has an A record pointing to Vercel IP %s but is not configured in any project.", fqdn, recValue),
					"dns_record", recID, fqdn,
					"Either add the domain to the correct Vercel project or remove the DNS A record.",
					map[string]string{"record_type": recType, "record_value": recValue, "fqdn": fqdn},
				)
				f.PocEvidence = []models.PocEvidence{buildEvidence(c, fmt.Sprintf("/v4/domains/%s/records", domainName), r, []string{"id", "type", "name", "value"}, fmt.Sprintf("A record for '%s' points to Vercel IP %s but no project claims this domain", fqdn, recValue))}
				findings = append(findings, f)
			} else {
				findings = append(findings, pass(
					"sto-003", "A Record to Vercel Claimed", catTakeover,
					fmt.Sprintf("A record '%s' in domain '%s' points to Vercel IP %s and is claimed by a project.", recName, domainName, recValue),
					"dns_record", recID, fqdn,
				))
			}
		}
	}

	return findings
}

// checkOrphanedAliases detects aliases not linked to any active project domain (sto-002).
func (tc *TakeoverChecks) checkOrphanedAliases(c *client.Client, projectDomains map[string]bool) []models.Finding {
	var findings []models.Finding

	aliases, err := c.ListAliases()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"sto-002", "Orphaned Alias Check — Insufficient Permissions", catTakeover,
				"Cannot list aliases: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "sto-002", Title: "Orphaned Alias Check Failed", Category: catTakeover,
				Severity: models.Info, Status: models.Error,
				Description:  fmt.Sprintf("Failed to list aliases: %v", err),
				ResourceType: "alias", ResourceID: "N/A",
			})
		}
		return findings
	}

	for _, a := range aliases {
		aliasHostname := strings.ToLower(str(a["alias"]))
		if aliasHostname == "" {
			continue
		}

		aliasID := str(a["uid"])

		if !projectDomains[aliasHostname] {
			f := warn(
				"sto-002", "Orphaned Alias", catTakeover, models.High,
				7.0,
				"Aliases not linked to any active project domain may be claimable if DNS still resolves to Vercel, enabling subdomain takeover.",
				fmt.Sprintf("Alias '%s' is not associated with any active project domain.", aliasHostname),
				"alias", aliasID, aliasHostname,
				"Review orphaned aliases and remove any that are no longer needed. Ensure DNS records for removed aliases are also cleaned up.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v4/aliases", a, []string{"alias", "uid", "deployment", "createdAt"}, fmt.Sprintf("Alias '%s' exists but is not linked to any active project domain", aliasHostname))}
			findings = append(findings, f)
		} else {
			findings = append(findings, pass(
				"sto-002", "Alias Linked to Project", catTakeover,
				fmt.Sprintf("Alias '%s' is linked to an active project domain.", aliasHostname),
				"alias", aliasID, aliasHostname,
			))
		}
	}

	return findings
}
