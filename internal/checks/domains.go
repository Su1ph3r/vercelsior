package checks

import (
	"fmt"
	"time"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catDomains = "Domains & Certificates"

type DomainChecks struct{}

func (dc *DomainChecks) Name() string     { return "Domains" }
func (dc *DomainChecks) Category() string { return catDomains }

func (dc *DomainChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding
	findings = append(findings, dc.checkDomains(c)...)
	findings = append(findings, dc.checkProjectDomains(c)...)
	findings = append(findings, dc.checkDNS(c)...)
	return findings
}

func (dc *DomainChecks) checkDomains(c *client.Client) []models.Finding {
	var findings []models.Finding

	domains, err := c.ListDomains()
	if err != nil {
		return findings
	}

	now := time.Now()

	for _, d := range domains {
		name := str(d["name"])
		domainID := name

		// Check: domain verification
		verified := boolean(d["verified"])
		if !verified {
			findings = append(findings, fail(
				"dom-001", "Unverified Domain", catDomains, models.High,
				7.0, "Unverified domains can be claimed by attackers, enabling phishing or traffic interception on your brand's domain.",
				fmt.Sprintf("Domain '%s' is not verified. Unverified domains may not serve traffic correctly and could be claimed by others.", name),
				"domain", domainID, name,
				"Verify domain ownership through DNS TXT record or CNAME configuration.",
				nil,
			))
		} else {
			findings = append(findings, pass(
				"dom-001", "Domain Verified", catDomains,
				fmt.Sprintf("Domain '%s' is verified.", name),
				"domain", domainID, name,
			))
		}

		// Check: expiration (for registrar-managed domains)
		if expiresAt := d["expiresAt"]; expiresAt != nil && num(expiresAt) > 0 {
			expiry := time.UnixMilli(int64(num(expiresAt)))
			daysUntilExpiry := int(expiry.Sub(now).Hours() / 24)

			if daysUntilExpiry < 0 {
				findings = append(findings, fail(
					"dom-002", "Domain Expired", catDomains, models.Critical,
					10.0, "An expired domain can be re-registered by anyone. Attackers can take over the domain to intercept traffic, steal cookies, or phish users.",
					fmt.Sprintf("Domain '%s' expired %d days ago!", name, -daysUntilExpiry),
					"domain", domainID, name,
					"Renew the domain immediately to prevent domain takeover.",
					map[string]string{"expired_days_ago": fmt.Sprintf("%d", -daysUntilExpiry)},
				))
			} else if daysUntilExpiry < 30 {
				findings = append(findings, warn(
					"dom-003", "Domain Expiring Soon", catDomains, models.High,
					7.0, "Domain expires within 30 days. If not renewed, it becomes available for hostile registration and takeover.",
					fmt.Sprintf("Domain '%s' expires in %d days.", name, daysUntilExpiry),
					"domain", domainID, name,
					"Renew the domain or enable auto-renewal.",
					map[string]string{"days_until_expiry": fmt.Sprintf("%d", daysUntilExpiry)},
				))
			} else if daysUntilExpiry < 90 {
				findings = append(findings, warn(
					"dom-004", "Domain Expiring Within 90 Days", catDomains, models.Medium,
					4.0, "Domain expires within 90 days. Sufficient time to act but warrants attention to prevent accidental lapse.",
					fmt.Sprintf("Domain '%s' expires in %d days.", name, daysUntilExpiry),
					"domain", domainID, name,
					"Plan domain renewal. Enable auto-renewal if not already enabled.",
					map[string]string{"days_until_expiry": fmt.Sprintf("%d", daysUntilExpiry)},
				))
			}
		}

		// Check: auto-renew disabled (if field present)
		if renew, ok := d["renew"]; ok {
			if !boolean(renew) {
				findings = append(findings, warn(
					"dom-005", "Domain Auto-Renew Disabled", catDomains, models.Medium,
					5.0, "Without auto-renewal, human error or oversight can cause domain expiration, enabling takeover.",
					fmt.Sprintf("Domain '%s' does not have auto-renew enabled. The domain could expire and be taken over.", name),
					"domain", domainID, name,
					"Enable auto-renewal for all domains to prevent accidental expiration.",
					nil,
				))
			}
		}

		// Check: domain transfer lock (registrar-managed domains)
		if transferable, ok := d["transferable"]; ok {
			if boolean(transferable) {
				findings = append(findings, warn(
					"dom-031", "Domain Transfer Lock Not Enabled", catDomains, models.Medium,
					6.0, "Without transfer lock, an attacker with registrar access can transfer the domain away, enabling complete domain takeover.",
					fmt.Sprintf("Domain '%s' does not have transfer lock enabled.", name),
					"domain", domainID, name,
					"Enable domain transfer lock to prevent unauthorized domain transfers.",
					nil,
				))
			}
		}
		// Also check via serviceType or locked fields
		if locked, ok := d["locked"]; ok {
			if !boolean(locked) {
				findings = append(findings, warn(
					"dom-031", "Domain Transfer Lock Not Enabled", catDomains, models.Medium,
					6.0, "Without transfer lock, an attacker with registrar access can transfer the domain away, enabling complete domain takeover.",
					fmt.Sprintf("Domain '%s' is not locked against transfers.", name),
					"domain", domainID, name,
					"Enable domain transfer lock in your registrar settings.",
					nil,
				))
			}
		}

		// Check: domain config (misconfiguration)
		config, err := c.GetDomainConfig(name)
		if err == nil && config != nil {
			misconfigured := boolean(config["misconfigured"])
			if misconfigured {
				findings = append(findings, fail(
					"dom-006", "Domain Misconfigured", catDomains, models.High,
					6.0, "DNS misconfiguration may cause traffic routing failures or create conditions exploitable for subdomain takeover.",
					fmt.Sprintf("Domain '%s' has a DNS misconfiguration detected by Vercel.", name),
					"domain", domainID, name,
					"Check DNS records and ensure they point correctly to Vercel's infrastructure.",
					nil,
				))
			}
		}
	}

	return findings
}

func (dc *DomainChecks) checkProjectDomains(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		return findings
	}

	for _, p := range projects {
		projID := str(p["id"])
		projName := str(p["name"])

		domains, err := c.ListProjectDomains(projID)
		if err != nil {
			continue
		}

		if len(domains) == 0 {
			findings = append(findings, warn(
				"dom-010", "Project Has No Custom Domain", catDomains, models.Low,
				1.0, "Using only .vercel.app subdomains is not a security risk but limits branding and may indicate a non-production project.",
				fmt.Sprintf("Project '%s' has no custom domain configured. It is only accessible via the .vercel.app subdomain.", projName),
				"project", projID, projName,
				"Consider adding a custom domain for production use.",
				nil,
			))
		}

		for _, d := range domains {
			name := str(d["name"])

			// Check redirect configuration
			redirect := str(d["redirect"])
			redirectStatusCode := int(num(d["redirectStatusCode"]))
			if redirect != "" && redirectStatusCode == 301 {
				// 301 is fine, just informational
			} else if redirect != "" && redirectStatusCode != 301 && redirectStatusCode != 308 {
				findings = append(findings, warn(
					"dom-011", "Non-Permanent Domain Redirect", catDomains, models.Low,
					1.0, "Non-permanent redirects are an SEO and caching concern. Minimal security impact.",
					fmt.Sprintf("Project '%s': Domain '%s' uses a %d redirect instead of 301/308.", projName, name, redirectStatusCode),
					"project_domain", name, name,
					"Use 301 or 308 permanent redirects for domain canonicalization.",
					map[string]string{"status_code": fmt.Sprintf("%d", redirectStatusCode)},
				))
			}
		}
	}

	return findings
}

func (dc *DomainChecks) checkDNS(c *client.Client) []models.Finding {
	var findings []models.Finding

	domains, err := c.ListDomains()
	if err != nil {
		return findings
	}

	for _, d := range domains {
		name := str(d["name"])

		records, err := c.ListDNSRecords(name)
		if err != nil {
			continue
		}

		for _, r := range records {
			recType := str(r["type"])
			recName := str(r["name"])
			recValue := str(r["value"])
			recID := str(r["id"])

			// Check: wildcard A/AAAA records
			if (recType == "A" || recType == "AAAA") && recName == "*" {
				findings = append(findings, warn(
					"dom-020", "Wildcard DNS Record", catDomains, models.Medium,
					6.0, "Wildcard DNS records can create dangling subdomain vulnerabilities. Any unclaimed subdomain resolves, enabling potential takeover.",
					fmt.Sprintf("Domain '%s' has a wildcard %s record pointing to %s. Wildcard records can create dangling subdomain risks.", name, recType, recValue),
					"dns_record", recID, fmt.Sprintf("*.%s", name),
					"Review whether a wildcard DNS record is necessary. Use specific subdomains instead.",
					map[string]string{"record_type": recType, "value": recValue},
				))
			}

			// Check: CNAME on apex
			if recType == "CNAME" && (recName == "" || recName == "@") {
				findings = append(findings, warn(
					"dom-021", "CNAME Record on Apex Domain", catDomains, models.Low,
					2.0, "Technical DNS concern that can cause MX/TXT record conflicts. Indirect security impact through email delivery issues.",
					fmt.Sprintf("Domain '%s' has a CNAME record on the apex. This can cause issues with MX and TXT records.", name),
					"dns_record", recID, name,
					"Use an ALIAS or A record for the apex domain instead of CNAME.",
					map[string]string{"value": recValue},
				))
			}

			// Check: MX record pointing to generic/free providers (informational)
			if recType == "TXT" && recName == "_dmarc" {
				// DMARC is present -- good
				findings = append(findings, pass(
					"dom-022", "DMARC Record Present", catDomains,
					fmt.Sprintf("Domain '%s' has a DMARC record configured.", name),
					"dns_record", recID, name,
				))
			}
		}

		// Check: no SPF record
		hasSPF := false
		hasDMARC := false
		for _, r := range records {
			if str(r["type"]) == "TXT" {
				val := str(r["value"])
				if len(val) > 6 && val[:6] == "v=spf1" {
					hasSPF = true
				}
				if str(r["name"]) == "_dmarc" {
					hasDMARC = true
				}
			}
		}
		if !hasSPF && len(records) > 0 {
			findings = append(findings, warn(
				"dom-023", "No SPF Record", catDomains, models.Medium,
				5.0, "Without SPF, attackers can send email appearing to come from your domain. Enables phishing and social engineering.",
				fmt.Sprintf("Domain '%s' has no SPF record. This increases the risk of email spoofing.", name),
				"domain", name, name,
				"Add an SPF TXT record to prevent email spoofing.",
				nil,
			))
		}
		if !hasDMARC && len(records) > 0 {
			findings = append(findings, warn(
				"dom-024", "No DMARC Record", catDomains, models.Medium,
				5.0, "Without DMARC, email spoofing goes undetected and unreported. Attackers can impersonate your domain in phishing campaigns.",
				fmt.Sprintf("Domain '%s' has no DMARC record. This allows email spoofing to go undetected.", name),
				"domain", name, name,
				"Add a DMARC TXT record at _dmarc.%s to enable email authentication reporting.",
				nil,
			))
		}

		// Check: CAA record
		hasCAA := false
		for _, r := range records {
			if str(r["type"]) == "CAA" {
				hasCAA = true
				break
			}
		}
		if !hasCAA && len(records) > 0 {
			findings = append(findings, warn(
				"dom-030", "Domain Missing CAA Record", catDomains, models.Medium,
				5.0, "Without CAA, any Certificate Authority can issue certificates for your domain. CAA restricts issuance to authorized CAs only.",
				fmt.Sprintf("Domain '%s' has no CAA record. Any CA can issue certificates for this domain.", name),
				"domain", name, name,
				"Add a CAA DNS record to restrict which Certificate Authorities can issue certificates for your domain.",
				nil,
			))
		}

		// Check: DNSSEC
		hasDNSSEC := false
		for _, r := range records {
			recType := str(r["type"])
			if recType == "DNSKEY" || recType == "DS" {
				hasDNSSEC = true
				break
			}
		}
		if !hasDNSSEC && len(records) > 0 {
			findings = append(findings, warn(
				"dom-032", "DNSSEC Not Enabled", catDomains, models.Medium,
				4.0, "Without DNSSEC, DNS responses can be spoofed, redirecting users to attacker-controlled infrastructure.",
				fmt.Sprintf("Domain '%s' does not have DNSSEC enabled.", name),
				"domain", name, name,
				"Enable DNSSEC to protect against DNS spoofing attacks.",
				nil,
			))
		}
	}

	return findings
}
