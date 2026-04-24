package checks

import (
	"strings"

	"github.com/Su1ph3r/vercelsior/internal/models"
)

type RemediationEntry struct {
	PocVerification      string
	RemediationCommands  []models.RemediationCommand
	RemediationResources []models.RemediationResource
}

var remediationKB = map[string]RemediationEntry{
	"iam-001": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" https://api.vercel.com/v5/user/tokens | jq '.tokens[] | select(.expiresAt == null) | {name, id, createdAt}'`,
		RemediationCommands: []models.RemediationCommand{
			{Type: "api", Command: `curl -X DELETE -H "Authorization: Bearer $VERCEL_TOKEN" https://api.vercel.com/v3/user/tokens/{token_id}`, Description: "Delete the token without expiration"},
		},
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Token Management", URL: "https://vercel.com/docs/rest-api#creating-an-access-token", Type: "documentation"},
		},
	},
	"iam-003": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" https://api.vercel.com/v5/user/tokens | jq '.tokens[] | select(.leakedAt != null) | {name, leakedAt, leakedUrl}'`,
		RemediationCommands: []models.RemediationCommand{
			{Type: "api", Command: `curl -X DELETE -H "Authorization: Bearer $VERCEL_TOKEN" https://api.vercel.com/v3/user/tokens/{token_id}`, Description: "Immediately revoke the leaked token"},
		},
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Security Best Practices", URL: "https://vercel.com/docs/security", Type: "documentation"},
		},
	},
	"iam-010": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" https://api.vercel.com/v2/teams/{team_id} | jq '{saml, name}'`,
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel SAML SSO", URL: "https://vercel.com/docs/security/saml", Type: "documentation"},
		},
	},
	"iam-025": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" https://api.vercel.com/v2/teams/{team_id} | jq '{requireMfa, mfaEnforced}'`,
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel MFA", URL: "https://vercel.com/docs/security/multi-factor-authentication", Type: "documentation"},
		},
	},
	"fw-001": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v1/security/firewall/config/active?projectId={project_id}" | jq '.firewallEnabled'`,
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Web Application Firewall", URL: "https://vercel.com/docs/security/vercel-waf", Type: "documentation"},
			{Title: "Vercel Firewall API", URL: "https://vercel.com/docs/security/vercel-firewall/vercel-waf", Type: "documentation"},
		},
	},
	"fw-010": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v1/security/firewall/config/active?projectId={project_id}" | jq '.crs'`,
		RemediationCommands: []models.RemediationCommand{
			{Type: "console", Command: "In Vercel Dashboard > Project > Settings > Firewall, change OWASP rule action from 'Log' to 'Block'", Description: "Switch OWASP rules to block mode"},
		},
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel WAF Managed Rulesets", URL: "https://vercel.com/docs/security/vercel-waf/managed-rulesets", Type: "documentation"},
		},
	},
	"fw-002": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v1/security/firewall/config/active?projectId={project_id}" | jq '.firewallEnabled'`,
		RemediationCommands: []models.RemediationCommand{
			{Type: "api", Command: `curl -X PATCH -H "Authorization: Bearer $VERCEL_TOKEN" -H "Content-Type: application/json" -d '{"firewallEnabled":true}' "https://api.vercel.com/v1/security/firewall/config?projectId={project_id}"`, Description: "Enable the firewall"},
		},
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel WAF Configuration", URL: "https://vercel.com/docs/security/vercel-waf", Type: "documentation"},
		},
	},
	"sec-001": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v10/projects/{project_id}/env" | jq '.envs[] | select(.type == "plain") | {key, type, target}'`,
		RemediationCommands: []models.RemediationCommand{
			{Type: "cli", Command: `vercel env rm {env_key} production`, Description: "Remove the plain text variable"},
			{Type: "cli", Command: `vercel env add {env_key} production`, Description: "Re-add as encrypted (default type)"},
		},
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Environment Variables", URL: "https://vercel.com/docs/projects/environment-variables", Type: "documentation"},
		},
	},
	"sec-002": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v10/projects/{project_id}/env" | jq '.envs[] | select(.target | contains(["preview"])) | {key, type, target}'`,
		RemediationResources: []models.RemediationResource{
			{Title: "Environment Variable Targets", URL: "https://vercel.com/docs/projects/environment-variables#environments", Type: "documentation"},
		},
	},
	"sec-020": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v1/env" | jq '.data[] | select(.target | length == 3) | {key, target}'`,
		RemediationResources: []models.RemediationResource{
			{Title: "Environment Variable Best Practices", URL: "https://vercel.com/docs/projects/environment-variables", Type: "documentation"},
		},
	},
	"sec-026": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v10/projects/{project_id}/env" | jq '.envs[] | select(.key | test("^(VITE_|GATSBY_|REACT_APP_|NUXT_PUBLIC_)")) | {key, target, type}'`,
		RemediationCommands: []models.RemediationCommand{
			{Type: "console", Command: "Remove the client-exposure prefix from the env var name or use a server-only variable", Description: "Prevent client-side exposure of sensitive values"},
		},
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Environment Variables", URL: "https://vercel.com/docs/environment-variables", Type: "documentation"},
			{Title: "Next.js Environment Variables", URL: "https://nextjs.org/docs/app/building-your-application/configuring/environment-variables", Type: "documentation"},
		},
	},
	"njs-001": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v10/projects/{project_id}/env" | jq '.envs[] | select(.key | startswith("NEXT_PUBLIC_")) | {key, type, target}'`,
		RemediationCommands: []models.RemediationCommand{
			{Type: "cli", Command: `vercel env rm NEXT_PUBLIC_{sensitive_name}`, Description: "Remove the NEXT_PUBLIC_ prefixed secret"},
		},
		RemediationResources: []models.RemediationResource{
			{Title: "Next.js Environment Variables", URL: "https://nextjs.org/docs/app/building-your-application/configuring/environment-variables", Type: "documentation"},
			{Title: "Vercel NEXT_PUBLIC_ Warning", URL: "https://vercel.com/changelog/public-environment-variables-now-display-a-warning", Type: "blog"},
		},
	},
	"dep-001": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v9/projects/{project_id}" | jq '.gitForkProtection'`,
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Git Fork Protection", URL: "https://vercel.com/docs/security/deployment-protection/methods-to-bypass-deployment-protection", Type: "documentation"},
		},
	},
	"dep-004": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v9/projects/{project_id}" | jq '{passwordProtection, ssoProtection}'`,
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Deployment Protection", URL: "https://vercel.com/docs/security/deployment-protection", Type: "documentation"},
		},
	},
	"dep-008": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v9/projects/{project_id}" | jq '.nodeVersion'`,
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Node.js Version", URL: "https://vercel.com/docs/functions/runtimes/node-js", Type: "documentation"},
		},
	},
	"prev-001": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v9/projects/{project_id}" | jq '{passwordProtection, ssoProtection}'`,
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Deployment Protection", URL: "https://vercel.com/docs/security/deployment-protection", Type: "documentation"},
		},
	},
	"log-001": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v1/drains" | jq '.drains | length'`,
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Log Drains", URL: "https://vercel.com/docs/observability/log-drains", Type: "documentation"},
		},
	},
	"log-010": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v1/webhooks" | jq 'length'`,
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Webhooks", URL: "https://vercel.com/docs/observability/webhooks", Type: "documentation"},
		},
	},
	"log-024": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" https://api.vercel.com/v1/webhooks | jq '.[] | select(.secret == null or .secret == "") | {id, url}'`,
		RemediationCommands: []models.RemediationCommand{
			{Type: "console", Command: "Update webhook configuration in Vercel Dashboard > Settings > Webhooks to include a signing secret", Description: "Add a signing secret to the webhook"},
		},
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Webhooks", URL: "https://vercel.com/docs/webhooks", Type: "documentation"},
			{Title: "Securing Webhooks", URL: "https://vercel.com/docs/webhooks#securing-webhooks", Type: "documentation"},
		},
	},
	"dom-001": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v5/domains/{domain}" | jq '{verified, name}'`,
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Domain Verification", URL: "https://vercel.com/docs/projects/domains", Type: "documentation"},
		},
	},
	"dom-023": {
		PocVerification: `dig TXT {domain} +short | grep "v=spf1"`,
		RemediationResources: []models.RemediationResource{
			{Title: "SPF Record Setup", URL: "https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/", Type: "guide"},
		},
	},
	"dom-024": {
		PocVerification: `dig TXT _dmarc.{domain} +short`,
		RemediationResources: []models.RemediationResource{
			{Title: "DMARC Record Setup", URL: "https://www.cloudflare.com/learning/dns/dns-records/dns-dmarc-record/", Type: "guide"},
		},
	},
	"sto-003": {
		PocVerification: `dig +short {domain} A | grep -E "76\.76\.21\.(21|98)"`,
		RemediationCommands: []models.RemediationCommand{
			{Type: "console", Command: "Add the domain to your Vercel project or remove the A record from DNS", Description: "Prevent subdomain takeover via dangling A record"},
		},
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Custom Domains", URL: "https://vercel.com/docs/projects/domains", Type: "documentation"},
			{Title: "Subdomain Takeover Prevention", URL: "https://vercel.com/docs/security", Type: "documentation"},
		},
	},
	"sto-001": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v5/domains/{domain}/records" | jq '.records[] | select(.type == "CNAME" and (.value | contains("vercel")))'`,
		RemediationResources: []models.RemediationResource{
			{Title: "Subdomain Takeover Prevention", URL: "https://vercel.com/docs/projects/domains", Type: "documentation"},
		},
	},
	"route-004": {
		PocVerification: `curl -s -H "Authorization: Bearer $VERCEL_TOKEN" "https://api.vercel.com/v1/projects/{project_id}/routes" | jq '.routes[] | select(.dest | test("(localhost|127\\.0\\.0\\.1|169\\.254|10\\.|172\\.(1[6-9]|2[0-9]|3[01])|192\\.168)")) | {src, dest}'`,
		RemediationCommands: []models.RemediationCommand{
			{Type: "console", Command: "Remove or update the rewrite/redirect destination to use a public endpoint. For internal backends, use Vercel Secure Compute.", Description: "Eliminate SSRF risk from route configuration"},
		},
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Rewrites", URL: "https://vercel.com/docs/edge-network/rewrites", Type: "documentation"},
			{Title: "Vercel Secure Compute", URL: "https://vercel.com/docs/security/secure-compute", Type: "documentation"},
		},
	},
	"hdr-000": {
		PocVerification: `curl -sI https://{domain}`,
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Security Headers", URL: "https://vercel.com/docs/concepts/edge-network/headers#security-headers", Type: "documentation"},
		},
	},
	"hdr-001": {
		PocVerification: `curl -sI https://{domain} | grep -i content-security-policy`,
		RemediationCommands: []models.RemediationCommand{
			{Type: "config", Command: `// vercel.json\n{"headers":[{"source":"/(.*)", "headers":[{"key":"Content-Security-Policy","value":"default-src 'self'"}]}]}`, Description: "Add CSP header via vercel.json"},
		},
		RemediationResources: []models.RemediationResource{
			{Title: "Vercel Security Headers", URL: "https://vercel.com/docs/concepts/edge-network/headers#security-headers", Type: "documentation"},
			{Title: "CSP Reference", URL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", Type: "guide"},
		},
	},
	"hdr-002": {
		PocVerification: `curl -sI https://{domain} | grep -i strict-transport-security`,
		RemediationCommands: []models.RemediationCommand{
			{Type: "config", Command: `// vercel.json\n{"headers":[{"source":"/(.*)", "headers":[{"key":"Strict-Transport-Security","value":"max-age=31536000; includeSubDomains"}]}]}`, Description: "Add HSTS header via vercel.json"},
		},
		RemediationResources: []models.RemediationResource{
			{Title: "HSTS Reference", URL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security", Type: "guide"},
		},
	},
}

// GetRemediation returns the KB entry for a check ID, or nil if not found.
func GetRemediation(checkID string) *RemediationEntry {
	if entry, ok := remediationKB[checkID]; ok {
		return &entry
	}
	return nil
}

// EnrichFinding adds KB remediation data to a finding, substituting placeholders
// like {project_id}, {team_id}, {domain}, {token_id} with real values.
func EnrichFinding(f *models.Finding) {
	entry := GetRemediation(f.CheckID)
	if entry == nil {
		return
	}

	// Use project ID from Details if available (env-var-scoped findings store
	// the env var ID in ResourceID, not the project ID).
	projectID := f.ResourceID
	if pid, ok := f.Details["project_id"]; ok && pid != "" {
		projectID = pid
	}

	replacer := strings.NewReplacer(
		"{project_id}", projectID,
		"{team_id}", f.ResourceID,
		"{token_id}", f.ResourceID,
		"{domain}", f.ResourceName,
		"{resource_id}", f.ResourceID,
		"{env_key}", f.ResourceName,
		"{sensitive_name}", f.ResourceName,
	)

	if entry.PocVerification != "" && f.PocVerification == "" {
		f.PocVerification = replacer.Replace(entry.PocVerification)
	}
	if len(entry.RemediationCommands) > 0 && len(f.RemediationCommands) == 0 {
		cmds := make([]models.RemediationCommand, len(entry.RemediationCommands))
		for i, cmd := range entry.RemediationCommands {
			cmds[i] = models.RemediationCommand{
				Type:        cmd.Type,
				Command:     replacer.Replace(cmd.Command),
				Description: cmd.Description,
			}
		}
		f.RemediationCommands = cmds
	}
	if len(entry.RemediationResources) > 0 && len(f.RemediationResources) == 0 {
		f.RemediationResources = entry.RemediationResources
	}
}
