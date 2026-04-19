package checks

import (
	"fmt"
	"strings"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/models"
)

const catLogging = "Logging & Monitoring"

type LoggingChecks struct{}

func (lc *LoggingChecks) Name() string     { return "Logging" }
func (lc *LoggingChecks) Category() string { return catLogging }

func (lc *LoggingChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding
	findings = append(findings, lc.checkLogDrains(c)...)
	findings = append(findings, lc.checkWebhooks(c)...)
	return findings
}

func (lc *LoggingChecks) checkLogDrains(c *client.Client) []models.Finding {
	var findings []models.Finding

	drains, err := c.ListLogDrains()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"log-001", "Log Drain Enumeration — Insufficient Permissions", catLogging,
				"Cannot list log drains: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "log-001", Title: "Log Drain Enumeration", Category: catLogging,
				Severity: models.Info, Status: models.Error,
				Description: fmt.Sprintf("Failed to list log drains: %v", err),
				ResourceType: "log_drain", ResourceID: "N/A",
			})
		}
		return findings
	}

	// Check: no log drains configured
	if len(drains) == 0 {
		f := fail(
			"log-001", "No Log Drains Configured", catLogging, models.High,
			7.0, "Without centralized logging, security incidents cannot be detected, investigated, or correlated. Blind spot for incident response.",
			"No log drains are configured. Application logs are not being sent to a centralized logging system.",
			"log_drain", "N/A", "N/A",
			"Configure at least one log drain to send logs to a centralized logging/SIEM platform (Datadog, Splunk, etc.).",
			nil,
		)
		f.PocEvidence = []models.PocEvidence{buildEvidenceRaw("/v1/drains", 200, `[]`, "Log drains API returned an empty array, confirming no log drains are configured.")}
		findings = append(findings, f)
		return findings
	}

	findings = append(findings, pass(
		"log-001", "Log Drains Configured", catLogging,
		fmt.Sprintf("%d log drain(s) configured.", len(drains)),
		"log_drain", "N/A", "N/A",
	))

	for _, drain := range drains {
		drainID := str(drain["id"])
		drainName := str(drain["name"])
		if drainName == "" {
			drainName = drainID
		}
		endpoint := str(drain["url"])
		if endpoint == "" {
			endpoint = str(drain["endpoint"])
		}

		// Check: HTTP (not HTTPS) endpoint
		if strings.HasPrefix(endpoint, "http://") {
			findings = append(findings, fail(
				"log-002", "Log Drain Using HTTP", catLogging, models.High,
				8.0, "Logs sent over HTTP can be intercepted in transit, exposing application data, user info, and potentially secrets logged accidentally.",
				fmt.Sprintf("Log drain '%s' sends logs over unencrypted HTTP to %s.", drainName, endpoint),
				"log_drain", drainID, drainName,
				"Change the log drain endpoint to use HTTPS for encrypted transport.",
				map[string]string{"endpoint": endpoint},
			))
		} else {
			findings = append(findings, pass(
				"log-002", "Log Drain Using HTTPS", catLogging,
				fmt.Sprintf("Log drain '%s' uses encrypted transport.", drainName),
				"log_drain", drainID, drainName,
			))
		}

		// Check: drain status
		status := str(drain["status"])
		if status == "errored" || status == "disabled" {
			findings = append(findings, fail(
				"log-003", "Log Drain Not Operational", catLogging, models.High,
				7.0, "A broken log drain means logs are silently lost. Security events go unrecorded, creating gaps in audit trails and incident detection.",
				fmt.Sprintf("Log drain '%s' has status: %s. Logs are not being delivered.", drainName, status),
				"log_drain", drainID, drainName,
				"Investigate and fix the log drain configuration. Test delivery with the drain test endpoint.",
				map[string]string{"status": status},
			))
		}
	}

	return findings
}

func (lc *LoggingChecks) checkWebhooks(c *client.Client) []models.Finding {
	var findings []models.Finding

	webhooks, err := c.ListWebhooks()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"log-010", "Webhooks Check — Insufficient Permissions", catLogging,
				"Cannot list webhooks: API token lacks required permissions. This check was skipped.",
			))
		}
		return findings
	}

	if len(webhooks) == 0 {
		f := warn(
			"log-010", "No Webhooks Configured", catLogging, models.Medium,
			4.0, "Without webhooks, security events like firewall attacks or env var changes require manual dashboard monitoring instead of automated alerting.",
			"No webhooks are configured. Consider webhooks for security event notifications (firewall events, env var changes, etc.).",
			"webhook", "N/A", "N/A",
			"Configure webhooks for security-relevant events: firewall.attack, project.env-variable.created, domain.certificate.expired.",
			nil,
		)
		f.PocEvidence = []models.PocEvidence{buildEvidenceRaw("/v1/webhooks", 200, `[]`, "Webhooks API returned an empty array, confirming no webhooks are configured.")}
		findings = append(findings, f)
		return findings
	}

	securityEvents := map[string]bool{
		"firewall.attack":                    false,
		"firewall.system-rule-anomaly":       false,
		"firewall.custom-rule-anomaly":       false,
		"project.env-variable.created":       false,
		"project.env-variable.updated":       false,
		"project.env-variable.deleted":       false,
		"domain.certificate.expired":         false,
		"budget.reached":                         false,
		"edge-config.items.updated":              false,
		"integration-configuration.permission-upgraded": false,
	}

	for _, wh := range webhooks {
		whID := str(wh["id"])
		whURL := str(wh["url"])

		// Check: webhook using HTTP
		if strings.HasPrefix(whURL, "http://") {
			findings = append(findings, fail(
				"log-011", "Webhook Using HTTP", catLogging, models.High,
				8.0, "Security event payloads sent over HTTP can be intercepted. Webhook secrets and event data are exposed to network-level attackers.",
				fmt.Sprintf("Webhook '%s' sends events over unencrypted HTTP.", whID),
				"webhook", whID, whID,
				"Change the webhook URL to use HTTPS.",
				map[string]string{"url": whURL},
			))
		}

		// Check for missing webhook signing secret
		secret := str(wh["secret"])
		if secret == "" {
			findings = append(findings, warn(
				"log-024", "Webhook Missing Signing Secret", catLogging,
				models.Medium, 5.0,
				"Without a webhook secret, the x-vercel-signature HMAC header cannot be validated, allowing anyone who discovers the endpoint URL to forge webhook deliveries.",
				fmt.Sprintf("Webhook '%s' does not have a signing secret configured.", whID),
				"webhook", whID, whID,
				"Configure a webhook secret to enable HMAC signature verification on incoming deliveries.",
				map[string]string{"url": whURL},
			))
		}

		// Track which security events are covered
		if events, ok := wh["events"].([]interface{}); ok {
			for _, e := range events {
				if eventStr, ok := e.(string); ok {
					if _, tracked := securityEvents[eventStr]; tracked {
						securityEvents[eventStr] = true
					}
				}
			}
		}
	}

	// Check: missing security event webhooks
	missing := []string{}
	for event, covered := range securityEvents {
		if !covered {
			missing = append(missing, event)
		}
	}
	if len(missing) > 0 {
		findings = append(findings, warn(
			"log-012", "Missing Security Event Webhooks", catLogging, models.Medium,
			4.0, "Uncovered security events mean attacks or configuration changes won't trigger automated alerts. Detection relies on manual review.",
			fmt.Sprintf("The following security-relevant events are not covered by any webhook: %s", strings.Join(missing, ", ")),
			"webhook", "N/A", "N/A",
			"Add webhook subscriptions for security events to enable alerting on security-relevant changes.",
			map[string]string{"missing_events": strings.Join(missing, ",")},
		))
	}

	// Check: audit log monitoring (Enterprise feature — gracefully skipped if not available)
	// If we have webhooks but none cover audit-relevant events, flag it
	auditEvents := []string{
		"team.member.added",
		"team.member.removed",
		"integration-configuration.removed",
		"integration-configuration.scope-change-confirmed",
	}
	auditCovered := 0
	for _, wh := range webhooks {
		if events, ok := wh["events"].([]interface{}); ok {
			for _, e := range events {
				for _, ae := range auditEvents {
					if str(e) == ae {
						auditCovered++
					}
				}
			}
		}
	}
	if auditCovered == 0 {
		findings = append(findings, warn(
			"log-022", "No Audit Event Monitoring", catLogging, models.Medium,
			6.0, "Team membership changes, integration removals, and scope changes are not monitored. These are key audit trail events for detecting unauthorized access changes.",
			"No webhooks are configured for audit-relevant events (team member changes, integration scope changes).",
			"webhook", "N/A", "N/A",
			"Add webhook subscriptions for team.member.added, team.member.removed, and integration configuration events.",
			nil,
		))
	}

	return findings
}
