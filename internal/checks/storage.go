package checks

import (
	"fmt"
	"strings"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catStorage = "Storage & Data"

type StorageChecks struct{}

func (sc *StorageChecks) Name() string     { return "Storage" }
func (sc *StorageChecks) Category() string { return catStorage }

// storageEnvPatterns are environment variable name patterns that indicate
// Vercel managed storage (KV, Postgres, Blob).
var storageEnvPatterns = []string{
	"KV_URL", "KV_REST_API_URL", "KV_REST_API_TOKEN",
	"POSTGRES_URL", "POSTGRES_HOST", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DATABASE",
	"BLOB_READ_WRITE_TOKEN",
}

func isStorageEnvVar(key string) bool {
	upper := strings.ToUpper(key)
	for _, pattern := range storageEnvPatterns {
		if strings.Contains(upper, pattern) {
			return true
		}
	}
	return false
}

func (sc *StorageChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"stor-001", "Project Enumeration — Insufficient Permissions", catStorage,
				"Cannot list projects: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "stor-001", Title: "Project Enumeration", Category: catStorage,
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

		envVars, err := c.ListProjectEnvVars(projID)
		if err != nil {
			if IsPermissionDenied(err) && !permSeen["ListProjectEnvVars"] {
				permSeen["ListProjectEnvVars"] = true
				findings = append(findings, permissionFinding(
					"sto-010", "Storage Check — Insufficient Permissions", catStorage,
					"Cannot list project environment variables: API token lacks required permissions. This check was skipped for all projects.",
				))
			}
			continue
		}

		// Collect storage env vars and their targets
		hasStorageVars := false
		hasCronVars := false
		hasCronSecret := false

		for _, env := range envVars {
			envKey := str(env["key"])

			if isStorageEnvVar(envKey) {
				hasStorageVars = true
			}
			if strings.Contains(strings.ToUpper(envKey), "CRON") {
				hasCronVars = true
			}
			if strings.ToUpper(envKey) == "CRON_SECRET" {
				hasCronSecret = true
			}
		}

		// stor-001: Vercel Storage Without IP Restrictions
		if hasStorageVars {
			trustedIps := mapVal(p["trustedIps"])
			hasTrustedIPs := trustedIps != nil
			if addrs, ok := trustedIps["addresses"].([]interface{}); ok {
				hasTrustedIPs = len(addrs) > 0
			}

			// Check for secure compute
			hasSecureCompute := false
			if security := mapVal(p["security"]); security != nil {
				if sc := mapVal(security["secureCompute"]); sc != nil {
					hasSecureCompute = boolean(sc["enabled"])
				}
			}

			if !hasTrustedIPs && !hasSecureCompute {
				findings = append(findings, warn(
					"stor-001", "Vercel Storage Without IP Restrictions", catStorage, models.Medium,
					5.0, "Vercel managed storage (KV, Postgres, Blob) may be accessible from outside Vercel if not properly configured with connection restrictions.",
					fmt.Sprintf("Project '%s' uses Vercel managed storage but has no trusted IPs or Secure Compute configured.", projName),
					"project", projID, projName,
					"Configure Secure Compute or trusted IPs for projects using Vercel managed storage.",
					nil,
				))
			}
		}

		// stor-002: Storage Credentials in Preview Environment
		for _, env := range envVars {
			envKey := str(env["key"])
			envID := str(env["id"])

			if !isStorageEnvVar(envKey) {
				continue
			}

			targets := toStringSlice(env["target"])
			hasProd := contains(targets, "production")
			hasPreview := contains(targets, "preview")

			if hasProd && hasPreview {
				f := warn(
					"stor-002", "Storage Credentials in Preview Environment", catStorage, models.High,
					7.0, "Production storage credentials accessible in preview deployments allow untrusted code to read/write production data.",
					fmt.Sprintf("Project '%s': Storage variable '%s' targets both production and preview environments.", projName, envKey),
					"env_var", envID, envKey,
					"Use separate storage credentials for preview environments or restrict storage env vars to production only.",
					map[string]string{"project": projName, "variable": envKey},
				)
				f.PocEvidence = []models.PocEvidence{buildEvidence(c, fmt.Sprintf("/v10/projects/%s/env", projID), env, []string{"key", "id", "type", "target"}, fmt.Sprintf("Storage variable '%s' shared between production and preview", envKey))}
				findings = append(findings, f)
			}
		}

		// cron-001: Cron Job Endpoint Not Protected
		if hasCronVars && !hasCronSecret {
			findings = append(findings, warn(
				"cron-001", "Cron Job Endpoint Not Protected", catStorage, models.Medium,
				5.0, "Vercel Cron Jobs call HTTP endpoints. If the endpoint doesn't verify the CRON_SECRET header, anyone can trigger it.",
				fmt.Sprintf("Project '%s' has cron-related environment variables but no CRON_SECRET configured.", projName),
				"project", projID, projName,
				"Set a CRON_SECRET environment variable and validate the x-vercel-cron-secret header in your cron endpoint.",
				nil,
			))
		}
	}

	return findings
}
