package checks

import (
	"fmt"
	"math"
	"strings"

	"github.com/su1ph/vercelsior/internal/client"
	"github.com/su1ph/vercelsior/internal/models"
)

const catSecrets = "Secrets & Environment Variables"

type SecretsChecks struct{}

func (sc *SecretsChecks) Name() string     { return "Secrets" }
func (sc *SecretsChecks) Category() string { return catSecrets }

// Patterns that suggest a sensitive value
var sensitiveKeyPatterns = []string{
	"SECRET", "KEY", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL",
	"PRIVATE", "AUTH", "API_KEY", "APIKEY", "ACCESS_KEY",
	"SIGNING", "ENCRYPT", "JWT", "BEARER", "OAUTH",
	"DATABASE_URL", "DB_URL", "DB_PASS", "DB_PASSWORD",
	"REDIS_URL", "MONGO_URI", "STRIPE", "TWILIO",
	"SENDGRID", "MAILGUN", "AWS_", "AZURE_", "GCP_",
	"GITHUB_TOKEN", "SLACK_TOKEN", "WEBHOOK_SECRET",
}

func isSensitiveName(name string) bool {
	upper := strings.ToUpper(name)
	for _, pattern := range sensitiveKeyPatterns {
		if strings.Contains(upper, pattern) {
			return true
		}
	}
	return false
}

func (sc *SecretsChecks) Run(c *client.Client) []models.Finding {
	var findings []models.Finding
	findings = append(findings, sc.checkProjectEnvVars(c)...)
	findings = append(findings, sc.checkSharedEnvVars(c)...)
	return findings
}

func (sc *SecretsChecks) checkProjectEnvVars(c *client.Client) []models.Finding {
	var findings []models.Finding

	projects, err := c.ListProjects()
	if err != nil {
		return findings
	}

	for _, p := range projects {
		projID := str(p["id"])
		projName := str(p["name"])

		envVars, err := c.ListProjectEnvVars(projID)
		if err != nil {
			continue
		}

		for _, env := range envVars {
			envKey := str(env["key"])
			envID := str(env["id"])
			envType := str(env["type"]) // "encrypted", "plain", "secret", "sensitive", "system"
			targets := env["target"]     // array of environments: "production", "preview", "development"

			sensitive := isSensitiveName(envKey)

			// Check: plain text secret
			if sensitive && envType == "plain" {
				f := fail(
					"sec-001", "Sensitive Env Var Stored as Plain Text", catSecrets, models.Critical,
					9.5, "Production secrets stored in plain text are readable by anyone with project access. No encryption barrier to credential theft.",
					fmt.Sprintf("Project '%s': Environment variable '%s' appears sensitive but is stored as plain text.", projName, envKey),
					"env_var", envID, envKey,
					"Change the type to 'encrypted' or 'sensitive' for environment variables containing secrets.",
					map[string]string{"project": projName, "type": envType},
				)
				f.PocEvidence = []models.PocEvidence{buildEvidence(c, fmt.Sprintf("/v10/projects/%s/env", projID), env, []string{"key", "id", "type", "target"}, fmt.Sprintf("Sensitive variable '%s' stored as plain text", envKey))}
				findings = append(findings, f)
			}

			// Check: sensitive value exposed to preview/development
			if sensitive {
				targetSlice := toStringSlice(targets)
				hasPreview := contains(targetSlice, "preview")
				hasDev := contains(targetSlice, "development")
				if hasPreview || hasDev {
					exposed := []string{}
					if hasPreview {
						exposed = append(exposed, "preview")
					}
					if hasDev {
						exposed = append(exposed, "development")
					}
					f := warn(
						"sec-002", "Sensitive Env Var Exposed to Non-Production", catSecrets, models.High,
						7.0, "Sensitive credentials in preview/development environments are accessible to anyone who can trigger a preview deployment, including external contributors.",
						fmt.Sprintf("Project '%s': Sensitive variable '%s' is available in %s environment(s). Preview deployments may be less protected.", projName, envKey, strings.Join(exposed, ", ")),
						"env_var", envID, envKey,
						"Restrict sensitive environment variables to production only, or use separate values for non-production environments.",
						map[string]string{"project": projName, "environments": strings.Join(exposed, ",")},
					)
					f.PocEvidence = []models.PocEvidence{buildEvidence(c, fmt.Sprintf("/v10/projects/%s/env", projID), env, []string{"key", "id", "type", "target"}, fmt.Sprintf("Sensitive variable '%s' exposed to non-production environments", envKey))}
					findings = append(findings, f)
				}
			}

			// Check: non-encrypted type for any variable
			if envType == "plain" {
				findings = append(findings, warn(
					"sec-003", "Plain Text Environment Variable", catSecrets, models.Low,
					2.0, "Non-sensitive plain text variables are a minor hygiene issue. Encryption adds defense-in-depth but the values themselves are not secret.",
					fmt.Sprintf("Project '%s': Variable '%s' is stored as plain text.", projName, envKey),
					"env_var", envID, envKey,
					"Consider using encrypted environment variables for all values.",
					map[string]string{"project": projName, "type": envType},
				))
			}

			// Check: high-entropy value that might be an undeclared secret
			// Note: decrypted values are only available for "plain" type vars
			if envType == "plain" && !sensitive {
				if val := str(env["value"]); val != "" && len(val) >= 16 {
					entropy := calcEntropy(val)
					if entropy > 4.0 {
						findings = append(findings, warn(
							"sec-023", "High-Entropy Plain Text Value", catSecrets, models.Medium,
							5.0, "High-entropy values in plain text variables may be undeclared secrets. The value has characteristics of a random token or key.",
							fmt.Sprintf("Project '%s': Plain text variable '%s' has high entropy (%.1f bits/char), suggesting it may be a secret.", projName, envKey, entropy),
							"env_var", envID, envKey,
							"Review this variable. If it contains a secret, change its type to 'encrypted' or 'sensitive'.",
							map[string]string{"project": projName, "entropy": fmt.Sprintf("%.1f", entropy)},
						))
					}
				}
			}
		}

		// Check: autoExposeSystemEnvs
		if boolean(p["autoExposeSystemEnvs"]) {
			f := warn(
				"sec-004", "System Env Vars Auto-Exposed", catSecrets, models.Medium,
				4.0, "Auto-exposed system variables leak deployment metadata. Low direct risk but can aid reconnaissance.",
				fmt.Sprintf("Project '%s' automatically exposes system environment variables (VERCEL_URL, etc.) to the build.", projName),
				"project", projID, projName,
				"Review whether auto-exposed system environment variables are needed. Disable if not required.",
				nil,
			)
			f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v10/projects", p, []string{"name", "id", "autoExposeSystemEnvs"}, "Project has auto-expose system env vars enabled")}
			findings = append(findings, f)
		}

		// Check: excessive environment variables
		if len(envVars) > 50 {
			findings = append(findings, warn(
				"sec-022", "Excessive Environment Variables", catSecrets, models.Low,
				3.0, "Large numbers of env vars increase the chance of misconfiguration, unused secrets, or accidental exposure.",
				fmt.Sprintf("Project '%s' has %d environment variables.", projName, len(envVars)),
				"project", projID, projName,
				"Review environment variables and remove any that are unused or redundant.",
				map[string]string{"count": fmt.Sprintf("%d", len(envVars))},
			))
		}

		// Check: sensitive env vars without git branch filtering
		for _, env := range envVars {
			envKey := str(env["key"])
			envID := str(env["id"])
			if isSensitiveName(envKey) {
				gitBranch := str(env["gitBranch"])
				if gitBranch == "" {
					targets := toStringSlice(env["target"])
					if contains(targets, "preview") {
						findings = append(findings, warn(
							"sec-021", "Sensitive Env Var Without Branch Filtering", catSecrets, models.Medium,
							6.0, "Without branch filtering, any branch deployment including those from contributors can access this secret.",
							fmt.Sprintf("Project '%s': Sensitive variable '%s' is available on all preview branches with no git branch restriction.", projName, envKey),
							"env_var", envID, envKey,
							"Add git branch filtering to restrict which branches can access sensitive environment variables.",
							map[string]string{"project": projName},
						))
					}
				}
			}
		}

		// Check: same sensitive env var across all environments
		for _, env := range envVars {
			envKey := str(env["key"])
			envID := str(env["id"])
			if isSensitiveName(envKey) {
				targets := toStringSlice(env["target"])
				hasProd := contains(targets, "production")
				hasPreview := contains(targets, "preview")
				hasDev := contains(targets, "development")
				if hasProd && hasPreview && hasDev {
					f := warn(
						"sec-020", "Sensitive Env Var Shared Across All Environments", catSecrets, models.High,
						7.0, "Using the same secret in all environments means a preview deployment compromise also compromises production credentials.",
						fmt.Sprintf("Project '%s': Sensitive variable '%s' is available in all environments (production, preview, and development).", projName, envKey),
						"env_var", envID, envKey,
						"Use different secret values for each environment. At minimum, separate production from preview/development.",
						map[string]string{"project": projName},
					)
					f.PocEvidence = []models.PocEvidence{buildEvidence(c, fmt.Sprintf("/v10/projects/%s/env", projID), env, []string{"key", "id", "type", "target"}, fmt.Sprintf("Sensitive variable '%s' shared across all environments", envKey))}
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

func (sc *SecretsChecks) checkSharedEnvVars(c *client.Client) []models.Finding {
	var findings []models.Finding

	sharedVars, err := c.ListSharedEnvVars()
	if err != nil {
		return findings
	}

	for _, env := range sharedVars {
		envKey := str(env["key"])
		envID := str(env["id"])
		envType := str(env["type"])
		sensitive := isSensitiveName(envKey)

		// Shared env vars linked to many projects
		if linkedProjects, ok := env["projectId"].([]interface{}); ok && len(linkedProjects) > 10 {
			findings = append(findings, warn(
				"sec-010", "Shared Env Var Linked to Many Projects", catSecrets, models.Medium,
				5.0, "A shared secret across many projects means a single compromise has wide blast radius. Lateral movement risk.",
				fmt.Sprintf("Shared variable '%s' is linked to %d projects. Compromise of this variable affects all linked projects.", envKey, len(linkedProjects)),
				"shared_env_var", envID, envKey,
				"Review whether all linked projects need this variable. Consider per-project secrets where possible.",
				map[string]string{"linked_projects": fmt.Sprintf("%d", len(linkedProjects))},
			))
		}

		if sensitive && envType == "plain" {
			findings = append(findings, fail(
				"sec-011", "Shared Sensitive Env Var in Plain Text", catSecrets, models.Critical,
				9.5, "Shared sensitive credentials in plain text are readable across all linked projects. Maximum exposure with no encryption.",
				fmt.Sprintf("Shared variable '%s' appears sensitive but is stored as plain text.", envKey),
				"shared_env_var", envID, envKey,
				"Change to encrypted or sensitive type.",
				map[string]string{"type": envType},
			))
		}

		// Check: shared sensitive var exposed to all environments
		if sensitive {
			targets := toStringSlice(env["target"])
			hasProd := contains(targets, "production")
			hasPreview := contains(targets, "preview")
			hasDev := contains(targets, "development")
			if hasProd && hasPreview && hasDev {
				f := warn(
					"sec-020", "Shared Sensitive Env Var Across All Environments", catSecrets, models.High,
					7.0, "A shared sensitive variable targeting all environments means preview deployment compromise also compromises production credentials across all linked projects.",
					fmt.Sprintf("Shared variable '%s' is available in all environments (production, preview, and development).", envKey),
					"shared_env_var", envID, envKey,
					"Use different values per environment. At minimum, separate production from preview/development.",
					nil,
				)
				f.PocEvidence = []models.PocEvidence{buildEvidence(c, "/v1/env", env, []string{"key", "id", "type", "target"}, "Shared sensitive variable targets all environments")}
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func toStringSlice(v interface{}) []string {
	if arr, ok := v.([]interface{}); ok {
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func calcEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * (math.Log(p) / math.Log(2))
		}
	}
	return entropy
}
