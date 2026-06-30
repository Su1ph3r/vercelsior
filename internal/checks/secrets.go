package checks

import (
	"fmt"
	"math"
	"net/url"
	"strings"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/models"
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

var clientExposurePrefixes = []struct {
	Prefix    string
	Framework string
}{
	{"VITE_", "Vite/SvelteKit"},
	{"GATSBY_", "Gatsby"},
	{"REACT_APP_", "Create React App"},
	{"NUXT_PUBLIC_", "Nuxt"},
}

// knownNonSecretNames are environment variables whose names match a sensitive
// pattern (typically because they contain "AUTH") but which, by framework
// convention, hold public, non-secret values: canonical site URLs, issuer
// domains, and host-trust flags. The corresponding real secrets (NEXTAUTH_SECRET,
// AUTH_SECRET, AUTH0_CLIENT_SECRET, and the like) are deliberately absent here
// and still match the sensitive patterns. Compared case-insensitively.
var knownNonSecretNames = map[string]bool{
	// NextAuth.js / Auth.js
	"NEXTAUTH_URL":          true, // canonical deployment URL, public
	"NEXTAUTH_URL_INTERNAL": true, // internal base URL, not a credential
	"AUTH_URL":              true, // Auth.js v5 canonical URL
	"AUTH_TRUST_HOST":       true, // boolean host-trust flag
	// Auth0 SDKs
	"AUTH0_DOMAIN":          true, // public tenant domain
	"AUTH0_BASE_URL":        true, // application base URL
	"AUTH0_ISSUER_BASE_URL": true, // public issuer URL
	// Vercel system-provided deployment locators
	"VERCEL_URL":                    true,
	"VERCEL_BRANCH_URL":             true,
	"VERCEL_PROJECT_PRODUCTION_URL": true,
}

func isKnownNonSecretName(name string) bool {
	return knownNonSecretNames[strings.ToUpper(strings.TrimSpace(name))]
}

func isSensitiveName(name string) bool {
	if isKnownNonSecretName(name) {
		return false
	}
	upper := strings.ToUpper(name)
	for _, pattern := range sensitiveKeyPatterns {
		if strings.Contains(upper, pattern) {
			return true
		}
	}
	return false
}

// hardSecretWords name credential material directly. If any underscore-delimited
// word of a variable name is one of these, the variable holds a secret whatever
// its value looks like, so the URL value-shape relaxation must never clear it.
// This guards against a secret carried in a URL path (e.g. a Slack WEBHOOK_SECRET
// such as https://hooks.slack.com/services/T/B/XXXX, or a *_TOKEN mistakenly set
// to a URL), which looksLikeNonSecretURL cannot see. Matching is on whole words,
// not substrings, so "KEY" does not falsely fire on a name like KEYCLOAK_AUTH_URL.
var hardSecretWords = map[string]bool{
	"SECRET": true, "SECRETS": true,
	"TOKEN": true, "TOKENS": true,
	"PASSWORD": true, "PASSWD": true, "PASS": true,
	"CREDENTIAL": true, "CREDENTIALS": true,
	"PRIVATE": true,
	"KEY":     true, "KEYS": true, "APIKEY": true,
	"SIGNING": true, "JWT": true, "BEARER": true,
	"WEBHOOK": true,
}

func hasHardSecretWord(name string) bool {
	for _, word := range strings.Split(strings.ToUpper(name), "_") {
		if hardSecretWords[word] {
			return true
		}
	}
	return false
}

// looksLikeNonSecretURL reports whether value is a plain web locator: an
// http/https URL or origin that embeds no credentials. This is what separates a
// public config URL such as NEXTAUTH_URL ("https://example.com") from a
// connection string such as DATABASE_URL ("postgres://user:pass@host/db"), whose
// userinfo carries a password and whose scheme is not web. Only http(s) URLs with
// no userinfo, query, or fragment qualify, so connection strings and token-bearing
// URLs are never cleared. Note this cannot detect a secret carried in the URL
// path; callers must not apply it to names that denote credential material (see
// hasHardSecretWord).
func looksLikeNonSecretURL(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	u, err := url.Parse(value)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Host == "" {
		return false
	}
	if u.User != nil { // user[:password]@ means the URL itself is a credential
		return false
	}
	if u.RawQuery != "" || u.Fragment != "" { // a token could hide in ?x=... or #...
		return false
	}
	return true
}

// isSensitiveEnvVar decides whether an environment variable should be treated as
// holding a secret. It starts from the name heuristic and, when the decrypted
// value is available (Vercel only returns it for "plain" type vars), refines the
// verdict by inspecting the value's shape. This stops public locators like
// NEXTAUTH_URL or a custom FOO_AUTH_URL from being misreported as plain-text
// credentials. The value-shape relaxation is applied only to names that do not
// contain a hard-secret word, so genuine secrets stay classified as sensitive
// even when their value happens to look like a URL. Without a value it falls back
// to the name verdict.
func isSensitiveEnvVar(env map[string]interface{}) bool {
	key := str(env["key"])
	if !isSensitiveName(key) {
		return false
	}
	if !hasHardSecretWord(key) {
		if val := str(env["value"]); val != "" && looksLikeNonSecretURL(val) {
			return false
		}
	}
	return true
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
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"sec-001", "Secrets Check — Insufficient Permissions", catSecrets,
				"Cannot list projects: API token lacks required permissions. This check was skipped.",
			))
		} else {
			findings = append(findings, models.Finding{
				CheckID: "sec-001", Title: "Secrets Check Failed", Category: catSecrets,
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
					"sec-001", "Env Var Check — Insufficient Permissions", catSecrets,
					"Cannot list project environment variables: API token lacks required permissions. This check was skipped for all projects.",
				))
			}
			continue
		}

		for _, env := range envVars {
			envKey := str(env["key"])
			envID := str(env["id"])
			envType := str(env["type"]) // "encrypted", "plain", "secret", "sensitive", "system"
			targets := env["target"]    // array of environments: "production", "preview", "development"

			sensitive := isSensitiveEnvVar(env)

			// Check: plain text secret
			if sensitive && envType == "plain" {
				f := fail(
					"sec-001", "Sensitive Env Var Stored as Plain Text", catSecrets, models.Critical,
					9.5, "Production secrets stored in plain text are readable by anyone with project access. No encryption barrier to credential theft.",
					fmt.Sprintf("Project '%s': Environment variable '%s' appears sensitive but is stored as plain text.", projName, envKey),
					"env_var", envID, envKey,
					"Change the type to 'encrypted' or 'sensitive' for environment variables containing secrets.",
					map[string]string{"project": projName, "project_id": projID, "type": envType},
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
						map[string]string{"project": projName, "project_id": projID, "environments": strings.Join(exposed, ",")},
					)
					f.PocEvidence = []models.PocEvidence{buildEvidence(c, fmt.Sprintf("/v10/projects/%s/env", projID), env, []string{"key", "id", "type", "target"}, fmt.Sprintf("Sensitive variable '%s' exposed to non-production environments", envKey))}
					findings = append(findings, f)
				}
			}

			// sec-026: Framework client-exposure prefixes
			for _, pfx := range clientExposurePrefixes {
				if strings.HasPrefix(strings.ToUpper(envKey), pfx.Prefix) {
					stripped := envKey[len(pfx.Prefix):]
					if isSensitiveName(stripped) {
						findings = append(findings, fail(
							"sec-026", "Client-Exposed Sensitive Environment Variable", catSecrets,
							models.Critical, 10.0,
							fmt.Sprintf("The %s prefix exposes this variable to client-side JavaScript in %s applications. Variable '%s' matches sensitive naming patterns and may leak secrets to browsers.", pfx.Prefix, pfx.Framework, envKey),
							fmt.Sprintf("Project '%s': env var '%s' uses the %s prefix which exposes it to client-side code.", projName, envKey, pfx.Prefix),
							"env_var", envID, envKey,
							fmt.Sprintf("Remove the %s prefix or move the value to a server-only environment variable.", pfx.Prefix),
							map[string]string{"project": projName, "project_id": projID, "prefix": pfx.Prefix, "framework": pfx.Framework},
						))
						break // only flag once per env var
					}
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
			if isSensitiveEnvVar(env) {
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
			if isSensitiveEnvVar(env) {
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
		if IsPermissionDenied(err) {
			findings = append(findings, permissionFinding(
				"sec-010", "Shared Env Vars Check — Insufficient Permissions", catSecrets,
				"Cannot list shared environment variables: API token lacks required permissions. This check was skipped.",
			))
		}
		return findings
	}

	for _, env := range sharedVars {
		envKey := str(env["key"])
		envID := str(env["id"])
		envType := str(env["type"])
		sensitive := isSensitiveEnvVar(env)

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

		// sec-026: Framework client-exposure prefixes (shared env vars)
		for _, pfx := range clientExposurePrefixes {
			if strings.HasPrefix(strings.ToUpper(envKey), pfx.Prefix) {
				stripped := envKey[len(pfx.Prefix):]
				if isSensitiveName(stripped) {
					findings = append(findings, fail(
						"sec-026", "Client-Exposed Sensitive Shared Environment Variable", catSecrets,
						models.Critical, 10.0,
						fmt.Sprintf("The %s prefix exposes this variable to client-side JavaScript in %s applications. Variable '%s' matches sensitive naming patterns and may leak secrets to browsers.", pfx.Prefix, pfx.Framework, envKey),
						fmt.Sprintf("Shared env var '%s' uses the %s prefix which exposes it to client-side code across all linked projects.", envKey, pfx.Prefix),
						"shared_env_var", envID, envKey,
						fmt.Sprintf("Remove the %s prefix or move the value to a server-only environment variable.", pfx.Prefix),
						map[string]string{"prefix": pfx.Prefix, "framework": pfx.Framework},
					))
					break // only flag once per env var
				}
			}
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
