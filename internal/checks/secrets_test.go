package checks

import "testing"

func TestIsSensitiveName(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want bool
	}{
		// Genuine secrets: must stay flagged.
		{"nextauth secret", "NEXTAUTH_SECRET", true},
		{"authjs secret", "AUTH_SECRET", true},
		{"auth0 client secret", "AUTH0_CLIENT_SECRET", true},
		{"api key", "API_KEY", true},
		{"stripe secret key", "STRIPE_SECRET_KEY", true},
		{"database url", "DATABASE_URL", true},
		{"redis url", "REDIS_URL", true},
		{"mongo uri", "MONGO_URI", true},
		{"bearer token", "MY_BEARER_TOKEN", true},

		// Public-by-convention vars that contain a sensitive substring: must be cleared.
		{"nextauth url", "NEXTAUTH_URL", false},
		{"nextauth url internal", "NEXTAUTH_URL_INTERNAL", false},
		{"authjs url", "AUTH_URL", false},
		{"auth trust host flag", "AUTH_TRUST_HOST", false},
		{"auth0 domain", "AUTH0_DOMAIN", false},
		{"auth0 base url", "AUTH0_BASE_URL", false},
		{"auth0 issuer base url", "AUTH0_ISSUER_BASE_URL", false},
		{"vercel url", "VERCEL_URL", false},
		{"vercel production url", "VERCEL_PROJECT_PRODUCTION_URL", false},

		// Allowlist is case-insensitive.
		{"lowercase nextauth url", "nextauth_url", false},
		{"mixed case auth url", "Auth_Url", false},

		// Non-sensitive names stay non-sensitive.
		{"node env", "NODE_ENV", false},
		{"port", "PORT", false},
		{"empty", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSensitiveName(tc.key); got != tc.want {
				t.Errorf("isSensitiveName(%q) = %v; want %v", tc.key, got, tc.want)
			}
		})
	}
}

func TestLooksLikeNonSecretURL(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		// Clean web locators (these are public URLs), not secrets.
		{"https origin", "https://example.com", true},
		{"http origin", "http://example.com", true},
		{"https with port", "https://example.com:3000", true},
		{"https with path", "https://example.com/api/auth", true},
		{"trailing whitespace", "  https://example.com  ", true},

		// Credential-bearing or non-web: must NOT be cleared.
		{"postgres connection string", "postgres://user:pass@host:5432/db", false},
		{"redis connection string", "redis://host:6379", false},
		{"mongodb uri", "mongodb://user:pass@host/db", false},
		{"http with userinfo", "https://user:pass@example.com", false},
		{"http with userinfo no pass", "https://user@example.com", false},
		{"url with query token", "https://example.com/cb?token=abc123", false},
		{"url with fragment", "https://example.com/#secret", false},

		// Not URLs at all.
		{"empty", "", false},
		{"bare secret", "redacted-fake-token-not-a-real-key", false},
		{"scheme only", "https://", false},
		{"no scheme", "example.com", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeNonSecretURL(tc.value); got != tc.want {
				t.Errorf("looksLikeNonSecretURL(%q) = %v; want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestHasHardSecretWord(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want bool
	}{
		{"webhook secret", "WEBHOOK_SECRET", true},
		{"slack token", "SLACK_TOKEN", true},
		{"api key", "API_KEY", true},
		{"db password", "DB_PASSWORD", true},
		{"jwt signing key", "JWT_SIGNING_KEY", true},
		{"private key", "MY_PRIVATE_KEY", true},
		{"lowercase token", "service_token", true},
		// Whole-word matching: "KEY" must not fire inside "KEYCLOAK".
		{"keycloak auth url", "KEYCLOAK_AUTH_URL", false},
		{"auth url", "AUTH_URL", false},
		{"plain url", "FOO_AUTH_URL", false},
		{"node env", "NODE_ENV", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasHardSecretWord(tc.key); got != tc.want {
				t.Errorf("hasHardSecretWord(%q) = %v; want %v", tc.key, got, tc.want)
			}
		})
	}
}

func TestIsSensitiveEnvVar(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]interface{}
		want bool
	}{
		// The reported false positive: NEXTAUTH_URL plain-text with a public URL value.
		{
			"nextauth url plain public value",
			map[string]interface{}{"key": "NEXTAUTH_URL", "type": "plain", "value": "https://example.com"},
			false,
		},
		// Allowlisted even when no value is exposed (e.g. stored encrypted).
		{
			"nextauth url no value",
			map[string]interface{}{"key": "NEXTAUTH_URL", "type": "encrypted"},
			false,
		},
		// A sensitive name whose plain value is a real credential URL stays sensitive.
		{
			"database url with embedded creds",
			map[string]interface{}{"key": "DATABASE_URL", "type": "plain", "value": "postgres://u:p@host/db"},
			true,
		},
		// A sensitive name with no value falls back to the name verdict.
		{
			"database url no value",
			map[string]interface{}{"key": "DATABASE_URL", "type": "encrypted"},
			true,
		},
		// A sensitive name holding a non-URL secret value stays sensitive.
		{
			"api key secret value",
			map[string]interface{}{"key": "API_KEY", "type": "plain", "value": "redacted-fake-token-not-a-real-key"},
			true,
		},
		// NEXTAUTH_SECRET is a real secret regardless of value shape.
		{
			"nextauth secret",
			map[string]interface{}{"key": "NEXTAUTH_SECRET", "type": "plain", "value": "verysecretvalue"},
			true,
		},
		// Fail-open guard: a hard-secret name whose value is a clean web URL must NOT
		// be cleared, because the secret can live in the URL path (Slack webhook).
		{
			"webhook secret as slack url",
			map[string]interface{}{"key": "WEBHOOK_SECRET", "type": "plain", "value": "https://webhook.example.com/services/aaa/bbb/ccccccccccc"},
			true,
		},
		{
			"api key set to a url",
			map[string]interface{}{"key": "API_KEY", "type": "plain", "value": "https://example.com/v1/endpoint"},
			true,
		},
		// A non-allowlisted AUTH endpoint with a clean URL value is correctly relaxed.
		{
			"custom auth url with public value",
			map[string]interface{}{"key": "KEYCLOAK_AUTH_URL", "type": "plain", "value": "https://idp.example.com/auth"},
			false,
		},
		// Non-sensitive name is never flagged.
		{
			"plain non-sensitive var",
			map[string]interface{}{"key": "NODE_ENV", "type": "plain", "value": "production"},
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSensitiveEnvVar(tc.env); got != tc.want {
				t.Errorf("isSensitiveEnvVar(%v) = %v; want %v", tc.env, got, tc.want)
			}
		})
	}
}
