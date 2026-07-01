// Package project implements Vercelsior's local IaC/SAST mode: it statically
// analyzes a Vercel project's source files — no API token, suitable for
// pre-deploy / shift-left scanning in CI on every PR. It reads through an
// fs.FS so the checks are unit-testable with fstest.MapFS (no real filesystem
// or network).
//
// Checks (v1):
//   - package.json: `next` dependency pinned to a version with known CVEs
//   - .env*:       committed secrets, public-prefix (NEXT_PUBLIC_/VITE_/...)
//     secret leakage, and .env not covered by .gitignore
//   - next.config: productionBrowserSourceMaps, ignoreBuildErrors/ignoreDuringBuilds
//   - vercel.json: redirects/rewrites to external destinations; missing
//     security headers
//   - .github/workflows/*: actions/cache steps whose key/restore-keys are not
//     bound to a lockfile hash (GitHub Actions cache poisoning, CWE-494)
package project

import (
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/Su1ph3r/vercelsior/internal/models"
	"github.com/Su1ph3r/vercelsior/internal/nextjs"
)

const (
	catFramework   = "Framework Security"
	catSecrets     = "Secrets & Environment"
	catConfig      = "Project Configuration"
	catRouting     = "Routes & Redirects"
	catSupplyChain = "Supply Chain"
)

var envFileNames = []string{
	".env", ".env.local", ".env.development", ".env.development.local",
	".env.production", ".env.production.local", ".env.test",
}

var nextConfigNames = []string{
	"next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs",
}

// publicPrefixes are env-var name prefixes whose values are inlined into the
// client bundle at build time by their respective frameworks.
var publicPrefixes = []string{
	"NEXT_PUBLIC_", "VITE_", "GATSBY_", "REACT_APP_", "NUXT_PUBLIC_", "PUBLIC_",
}

var (
	// Strong, low-false-positive token shapes.
	secretValueRes = []*regexp.Regexp{
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                                                 // AWS access key id
		regexp.MustCompile(`(?i)sk-[a-z0-9]{20,}`),                                             // OpenAI-style secret key
		regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),                                       // GitHub token
		regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),                                     // Slack token
		regexp.MustCompile(`AIza[0-9A-Za-z_\-]{20,}`),                                          // Google API key
		regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`), // JWT
		regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),                               // PEM private key
	}
	sensitiveKeyRe = regexp.MustCompile(`(?i)(secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|client[_-]?secret|auth)`)
	placeholderRe  = regexp.MustCompile(`(?i)^(your[_-]|example|changeme|placeholder|xxx+|<.*>|\$\{.*\}|test|dummy|sample|todo|none|null|true|false)`)
	envLineRe      = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$`)
)

// Run executes all project checks against the filesystem rooted at fsys and
// returns a ScanResult whose Findings feed the standard reporters. displayPath
// is the human-facing project path recorded on the result.
func Run(fsys fs.FS, displayPath, scanID string) *models.ScanResult {
	result := &models.ScanResult{
		ScanID:      scanID,
		StartedAt:   time.Now().UTC(),
		AccountName: displayPath,
		Findings:    []models.Finding{},
	}

	gitignored := loadGitignoreEnvCoverage(fsys)

	result.Findings = append(result.Findings, checkPackageJSON(fsys)...)
	result.Findings = append(result.Findings, checkEnvFiles(fsys, gitignored)...)
	result.Findings = append(result.Findings, checkNextConfig(fsys)...)
	result.Findings = append(result.Findings, checkVercelJSON(fsys)...)
	result.Findings = append(result.Findings, checkWorkflows(fsys)...)

	if len(result.Findings) == 0 {
		result.Findings = append(result.Findings, passFinding("prj-scope",
			"No recognizable Vercel project files found", catConfig,
			"None of vercel.json, next.config.*, package.json, .env*, or .github/workflows/* were found at the target path. Point project mode at a project root.",
			displayPath))
	}

	result.Compute()
	return result
}

// --- package.json / Next.js version ---

func checkPackageJSON(fsys fs.FS) []models.Finding {
	const id = "prj-next-cve"
	const title = "Next.js version with known CVEs"
	data, err := fs.ReadFile(fsys, "package.json")
	if errors.Is(err, fs.ErrNotExist) {
		return nil // genuinely absent — not a Node project; skip
	}
	if err != nil {
		// Present but unreadable (permission, is-a-directory, I/O). Never
		// silently skip a security check — surface that it could not run.
		return []models.Finding{errorFinding(id, "package.json unreadable", catFramework,
			"package.json exists but could not be read: "+err.Error(), "package.json")}
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return []models.Finding{errorFinding(id, "Unparseable package.json", catFramework,
			"package.json could not be parsed as JSON: "+err.Error(), "package.json")}
	}

	version := pkg.Dependencies["next"]
	if version == "" {
		version = pkg.DevDependencies["next"]
	}
	if version == "" {
		return nil // not a Next.js project
	}

	ids, maxCVSS, ok := nextjs.Match(version)
	if !ok {
		return []models.Finding{infoFinding(id, "Next.js version not pinned", catFramework,
			"package.json declares next@"+version+", which is not a concrete version (range/wildcard/tag); CVE evaluation skipped. Pin a version or check the installed lockfile.",
			"package.json")}
	}
	if len(ids) == 0 {
		return []models.Finding{passFinding(id, "Next.js version has no known CVEs", catFramework,
			"package.json declares next@"+version+", which matches no known advisory in the matrix.",
			"package.json")}
	}

	sev := models.High
	if maxCVSS >= 9.0 {
		sev = models.Critical
	}
	cveList := strings.Join(ids, ", ")
	f := failFinding(id, title, catFramework, sev, maxCVSS,
		"The declared Next.js version is affected by "+itoa(len(ids))+" known CVE(s) ("+cveList+"); the most severe scores "+ftoa(maxCVSS)+". CVE-2025-29927 in particular allows middleware auth bypass and is testable live via `vercelsior probe`.",
		"package.json declares next@"+version+", affected by: "+cveList+".",
		"package.json",
		"Upgrade Next.js to a patched release (>=15.2.3 / 14.2.25 for CVE-2025-29927; see each advisory for minimums) and commit the updated lockfile.")
	f.Details = map[string]string{"next_version": version, "cves": cveList, "max_cvss": ftoa(maxCVSS)}
	return []models.Finding{f}
}

// --- .env files ---

func checkEnvFiles(fsys fs.FS, envGitignored bool) []models.Finding {
	var findings []models.Finding
	foundAnyEnv := false

	for _, name := range envFileNames {
		data, err := fs.ReadFile(fsys, name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			// Present but unreadable — record the gap rather than skipping the
			// secret scan for this file silently.
			foundAnyEnv = true
			findings = append(findings, errorFinding("prj-env-secret",
				name+" unreadable", catSecrets,
				name+" exists but could not be read for secret scanning: "+err.Error(), name))
			continue
		}
		foundAnyEnv = true
		// .env.local / *.local files are git-ignored by Next.js convention and
		// not meant to be committed; real .env / .env.production are the risk.
		committable := !strings.Contains(name, ".local")

		for _, line := range strings.Split(string(data), "\n") {
			m := envLineRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			key := m[1]
			val := unquote(strings.TrimSpace(m[2]))
			if val == "" || isPlaceholder(val) {
				continue
			}

			// Public-prefix leakage: a client-inlined var whose VALUE looks like
			// a real credential. Gating on the value (not the key name) avoids
			// false-positive CRITICALs on intentionally-public client config
			// such as NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN or a Stripe publishable
			// key, whose names match "auth"/"key" but whose values are public.
			if prefix, _, isPublic := splitPublicPrefix(key); isPublic {
				if matchesSecretToken(val) {
					findings = append(findings, withDetails(failFinding("prj-env-public-leak",
						"Client-exposed secret via "+prefix+" prefix", catSecrets,
						models.Critical, 9.0,
						prefix+" variables are inlined into the client bundle at build time and readable by anyone viewing page source — the most common real-world Vercel secret leak.",
						name+": `"+key+"` carries a secret-looking value but is exposed to the browser via its "+prefix+" prefix.",
						name+":"+key,
						"Remove the public prefix from secret values; read them server-side (API routes, server components) instead. Rotate the exposed credential."),
						map[string]string{"file": name, "variable": key}))
				}
				continue
			}

			// Committed secret: sensitive name with a real value, or a strong
			// token shape, in a committable env file.
			if committable && (sensitiveKeyRe.MatchString(key) && looksRealValue(val) || looksLikeSecretValue(val)) {
				findings = append(findings, withDetails(failFinding("prj-env-secret",
					"Hardcoded secret in "+name, catSecrets, models.High, 7.5,
					"Secrets in a committable .env file are easily checked into version control and shared in the repo. Use a secret manager or Vercel project env vars instead.",
					name+": `"+key+"` appears to contain a hardcoded secret value.",
					name+":"+key,
					"Move the secret out of the committed file (use Vercel env vars / a secret manager), rotate it, and add the file to .gitignore."),
					map[string]string{"file": name, "variable": key}))
			}
		}
	}

	// .gitignore coverage: a committable .env exists but is not ignored.
	if foundAnyEnv && !envGitignored {
		findings = append(findings, warnFinding("prj-env-gitignore",
			".env not covered by .gitignore", catSecrets, models.High, 6.0,
			"An .env file is present but no .gitignore rule covers it, so it is at risk of being committed to version control along with any secrets it holds.",
			"A committable .env file exists with no matching .gitignore rule.",
			".gitignore",
			"Add `.env*.local` and `.env` (as appropriate) to .gitignore, and verify the file was never previously committed."))
	}

	if len(findings) == 0 && foundAnyEnv {
		findings = append(findings, passFinding("prj-env-secret",
			"No hardcoded secrets detected in .env files", catSecrets,
			"Scanned .env file(s); no client-exposed or hardcoded secret values were detected.", ".env"))
	}
	return findings
}

// --- next.config ---

func checkNextConfig(fsys fs.FS) []models.Finding {
	var body string
	var name string
	var readErr error
	for _, n := range nextConfigNames {
		data, err := fs.ReadFile(fsys, n)
		if err == nil {
			body = string(data)
			name = n
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			readErr = err // present but unreadable
		}
	}
	if name == "" {
		if readErr != nil {
			return []models.Finding{errorFinding("prj-nextconfig", "next.config unreadable", catConfig,
				"A next.config.* file exists but could not be read: "+readErr.Error(), "next.config")}
		}
		return nil
	}
	var findings []models.Finding

	if matchAssignTrue(body, "productionBrowserSourceMaps") {
		findings = append(findings, warnFinding("prj-sourcemaps",
			"Production browser source maps enabled", catConfig, models.Medium, 5.0,
			"`productionBrowserSourceMaps: true` ships .map files for client bundles to production, exposing original source (and sometimes secrets) to anyone. This is directly verifiable post-deploy via `vercelsior probe`.",
			name+" sets `productionBrowserSourceMaps: true`.",
			name,
			"Set `productionBrowserSourceMaps: false` (the default) for production builds."))
	}
	if matchAssignTrue(body, "ignoreBuildErrors") {
		findings = append(findings, warnFinding("prj-ignore-ts-errors",
			"TypeScript build errors ignored", catConfig, models.Low, 3.0,
			"`typescript.ignoreBuildErrors: true` ships code that fails type-checking, which can mask real bugs and unsafe casts that lead to security issues.",
			name+" sets `ignoreBuildErrors: true`.", name,
			"Remove `ignoreBuildErrors` and fix the underlying type errors."))
	}
	if matchAssignTrue(body, "ignoreDuringBuilds") {
		findings = append(findings, warnFinding("prj-ignore-eslint",
			"ESLint ignored during builds", catConfig, models.Low, 2.0,
			"`eslint.ignoreDuringBuilds: true` disables lint enforcement at build time, allowing flagged anti-patterns (including security rules) to ship.",
			name+" sets `ignoreDuringBuilds: true`.", name,
			"Remove `ignoreDuringBuilds` and resolve the lint findings."))
	}
	if matchAssignTrue(body, "poweredByHeader") {
		findings = append(findings, warnFinding("prj-poweredby",
			"X-Powered-By header explicitly enabled", catConfig, models.Low, 2.0,
			"`poweredByHeader: true` advertises the framework via X-Powered-By, helping attackers map the target to known CVEs.",
			name+" sets `poweredByHeader: true`.", name,
			"Set `poweredByHeader: false`."))
	}

	if len(findings) == 0 {
		findings = append(findings, passFinding("prj-nextconfig",
			"next.config has no risky flags", catConfig,
			"Scanned "+name+"; none of the checked risky flags (source maps, ignored build/lint errors, X-Powered-By) were enabled.", name))
	}
	return findings
}

// --- vercel.json ---

func checkVercelJSON(fsys fs.FS) []models.Finding {
	data, err := fs.ReadFile(fsys, "vercel.json")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return []models.Finding{errorFinding("prj-vercel-json", "vercel.json unreadable", catConfig,
			"vercel.json exists but could not be read: "+err.Error(), "vercel.json")}
	}
	var cfg struct {
		Headers []struct {
			Source  string `json:"source"`
			Headers []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"headers"`
		} `json:"headers"`
		Redirects []struct {
			Source      string `json:"source"`
			Destination string `json:"destination"`
		} `json:"redirects"`
		Rewrites []struct {
			Source      string `json:"source"`
			Destination string `json:"destination"`
		} `json:"rewrites"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return []models.Finding{errorFinding("prj-vercel-json", "Unparseable vercel.json", catConfig,
			"vercel.json could not be parsed as JSON: "+err.Error(), "vercel.json")}
	}

	var findings []models.Finding

	// External / wildcard redirect & rewrite destinations.
	for _, r := range cfg.Redirects {
		if isExternalDestination(r.Destination) {
			findings = append(findings, withDetails(warnFinding("prj-open-redirect",
				"Redirect to external destination", catRouting, models.Medium, 5.0,
				"A redirect points off-site; if the destination is attacker-influenced (wildcard capture, untrusted input) this is an open-redirect used for phishing and OAuth token theft.",
				"vercel.json redirect `"+r.Source+"` → `"+r.Destination+"` targets an external origin.",
				"vercel.json:redirect:"+r.Source,
				"Restrict redirects to same-origin paths, or validate/allowlist external destinations."),
				map[string]string{"source": r.Source, "destination": r.Destination}))
		}
	}
	for _, r := range cfg.Rewrites {
		if isExternalDestination(r.Destination) {
			findings = append(findings, withDetails(warnFinding("prj-external-rewrite",
				"Rewrite proxies to external origin", catRouting, models.Medium, 5.0,
				"A rewrite silently proxies requests to an external origin under your domain; combined with wildcard sources this can expose internal services or enable request smuggling/SSRF.",
				"vercel.json rewrite `"+r.Source+"` → `"+r.Destination+"` proxies to an external origin.",
				"vercel.json:rewrite:"+r.Source,
				"Avoid proxying to untrusted/external origins; pin destinations and avoid open wildcard captures."),
				map[string]string{"source": r.Source, "destination": r.Destination}))
		}
	}

	// Security headers configured anywhere?
	if !hasSecurityHeader(cfg.Headers) {
		findings = append(findings, warnFinding("prj-missing-headers",
			"No security headers configured in vercel.json", catConfig, models.Low, 3.0,
			"vercel.json defines no Content-Security-Policy / Strict-Transport-Security / X-Frame-Options header. If they are not set in next.config.js either, responses ship without these protections (verify live with `vercelsior probe`).",
			"vercel.json `headers` does not configure CSP, HSTS, or X-Frame-Options.",
			"vercel.json",
			"Add a `headers` entry setting Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, and X-Content-Type-Options."))
	} else {
		findings = append(findings, passFinding("prj-missing-headers",
			"Security headers configured in vercel.json", catConfig,
			"vercel.json configures one or more security headers.", "vercel.json"))
	}

	return findings
}

// --- helpers ---

func loadGitignoreEnvCoverage(fsys fs.FS) bool {
	data, err := fs.ReadFile(fsys, ".gitignore")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if l == ".env" || l == ".env*" || l == ".env.*" || l == "*.env" ||
			strings.HasPrefix(l, ".env*") || l == ".env.local" {
			return true
		}
	}
	return false
}

func splitPublicPrefix(key string) (prefix, rest string, ok bool) {
	for _, p := range publicPrefixes {
		if strings.HasPrefix(key, p) {
			return strings.TrimSuffix(p, "_"), strings.TrimPrefix(key, p), true
		}
	}
	return "", "", false
}

// matchesSecretToken reports whether the value matches a strong, recognizable
// credential shape (AWS key, sk- key, GitHub/Slack token, JWT, PEM, Google API
// key). This is the high-precision signal with negligible false positives —
// used to gate the CRITICAL public-prefix leak finding so intentionally-public
// values (Stripe *publishable* keys, public URLs, build IDs) are not flagged.
func matchesSecretToken(v string) bool {
	for _, re := range secretValueRes {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

// looksLikeSecretValue is the broader signal: a known token shape OR a long,
// high-entropy opaque value. The entropy fallback adds recall for unrecognized
// secret formats but is noisier, so it is only used where the surrounding
// context (a sensitive key name, a committable file) already raises suspicion —
// never to gate the public-prefix leak finding.
func looksLikeSecretValue(v string) bool {
	if matchesSecretToken(v) {
		return true
	}
	// High-entropy, long, opaque token (no spaces) — secondary signal.
	if len(v) >= 24 && !strings.ContainsAny(v, " \t/") && shannonEntropy(v) >= 3.5 {
		return true
	}
	return false
}

// looksRealValue is a weaker check used only alongside a sensitive KEY name:
// any non-placeholder value of reasonable length counts.
func looksRealValue(v string) bool {
	return len(v) >= 6 && !isPlaceholder(v)
}

func isPlaceholder(v string) bool {
	return placeholderRe.MatchString(strings.TrimSpace(v))
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	// Strip trailing inline comment for unquoted values.
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

func isExternalDestination(dest string) bool {
	d := strings.TrimSpace(strings.ToLower(dest))
	return strings.HasPrefix(d, "http://") || strings.HasPrefix(d, "https://") || strings.HasPrefix(d, "//")
}

func hasSecurityHeader(headers []struct {
	Source  string `json:"source"`
	Headers []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"headers"`
}) bool {
	want := map[string]bool{
		"content-security-policy":   true,
		"strict-transport-security": true,
		"x-frame-options":           true,
		"x-content-type-options":    true,
	}
	for _, h := range headers {
		for _, kv := range h.Headers {
			if want[strings.ToLower(kv.Key)] {
				return true
			}
		}
	}
	return false
}

// matchAssignTrue reports whether body contains `key: true` (tolerant of
// whitespace), the common form for the boolean Next.js config flags checked.
func matchAssignTrue(body, key string) bool {
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(key) + `\s*:\s*true\b`)
	return re.MatchString(body)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func ftoa(f float64) string {
	whole := int(f)
	frac := int((f-float64(whole))*10 + 0.5)
	if frac >= 10 {
		whole++
		frac = 0
	}
	return itoa(whole) + "." + itoa(frac)
}

// finding constructors

// withDetails attaches a Details map to a finding (free function since
// models.Finding lives in another package and cannot carry methods here).
func withDetails(f models.Finding, d map[string]string) models.Finding {
	f.Details = d
	return f
}

func passFinding(id, title, category, desc, resID string) models.Finding {
	return models.Finding{
		CheckID: id, Title: title, Category: category,
		Severity: models.Info, Status: models.Pass, RiskScore: 0,
		Description: desc, ResourceType: "file", ResourceID: resID, ResourceName: resID,
	}
}

func infoFinding(id, title, category, desc, resID string) models.Finding {
	return models.Finding{
		CheckID: id, Title: title, Category: category,
		Severity: models.Info, Status: models.Warn, RiskScore: 0.5,
		Description: desc, ResourceType: "file", ResourceID: resID, ResourceName: resID,
	}
}

func errorFinding(id, title, category, desc, resID string) models.Finding {
	return models.Finding{
		CheckID: id, Title: title, Category: category,
		Severity: models.Info, Status: models.Error,
		Description: desc, ResourceType: "file", ResourceID: resID, ResourceName: resID,
	}
}

func failFinding(id, title, category string, sev models.Severity, risk float64, rationale, desc, resID, rem string) models.Finding {
	return models.Finding{
		CheckID: id, Title: title, Category: category,
		Severity: sev, Status: models.Fail, RiskScore: risk,
		Rationale: rationale, Description: desc,
		ResourceType: "file", ResourceID: resID, ResourceName: resID, Remediation: rem,
	}
}

func warnFinding(id, title, category string, sev models.Severity, risk float64, rationale, desc, resID, rem string) models.Finding {
	return models.Finding{
		CheckID: id, Title: title, Category: category,
		Severity: sev, Status: models.Warn, RiskScore: risk,
		Rationale: rationale, Description: desc,
		ResourceType: "file", ResourceID: resID, ResourceName: resID, Remediation: rem,
	}
}
