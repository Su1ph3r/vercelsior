// Package prober implements Vercelsior's black-box DAST mode: it tests a
// deployed URL from the outside, with no API token, from an attacker's
// perspective. It is decoupled from the network via the Fetcher interface so
// the checks are unit-testable with canned responses.
//
// Checks (v1):
//   - CVE-2025-29927: Next.js middleware auth bypass via x-middleware-subrequest
//   - Source-map exposure (/_next/static/**/*.js.map leaking original source)
//   - Security-header hygiene (CSP, HSTS, X-Frame-Options, etc.) on live responses
//   - Information-disclosure headers (x-powered-by tech/version leakage)
package prober

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Su1ph3r/vercelsior/internal/models"
)

// Response is a probed HTTP response. Headers are lowercased, first-value-only.
type Response struct {
	Status  int
	Headers map[string]string
	Body    string
	URL     string
}

// Fetcher performs a single HTTP request to an absolute URL with optional
// headers. The real implementation wraps the SSRF-guarded client.Probe; tests
// supply a mock. Redirects must NOT be followed — the raw 3xx is a signal the
// middleware-bypass check depends on.
type Fetcher interface {
	Fetch(method, absURL string, headers map[string]string) (*Response, error)
}

// cvePayloads are the x-middleware-subrequest values that trigger
// CVE-2025-29927 across affected Next.js versions. The value is the middleware
// module path, repeated up to the recursion-depth limit; the spelling differs
// by layout (root vs src/) and Next.js major.
var cvePayloads = []string{
	"middleware",
	"src/middleware",
	"middleware:middleware:middleware:middleware:middleware",
	"src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
	"pages/_middleware",
	"src/pages/_middleware",
}

var (
	scriptSrcRe   = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js)["']`)
	sourceMapRe   = regexp.MustCompile(`(?i)//[#@]\s*sourceMappingURL=(\S+)`)
	authHintRe    = regexp.MustCompile(`(?i)(login|signin|sign-in|auth|sso|account/login)`)
	maxScriptScan = 8
)

// Run executes all probe checks against target and returns a ScanResult whose
// Findings feed the standard reporters (terminal/json/html/md/sarif).
func Run(target *url.URL, scanID string, f Fetcher) *models.ScanResult {
	result := &models.ScanResult{
		ScanID:      scanID,
		StartedAt:   time.Now().UTC(),
		AccountName: target.String(),
		Findings:    []models.Finding{},
	}

	base, err := f.Fetch("GET", target.String(), nil)
	if err != nil {
		result.Findings = append(result.Findings, models.Finding{
			CheckID:      "prb-connect",
			Title:        "Target unreachable",
			Category:     "Probe",
			Severity:     models.Info,
			Status:       models.Error,
			Description:  "Could not reach the target URL: " + err.Error(),
			ResourceType: "url",
			ResourceID:   target.String(),
		})
		result.Compute()
		return result
	}

	isNext := looksLikeNextJS(base)

	result.Findings = append(result.Findings, checkMiddlewareBypass(target, base, isNext, f)...)
	result.Findings = append(result.Findings, checkSourceMaps(target, base, f)...)
	result.Findings = append(result.Findings, checkSecurityHeaders(target, base)...)
	result.Findings = append(result.Findings, checkInfoDisclosure(target, base)...)

	result.Compute()
	return result
}

// looksLikeNextJS reports whether the response is plausibly a Next.js app, used
// to scope the CVE-2025-29927 check and avoid false claims against non-Next
// sites.
func looksLikeNextJS(r *Response) bool {
	if strings.Contains(strings.ToLower(r.Headers["x-powered-by"]), "next.js") {
		return true
	}
	if _, ok := r.Headers["x-nextjs-cache"]; ok {
		return true
	}
	if _, ok := r.Headers["x-nextjs-prerender"]; ok {
		return true
	}
	return strings.Contains(r.Body, "/_next/") || strings.Contains(r.Body, "__NEXT_DATA__")
}

// checkMiddlewareBypass tests CVE-2025-29927. It compares a baseline request
// (no header) against requests carrying the x-middleware-subrequest bypass
// header. A finding is raised only when the baseline is access-controlled
// (401/403, or a redirect to an auth page) AND the bypass header flips the
// response to a 2xx — i.e. the protection was observably skipped.
func checkMiddlewareBypass(target *url.URL, base *Response, isNext bool, f Fetcher) []models.Finding {
	const id = "prb-cve-2025-29927"
	const title = "Next.js middleware auth bypass (CVE-2025-29927)"
	const cat = "Middleware Auth Bypass"
	res := target.String()

	if !isNext {
		return []models.Finding{passFinding(id, title, cat,
			"Target does not appear to be a Next.js app; middleware-bypass check not applicable.", res)}
	}
	if !isBlocked(base) {
		// Nothing to bypass on this path — middleware either allows it or the
		// path isn't gated. Tell the operator how to test a protected route.
		return []models.Finding{passFinding(id, title, cat,
			"No access control observed on this path (baseline was not 401/403/auth-redirect). Re-run probe against a protected path to test the bypass.", res)}
	}

	probed := 0
	var lastErr error
	for _, payload := range cvePayloads {
		resp, err := f.Fetch("GET", target.String(), map[string]string{"x-middleware-subrequest": payload})
		if err != nil || resp == nil {
			if err != nil {
				lastErr = err
			}
			continue
		}
		probed++
		if resp.Status >= 200 && resp.Status < 300 {
			ev := []models.PocEvidence{
				{
					Request:  models.PocRequest{Method: "GET", URL: res},
					Response: models.PocResponse{StatusCode: base.Status, Body: truncate(locationLine(base), 2000)},
					Summary:  "Baseline (no bypass header) is access-controlled.",
				},
				{
					Request:  models.PocRequest{Method: "GET", URL: res},
					Response: models.PocResponse{StatusCode: resp.Status, Body: truncate(resp.Body, 2000)},
					Summary:  "With header `x-middleware-subrequest: " + payload + "` the request returns " + statusText(resp.Status) + " — middleware was skipped.",
				},
			}
			fnd := failFinding(id, title, cat, models.Critical, 9.3,
				"A request that is blocked without the header succeeds with the x-middleware-subrequest bypass header, proving middleware (and any auth/authorization it enforces) is skipped. Affected Next.js versions: 11.1.4–15.2.2 (fixed in 15.2.3, 14.2.25, 13.5.9, 12.3.5).",
				"Middleware-based access control on this route can be bypassed by sending the `x-middleware-subrequest` header (CVE-2025-29927).",
				res,
				"Upgrade Next.js to a patched release (>=15.2.3 / 14.2.25 / 13.5.9 / 12.3.5). As mitigation, block external requests carrying the `x-middleware-subrequest` header at the edge/WAF, and do not rely on middleware as the sole authorization layer.",
				ev)
			fnd.Details = map[string]string{"bypass_payload": payload, "baseline_status": statusText(base.Status)}
			return []models.Finding{fnd}
		}
	}

	// If not a single bypass payload yielded a usable response (e.g. the edge
	// WAF tarpits/blocks requests carrying x-middleware-subrequest, or the
	// network failed), we cannot assert the target is safe. Emit ERROR rather
	// than a misleading "not exploitable" PASS.
	if probed == 0 {
		msg := "Could not evaluate CVE-2025-29927: every x-middleware-subrequest probe failed, so exploitability is unknown (not a confirmation of safety)."
		if lastErr != nil {
			msg += " Last error: " + lastErr.Error()
		}
		return []models.Finding{errorFinding(id, title, cat, msg, res)}
	}

	return []models.Finding{passFinding(id, title, cat,
		"Baseline is access-controlled and the x-middleware-subrequest bypass payloads did not flip it to a 2xx — not exploitable via CVE-2025-29927.", res)}
}

// checkSourceMaps looks for exposed JavaScript source maps, which leak original
// (pre-minification) source — comments, internal paths, and sometimes secrets.
func checkSourceMaps(target *url.URL, base *Response, f Fetcher) []models.Finding {
	const id = "prb-sourcemap"
	const title = "Exposed JavaScript source map"
	const cat = "Source Map Exposure"

	candidates := discoverMapURLs(target, base)
	if len(candidates) == 0 {
		// Nothing to test: no same-host <script> bundles were found in the
		// document (static page, client-injected scripts, or the body was
		// truncated at the read cap). Report honestly instead of implying the
		// target was scanned and is clean.
		return []models.Finding{errorFinding(id, title, cat,
			"No same-host JavaScript bundles were discovered in the page to test for source maps (static page, client-injected scripts, or response body exceeded the read limit).",
			target.String())}
	}

	var findings []models.Finding
	seen := map[string]bool{}
	checked := 0
	fetched := 0
	var lastErr error

	for _, mapURL := range candidates {
		if seen[mapURL] || checked >= maxScriptScan {
			continue
		}
		seen[mapURL] = true
		checked++

		resp, err := f.Fetch("GET", mapURL, nil)
		if err != nil || resp == nil {
			if err != nil {
				lastErr = err
			}
			continue
		}
		fetched++
		if resp.Status == 200 && isSourceMap(resp.Body) {
			ev := []models.PocEvidence{{
				Request:  models.PocRequest{Method: "GET", URL: mapURL},
				Response: models.PocResponse{StatusCode: resp.Status, Body: truncate(resp.Body, 2000)},
				Summary:  "The .map responds 200 with a valid source-map document (version + sources).",
			}}
			findings = append(findings, failFinding(id, title, cat, models.Medium, 5.0,
				"The source map is publicly fetchable and contains the original, un-minified source (the \"sources\"/\"sourcesContent\" fields), exposing internal logic, file paths, and occasionally hardcoded secrets.",
				"A JavaScript source map is publicly accessible: "+mapURL,
				mapURL,
				"Disable source-map generation for production, or restrict the deployment so .map files are not served. In Next.js set `productionBrowserSourceMaps: false` (the default) and ensure no build step uploads maps to the public bundle.",
				ev))
		}
	}

	if len(findings) == 0 {
		// Candidates existed but none could be fetched — don't claim "clean".
		if fetched == 0 {
			msg := "Discovered " + strconv.Itoa(checked) + " candidate source-map URL(s) but none could be fetched, so source-map exposure is unknown (not a confirmation of safety)."
			if lastErr != nil {
				msg += " Last error: " + lastErr.Error()
			}
			return []models.Finding{errorFinding(id, title, cat, msg, target.String())}
		}
		return []models.Finding{passFinding(id, title, cat,
			"Fetched "+strconv.Itoa(fetched)+" discovered bundle map URL(s); none exposed a valid source map.", target.String())}
	}
	return findings
}

// securityHeader describes a header-hygiene check.
type securityHeader struct {
	id        string
	name      string // human label
	header    string // lowercased header key
	altCSP    string // optional CSP directive that also satisfies it (e.g. frame-ancestors)
	severity  models.Severity
	risk      float64
	httpsOnly bool
	title     string
	desc      string
	rem       string
}

var securityHeaders = []securityHeader{
	{"prb-header-csp", "Content-Security-Policy", "content-security-policy", "", models.Medium, 5.0, false,
		"Missing Content-Security-Policy header",
		"No Content-Security-Policy is set, so the browser applies no allowlist for scripts, styles, or framing — removing a key defense against XSS and data injection.",
		"Set a Content-Security-Policy header (start in report-only mode) restricting script/style/connect sources. In Next.js, configure it via `headers()` in next.config.js or middleware."},
	{"prb-header-hsts", "Strict-Transport-Security", "strict-transport-security", "", models.Medium, 4.0, true,
		"Missing Strict-Transport-Security header",
		"No HSTS header is set, so a browser may downgrade to HTTP and is exposed to SSL-stripping / MITM on the first or subsequent visits.",
		"Set `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`. Vercel serves HTTPS by default; add the header via next.config.js `headers()`."},
	{"prb-header-xfo", "X-Frame-Options / frame-ancestors", "x-frame-options", "frame-ancestors", models.Medium, 4.0, false,
		"Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)",
		"Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so the site can be embedded in a hostile iframe and used for clickjacking.",
		"Set `X-Frame-Options: DENY` (or `SAMEORIGIN`), or a CSP `frame-ancestors 'none'` directive."},
	{"prb-header-xcto", "X-Content-Type-Options", "x-content-type-options", "", models.Low, 2.0, false,
		"Missing X-Content-Type-Options header",
		"Without `X-Content-Type-Options: nosniff`, browsers may MIME-sniff responses and execute content as a different type than declared.",
		"Set `X-Content-Type-Options: nosniff`."},
	{"prb-header-referrer", "Referrer-Policy", "referrer-policy", "", models.Low, 1.5, false,
		"Missing Referrer-Policy header",
		"No Referrer-Policy is set, so full URLs (which may contain tokens or identifiers) can leak to third-party origins via the Referer header.",
		"Set `Referrer-Policy: strict-origin-when-cross-origin` (or stricter)."},
	{"prb-header-permissions", "Permissions-Policy", "permissions-policy", "", models.Low, 1.5, false,
		"Missing Permissions-Policy header",
		"No Permissions-Policy is set, so powerful browser features (camera, geolocation, microphone) are not explicitly restricted.",
		"Set a `Permissions-Policy` header disabling features the app does not use, e.g. `geolocation=(), camera=(), microphone=()`."},
}

func checkSecurityHeaders(target *url.URL, base *Response) []models.Finding {
	const cat = "Security Headers"
	res := target.String()
	csp := base.Headers["content-security-policy"]
	isHTTPS := strings.EqualFold(target.Scheme, "https")

	var findings []models.Finding
	for _, h := range securityHeaders {
		if h.httpsOnly && !isHTTPS {
			continue
		}
		present := base.Headers[h.header] != ""
		if !present && h.altCSP != "" && csp != "" && strings.Contains(strings.ToLower(csp), h.altCSP) {
			present = true
		}
		if present {
			findings = append(findings, passFinding(h.id, h.name+" present", cat,
				h.name+" is set on the response.", res))
			continue
		}
		ev := []models.PocEvidence{{
			Request:  models.PocRequest{Method: "GET", URL: res},
			Response: models.PocResponse{StatusCode: base.Status, Body: "(" + h.header + " absent from response headers)"},
			Summary:  h.name + " was not present in the live response headers.",
		}}
		findings = append(findings, warnFinding(h.id, h.title, cat, h.severity, h.risk, h.desc, h.desc, res, h.rem, ev))
	}
	return findings
}

// checkInfoDisclosure flags response headers that reveal stack/version detail
// useful to an attacker for targeting known CVEs.
func checkInfoDisclosure(target *url.URL, base *Response) []models.Finding {
	const id = "prb-info-disclosure"
	const cat = "Information Disclosure"
	res := target.String()

	if poweredBy := base.Headers["x-powered-by"]; poweredBy != "" {
		ev := []models.PocEvidence{{
			Request:  models.PocRequest{Method: "GET", URL: res},
			Response: models.PocResponse{StatusCode: base.Status, Body: "x-powered-by: " + poweredBy},
			Summary:  "The response advertises its technology stack via X-Powered-By.",
		}}
		f := warnFinding(id, "Technology disclosure via X-Powered-By", cat, models.Low, 2.0,
			"The X-Powered-By header reveals the framework (and sometimes version), helping an attacker map the target to known CVEs.",
			"Response advertises its stack via `X-Powered-By: "+poweredBy+"`.",
			res,
			"Remove the X-Powered-By header. In Next.js set `poweredByHeader: false` in next.config.js.",
			ev)
		f.Details = map[string]string{"x-powered-by": poweredBy}
		return []models.Finding{f}
	}
	return []models.Finding{passFinding(id, "No technology disclosure via X-Powered-By", cat,
		"No X-Powered-By header was present.", res)}
}

// --- helpers ---

// isBlocked reports whether a response represents access control: an explicit
// 401/403, or a redirect whose Location points at an auth/login destination.
func isBlocked(r *Response) bool {
	if r.Status == 401 || r.Status == 403 {
		return true
	}
	if r.Status >= 300 && r.Status < 400 {
		loc := r.Headers["location"]
		if loc != "" && authHintRe.MatchString(loc) {
			return true
		}
	}
	return false
}

func discoverMapURLs(target *url.URL, base *Response) []string {
	var urls []string
	add := func(ref string) {
		if abs := sameHostAbs(target, ref); abs != "" {
			urls = append(urls, abs)
		}
	}
	// Explicit sourceMappingURL comments in the document.
	for _, m := range sourceMapRe.FindAllStringSubmatch(base.Body, -1) {
		add(m[1])
	}
	// Inferred <script src=...js> -> <src>.map.
	scripts := scriptSrcRe.FindAllStringSubmatch(base.Body, -1)
	for i, m := range scripts {
		if i >= maxScriptScan {
			break
		}
		add(m[1] + ".map")
	}
	return urls
}

// sameHostAbs resolves ref against target and returns the absolute URL only if
// it stays on the same host (so probe never chases off-host script/CDN URLs —
// reducing both false positives and SSRF surface).
func sameHostAbs(target *url.URL, ref string) string {
	u, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return ""
	}
	abs := target.ResolveReference(u)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	if !strings.EqualFold(abs.Hostname(), target.Hostname()) {
		return ""
	}
	return abs.String()
}

func isSourceMap(body string) bool {
	b := strings.TrimSpace(body)
	if !strings.HasPrefix(b, "{") {
		return false
	}
	return strings.Contains(b, "\"version\"") &&
		(strings.Contains(b, "\"sources\"") || strings.Contains(b, "\"mappings\""))
}

func locationLine(r *Response) string {
	if loc := r.Headers["location"]; loc != "" {
		return "Location: " + loc
	}
	return statusText(r.Status)
}

func statusText(code int) string {
	switch code {
	case 200:
		return "200 OK"
	case 401:
		return "401 Unauthorized"
	case 403:
		return "403 Forbidden"
	case 307:
		return "307 Temporary Redirect"
	case 308:
		return "308 Permanent Redirect"
	case 302:
		return "302 Found"
	}
	return strconv.Itoa(code)
}

// truncate cuts s to at most n bytes on a valid UTF-8 rune boundary. Probe PoC
// evidence bodies are arbitrary server-controlled content (HTML, source-map
// JSON) that often contains multi-byte runes; a raw byte slice could split one
// and corrupt the body to U+FFFD when the report is JSON-marshaled.
func truncate(s string, n int) string {
	if n < 0 || len(s) <= n {
		return s
	}
	t := s[:n]
	for len(t) > 0 && !utf8.ValidString(t) {
		t = t[:len(t)-1]
	}
	return t
}

// finding constructors mirroring internal/checks helper semantics.

func passFinding(id, title, category, desc, resID string) models.Finding {
	return models.Finding{
		CheckID: id, Title: title, Category: category,
		Severity: models.Info, Status: models.Pass, RiskScore: 0,
		Description: desc, ResourceType: "url", ResourceID: resID, ResourceName: resID,
	}
}

// errorFinding reports that a check could not be evaluated (network errors,
// nothing to test). It is deliberately NOT a Pass: a security check that did
// not run must never assert safety.
func errorFinding(id, title, category, desc, resID string) models.Finding {
	return models.Finding{
		CheckID: id, Title: title, Category: category,
		Severity: models.Info, Status: models.Error,
		Description: desc, ResourceType: "url", ResourceID: resID, ResourceName: resID,
	}
}

func failFinding(id, title, category string, sev models.Severity, risk float64, rationale, desc, resID, rem string, ev []models.PocEvidence) models.Finding {
	return models.Finding{
		CheckID: id, Title: title, Category: category,
		Severity: sev, Status: models.Fail, RiskScore: risk,
		Rationale: rationale, Description: desc,
		ResourceType: "url", ResourceID: resID, ResourceName: resID,
		Remediation: rem, PocEvidence: ev,
	}
}

func warnFinding(id, title, category string, sev models.Severity, risk float64, rationale, desc, resID, rem string, ev []models.PocEvidence) models.Finding {
	return models.Finding{
		CheckID: id, Title: title, Category: category,
		Severity: sev, Status: models.Warn, RiskScore: risk,
		Rationale: rationale, Description: desc,
		ResourceType: "url", ResourceID: resID, ResourceName: resID,
		Remediation: rem, PocEvidence: ev,
	}
}
