package prober

import (
	"net/url"
	"testing"
	"unicode/utf8"

	"github.com/Su1ph3r/vercelsior/internal/models"
)

// mockFetcher routes each request through a user-supplied function so tests can
// return canned responses keyed by URL and header presence.
type mockFetcher struct {
	fn func(method, url string, headers map[string]string) (*Response, error)
}

func (m *mockFetcher) Fetch(method, url string, headers map[string]string) (*Response, error) {
	return m.fn(method, url, headers)
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}

func findByID(fs []models.Finding, id string) *models.Finding {
	for i := range fs {
		if fs[i].CheckID == id {
			return &fs[i]
		}
	}
	return nil
}

func nextResp(status int, headers map[string]string, body string) *Response {
	h := map[string]string{"x-powered-by": "Next.js"}
	for k, v := range headers {
		h[k] = v
	}
	return &Response{Status: status, Headers: h, Body: body}
}

func TestCheckMiddlewareBypass_Vulnerable(t *testing.T) {
	target := mustURL(t, "https://app.vercel.app/dashboard")
	// Baseline: blocked (redirect to login). With bypass header: 200.
	base := nextResp(307, map[string]string{"location": "/login?next=/dashboard"}, "")
	f := &mockFetcher{fn: func(method, u string, h map[string]string) (*Response, error) {
		if h["x-middleware-subrequest"] != "" {
			return nextResp(200, nil, "<html>secret dashboard</html>"), nil
		}
		return base, nil
	}}

	got := checkMiddlewareBypass(target, base, true, f)
	f0 := findByID(got, "prb-cve-2025-29927")
	if f0 == nil {
		t.Fatal("no CVE finding produced")
	}
	if f0.Status != models.Fail || f0.Severity != models.Critical {
		t.Errorf("status/severity = %s/%s; want FAIL/CRITICAL", f0.Status, f0.Severity)
	}
	if len(f0.PocEvidence) != 2 {
		t.Errorf("evidence count = %d; want 2 (baseline + bypass)", len(f0.PocEvidence))
	}
	if f0.Details["bypass_payload"] == "" {
		t.Error("expected bypass_payload detail recorded")
	}
}

func TestCheckMiddlewareBypass_NotVulnerable(t *testing.T) {
	target := mustURL(t, "https://app.vercel.app/dashboard")
	base := nextResp(307, map[string]string{"location": "/login"}, "")
	f := &mockFetcher{fn: func(method, u string, h map[string]string) (*Response, error) {
		// Still blocked even with the header — middleware enforced.
		return base, nil
	}}
	got := checkMiddlewareBypass(target, base, true, f)
	f0 := findByID(got, "prb-cve-2025-29927")
	if f0 == nil || f0.Status != models.Pass {
		t.Fatalf("want PASS finding; got %+v", f0)
	}
}

func TestCheckMiddlewareBypass_NotNextJS(t *testing.T) {
	target := mustURL(t, "https://example.com/")
	base := &Response{Status: 200, Headers: map[string]string{}, Body: "<html>plain</html>"}
	f := &mockFetcher{fn: func(method, u string, h map[string]string) (*Response, error) {
		t.Fatal("should not fetch bypass payloads for non-Next target")
		return nil, nil
	}}
	got := checkMiddlewareBypass(target, base, false, f)
	if f0 := findByID(got, "prb-cve-2025-29927"); f0 == nil || f0.Status != models.Pass {
		t.Fatalf("want PASS (not applicable); got %+v", f0)
	}
}

func TestCheckMiddlewareBypass_NoProtectionOnPath(t *testing.T) {
	target := mustURL(t, "https://app.vercel.app/")
	base := nextResp(200, nil, "<html>/_next/ home</html>") // 200, not blocked
	f := &mockFetcher{fn: func(method, u string, h map[string]string) (*Response, error) {
		t.Fatal("should not send bypass payloads when baseline is not blocked")
		return nil, nil
	}}
	got := checkMiddlewareBypass(target, base, true, f)
	if f0 := findByID(got, "prb-cve-2025-29927"); f0 == nil || f0.Status != models.Pass {
		t.Fatalf("want PASS (no protection on path); got %+v", f0)
	}
}

func TestCheckSourceMaps_Exposed(t *testing.T) {
	target := mustURL(t, "https://app.vercel.app/")
	body := `<html><script src="/_next/static/chunks/main-abc.js"></script></html>`
	base := nextResp(200, nil, body)
	mapJSON := `{"version":3,"sources":["../src/app.tsx"],"sourcesContent":["secret"],"mappings":"AAAA"}`
	f := &mockFetcher{fn: func(method, u string, h map[string]string) (*Response, error) {
		if u == "https://app.vercel.app/_next/static/chunks/main-abc.js.map" {
			return &Response{Status: 200, Headers: map[string]string{}, Body: mapJSON}, nil
		}
		return &Response{Status: 404, Headers: map[string]string{}, Body: "not found"}, nil
	}}
	got := checkSourceMaps(target, base, f)
	f0 := findByID(got, "prb-sourcemap")
	if f0 == nil || f0.Status != models.Fail {
		t.Fatalf("want FAIL source-map finding; got %+v", f0)
	}
	if f0.ResourceID != "https://app.vercel.app/_next/static/chunks/main-abc.js.map" {
		t.Errorf("resource = %q; want the .map URL", f0.ResourceID)
	}
}

func TestCheckSourceMaps_NotExposed(t *testing.T) {
	target := mustURL(t, "https://app.vercel.app/")
	base := nextResp(200, nil, `<script src="/_next/static/chunks/main.js"></script>`)
	f := &mockFetcher{fn: func(method, u string, h map[string]string) (*Response, error) {
		return &Response{Status: 404, Headers: map[string]string{}, Body: "not found"}, nil
	}}
	got := checkSourceMaps(target, base, f)
	if f0 := findByID(got, "prb-sourcemap"); f0 == nil || f0.Status != models.Pass {
		t.Fatalf("want PASS; got %+v", f0)
	}
}

func TestCheckSourceMaps_IgnoresOffHostScripts(t *testing.T) {
	target := mustURL(t, "https://app.vercel.app/")
	// Script hosted on a CDN — must not be fetched (same-host policy).
	base := nextResp(200, nil, `<script src="https://cdn.evil.com/x.js"></script>`)
	f := &mockFetcher{fn: func(method, u string, h map[string]string) (*Response, error) {
		t.Fatalf("must not fetch off-host URL %q", u)
		return nil, nil
	}}
	got := checkSourceMaps(target, base, f)
	// Off-host scripts yield zero same-host candidates: the check could not
	// test anything, so it must report ERROR (not a misleading "clean" PASS).
	if f0 := findByID(got, "prb-sourcemap"); f0 == nil || f0.Status != models.Error {
		t.Fatalf("want ERROR (no same-host bundles to test); got %+v", f0)
	}
}

func TestCheckMiddlewareBypass_AllProbesError(t *testing.T) {
	target := mustURL(t, "https://app.vercel.app/dashboard")
	base := nextResp(403, nil, "") // access-controlled baseline
	f := &mockFetcher{fn: func(method, u string, h map[string]string) (*Response, error) {
		if h["x-middleware-subrequest"] != "" {
			return nil, errString("connection reset by WAF") // every bypass probe fails
		}
		return base, nil
	}}
	got := checkMiddlewareBypass(target, base, true, f)
	f0 := findByID(got, "prb-cve-2025-29927")
	if f0 == nil || f0.Status != models.Error {
		t.Fatalf("want ERROR when all bypass probes fail (must not assert safety); got %+v", f0)
	}
}

func TestCheckSourceMaps_AllFetchesError(t *testing.T) {
	target := mustURL(t, "https://app.vercel.app/")
	base := nextResp(200, nil, `<script src="/_next/static/chunks/main.js"></script>`)
	f := &mockFetcher{fn: func(method, u string, h map[string]string) (*Response, error) {
		return nil, errString("timeout") // candidate exists but can't be fetched
	}}
	got := checkSourceMaps(target, base, f)
	if f0 := findByID(got, "prb-sourcemap"); f0 == nil || f0.Status != models.Error {
		t.Fatalf("want ERROR when candidates exist but none fetch; got %+v", f0)
	}
}

func TestCheckSecurityHeaders_AllMissing(t *testing.T) {
	target := mustURL(t, "https://app.vercel.app/")
	base := &Response{Status: 200, Headers: map[string]string{}, Body: ""}
	got := checkSecurityHeaders(target, base)
	wantWarn := []string{"prb-header-csp", "prb-header-hsts", "prb-header-xfo", "prb-header-xcto", "prb-header-referrer", "prb-header-permissions"}
	for _, id := range wantWarn {
		f := findByID(got, id)
		if f == nil || f.Status != models.Warn {
			t.Errorf("%s: want WARN; got %+v", id, f)
		}
	}
}

func TestCheckSecurityHeaders_FrameAncestorsSatisfiesXFO(t *testing.T) {
	target := mustURL(t, "https://app.vercel.app/")
	base := &Response{Status: 200, Body: "", Headers: map[string]string{
		"content-security-policy": "default-src 'self'; frame-ancestors 'none'",
	}}
	got := checkSecurityHeaders(target, base)
	if f := findByID(got, "prb-header-xfo"); f == nil || f.Status != models.Pass {
		t.Errorf("frame-ancestors in CSP should satisfy clickjacking check; got %+v", f)
	}
	// CSP itself is present, so its check should PASS too.
	if f := findByID(got, "prb-header-csp"); f == nil || f.Status != models.Pass {
		t.Errorf("CSP present should PASS; got %+v", f)
	}
}

func TestCheckSecurityHeaders_HSTSSkippedOnHTTP(t *testing.T) {
	target := mustURL(t, "http://app.local/")
	base := &Response{Status: 200, Headers: map[string]string{}, Body: ""}
	got := checkSecurityHeaders(target, base)
	if f := findByID(got, "prb-header-hsts"); f != nil {
		t.Errorf("HSTS check should be skipped on http; got %+v", f)
	}
}

func TestCheckInfoDisclosure(t *testing.T) {
	target := mustURL(t, "https://app.vercel.app/")
	base := &Response{Status: 200, Headers: map[string]string{"x-powered-by": "Next.js"}, Body: ""}
	got := checkInfoDisclosure(target, base)
	f := findByID(got, "prb-info-disclosure")
	if f == nil || f.Status != models.Warn {
		t.Fatalf("want WARN x-powered-by finding; got %+v", f)
	}
	if f.Details["x-powered-by"] != "Next.js" {
		t.Errorf("missing x-powered-by detail")
	}
}

func TestRun_Unreachable(t *testing.T) {
	target := mustURL(t, "https://down.vercel.app/")
	f := &mockFetcher{fn: func(method, u string, h map[string]string) (*Response, error) {
		return nil, errString("connection refused")
	}}
	res := Run(target, "test", f)
	if f0 := findByID(res.Findings, "prb-connect"); f0 == nil || f0.Status != models.Error {
		t.Fatalf("want ERROR connect finding; got %+v", f0)
	}
}

func TestRun_FullVulnerableTarget(t *testing.T) {
	target := mustURL(t, "https://app.vercel.app/dashboard")
	body := `<html><script src="/_next/static/chunks/main.js"></script>/_next/</html>`
	f := &mockFetcher{fn: func(method, u string, h map[string]string) (*Response, error) {
		switch {
		case h["x-middleware-subrequest"] != "":
			return nextResp(200, nil, "secret"), nil
		case u == "https://app.vercel.app/_next/static/chunks/main.js.map":
			return &Response{Status: 200, Body: `{"version":3,"sources":["a"],"mappings":"A"}`}, nil
		default:
			// baseline: blocked + no security headers + x-powered-by
			return nextResp(307, map[string]string{"location": "/login"}, body), nil
		}
	}}
	res := Run(target, "test", f)

	if f0 := findByID(res.Findings, "prb-cve-2025-29927"); f0 == nil || f0.Status != models.Fail {
		t.Error("expected CVE finding to FAIL")
	}
	if f0 := findByID(res.Findings, "prb-sourcemap"); f0 == nil || f0.Status != models.Fail {
		t.Error("expected source-map finding to FAIL")
	}
	if f0 := findByID(res.Findings, "prb-header-csp"); f0 == nil || f0.Status != models.Warn {
		t.Error("expected CSP header WARN")
	}
	// PostureScore must be computed and below 100 (we have failures).
	if res.Summary.PostureScore >= 100 || res.Summary.Total == 0 {
		t.Errorf("posture not computed correctly: total=%d score=%.1f", res.Summary.Total, res.Summary.PostureScore)
	}
}

func TestTruncate_UTF8Safe(t *testing.T) {
	cases := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"ascii under", "abc", 5, "abc"},
		{"ascii exact", "abc", 3, "abc"},
		{"ascii over", "abcdef", 3, "abc"},
		{"split 2-byte rune", "aé", 2, "a"},    // é = 2 bytes; cut at 2 would split it
		{"split emoji", "a\U0001f512", 3, "a"}, // 🔒 = 4 bytes
		{"rune at exact boundary kept", "aé", 3, "aé"},
		{"negative n", "abc", -1, "abc"},
	}
	for _, tc := range cases {
		got := truncate(tc.in, tc.n)
		if got != tc.want {
			t.Errorf("%s: truncate(%q,%d)=%q; want %q", tc.name, tc.in, tc.n, got, tc.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("%s: truncate produced invalid UTF-8: %q", tc.name, got)
		}
	}
}

func TestIsSourceMap(t *testing.T) {
	cases := map[string]bool{
		`{"version":3,"sources":["a"],"mappings":"A"}`: true,
		`{"version":3,"mappings":"AAAA"}`:              true,
		`<html>not json</html>`:                        false,
		`{"foo":"bar"}`:                                false,
		``:                                             false,
	}
	for body, want := range cases {
		if got := isSourceMap(body); got != want {
			t.Errorf("isSourceMap(%q) = %v; want %v", body, got, want)
		}
	}
}

func TestIsBlocked(t *testing.T) {
	cases := []struct {
		name string
		resp *Response
		want bool
	}{
		{"401", &Response{Status: 401}, true},
		{"403", &Response{Status: 403}, true},
		{"redirect to login", &Response{Status: 307, Headers: map[string]string{"location": "/login"}}, true},
		{"redirect elsewhere", &Response{Status: 307, Headers: map[string]string{"location": "/home"}}, false},
		{"200", &Response{Status: 200}, false},
	}
	for _, tc := range cases {
		if got := isBlocked(tc.resp); got != tc.want {
			t.Errorf("%s: isBlocked = %v; want %v", tc.name, got, tc.want)
		}
	}
}

func TestSameHostAbs(t *testing.T) {
	target := mustURL(t, "https://app.vercel.app/page")
	cases := map[string]string{
		"/_next/x.js":                 "https://app.vercel.app/_next/x.js",
		"https://app.vercel.app/y.js": "https://app.vercel.app/y.js",
		"https://cdn.other.com/z.js":  "", // off-host -> rejected
		"ftp://app.vercel.app/a":      "", // bad scheme -> rejected
	}
	for ref, want := range cases {
		if got := sameHostAbs(target, ref); got != want {
			t.Errorf("sameHostAbs(%q) = %q; want %q", ref, got, want)
		}
	}
}

// errString is a tiny error type so the test file needs no extra imports.
type errString string

func (e errString) Error() string { return string(e) }
