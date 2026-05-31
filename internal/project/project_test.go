package project

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/Su1ph3r/vercelsior/internal/models"
)

// errFS is an fs.FS whose every Open fails with a fixed error, used to
// simulate an unreadable (e.g. permission-denied) file that nonetheless exists.
type errFS struct{ err error }

func (e errFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: e.err}
}

func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

func findByID(fs []models.Finding, id string) *models.Finding {
	for i := range fs {
		if fs[i].CheckID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestPackageJSON_VulnerableNext(t *testing.T) {
	fsys := fstest.MapFS{
		"package.json": file(`{"dependencies":{"next":"14.2.0"}}`),
	}
	got := checkPackageJSON(fsys)
	f := findByID(got, "prj-next-cve")
	if f == nil || f.Status != models.Fail {
		t.Fatalf("want FAIL CVE finding; got %+v", f)
	}
	if f.Details["cves"] == "" {
		t.Error("expected cves detail")
	}
}

func TestPackageJSON_PatchedNext(t *testing.T) {
	// 16.2.0 is past every patched-version threshold in the matrix.
	fsys := fstest.MapFS{"package.json": file(`{"dependencies":{"next":"^16.2.0"}}`)}
	got := checkPackageJSON(fsys)
	if f := findByID(got, "prj-next-cve"); f == nil || f.Status != models.Pass {
		t.Fatalf("want PASS for patched next; got %+v", f)
	}
}

func TestPackageJSON_NotNext(t *testing.T) {
	fsys := fstest.MapFS{"package.json": file(`{"dependencies":{"react":"19.0.0"}}`)}
	if got := checkPackageJSON(fsys); len(got) != 0 {
		t.Errorf("non-Next project should produce no findings; got %d", len(got))
	}
}

func TestPackageJSON_Unpinned(t *testing.T) {
	fsys := fstest.MapFS{"package.json": file(`{"dependencies":{"next":"latest"}}`)}
	got := checkPackageJSON(fsys)
	if f := findByID(got, "prj-next-cve"); f == nil || f.Status != models.Warn {
		t.Fatalf("want WARN (unpinned); got %+v", f)
	}
}

func TestEnv_HardcodedSecret(t *testing.T) {
	fsys := fstest.MapFS{
		".env":       file("DATABASE_PASSWORD=sup3rs3cr3t-prod-value\nPORT=3000\n"),
		".gitignore": file(".env\n"),
	}
	got := checkEnvFiles(fsys, true)
	if f := findByID(got, "prj-env-secret"); f == nil || f.Status != models.Fail {
		t.Fatalf("want FAIL hardcoded-secret; got %+v", f)
	}
}

func TestEnv_TokenShapeSecret(t *testing.T) {
	fsys := fstest.MapFS{".env.production": file("SOME_VAR=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n")}
	got := checkEnvFiles(fsys, true)
	if f := findByID(got, "prj-env-secret"); f == nil || f.Status != models.Fail {
		t.Fatalf("want FAIL for GitHub token shape; got %+v", f)
	}
}

func TestEnv_PublicPrefixLeak(t *testing.T) {
	fsys := fstest.MapFS{".env": file("NEXT_PUBLIC_API_SECRET=sk-abcdefghijklmnopqrstuvwxyz\n")}
	got := checkEnvFiles(fsys, true)
	f := findByID(got, "prj-env-public-leak")
	if f == nil || f.Status != models.Fail || f.Severity != models.Critical {
		t.Fatalf("want CRITICAL public-leak; got %+v", f)
	}
}

func TestEnv_PublicPrefix_NoFalsePositiveOnPublicConfig(t *testing.T) {
	// Intentionally-public client config whose NAMES match sensitive tokens
	// ("auth", "key") but whose VALUES are public must NOT be flagged.
	fsys := fstest.MapFS{".env": file(
		"NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=myapp.firebaseapp.com\n" +
			"NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_realistic_publishable\n" +
			"NEXT_PUBLIC_API_URL=https://api.example.com\n")}
	got := checkEnvFiles(fsys, true)
	if f := findByID(got, "prj-env-public-leak"); f != nil {
		t.Errorf("public config must not be flagged as a leak; got %+v", f)
	}
}

func TestEnv_PublicPrefix_FlagsRealSecretValue(t *testing.T) {
	// A genuinely secret-shaped value under a public prefix IS a critical leak.
	fsys := fstest.MapFS{".env": file("NEXT_PUBLIC_KEY=AKIAIOSFODNN7EXAMPLE\n")}
	got := checkEnvFiles(fsys, true)
	f := findByID(got, "prj-env-public-leak")
	if f == nil || f.Status != models.Fail || f.Severity != models.Critical {
		t.Fatalf("want CRITICAL leak for secret-shaped value; got %+v", f)
	}
}

func TestEnv_PlaceholdersIgnored(t *testing.T) {
	fsys := fstest.MapFS{
		".env":       file("API_KEY=your-api-key-here\nSECRET_TOKEN=changeme\nFOO=${BAR}\n"),
		".gitignore": file(".env*\n"),
	}
	got := checkEnvFiles(fsys, true)
	if f := findByID(got, "prj-env-secret"); f != nil && f.Status == models.Fail {
		t.Errorf("placeholders must not be flagged as secrets; got %+v", f)
	}
}

func TestEnv_GitignoreMissing(t *testing.T) {
	fsys := fstest.MapFS{".env": file("FOO=bar\n")} // no .gitignore
	got := checkEnvFiles(fsys, loadGitignoreEnvCoverage(fsys))
	if f := findByID(got, "prj-env-gitignore"); f == nil || f.Status != models.Warn {
		t.Fatalf("want WARN gitignore; got %+v", f)
	}
}

func TestEnv_GitignoreCovered(t *testing.T) {
	fsys := fstest.MapFS{
		".env":       file("FOO=bar\n"),
		".gitignore": file("node_modules\n.env*\n"),
	}
	got := checkEnvFiles(fsys, loadGitignoreEnvCoverage(fsys))
	if f := findByID(got, "prj-env-gitignore"); f != nil {
		t.Errorf("gitignore covers .env; no warning expected; got %+v", f)
	}
}

func TestEnv_LocalFileNotTreatedAsCommittable(t *testing.T) {
	// .env.local is git-ignored by convention; a secret there is not a
	// "committed secret" finding (but token-shape still flags via value).
	fsys := fstest.MapFS{".env.local": file("DB_PASSWORD=realisticvalue123\n")}
	got := checkEnvFiles(fsys, true)
	if f := findByID(got, "prj-env-secret"); f != nil && f.Status == models.Fail {
		t.Errorf(".env.local sensitive-name value should not be a committed-secret FAIL; got %+v", f)
	}
}

func TestNextConfig_SourceMaps(t *testing.T) {
	fsys := fstest.MapFS{
		"next.config.js": file("module.exports = { productionBrowserSourceMaps: true }\n"),
	}
	got := checkNextConfig(fsys)
	if f := findByID(got, "prj-sourcemaps"); f == nil || f.Status != models.Warn {
		t.Fatalf("want WARN source maps; got %+v", f)
	}
}

func TestNextConfig_Clean(t *testing.T) {
	fsys := fstest.MapFS{"next.config.mjs": file("export default { reactStrictMode: true }\n")}
	got := checkNextConfig(fsys)
	if f := findByID(got, "prj-nextconfig"); f == nil || f.Status != models.Pass {
		t.Fatalf("want PASS clean config; got %+v", f)
	}
}

func TestVercelJSON_ExternalRedirect(t *testing.T) {
	fsys := fstest.MapFS{
		"vercel.json": file(`{"redirects":[{"source":"/go","destination":"https://evil.example.com"}]}`),
	}
	got := checkVercelJSON(fsys)
	if f := findByID(got, "prj-open-redirect"); f == nil || f.Status != models.Warn {
		t.Fatalf("want WARN open-redirect; got %+v", f)
	}
}

func TestVercelJSON_MissingHeaders(t *testing.T) {
	fsys := fstest.MapFS{"vercel.json": file(`{"redirects":[]}`)}
	got := checkVercelJSON(fsys)
	if f := findByID(got, "prj-missing-headers"); f == nil || f.Status != models.Warn {
		t.Fatalf("want WARN missing-headers; got %+v", f)
	}
}

func TestVercelJSON_WithCSPHeader(t *testing.T) {
	fsys := fstest.MapFS{"vercel.json": file(`{"headers":[{"source":"/(.*)","headers":[{"key":"Content-Security-Policy","value":"default-src 'self'"}]}]}`)}
	got := checkVercelJSON(fsys)
	if f := findByID(got, "prj-missing-headers"); f == nil || f.Status != models.Pass {
		t.Fatalf("want PASS with CSP header; got %+v", f)
	}
}

func TestRun_Integration(t *testing.T) {
	fsys := fstest.MapFS{
		"package.json":   file(`{"dependencies":{"next":"14.2.0"}}`),
		".env":           file("STRIPE_SECRET_KEY=sk-livedummyabcdefghijklmnop\nNEXT_PUBLIC_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"),
		"next.config.js": file("module.exports = { productionBrowserSourceMaps: true, poweredByHeader: true }"),
		"vercel.json":    file(`{"rewrites":[{"source":"/api/(.*)","destination":"https://backend.internal/$1"}]}`),
		// no .gitignore -> env-gitignore warning expected
	}
	res := Run(fsys, "/tmp/app", "test")

	wantFail := []string{"prj-next-cve", "prj-env-secret", "prj-env-public-leak"}
	for _, id := range wantFail {
		if f := findByID(res.Findings, id); f == nil || f.Status != models.Fail {
			t.Errorf("%s: want FAIL; got %+v", id, f)
		}
	}
	wantWarn := []string{"prj-sourcemaps", "prj-poweredby", "prj-external-rewrite", "prj-env-gitignore"}
	for _, id := range wantWarn {
		if f := findByID(res.Findings, id); f == nil || f.Status != models.Warn {
			t.Errorf("%s: want WARN; got %+v", id, f)
		}
	}
	if res.Summary.PostureScore >= 100 || res.Summary.Total == 0 {
		t.Errorf("posture not computed: total=%d score=%.1f", res.Summary.Total, res.Summary.PostureScore)
	}
}

func TestRun_EmptyDir(t *testing.T) {
	res := Run(fstest.MapFS{}, "/tmp/empty", "test")
	if f := findByID(res.Findings, "prj-scope"); f == nil {
		t.Fatal("empty dir should produce prj-scope finding")
	}
}

func TestUnreadableFilesReportError(t *testing.T) {
	// A present-but-unreadable file must surface as ERROR, never be silently
	// skipped (which would let a security check report nothing).
	fsys := errFS{err: fs.ErrPermission}

	if f := findByID(checkPackageJSON(fsys), "prj-next-cve"); f == nil || f.Status != models.Error {
		t.Errorf("package.json unreadable: want ERROR; got %+v", f)
	}
	if f := findByID(checkVercelJSON(fsys), "prj-vercel-json"); f == nil || f.Status != models.Error {
		t.Errorf("vercel.json unreadable: want ERROR; got %+v", f)
	}
	if f := findByID(checkNextConfig(fsys), "prj-nextconfig"); f == nil || f.Status != models.Error {
		t.Errorf("next.config unreadable: want ERROR; got %+v", f)
	}
	envFindings := checkEnvFiles(fsys, true)
	sawErr := false
	for _, f := range envFindings {
		if f.CheckID == "prj-env-secret" && f.Status == models.Error {
			sawErr = true
		}
	}
	if !sawErr {
		t.Errorf(".env unreadable: want an ERROR finding; got %+v", envFindings)
	}
}

func TestShannonEntropy(t *testing.T) {
	if shannonEntropy("aaaaaaaa") > 1.0 {
		t.Error("repeated char should have ~0 entropy")
	}
	if shannonEntropy("a1B2c3D4e5F6g7H8") < 3.0 {
		t.Error("mixed string should have high entropy")
	}
}
