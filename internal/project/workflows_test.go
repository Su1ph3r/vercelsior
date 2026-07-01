package project

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Su1ph3r/vercelsior/internal/models"
)

func TestWorkflows_UnkeyedCacheFlagged(t *testing.T) {
	wf := `name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Cache deps
        uses: actions/cache@v4
        with:
          path: ~/.npm
          key: ${{ runner.os }}-node
      - run: npm ci
`
	fsys := fstest.MapFS{".github/workflows/ci.yml": file(wf)}
	got := checkWorkflows(fsys)
	f := findByID(got, "prj-gha-cache-poison")
	if f == nil || f.Status != models.Warn {
		t.Fatalf("want WARN cache-poison finding; got %+v", f)
	}
	if f.Details["cwe"] != "CWE-494" {
		t.Errorf("expected CWE-494 detail; got %+v", f.Details)
	}
}

func TestWorkflows_HashBoundCachePasses(t *testing.T) {
	wf := `jobs:
  build:
    steps:
      - name: Cache
        uses: actions/cache@v4
        with:
          path: ~/.npm
          key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
`
	fsys := fstest.MapFS{".github/workflows/ci.yml": file(wf)}
	got := checkWorkflows(fsys)
	f := findByID(got, "prj-gha-cache-poison")
	if f == nil || f.Status != models.Pass {
		t.Fatalf("want PASS for hash-bound cache; got %+v", f)
	}
}

func TestWorkflows_BroadRestoreKeysFlagged(t *testing.T) {
	wf := `jobs:
  build:
    steps:
      - uses: actions/cache@v4
        with:
          key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
          restore-keys: |
            ${{ runner.os }}-node-
            ${{ runner.os }}-
`
	fsys := fstest.MapFS{".github/workflows/ci.yml": file(wf)}
	got := checkWorkflows(fsys)
	if f := findByID(got, "prj-gha-cache-restore-keys"); f == nil || f.Status != models.Warn {
		t.Fatalf("want WARN broad restore-keys finding; got %+v", f)
	}
	// A hash-bound key with only broad restore-keys is not the full-poison case.
	if f := findByID(got, "prj-gha-cache-poison"); f != nil && f.Status == models.Warn {
		t.Errorf("did not expect full cache-poison WARN; got %+v", f)
	}
}

func TestWorkflows_HashBoundRestoreKeysPasses(t *testing.T) {
	wf := `jobs:
  build:
    steps:
      - uses: actions/cache@v4
        with:
          key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
          restore-keys: |
            ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
`
	fsys := fstest.MapFS{".github/workflows/ci.yml": file(wf)}
	got := checkWorkflows(fsys)
	if f := findByID(got, "prj-gha-cache-restore-keys"); f != nil {
		t.Fatalf("hash-bound restore-keys should not flag; got %+v", f)
	}
	if f := findByID(got, "prj-gha-cache-poison"); f == nil || f.Status != models.Pass {
		t.Fatalf("want PASS; got %+v", f)
	}
}

func TestWorkflows_NoCacheStepNoFinding(t *testing.T) {
	wf := `jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm run build
`
	fsys := fstest.MapFS{".github/workflows/ci.yml": file(wf)}
	if got := checkWorkflows(fsys); len(got) != 0 {
		t.Errorf("no cache step should produce no findings; got %+v", got)
	}
}

func TestWorkflows_NoWorkflowsDir(t *testing.T) {
	fsys := fstest.MapFS{"package.json": file(`{}`)}
	if got := checkWorkflows(fsys); got != nil {
		t.Errorf("absent workflows dir should be skipped; got %+v", got)
	}
}

func TestWorkflows_CacheSaveVariant(t *testing.T) {
	wf := `jobs:
  build:
    steps:
      - uses: actions/cache/save@v4
        with:
          path: dist
          key: build-static
`
	fsys := fstest.MapFS{".github/workflows/release.yaml": file(wf)}
	got := checkWorkflows(fsys)
	if f := findByID(got, "prj-gha-cache-poison"); f == nil || f.Status != models.Warn {
		t.Fatalf("want WARN for unbound cache/save key; got %+v", f)
	}
}

func TestWorkflows_QuotedUsesFlagged(t *testing.T) {
	for _, q := range []string{`"actions/cache@v4"`, `'actions/cache@v4'`} {
		wf := "jobs:\n  build:\n    steps:\n      - uses: " + q +
			"\n        with:\n          key: static-key\n"
		fsys := fstest.MapFS{".github/workflows/ci.yml": file(wf)}
		got := checkWorkflows(fsys)
		if f := findByID(got, "prj-gha-cache-poison"); f == nil || f.Status != models.Warn {
			t.Fatalf("quoted uses %s: want WARN; got %+v", q, f)
		}
	}
}

func TestWorkflows_GithubShaKeyPasses(t *testing.T) {
	wf := `jobs:
  build:
    steps:
      - uses: actions/cache@v4
        with:
          key: build-${{ github.sha }}
`
	fsys := fstest.MapFS{".github/workflows/ci.yml": file(wf)}
	got := checkWorkflows(fsys)
	if f := findByID(got, "prj-gha-cache-poison"); f == nil || f.Status != models.Pass {
		t.Fatalf("commit-SHA-keyed cache should PASS; got %+v", f)
	}
}

func TestWorkflows_CommentedUsesIgnored(t *testing.T) {
	wf := `jobs:
  build:
    steps:
      # - uses: actions/cache@v4
      #   with:
      #     key: static
      - run: npm ci
`
	fsys := fstest.MapFS{".github/workflows/ci.yml": file(wf)}
	if got := checkWorkflows(fsys); len(got) != 0 {
		t.Errorf("commented-out cache step should produce no findings; got %+v", got)
	}
}

func TestWorkflows_UnparsedMentionSuppressesPass(t *testing.T) {
	// One hash-bound step (safe) plus a ref-less `uses: actions/cache` the
	// strict matcher cannot parse: must surface an ERROR, never a PASS.
	wf := `jobs:
  build:
    steps:
      - uses: actions/cache@v4
        with:
          key: ${{ hashFiles('**/package-lock.json') }}
      - uses: actions/cache
        with:
          key: static-poison
`
	fsys := fstest.MapFS{".github/workflows/ci.yml": file(wf)}
	got := checkWorkflows(fsys)
	if f := findByID(got, "prj-gha-cache-poison"); f == nil || f.Status != models.Error {
		t.Fatalf("unparsed cache step should ERROR; got %+v", f)
	}
	for _, f := range got {
		if f.CheckID == "prj-gha-cache-poison" && f.Status == models.Pass {
			t.Errorf("must not emit PASS when a step was unparsed")
		}
	}
}

func TestWorkflows_DuplicateStaticKeyDistinctResourceID(t *testing.T) {
	// Two unnamed cache steps sharing one static key must not collapse to a
	// single resource ID (which would drop one via SARIF fingerprint dedup).
	wf := `jobs:
  build:
    steps:
      - uses: actions/cache@v4
        with:
          key: shared-static
  test:
    steps:
      - uses: actions/cache@v4
        with:
          key: shared-static
`
	fsys := fstest.MapFS{".github/workflows/ci.yml": file(wf)}
	got := checkWorkflows(fsys)
	var ids []string
	for _, f := range got {
		if f.CheckID == "prj-gha-cache-poison" && f.Status == models.Warn {
			ids = append(ids, f.ResourceID)
		}
	}
	if len(ids) != 2 {
		t.Fatalf("want 2 WARN findings; got %d (%v)", len(ids), ids)
	}
	if ids[0] == ids[1] {
		t.Errorf("resource IDs must be distinct; both are %q", ids[0])
	}
}

func TestWorkflows_LargeFileCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString("jobs:\n  build:\n    steps:\n")
	filler := strings.Repeat("      - run: echo hi\n", (maxWorkflowBytes/20)+1)
	b.WriteString(filler)
	fsys := fstest.MapFS{".github/workflows/big.yml": file(b.String())}
	got := checkWorkflows(fsys)
	if f := findByID(got, "prj-gha-cache-poison"); f == nil || f.Status != models.Error {
		t.Fatalf("oversized workflow should ERROR (skipped); got %+v", f)
	}
}
