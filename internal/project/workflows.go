package project

import (
	"errors"
	"io/fs"
	"regexp"
	"strings"

	"github.com/Su1ph3r/vercelsior/internal/models"
)

// GitHub Actions cache-poisoning detection (CWE-494).
//
// Vercel deploy previews are frequently built in CI via GitHub Actions. When a
// workflow restores a build/dependency cache whose key is not bound to the tree
// state, a cache entry poisoned by a lower-trust context (a fork PR, a feature
// branch) persists and is restored into later — including production/deploy —
// runs. The classic vector is `actions/cache` used with a static key, or with a
// broad `restore-keys:` prefix that falls back to an arbitrary older entry
// regardless of the current dependency manifest.
//
// We intentionally avoid a YAML dependency (the binary is stdlib-only) and
// parse the specific `actions/cache` step shape with an indentation-aware line
// scanner. The detection is deliberately narrow to keep false positives low: a
// cache step is flagged only when its `key:` / `restore-keys:` material carries
// no integrity binding — neither a `hashFiles(...)` over a lockfile nor a
// commit-SHA context (`github.sha` / `*.head.sha`), both of which change with
// the tree so a poisoned entry can never be restored.

const (
	workflowDir = ".github/workflows"
	// maxWorkflowBytes caps the per-file scan to bound the parser's worst-case
	// cost on a crafted input. Real workflow files are a few KiB; anything past
	// 1 MiB is not a workflow we need to parse line-by-line.
	maxWorkflowBytes = 1 << 20
)

var (
	// cacheUsesRe matches a step that uses actions/cache, actions/cache/restore,
	// or actions/cache/save at a pinned ref. The optional quote tolerates
	// `uses: "actions/cache@v4"` / `uses: 'actions/cache@v4'`.
	cacheUsesRe = regexp.MustCompile(`(?i)uses:\s*['"]?actions/cache(?:/(?:restore|save))?@`)
	// cacheMentionRe is a looser superset used only to count how many cache
	// steps are present, so we can tell when cacheUsesRe failed to fully parse
	// one (and must not emit a reassuring PASS). It does not require a ref.
	cacheMentionRe = regexp.MustCompile(`(?i)uses:\s*['"]?actions/cache(?:/(?:restore|save))?(?:@|['"]|\s|$)`)
	keyLineRe      = regexp.MustCompile(`(?i)^\s*key:\s*(.*)$`)
	restoreRe      = regexp.MustCompile(`(?i)^\s*restore-keys:\s*(.*)$`)
	nameLineRe     = regexp.MustCompile(`(?i)^\s*(?:-\s*)?name:\s*(.+)$`)
	// boundRe marks a cache key as integrity-bound: a hashFiles() over a
	// lockfile, or a commit-SHA context. Both change with the tree state, so a
	// poisoned entry written under one is never restored under another.
	boundRe = regexp.MustCompile(`(?i)hashfiles\s*\(|github\.sha|head[._]sha`)
)

func checkWorkflows(fsys fs.FS) []models.Finding {
	entries, err := fs.ReadDir(fsys, workflowDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // no workflows directory — not a CI-built repo, skip
	}
	if err != nil {
		return []models.Finding{errorFinding("prj-gha-cache-poison",
			".github/workflows unreadable", catSupplyChain,
			workflowDir+" exists but could not be read: "+err.Error(), workflowDir)}
	}

	var findings []models.Finding
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		path := workflowDir + "/" + name
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			findings = append(findings, errorFinding("prj-gha-cache-poison",
				"Workflow unreadable", catSupplyChain,
				path+" could not be read: "+err.Error(), path))
			continue
		}
		if len(data) > maxWorkflowBytes {
			// Surface the gap rather than silently skipping the security check.
			findings = append(findings, errorFinding("prj-gha-cache-poison",
				"Workflow too large to scan", catSupplyChain,
				path+" exceeds the "+itoa(maxWorkflowBytes>>10)+" KiB scan cap; cache checks were skipped for this file. Review it manually.", path))
			continue
		}
		findings = append(findings, scanWorkflowCaches(path, string(data))...)
	}
	return findings
}

// scanWorkflowCaches inspects every actions/cache step in one workflow file.
func scanWorkflowCaches(path, content string) []models.Finding {
	lines := strings.Split(content, "\n")
	markers := stepMarkers(lines)
	var findings []models.Finding
	cacheSteps, issues, mentions := 0, 0, 0

	// Count cache steps up front with the looser matcher so a step the strict
	// matcher cannot parse is detected rather than silently trusted.
	for _, line := range lines {
		if isComment(line) {
			continue
		}
		if cacheMentionRe.MatchString(line) {
			mentions++
		}
	}

	for i, line := range lines {
		if isComment(line) || !cacheUsesRe.MatchString(line) {
			continue
		}
		cacheSteps++

		block := stepBlock(lines, markers, i)
		stepName, keyVal, restoreVal := extractCacheConfig(block)
		keyBound := boundRe.MatchString(keyVal)
		restoreBound := boundRe.MatchString(restoreVal)

		// A human-facing label for the finding; the resource ID keys on the
		// line number so two same-key steps never collide (which would let
		// SARIF fingerprint dedup silently drop one).
		label := stepName
		if label == "" {
			label = strings.TrimSpace(keyVal)
		}
		if label == "" {
			label = "line " + itoa(i+1)
		}
		resID := path + ":step:" + itoa(i+1)

		switch {
		case !keyBound && !restoreBound:
			// No integrity binding anywhere in the key or restore-keys: any
			// poisoned entry survives and is restored blindly.
			issues++
			findings = append(findings, withDetails(warnFinding("prj-gha-cache-poison",
				"Cache key not bound to a lockfile hash (cache poisoning)", catSupplyChain,
				models.Medium, 5.0,
				"An actions/cache step keys its cache with no integrity binding — neither a hashFiles() over a lockfile nor a commit-SHA context (CWE-494: no integrity check). A cache entry written from a lower-trust context (fork PR, feature branch) is restored unchanged into later builds, including deploy previews, letting a compromised dependency persist across deployments.",
				"Workflow `"+path+"` step ("+label+") caches with key `"+oneLine(keyVal)+"` and no lockfile-hash or commit-SHA binding in its key or restore-keys.",
				resID,
				"Bind the cache key to the dependency manifest, e.g. `key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}`, and drop broad restore-keys prefixes so a mismatched (potentially poisoned) entry is never restored."),
				map[string]string{"workflow": path, "step": label, "key": oneLine(keyVal), "cwe": "CWE-494"}))
		case keyBound && restoreVal != "" && !restoreBound:
			// Primary key is bound, but a broad restore-keys prefix still lets
			// the build fall back to an arbitrary older entry.
			issues++
			findings = append(findings, withDetails(warnFinding("prj-gha-cache-restore-keys",
				"Broad restore-keys fallback bypasses cache key hash", catSupplyChain,
				models.Low, 3.0,
				"The cache key is integrity-bound, but restore-keys uses an unbound prefix. On a key miss the build falls back to any older entry matching that prefix regardless of the current lockfile, reintroducing the cache-poisoning path the bound key was meant to close.",
				"Workflow `"+path+"` step ("+label+") has a bound key but an unbound restore-keys prefix `"+oneLine(restoreVal)+"`.",
				resID,
				"Remove the unbound restore-keys prefix, or include the same hashFiles() segment in every restore-keys entry so only manifest-matching caches are ever restored."),
				map[string]string{"workflow": path, "step": label, "restore_keys": oneLine(restoreVal), "cwe": "CWE-494"}))
		}
	}

	// A cache step the strict matcher could not parse means our view is
	// incomplete — surface it and withhold any all-clear for this file.
	if mentions > cacheSteps {
		findings = append(findings, errorFinding("prj-gha-cache-poison",
			"Unparsed actions/cache step", catSupplyChain,
			"Workflow `"+path+"` references actions/cache in a form vercelsior could not fully parse; "+itoa(mentions-cacheSteps)+" step(s) were not evaluated for cache poisoning. Review them manually.", path))
	}

	if cacheSteps > 0 && issues == 0 && mentions == cacheSteps {
		findings = append(findings, passFinding("prj-gha-cache-poison",
			"Workflow caches are integrity-bound", catSupplyChain,
			"Every actions/cache step in `"+path+"` binds its key (and restore-keys) to a lockfile hash or commit SHA, so poisoned entries are not restored.",
			path))
	}
	return findings
}

// stepMarkers returns the indices of every line that opens a YAML list item
// (`- ...`), precomputed once so stepBlock is a bounded lookup rather than a
// backward rescan to the top of the file on every cache step.
func stepMarkers(lines []string) []int {
	var m []int
	for i, l := range lines {
		t := strings.TrimLeft(l, " \t")
		if t == "-" || strings.HasPrefix(t, "- ") {
			m = append(m, i)
		}
	}
	return m
}

// stepBlock returns the lines belonging to the workflow step that contains the
// actions/cache `uses:` line at index i. A step begins at the nearest list
// marker at or above i whose indent is no deeper than the uses line, and ends
// before the next line that dedents to (or past) that marker. markers is the
// precomputed set of list-item line indices (see stepMarkers).
func stepBlock(lines []string, markers []int, i int) []string {
	usesIndent := indentOf(lines[i])

	// Largest marker index <= i (binary search), then walk back through markers
	// to the first whose indent is no deeper than the uses line: the step's own
	// marker. With markers precomputed this is bounded by nesting depth, not by
	// distance to the file top.
	lo, hi := 0, len(markers)
	for lo < hi {
		mid := (lo + hi) / 2
		if markers[mid] <= i {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	start := i
	for k := lo - 1; k >= 0; k-- {
		j := markers[k]
		if indentOf(lines[j]) <= usesIndent {
			start = j
			break
		}
	}
	markerIndent := indentOf(lines[start])

	end := len(lines)
	for j := start + 1; j < len(lines); j++ {
		if strings.TrimSpace(lines[j]) == "" {
			continue
		}
		if indentOf(lines[j]) <= markerIndent {
			end = j
			break
		}
	}
	return lines[start:end]
}

// extractCacheConfig pulls the step name, key: value, and full restore-keys:
// material (including a `|` block scalar's indented entries) from a step block.
func extractCacheConfig(block []string) (stepName, keyVal, restoreVal string) {
	for i := 0; i < len(block); i++ {
		line := block[i]
		if isComment(line) {
			continue
		}
		if stepName == "" {
			if m := nameLineRe.FindStringSubmatch(line); m != nil {
				stepName = unquote(strings.TrimSpace(m[1]))
			}
		}
		if keyVal == "" {
			if m := keyLineRe.FindStringSubmatch(line); m != nil {
				keyVal = strings.TrimSpace(m[1])
			}
		}
		if m := restoreRe.FindStringSubmatch(line); m != nil {
			restoreVal = strings.TrimSpace(m[1])
			// Gather a block scalar: subsequent lines indented deeper than the
			// restore-keys: key are additional fallback prefixes.
			base := indentOf(line)
			for j := i + 1; j < len(block); j++ {
				if strings.TrimSpace(block[j]) == "" {
					continue
				}
				if indentOf(block[j]) <= base {
					break
				}
				restoreVal += " " + strings.TrimSpace(block[j])
			}
		}
	}
	return stepName, keyVal, restoreVal
}

// isComment reports whether a line is a full-line YAML comment, so a commented
// `# uses: actions/cache@v4` is never mistaken for a real step.
func isComment(s string) bool {
	return strings.HasPrefix(strings.TrimLeft(s, " \t"), "#")
}

func indentOf(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' || r == '\t' {
			n++
			continue
		}
		break
	}
	return n
}

// oneLine collapses a value to a single trimmed line for display, stripping a
// leading `|`/`>` block-scalar indicator.
func oneLine(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "|")
	s = strings.TrimPrefix(s, ">")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}
