package checks

import "strings"

// nameSegments splits an identifier (env var key, edge-config slug, feature-flag
// name) into upper-cased word segments on common delimiters. It lets detections
// match whole words instead of substrings, which is the difference between
// flagging API_KEY and wrongly flagging MONKEY. Examples:
//
//	"NEXT_PUBLIC_API_URL" -> [NEXT PUBLIC API URL]
//	"oauth-routes"        -> [OAUTH ROUTES]
func nameSegments(name string) []string {
	return strings.FieldsFunc(strings.ToUpper(name), func(r rune) bool {
		switch r {
		case '_', '-', '.', '/', ' ', ':':
			return true
		default:
			return false
		}
	})
}

// hasWholeSegment reports whether any delimiter-separated segment of name equals
// one of words (case-insensitive). Use this instead of strings.Contains for
// name-based heuristics: it matches "KEY" in "API_KEY" but not in "MONKEY", and
// "AUTH" in "AUTH_URL" but not in "OAUTH" or "AUTHOR".
func hasWholeSegment(name string, words ...string) bool {
	segs := nameSegments(name)
	for _, w := range words {
		wu := strings.ToUpper(w)
		for _, s := range segs {
			if s == wu {
				return true
			}
		}
	}
	return false
}

// hasSegmentSuffix reports whether name ends with the given (possibly
// multi-segment) suffix on a delimiter boundary, case-insensitively. This is for
// canonical names that the platform may prefix, such as a Vercel storage var
// POSTGRES_URL surfaced as MYDB_POSTGRES_URL. An exact match counts; an embedded
// or extended match does not:
//
//	hasSegmentSuffix("MYDB_POSTGRES_URL", "POSTGRES_URL") == true
//	hasSegmentSuffix("POSTGRES_URL",      "POSTGRES_URL") == true
//	hasSegmentSuffix("OLD_POSTGRES_URL_BACKUP", "POSTGRES_URL") == false
func hasSegmentSuffix(name, suffix string) bool {
	nu := strings.ToUpper(strings.TrimSpace(name))
	su := strings.ToUpper(strings.TrimSpace(suffix))
	if su == "" {
		return false
	}
	if nu == su {
		return true
	}
	return strings.HasSuffix(nu, "_"+su) || strings.HasSuffix(nu, "-"+su)
}

// hasAnySegmentSuffix reports whether name matches any of the given suffixes per
// hasSegmentSuffix.
func hasAnySegmentSuffix(name string, suffixes ...string) bool {
	for _, s := range suffixes {
		if hasSegmentSuffix(name, s) {
			return true
		}
	}
	return false
}

// domainClaimed reports whether fqdn is covered by a set of project domains,
// accounting for wildcard coverage: a set entry "*.example.com" claims
// "app.example.com". Comparison is case-insensitive and ignores a trailing dot.
// This prevents a legitimately wildcard-served subdomain from being reported as
// an unclaimed takeover candidate. Vercel wildcards cover a single label, so only
// the immediate wildcard parent is consulted.
func domainClaimed(set map[string]bool, fqdn string) bool {
	f := normalizeDomain(fqdn)
	if f == "" {
		return false
	}
	if set[f] {
		return true
	}
	if i := strings.IndexByte(f, '.'); i >= 0 {
		if set["*."+f[i+1:]] {
			return true
		}
	}
	return false
}

// clientExposedKeyPrefixes are env var name prefixes that frameworks inline into
// client-side JavaScript. A var with one of these prefixes is, by design, a
// public value (a public API URL, a publishable key) and must not be treated as a
// private backend connection or a secret-bearing binding.
var clientExposedKeyPrefixes = []string{
	"NEXT_PUBLIC_", "VITE_", "GATSBY_", "REACT_APP_", "NUXT_PUBLIC_", "PUBLIC_",
}

// isClientExposedKey reports whether an env var name uses a framework
// client-exposure prefix (case-insensitive).
func isClientExposedKey(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	for _, p := range clientExposedKeyPrefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	return false
}

// normalizeDomain lower-cases a domain name and strips surrounding whitespace and
// a single trailing dot, so set membership and comparisons are stable regardless
// of how the API renders a name.
func normalizeDomain(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}
