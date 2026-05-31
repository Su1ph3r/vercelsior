// Package nextjs is the single source of truth for Next.js version parsing and
// the known-CVE matrix. It is consumed by both the account-scan path
// (internal/checks/nextjs.go, which reads the framework version from the
// deployment API) and project mode (internal/project, which reads the `next`
// dependency from package.json), so a CVE only needs to be added here once.
package nextjs

import "strings"

// CVE describes a Next.js advisory and the version predicate that matches it.
type CVE struct {
	ID          string
	Description string
	CVSS        float64
	Vulnerable  func(maj, min, pat int) bool
}

// CVEs is the known Next.js advisory matrix (kept in sync with
// internal/checks/nextjs.go).
var CVEs = []CVE{
	{
		ID:          "CVE-2025-29927",
		Description: "Next.js middleware authorization bypass",
		CVSS:        9.1,
		Vulnerable: func(maj, min, pat int) bool {
			if maj < 12 {
				return false
			}
			if maj < 14 {
				return true
			}
			if maj == 14 {
				return min < 2 || (min == 2 && pat < 25)
			}
			if maj == 15 {
				return min < 2 || (min == 2 && pat < 3)
			}
			return false
		},
	},
	{
		ID:          "CVE-2025-55182",
		Description: "React Server Components deserialization RCE (React2Shell)",
		CVSS:        10.0,
		Vulnerable: func(maj, min, pat int) bool {
			if maj < 14 {
				return false
			}
			if maj == 14 {
				return min == 2 && pat < 35
			}
			if maj == 15 {
				switch min {
				case 0:
					return pat >= 4 && pat < 7
				case 1:
					return pat < 11
				case 2:
					return pat < 8
				case 3:
					return pat < 8
				case 4:
					return pat < 10
				case 5:
					return pat < 9
				default:
					return false
				}
			}
			if maj == 16 {
				return min == 0 && pat < 10
			}
			return false
		},
	},
	{
		ID:          "CVE-2025-49826",
		Description: "ISR cache poisoning via 204 response",
		CVSS:        7.5,
		Vulnerable: func(maj, min, pat int) bool {
			return maj == 15 && min == 1 && pat < 8
		},
	},
	{
		ID:          "CVE-2025-59471",
		Description: "Image optimization memory exhaustion via /_next/image",
		CVSS:        5.9,
		Vulnerable: func(maj, min, pat int) bool {
			if maj == 15 {
				return min < 5 || (min == 5 && pat < 10)
			}
			if maj == 16 {
				return min < 1 || (min == 1 && pat < 5)
			}
			return false
		},
	},
	{
		ID:          "CVE-2025-59472",
		Description: "PPR resume endpoint denial of service via zip bomb",
		CVSS:        5.9,
		Vulnerable: func(maj, min, pat int) bool {
			if maj == 15 {
				return min < 5 || (min == 5 && pat < 10)
			}
			if maj == 16 {
				return min < 1 || (min == 1 && pat < 5)
			}
			return false
		},
	},
}

// Match returns the IDs of every CVE affecting the given version and the
// highest CVSS among them. ok is false when the version string cannot be
// pinned to a concrete major.minor.patch (e.g. "latest", "15.x", a range that
// does not begin with a concrete version), in which case the caller should
// record the gap rather than assume safe-or-vulnerable.
func Match(version string) (ids []string, maxCVSS float64, ok bool) {
	maj, min, pat, parsed := ParseVersion(version)
	if !parsed {
		return nil, 0, false
	}
	for _, cve := range CVEs {
		if cve.Vulnerable(maj, min, pat) {
			ids = append(ids, cve.ID)
			if cve.CVSS > maxCVSS {
				maxCVSS = cve.CVSS
			}
		}
	}
	return ids, maxCVSS, true
}

// ParseVersion extracts major.minor.patch from a version or npm range string.
// It tolerates a single leading range operator (^, ~, >=, >, <=, <, =, v) and
// trailing prerelease/build metadata. A wildcard or non-numeric major/minor
// (e.g. "15.x", "*", "latest", "next") yields ok=false so the caller skips the
// CVE comparison instead of guessing.
func ParseVersion(v string) (maj, min, pat int, ok bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, ">=")
	v = strings.TrimPrefix(v, "<=")
	v = strings.TrimLeft(v, "^~><=v ")
	// Take the first whitespace-delimited token (handles ranges like
	// ">=14.0.0 <15.0.0" by pinning to the lower bound).
	if i := strings.IndexByte(v, ' '); i >= 0 {
		v = v[:i]
	}

	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0, 0, false
	}
	major, ok1 := parseUint(parts[0])
	minor, ok2 := parseUint(parts[1])
	if !ok1 || !ok2 {
		return 0, 0, 0, false
	}
	patch := 0
	if len(parts) >= 3 {
		ps := parts[2]
		if idx := strings.IndexAny(ps, "-+"); idx >= 0 {
			ps = ps[:idx]
		}
		if ps != "" {
			p, okp := parseUint(ps)
			if !okp {
				return 0, 0, 0, false
			}
			patch = p
		}
	}
	return major, minor, patch, true
}

func parseUint(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		next := n*10 + int(ch-'0')
		if next < n {
			return 0, false
		}
		n = next
	}
	return n, true
}
