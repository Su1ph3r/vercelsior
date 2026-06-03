package checks

import "testing"

// TestIsVercelManagedAlias guards the sto-002 false-positive fix: Vercel-managed
// *.vercel.app aliases (auto-generated production/branch/deployment aliases) must
// be skipped by the orphaned-alias check, while genuine custom-domain aliases must
// still be evaluated for subdomain-takeover risk.
func TestIsVercelManagedAlias(t *testing.T) {
	cases := []struct {
		name string
		host string
		want bool
	}{
		// Vercel-managed aliases — must be skipped (these were the false positives)
		{"scoped production alias", "nextjs-boilerplate-su1ph3rs-projects.vercel.app", true},
		{"scoped git-branch alias", "nextjs-boilerplate-git-main-su1ph3rs-projects.vercel.app", true},
		{"bare project alias", "myapp.vercel.app", true},
		{"deployment hash alias", "myapp-abc123def-su1ph3rs-projects.vercel.app", true},
		{"apex vercel.app", "vercel.app", true},
		{"uppercase normalizes", "MyApp.Vercel.App", true},
		{"trailing dot (fqdn)", "myapp.vercel.app.", true},
		{"surrounding whitespace", "  myapp.vercel.app  ", true},

		// Custom domains — must NOT be skipped (real takeover candidates)
		{"custom subdomain", "app.example.com", false},
		{"custom apex", "example.com", false},
		{"vercel-prefixed custom", "vercel.example.com", false},

		// Lookalike / spoof guards — must NOT be skipped
		{"suffix without dot", "notvercel.app", false},
		{"hyphen lookalike", "evil-vercel.app", false},
		{"vercel.app as left label", "vercel.app.evil.com", false},
		{"embedded not suffix", "myvercel.app.attacker.net", false},

		// Edge
		{"empty", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isVercelManagedAlias(tc.host); got != tc.want {
				t.Errorf("isVercelManagedAlias(%q) = %v; want %v", tc.host, got, tc.want)
			}
		})
	}
}
