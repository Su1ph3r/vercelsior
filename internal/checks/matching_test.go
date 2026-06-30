package checks

import "testing"

func TestHasWholeSegment(t *testing.T) {
	cases := []struct {
		name  string
		input string
		words []string
		want  bool
	}{
		{"key in API_KEY", "API_KEY", []string{"KEY"}, true},
		{"key not in MONKEY", "MONKEY", []string{"KEY"}, false},
		{"auth in AUTH_URL", "AUTH_URL", []string{"AUTH"}, true},
		{"auth not in OAUTH", "OAUTH_ROUTES", []string{"AUTH"}, false},
		{"auth not in AUTHOR", "AUTHOR_BIOS", []string{"AUTH"}, false},
		{"kebab slug", "secret-config", []string{"secret"}, true},
		{"dotted flag", "feature.admin.toggle", []string{"admin"}, true},
		{"case insensitive", "my-Secret-thing", []string{"SECRET"}, true},
		{"multiple words any-match", "debug-banner", []string{"admin", "debug"}, true},
		{"no match", "landing-page", []string{"admin", "auth"}, false},
		{"empty name", "", []string{"key"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasWholeSegment(tc.input, tc.words...); got != tc.want {
				t.Errorf("hasWholeSegment(%q, %v) = %v; want %v", tc.input, tc.words, got, tc.want)
			}
		})
	}
}

func TestHasSegmentSuffix(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		suffix string
		want   bool
	}{
		{"exact", "POSTGRES_URL", "POSTGRES_URL", true},
		{"platform prefix", "MYDB_POSTGRES_URL", "POSTGRES_URL", true},
		{"public prefix", "NEXT_PUBLIC_API_URL", "API_URL", true},
		{"extended not suffix", "OLD_POSTGRES_URL_BACKUP", "POSTGRES_URL", false},
		{"embedded not boundary", "XPOSTGRES_URL", "POSTGRES_URL", false},
		{"different", "MY_DATABASE", "DATA", false},
		{"empty suffix", "ANYTHING", "", false},
		{"empty name", "", "API_URL", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasSegmentSuffix(tc.input, tc.suffix); got != tc.want {
				t.Errorf("hasSegmentSuffix(%q, %q) = %v; want %v", tc.input, tc.suffix, got, tc.want)
			}
		})
	}
}

func TestDomainClaimed(t *testing.T) {
	set := map[string]bool{
		"example.com":    true,
		"*.example.com":  true,
		"app.acme.io":    true,
		"*.team.acme.io": true,
	}
	cases := []struct {
		name string
		fqdn string
		want bool
	}{
		{"exact apex", "example.com", true},
		{"wildcard child", "app.example.com", true},
		{"wildcard child other", "staging.example.com", true},
		{"exact subdomain", "app.acme.io", true},
		{"wildcard nested", "ci.team.acme.io", true},
		{"trailing dot", "app.example.com.", true},
		{"uppercase", "APP.EXAMPLE.COM", true},
		{"two-level not covered by single wildcard", "a.b.example.com", false},
		{"unrelated", "evil.com", false},
		{"unclaimed subdomain", "api.acme.io", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := domainClaimed(set, tc.fqdn); got != tc.want {
				t.Errorf("domainClaimed(set, %q) = %v; want %v", tc.fqdn, got, tc.want)
			}
		})
	}
}
