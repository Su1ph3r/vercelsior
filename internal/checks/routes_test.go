package checks

import "testing"

func TestIsInternalDestination(t *testing.T) {
	cases := []struct {
		name string
		dest string
		want bool
	}{
		// Known internal hostnames
		{"localhost bare", "http://localhost/", true},
		{"localhost with port", "http://localhost:8080/api", true},
		{"GCP metadata", "https://metadata.google.internal/", true},

		// Well-known metadata IPs
		{"AWS metadata IP", "http://169.254.169.254/latest/meta-data/", true},
		{"Alibaba metadata", "http://100.100.100.200/", true},

		// Loopback IPs
		{"ipv4 loopback", "http://127.0.0.1/", true},
		{"ipv6 loopback", "http://[::1]/", true},
		{"ipv4 loopback range", "http://127.5.5.5/", true},

		// RFC 1918 private ranges
		{"10.0.0.0/8", "http://10.0.0.5/", true},
		{"172.16.0.0/12 low", "http://172.16.0.1/", true},
		{"172.31.0.0/12 high", "http://172.31.255.255/", true},
		{"192.168.0.0/16", "http://192.168.1.1/", true},

		// Link-local
		{"169.254.x.x", "http://169.254.1.1/", true},

		// Public internet — must not flag
		{"public IP", "http://8.8.8.8/", false},
		{"public hostname", "https://example.com/api", false},
		{"cloudflare dns", "http://1.1.1.1/", false},

		// Malformed / edge
		{"empty", "", false},
		{"no scheme", "localhost/", false}, // without scheme, url.Parse treats it as path
		{"not a URL", "not a url at all", false},
		{"relative path", "/api/foo", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isInternalDestination(tc.dest)
			if got != tc.want {
				t.Errorf("isInternalDestination(%q) = %v; want %v", tc.dest, got, tc.want)
			}
		})
	}
}
