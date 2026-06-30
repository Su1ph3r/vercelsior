package checks

import "testing"

func TestIsMetadataDestination(t *testing.T) {
	cases := []struct {
		name string
		dest string
		want bool
	}{
		// Cloud instance-metadata endpoints (the genuinely dangerous SSRF subset).
		{"GCP metadata host", "https://metadata.google.internal/", true},
		{"AWS metadata IP", "http://169.254.169.254/latest/meta-data/", true},
		{"Alibaba metadata", "http://100.100.100.200/", true},
		{"link-local range", "http://169.254.1.1/", true},
		{"AWS IMDSv6 compressed", "http://[fd00:ec2::254]/latest/meta-data/", true},
		{"AWS IMDSv6 expanded", "http://[fd00:ec2:0:0:0:0:0:254]/", true},

		// Private/loopback are NOT metadata.
		{"localhost", "http://localhost/", false},
		{"ipv4 loopback", "http://127.0.0.1/", false},
		{"rfc1918 10", "http://10.0.0.5/", false},
		{"rfc1918 192.168", "http://192.168.1.1/", false},

		// Public and malformed.
		{"public IP", "http://8.8.8.8/", false},
		{"public hostname", "https://example.com/api", false},
		{"empty", "", false},
		{"relative path", "/api/foo", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMetadataDestination(tc.dest); got != tc.want {
				t.Errorf("isMetadataDestination(%q) = %v; want %v", tc.dest, got, tc.want)
			}
		})
	}
}

func TestIsPrivateDestination(t *testing.T) {
	cases := []struct {
		name string
		dest string
		want bool
	}{
		// Loopback / RFC-1918 private (intentional internal-proxy territory).
		{"localhost bare", "http://localhost/", true},
		{"localhost with port", "http://localhost:8080/api", true},
		{"ipv4 loopback", "http://127.0.0.1/", true},
		{"ipv6 loopback", "http://[::1]/", true},
		{"ipv4 loopback range", "http://127.5.5.5/", true},
		{"10.0.0.0/8", "http://10.0.0.5/", true},
		{"172.16.0.0/12 low", "http://172.16.0.1/", true},
		{"172.31.0.0/12 high", "http://172.31.255.255/", true},
		{"192.168.0.0/16", "http://192.168.1.1/", true},

		// Unspecified addresses (all-interfaces) route to local services.
		{"ipv4 unspecified", "http://0.0.0.0:8080/", true},
		{"ipv6 unspecified", "http://[::]/", true},

		// Metadata/link-local is reported by isMetadataDestination, not here.
		{"link-local", "http://169.254.1.1/", false},
		{"gcp metadata host", "https://metadata.google.internal/", false},
		{"aws imdsv6", "http://[fd00:ec2::254]/", false},

		// Public and malformed.
		{"public IP", "http://8.8.8.8/", false},
		{"public hostname", "https://example.com/api", false},
		{"cloudflare dns", "http://1.1.1.1/", false},
		{"empty", "", false},
		{"no scheme", "localhost/", false},
		{"not a URL", "not a url at all", false},
		{"relative path", "/api/foo", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPrivateDestination(tc.dest); got != tc.want {
				t.Errorf("isPrivateDestination(%q) = %v; want %v", tc.dest, got, tc.want)
			}
		})
	}
}
