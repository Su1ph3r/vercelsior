package client

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecorderRoundTrip(t *testing.T) {
	// Test that record mode saves files and replay mode reads them
	dir := t.TempDir()

	// Create a fake recording manually
	fakeResponse := `{"status_code":200,"headers":{"Content-Type":"application/json"},"body":"{\"user\":{\"id\":\"test123\",\"username\":\"testuser\"}}"}`

	t.Run("RequestKey deterministic", func(t *testing.T) {
		// Verify same input produces same key
		key1 := RequestKey(mustNewRequest("GET", "https://api.vercel.com/v2/user"))
		key2 := RequestKey(mustNewRequest("GET", "https://api.vercel.com/v2/user"))
		if key1 != key2 {
			t.Errorf("keys differ: %s vs %s", key1, key2)
		}
	})

	t.Run("different requests produce different keys", func(t *testing.T) {
		key1 := RequestKey(mustNewRequest("GET", "https://api.vercel.com/v2/user"))
		key2 := RequestKey(mustNewRequest("GET", "https://api.vercel.com/v5/domains"))
		if key1 == key2 {
			t.Errorf("different requests should produce different keys")
		}
	})

	t.Run("replay returns recorded data", func(t *testing.T) {
		// Write a recording file
		req := mustNewRequest("GET", "https://api.vercel.com/v2/user")
		key := RequestKey(req)
		filePath := filepath.Join(dir, key+".json")
		os.WriteFile(filePath, []byte(fakeResponse), 0644)

		transport := &RecordingTransport{
			Mode:      ModeReplay,
			Directory: dir,
		}

		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("replay returns 404 for missing recording", func(t *testing.T) {
		req := mustNewRequest("GET", "https://api.vercel.com/v99/nonexistent")
		transport := &RecordingTransport{
			Mode:      ModeReplay,
			Directory: dir,
		}
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 404 {
			t.Errorf("expected 404, got %d", resp.StatusCode)
		}
	})
}

func mustNewRequest(method, targetURL string) *http.Request {
	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		panic(err)
	}
	return req
}

// ---------- Helper coverage ----------

func TestUtf8SafeTruncateString(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		max   int
		want  string
		bytes int
	}{
		{"ascii below", "hello", 10, "hello", 5},
		{"ascii above", "helloworld", 5, "hello", 5},
		{"multi-byte cut mid-rune", "é", 1, "", 0}, // "é" = 2 bytes
		{"emoji mid-cut", "🔒", 2, "", 0},           // "🔒" = 4 bytes
		{"ascii+emoji mid-cut", "hi🔒", 3, "hi", 2}, // cuts before emoji
		{"at exact boundary", "🔒", 4, "🔒", 4},
		{"negative max treated as unlimited", "abc", -1, "abc", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := utf8SafeTruncateString(tc.in, tc.max)
			if got != tc.want {
				t.Errorf("utf8SafeTruncateString(%q, %d) = %q; want %q", tc.in, tc.max, got, tc.want)
			}
			if len(got) != tc.bytes {
				t.Errorf("byte length = %d; want %d", len(got), tc.bytes)
			}
		})
	}
}

// ---------- parseListResponse ----------

func TestParseListResponse(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		keys    []string
		wantLen int
		wantErr bool
	}{
		{
			name: "object with first matching key",
			body: `{"drains":[{"id":"d1"},{"id":"d2"}]}`,
			keys: []string{"drains"}, wantLen: 2, wantErr: false,
		},
		{
			name: "object with second-listed key",
			body: `{"envs":[{"k":"x"}]}`,
			keys: []string{"data", "envs"}, wantLen: 1, wantErr: false,
		},
		{
			name: "bare array",
			body: `[{"id":"a"},{"id":"b"},{"id":"c"}]`,
			keys: []string{"ignored"}, wantLen: 3, wantErr: false,
		},
		{
			name: "empty body",
			body: ``,
			keys: []string{"drains"}, wantLen: 0, wantErr: false,
		},
		{
			name: "object missing expected key — must error, not silently fall back",
			body: `{"error":{"code":"not_found"}}`,
			keys: []string{"drains"}, wantLen: 0, wantErr: true,
		},
		{
			name: "garbage",
			body: `this is not json`,
			keys: []string{"drains"}, wantLen: 0, wantErr: true,
		},
		{
			name: "scalar value",
			body: `"just a string"`,
			keys: []string{"drains"}, wantLen: 0, wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseListResponse(json.RawMessage(tc.body), tc.keys...)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v; wantErr = %v", err, tc.wantErr)
			}
			if len(got) != tc.wantLen {
				t.Errorf("len = %d; want %d", len(got), tc.wantLen)
			}
		})
	}
}

// ---------- GetPaginated params isolation (F-EC8) ----------

func TestGetPaginatedDoesNotMutateCallerParams(t *testing.T) {
	// Spin up a test server that returns a single-page response so the
	// loop exits after one call. The client's underlying http.Client is
	// swapped to point at this server via a custom transport.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":"1"}],"pagination":{}}`))
	}))
	defer srv.Close()

	c := New("fake-token", "", "")
	c.http.Transport = &rewriteTransport{Target: srv.URL}

	callerParams := map[string]string{"foo": "bar"}
	if _, err := c.GetPaginated("/v1/items", "items", callerParams); err != nil {
		t.Fatalf("GetPaginated err = %v", err)
	}
	// The caller's map must contain only the original key. The client
	// internally sets "limit" (and maybe "until") on a copy.
	if _, exists := callerParams["limit"]; exists {
		t.Error("caller params map was mutated with 'limit'")
	}
	if _, exists := callerParams["until"]; exists {
		t.Error("caller params map was mutated with 'until'")
	}
	if callerParams["foo"] != "bar" {
		t.Errorf("caller params 'foo' changed to %q", callerParams["foo"])
	}
}

// rewriteTransport forwards all requests to an alternate base URL (used by
// tests to intercept api.vercel.com calls and route them to httptest).
type rewriteTransport struct {
	Target string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, err := url.Parse(t.Target)
	if err != nil {
		return nil, err
	}
	req = req.Clone(req.Context())
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	return http.DefaultTransport.RoundTrip(req)
}

// ---------- SSRF guard helpers ----------

func TestIsDisallowedProbeIP(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"nil", "", true},
		{"public v4", "8.8.8.8", false},
		{"public v6", "2606:4700:4700::1111", false},

		{"loopback v4", "127.0.0.1", true},
		{"loopback v4 range", "127.5.5.5", true},
		{"loopback v6", "::1", true},

		{"rfc1918 10", "10.1.2.3", true},
		{"rfc1918 172.16", "172.16.5.5", true},
		{"rfc1918 192.168", "192.168.1.100", true},

		{"link-local v4", "169.254.169.254", true},
		{"link-local v6", "fe80::1", true},

		{"unspecified v4", "0.0.0.0", true},
		{"unspecified v6", "::", true},

		{"multicast v4", "224.0.0.1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ip net.IP
			if tc.ip != "" {
				ip = net.ParseIP(tc.ip)
				if ip == nil {
					t.Fatalf("could not parse test IP %q", tc.ip)
				}
			}
			got := isDisallowedProbeIP(ip)
			if got != tc.want {
				t.Errorf("isDisallowedProbeIP(%q) = %v; want %v", tc.ip, got, tc.want)
			}
		})
	}
}

// ---------- ProbeHeaders behavior ----------

// TestProbeHeadersBlocksLoopback ensures the SSRF guard rejects requests
// whose hostname resolves to the loopback interface. We use "localhost"
// which is always present in the host's hosts file.
func TestProbeHeadersBlocksLoopback(t *testing.T) {
	c := New("fake-token", "", "")
	_, err := c.ProbeHeaders("http://localhost/")
	if err == nil {
		t.Fatal("expected ProbeHeaders to reject localhost; got nil error")
	}
	if !strings.Contains(err.Error(), "blocked request") && !strings.Contains(err.Error(), "localhost") {
		t.Errorf("error = %v; want it to mention the block reason", err)
	}
}

// TestProbeHeadersRejectsInvalidScheme ensures non-http(s) URLs are refused
// before any network access.
func TestProbeHeadersRejectsInvalidScheme(t *testing.T) {
	c := New("fake-token", "", "")
	_, err := c.ProbeHeaders("file:///etc/passwd")
	if err == nil {
		t.Fatal("expected file:// URL to be rejected")
	}
	if !strings.Contains(err.Error(), "http or https") {
		t.Errorf("error = %v; want it to mention scheme constraint", err)
	}
}

func TestProbeHeadersRejectsMissingHost(t *testing.T) {
	c := New("fake-token", "", "")
	_, err := c.ProbeHeaders("http:///path-only")
	if err == nil {
		t.Fatal("expected empty-host URL to be rejected")
	}
}

// TestProbeHeadersReusesTransport asserts that the pooled probe client is
// reused across calls (F-R2). We don't have direct access to the transport
// after construction so we assert via the sync.Once side-effect: the
// probeClient pointer stays the same across calls.
func TestProbeHeadersReusesTransport(t *testing.T) {
	c := New("fake-token", "", "")
	// Trigger lazy init twice via the internal getter.
	first := c.getProbeClient()
	second := c.getProbeClient()
	if first != second {
		t.Error("getProbeClient returned different *http.Client instances; expected reuse")
	}
}
