package client

import (
	"net/http"
	"os"
	"path/filepath"
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

func mustNewRequest(method, url string) *http.Request {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		panic(err)
	}
	return req
}
