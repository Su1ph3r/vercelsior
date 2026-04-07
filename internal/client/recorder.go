package client

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type RecorderMode int

const (
	ModePassthrough RecorderMode = iota
	ModeRecord
	ModeReplay
)

type RecordingTransport struct {
	Inner     http.RoundTripper
	Mode      RecorderMode
	Directory string // directory to store/read recordings
}

type recordedResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

func (t *RecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := RequestKey(req)
	filePath := filepath.Join(t.Directory, key+".json")

	switch t.Mode {
	case ModeReplay:
		return t.replayResponse(filePath, req)
	case ModeRecord:
		resp, err := t.Inner.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		t.saveResponse(filePath, resp)
		return resp, nil
	default:
		return t.Inner.RoundTrip(req)
	}
}

// RequestKey returns a deterministic file-safe key for an HTTP request.
// Exported so integration tests can write fixture files with matching names.
func RequestKey(req *http.Request) string {
	// Create a deterministic key from method + path + sorted query params
	path := req.URL.Path
	query := req.URL.RawQuery
	raw := fmt.Sprintf("%s|%s|%s", req.Method, path, query)
	hash := sha256.Sum256([]byte(raw))
	// Use a readable prefix + short hash
	safePath := strings.ReplaceAll(path, "/", "_")
	if len(safePath) > 60 {
		safePath = safePath[:60]
	}
	return fmt.Sprintf("%s_%s_%x", req.Method, safePath, hash[:8])
}

func (t *RecordingTransport) saveResponse(filePath string, resp *http.Response) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Warning: failed to read response body for recording: %v", err)
		return
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))

	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		log.Printf("Warning: failed to create recording directory: %v", err)
		return
	}

	rec := recordedResponse{
		StatusCode: resp.StatusCode,
		Headers:    make(map[string]string),
		Body:       string(body),
	}
	for k, v := range resp.Header {
		if len(v) > 0 {
			rec.Headers[k] = v[0]
		}
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		log.Printf("Warning: failed to marshal recording: %v", err)
		return
	}
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		log.Printf("Warning: failed to write recording file %s: %v", filePath, err)
	}
}

func (t *RecordingTransport) replayResponse(filePath string, req *http.Request) (*http.Response, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		// No recording found — return 404
		return &http.Response{
			StatusCode: 404,
			Body:       io.NopCloser(strings.NewReader(`{"error":{"code":"not_found"}}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}

	var rec recordedResponse
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("corrupt recording %s: %w", filePath, err)
	}

	header := make(http.Header)
	for k, v := range rec.Headers {
		header.Set(k, v)
	}

	return &http.Response{
		StatusCode: rec.StatusCode,
		Body:       io.NopCloser(strings.NewReader(rec.Body)),
		Header:     header,
		Request:    req,
	}, nil
}

// NewRecordingClient creates a client that records or replays API responses.
func NewRecordingClient(token string, teamID string, teamSlug string, mode RecorderMode, dir string) *Client {
	transport := &RecordingTransport{
		Inner:     http.DefaultTransport,
		Mode:      mode,
		Directory: dir,
	}
	c := New(token, teamID, teamSlug)
	c.http.Transport = transport
	return c
}
