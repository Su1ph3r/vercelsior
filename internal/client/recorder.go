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

// redactedPlaceholder is written in place of any value whose key matches
// sensitiveJSONKeys, or in place of a stripped response header. It is a
// visible marker so users can tell at a glance that a recorded fixture has
// been redacted and not just truncated.
const redactedPlaceholder = "[REDACTED]"

// sensitiveResponseHeaders lists response header names (lowercase) that are
// scrubbed from recorded fixtures. Set-Cookie can carry session identifiers;
// x-vercel-id and similar platform identifiers are per-account and can
// correlate recordings to a specific tenant.
var sensitiveResponseHeaders = map[string]bool{
	"set-cookie":       true,
	"x-vercel-id":      true,
	"x-vercel-trace":   true,
	"x-amz-request-id": true,
}

// sensitiveJSONKeys is the set of JSON object keys whose values are replaced
// with redactedPlaceholder when walking recorded response bodies. The list
// covers Vercel API fields that carry decrypted secrets (plain-type env var
// values), token material, and leak-detection metadata. The match is
// case-insensitive.
var sensitiveJSONKeys = map[string]bool{
	"value":          true, // env var decrypted value (for plain-type vars)
	"decryptedvalue": true,
	"token":          true, // access token material
	"bearertoken":    true,
	"accesstoken":    true,
	"refreshtoken":   true,
	"secret":         true, // webhook secrets, signing secrets
	"signingsecret":  true,
	"privatekey":     true,
	"password":       true,
	"leakedurl":      true, // URL where a leaked token was detected — can identify paste sites
	"invitecode":     true, // team invite codes
}

func (t *RecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := RequestKey(req)
	filePath, pathErr := safeRecordingPath(t.Directory, key)

	switch t.Mode {
	case ModeReplay:
		if pathErr != nil {
			return nil, pathErr
		}
		return t.replayResponse(filePath, req)
	case ModeRecord:
		resp, err := t.Inner.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		if pathErr != nil {
			// Can't write a recording with an unsafe key; still return the
			// live response so the scan can proceed.
			log.Printf("Warning: skipping recording for %s %s: %v", req.Method, req.URL.Path, pathErr)
			return resp, nil
		}
		if saveErr := t.saveResponse(filePath, resp); saveErr != nil {
			log.Printf("Warning: failed to record %s %s: %v", req.Method, req.URL.Path, saveErr)
		}
		return resp, nil
	default:
		return t.Inner.RoundTrip(req)
	}
}

// safeRecordingPath builds a replay/record file path for a request key,
// rejecting any key that would escape the recording directory. This is
// belt-and-braces: RequestKey currently emits only safe characters, but
// validating at the filesystem boundary prevents a future change (or a
// caller that bypasses RequestKey) from producing a path-traversal write.
func safeRecordingPath(dir, key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("empty recording key")
	}
	if strings.ContainsAny(key, `/\`) || strings.Contains(key, "..") {
		return "", fmt.Errorf("invalid recording key %q", key)
	}
	candidate := filepath.Join(dir, key+".json")
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolving recording dir: %w", err)
	}
	absCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("resolving recording path: %w", err)
	}
	rel, err := filepath.Rel(absDir, absCandidate)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", fmt.Errorf("recording key %q escapes recording directory", key)
	}
	return candidate, nil
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

func (t *RecordingTransport) saveResponse(filePath string, resp *http.Response) error {
	// Read the live body and reset resp.Body so the caller still sees it.
	// Capture the original ReadCloser separately so we can guarantee it is
	// closed even when io.ReadAll fails partway through (otherwise the
	// underlying TCP connection leaks until keep-alive timeout).
	origBody := resp.Body
	body, readErr := io.ReadAll(origBody)
	closeErr := origBody.Close()
	if readErr != nil {
		// Give the caller an empty body so downstream reads don't explode.
		resp.Body = io.NopCloser(strings.NewReader(""))
		return fmt.Errorf("reading response body for recording: %w", readErr)
	}
	if closeErr != nil {
		// Non-fatal: we already have the bytes. Log but continue.
		log.Printf("Warning: closing original response body: %v", closeErr)
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))

	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return fmt.Errorf("creating recording directory: %w", err)
	}

	rec := recordedResponse{
		StatusCode: resp.StatusCode,
		Headers:    make(map[string]string),
		Body:       redactJSONBody(body),
	}
	for k, v := range resp.Header {
		if sensitiveResponseHeaders[strings.ToLower(k)] {
			rec.Headers[k] = redactedPlaceholder
			continue
		}
		if len(v) > 0 {
			rec.Headers[k] = v[0]
		}
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling recording: %w", err)
	}
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("writing recording file %s: %w", filePath, err)
	}
	return nil
}

// redactJSONBody walks the JSON body and replaces the values of any keys in
// sensitiveJSONKeys with redactedPlaceholder. Non-JSON bodies are returned
// unchanged (they don't come from Vercel's JSON API endpoints, and applying
// a string-replace heuristic would corrupt them). The output re-marshals
// the walked object so the recording remains parseable on replay.
func redactJSONBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		// Not JSON — return as-is, callers can decide whether they trust it.
		return string(body)
	}
	redacted := redactValue(parsed)
	out, err := json.Marshal(redacted)
	if err != nil {
		return string(body)
	}
	return string(out)
}

// redactValue recursively walks a decoded JSON value. Map values whose keys
// match sensitiveJSONKeys (case-insensitively) are replaced with a string
// placeholder; other values are recursed into so nested objects and arrays
// are also redacted.
func redactValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, vv := range val {
			if sensitiveJSONKeys[strings.ToLower(k)] {
				if vv == nil {
					out[k] = nil
				} else {
					out[k] = redactedPlaceholder
				}
				continue
			}
			out[k] = redactValue(vv)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, item := range val {
			out[i] = redactValue(item)
		}
		return out
	default:
		return v
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
