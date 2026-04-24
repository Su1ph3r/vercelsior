package client

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- Redaction ----------

func TestRedactJSONBody_PlainEnvVarValue(t *testing.T) {
	// Mimic a /v1/env response where "value" carries a decrypted secret
	// for plain-type vars.
	body := []byte(`{"envs":[{"key":"DATABASE_URL","value":"postgres://u:p@host/db","type":"plain"}]}`)
	out := redactJSONBody(body)

	if strings.Contains(out, "postgres://u:p@host/db") {
		t.Errorf("env var value was not redacted; got: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected [REDACTED] placeholder in output; got: %s", out)
	}
	// The non-sensitive fields stay intact.
	if !strings.Contains(out, "DATABASE_URL") || !strings.Contains(out, "plain") {
		t.Errorf("non-sensitive fields were wrongly redacted: %s", out)
	}
}

func TestRedactJSONBody_TokenMetadata(t *testing.T) {
	body := []byte(`{"tokens":[{"id":"tok_1","name":"ci","leakedUrl":"https://gist.github.com/leak"}]}`)
	out := redactJSONBody(body)
	if strings.Contains(out, "gist.github.com/leak") {
		t.Errorf("leakedUrl not redacted: %s", out)
	}
}

func TestRedactJSONBody_NestedRedaction(t *testing.T) {
	body := []byte(`{"outer":{"inner":{"secret":"hunter2","name":"ok"}}}`)
	out := redactJSONBody(body)
	if strings.Contains(out, "hunter2") {
		t.Errorf("nested secret not redacted: %s", out)
	}
	if !strings.Contains(out, `"name":"ok"`) {
		t.Errorf("nested non-sensitive field removed: %s", out)
	}
}

func TestRedactJSONBody_ArrayOfObjects(t *testing.T) {
	body := []byte(`[{"token":"abc"},{"token":"def"}]`)
	out := redactJSONBody(body)
	if strings.Contains(out, `"abc"`) || strings.Contains(out, `"def"`) {
		t.Errorf("tokens in array not redacted: %s", out)
	}
}

func TestRedactJSONBody_CaseInsensitiveKeyMatch(t *testing.T) {
	// JSON keys are case-sensitive in JSON, but our redaction treats keys
	// case-insensitively so "Secret", "SECRET", and "SecretKey"-style
	// values don't leak through by capitalization alone.
	body := []byte(`{"Secret":"a","SECRET":"b","value":"c"}`)
	out := redactJSONBody(body)
	for _, raw := range []string{`"a"`, `"b"`, `"c"`} {
		if strings.Contains(out, raw) {
			t.Errorf("raw value %s not redacted: %s", raw, out)
		}
	}
}

func TestRedactJSONBody_NonJSONPassthrough(t *testing.T) {
	// A non-JSON body (e.g. HTML error page) is returned as-is rather
	// than truncated or garbled.
	body := []byte(`<html>error</html>`)
	if got := redactJSONBody(body); got != string(body) {
		t.Errorf("non-JSON body altered: got %q; want %q", got, string(body))
	}
}

func TestRedactJSONBody_Empty(t *testing.T) {
	if got := redactJSONBody(nil); got != "" {
		t.Errorf("nil body -> %q; want empty", got)
	}
	if got := redactJSONBody([]byte("")); got != "" {
		t.Errorf("empty body -> %q; want empty", got)
	}
}

func TestRedactJSONBody_PreservesNullForSensitiveKey(t *testing.T) {
	// A null value for a sensitive key stays null (don't invent a string
	// placeholder where the API explicitly returned null).
	body := []byte(`{"value":null,"token":null}`)
	out := redactJSONBody(body)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if parsed["value"] != nil {
		t.Errorf("null value was overwritten: %v", parsed["value"])
	}
}

func TestRedactValue_NonMutating(t *testing.T) {
	// The walker must not mutate the input in place — it should return a
	// new structure.
	original := map[string]interface{}{
		"secret": "keep-original",
		"nested": map[string]interface{}{"token": "abc"},
	}
	_ = redactValue(original)
	if original["secret"] != "keep-original" {
		t.Errorf("original was mutated: %v", original["secret"])
	}
	nested := original["nested"].(map[string]interface{})
	if nested["token"] != "abc" {
		t.Errorf("nested map was mutated: %v", nested["token"])
	}
}

// ---------- Path traversal defense ----------

func TestSafeRecordingPath(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"normal", "GET__v2_user_abc123", false},
		{"empty", "", true},
		{"with slash", "a/b", true},
		{"with backslash", `a\b`, true},
		{"with dot-dot", "..evil", true},
		{"path traversal", "../../etc/passwd", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := safeRecordingPath(dir, tc.key)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v; wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && !strings.HasPrefix(p, dir) {
				t.Errorf("returned path %q not inside %q", p, dir)
			}
		})
	}
}

// ---------- Sensitive response headers ----------

func TestSaveResponse_ScrubsSensitiveHeaders(t *testing.T) {
	dir := t.TempDir()
	key := "GET__v5_user_tokens_testkey"
	filePath, err := safeRecordingPath(dir, key)
	if err != nil {
		t.Fatal(err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
			"Set-Cookie":   []string{"session=abc123"},
			"X-Vercel-Id":  []string{"iad1::abc"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{}`))),
	}
	tr := &RecordingTransport{Directory: dir}
	if err := tr.saveResponse(filePath, resp); err != nil {
		t.Fatalf("saveResponse err = %v", err)
	}

	// Read it back and confirm Set-Cookie/X-Vercel-Id are redacted while
	// Content-Type passes through.
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	var rec recordedResponse
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("corrupt recording: %v", err)
	}
	if rec.Headers["Content-Type"] != "application/json" {
		t.Errorf("Content-Type missing or wrong: %q", rec.Headers["Content-Type"])
	}
	if rec.Headers["Set-Cookie"] != "[REDACTED]" {
		t.Errorf("Set-Cookie not redacted: %q", rec.Headers["Set-Cookie"])
	}
	if rec.Headers["X-Vercel-Id"] != "[REDACTED]" {
		t.Errorf("X-Vercel-Id not redacted: %q", rec.Headers["X-Vercel-Id"])
	}
}

// ---------- saveResponse error paths ----------

// TestSaveResponse_ReadErrorClosesBody ensures the original body is closed
// even when io.ReadAll fails (regression for F-R1). We wrap a ReadCloser
// that returns an error on first read and tracks Close() calls.
func TestSaveResponse_ReadErrorClosesBody(t *testing.T) {
	dir := t.TempDir()
	filePath, _ := safeRecordingPath(dir, "GET__fail_testkey")

	flaky := &flakyBody{err: io.ErrUnexpectedEOF}
	resp := &http.Response{
		StatusCode: 500,
		Header:     http.Header{},
		Body:       flaky,
	}
	tr := &RecordingTransport{Directory: dir}
	err := tr.saveResponse(filePath, resp)
	if err == nil {
		t.Fatal("expected an error when body read fails")
	}
	if !flaky.closed {
		t.Error("original body was not closed on read error (resource leak)")
	}
}

type flakyBody struct {
	err    error
	closed bool
}

func (f *flakyBody) Read(p []byte) (int, error) { return 0, f.err }
func (f *flakyBody) Close() error               { f.closed = true; return nil }

// ---------- Record + replay round trip with redaction ----------

func TestRecordThenReplay_SecretsAreRedactedOnDisk(t *testing.T) {
	dir := t.TempDir()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=top-secret")
		_, _ = w.Write([]byte(`{"tokens":[{"id":"t1","token":"raw-bearer-xyz"}]}`))
	}))
	defer upstream.Close()

	transport := &RecordingTransport{
		Inner:     &rewriteTransport{Target: upstream.URL},
		Mode:      ModeRecord,
		Directory: dir,
	}

	req, _ := http.NewRequest("GET", "https://api.vercel.com/v5/user/tokens", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	// Consume the response so the replay-mode caller sees the live body.
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "raw-bearer-xyz") {
		t.Errorf("live response should have included the raw token; body = %s", body)
	}

	// Now inspect the on-disk fixture — the token and cookie must be gone.
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("recording directory empty: %v", err)
	}
	diskData, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	disk := string(diskData)
	if strings.Contains(disk, "raw-bearer-xyz") {
		t.Errorf("raw token leaked to disk:\n%s", disk)
	}
	if strings.Contains(disk, "top-secret") {
		t.Errorf("session cookie leaked to disk:\n%s", disk)
	}
	if !strings.Contains(disk, "[REDACTED]") {
		t.Errorf("expected [REDACTED] placeholder on disk:\n%s", disk)
	}
}
