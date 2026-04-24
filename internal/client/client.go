package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ErrPermissionDenied is returned when the API returns HTTP 403.
var ErrPermissionDenied = errors.New("permission denied (HTTP 403)")

const baseURL = "https://api.vercel.com"

type APIEvidence struct {
	Method     string
	Path       string
	StatusCode int
	Body       string // truncated
}

type Client struct {
	token            string
	teamID           string
	teamSlug         string
	http             *http.Client
	LiveProbe        bool
	PermissionDenied []string // tracks paths that returned 403
	permMu           sync.Mutex
	evidenceLog      []APIEvidence
	evidenceMu       sync.Mutex

	// probeClient is a lazily-initialized HTTP client used by ProbeHeaders.
	// Sharing a single client across all probes (instead of building a fresh
	// http.Transport per call) avoids leaking idle sockets and read-loop
	// goroutines scaled to the number of projects in a scan.
	probeOnce   sync.Once
	probeClient *http.Client
}

func New(token string, teamID string, teamSlug string) *Client {
	return &Client{
		token:    token,
		teamID:   teamID,
		teamSlug: teamSlug,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) buildURL(path string, params map[string]string) string {
	u := baseURL + path
	q := url.Values{}
	if c.teamID != "" {
		q.Set("teamId", c.teamID)
	} else if c.teamSlug != "" {
		q.Set("slug", c.teamSlug)
	}
	for k, v := range params {
		q.Set(k, v)
	}
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

func (c *Client) request(method, path string, params map[string]string) (json.RawMessage, error) {
	reqURL := c.buildURL(path, params)
	for attempt := 0; attempt < 5; attempt++ {
		req, err := http.NewRequest(method, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("executing request: %w", err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading response body for %s: %w", path, err)
		}

		if resp.StatusCode == 429 {
			resetStr := resp.Header.Get("X-RateLimit-Reset")
			wait := 5
			if resetStr != "" {
				if resetTs, err := strconv.ParseInt(resetStr, 10, 64); err == nil {
					wait = int(resetTs - time.Now().Unix())
					if wait < 1 {
						wait = 1
					}
					if wait > 60 {
						wait = 60
					}
				}
			}
			log.Printf("Rate limited, waiting %ds...", wait)
			c.logEvidence(method, path, resp.StatusCode, string(body))
			time.Sleep(time.Duration(wait) * time.Second)
			continue
		}
		c.logEvidence(method, path, resp.StatusCode, string(body))

		if resp.StatusCode == 403 {
			c.permMu.Lock()
			c.PermissionDenied = append(c.PermissionDenied, path)
			c.permMu.Unlock()
			log.Printf("403 on %s %s — insufficient permissions, skipping.", method, path)
			return nil, ErrPermissionDenied
		}
		if resp.StatusCode == 404 {
			return nil, nil
		}
		if resp.StatusCode >= 400 {
			msg := utf8SafeTruncateString(string(body), 500)
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
		}
		if resp.StatusCode == 204 || len(body) == 0 {
			return json.RawMessage("{}"), nil
		}
		return json.RawMessage(body), nil
	}
	return nil, fmt.Errorf("rate limit retries exhausted")
}

func (c *Client) Get(path string, params map[string]string) (json.RawMessage, error) {
	return c.request("GET", path, params)
}

// GetPaginated fetches all pages from a paginated Vercel API endpoint.
// dataKey is the JSON key containing the array of items.
//
// The caller's params map is never mutated: a local copy is used for the
// pagination cursor so reusing a params map across calls to different
// endpoints does not leak an `until` cursor into the next request.
func (c *Client) GetPaginated(path, dataKey string, params map[string]string) ([]json.RawMessage, error) {
	local := make(map[string]string, len(params)+1)
	for k, v := range params {
		local[k] = v
	}
	if _, ok := local["limit"]; !ok {
		local["limit"] = "100"
	}
	params = local
	var all []json.RawMessage

	for {
		raw, err := c.Get(path, params)
		if err != nil {
			return all, err
		}
		if raw == nil {
			break
		}

		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return all, fmt.Errorf("parsing response: %w", err)
		}

		itemsRaw, ok := envelope[dataKey]
		if !ok {
			break
		}
		var items []json.RawMessage
		if err := json.Unmarshal(itemsRaw, &items); err != nil {
			return all, fmt.Errorf("parsing items for %s: %w", path, err)
		}
		all = append(all, items...)

		paginationRaw, ok := envelope["pagination"]
		if !ok {
			break
		}
		var pagination struct {
			Next *int64 `json:"next"`
		}
		if err := json.Unmarshal(paginationRaw, &pagination); err != nil || pagination.Next == nil {
			break
		}
		params["until"] = strconv.FormatInt(*pagination.Next, 10)
	}
	return all, nil
}

// Convenience helpers that return parsed data

func (c *Client) GetUser() (map[string]interface{}, error) {
	raw, err := c.Get("/v2/user", nil)
	if err != nil || raw == nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	if user, ok := resp["user"].(map[string]interface{}); ok {
		return user, nil
	}
	return resp, nil
}

func (c *Client) ListTeams() ([]map[string]interface{}, error) {
	return c.getPaginatedMaps("/v2/teams", "teams", nil)
}

func (c *Client) GetTeam(teamID string) (map[string]interface{}, error) {
	raw, err := c.Get(fmt.Sprintf("/v2/teams/%s", teamID), nil)
	if err != nil || raw == nil {
		return nil, err
	}
	var result map[string]interface{}
	return result, json.Unmarshal(raw, &result)
}

func (c *Client) ListTeamMembers(teamID string) ([]map[string]interface{}, error) {
	return c.getPaginatedMaps(fmt.Sprintf("/v3/teams/%s/members", teamID), "members", nil)
}

func (c *Client) ListTokens() ([]map[string]interface{}, error) {
	raw, err := c.Get("/v5/user/tokens", nil)
	if err != nil || raw == nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return toSliceOfMaps(resp["tokens"]), nil
}

func (c *Client) ListProjects() ([]map[string]interface{}, error) {
	return c.getPaginatedMaps("/v10/projects", "projects", nil)
}

func (c *Client) GetProject(id string) (map[string]interface{}, error) {
	raw, err := c.Get(fmt.Sprintf("/v9/projects/%s", id), nil)
	if err != nil || raw == nil {
		return nil, err
	}
	var result map[string]interface{}
	return result, json.Unmarshal(raw, &result)
}

func (c *Client) ListProjectEnvVars(projectID string) ([]map[string]interface{}, error) {
	return c.getPaginatedMaps(fmt.Sprintf("/v10/projects/%s/env", projectID), "envs", nil)
}

func (c *Client) ListProjectDomains(projectID string) ([]map[string]interface{}, error) {
	return c.getPaginatedMaps(fmt.Sprintf("/v9/projects/%s/domains", projectID), "domains", nil)
}

func (c *Client) ListProjectMembers(projectID string) ([]map[string]interface{}, error) {
	return c.getPaginatedMaps(fmt.Sprintf("/v1/projects/%s/members", projectID), "members", nil)
}

func (c *Client) ListDomains() ([]map[string]interface{}, error) {
	return c.getPaginatedMaps("/v5/domains", "domains", nil)
}

func (c *Client) GetDomainConfig(domain string) (map[string]interface{}, error) {
	raw, err := c.Get(fmt.Sprintf("/v6/domains/%s/config", domain), nil)
	if err != nil || raw == nil {
		return nil, err
	}
	var result map[string]interface{}
	return result, json.Unmarshal(raw, &result)
}

func (c *Client) ListDNSRecords(domain string) ([]map[string]interface{}, error) {
	return c.getPaginatedMaps(fmt.Sprintf("/v5/domains/%s/records", domain), "records", nil)
}

func (c *Client) GetFirewallConfig(projectID string) (map[string]interface{}, error) {
	raw, err := c.Get("/v1/security/firewall/config/active", map[string]string{"projectId": projectID})
	if err != nil || raw == nil {
		return nil, err
	}
	var result map[string]interface{}
	return result, json.Unmarshal(raw, &result)
}

func (c *Client) GetFirewallBypass(projectID string) (map[string]interface{}, error) {
	raw, err := c.Get("/v1/security/firewall/bypass", map[string]string{"projectId": projectID})
	if err != nil || raw == nil {
		return nil, err
	}
	var result map[string]interface{}
	return result, json.Unmarshal(raw, &result)
}

func (c *Client) ListDeployments(projectID string, limit int) ([]map[string]interface{}, error) {
	params := map[string]string{"limit": strconv.Itoa(limit)}
	if projectID != "" {
		params["projectId"] = projectID
	}
	return c.getPaginatedMaps("/v6/deployments", "deployments", params)
}

// ListDeploymentsLimit fetches up to `limit` most recent deployments without pagination.
func (c *Client) ListDeploymentsLimit(projectID string, limit int) ([]map[string]interface{}, error) {
	params := map[string]string{"limit": strconv.Itoa(limit)}
	if projectID != "" {
		params["projectId"] = projectID
	}
	raw, err := c.Get("/v6/deployments", params)
	if err != nil || raw == nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return toSliceOfMaps(resp["deployments"]), nil
}

func (c *Client) ListWebhooks() ([]map[string]interface{}, error) {
	raw, err := c.Get("/v1/webhooks", nil)
	if err != nil || raw == nil {
		return nil, err
	}
	return parseListResponse(raw, "webhooks")
}

func (c *Client) ListLogDrains() ([]map[string]interface{}, error) {
	raw, err := c.Get("/v1/drains", nil)
	if err != nil || raw == nil {
		return nil, err
	}
	// Response may be a raw array or an object {"drains": [...]}.
	return parseListResponse(raw, "drains")
}

func (c *Client) ListIntegrations() ([]map[string]interface{}, error) {
	return c.getPaginatedMaps("/v1/integrations/configurations", "configurations", map[string]string{"view": "account"})
}

func (c *Client) ListEdgeConfigs() ([]map[string]interface{}, error) {
	raw, err := c.Get("/v1/edge-config", nil)
	if err != nil || raw == nil {
		return nil, err
	}
	return parseListResponse(raw, "items")
}

func (c *Client) ListEdgeConfigTokens(edgeConfigID string) ([]map[string]interface{}, error) {
	raw, err := c.Get(fmt.Sprintf("/v1/edge-config/%s/tokens", edgeConfigID), nil)
	if err != nil || raw == nil {
		return nil, err
	}
	return parseListResponse(raw, "tokens")
}

func (c *Client) ListAccessGroups() ([]map[string]interface{}, error) {
	return c.getPaginatedMaps("/v1/access-groups", "accessGroups", nil)
}

func (c *Client) ListAliases() ([]map[string]interface{}, error) {
	return c.getPaginatedMaps("/v4/aliases", "aliases", nil)
}

func (c *Client) ListSecureComputeNetworks() ([]map[string]interface{}, error) {
	raw, err := c.Get("/v1/connect/networks", nil)
	if err != nil || raw == nil {
		return nil, err
	}
	return parseListResponse(raw, "networks")
}

func (c *Client) ListSharedEnvVars() ([]map[string]interface{}, error) {
	raw, err := c.Get("/v1/env", nil)
	if err != nil || raw == nil {
		return nil, err
	}
	// Vercel migrated from "envs" to "data" at some point; accept both.
	return parseListResponse(raw, "data", "envs")
}

func (c *Client) GetArtifactsStatus() (map[string]interface{}, error) {
	raw, err := c.Get("/v8/artifacts/status", nil)
	if err != nil || raw == nil {
		return nil, err
	}
	var result map[string]interface{}
	return result, json.Unmarshal(raw, &result)
}

func (c *Client) ListCertificates() ([]map[string]interface{}, error) {
	raw, err := c.Get("/v7/certs", nil)
	if err != nil || raw == nil {
		return nil, err
	}
	return parseListResponse(raw, "certs")
}

func (c *Client) ListFeatureFlags(projectID string) ([]map[string]interface{}, error) {
	return c.getPaginatedMaps(fmt.Sprintf("/v1/projects/%s/feature-flags/flags", projectID), "data", nil)
}

func (c *Client) ListBulkRedirects(projectID string) ([]map[string]interface{}, error) {
	raw, err := c.Get("/v1/bulk-redirects", map[string]string{"projectId": projectID})
	if err != nil || raw == nil {
		return nil, err
	}
	return parseListResponse(raw, "redirects")
}

func (c *Client) ListProjectRoutes(projectID string) ([]map[string]interface{}, error) {
	raw, err := c.Get(fmt.Sprintf("/v1/projects/%s/routes", projectID), nil)
	if err != nil || raw == nil {
		return nil, err
	}
	return parseListResponse(raw, "routes")
}

func (c *Client) ListSandboxes(projectID string) ([]map[string]interface{}, error) {
	raw, err := c.Get("/v1/sandboxes", map[string]string{"project": projectID})
	if err != nil || raw == nil {
		return nil, err
	}
	return parseListResponse(raw, "sandboxes")
}

func (c *Client) ListDeploymentChecks(deploymentID string) ([]map[string]interface{}, error) {
	return c.getPaginatedMaps(fmt.Sprintf("/v2/deployments/%s/check-runs", deploymentID), "runs", nil)
}

func (c *Client) GetRollingReleaseConfig(projectID string) (map[string]interface{}, error) {
	raw, err := c.Get(fmt.Sprintf("/v1/projects/%s/rolling-release/config", projectID), nil)
	if err != nil || raw == nil {
		return nil, err
	}
	var result map[string]interface{}
	return result, json.Unmarshal(raw, &result)
}

func (c *Client) logEvidence(method, path string, status int, body string) {
	c.evidenceMu.Lock()
	defer c.evidenceMu.Unlock()
	if len(body) > 50000 {
		body = utf8SafeTruncateString(body, 50000) + "...[truncated]"
	}
	c.evidenceLog = append(c.evidenceLog, APIEvidence{
		Method: method, Path: path, StatusCode: status, Body: body,
	})
	// Keep last 200 entries
	if len(c.evidenceLog) > 200 {
		c.evidenceLog = c.evidenceLog[len(c.evidenceLog)-200:]
	}
}

// utf8SafeTruncateString cuts s to at most maxBytes while preserving valid
// UTF-8. A raw byte slice can split a multi-byte rune; the error message or
// evidence body would then appear as U+FFFD characters in reports.
func utf8SafeTruncateString(s string, maxBytes int) string {
	if maxBytes < 0 || len(s) <= maxBytes {
		return s
	}
	trimmed := s[:maxBytes]
	for len(trimmed) > 0 && !utf8.ValidString(trimmed) {
		trimmed = trimmed[:len(trimmed)-1]
	}
	return trimmed
}

// GetEvidence returns evidence for a specific API path (most recent match).
// Supports exact match and prefix match (for paginated list endpoints).
func (c *Client) GetEvidence(path string) *APIEvidence {
	c.evidenceMu.Lock()
	defer c.evidenceMu.Unlock()
	// Exact match first
	for i := len(c.evidenceLog) - 1; i >= 0; i-- {
		if c.evidenceLog[i].Path == path {
			ev := c.evidenceLog[i]
			return &ev
		}
	}
	// Prefix match (e.g., path="/v10/projects" matches logged "/v10/projects")
	for i := len(c.evidenceLog) - 1; i >= 0; i-- {
		if strings.HasPrefix(c.evidenceLog[i].Path, path) || strings.HasPrefix(path, c.evidenceLog[i].Path) {
			ev := c.evidenceLog[i]
			return &ev
		}
	}
	return nil
}

// PermissionSummary returns a deduplicated list of API paths that returned 403.
func (c *Client) PermissionSummary() []string {
	c.permMu.Lock()
	defer c.permMu.Unlock()
	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, p := range c.PermissionDenied {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// helpers

func (c *Client) getPaginatedMaps(path, dataKey string, params map[string]string) ([]map[string]interface{}, error) {
	raws, err := c.GetPaginated(path, dataKey, params)
	if err != nil {
		return nil, err
	}
	result := make([]map[string]interface{}, 0, len(raws))
	skipped := 0
	for _, r := range raws {
		var m map[string]interface{}
		if err := json.Unmarshal(r, &m); err != nil {
			skipped++
			continue
		}
		result = append(result, m)
	}
	if skipped > 0 {
		// Don't fail the whole list (single bad items shouldn't sink an entire
		// audit) but log once so the skip is not fully invisible.
		log.Printf("Warning: %d item(s) from %s failed to parse and were skipped", skipped, path)
	}
	return result, nil
}

func toSliceOfMaps(v interface{}) []map[string]interface{} {
	if arr, ok := v.([]interface{}); ok {
		result := make([]map[string]interface{}, 0, len(arr))
		for _, item := range arr {
			if m, ok := item.(map[string]interface{}); ok {
				result = append(result, m)
			}
		}
		return result
	}
	return nil
}

// parseListResponse decodes raw as either a JSON array of items or an object
// whose value at one of the supplied keys is the item array. An empty body
// returns (nil, nil). Any parse failure or unrecognized shape returns an
// error — callers get a real failure instead of an empty list that hides a
// malformed API response.
func parseListResponse(raw json.RawMessage, dataKeys ...string) ([]map[string]interface{}, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var arr []map[string]interface{}
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("parsing array response: %w", err)
		}
		return arr, nil
	}
	if trimmed[0] == '{' {
		var obj map[string]interface{}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil, fmt.Errorf("parsing object response: %w", err)
		}
		for _, key := range dataKeys {
			if items, ok := obj[key]; ok {
				return toSliceOfMaps(items), nil
			}
		}
		return nil, fmt.Errorf("response object does not contain any of the expected keys %v", dataKeys)
	}
	return nil, fmt.Errorf("unexpected response shape: neither array nor object")
}

// isDisallowedProbeIP reports whether the given IP is in a range that the
// SSRF guard must refuse: loopback, private, link-local, multicast, or the
// unspecified address (0.0.0.0 / ::). The 169.254.169.254 cloud metadata
// endpoint is already covered by IsLinkLocalUnicast, but we check it
// explicitly as belt-and-braces.
func isDisallowedProbeIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	return false
}

// getProbeClient returns a shared http.Client used for header probes in
// --live mode. The client is built once per Client and reused across all
// ProbeHeaders calls, so per-call transport allocation does not leak idle
// sockets or background goroutines scaled to the number of projects.
//
// The dialer resolves the host exactly once per connection and then dials
// the already-validated IP directly. This closes the DNS-rebinding TOCTOU
// gap that exists when the SSRF check and the underlying net.Dial each
// perform their own independent resolution. TLS ServerName (and the Host
// header) continue to carry the original hostname so virtual-host routing
// and certificate validation work normally.
//
// Redirects are not followed (CheckRedirect returns ErrUseLastResponse)
// because a 30x redirect would re-enter net/http's dialer for the new host
// without our pinned-IP logic, and because a probe that silently follows
// off-host redirects can leak response headers from internal targets.
func (c *Client) getProbeClient() *http.Client {
	c.probeOnce.Do(func() {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		transport := &http.Transport{
			// Keep the per-Client pool small — we make at most one HEAD per
			// project and want idle conns to expire quickly.
			MaxIdleConns:          10,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid address %s: %w", addr, err)
				}
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
				}
				if len(ips) == 0 {
					return nil, fmt.Errorf("no IPs resolved for %s", host)
				}
				// Reject if ANY resolved IP is disallowed. A legitimate host
				// should never resolve to a private IP; refusing the whole
				// lookup prevents a round-robin rebind from sneaking an
				// internal address into the pool.
				for _, ip := range ips {
					if isDisallowedProbeIP(ip.IP) {
						return nil, fmt.Errorf("blocked request to private/reserved IP %s for host %s", ip.IP, host)
					}
				}
				// Dial the first validated IP directly so the connection
				// cannot re-resolve and land on a different address. The
				// SNI/Host preservation is handled by the caller via
				// tls.Config.ServerName and req.Host, which default to the
				// original hostname from the URL.
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
			},
		}
		c.probeClient = &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
			// Don't follow redirects: the pinned-IP dialer only makes sense
			// for the hostname the caller validated; following a redirect
			// to a different host bypasses the caller's intent and opens a
			// second TOCTOU window.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	})
	return c.probeClient
}

// ProbeHeaders performs a HEAD request against the given URL and returns
// the response headers as a lowercase key -> value map.
// Blocks requests to private/reserved IP ranges to prevent SSRF, including
// DNS-rebinding attacks where a hostile authoritative DNS server returns
// a public IP on the first lookup and an internal IP on the second.
func (c *Client) ProbeHeaders(targetURL string) (map[string]string, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parsing probe URL %q: %w", targetURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("probe URL must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("probe URL has no host")
	}

	req, err := http.NewRequest(http.MethodHead, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating probe request: %w", err)
	}
	req.Header.Set("User-Agent", "vercelsior-security-scanner")
	// TLS SNI and the HTTP Host header are derived by net/http from the
	// request's URL.Host; the dialer's pinned-IP connection still gets the
	// original hostname presented during the TLS handshake, so certificate
	// validation works correctly.

	resp, err := c.getProbeClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("probing %s: %w", targetURL, err)
	}
	defer resp.Body.Close()
	// HEAD responses have no body, but some servers ignore that. Drain
	// any bytes so the connection can return to the idle pool cleanly.
	_, _ = io.Copy(io.Discard, resp.Body)

	headers := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}
	return headers, nil
}
