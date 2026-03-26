package client

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

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
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

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
			time.Sleep(time.Duration(wait) * time.Second)
			continue
		}
		c.logEvidence(method, path, resp.StatusCode, string(body))

		if resp.StatusCode == 403 {
			c.permMu.Lock()
			c.PermissionDenied = append(c.PermissionDenied, path)
			c.permMu.Unlock()
			log.Printf("403 on %s %s — insufficient permissions, skipping.", method, path)
			return nil, nil
		}
		if resp.StatusCode == 404 {
			return nil, nil
		}
		if resp.StatusCode >= 400 {
			msg := string(body)
			if len(msg) > 500 {
				msg = msg[:500]
			}
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
func (c *Client) GetPaginated(path, dataKey string, params map[string]string) ([]json.RawMessage, error) {
	if params == nil {
		params = make(map[string]string)
	}
	if _, ok := params["limit"]; !ok {
		params["limit"] = "100"
	}
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
			break
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
	return rawToSliceOfMaps(raw)
}

func (c *Client) ListLogDrains() ([]map[string]interface{}, error) {
	raw, err := c.Get("/v1/drains", nil)
	if err != nil || raw == nil {
		return nil, err
	}
	// Response may be array directly or {drains: [...]}
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err == nil {
		if drains, ok := resp["drains"]; ok {
			return toSliceOfMaps(drains), nil
		}
	}
	return rawToSliceOfMaps(raw)
}

func (c *Client) ListIntegrations() ([]map[string]interface{}, error) {
	return c.getPaginatedMaps("/v1/integrations/configurations", "configurations", map[string]string{"view": "account"})
}

func (c *Client) ListEdgeConfigs() ([]map[string]interface{}, error) {
	raw, err := c.Get("/v1/edge-config", nil)
	if err != nil || raw == nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err == nil {
		if items, ok := resp["items"]; ok {
			return toSliceOfMaps(items), nil
		}
	}
	return rawToSliceOfMaps(raw)
}

func (c *Client) ListEdgeConfigTokens(edgeConfigID string) ([]map[string]interface{}, error) {
	raw, err := c.Get(fmt.Sprintf("/v1/edge-config/%s/tokens", edgeConfigID), nil)
	if err != nil || raw == nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err == nil {
		if tokens, ok := resp["tokens"]; ok {
			return toSliceOfMaps(tokens), nil
		}
	}
	return rawToSliceOfMaps(raw)
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
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err == nil {
		if nets, ok := resp["networks"]; ok {
			return toSliceOfMaps(nets), nil
		}
	}
	return rawToSliceOfMaps(raw)
}

func (c *Client) ListSharedEnvVars() ([]map[string]interface{}, error) {
	raw, err := c.Get("/v1/env", nil)
	if err != nil || raw == nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err == nil {
		// API returns "data" key, not "envs"
		if data, ok := resp["data"]; ok {
			return toSliceOfMaps(data), nil
		}
		if envs, ok := resp["envs"]; ok {
			return toSliceOfMaps(envs), nil
		}
	}
	return rawToSliceOfMaps(raw)
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
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err == nil {
		if certs, ok := resp["certs"]; ok {
			return toSliceOfMaps(certs), nil
		}
	}
	return rawToSliceOfMaps(raw)
}

func (c *Client) ListFeatureFlags(projectID string) ([]map[string]interface{}, error) {
	return c.getPaginatedMaps(fmt.Sprintf("/v1/projects/%s/feature-flags/flags", projectID), "data", nil)
}

func (c *Client) ListBulkRedirects(projectID string) ([]map[string]interface{}, error) {
	raw, err := c.Get("/v1/bulk-redirects", map[string]string{"projectId": projectID})
	if err != nil || raw == nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err == nil {
		if redirects, ok := resp["redirects"]; ok {
			return toSliceOfMaps(redirects), nil
		}
	}
	return rawToSliceOfMaps(raw)
}

func (c *Client) ListProjectRoutes(projectID string) ([]map[string]interface{}, error) {
	raw, err := c.Get(fmt.Sprintf("/v1/projects/%s/routes", projectID), nil)
	if err != nil || raw == nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err == nil {
		if routes, ok := resp["routes"]; ok {
			return toSliceOfMaps(routes), nil
		}
	}
	return rawToSliceOfMaps(raw)
}

func (c *Client) ListSandboxes(projectID string) ([]map[string]interface{}, error) {
	raw, err := c.Get("/v1/sandboxes", map[string]string{"project": projectID})
	if err != nil || raw == nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err == nil {
		if items, ok := resp["sandboxes"]; ok {
			return toSliceOfMaps(items), nil
		}
	}
	return rawToSliceOfMaps(raw)
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
		body = body[:50000] + "...[truncated]"
	}
	c.evidenceLog = append(c.evidenceLog, APIEvidence{
		Method: method, Path: path, StatusCode: status, Body: body,
	})
	// Keep last 200 entries
	if len(c.evidenceLog) > 200 {
		c.evidenceLog = c.evidenceLog[len(c.evidenceLog)-200:]
	}
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
	for _, r := range raws {
		var m map[string]interface{}
		if err := json.Unmarshal(r, &m); err == nil {
			result = append(result, m)
		}
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

func rawToSliceOfMaps(raw json.RawMessage) ([]map[string]interface{}, error) {
	var arr []map[string]interface{}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

// ProbeHeaders performs a HEAD request against the given URL and returns
// the response headers as a lowercase key -> value map.
func (c *Client) ProbeHeaders(targetURL string) (map[string]string, error) {
	hc := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest("HEAD", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating probe request: %w", err)
	}
	req.Header.Set("User-Agent", "vercelsior-security-scanner")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("probing %s: %w", targetURL, err)
	}
	resp.Body.Close()

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}
	return headers, nil
}
