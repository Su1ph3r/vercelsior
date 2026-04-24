package scanner

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Su1ph3r/vercelsior/internal/checks"
	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/config"
	"github.com/Su1ph3r/vercelsior/internal/models"
)

type ProgressFunc func(checkName string, status string)

type Scanner struct {
	client     *client.Client
	checks     []checks.Check
	onProgress ProgressFunc
	cfg        *config.Config
}

func New(c *client.Client, cfg *config.Config, onProgress ProgressFunc) *Scanner {
	if cfg == nil {
		cfg = config.New()
	}
	return &Scanner{
		client: c,
		cfg:    cfg,
		checks: []checks.Check{
			&checks.IAMChecks{},
			&checks.FirewallChecks{},
			&checks.SecretsChecks{},
			&checks.DeploymentChecks{},
			&checks.DomainChecks{},
			&checks.LoggingChecks{},
			&checks.IntegrationChecks{},
			&checks.InfrastructureChecks{},
			&checks.PreviewChecks{},
			&checks.NextJSChecks{},
			&checks.TakeoverChecks{},
			&checks.GitChecks{},
			&checks.FeatureFlagChecks{},
			&checks.TLSChecks{},
			&checks.RouteChecks{},
			&checks.HeaderChecks{},
			&checks.RollingReleaseChecks{},
			&checks.SandboxChecks{},
			&checks.VerificationChecks{},
			&checks.StorageChecks{},
		},
		onProgress: onProgress,
	}
}

func (s *Scanner) Run(scanID string) (*models.ScanResult, error) {
	result := &models.ScanResult{
		ScanID:    scanID,
		StartedAt: time.Now().UTC(),
		Findings:  []models.Finding{},
	}

	// Identify the account
	user, err := s.client.GetUser()
	if err == nil && user != nil {
		if uid, ok := user["id"].(string); ok {
			result.AccountID = uid
		}
		if uname, ok := user["username"].(string); ok {
			result.AccountName = uname
		}
		if name, ok := user["name"].(string); ok && result.AccountName == "" {
			result.AccountName = name
		}
	}

	// Run all check modules concurrently
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, check := range s.checks {
		wg.Add(1)
		go func(ch checks.Check) {
			defer wg.Done()
			if s.onProgress != nil {
				s.onProgress(ch.Name(), "running")
			}

			var findings []models.Finding
			func() {
				defer func() {
					if r := recover(); r != nil {
						findings = []models.Finding{{
							CheckID:      "panic",
							Title:        fmt.Sprintf("Check Module Panic: %s", ch.Name()),
							Category:     ch.Category(),
							Severity:     models.Info,
							Status:       models.Error,
							Description:  fmt.Sprintf("Check module '%s' panicked: %v", ch.Name(), r),
							ResourceType: "check_module",
							ResourceID:   ch.Name(),
							ResourceName: ch.Name(),
						}}
					}
				}()
				findings = ch.Run(s.client)
			}()

			mu.Lock()
			result.Findings = append(result.Findings, findings...)
			mu.Unlock()

			if s.onProgress != nil {
				s.onProgress(ch.Name(), fmt.Sprintf("done (%d findings)", len(findings)))
			}
		}(check)
	}

	wg.Wait()

	// Enrich findings with PoC evidence and remediation KB data
	s.enrichFindings(result.Findings)

	result.Findings = applyFilters(s.cfg, result.Findings)
	result.Findings = dedupeFindings(result.Findings)

	// Sort findings: status (FAIL > WARN > ERROR > PASS), then severity, then risk score, then category
	statusRank := map[models.Status]int{
		models.Fail: 0, models.Warn: 1, models.Error: 2, models.Pass: 3,
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		fi, fj := result.Findings[i], result.Findings[j]
		si, sj := statusRank[fi.Status], statusRank[fj.Status]
		if si != sj {
			return si < sj
		}
		if fi.Severity.Rank() != fj.Severity.Rank() {
			return fi.Severity.Rank() < fj.Severity.Rank()
		}
		if fi.RiskScore != fj.RiskScore {
			return fi.RiskScore > fj.RiskScore // higher score first
		}
		if fi.Category != fj.Category {
			return fi.Category < fj.Category
		}
		return fi.CheckID < fj.CheckID
	})

	result.Compute()
	return result, nil
}

// applyFilters is the config-driven post-processing that runs on the raw
// findings collected from each check module. It enforces three rules in a
// specific order:
//
//  1. Category allowlist / skip list
//  2. CheckID allowlist / skip list
//  3. Suppression rewrite (Status becomes Pass with a [SUPPRESSED] prefix)
//  4. Minimum severity cut — applied AFTER suppression so a suppressed check
//     below the threshold stays visible as Pass instead of silently
//     disappearing.
//
// The ordering in step 3-4 is load-bearing (regression for F-L2). See
// scanner_test.go TestApplyFilters_SuppressionBeforeMinSeverity.
func applyFilters(cfg *config.Config, findings []models.Finding) []models.Finding {
	filtered := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		if !cfg.IsCategoryAllowed(f.Category) {
			continue
		}
		if !cfg.IsCheckAllowed(f.CheckID) {
			continue
		}
		if cfg.IsSuppressed(f.CheckID) {
			f.Status = models.Pass
			f.Description = "[SUPPRESSED] " + f.Description
		}
		if !cfg.MeetsMinSeverity(string(f.Severity)) && f.Status != models.Pass {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// dedupeFindings removes duplicates that share CheckID + ResourceID.
// Later duplicates (same key) are dropped; the first occurrence wins.
func dedupeFindings(findings []models.Finding) []models.Finding {
	seen := make(map[string]bool, len(findings))
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.CheckID + "|" + f.ResourceID
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func (s *Scanner) CheckCount() int {
	return len(s.checks)
}

func (s *Scanner) CheckNames() []string {
	names := make([]string, len(s.checks))
	for i, ch := range s.checks {
		names[i] = ch.Name()
	}
	return names
}

// enrichFindings adds remediation KB data to findings.
func (s *Scanner) enrichFindings(findings []models.Finding) {
	for i := range findings {
		f := &findings[i]
		if f.Status != models.Fail && f.Status != models.Warn {
			continue
		}

		// Enrich with remediation KB
		checks.EnrichFinding(f)
	}
}
