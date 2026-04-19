package reporter

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"

	"github.com/Su1ph3r/vercelsior/internal/models"
)

type htmlData struct {
	Result            *models.ScanResult
	CriticalCount     int
	HighCount         int
	MediumCount       int
	LowCount          int
	InfoCount         int
	FailFindings      []models.Finding
	WarnFindings      []models.Finding
	PassFindings      []models.Finding
	Categories        []categoryGroup
	PostureScore      float64
	PostureClass      string
	ScorePercent      int
	ScoreClass        string
	DashOffset        string
}

type categoryGroup struct {
	Name        string
	Findings    []models.Finding
	Pass        int
	Fail        int
	Warn        int
	MaxSeverity int // 0=CRITICAL, 1=HIGH, 2=MEDIUM, 3=LOW, 4=INFO, 5=none
}

func WriteHTML(result *models.ScanResult, path string) error {
	data := buildHTMLData(result)

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityClass": func(s models.Severity) string { return strings.ToLower(string(s)) },
		"statusClass":   func(s models.Status) string { return strings.ToLower(string(s)) },
		"riskRating":    models.RiskRating,
		"fmtScore":      func(f float64) string { return fmt.Sprintf("%.1f", f) },
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func buildHTMLData(result *models.ScanResult) htmlData {
	d := htmlData{Result: result}

	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		count := result.Summary.SeverityCounts[sev]
		switch sev {
		case "CRITICAL":
			d.CriticalCount = count
		case "HIGH":
			d.HighCount = count
		case "MEDIUM":
			d.MediumCount = count
		case "LOW":
			d.LowCount = count
		case "INFO":
			d.InfoCount = count
		}
	}

	cats := make(map[string]*categoryGroup)
	for _, f := range result.Findings {
		switch f.Status {
		case models.Fail:
			d.FailFindings = append(d.FailFindings, f)
		case models.Warn:
			d.WarnFindings = append(d.WarnFindings, f)
		case models.Pass:
			d.PassFindings = append(d.PassFindings, f)
		}

		cg, ok := cats[f.Category]
		if !ok {
			cg = &categoryGroup{Name: f.Category, MaxSeverity: 5}
			cats[f.Category] = cg
		}
		cg.Findings = append(cg.Findings, f)
		switch f.Status {
		case models.Pass:
			cg.Pass++
		case models.Fail:
			cg.Fail++
		case models.Warn:
			cg.Warn++
		}
		// Track highest severity (lowest rank = highest severity)
		if f.Status == models.Fail || f.Status == models.Warn {
			rank := f.Severity.Rank()
			if rank < cg.MaxSeverity {
				cg.MaxSeverity = rank
			}
		}
	}

	for _, cg := range cats {
		d.Categories = append(d.Categories, *cg)
	}
	// Sort categories: highest severity first, then most fails, then most warns, then pass-only
	sort.Slice(d.Categories, func(i, j int) bool {
		ci, cj := d.Categories[i], d.Categories[j]
		// Categories with findings beat pass-only
		iHasIssues := ci.Fail + ci.Warn
		jHasIssues := cj.Fail + cj.Warn
		if (iHasIssues > 0) != (jHasIssues > 0) {
			return iHasIssues > 0
		}
		// Sort by highest severity finding in category
		if ci.MaxSeverity != cj.MaxSeverity {
			return ci.MaxSeverity < cj.MaxSeverity
		}
		// Then by fail count
		if ci.Fail != cj.Fail {
			return ci.Fail > cj.Fail
		}
		// Then by warn count
		if ci.Warn != cj.Warn {
			return ci.Warn > cj.Warn
		}
		return ci.Name < cj.Name
	})

	// Posture score (weighted)
	d.PostureScore = result.Summary.PostureScore
	d.ScorePercent = int(d.PostureScore)
	switch {
	case d.PostureScore >= 80:
		d.PostureClass = "good"
	case d.PostureScore >= 50:
		d.PostureClass = "warning"
	default:
		d.PostureClass = "danger"
	}
	d.ScoreClass = d.PostureClass

	// SVG circle circumference = 2 * pi * 52 = 326.73
	circumference := 326.73
	offset := circumference - (circumference * d.PostureScore / 100.0)
	d.DashOffset = fmt.Sprintf("%.1f", offset)

	return d
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vercelsior Security Report</title>
<style>
  :root {
    --bg: #000; --surface: #0a0a0a; --surface2: #111; --border: #222;
    --text: #e8e8e8; --text-muted: #777; --accent: #fff;
    --critical: #fff; --high: #ccc; --medium: #999; --low: #666; --info: #444;
    --pass-bg: #000; --pass-border: #333; --pass-text: #888;
    --fail-bg: #0a0a0a; --fail-border: #444; --fail-text: #fff;
    --warn-bg: #0a0a0a; --warn-border: #333; --warn-text: #ccc;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'SF Mono', 'Consolas', 'Liberation Mono', monospace; background: var(--bg); color: var(--text); line-height: 1.7; font-size: 14px; }
  .container { max-width: 1100px; margin: 0 auto; padding: 2.5rem; }
  header { border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2.5rem; }
  h1 { font-size: 1.5rem; font-weight: 400; letter-spacing: 0.15em; text-transform: uppercase; }
  h1 span { color: var(--text-muted); }
  .meta { color: var(--text-muted); font-size: 0.875rem; margin-top: 0.5rem; }
  .meta span { margin-right: 1.5rem; }

  .score-ring { display: flex; align-items: center; gap: 3rem; margin: 2.5rem 0; padding: 2rem; border: 1px solid var(--border); }
  .score-circle { position: relative; width: 120px; height: 120px; }
  .score-circle svg { transform: rotate(-90deg); }
  .score-circle circle { fill: none; stroke-width: 6; }
  .score-circle .track { stroke: #111; }
  .score-circle .progress { stroke-linecap: butt; transition: stroke-dashoffset 1s ease; }
  .score-circle .progress.good { stroke: #6a6; }
  .score-circle .progress.warning { stroke: #db0; }
  .score-circle .progress.danger { stroke: #e45; }
  .score-label { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 1.5rem; font-weight: 400; letter-spacing: 0.05em; }
  .score-stats { display: flex; gap: 2.5rem; flex-wrap: wrap; }
  .stat { text-align: left; }
  .stat-value { font-size: 1.5rem; font-weight: 400; }
  .stat-label { font-size: 0.65rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.1em; }
  .stat-value.pass { color: #6a6; }
  .stat-value.fail { color: #e45; }
  .stat-value.warn { color: #db0; }

  .severity-bar { display: flex; gap: 1rem; margin: 1.5rem 0; flex-wrap: wrap; }
  .sev-chip { padding: 0.25rem 0.5rem; font-size: 0.65rem; font-weight: 400; letter-spacing: 0.12em; text-transform: uppercase; border: 1px solid; }
  .sev-chip.critical { color: #e45; border-color: #e45; }
  .sev-chip.high { color: #e83; border-color: #e83; }
  .sev-chip.medium { color: #db0; border-color: #db0; }
  .sev-chip.low { color: #4af; border-color: #4af; }
  .sev-chip.info { color: #444; border-color: #333; }

  h2 { font-size: 1.25rem; font-weight: 600; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  .category-section { margin-bottom: 2rem; }
  .category-header { display: flex; justify-content: space-between; align-items: center; cursor: pointer; padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); margin-bottom: 0.25rem; }
  .category-header:hover { background: var(--surface); }
  .category-name { font-weight: 400; letter-spacing: 0.04em; }
  .category-badges { display: flex; gap: 0.75rem; }
  .badge { padding: 0.125rem 0; font-size: 0.7rem; font-weight: 400; letter-spacing: 0.05em; }
  .badge.pass { color: #555; }
  .badge.fail { color: #e45; }
  .badge.warn { color: #db0; }

  .findings-list { display: none; }
  .findings-list.open { display: block; }
  .finding { margin: 0.25rem 0; border-left: 2px solid; }
  .finding.fail { border-left-color: #e45; }
  .finding.warn { border-left-color: #db0; }
  .finding.pass { border-left-color: #222; }
  .finding-header { cursor: pointer; display: flex; justify-content: space-between; align-items: center; padding: 0.6rem 1rem; }
  .finding-header:hover { background: var(--surface); }
  .finding-meta { display: flex; gap: 0.75rem; align-items: center; }
  .finding-body { display: none; padding: 0.5rem 1rem 1rem; border-bottom: 1px solid var(--border); }
  .finding-body.open { display: block; }
  .finding-title { font-weight: 400; font-size: 0.9rem; }
  .finding-id { color: var(--text-muted); font-size: 0.7rem; }
  .finding-desc { color: var(--text-muted); font-size: 0.85rem; margin-bottom: 0.5rem; }
  .finding-resource { font-size: 0.8rem; color: var(--text-muted); }
  .finding-resource code { border: 1px solid var(--border); padding: 0.1rem 0.3rem; font-size: 0.75rem; }
  .remediation { margin-top: 0.5rem; padding: 0.5rem 0.75rem; border-left: 1px solid #444; font-size: 0.8rem; color: #999; }
  .risk-score { margin-bottom: 0.5rem; font-size: 0.8rem; display: flex; align-items: center; gap: 0.75rem; }
  .risk-badge { padding: 0.15rem 0.4rem; border: 1px solid var(--border); font-weight: 400; font-size: 0.75rem; }
  .rationale { color: var(--text-muted); font-style: italic; font-size: 0.8rem; }

  .poc-section, .verification-section, .remediation-section, .resources-section { margin-top: 0.75rem; }
  .poc-label { font-size: 0.6rem; font-weight: 400; text-transform: uppercase; letter-spacing: 0.15em; color: #555; margin-bottom: 0.375rem; }
  .poc-block { border: 1px solid var(--border); padding: 0.5rem; margin-bottom: 0.5rem; }
  .poc-request, .poc-response { font-size: 0.8rem; margin-bottom: 0.25rem; }
  .poc-tag { font-size: 0.6rem; font-weight: 400; padding: 0.1rem 0.3rem; letter-spacing: 0.08em; border: 1px solid #333; color: #888; }
  .poc-status { font-weight: 400; }
  .poc-body { font-size: 0.75rem; line-height: 1.5; border: 1px solid var(--border); padding: 0.75rem; max-height: 400px; overflow: auto; white-space: pre; color: #888; margin-top: 0.375rem; tab-size: 2; }
  .verification-cmd { font-size: 0.8rem; border: 1px solid var(--border); padding: 0.5rem; white-space: pre-wrap; word-break: break-all; color: #aaa; }
  .remediation-cmd { margin-bottom: 0.5rem; }
  .cmd-type { font-size: 0.6rem; font-weight: 400; padding: 0.1rem 0.3rem; letter-spacing: 0.08em; border: 1px solid #333; color: #888; }
  .cmd-desc { font-size: 0.8rem; color: var(--text-muted); margin-left: 0.5rem; }
  .cmd-code { font-size: 0.8rem; border: 1px solid var(--border); padding: 0.5rem; margin-top: 0.25rem; white-space: pre-wrap; word-break: break-all; color: #aaa; }
  .resource-link { font-size: 0.85rem; margin-bottom: 0.25rem; }
  .resource-link a { color: #ccc; text-decoration: none; border-bottom: 1px solid #333; }
  .resource-link a:hover { color: #fff; border-bottom-color: #fff; }
  .resource-type { color: var(--text-muted); font-size: 0.75rem; }

  .filter-bar { display: flex; gap: 0.5rem; margin: 1rem 0; flex-wrap: wrap; }
  .filter-btn { padding: 0.3rem 0.6rem; border: 1px solid var(--border); background: none; color: #666; cursor: pointer; font-size: 0.75rem; font-family: inherit; letter-spacing: 0.05em; transition: all 0.15s; }
  .filter-btn:hover { color: #fff; border-color: #444; }
  .filter-btn.active { color: #fff; border-color: #fff; }

  footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: #333; font-size: 0.7rem; text-align: center; letter-spacing: 0.1em; }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1><span>vercel</span>sior</h1>
    <div class="meta">
      <span>Scan: {{.Result.ScanID}}</span>
      <span>Account: {{.Result.AccountName}}</span>
      <span>{{.Result.StartedAt.Format "2006-01-02 15:04:05 UTC"}}</span>
    </div>
  </header>

  <div class="score-ring">
    <div class="score-circle">
      <svg viewBox="0 0 120 120" width="120" height="120">
        <circle class="track" cx="60" cy="60" r="52"/>
        <circle class="progress {{.ScoreClass}}" cx="60" cy="60" r="52"
          stroke-dasharray="326.73"
          stroke-dashoffset="{{.DashOffset}}"/>
      </svg>
      <div class="score-label">{{fmtScore .PostureScore}}</div>
    </div>
    <div class="score-stats">
      <div class="stat"><div class="stat-value">{{.Result.Summary.Total}}</div><div class="stat-label">Total</div></div>
      <div class="stat"><div class="stat-value pass">{{.Result.Summary.Passed}}</div><div class="stat-label">Passed</div></div>
      <div class="stat"><div class="stat-value fail">{{.Result.Summary.Failed}}</div><div class="stat-label">Failed</div></div>
      <div class="stat"><div class="stat-value warn">{{.Result.Summary.Warnings}}</div><div class="stat-label">Warnings</div></div>
    </div>
  </div>

  <div class="severity-bar">
    {{if .CriticalCount}}<span class="sev-chip critical">CRITICAL: {{.CriticalCount}}</span>{{end}}
    {{if .HighCount}}<span class="sev-chip high">HIGH: {{.HighCount}}</span>{{end}}
    {{if .MediumCount}}<span class="sev-chip medium">MEDIUM: {{.MediumCount}}</span>{{end}}
    {{if .LowCount}}<span class="sev-chip low">LOW: {{.LowCount}}</span>{{end}}
    {{if .InfoCount}}<span class="sev-chip info">INFO: {{.InfoCount}}</span>{{end}}
  </div>

  <h2>Findings by Category</h2>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterFindings('all')">All</button>
    <button class="filter-btn" onclick="filterFindings('fail')">Failures</button>
    <button class="filter-btn" onclick="filterFindings('warn')">Warnings</button>
    <button class="filter-btn" onclick="filterFindings('pass')">Passed</button>
  </div>

  {{range .Categories}}
  <div class="category-section">
    <div class="category-header" onclick="toggleCategory(this)">
      <span class="category-name">{{.Name}}</span>
      <div class="category-badges">
        {{if .Fail}}<span class="badge fail">{{.Fail}} fail</span>{{end}}
        {{if .Warn}}<span class="badge warn">{{.Warn}} warn</span>{{end}}
        {{if .Pass}}<span class="badge pass">{{.Pass}} pass</span>{{end}}
      </div>
    </div>
    <div class="findings-list">
      {{range .Findings}}
      <div class="finding {{statusClass .Status}}" data-status="{{statusClass .Status}}" data-severity="{{severityClass .Severity}}">
        <div class="finding-header" onclick="toggleFinding(this)">
          <span class="finding-title">
            <span class="sev-chip {{severityClass .Severity}}">{{.Severity}}</span>
            {{.Title}}
          </span>
          <span class="finding-meta">
            {{if .RiskScore}}<span class="risk-badge {{severityClass .Severity}}">{{fmtScore .RiskScore}}</span>{{end}}
            <span class="finding-id">{{.CheckID}}</span>
          </span>
        </div>
        <div class="finding-body">
          {{if .Rationale}}<div class="rationale">{{.Rationale}}</div>{{end}}
          <div class="finding-desc">{{.Description}}</div>
          <div class="finding-resource">{{.ResourceType}}: <code>{{.ResourceName}}</code> ({{.ResourceID}})</div>

          {{if .PocEvidence}}
          <div class="poc-section">
            <div class="poc-label">Proof of Concept Evidence</div>
            {{range .PocEvidence}}
            <div class="poc-block">
              <div class="poc-request"><span class="poc-tag">REQUEST</span> <code>{{.Request.Method}} {{.Request.URL}}</code></div>
              <div class="poc-response"><span class="poc-tag">RESPONSE</span> <span class="poc-status">{{.Response.StatusCode}}</span></div>
              <pre class="poc-body">{{.Response.Body}}</pre>
            </div>
            {{end}}
          </div>
          {{end}}

          {{if .PocVerification}}
          <div class="verification-section">
            <div class="poc-label">Verification Command</div>
            <pre class="verification-cmd">{{.PocVerification}}</pre>
          </div>
          {{end}}

          {{if .Remediation}}<div class="remediation">{{.Remediation}}</div>{{end}}

          {{if .RemediationCommands}}
          <div class="remediation-section">
            <div class="poc-label">Remediation Commands</div>
            {{range .RemediationCommands}}
            <div class="remediation-cmd">
              <span class="cmd-type">{{.Type}}</span>
              <span class="cmd-desc">{{.Description}}</span>
              <pre class="cmd-code">{{.Command}}</pre>
            </div>
            {{end}}
          </div>
          {{end}}

          {{if .RemediationResources}}
          <div class="resources-section">
            <div class="poc-label">References</div>
            {{range .RemediationResources}}
            <div class="resource-link"><a href="{{.URL}}" target="_blank">{{.Title}}</a> <span class="resource-type">({{.Type}})</span></div>
            {{end}}
          </div>
          {{end}}
        </div>
      </div>
      {{end}}
    </div>
  </div>
  {{end}}

  <footer>
    Generated by vercelsior &mdash; Vercel Security Auditing Tool
  </footer>
</div>

<script>
function toggleCategory(el) {
  const list = el.nextElementSibling;
  list.classList.toggle('open');
}
function toggleFinding(el) {
  const body = el.nextElementSibling;
  body.classList.toggle('open');
}
function filterFindings(status) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding').forEach(f => {
    if (status === 'all') { f.style.display = ''; return; }
    f.style.display = f.dataset.status === status ? '' : 'none';
  });
}
// Auto-open categories with failures
document.querySelectorAll('.category-section').forEach(s => {
  if (s.querySelector('.badge.fail')) {
    s.querySelector('.findings-list').classList.add('open');
  }
});
// Auto-open FAIL findings
document.querySelectorAll('.finding.fail .finding-body').forEach(b => b.classList.add('open'));
// Pretty-print JSON in PoC evidence bodies using safe DOM methods
document.querySelectorAll('.poc-body').forEach(function(el) {
  try {
    var raw = el.textContent.replace(/\.\.\.\[truncated\]$/, '');
    var obj = JSON.parse(raw);
    var pretty = JSON.stringify(obj, null, 2);
    el.textContent = pretty;
  } catch(e) { /* not valid JSON, leave as-is */ }
});
</script>
</body>
</html>`
