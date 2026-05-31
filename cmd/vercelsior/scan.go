package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/config"
	"github.com/Su1ph3r/vercelsior/internal/models"
	"github.com/Su1ph3r/vercelsior/internal/reporter"
	"github.com/Su1ph3r/vercelsior/internal/scanner"
)

// runScan executes the account/team CSPM audit against the Vercel API. It
// returns the process exit code:
//
//	0  all checks passed (or no failures at/above --min-severity)
//	2  one or more findings at/above the severity threshold
//
// Terminal startup failures (bad flags, no token, unreachable API) call
// fatal(), which exits 1 directly.
func runScan(argv []string) int {
	args := parseScanArgs(argv)

	if args.noColor {
		applyNoColor()
	}

	if args.help {
		printScanUsage()
		return 0
	}
	if args.version {
		fmt.Printf("vercelsior v%s\n", version)
		return 0
	}

	// Stamp the build version into SARIF output so reports are attributable
	// to a specific Vercelsior build.
	reporter.SetSARIFVersion(version)

	token := args.token
	if token == "" {
		token = os.Getenv("VERCEL_TOKEN")
	}
	if token == "" {
		fatal("No Vercel API token provided. Use --token or set VERCEL_TOKEN environment variable.")
	}

	cfg, cfgErr := config.Load(args.configFile)
	if cfgErr != nil {
		fatal("Failed to load config: %v", cfgErr)
	}
	// Merge CLI flags
	var checksList, skipChecksList, categoriesList []string
	if args.checks != "" {
		checksList = strings.Split(args.checks, ",")
	}
	if args.skipChecks != "" {
		skipChecksList = strings.Split(args.skipChecks, ",")
	}
	if args.categories != "" {
		categoriesList = strings.Split(args.categories, ",")
	}
	cfg.Merge(args.minSeverity, checksList, skipChecksList, categoriesList)

	if cfg.MinSeverity != "" {
		validSeverities := map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFO": true}
		if !validSeverities[cfg.MinSeverity] {
			fatal("Invalid --min-severity value: %s. Valid values: CRITICAL, HIGH, MEDIUM, LOW, INFO", cfg.MinSeverity)
		}
	}

	printBanner()

	var c *client.Client
	if args.replay != "" {
		c = client.NewRecordingClient(token, args.teamID, args.teamSlug, client.ModeReplay, args.replay)
		fmt.Printf("%s[*]%s Replay mode: loading responses from %s\n", colorCyan, colorReset, args.replay)
	} else if args.record != "" {
		c = client.NewRecordingClient(token, args.teamID, args.teamSlug, client.ModeRecord, args.record)
		fmt.Printf("%s[*]%s Record mode: saving responses to %s\n", colorCyan, colorReset, args.record)
	} else {
		c = client.New(token, args.teamID, args.teamSlug)
	}
	c.LiveProbe = args.live

	// Verify connectivity
	fmt.Printf("%s[*]%s Verifying API access...\n", colorCyan, colorReset)
	user, err := c.GetUser()
	if err != nil {
		fatal("Failed to connect to Vercel API: %v", err)
	}
	if user == nil {
		fatal("Invalid API token or insufficient permissions.")
	}
	username := ""
	if u, ok := user["username"].(string); ok {
		username = u
	}
	fmt.Printf("%s[+]%s Authenticated as: %s%s%s\n\n", colorGreen, colorReset, colorBold, username, colorReset)

	// Nanosecond precision prevents collisions when two scans start in the
	// same second (CI parallelism, rapid re-runs), which would otherwise
	// cause the second scan's reports to silently overwrite the first's.
	scanID := fmt.Sprintf("vercelsior-%d", time.Now().UnixNano())

	s := scanner.New(c, cfg, func(checkName, status string) {
		icon := colorCyan + "[*]" + colorReset
		if strings.HasPrefix(status, "done") {
			icon = colorGreen + "[+]" + colorReset
		}
		fmt.Printf("  %s %-20s %s\n", icon, checkName, status)
	})

	fmt.Printf("%s[*]%s Running %d check modules...\n", colorCyan, colorReset, s.CheckCount())
	result, err := s.Run(scanID)
	if err != nil {
		fatal("Scan failed: %v", err)
	}

	// Report permission issues
	denied := c.PermissionSummary()
	if len(denied) > 0 {
		fmt.Printf("\n%s[!]%s %d API endpoint(s) returned 403 (insufficient permissions):\n", colorYellow, colorReset, len(denied))
		for _, p := range denied {
			fmt.Printf("    %s%s%s\n", colorDim, p, colorReset)
		}
		fmt.Printf("  Some checks may have been skipped. Ensure your token has the required scopes.\n")
	}

	fmt.Println()
	printSummary(result)

	// Write reports
	outDir := args.outputDir
	if outDir == "" {
		outDir = "."
	}
	writeReports(result, outDir, args.formats, scanID)

	// Diff comparison
	if args.diff != "" {
		fmt.Printf("\n%s[*]%s Comparing with previous scan: %s\n", colorCyan, colorReset, args.diff)
		diff, diffErr := reporter.CompareScanResults(result, args.diff)
		if diffErr != nil {
			fmt.Printf("  %s[-]%s Diff failed: %v\n", colorRed, colorReset, diffErr)
		} else {
			diffMDPath := fmt.Sprintf("%s/%s-diff.md", outDir, scanID)
			diffJSONPath := fmt.Sprintf("%s/%s-diff.json", outDir, scanID)
			if err := reporter.WriteDiffMarkdown(diff, diffMDPath); err != nil {
				fmt.Printf("  %s[-]%s Failed to write diff markdown: %v\n", colorRed, colorReset, err)
			}
			if err := reporter.WriteDiffJSON(diff, diffJSONPath); err != nil {
				fmt.Printf("  %s[-]%s Failed to write diff JSON: %v\n", colorRed, colorReset, err)
			}

			// Print diff summary to terminal
			changeIcon := "+"
			if diff.PostureChange < 0 {
				changeIcon = ""
			}
			fmt.Printf("  Posture change: %s%s%s%.1f%s points\n", colorBold, scoreColorForChange(diff.PostureChange), changeIcon, diff.PostureChange, colorReset)
			if diff.TotalNew > 0 {
				fmt.Printf("  %s%d new finding(s)%s\n", colorRed, diff.TotalNew, colorReset)
			}
			if diff.TotalResolved > 0 {
				fmt.Printf("  %s%d resolved finding(s)%s\n", colorGreen, diff.TotalResolved, colorReset)
			}
			if diff.TotalNew == 0 && diff.TotalResolved == 0 {
				fmt.Printf("  No changes detected.\n")
			}
			fmt.Printf("  %s[+]%s %s\n", colorGreen, colorReset, diffMDPath)
		}
	}

	fmt.Printf("\n%s[+]%s Scan complete.\n", colorGreen, colorReset)

	// Exit code based on findings — if min-severity is set, only exit 2 for
	// failures at or above that severity threshold.
	var meets func(string) bool
	if cfg.MinSeverity != "" {
		meets = cfg.MeetsMinSeverity
	}
	if hasFailAtOrAbove(result, meets) {
		return 2
	}
	return 0
}

func printSummary(result *models.ScanResult) {
	fmt.Printf("%s%s=== Scan Summary ===%s\n\n", colorBold, colorPurple, colorReset)

	total := result.Summary.Total
	passed := result.Summary.Passed
	failed := result.Summary.Failed
	warnings := result.Summary.Warnings
	posture := result.Summary.PostureScore

	scoreColor := colorGreen
	if posture < 80 {
		scoreColor = colorYellow
	}
	if posture < 50 {
		scoreColor = colorRed
	}

	fmt.Printf("  Posture Score:  %s%s%.1f / 100%s\n", colorBold, scoreColor, posture, colorReset)
	fmt.Printf("  %s(risk-weighted — failures deduct proportional to severity)%s\n\n", colorDim, colorReset)
	fmt.Printf("  Total Checks:  %d\n", total)
	fmt.Printf("  %sPassed:%s       %d\n", colorGreen, colorReset, passed)
	fmt.Printf("  %sFailed:%s       %d\n", colorRed, colorReset, failed)
	fmt.Printf("  %sWarnings:%s     %d\n", colorYellow, colorReset, warnings)
	// Surface checks that could not run (permission denied, unparseable input,
	// all probes failed, module panic). Without this the terminal hides a
	// coverage loss — which also inflates the posture score.
	if errs := result.Summary.Errors; errs > 0 {
		fmt.Printf("  %sErrors:%s       %d  %s(checks that could not run — see report)%s\n",
			colorYellow, colorReset, errs, colorDim, colorReset)
	}

	if len(result.Summary.SeverityCounts) > 0 {
		fmt.Printf("\n  Severity Breakdown:\n")
		sevOrder := []struct {
			name  string
			color string
		}{
			{"CRITICAL", colorRed},
			{"HIGH", colorRed},
			{"MEDIUM", colorYellow},
			{"LOW", colorBlue},
			{"INFO", colorDim},
		}
		for _, s := range sevOrder {
			if count, ok := result.Summary.SeverityCounts[s.name]; ok && count > 0 {
				fmt.Printf("    %s%-10s%s %d\n", s.color, s.name, colorReset, count)
			}
		}
	}
	fmt.Println()
}

func scoreColorForChange(change float64) string {
	if change > 0 {
		return colorGreen
	}
	if change < 0 {
		return colorRed
	}
	return colorYellow
}

type args struct {
	token       string
	teamID      string
	teamSlug    string
	outputDir   string
	formats     []string
	live        bool
	help        bool
	version     bool
	minSeverity string
	checks      string
	skipChecks  string
	categories  string
	noColor     bool
	configFile  string
	diff        string
	record      string // directory to record API responses to
	replay      string // directory to replay API responses from
}

// parseScanArgs parses the scan subcommand's flags from argv (which excludes
// the program name and the optional 'scan' token).
func parseScanArgs(argv []string) args {
	a := args{}
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "--token", "-t":
			if i+1 < len(argv) {
				i++
				a.token = argv[i]
			}
		case "--team-id":
			if i+1 < len(argv) {
				i++
				a.teamID = argv[i]
			}
		case "--team-slug", "--team":
			if i+1 < len(argv) {
				i++
				a.teamSlug = argv[i]
			}
		case "--output", "-o":
			if i+1 < len(argv) {
				i++
				a.outputDir = argv[i]
			}
		case "--format", "-f":
			if i+1 < len(argv) {
				i++
				a.formats = strings.Split(argv[i], ",")
			}
		case "--live":
			a.live = true
		case "--help", "-h":
			a.help = true
		case "--version", "-v":
			a.version = true
		case "--min-severity":
			if i+1 < len(argv) {
				i++
				a.minSeverity = argv[i]
			}
		case "--checks":
			if i+1 < len(argv) {
				i++
				a.checks = argv[i]
			}
		case "--skip-checks":
			if i+1 < len(argv) {
				i++
				a.skipChecks = argv[i]
			}
		case "--category":
			if i+1 < len(argv) {
				i++
				a.categories = argv[i]
			}
		case "--no-color":
			a.noColor = true
		case "--config", "-c":
			if i+1 < len(argv) {
				i++
				a.configFile = argv[i]
			}
		case "--diff":
			if i+1 < len(argv) {
				i++
				a.diff = argv[i]
			}
		case "--record":
			if i+1 < len(argv) {
				i++
				a.record = argv[i]
			}
		case "--replay":
			if i+1 < len(argv) {
				i++
				a.replay = argv[i]
			}
		}
	}
	return a
}

func printScanUsage() {
	fmt.Printf(`%svercelsior scan%s - Audit a Vercel account/team via the API (CSPM)

%sUSAGE:%s
  vercelsior scan [OPTIONS]
  vercelsior [OPTIONS]            (alias — 'scan' may be omitted)

%sOPTIONS:%s
  -t, --token TOKEN       Vercel API token (or set VERCEL_TOKEN env var)
      --team-id ID        Scope scan to a specific team by ID
      --team, --team-slug Scope scan to a specific team by slug
  -o, --output DIR        Output directory for reports (default: current dir)
  -f, --format FORMATS    Comma-separated output formats: html,json,md,sarif (default: html,json,md)
      --live              Enable live HTTP header probing against production domains
      --min-severity SEV  Minimum severity to report: CRITICAL,HIGH,MEDIUM,LOW,INFO
      --checks IDS        Comma-separated check IDs to include (allowlist)
      --skip-checks IDS   Comma-separated check IDs to skip
      --category CATS     Comma-separated categories to include (allowlist)
      --no-color          Disable colored output
  -c, --config FILE       Path to config file (default: .vercelsior)
      --diff FILE         Path to previous JSON report for diff comparison
      --record DIR        Record API responses to directory (for test fixtures)
      --replay DIR        Replay API responses from directory (offline testing)
  -h, --help              Show this help message

%sEXAMPLES:%s
  vercelsior scan --token vrcl_xxxxx
  vercelsior scan --token vrcl_xxxxx --team my-team -o ./reports
  vercelsior scan --token vrcl_xxxxx -f json,html
  vercelsior scan --token vrcl_xxxxx -f sarif -o ./results   # GitHub code scanning
  vercelsior scan --token vrcl_xxxxx --min-severity HIGH --no-color
  vercelsior scan --token vrcl_xxxxx --skip-checks IAM-001,IAM-002
  VERCEL_TOKEN=vrcl_xxxxx vercelsior --team-id team_xxxxx

%sEXIT CODES:%s
  0  All checks passed (or no failures at/above min-severity)
  2  One or more checks failed at/above the minimum severity threshold

`, colorBold, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
	)
}
