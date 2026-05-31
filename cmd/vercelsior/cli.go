package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Su1ph3r/vercelsior/internal/models"
	"github.com/Su1ph3r/vercelsior/internal/reporter"
)

// splitCSV splits a comma-separated flag value into its parts, returning nil
// for an empty string (so an unset --format yields no formats rather than one
// empty entry).
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// ANSI color codes shared across all subcommands. They are package-level so a
// single --no-color flag (handled per subcommand via applyNoColor) disables
// coloring everywhere.
var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// applyNoColor blanks every color code so output is plain text. Called by each
// subcommand when --no-color is set (or stdout is not a TTY in the future).
func applyNoColor() {
	colorReset = ""
	colorRed = ""
	colorGreen = ""
	colorYellow = ""
	colorBlue = ""
	colorPurple = ""
	colorCyan = ""
	colorBold = ""
	colorDim = ""
}

// printBanner renders the ASCII logo. Shared so every mode (scan/project/probe)
// opens with the same identity.
func printBanner() {
	fmt.Printf(`
%s                        _     _
 __   _____ _ __ ___ ___| |___(_) ___  _ __
 \ \ / / _ \ '__/ __/ _ \ / __| |/ _ \| '__|
  \ V /  __/ | | (_|  __/ \__ \ | (_) | |
   \_/ \___|_|  \___\___|_|___/_|\___/|_|
                                      v%s%s

%sVercel Security Auditing Tool%s
`, colorPurple, version, colorReset, colorDim, colorReset)
	fmt.Println()
}

// fatal prints an error to stderr and exits with code 1. Used for terminal
// startup failures (bad flags, no token, unreachable API) where continuing is
// impossible.
func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, colorRed+"[-] "+colorReset+format+"\n", args...)
	os.Exit(1)
}

// writeReports renders the scan/probe result into the requested formats under
// outDir (created if needed). Shared by the scan and probe subcommands so both
// emit identical report files. An empty formats list defaults to html+json+md;
// outDir defaults to the current directory.
func writeReports(result *models.ScanResult, outDir string, formats []string, scanID string) {
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fatal("Failed to create output directory %s: %v", outDir, err)
	}
	if len(formats) == 0 {
		formats = []string{"html", "json", "md"}
	}

	fmt.Printf("\n%s[*]%s Writing reports...\n", colorCyan, colorReset)
	for _, format := range formats {
		var path string
		var writeErr error
		switch format {
		case "json":
			path = fmt.Sprintf("%s/%s.json", outDir, scanID)
			writeErr = reporter.WriteJSON(result, path)
		case "html":
			path = fmt.Sprintf("%s/%s.html", outDir, scanID)
			writeErr = reporter.WriteHTML(result, path)
		case "md", "markdown":
			path = fmt.Sprintf("%s/%s.md", outDir, scanID)
			writeErr = reporter.WriteMarkdown(result, path)
		case "sarif":
			path = fmt.Sprintf("%s/%s.sarif", outDir, scanID)
			writeErr = reporter.WriteSARIF(result, path)
		default:
			fmt.Printf("  %s[!]%s Unknown format: %s\n", colorYellow, colorReset, format)
			continue
		}
		if writeErr != nil {
			fmt.Printf("  %s[-]%s Failed to write %s: %v\n", colorRed, colorReset, format, writeErr)
		} else {
			fmt.Printf("  %s[+]%s %s\n", colorGreen, colorReset, path)
		}
	}
}

// hasFailAtOrAbove reports whether any FAIL finding meets the minimum severity
// (empty minSeverity means any FAIL counts). Drives the exit-2 convention
// shared by scan and probe.
func hasFailAtOrAbove(result *models.ScanResult, meets func(string) bool) bool {
	for _, f := range result.Findings {
		if f.Status == models.Fail && (meets == nil || meets(string(f.Severity))) {
			return true
		}
	}
	return false
}
