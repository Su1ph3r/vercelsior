package main

import (
	"fmt"
	"os"
	"time"

	"github.com/Su1ph3r/vercelsior/internal/project"
	"github.com/Su1ph3r/vercelsior/internal/reporter"
)

// runProject performs static analysis of a local Vercel project — no API
// token, suitable for pre-deploy / shift-left scanning in CI. It returns the
// process exit code:
//
//	0  no failing findings
//	2  one or more FAIL findings
//
// It inspects vercel.json, next.config.*, package.json, and .env* files via an
// fs.FS rooted at the target directory.
func runProject(argv []string) int {
	opts := parseProjectArgs(argv)
	if opts.noColor {
		applyNoColor()
	}
	if opts.help {
		printProjectUsage()
		return 0
	}

	root := opts.path
	if root == "" {
		root = "."
	}
	info, err := os.Stat(root)
	if err != nil {
		fatal("Cannot access project path %q: %v", root, err)
	}
	if !info.IsDir() {
		fatal("Project path %q is not a directory", root)
	}

	reporter.SetSARIFVersion(version)
	printBanner()
	fmt.Printf("%s[*]%s Scanning project at %s%s%s (local, no token)\n", colorCyan, colorReset, colorBold, root, colorReset)

	scanID := fmt.Sprintf("vercelsior-project-%d", time.Now().UnixNano())
	result := project.Run(os.DirFS(root), root, scanID)

	fmt.Println()
	printSummary(result)

	outDir := opts.outputDir
	if outDir == "" {
		outDir = "."
	}
	writeReports(result, outDir, opts.formats, scanID)

	fmt.Printf("\n%s[+]%s Project scan complete.\n", colorGreen, colorReset)

	if hasFailAtOrAbove(result, nil) {
		return 2
	}
	return 0
}

type projectOpts struct {
	path      string
	formats   []string
	outputDir string
	noColor   bool
	help      bool
}

func parseProjectArgs(argv []string) projectOpts {
	o := projectOpts{path: "."}
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "--output", "-o":
			if i+1 < len(argv) {
				i++
				o.outputDir = argv[i]
			}
		case "--format", "-f":
			if i+1 < len(argv) {
				i++
				o.formats = splitCSV(argv[i])
			}
		case "--no-color":
			o.noColor = true
		case "--help", "-h":
			o.help = true
		default:
			// First non-flag argument is the project path.
			if len(argv[i]) > 0 && argv[i][0] != '-' {
				o.path = argv[i]
			}
		}
	}
	return o
}

func printProjectUsage() {
	fmt.Printf(`%svercelsior project%s - Scan a local Vercel project (no token, pre-deploy)

%sUSAGE:%s
  vercelsior project [PATH] [OPTIONS]

%sARGUMENTS:%s
  PATH                    Path to the project directory (default: current dir)

%sOPTIONS:%s
  -o, --output DIR        Output directory for reports (default: current dir)
  -f, --format FORMATS    Comma-separated output formats: html,json,md,sarif
      --no-color          Disable colored output
  -h, --help              Show this help message

%sSCANS:%s
  package.json (Next.js CVE matrix), .env* (committed/client-exposed secrets,
  .gitignore coverage), next.config.* (source maps, ignored build/lint errors,
  X-Powered-By), and vercel.json (external redirects/rewrites, missing
  security headers).

%sEXIT CODES:%s
  0  No failing findings
  2  One or more failing findings
`, colorBold, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
	)
}
