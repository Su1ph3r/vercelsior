package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Su1ph3r/vercelsior/internal/client"
	"github.com/Su1ph3r/vercelsior/internal/prober"
	"github.com/Su1ph3r/vercelsior/internal/reporter"
)

// runProbe black-box tests a deployed Vercel URL from the outside — no API
// token, the attacker's perspective (DAST). It returns the process exit code:
//
//	0  no failing findings
//	2  one or more FAIL findings
//
// All network egress goes through the SSRF-guarded, redirect-pinned probe
// client in internal/client, so probe mode cannot be turned into an SSRF
// primitive.
func runProbe(argv []string) int {
	opts := parseProbeArgs(argv)
	if opts.noColor {
		applyNoColor()
	}
	if opts.help {
		printProbeUsage()
		return 0
	}
	if opts.url == "" {
		printProbeUsage()
		fatal("probe requires a target URL, e.g. vercelsior probe https://my-app.vercel.app")
	}

	target, err := normalizeProbeURL(opts.url)
	if err != nil {
		fatal("Invalid target URL %q: %v", opts.url, err)
	}

	reporter.SetSARIFVersion(version)
	printBanner()
	fmt.Printf("%s[*]%s Probing %s%s%s (black-box, no token)\n", colorCyan, colorReset, colorBold, target.String(), colorReset)

	// No token needed for external probing; the client is used only for its
	// hardened probe transport.
	c := client.New("", "", "")
	scanID := fmt.Sprintf("vercelsior-probe-%d", time.Now().UnixNano())

	result := prober.Run(target, scanID, &probeFetcher{c: c})

	fmt.Println()
	printSummary(result)

	outDir := opts.outputDir
	if outDir == "" {
		outDir = "."
	}
	writeReports(result, outDir, opts.formats, scanID)

	fmt.Printf("\n%s[+]%s Probe complete.\n", colorGreen, colorReset)

	if hasFailAtOrAbove(result, nil) {
		return 2
	}
	return 0
}

// probeFetcher adapts the SSRF-guarded client.Probe to the prober.Fetcher
// interface, translating the client's ProbeResponse into prober's Response.
type probeFetcher struct {
	c *client.Client
}

func (p *probeFetcher) Fetch(method, absURL string, headers map[string]string) (*prober.Response, error) {
	resp, err := p.c.Probe(method, absURL, headers)
	if err != nil {
		return nil, err
	}
	return &prober.Response{
		Status:  resp.StatusCode,
		Headers: resp.Headers,
		Body:    resp.Body,
		URL:     resp.FinalURL,
	}, nil
}

// normalizeProbeURL parses a user-supplied target, defaulting to https:// when
// no scheme is given (so `vercelsior probe my-app.vercel.app` works), and
// validates the scheme and host.
func normalizeProbeURL(raw string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("missing host")
	}
	return u, nil
}

type probeOpts struct {
	url       string
	formats   []string
	outputDir string
	noColor   bool
	help      bool
}

func parseProbeArgs(argv []string) probeOpts {
	o := probeOpts{}
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
			// First non-flag argument is the target URL.
			if len(argv[i]) > 0 && argv[i][0] != '-' {
				o.url = argv[i]
			}
		}
	}
	return o
}

func printProbeUsage() {
	fmt.Printf(`%svercelsior probe%s - Black-box test a deployed Vercel URL (no token, DAST)

%sUSAGE:%s
  vercelsior probe <URL> [OPTIONS]

%sARGUMENTS:%s
  URL                     Target URL (e.g. https://my-app.vercel.app)

%sOPTIONS:%s
  -o, --output DIR        Output directory for reports (default: current dir)
  -f, --format FORMATS    Comma-separated output formats: html,json,md,sarif
      --no-color          Disable colored output
  -h, --help              Show this help message

%sTESTS:%s
  CVE-2025-29927 middleware auth bypass, exposed source maps, security headers
  (CSP/HSTS/X-Frame-Options/etc.), and technology disclosure. All egress uses
  the SSRF-guarded probe client.

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
