package main

import (
	"fmt"
	"os"
)

// version is the build version. Release builds override it via
// -ldflags "-X main.version={{.Version}}" (see .goreleaser.yml), so
// `vercelsior version` reports the real tag; this literal is the fallback for
// `go build`/`go install` without ldflags.
var version = "1.0.0"

// Vercelsior tests Vercel security from three angles, each its own subcommand:
//
//	scan     account/team CSPM via the Vercel API (requires a token)
//	project  static analysis of a local Vercel project (no token, pre-deploy)
//	probe    black-box testing of a deployed URL (no token, external)
//
// For backward compatibility, invoking vercelsior with no subcommand (or with a
// leading flag, e.g. `vercelsior --token X`) runs `scan` — the original and
// only behavior prior to the multi-mode split.
func main() {
	os.Exit(run(os.Args[1:]))
}

// run dispatches argv to a subcommand and returns the process exit code. It is
// separated from main() (which only calls os.Exit) so the router is testable.
func run(argv []string) int {
	// Honor --no-color uniformly, including on the help/version/root paths that
	// don't run a subcommand's own flag parser. Idempotent: subcommands may
	// call applyNoColor again with no effect.
	for _, a := range argv {
		if a == "--no-color" {
			applyNoColor()
			break
		}
	}

	name, rest := route(argv)
	switch name {
	case "version":
		fmt.Printf("vercelsior v%s\n", version)
		return 0
	case "help":
		return runHelp(rest)
	case "project":
		return runProject(rest)
	case "probe":
		return runProbe(rest)
	default: // "scan"
		return runScan(rest)
	}
}

// route maps argv to a subcommand name and the args remaining for that command.
//
// Any legacy / flag-first invocation (no recognized subcommand token in the
// first position) maps to "scan" with ALL args preserved, so existing
// `vercelsior --token ...` / `VERCEL_TOKEN=... vercelsior` usage, scripts, and
// CI pipelines keep working unchanged. A recognized subcommand consumes the
// first token and passes the rest through.
func route(argv []string) (name string, rest []string) {
	if len(argv) == 0 {
		return "scan", argv
	}
	switch argv[0] {
	case "version", "--version", "-v":
		return "version", argv[1:]
	case "help", "--help", "-h":
		return "help", argv[1:]
	case "scan", "project", "probe":
		return argv[0], argv[1:]
	default:
		return "scan", argv // legacy: leading flag, keep all args
	}
}

// runHelp prints either the root usage or, when given a subcommand name, that
// subcommand's usage (so `vercelsior help scan` works alongside
// `vercelsior scan --help`).
func runHelp(rest []string) int {
	if len(rest) > 0 {
		switch rest[0] {
		case "scan":
			printScanUsage()
			return 0
		case "project":
			printProjectUsage()
			return 0
		case "probe":
			printProbeUsage()
			return 0
		}
	}
	printRootUsage()
	return 0
}

func printRootUsage() {
	fmt.Printf(`%svercelsior%s v%s — the Vercel security testing tool

%sUSAGE:%s
  vercelsior <command> [options]
  vercelsior [options]                 (alias for 'scan' — legacy form)

%sCOMMANDS:%s
  scan       Audit a Vercel account/team via the API (CSPM). Requires a token.
  probe      Black-box test a deployed Vercel URL from the outside (DAST,
             no token). CVE-2025-29927, source maps, header hygiene.
  project    Scan a local Vercel project pre-deploy (no token): package.json
             CVEs, .env secrets, next.config + vercel.json misconfig.
  version    Print the version.
  help       Show help. Use 'help <command>' for command-specific options.

%sEXAMPLES:%s
  vercelsior scan --token vrcl_xxxxx --min-severity HIGH
  vercelsior --token vrcl_xxxxx -f sarif -o ./results   # legacy form of 'scan'
  vercelsior project ./my-app
  vercelsior probe https://my-app.vercel.app

Run 'vercelsior help <command>' for the full option list of a command.
`,
		colorBold, colorReset, version,
		colorCyan, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
	)
}
