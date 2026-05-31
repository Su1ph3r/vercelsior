package main

import (
	"reflect"
	"testing"
)

func TestRoute(t *testing.T) {
	cases := []struct {
		name     string
		argv     []string
		wantName string
		wantRest []string
	}{
		// Backward compatibility: the original flag-first invocations must all
		// route to scan with every argument preserved.
		{"no args -> scan", nil, "scan", nil},
		{"empty slice -> scan", []string{}, "scan", []string{}},
		{"legacy token", []string{"--token", "x"}, "scan", []string{"--token", "x"}},
		{"legacy short token", []string{"-t", "x", "-f", "json"}, "scan", []string{"-t", "x", "-f", "json"}},
		{"legacy min-severity", []string{"--min-severity", "HIGH"}, "scan", []string{"--min-severity", "HIGH"}},

		// Explicit subcommands consume the leading token.
		{"explicit scan", []string{"scan", "--token", "x"}, "scan", []string{"--token", "x"}},
		{"project with path", []string{"project", "./app"}, "project", []string{"./app"}},
		{"probe with url", []string{"probe", "https://x.vercel.app"}, "probe", []string{"https://x.vercel.app"}},

		// Version / help in all their spellings.
		{"version word", []string{"version"}, "version", []string{}},
		{"version long", []string{"--version"}, "version", []string{}},
		{"version short", []string{"-v"}, "version", []string{}},
		{"help word", []string{"help"}, "help", []string{}},
		{"help long", []string{"--help"}, "help", []string{}},
		{"help short", []string{"-h"}, "help", []string{}},
		{"help with sub", []string{"help", "scan"}, "help", []string{"scan"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotRest := route(tc.argv)
			if gotName != tc.wantName {
				t.Errorf("route(%v) name = %q; want %q", tc.argv, gotName, tc.wantName)
			}
			if !reflect.DeepEqual(gotRest, tc.wantRest) {
				t.Errorf("route(%v) rest = %#v; want %#v", tc.argv, gotRest, tc.wantRest)
			}
		})
	}
}

// TestRun_HelpAndVersionExitZero verifies the non-scan, non-network paths
// return success without touching the API. (scan/probe-without-url call
// os.Exit via fatal(), so they are intentionally not exercised here.)
func TestRun_HelpAndVersionExitZero(t *testing.T) {
	cases := [][]string{
		{"version"},
		{"--version"},
		{"-v"},
		{"help"},
		{"--help"},
		{"help", "scan"},
		{"help", "project"},
		{"help", "probe"},
		{"scan", "--help"},
		{"project", "--help"},
		{"probe", "--help"},
	}
	for _, argv := range cases {
		if code := run(argv); code != 0 {
			t.Errorf("run(%v) = %d; want 0", argv, code)
		}
	}
}

// Note: project and probe do real I/O (filesystem / network) when invoked for
// real, so run() is not exercised against them here — their logic is covered
// by internal/project and internal/prober tests, plus TestNormalizeProbeURL.

func TestNormalizeProbeURL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"https://app.vercel.app", "https://app.vercel.app", false},
		{"app.vercel.app", "https://app.vercel.app", false}, // scheme defaulted
		{"http://app.local/path", "http://app.local/path", false},
		{"  app.vercel.app/x  ", "https://app.vercel.app/x", false}, // trimmed
		{"ftp://app.vercel.app", "", true},                          // bad scheme
		{"https://", "", true},                                      // no host
	}
	for _, tc := range cases {
		got, err := normalizeProbeURL(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("normalizeProbeURL(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeProbeURL(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("normalizeProbeURL(%q) = %q; want %q", tc.in, got.String(), tc.want)
		}
	}
}
