package config

import (
	"bufio"
	"os"
	"strings"
)

type Config struct {
	Suppress       map[string]bool
	MinSeverity    string
	Checks         map[string]bool
	SkipChecks     map[string]bool
	Categories     map[string]bool
	SkipCategories map[string]bool
}

func New() *Config {
	return &Config{
		Suppress:       make(map[string]bool),
		Checks:         make(map[string]bool),
		SkipChecks:     make(map[string]bool),
		Categories:     make(map[string]bool),
		SkipCategories: make(map[string]bool),
	}
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = ".vercelsior"
	}
	cfg := New()

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "suppress":
			cfg.Suppress[val] = true
		case "min_severity":
			cfg.MinSeverity = strings.ToUpper(val)
		case "check":
			cfg.Checks[val] = true
		case "skip_check":
			cfg.SkipChecks[val] = true
		case "category":
			cfg.Categories[val] = true
		case "skip_category":
			cfg.SkipCategories[val] = true
		}
	}
	return cfg, scanner.Err()
}

func (c *Config) IsSuppressed(checkID string) bool {
	return c.Suppress[checkID]
}

func (c *Config) IsCheckAllowed(checkID string) bool {
	if len(c.Checks) > 0 {
		return c.Checks[checkID]
	}
	return !c.SkipChecks[checkID]
}

func (c *Config) IsCategoryAllowed(category string) bool {
	if len(c.Categories) > 0 {
		return c.Categories[category]
	}
	return !c.SkipCategories[category]
}

func (c *Config) SeverityRank(sev string) int {
	ranks := map[string]int{
		"CRITICAL": 0,
		"HIGH":     1,
		"MEDIUM":   2,
		"LOW":      3,
		"INFO":     4,
	}
	if r, ok := ranks[strings.ToUpper(sev)]; ok {
		return r
	}
	return 5
}

func (c *Config) MeetsMinSeverity(sev string) bool {
	if c.MinSeverity == "" {
		return true
	}
	return c.SeverityRank(sev) <= c.SeverityRank(c.MinSeverity)
}

// Merge applies CLI flag overrides on top of config file settings.
func (c *Config) Merge(minSev string, checks, skipChecks, categories []string) {
	if minSev != "" {
		c.MinSeverity = strings.ToUpper(minSev)
	}
	for _, ch := range checks {
		c.Checks[ch] = true
	}
	for _, ch := range skipChecks {
		c.SkipChecks[ch] = true
	}
	for _, cat := range categories {
		c.Categories[cat] = true
	}
}
