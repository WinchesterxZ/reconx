package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Target holds all input targets for a scan run
type Target struct {
	Domains   []string
	OrgName   string
	IPRanges  []string
	ASNs      []string
	ScopeFile string
}

// Scope defines in-scope and out-of-scope patterns
type Scope struct {
	InScope    []string
	OutOfScope []string
}

// ToolConfig holds per-tool configuration
type ToolConfig struct {
	Enabled   bool
	Path      string
	Flags     []string
	Timeout   int
	RateLimit int
	Extra     map[string]string
}

// PhasesConfig controls which phases to run
type PhasesConfig struct {
	SubdomainEnum bool
	AliveCheck    bool
	PortScan      bool
	URLDiscovery  bool
	JSAnalysis    bool
	VulnScan      bool
	Report        bool
}

// OutputConfig controls output behavior
type OutputConfig struct {
	OutputDir   string
	HTMLReport  bool
	JSONReport  bool
	ColoredTerm bool
	Verbose     bool
	SaveRaw     bool
}

// Config is the root configuration
type Config struct {
	Target          Target
	Scope           Scope
	Phases          PhasesConfig
	Output          OutputConfig
	Tools           map[string]ToolConfig
	Workers         int
	Tokens          map[string]string
	BugBountyHeader string
	ResumeDir       string // path to existing scan dir to resume from
}

// DefaultConfig returns production-grade timeouts tested on real bug bounty targets
// All timeouts here are based on real-world runs against large targets (airbnb, etc.)
func DefaultConfig() *Config {
	return &Config{
		Workers: 10,
		Phases: PhasesConfig{
			SubdomainEnum: true,
			AliveCheck:    true,
			PortScan:      true,
			URLDiscovery:  true,
			JSAnalysis:    true,
			VulnScan:      true,
			Report:        true,
		},
		Output: OutputConfig{
			OutputDir:   "./reconx-output",
			HTMLReport:  true,
			JSONReport:  true,
			ColoredTerm: true,
			Verbose:     false,
			SaveRaw:     true,
		},
		Tools: map[string]ToolConfig{
			// ── Subdomain tools ──────────────────────────────────────────────
			"subfinder": {
				Enabled: true, Path: "subfinder",
				Flags:   []string{"-all", "-recursive"},
				Timeout: 600, // 10 min — large targets need time
			},
			"amass": {
				Enabled: true, Path: "amass",
				Timeout: 600, // 10 min cap — amass is slow by design
			},
			"assetfinder": {
				Enabled: true, Path: "assetfinder",
				Timeout: 300, // 5 min
			},
			"findomain": {
				Enabled: true, Path: "findomain",
				Timeout: 300, // 5 min
			},
			"chaos": {
				Enabled: true, Path: "chaos",
				Timeout: 300,
			},
			"puredns": {
				Enabled: true, Path: "puredns",
				Timeout: 1800, // 30 min — bruteforce takes time
			},
			"dnsx": {
				Enabled: true, Path: "dnsx",
				Timeout: 1800, // 30 min
			},

			// ── Alive detection ──────────────────────────────────────────────
			// 1681 subdomains @ 50 threads = ~34s minimum network time
			// Real targets add TLS, redirects, slow hosts → need 20-30 min
			"httpx": {
				Enabled: true, Path: "httpx",
				Flags:   []string{"-follow-redirects", "-status-code", "-title", "-web-server", "-content-length"},
				Timeout: 1800, // 30 min — critical fix, was 5 min (not enough for 1000+ subs)
			},

			// ── Port scanning ────────────────────────────────────────────────
			"naabu": {
				Enabled: true, Path: "naabu",
				Flags:   []string{"-rate", "2000"},
				Timeout: 1800, // 30 min
			},

			// ── URL discovery ────────────────────────────────────────────────
			"waybackurls": {
				Enabled: true, Path: "waybackurls",
				Timeout: 0, // no timeout — runs until complete
			},
			"waymore": {
				Enabled: true, Path: "waymore",
				Timeout: 0, // no timeout
			},
			"gau": {
				Enabled: true, Path: "gau",
				Flags:   []string{"--threads", "50"},
				Timeout: 0, // no timeout
			},
			"gauplus": {
				Enabled: true, Path: "gauplus",
				Timeout: 0, // no timeout
			},
			"katana": {
				Enabled: true, Path: "katana",
				Flags:   []string{"-jc", "-kf", "all", "-d", "5", "-silent"},
				Timeout: 0, // no timeout
			},
			"hakrawler": {
				Enabled: true, Path: "hakrawler",
				Timeout: 0, // no timeout
			},
			"gospider": {
				Enabled: true, Path: "gospider",
				Timeout: 0, // no timeout
			},
			"paramspider": {
				Enabled: true, Path: "paramspider",
				Timeout: 0, // no timeout
			},

			// ── JS / Secrets ─────────────────────────────────────────────────
			"trufflehog": {Enabled: true, Path: "trufflehog", Timeout: 1800},
			"mantra":     {Enabled: true, Path: "mantra",     Timeout: 1800},
			"jsecret":    {Enabled: true, Path: "jsecret",    Timeout: 1800},
			"subjs":      {Enabled: true, Path: "subjs",      Timeout: 1800},

			// ── Vuln scanning ────────────────────────────────────────────────
			"nuclei": {
				Enabled: true, Path: "nuclei",
				Flags:   []string{"-severity", "critical,high,medium", "-silent"},
				Timeout: 3600, // 60 min per template category
			},
		},
		Tokens: map[string]string{},
	}
}

// LoadScope loads scope patterns from a file.
// Lines starting with '-' are out-of-scope; '+' or bare lines are in-scope.
func (c *Config) LoadScope(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening scope file: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") {
			c.Scope.OutOfScope = append(c.Scope.OutOfScope, strings.TrimSpace(line[1:]))
		} else {
			c.Scope.InScope = append(c.Scope.InScope, strings.TrimSpace(strings.TrimPrefix(line, "+")))
		}
	}
	return sc.Err()
}

// WriteDefault writes a commented default config to path
func WriteDefault(path string) error {
	content := `# ╔══════════════════════════════════════╗
# ║     ReconX Configuration File       ║
# ╚══════════════════════════════════════╝

[output]
output_dir       = ./reconx-output
html_report      = true
json_report      = true
colored_terminal = true
verbose          = false
save_raw         = true

[phases]
subdomain_enum = true
alive_check    = true
port_scan      = true
url_discovery  = true
js_analysis    = true
vuln_scan      = true
report         = true

[tokens]
github     = ""
chaos      = ""
shodan     = ""
virustotal = ""

# Timeouts are in seconds — tuned for large bug bounty targets (1000+ subdomains)
[tool.httpx]
enabled = true
timeout = 1800   # 30 min — needs time for 1000+ subs

[tool.waybackurls]
enabled = true
timeout = 3600   # 60 min — Wayback archive is huge

[tool.katana]
enabled = true
flags   = ["-jc", "-kf", "all", "-d", "5", "-silent"]
timeout = 3600   # 60 min — headless crawl

[tool.gau]
enabled = true
flags   = ["--threads", "50"]
timeout = 3600

[tool.nuclei]
enabled = true
flags   = ["-severity", "critical,high,medium"]
timeout = 3600

[tool.subfinder]
enabled = true
flags   = ["-all", "-recursive"]
timeout = 600

[tool.naabu]
enabled = true
flags   = ["-rate", "2000"]
timeout = 1800
`
	return os.WriteFile(path, []byte(content), 0644)
}
