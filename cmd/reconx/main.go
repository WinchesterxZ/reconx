package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/reconx/reconx/internal/config"
	"github.com/reconx/reconx/internal/pipeline"
)

const version = "v1.0.0"

const banner = `
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║ ╚███╔╝ 
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║ ██╔██╗ 
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║██╔╝╚██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝╚═╝  ╚═╝
`

type multiFlag []string

func (m *multiFlag) String() string        { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error    { *m = append(*m, v); return nil }

func main() {
	var (
		domains     multiFlag
		ipRanges    multiFlag
		asns        multiFlag
		orgName     = flag.String("org", "", "Organization name")
		scopeFile   = flag.String("scope", "", "Scope file path")
		outDir      = flag.String("output", "./reconx-output", "Output directory")
		verbose     = flag.Bool("v", false, "Verbose output")
		githubToken = flag.String("github-token", "", "GitHub API token")
		chaosKey    = flag.String("chaos-key", "", "ProjectDiscovery Chaos API key")
		bbHeader    = flag.String("header", "", "Custom header added to all requests (e.g. \"X-Bug-Bounty: True\")")

		// Phase toggles
		skipSubs  = flag.Bool("skip-subs",  false, "Skip subdomain enumeration")
		skipAlive = flag.Bool("skip-alive", false, "Skip alive host detection")
		skipPorts = flag.Bool("skip-ports", false, "Skip port scanning")
		skipURLs  = flag.Bool("skip-urls",  false, "Skip URL discovery")
		skipJS    = flag.Bool("skip-js",    false, "Skip JS & secret analysis")
		skipVuln  = flag.Bool("skip-vuln",  false, "Skip vulnerability scanning")

		// Timeout control
		// --no-timeout removes ALL timeouts from every tool.
		// Tools run until they finish naturally or you press Ctrl+C.
		// Use this for large targets (airbnb, google, etc.) where tools
		// like waybackurls and katana need hours to complete.
		noTimeout = flag.Bool("no-timeout", false,
			"Disable all tool timeouts — tools run until complete (recommended for large targets)")

		// Resume mode
		// --resume allows continuing a previous scan from where it left off.
		// Pass the scan directory path (e.g., ./airbnb-scan/airbnb.com-1234567).
		// Already-completed phases (subdomains, alive, URLs) are skipped automatically.
		// Use this after a crash or Ctrl+C to run JS/Vuln phases on existing results.
		resumeDir = flag.String("resume", "", "Resume scan from existing output directory (skips completed phases)")

		// Special
		initCmd  = flag.Bool("init",    false, "Write default reconx.yaml config and exit")
		version_ = flag.Bool("version", false, "Print version and exit")
	)

	flag.Var(&domains,  "d",   "Target domain (repeatable: -d a.com -d b.com)")
	flag.Var(&ipRanges, "ip",  "IP range CIDR (repeatable: --ip 10.0.0.0/24)")
	flag.Var(&asns,     "asn", "ASN to enumerate (repeatable: --asn AS12345)")

	flag.Usage = func() {
		fmt.Print("\033[1;32m" + banner + "\033[0m")
		fmt.Printf("  Automated Bug Bounty Recon Framework %s\n\n", version)
		fmt.Println("  Usage:")
		fmt.Println("    reconx -d example.com [flags]")
		fmt.Println("    reconx -d example.com -d api.example.com --scope scope.txt")
		fmt.Println("    reconx --ip 10.0.0.0/24 --asn AS12345")
		fmt.Println()
		fmt.Println("  Flags:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("  Scope file format (+in / -out):")
		fmt.Println("    +*.example.com")
		fmt.Println("    +api.example.com")
		fmt.Println("    -staging.example.com")
		fmt.Println()
		fmt.Println("  Environment Variables:")
		fmt.Println("    GITHUB_TOKEN    GitHub API token")
		fmt.Println("    PDCP_API_KEY    Chaos dataset key")
		fmt.Println("    SHODAN_API_KEY  Shodan API key")
		fmt.Println()
		fmt.Println("  Examples:")
		fmt.Println("    # Resume a suspended scan (skip subdomain/alive/URL phases)")
		fmt.Println("    reconx --resume ./airbnb-scan/airbnb.com-1774175844 --no-timeout")
		fmt.Println()
		fmt.Println("    # Full scan with no timeouts (recommended for large targets)")
		fmt.Println("    reconx -d airbnb.com --scope scope.txt --header \"X-Bug-Bounty: True\" --no-timeout --skip-ports")
		fmt.Println()
		fmt.Println("    # Quick scan with default timeouts")
		fmt.Println("    reconx -d target.com --skip-ports --skip-vuln")
		fmt.Println()
	}

	flag.Parse()

	if *version_ {
		fmt.Printf("reconx %s\n", version)
		os.Exit(0)
	}

	if *initCmd {
		if err := config.WriteDefault("reconx.yaml"); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✓ Config written to reconx.yaml")
		os.Exit(0)
	}

	// Build config
	cfg := config.DefaultConfig()

	// Target
	cfg.Target.Domains  = cleanDomains(domains)
	cfg.Target.IPRanges = []string(ipRanges)
	cfg.Target.ASNs     = []string(asns)
	cfg.Target.OrgName  = *orgName

	// Output
	cfg.Output.OutputDir = *outDir
	cfg.Output.Verbose   = *verbose

	// Tokens: CLI flag > environment variable
	setToken(cfg, "github",     *githubToken, "GITHUB_TOKEN")
	setToken(cfg, "chaos",      *chaosKey,    "PDCP_API_KEY")
	setToken(cfg, "shodan",     "",           "SHODAN_API_KEY")
	setToken(cfg, "virustotal", "",           "VT_API_KEY")

	// Resume mode
	if *resumeDir != "" {
		cfg.ResumeDir = *resumeDir
		// In resume mode, use the resume dir as the output
		cfg.Output.OutputDir = filepath.Dir(*resumeDir)
		// Allow no target domains in resume mode
		if len(cfg.Target.Domains) == 0 {
			// Extract domain from directory name
			base := filepath.Base(*resumeDir)
			if idx := strings.LastIndex(base, "-"); idx > 0 {
				cfg.Target.Domains = []string{base[:idx]}
			}
		}
	}

	// Bug bounty header
	if *bbHeader != "" {
		cfg.BugBountyHeader = *bbHeader
	} else if h := os.Getenv("BB_HEADER"); h != "" {
		cfg.BugBountyHeader = h
	}

	// Load scope file
	if *scopeFile != "" {
		if err := cfg.LoadScope(*scopeFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading scope: %v\n", err)
			os.Exit(1)
		}
	}

	// Phase toggles
	if *skipSubs  { cfg.Phases.SubdomainEnum = false }
	if *skipAlive { cfg.Phases.AliveCheck    = false }
	if *skipPorts { cfg.Phases.PortScan      = false }
	if *skipURLs  { cfg.Phases.URLDiscovery  = false }
	if *skipJS    { cfg.Phases.JSAnalysis    = false }
	if *skipVuln  { cfg.Phases.VulnScan      = false }

	// --no-timeout: set every single tool timeout to 0 (no deadline)
	// Each tool runs until it finishes naturally.
	// Ctrl+C still works — it cancels the parent context which stops everything.
	if *noTimeout {
		for name, tool := range cfg.Tools {
			tool.Timeout = 0
			cfg.Tools[name] = tool
		}
	}

	// Validate targets
	if len(cfg.Target.Domains) == 0 && len(cfg.Target.IPRanges) == 0 && len(cfg.Target.ASNs) == 0 && *resumeDir == "" {
		fmt.Fprintln(os.Stderr, "\033[1;31mError:\033[0m no targets — use -d domain.com, --ip 10.0.0.0/24, or --asn AS12345")
		flag.Usage()
		os.Exit(1)
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\n\n  \033[33m⚠ Interrupt — saving results and exiting...\033[0m")
		cancel()
	}()

	// Run pipeline
	p, err := pipeline.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Init error: %v\n", err)
		os.Exit(1)
	}
	if err := p.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}
}

func cleanDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.TrimPrefix(d, "https://")
		d = strings.TrimPrefix(d, "http://")
		d = strings.TrimSuffix(d, "/")
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

func setToken(cfg *config.Config, key, flagVal, env string) {
	if flagVal != "" {
		cfg.Tokens[key] = flagVal
		return
	}
	if v := os.Getenv(env); v != "" {
		cfg.Tokens[key] = v
	}
}
