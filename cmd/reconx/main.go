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
	"github.com/reconx/reconx/pkg/runner"
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
                shodanKey   = flag.String("shodan-key", "", "Shodan API key (subdomain + port enrichment)")
                vtKey       = flag.String("vt-key", "", "VirusTotal API key (free tier works)")
                stKey       = flag.String("securitytrails-key", "", "SecurityTrails API key (50 free queries/month)")
                bbHeader    = flag.String("header", "", "Custom header added to all requests (e.g. \"X-Bug-Bounty: True\")")
                configFile  = flag.String("config", "", "Path to reconx.yaml config file (overrides defaults; CLI flags override config)")
                wordlist    = flag.String("wordlist", "", "DNS brute-force wordlist (overrides SecLists auto-detection)")
                resolvers   = flag.String("resolvers", "", "DNS resolvers file (overrides reconx resolvers auto-detection)")

		// Target modes
		singleTarget = flag.Bool("single", false, "Single target mode (scans only the specified host/domain; skips subdomain enum)")
		targetURL    = flag.String("u", "", "Single target URL or host (shorthand for single target scan, e.g. -u https://admin.example.com)")

		// Phase toggles
		skipSubs  = flag.Bool("skip-subs",  false, "Skip subdomain enumeration")
		skipAlive = flag.Bool("skip-alive", false, "Skip alive host detection")
		skipPorts = flag.Bool("skip-ports", false, "Skip port scanning")
		skipURLs  = flag.Bool("skip-urls",  false, "Skip URL discovery")
		skipJS    = flag.Bool("skip-js",    false, "Skip JS & secret analysis")
		skipVuln  = flag.Bool("skip-vuln",  false, "Skip vulnerability scanning")

		// Optional phases (opt-in for active fuzzing, opt-out for passive)
		enableFuzz  = flag.Bool("fuzz",        false, "Enable directory & content fuzzing (feroxbuster/dirsearch)")
		enableDirfuzz = flag.Bool("dirfuzz",   false, "Alias for --fuzz")
		skipFuzz    = flag.Bool("skip-dirfuzz",false, "Explicitly skip directory fuzzing")
                enableParams= flag.Bool("params",      false, "Enable hidden parameter discovery (arjun)")
                skipParams  = flag.Bool("skip-params", false, "Explicitly skip parameter discovery")
                skipCloud   = flag.Bool("skip-cloud",  false, "Skip cloud/S3 bucket enumeration")
                skipCORS    = flag.Bool("skip-cors",   false, "Skip CORS misconfiguration scanning")
                screenshots = flag.Bool("screenshots", false, "Enable screenshots of all live hosts (requires gowitness)")

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
                initCmd   = flag.Bool("init",    false, "Write default reconx.yaml config and exit")
                version_  = flag.Bool("version", false, "Print version and exit")
                listTools = flag.Bool("list-tools",  false, "List all known tools, their availability, and how to install missing ones, then exit")
                listPhases = flag.Bool("list-phases", false, "List all pipeline phases and what they do, then exit")
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

        if *listTools {
                printToolAvailability()
                os.Exit(0)
        }

        if *listPhases {
                printPhaseList()
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

        // Build config (defaults → optional config file → CLI flags)
        cfg := config.DefaultConfig()

        // Load config file if specified or default locations (~/.config/reconx/config.yaml or ./reconx.yaml)
        cfgPath := *configFile
        if cfgPath == "" {
                home, _ := os.UserHomeDir()
                userConfig := filepath.Join(home, ".config", "reconx", "config.yaml")
                if _, err := os.Stat(userConfig); err == nil {
                        cfgPath = userConfig
                } else if _, err := os.Stat("reconx.yaml"); err == nil {
                        cfgPath = "reconx.yaml"
                }
        }
        if cfgPath != "" {
                if err := config.Load(cfg, cfgPath); err != nil && *configFile != "" {
                        fmt.Fprintf(os.Stderr, "Error loading config %s: %v\n", cfgPath, err)
                        os.Exit(1)
                }
                cfg.ConfigPath = cfgPath
        }

        // -u is purely additive: it can be combined with -d to also probe a
        // specific host (admin panel, etc.) in addition to the parent domain.
        // The previous code disabled subdomain enum whenever -u was set —
        // silently dropping -d.
        if *targetURL != "" {
                domains = append(domains, *targetURL)
        }
        cfg.Target.Domains  = cleanDomains(domains)
        cfg.Target.IPRanges = []string(ipRanges)
        cfg.Target.ASNs     = []string(asns)
        cfg.Target.OrgName  = *orgName

        // Output — only override config when flag is explicitly set on CLI.
        // Go's flag package has no "was set?" API on the value itself, so we
        // use flag.Visit which only hits flags that were actually parsed.
        explicit := make(map[string]bool)
        flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

        if explicit["output"] {
                cfg.Output.OutputDir = *outDir
        }
        if explicit["v"] {
                cfg.Output.Verbose = *verbose
        }

        // Wordlist / resolvers overrides
        if explicit["wordlist"] {
                cfg.WordlistPath = *wordlist
        }
        if explicit["resolvers"] {
                cfg.ResolversPath = *resolvers
        }

        // Tokens: CLI flag > environment variable > config file (set above)
        setToken(cfg, "github",          *githubToken, "GITHUB_TOKEN")
        setToken(cfg, "chaos",           *chaosKey,    "PDCP_API_KEY")
        setToken(cfg, "shodan",          *shodanKey,   "SHODAN_API_KEY")
        setToken(cfg, "virustotal",      *vtKey,       "VT_API_KEY")
        setToken(cfg, "securitytrails",  *stKey,       "SECURITYTRAILS_API_KEY")

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
        // -u is "single target" only if no -d flag was given. If both
        // -u and -d are present, the -d domains still get full subdomain
        // enumeration; -u just adds an extra live-host probe.
        isOnlyURL := *targetURL != "" && !hasOnlyFlagValue(domains, *targetURL)
        singleHost := *singleTarget || (*targetURL != "" && isOnlyURL)
        if singleHost && !explicit["skip-subs"] {
                cfg.Phases.SubdomainEnum = false
        }
        if *skipSubs    { cfg.Phases.SubdomainEnum = false }
        if *skipAlive   { cfg.Phases.AliveCheck    = false }
        if *skipPorts   { cfg.Phases.PortScan      = false }
        if *skipURLs    { cfg.Phases.URLDiscovery  = false }
        if *skipJS      { cfg.Phases.JSAnalysis    = false }
        if *skipVuln    { cfg.Phases.VulnScan      = false }

        // Optional / active phases
        if *enableFuzz || *enableDirfuzz { cfg.Phases.DirFuzz = true }
        if *skipFuzz    { cfg.Phases.DirFuzz = false }
        if *enableParams{ cfg.Phases.Params = true }
        if *skipParams  { cfg.Phases.Params = false }
        if *skipCloud   { cfg.Phases.CloudEnum = false }
        if *skipCORS    { cfg.Phases.CORS = false }
        if *screenshots { cfg.Phases.Screenshots = true }

        // --no-timeout: set every single tool timeout to 0 (no deadline)
        // Each tool runs until it finishes naturally.
        // Ctrl+C still works — it cancels the parent context which stops everything.
        if *noTimeout {
                cfg.NoTimeout = true
                runner.SetNoTimeout(true)
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
                d = strings.TrimSpace(d)
                d = strings.TrimPrefix(d, "https://")
                d = strings.TrimPrefix(d, "http://")
                d = strings.TrimPrefix(d, "*.")
                d = strings.TrimPrefix(d, "*")
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

// hasOnlyFlagValue returns true if v is the only value in domains.
// (Used to distinguish "single -u target" from "-u + -d combo".)
func hasOnlyFlagValue(domains []string, v string) bool {
	if len(domains) == 0 {
		return false
	}
	if len(domains) == 1 && domains[0] == v {
		return true
	}
	return false
}


// printToolAvailability shows which reconx tools are installed in this
// environment. Use this when triaging "why isn't X running?".
func printToolAvailability() {
	fmt.Println("\n  reconx tool availability check")
	fmt.Println("  " + strings.Repeat("─", 50))

	categories := []struct {
		label string
		tools []string
	}{
		{"Subdomain", []string{"subfinder", "assetfinder", "amass", "findomain", "chaos", "puredns", "dnsx", "github-subdomains", "shuffledns", "massdns"}},
		{"Alive",     []string{"httpx", "curl", "wafw00f", "tlsx", "subjack"}},
		{"Ports",     []string{"naabu"}},
		{"URLs",      []string{"waybackurls", "gau", "gauplus", "katana", "hakrawler", "gospider", "paramspider"}},
		{"DirFuzz",   []string{"feroxbuster", "ffuf", "dirsearch"}},
		{"Params",    []string{"arjun", "dalfox", "getJS"}},
		{"Cloud/CORS",[]string{"s3scanner", "cloud_enum", "corsy"}},
		{"JS/Secrets",[]string{"mantra", "jsecret", "subjs", "trufflehog", "gitleaks"}},
		{"Vuln",      []string{"nuclei"}},
	}

	avail, missing := 0, 0
	for _, cat := range categories {
		fmt.Printf("\n  %s:\n", cat.label)
		for _, t := range cat.tools {
			if runner.IsAvailable(t) {
				fmt.Printf("    \033[32m✓\033[0m  %s\n", t)
				avail++
			} else {
				fmt.Printf("    \033[31m✗\033[0m  %s\n", t)
				missing++
			}
		}
	}

	fmt.Printf("\n  %d available, %d missing\n", avail, missing)
	if missing > 0 {
		fmt.Println("  Run 'bash install.sh' to install missing tools")
	}
	fmt.Println()
}

// printPhaseList shows every pipeline phase in order with a one-liner.
func printPhaseList() {
	fmt.Println("\n  reconx pipeline phases (in order)")
	fmt.Println("  " + strings.Repeat("─", 50))

	phases := []struct {
		name string
		desc string
	}{
		{"1. Subdomain enumeration", "25+ passive/active sources (subfinder, amass, crt.sh, OTX, ...)"},
		{"2. Alive host detection", "httpx probes every subdomain for HTTP/HTTPS"},
		{"3. Port scanning", "naabu top-1000 ports on every live host"},
		{"4. URL discovery", "waybackurls, katana, gau, gospider, paramspider"},
		{"4.7. Directory fuzzing (opt-in)", "feroxbuster/dirsearch/ffuf — adds noise, slow"},
		{"4.8. Param discovery (opt-in)", "arjun, dalfox, getJS — generates traffic"},
		{"4.9. Cloud enum", "s3scanner, cloud_enum"},
		{"4.10. CORS misconfig", "corsy + built-in origin reflection probe"},
		{"5. JS & secret analysis", "subjs, mantra, jsecret, trufflehog, gitleaks"},
		{"6. Vulnerability scan", "nuclei with 6 categories (exposures, takeovers, CVEs, ...)"},
		{"7. Report", "results.json + HTML report"},
	}

	for _, p := range phases {
		fmt.Printf("  \033[1;36m%s\033[0m\n", p.name)
		fmt.Printf("    %s\n", p.desc)
	}
	fmt.Println()
}
