package pipeline

import (
        "bufio"
        "context"
        "fmt"
        "net"
        "os"
        "path/filepath"
        "strconv"
        "strings"
        "time"

        "github.com/reconx/reconx/internal/config"
        "github.com/reconx/reconx/internal/modules/alive"
        "github.com/reconx/reconx/internal/modules/js"
        "github.com/reconx/reconx/internal/modules/portscan"
        "github.com/reconx/reconx/internal/modules/report"
        "github.com/reconx/reconx/internal/modules/subdomain"
        "github.com/reconx/reconx/internal/modules/urls"
        "github.com/reconx/reconx/internal/modules/vuln"
        "github.com/reconx/reconx/internal/scope"
        "github.com/reconx/reconx/internal/store"
        "github.com/reconx/reconx/pkg/logger"
        "github.com/reconx/reconx/pkg/runner"
)

// netSplitHostPort wraps net.SplitHostPort so we can stub it in tests.
func netSplitHostPort(s string) (string, string, error) {
        return net.SplitHostPort(s)
}

// guessPortService returns a friendly service name for common ports.
// Used when restoring ports from ports.txt during resume.
func guessPortService(port int) string {
        switch port {
        case 21:
                return "ftp"
        case 22:
                return "ssh"
        case 23:
                return "telnet"
        case 25:
                return "smtp"
        case 53:
                return "dns"
        case 80:
                return "http"
        case 110:
                return "pop3"
        case 143:
                return "imap"
        case 443:
                return "https"
        case 445:
                return "smb"
        case 587:
                return "smtp-tls"
        case 993:
                return "imaps"
        case 995:
                return "pop3s"
        case 1433:
                return "mssql"
        case 3306:
                return "mysql"
        case 3389:
                return "rdp"
        case 5432:
                return "postgres"
        case 5900:
                return "vnc"
        case 6379:
                return "redis"
        case 8080:
                return "http-alt"
        case 8443:
                return "https-alt"
        case 8888:
                return "jupyter"
        case 9200:
                return "elasticsearch"
        case 27017:
                return "mongodb"
        }
        return "unknown"
}

// Pipeline orchestrates the full recon workflow
type Pipeline struct {
        cfg    *config.Config
        store  *store.Store
        scope  *scope.Filter
        log    *logger.Logger
        outDir string
}

// New creates a Pipeline and its output directory.
// If cfg.ResumeDir is set, resumes from an existing scan directory.
func New(cfg *config.Config) (*Pipeline, error) {
        var outDir, scanID string

        if cfg.ResumeDir != "" {
                // Resume mode: use existing directory
                outDir = cfg.ResumeDir
                scanID = filepath.Base(outDir)
                if _, err := os.Stat(outDir); os.IsNotExist(err) {
                        return nil, fmt.Errorf("resume dir does not exist: %s", outDir)
                }
        } else {
                // Normal mode: create new scan directory
                scanID = fmt.Sprintf("scan-%d", time.Now().Unix())
                if len(cfg.Target.Domains) > 0 {
                        scanID = cfg.Target.Domains[0] + "-" + fmt.Sprintf("%d", time.Now().Unix())
                }
                outDir = filepath.Join(cfg.Output.OutputDir, scanID)
                if err := os.MkdirAll(outDir, 0755); err != nil {
                        return nil, fmt.Errorf("creating output dir: %w", err)
                }
        }

        logPath := filepath.Join(outDir, "reconx.log")
        log := logger.New(cfg.Output.Verbose, logPath)

        p := &Pipeline{
                cfg:    cfg,
                store:  store.New(scanID),
                scope:  scope.New(cfg),
                log:    log,
                outDir: outDir,
        }

        // If resuming, load existing results into store
        if cfg.ResumeDir != "" {
                if err := p.loadExistingResults(); err != nil {
                        log.Warn("Some existing results could not be loaded: %v", err)
                }
        }

        return p, nil
}

// loadExistingResults loads subdomains, alive hosts, URLs, and JS files
// from a previous scan output directory so later phases can resume.
//
// File formats (written by the corresponding phase modules):
//   subdomains.txt  → bare hostnames, one per line
//   alive.txt       → full URLs (https://host or http://host), one per line
//   urls.txt        → discovered URLs, one per line
//   urls_js.txt     → JS file URLs, one per line
//   ports.txt       → "host:port" lines, one per open port
func (p *Pipeline) loadExistingResults() error {
        loaded := []string{}

        // Load subdomains
        if subs, err := readLines(filepath.Join(p.outDir, "subdomains.txt")); err == nil {
                p.store.AddSubdomains(subs)
                loaded = append(loaded, fmt.Sprintf("%d subdomains", len(subs)))
        }

        // Load alive hosts — file contains URLs (https://host) per alive.go.saveAlive
        if hosts, err := readLines(filepath.Join(p.outDir, "alive.txt")); err == nil {
                for _, line := range hosts {
                        domain := stripURLToHost(line)
                        if domain == "" {
                                continue
                        }
                        url := line
                        if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
                                url = "https://" + line
                        }
                        p.store.AddHost(&store.Host{Domain: domain, Meta: map[string]string{"url": url}})
                }
                loaded = append(loaded, fmt.Sprintf("%d alive hosts", len(hosts)))
        }

        // Load URLs
        if urlList, err := readLines(filepath.Join(p.outDir, "urls.txt")); err == nil {
                p.store.AddURLs(urlList)
                loaded = append(loaded, fmt.Sprintf("%d URLs", len(urlList)))
        }

        // Load JS files
        if jsList, err := readLines(filepath.Join(p.outDir, "urls_js.txt")); err == nil {
                for _, js := range jsList {
                        p.store.AddJSFile(js)
                }
                loaded = append(loaded, fmt.Sprintf("%d JS files", len(jsList)))
        }

        // Load ports (optional — written by portscan module when SavePortsToTxt is called)
        if portList, err := readLines(filepath.Join(p.outDir, "ports.txt")); err == nil {
                for _, line := range portList {
                        parts := strings.SplitN(line, ":", 2)
                        if len(parts) != 2 {
                                continue
                        }
                        port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
                        if err != nil || port == 0 {
                                continue
                        }
                        p.store.AddPort(&store.Port{
                                Host:     strings.TrimSpace(parts[0]),
                                Port:     port,
                                Protocol: "tcp",
                                Service:  guessPortService(port),
                        })
                }
                loaded = append(loaded, fmt.Sprintf("%d ports", len(portList)))
        }

        if len(loaded) > 0 {
                p.log.Info("Resumed: loaded %s", strings.Join(loaded, ", "))
        }
        return nil
}

// stripURLToHost extracts the hostname from a URL or hostname string.
// Returns "" if no host can be extracted.
func stripURLToHost(s string) string {
        s = strings.TrimSpace(s)
        // Case-insensitive scheme stripping — https://, HTTPS://, Http://
        lower := strings.ToLower(s)
        for _, scheme := range []string{"https://", "http://", "ftp://"} {
                if strings.HasPrefix(lower, scheme) {
                        s = s[len(scheme):]
                        break
                }
        }
        if idx := strings.IndexAny(s, "/?#"); idx != -1 {
                s = s[:idx]
        }
        // Strip :port
        if h, _, err := netSplitHostPort(s); err == nil {
                s = h
        }
        return strings.ToLower(strings.TrimSpace(s))
}

// readLines reads a text file and returns non-empty lines
func readLines(path string) ([]string, error) {
        f, err := os.Open(path)
        if err != nil {
                return nil, err
        }
        defer f.Close()
        var lines []string
        sc := bufio.NewScanner(f)
        sc.Buffer(make([]byte, 10*1024*1024), 10*1024*1024)
        for sc.Scan() {
                if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
                        lines = append(lines, l)
                }
        }
        return lines, sc.Err()
}

// Run executes the full pipeline
func (p *Pipeline) Run(ctx context.Context) error {
        defer p.log.Close()

        p.log.Banner("v1.0.0")

        // Print scan header
        p.log.Info("Scan ID:   %s", p.store.ScanID)
        p.log.Info("Output:    %s", p.outDir)
        p.log.Info("Log file:  %s/reconx.log", p.outDir)
        if len(p.cfg.Target.Domains) > 0 {
                p.log.Info("Domains:   %v", p.cfg.Target.Domains)
        }
        if len(p.cfg.Target.IPRanges) > 0 {
                p.log.Info("IP Ranges: %v", p.cfg.Target.IPRanges)
        }
        if len(p.cfg.Target.ASNs) > 0 {
                p.log.Info("ASNs:      %v", p.cfg.Target.ASNs)
        }
        if len(p.cfg.Scope.InScope) > 0 {
                p.log.Info("In-scope:  %d patterns", len(p.cfg.Scope.InScope))
        }
        if len(p.cfg.Scope.OutOfScope) > 0 {
                p.log.Info("Out-scope: %d patterns", len(p.cfg.Scope.OutOfScope))
        }
        if p.cfg.BugBountyHeader != "" {
                p.log.Info("BB Header: %s", p.cfg.BugBountyHeader)
        }
        p.log.Separator()

        p.checkTools()

        start := time.Now()

        // In resume mode, skip phases that already have output files.
        // Each phase writes a marker file when it completes successfully,
        // so we can reliably detect what to skip on --resume.
        isResume := p.cfg.ResumeDir != ""
        hasSubdomains := fileExists(filepath.Join(p.outDir, "subdomains.txt"))
        hasAlive     := fileExists(filepath.Join(p.outDir, "alive.txt"))
        hasPorts     := fileExists(filepath.Join(p.outDir, "ports.txt"))
        hasURLs      := fileExists(filepath.Join(p.outDir, "urls.txt"))
        hasJS        := fileExists(filepath.Join(p.outDir, "js_files.txt"))

        if isResume {
                stats := p.store.Stats()
                p.log.Info("Resume mode — loaded: %d subdomains, %d live hosts, %d ports, %d URLs",
                        stats["subdomains"], stats["live_hosts"], stats["open_ports"], stats["urls"])
        }

        // ── PHASE 1: Subdomain Enumeration ──────────────────────────────────────
        if p.cfg.Phases.SubdomainEnum && !(isResume && hasSubdomains) {
                mod := subdomain.New(p.cfg, p.store, p.scope, p.log, p.outDir)
                if err := mod.Run(ctx); err != nil {
                        p.log.Error("Subdomain phase: %v", err)
                }
                p.printInterim("After subdomain enum")
        }

        // ── PHASE 2: Alive Host Detection ───────────────────────────────────────
        if p.cfg.Phases.AliveCheck && !(isResume && hasAlive) {
                mod := alive.New(p.cfg, p.store, p.log, p.outDir)
                if err := mod.Run(ctx); err != nil {
                        p.log.Error("Alive check phase: %v", err)
                }
                p.printInterim("After alive check")
        }

        // ── PHASE 3: Port Scanning ───────────────────────────────────────────────
        if p.cfg.Phases.PortScan && !(isResume && hasPorts) {
                mod := portscan.New(p.cfg, p.store, p.log, p.outDir)
                if err := mod.Run(ctx); err != nil {
                        p.log.Error("Port scan phase: %v", err)
                }
        }

        // ── PHASE 4: URL Discovery ───────────────────────────────────────────────
        if p.cfg.Phases.URLDiscovery && !(isResume && hasURLs) {
                mod := urls.New(p.cfg, p.store, p.log, p.outDir)
                if err := mod.Run(ctx); err != nil {
                        p.log.Error("URL discovery phase: %v", err)
                }
                p.printInterim("After URL discovery")
        }

        // ── PHASE 5: JS & Secret Analysis ───────────────────────────────────────
        // Use a fresh context for JS/Vuln so they always run even if URL tools
        // left orphan processes that put the parent context in a bad state.
        // The fresh context is still cancelled on Ctrl+C via the signal handler.
        if p.cfg.Phases.JSAnalysis && !(isResume && hasJS) {
                jsCtx, jsCancel := context.WithCancel(context.Background())
                stopWait := make(chan struct{})
                go func() {
                        select {
                        case <-ctx.Done():
                                jsCancel()
                        case <-stopWait:
                        }
                }()
                mod := js.New(p.cfg, p.store, p.log, p.outDir)
                if err := mod.Run(jsCtx); err != nil && err != context.Canceled {
                        p.log.Error("JS analysis phase: %v", err)
                }
                jsCancel()
                close(stopWait)
        }

        // ── PHASE 6: Vulnerability Scanning ─────────────────────────────────────
        if p.cfg.Phases.VulnScan {
                vulnCtx, vulnCancel := context.WithCancel(context.Background())
                stopWait := make(chan struct{})
                go func() {
                        select {
                        case <-ctx.Done():
                                vulnCancel()
                        case <-stopWait:
                        }
                }()
                mod := vuln.New(p.cfg, p.store, p.log, p.outDir)
                if err := mod.Run(vulnCtx); err != nil && err != context.Canceled {
                        p.log.Error("Vuln scan phase: %v", err)
                }
                vulnCancel()
                close(stopWait)
        }

        // ── PHASE 7: Report ──────────────────────────────────────────────────────
        if p.cfg.Phases.Report {
                p.log.Phase("Report Generation", "Saving results and building HTML report")

                if err := p.store.SaveJSON(p.outDir); err != nil {
                        p.log.Error("Failed to save JSON: %v", err)
                } else {
                        p.log.Success("JSON results: %s/results.json", p.outDir)
                }

                if p.cfg.Output.HTMLReport {
                        allTargets := append(p.cfg.Target.Domains, p.cfg.Target.IPRanges...)
                        if err := report.Generate(p.store, allTargets, p.outDir); err != nil {
                                p.log.Error("HTML report failed: %v", err)
                        } else {
                                p.log.Success("HTML report:  %s/report.html", p.outDir)
                        }
                }
        }

        p.printSummary(time.Since(start))
        return nil
}

func fileExists(path string) bool {
        _, err := os.Stat(path)
        return err == nil
}

func (p *Pipeline) printInterim(label string) {
        stats := p.store.Stats()
        p.log.Info("[%s] subdomains:%d  live:%d  urls:%d  js:%d  findings:%d  secrets:%d",
                label,
                stats["subdomains"], stats["live_hosts"], stats["urls"],
                stats["js_files"], stats["findings"], stats["secrets"])
        p.log.Separator()
}

func (p *Pipeline) printSummary(dur time.Duration) {
        stats := p.store.Stats()
        fmt.Println()
        p.log.Phase("SCAN COMPLETE", fmt.Sprintf("Total elapsed: %s", dur.Round(time.Second)))
        p.log.Stat("Subdomains discovered", stats["subdomains"])
        p.log.Stat("Live hosts",           stats["live_hosts"])
        p.log.Stat("Open ports",           stats["open_ports"])
        p.log.Stat("URLs discovered",      stats["urls"])
        p.log.Stat("JS files",             stats["js_files"])
        p.log.Stat("Vulnerabilities",      stats["findings"])
        p.log.Stat("Secrets found",        stats["secrets"])
        p.log.Separator()
        p.log.Stat("Output directory",     p.outDir)
        p.log.Stat("Full log",             p.outDir+"/reconx.log")
        if p.cfg.Output.HTMLReport {
                p.log.Stat("HTML report",       p.outDir+"/report.html")
        }
        p.log.Stat("JSON results",         p.outDir+"/results.json")
        fmt.Println()
}

func (p *Pipeline) checkTools() {
        categories := []struct {
                label string
                tools []string
        }{
                {"Subdomain",  []string{"subfinder", "assetfinder", "amass", "findomain", "chaos", "puredns", "dnsx", "github-subdomains", "crobat", "shuffledns"}},
                {"Alive",      []string{"httpx", "curl"}},
                {"Ports",      []string{"naabu"}},
                {"URLs",       []string{"waybackurls", "waymore", "gau", "gauplus", "katana", "hakrawler", "gospider", "paramspider"}},
                {"JS/Secrets", []string{"mantra", "jsecret", "subjs", "trufflehog"}},
                {"Vuln",       []string{"nuclei"}},
        }

        p.log.Phase("Tool Check", "Verifying installed tools and API tokens")

        totalAvail := 0
        totalMissing := 0

        for _, cat := range categories {
                var avail, missing []string
                for _, t := range cat.tools {
                        if runner.IsAvailable(t) {
                                avail = append(avail, t)
                                totalAvail++
                        } else {
                                missing = append(missing, t)
                                totalMissing++
                        }
                }
                if len(avail) > 0 {
                        p.log.Info("  %-12s ✓ %s", cat.label+":", joinGreen(avail))
                }
                if len(missing) > 0 {
                        p.log.Warn("  %-12s ✗ %s", cat.label+":", joinGray(missing))
                }
        }

        p.log.Separator()

        // Token check — every token unlocks an additional API source.
        // Even without any tokens, the pipeline still runs the binary-backed
        // tools + the free HTTP APIs (crt.sh, OTX, Anubis, etc.).
        tokens := []struct{ key, env, label string }{
                {"github",         "GITHUB_TOKEN",            "GitHub (github-subdomains + trufflehog)"},
                {"chaos",          "PDCP_API_KEY",            "Chaos dataset (ProjectDiscovery)"},
                {"shodan",         "SHODAN_API_KEY",          "Shodan (subdomains + ports)"},
                {"virustotal",     "VT_API_KEY",              "VirusTotal (subdomains, free tier OK)"},
                {"securitytrails", "SECURITYTRAILS_API_KEY",  "SecurityTrails (50 free reqs/month)"},
                {"censys",         "CENSYS_API_ID:SECRET",    "Censys (certificates, free tier OK)"},
        }
        anyToken := false
        for _, t := range tokens {
                if p.cfg.Tokens[t.key] != "" {
                        p.log.Info("  Token %-22s %s", t.key+":", "✓ set — "+t.label)
                        anyToken = true
                } else {
                        p.log.Debug("  Token %-22s not set (%s)", t.key+":", t.label)
                }
        }
        if !anyToken {
                p.log.Info("  No API tokens set — free sources still run (crt.sh, OTX, Anubis, etc.)")
                p.log.Info("  Set tokens via CLI flags (--shodan-key, --vt-key, ...) or env vars")
        }

        p.log.Info("Tools: %d available, %d missing", totalAvail, totalMissing)
        if totalMissing > 0 {
                p.log.Warn("Run 'bash install.sh' to install missing tools")
        }
        p.log.Separator()
}

func joinGreen(items []string) string {
        return "\033[92m" + joinItems(items) + "\033[0m"
}

func joinGray(items []string) string {
        return "\033[90m" + joinItems(items) + "\033[0m"
}

func joinItems(items []string) string {
        result := ""
        for i, s := range items {
                if i > 0 {
                        result += ", "
                }
                result += s
        }
        return result
}
