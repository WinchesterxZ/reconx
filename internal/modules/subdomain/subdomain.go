package subdomain

import (
        "context"
        "fmt"
        "io"
        "net/http"
        "os"
        "strings"
        "sync"
        "time"

        "github.com/reconx/reconx/internal/config"
        "github.com/reconx/reconx/internal/scope"
        "github.com/reconx/reconx/internal/store"
        "github.com/reconx/reconx/pkg/logger"
        "github.com/reconx/reconx/pkg/runner"
        "github.com/reconx/reconx/pkg/util"
)

type Module struct {
        cfg    *config.Config
        store  *store.Store
        scope  *scope.Filter
        log    *logger.Logger
        outDir string
}

func New(cfg *config.Config, st *store.Store, sc *scope.Filter, log *logger.Logger, outDir string) *Module {
        return &Module{cfg: cfg, store: st, scope: sc, log: log, outDir: outDir}
}

func (m *Module) Run(ctx context.Context) error {
        m.log.Phase("Subdomain Enumeration",
                "All tools run in parallel — board updates live — results merged & deduplicated")

        start := time.Now()
        board := m.log.NewProgressBoard()

        // Live totals in the summary header — gives the user an instant
        // "is anything happening?" answer without scrolling per-tool rows.
        board.SetLiveStats(func() map[string]int {
                stats := m.store.Stats()
                return map[string]int{
                        "subdomains": stats["subdomains"],
                        "live_hosts": stats["live_hosts"],
                        "urls":       stats["urls"],
                        "findings":   stats["findings"],
                        "secrets":    stats["secrets"],
                }
        })

        // ── Wildcard detection (MUST run before any bruteforce) ─────────────────────
        // If a domain has wildcard DNS, bruteforce results will be flooded with
        // false positives (every word resolves). We detect this early and warn
        // so the user can decide whether to continue or add --skip-bruteforce.
        for _, domain := range m.cfg.Target.Domains {
                m.runWildcardCheck(ctx, domain, board)
        }

        var wg sync.WaitGroup
        for _, domain := range m.cfg.Target.Domains {
                domain := domain
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        m.enumerateDomain(ctx, domain, board)
                }()
        }

        if len(m.cfg.Target.IPRanges) > 0 && runner.IsAvailable("dnsx") {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        m.runPTRSweep(ctx, board)
                }()
        }

        for _, asn := range m.cfg.Target.ASNs {
                asn := asn
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        m.runASNMap(ctx, asn, board)
                }()
        }

        wg.Wait()
        board.Stop()

        total := len(m.store.GetSubdomains())
        m.log.PhaseComplete("Subdomain Enumeration", total, time.Since(start))

        // ── massdns resolve (optional, runs if massdns binary is available) ────────
        // Much faster than puredns/dnsx for very large subdomain sets (10k+).
        // Results are merged back into store so later phases see everything.
        if total > 5000 && runner.IsAvailable("massdns") {
                m.runMassdns(ctx, m.store.GetSubdomains())
        }

        if err := store.SaveRaw(m.outDir+"/subdomains.txt", m.store.GetSubdomains()); err != nil {
                m.log.Warn("Failed to save subdomains.txt: %v", err)
        }
        return nil
}

func (m *Module) enumerateDomain(ctx context.Context, domain string, board *logger.ProgressBoard) {
        type toolDef struct {
                name     string
                binKey   string // binary name to check in PATH; "" = HTTP-only
                tokenKey string // config.Tokens key required to enable; "" = no token needed
                fn       func(context.Context, string, *logger.ProgressBoard) ([]string, []string)
        }

        // The set below is intentionally large — every source is tried in
        // parallel and the store deduplicates results. The user's stated goal
        // is "most domains ever", so we err on the side of including every
        // passive source we know about.
        tools := []toolDef{
                // Binary-backed tools (require install.sh)
                {"subfinder",    "subfinder",         "",                m.runSubfinder},
                {"assetfinder",  "assetfinder",       "",                m.runAssetfinder},
                {"findomain",    "findomain",         "",                m.runFindomain},
                {"amass",        "amass",             "",                m.runAmass},
                {"chaos",        "chaos",             "chaos",           m.runChaos},
                {"github-subs",  "github-subdomains", "github",          m.runGithubSubs},
                {"dnsx-brute",   "dnsx",              "",                m.runDnsxBrute},
                {"puredns",      "puredns",           "",                m.runPuredns},
                {"shuffledns",   "shuffledns",        "",                m.runShuffleDNS},

                // HTTP-only API sources (no binary needed)
                {"crt.sh",          "", "", m.runCrtSh},
                {"google-ct",       "", "", m.runGoogleCT},
                {"certspotter",     "", "", m.runCertspotter},
                {"hackertarget",    "", "", m.runHackerTarget},
                {"anubis",          "", "", m.runAnubis},
                {"rapiddns",        "", "", m.runRapidDNS},
                {"alienvault-otx",  "", "", m.runOTXSubs},
                {"urlscan",         "", "", m.runURLScan},
                {"dnsdumpster",     "", "", m.runDNSDumpster},
                {"virustotal",      "", "virustotal",     m.runVirusTotal},
                {"shodan",          "", "shodan",         m.runShodan},
                {"securitytrails",  "", "securitytrails", m.runSecurityTrails},
                {"censys",          "", "censys",         m.runCensys},

                // Local permutation — generates candidate names (dev-, -stg,
                // -prod, etc.) and resolves them via the system resolver.
                // No external binary needed; runs in pure Go.
                {"permute",         "", "", m.runPermute},
        }

        hasPuredns := runner.IsAvailable("puredns")
        hasShuffledns := runner.IsAvailable("shuffledns")

        var wg sync.WaitGroup
        for _, t := range tools {
                t := t

                // Avoid running 3 heavy bruteforcers against the same wordlist concurrently.
                // puredns is massdns-backed and fastest; fallback to shuffledns, then dnsx-brute.
                if t.name == "shuffledns" && hasPuredns {
                        board.Skip(t.name, "using puredns (fastest)")
                        continue
                }
                if t.name == "dnsx-brute" && (hasPuredns || hasShuffledns) {
                        board.Skip(t.name, "using massdns engine")
                        continue
                }

                if t.tokenKey != "" && m.cfg.Tokens[t.tokenKey] == "" {
                        board.Skip(t.name, "no "+t.tokenKey+" token")
                        continue
                }
                if t.binKey != "" {
                        path := t.binKey
                        if tcfg, ok := m.cfg.Tools[t.binKey]; ok {
                                if !tcfg.Enabled {
                                        board.Skip(t.name, "disabled")
                                        continue
                                }
                                if tcfg.Path != "" {
                                        path = tcfg.Path
                                }
                        }
                        if !runner.IsAvailable(path) {
                                board.Skip(t.name, "not found — run install.sh")
                                continue
                        }
                }

                board.Register(t.name, domain)
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        results, _ := t.fn(ctx, domain, board)
                        clean    := cleanLines(results)
                        filtered := m.scope.FilterList(clean)
                        // Tag each subdomain with the source that found it
                        // so the HTML report can filter by source.
                        added    := m.store.AddSubdomainsFromSource(filtered, t.name)
                        if added > 0 {
                                board.Update(t.name, len(m.store.GetSubdomains()))
                        }
                }()
        }
        wg.Wait()
}

// ── Tool runners ─────────────────────────────────────────────────────────────

func (m *Module) runSubfinder(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        tcfg  := m.cfg.Tools["subfinder"]
        args  := append([]string{"-d", domain, "-silent"}, tcfg.Flags...)

        r := runner.Run(ctx, tcfg.Path, args,
                runner.WithTimeout(time.Duration(tcfg.Timeout)*time.Second),
                runner.WithLineCallback(func(line string) { board.Update("subfinder", len(m.store.GetSubdomains())) }))

        finalize(board, "subfinder", r)
        return r.Lines, r.Stderr
}

func (m *Module) runAssetfinder(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        tcfg  := m.cfg.Tools["assetfinder"]

        r := runner.Run(ctx, tcfg.Path, []string{"-subs-only"},
                runner.WithStdin(domain),
                runner.WithTimeout(time.Duration(tcfg.Timeout)*time.Second))

        finalize(board, "assetfinder", r)
        return r.Lines, r.Stderr
}

func (m *Module) runFindomain(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        tcfg  := m.cfg.Tools["findomain"]

        r := runner.Run(ctx, tcfg.Path, []string{"-t", domain, "-q"},
                runner.WithTimeout(time.Duration(tcfg.Timeout)*time.Second))

        finalize(board, "findomain", r)
        return r.Lines, r.Stderr
}

func (m *Module) runAmass(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        tcfg    := m.cfg.Tools["amass"]
        timeout := 3 * time.Minute
        if tcfg.Timeout > 0 && tcfg.Timeout < 180 {
                timeout = time.Duration(tcfg.Timeout) * time.Second
        }
        // amass -timeout 3 ensures amass stops itself after 3 minutes
        r := runner.Run(ctx, tcfg.Path,
                []string{"enum", "-passive", "-d", domain, "-timeout", "3", "-silent"},
                runner.WithTimeout(timeout),
                runner.WithLineCallback(func(line string) { board.Heartbeat("amass") }),
                runner.WithStderrCallback(func(line string) { board.Heartbeat("amass") }))

        if r.IsTimeout() {
                board.Timeout("amass", len(r.Lines))
        } else if r.ExitCode == 1 || r.ExitCode == 2 {
                if len(r.Lines) > 0 {
                        board.Done("amass", len(r.Lines))
                } else {
                        board.Fail("amass", fmt.Sprintf("exit %d", r.ExitCode))
                }
        } else if r.Err != nil {
                board.Fail("amass", r.DiagString())
        } else {
                board.Done("amass", len(r.Lines))
        }
        return r.Lines, r.Stderr
}

func (m *Module) runChaos(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        tcfg  := m.cfg.Tools["chaos"]
        token := m.cfg.Tokens["chaos"]

        r := runner.Run(ctx, tcfg.Path, []string{"-d", domain, "-silent"},
                runner.WithEnv([]string{"PDCP_API_KEY=" + token}),
                runner.WithTimeout(time.Duration(tcfg.Timeout)*time.Second))

        finalize(board, "chaos", r)
        return r.Lines, r.Stderr
}

func (m *Module) runGithubSubs(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        token := m.cfg.Tokens["github"]
        path := "github-subdomains"
        // github-subdomains is not in cfg.Tools by default, but allow override.
        if tcfg, ok := m.cfg.Tools["github-subdomains"]; ok {
                if tcfg.Path != "" {
                        path = tcfg.Path
                }
        }

        r := runner.Run(ctx, path,
                []string{"-d", domain, "-t", token, "-q"},
                runner.WithTimeout(3*time.Minute))

        finalize(board, "github-subs", r)
        return r.Lines, r.Stderr
}

func (m *Module) runCrtSh(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        // crt.sh returns 502 / 504 frequently when busy. Retry up to 3 times
        // with a short backoff before giving up. The old code gave up on the
        // first error and logged a misleading "fail" for one of the best
        // free CT sources.
        apiURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

        var (
                body    []byte
                status  int
                err     error
                attempt int
        )
        for attempt = 0; attempt < 3; attempt++ {
                body, status, err = httpGetBody(ctx, apiURL, "crt.sh", m.log)
                if err == nil && status == 200 {
                        break
                }
                m.log.Debug("crt.sh: attempt %d failed (status=%d err=%v) — retrying", attempt+1, status, err)
                select {
                case <-ctx.Done():
                        board.Fail("crt.sh", "cancelled")
                        return nil, nil
                case <-time.After(time.Duration(attempt+1) * 3 * time.Second):
                }
        }
        if err != nil || status != 200 {
                board.Fail("crt.sh", fmt.Sprintf("HTTP %d after %d attempts", status, attempt))
                return nil, nil
        }

        seen := make(map[string]bool)
        var results []string
        for _, part := range strings.Split(string(body), `"name_value":"`) {
                if idx := strings.Index(part, `"`); idx > 0 {
                        for _, sub := range strings.Split(part[:idx], `\n`) {
                                sub = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(sub), "*."))
                                if strings.HasSuffix(sub, "."+domain) || sub == domain {
                                        if isValidDomain(sub) && !seen[sub] {
                                                seen[sub] = true
                                                results = append(results, sub)
                                        }
                                }
                        }
                }
        }
        board.Done("crt.sh", len(results))
        return results, nil
}

func (m *Module) runCertspotter(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        url   := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)

        reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
        defer cancel()
        req, _ := http.NewRequestWithContext(reqCtx, "GET", url, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 (reconx)")

        resp, err := http.DefaultClient.Do(req)
        if err != nil { board.Fail("certspotter", err.Error()); return nil, nil }
        defer resp.Body.Close()

        body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
        seen := make(map[string]bool)
        var results []string
        for _, part := range strings.Split(string(body), `"`) {
                sub := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(part), "*."))
                if (strings.HasSuffix(sub, "."+domain) || sub == domain) && !seen[sub] && isValidDomain(sub) {
                        seen[sub] = true
                        results = append(results, sub)
                }
        }
        board.Done("certspotter", len(results))
        return results, nil
}

func (m *Module) runHackerTarget(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        url   := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)

        reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
        defer cancel()
        req, _ := http.NewRequestWithContext(reqCtx, "GET", url, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 (reconx)")

        resp, err := http.DefaultClient.Do(req)
        if err != nil { board.Fail("hackertarget", err.Error()); return nil, nil }
        defer resp.Body.Close()

        body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
        bodyStr  := string(body)
        if strings.Contains(bodyStr, "API count exceeded") {
                board.Fail("hackertarget", "rate limited")
                return nil, nil
        }

        seen := make(map[string]bool)
        var results []string
        for _, line := range strings.Split(bodyStr, "\n") {
                if parts := strings.SplitN(line, ",", 2); len(parts) == 2 {
                        sub := strings.ToLower(strings.TrimSpace(parts[0]))
                        if strings.Contains(sub, domain) && !seen[sub] && isValidDomain(sub) {
                                seen[sub] = true
                                results = append(results, sub)
                        }
                }
        }
        board.Done("hackertarget", len(results))
        return results, nil
}

func (m *Module) runDnsxBrute(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        wordlist := findWordlist(m.cfg)
        if wordlist == "" {
                board.Skip("dnsx-brute", "no wordlist found")
                return nil, nil
        }
        tcfg := m.cfg.Tools["dnsx"]
        path := "dnsx"
        if tcfg.Path != "" {
                path = tcfg.Path
        }
        args := []string{"-silent", "-d", domain, "-w", wordlist, "-t", "100", "-rl", "500"}
        resolvers := findResolvers(m.cfg)
        if resolvers != "" {
                args = append(args, "-r", resolvers)
        }
        timeout := 10 * time.Minute
        if tcfg.Timeout > 0 {
                timeout = time.Duration(tcfg.Timeout) * time.Second
        }
        r := runner.Run(ctx, path, args,
                runner.WithTimeout(timeout),
                runner.WithLineCallback(func(line string) { board.Heartbeat("dnsx-brute") }),
                runner.WithStderrCallback(func(line string) { board.Heartbeat("dnsx-brute") }))

        finalize(board, "dnsx-brute", r)
        return r.Lines, r.Stderr
}

func (m *Module) runPuredns(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        wordlist  := findWordlist(m.cfg)
        if wordlist == "" {
                board.Skip("puredns", "no wordlist found")
                return nil, nil
        }
        resolvers := findResolvers(m.cfg)
        path      := "puredns"
        if tcfg, ok := m.cfg.Tools["puredns"]; ok && tcfg.Path != "" {
                path = tcfg.Path
        }
        args      := []string{"bruteforce", wordlist, domain}
        if resolvers != "" {
                args = append(args, "-r", resolvers)
        }
        timeout := 15 * time.Minute
        if tcfg, ok := m.cfg.Tools["puredns"]; ok && tcfg.Timeout > 0 {
                timeout = time.Duration(tcfg.Timeout) * time.Second
        }
        r := runner.Run(ctx, path, args,
                runner.WithTimeout(timeout),
                runner.WithLineCallback(func(line string) { board.Heartbeat("puredns") }),
                runner.WithStderrCallback(func(line string) { board.Heartbeat("puredns") }))
        finalize(board, "puredns", r)
        return r.Lines, r.Stderr
}

func (m *Module) runPTRSweep(ctx context.Context, board *logger.ProgressBoard) {
        for _, cidr := range m.cfg.Target.IPRanges {
                board.Register("dnsx-ptr", cidr)
                cmd := fmt.Sprintf("echo %s | dnsx -silent -resp-only -ptr", cidr)
                r   := runner.Run(ctx, "sh", []string{"-c", cmd}, runner.WithTimeout(5*time.Minute))
                if r.Err == nil && len(r.Lines) > 0 {
                        m.store.AddSubdomains(m.scope.FilterList(r.Lines))
                        board.Done("dnsx-ptr", len(r.Lines))
                } else {
                        board.Fail("dnsx-ptr", r.DiagString())
                }
        }
}

func (m *Module) runASNMap(ctx context.Context, asn string, board *logger.ProgressBoard) {
        path := "asnmap"
        if tcfg, ok := m.cfg.Tools["asnmap"]; ok && tcfg.Path != "" {
                path = tcfg.Path
        }
        if !runner.IsAvailable(path) {
                board.Skip("asnmap", "not found — install: go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest")
                return
        }
        board.Register("asnmap", asn)
        r := runner.Run(ctx, path, []string{"-a", asn, "-silent"}, runner.WithTimeout(2*time.Minute))
        finalize(board, "asnmap", r)
        // asnmap returns IP ranges (CIDRs) — store them so the rest of the
        // pipeline can use them. The old code fetched results but discarded
        // them, so ASN-derived assets were silently lost.
        if len(r.Lines) > 0 {
                m.store.AddSubdomainsFromSource(m.scope.FilterList(r.Lines), "asnmap")
        }
}

// finalize updates the board based on a runner.Result
func finalize(board *logger.ProgressBoard, name string, r *runner.Result) {
        if r.IsTimeout() {
                board.Timeout(name, len(r.Lines))
        } else if r.Err != nil && len(r.Lines) == 0 {
                board.Fail(name, r.DiagString())
        } else {
                board.Done(name, len(r.Lines))
        }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func cleanLines(lines []string) []string {
        out := make([]string, 0, len(lines))
        for _, l := range lines {
                l = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(l), "*."))
                if l != "" && isValidDomain(l) {
                        out = append(out, l)
                }
        }
        return out
}

func isValidDomain(s string) bool {
        return s != "" && len(s) <= 253 && strings.Contains(s, ".") &&
                !strings.ContainsAny(s, " \n\t/\\")
}

// findWordlist finds a DNS brute-force wordlist. Priority:
//  1. cfg.WordlistPath (from --wordlist flag or config)
//  2. Well-known SecLists paths
//  3. ./wordlists/subdomains.txt
func findWordlist(cfg *config.Config) string {
        // Allow user override via config / CLI flag
        if cfg != nil && cfg.WordlistPath != "" && util.FileExists(cfg.WordlistPath) {
                return cfg.WordlistPath
        }
        for _, p := range []string{
                "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
                "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                "/usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
                "/usr/share/wordlists/best-dns-wordlist.txt",
                "./wordlists/subdomains.txt",
        } {
                if util.FileExists(p) {
                        return p
                }
        }
        return ""
}

// findResolvers finds a DNS resolvers list. Priority:
//  1. cfg.ResolversPath (from --resolvers flag or config)
//  2. reconx config dir
//  3. ./resolvers.txt
func findResolvers(cfg *config.Config) string {
        if cfg != nil && cfg.ResolversPath != "" && util.FileExists(cfg.ResolversPath) {
                return cfg.ResolversPath
        }
        for _, p := range []string{
                os.ExpandEnv("$HOME/.config/reconx/resolvers.txt"),
                "/root/.config/reconx/resolvers.txt",
                "./resolvers.txt",
        } {
                if util.FileExists(p) {
                        return p
                }
        }
        return ""
}

// ── Wildcard detection ────────────────────────────────────────────────────────────────

// runWildcardCheck probes whether a domain has wildcard DNS configured.
// Strategy:
//  1. Resolve a random non-existent hostname with dig.
//     If it resolves to any IP → wildcard present.
//  2. If puredns is available, use --wildcard-tests 50 as a second pass.
//
// Wildcard detection is a WARN only — it does not stop the scan.
// The user is informed so they can interpret brute-force results carefully.
func (m *Module) runWildcardCheck(ctx context.Context, domain string, board *logger.ProgressBoard) {
        board.Register("wildcard-check", domain)

        // Generate a random label that almost certainly doesn't exist
        rndLabel := fmt.Sprintf("reconx-wc-test-77293819.%s", domain)

        // First: use dig (universally available on Linux/macOS)
        detected := false
        if runner.IsAvailable("dig") {
                digCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
                defer cancel()
                r := runner.Run(digCtx, "dig", []string{"+short", rndLabel})
                if r.Err == nil && len(r.Lines) > 0 {
                        for _, line := range r.Lines {
                                line = strings.TrimSpace(line)
                                if line != "" && !strings.HasPrefix(line, ";;") {
                                        detected = true
                                        break
                                }
                        }
                }
        }

        // Second pass: puredns --wildcard-tests if available
        if !detected && runner.IsAvailable("puredns") {
                resolvers := findResolvers(m.cfg)
                pureArgs := []string{"bruteforce", "/dev/null", domain, "--wildcard-tests", "50"}
                if resolvers != "" {
                        pureArgs = append(pureArgs, "-r", resolvers)
                }
                pureCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
                defer cancel()
                r := runner.Run(pureCtx, "puredns", pureArgs)
                // puredns exits non-zero when wildcard is detected — check stderr
                if r.Err != nil && len(r.Stderr) > 0 {
                        for _, line := range r.Stderr {
                                if strings.Contains(strings.ToLower(line), "wildcard") {
                                        detected = true
                                        break
                                }
                        }
                }
        }

        if detected {
                board.Fail("wildcard-check", fmt.Sprintf(
                        "WILDCARD DNS detected for %s — brute-force may have false positives", domain))
                m.log.Warn("Wildcard DNS detected for %s — brute-force results will need additional filtering.", domain)
                m.log.Warn("puredns/dnsx will attempt to filter wildcards automatically using their built-in wildcard filter.")
        } else {
                board.Done("wildcard-check", 0)
                m.log.Debug("No wildcard DNS detected for %s", domain)
        }
}

// ── Massdns (large-scale resolution) ────────────────────────────────────────────────────

// runMassdns resolves a large list of subdomains using massdns, which is
// significantly faster than puredns/dnsx for 10k+ entries.
// Results are merged back into the store as additional subdomains.
func (m *Module) runMassdns(ctx context.Context, domains []string) {
        if len(domains) == 0 {
                return
        }
        tcfg := m.cfg.Tools["massdns"]
        path := "massdns"
        if tcfg.Path != "" {
                path = tcfg.Path
        }
        if !runner.IsAvailable(path) {
                m.log.Debug("massdns not found — skipping mass resolution (puredns already ran)")
                return
        }

        resolvers := findResolvers(m.cfg)
        if resolvers == "" {
                m.log.Debug("massdns: no resolvers file found — skipping")
                return
        }

        // Write domains to a temp file
        tmpFile := m.outDir + "/.massdns_input.tmp"
        if err := store.SaveRaw(tmpFile, domains); err != nil {
                m.log.Warn("massdns: could not write input file: %v", err)
                return
        }
        defer os.Remove(tmpFile)

        outFile := m.outDir + "/massdns_raw.txt"
        args := []string{"-r", resolvers, "-t", "A", "-o", "S", "-w", outFile, tmpFile}

        m.log.Tool("massdns", fmt.Sprintf("%d subdomains → %s", len(domains), outFile))
        m.log.ToolCmd("massdns", args, "")

        start := time.Now()
        timeout := time.Duration(tcfg.Timeout) * time.Second
        if timeout == 0 {
                timeout = 30 * time.Minute
        }
        r := runner.Run(ctx, path, args, runner.WithTimeout(timeout))
        if r.Err != nil && len(r.Lines) == 0 {
                m.log.ToolError("massdns", fmt.Errorf(r.DiagString()), r.Stderr)
                return
        }

        // Parse massdns simple output (format: "hostname A ip")
        var newSubs []string
        for _, line := range r.Lines {
                parts := strings.Fields(line)
                if len(parts) >= 3 && strings.EqualFold(parts[1], "A") {
                        sub := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(parts[0])), ".")
                        if isValidDomain(sub) {
                                newSubs = append(newSubs, sub)
                        }
                }
        }

        added := m.store.AddSubdomainsFromSource(m.scope.FilterList(newSubs), "massdns")
        m.log.ToolDone("massdns", added, time.Since(start))
        m.log.Debug("massdns: %d lines parsed, %d new subdomains added", len(r.Lines), added)
}
