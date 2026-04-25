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

        if err := store.SaveRaw(m.outDir+"/subdomains.txt", m.store.GetSubdomains()); err != nil {
                m.log.Warn("Failed to save subdomains.txt: %v", err)
        }
        return nil
}

func (m *Module) enumerateDomain(ctx context.Context, domain string, board *logger.ProgressBoard) {
        type toolDef struct {
                name     string
                binKey   string
                tokenKey string
                fn       func(context.Context, string, *logger.ProgressBoard) ([]string, []string)
        }

        tools := []toolDef{
                {"subfinder",    "subfinder",         "",       m.runSubfinder},
                {"assetfinder",  "assetfinder",       "",       m.runAssetfinder},
                {"findomain",    "findomain",         "",       m.runFindomain},
                {"amass",        "amass",             "",       m.runAmass},
                {"chaos",        "chaos",             "chaos",  m.runChaos},
                {"github-subs",  "github-subdomains", "github", m.runGithubSubs},
                {"crt.sh",       "",                  "",       m.runCrtSh},
                {"certspotter",  "",                  "",       m.runCertspotter},
                {"hackertarget", "",                  "",       m.runHackerTarget},
                {"dnsx-brute",   "dnsx",              "",       m.runDnsxBrute},
                {"puredns",      "puredns",           "",       m.runPuredns},
        }

        var wg sync.WaitGroup
        for _, t := range tools {
                t := t

                if t.tokenKey != "" && m.cfg.Tokens[t.tokenKey] == "" {
                        board.Skip(t.name, "no "+t.tokenKey+" token")
                        continue
                }
                if t.binKey != "" {
                        path := t.binKey
                        if tcfg, ok := m.cfg.Tools[t.binKey]; ok {
                                if !tcfg.Enabled { board.Skip(t.name, "disabled"); continue }
                                if tcfg.Path != "" { path = tcfg.Path }
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
                        added    := m.store.AddSubdomains(filtered)
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
        timeout := 10 * time.Minute
        if tcfg.Timeout > 0 {
                timeout = time.Duration(tcfg.Timeout) * time.Second
        }
        amassCtx, cancel := context.WithTimeout(ctx, timeout)
        defer cancel()

        r := runner.Run(amassCtx, tcfg.Path,
                []string{"enum", "-passive", "-d", domain, "-timeout", "8", "-silent"},
                runner.WithTimeout(timeout),
                runner.WithStderrCallback(func(line string) { m.log.Debug("amass: %s", line) }))

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

        r := runner.Run(ctx, "github-subdomains",
                []string{"-d", domain, "-t", token, "-q"},
                runner.WithTimeout(3*time.Minute))

        finalize(board, "github-subs", r)
        return r.Lines, r.Stderr
}

func (m *Module) runCrtSh(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        url   := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

        reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
        defer cancel()
        req, _ := http.NewRequestWithContext(reqCtx, "GET", url, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 (reconx)")

        resp, err := http.DefaultClient.Do(req)
        if err != nil {
                board.Fail("crt.sh", err.Error())
                return nil, nil
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
        seen := make(map[string]bool)
        var results []string
        for _, part := range strings.Split(string(body), `"name_value":"`) {
                if idx := strings.Index(part, `"`); idx > 0 {
                        for _, sub := range strings.Split(part[:idx], `\n`) {
                                sub = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(sub), "*."))
                                if strings.Contains(sub, domain) && !seen[sub] && isValidDomain(sub) {
                                        seen[sub] = true
                                        results = append(results, sub)
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
        wordlist := findWordlist()
        if wordlist == "" {
                board.Skip("dnsx-brute", "no wordlist found")
                return nil, nil
        }
        r := runner.Run(ctx, "dnsx", []string{"-silent", "-d", domain, "-w", wordlist},
                runner.WithTimeout(30*time.Minute))

        finalize(board, "dnsx-brute", r)
        return r.Lines, r.Stderr
}

func (m *Module) runPuredns(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        wordlist  := findWordlist()
        if wordlist == "" {
                board.Skip("puredns", "no wordlist found")
                return nil, nil
        }
        resolvers := findResolvers()
        args      := []string{"bruteforce", wordlist, domain}
        if resolvers != "" {
                args = append(args, "-r", resolvers)
        }
        r := runner.Run(ctx, "puredns", args, runner.WithTimeout(30*time.Minute))
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
        if !runner.IsAvailable("asnmap") {
                return
        }
        board.Register("asnmap", asn)
        r := runner.Run(ctx, "asnmap", []string{"-a", asn, "-silent"}, runner.WithTimeout(2*time.Minute))
        finalize(board, "asnmap", r)
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

func findWordlist() string {
        for _, p := range []string{
                "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                "/usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
                "/usr/share/wordlists/best-dns-wordlist.txt",
                "./wordlists/subdomains.txt",
        } {
                if util.FileExists(p) { return p }
        }
        return ""
}

func findResolvers() string {
        for _, p := range []string{
                os.ExpandEnv("$HOME/.config/reconx/resolvers.txt"),
                "/root/.config/reconx/resolvers.txt",
                "./resolvers.txt",
        } {
                if util.FileExists(p) { return p }
        }
        return ""
}
