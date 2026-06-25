package alive

import (
        "context"
        "fmt"
        "strconv"
        "strings"
        "sync"
        "time"

        "github.com/reconx/reconx/internal/config"
        "github.com/reconx/reconx/internal/store"
        "github.com/reconx/reconx/pkg/logger"
        "github.com/reconx/reconx/pkg/runner"
        "github.com/reconx/reconx/pkg/util"
)

// Module probes discovered subdomains for live HTTP/S hosts
type Module struct {
        cfg    *config.Config
        store  *store.Store
        log    *logger.Logger
        outDir string
}

// New creates an alive-check module
func New(cfg *config.Config, st *store.Store, log *logger.Logger, outDir string) *Module {
        return &Module{cfg: cfg, store: st, log: log, outDir: outDir}
}

// Run probes all discovered subdomains
func (m *Module) Run(ctx context.Context) error {
        m.log.Phase("Alive Host Detection",
                "Probing all subdomains — status code, title, server, tech fingerprint")

        subs := m.store.GetSubdomains()
        if len(subs) == 0 {
                m.log.Warn("No subdomains to probe — subdomain phase may have failed")
                return nil
        }
        m.log.Info("Probing %d subdomains with httpx...", len(subs))

        tcfg := m.cfg.Tools["httpx"]
        httpxPath := "httpx"
        if tcfg.Path != "" {
                httpxPath = tcfg.Path
        }

        if !runner.IsAvailable(httpxPath) {
                m.log.ToolSkipped("httpx", fmt.Sprintf("binary '%s' not found in PATH — falling back to curl", httpxPath))
                return m.runCurlFallback(ctx, subs)
        }

        // Show httpx version for debugging
        ver := runner.Version(httpxPath)
        m.log.Debug("httpx version: %s (path: %s)", ver, runner.WhichPath(httpxPath))

        return m.runHttpx(ctx, subs, httpxPath, tcfg)
}

func (m *Module) runHttpx(ctx context.Context, subs []string, path string, tcfg config.ToolConfig) error {
        input := strings.Join(subs, "\n")
        start := time.Now()

        // Minimal safe flag set that works across httpx versions
        args := []string{
                "-silent",
                "-json",
                "-follow-redirects",
                "-threads", "50",
                "-timeout", "10",
                "-retries", "2",
                "-status-code",
                "-title",
                "-web-server",
                "-content-length",
                "-tech-detect",
        }

        m.log.Tool("httpx", fmt.Sprintf("%d subdomains", len(subs)))
        m.log.ToolCmd("httpx", args, fmt.Sprintf("[%d subdomains via stdin]", len(subs)))

        var (
                mu          sync.Mutex
                liveCount   int
                parseErrors int
                httpxErrors []string
        )
        board := m.log.NewProgressBoard()
        board.Register("httpx", fmt.Sprintf("%d subdomains", len(subs)))

        r := runner.Run(ctx, path, args,
                runner.WithStdin(input),
                runner.WithTimeout(time.Duration(tcfg.Timeout)*time.Second),
                runner.WithStderrCallback(func(line string) {
                        // httpx writes non-fatal warnings to stderr — log them as debug
                        m.log.Debug("httpx stderr: %s", line)
                        mu.Lock()
                        httpxErrors = append(httpxErrors, line)
                        mu.Unlock()
                }),
                runner.WithLineCallback(func(line string) {
                        line = strings.TrimSpace(line)
                        if line == "" || !strings.HasPrefix(line, "{") {
                                // httpx sometimes writes banner lines before JSON — skip them
                                m.log.Debug("httpx non-JSON line: %s", line)
                                return
                        }
                        host := parseHTTPXLine(line)
                        if host == nil {
                                parseErrors++
                                m.log.Debug("httpx: failed to parse JSON line: %s", util.Truncate(line, 120))
                                return
                        }
                        m.store.AddHost(host)
                        mu.Lock()
                        liveCount++
                        mu.Unlock()
                        board.Update("httpx", liveCount)
                        m.log.LiveHost(host.Domain, host.StatusCode, host.Title, host.Server)
                }),
        )

        elapsed := time.Since(start)

        if r.IsTimeout() {
                board.Timeout("httpx", liveCount)
                m.log.ToolTimeout("httpx", liveCount, time.Duration(tcfg.Timeout)*time.Second)
        } else if r.Err != nil && liveCount == 0 {
                // httpx exits non-zero when 0 hosts respond — check stderr for real errors
                m.log.ToolError("httpx", fmt.Errorf(r.DiagString()), r.Stderr)
                m.log.Warn("httpx returned 0 live hosts — possible issues:")
                m.log.Warn("  1. All %d subdomains are actually dead/unreachable", len(subs))
                m.log.Warn("  2. httpx flags incompatible with installed version (%s)", runner.Version(path))
                m.log.Warn("  3. Network connectivity issue — try: curl -s https://%s", subs[0])
                m.log.Warn("  Check %s/reconx.log for full stderr output", m.outDir)
        } else {
                board.Done("httpx", liveCount)
                m.log.ToolDone("httpx", liveCount, elapsed)
                if parseErrors > 0 {
                        m.log.Warn("httpx: %d JSON parse errors — check reconx.log for details", parseErrors)
                }
        }

        m.log.Debug("httpx stats: %d probed → %d live (%.1f%% hit rate)",
                len(subs), liveCount, float64(liveCount)/float64(len(subs))*100)

        board.Stop()
        return m.saveAlive()
}

// runCurlFallback probes hosts with curl when httpx isn't installed
func (m *Module) runCurlFallback(ctx context.Context, subs []string) error {
        if !runner.IsAvailable("curl") {
                m.log.Warn("Neither httpx nor curl found — install httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
                return nil
        }

        start := time.Now()
        m.log.Tool("curl-probe", fmt.Sprintf("%d subdomains (concurrency: 30)", len(subs)))

        type probeResult struct {
                domain string
                status int
                server string
        }

        sem     := make(chan struct{}, 30)
        results := make(chan probeResult, len(subs))

        for _, sub := range subs {
                sub := sub
                go func() {
                        sem <- struct{}{}
                        defer func() { <-sem }()

                        for _, scheme := range []string{"https", "http"} {
                                url := scheme + "://" + sub
                                r := runner.Run(ctx, "curl",
                                        []string{
                                                "-s", "-o", "/dev/null",
                                                "-w", "%{http_code}|||%{url_effective}",
                                                "--max-time", "8",
                                                "--connect-timeout", "5",
                                                "-L", "--max-redirs", "3",
                                                "-A", "Mozilla/5.0 (reconx)",
                                                url,
                                        },
                                        runner.WithTimeout(12*time.Second))

                                if r.Err == nil && len(r.Lines) > 0 {
                                        parts := strings.SplitN(r.Lines[0], "|||", 2)
                                        code, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
                                        if code > 0 {
                                                results <- probeResult{domain: sub, status: code}
                                                return
                                        }
                                }
                        }
                        results <- probeResult{}
                }()
        }

        liveCount := 0
        for range subs {
                if res := <-results; res.domain != "" {
                        h := &store.Host{
                                Domain:     res.domain,
                                StatusCode: res.status,
                                Meta:       map[string]string{"url": "https://" + res.domain},
                        }
                        tagHost(h)
                        m.store.AddHost(h)
                        liveCount++
                        m.log.LiveHost(res.domain, res.status, "", "")
                }
        }

        m.log.ToolDone("curl-probe", liveCount, time.Since(start))
        return m.saveAlive()
}

func (m *Module) saveAlive() error {
        hosts := m.store.GetHosts()
        lines := make([]string, 0, len(hosts))
        for _, h := range hosts {
                if url, ok := h.Meta["url"]; ok {
                        lines = append(lines, url)
                } else {
                        lines = append(lines, "https://"+h.Domain)
                }
        }
        if err := store.SaveRaw(m.outDir+"/alive.txt", lines); err != nil {
                m.log.Warn("Failed to save alive.txt: %v", err)
                return err
        }
        m.log.Debug("Saved alive.txt (%d entries)", len(lines))
        return nil
}

// parseHTTPXLine parses a httpx -json output line
// Handles schema differences between httpx versions
func parseHTTPXLine(line string) *store.Host {
        if !strings.Contains(line, "{") {
                return nil
        }

        host := &store.Host{Meta: make(map[string]string)}

        rawURL := firstOf(line, "url", "URL", "input", "Input")
        if rawURL == "" {
                return nil
        }
        host.Meta["url"] = rawURL

        // Clean to hostname
        clean := rawURL
        for _, p := range []string{"https://", "http://"} {
                clean = strings.TrimPrefix(clean, p)
        }
        if idx := strings.IndexAny(clean, "/?#"); idx != -1 {
                clean = clean[:idx]
        }
        if idx := strings.LastIndex(clean, ":"); idx > 0 {
                portStr := clean[idx+1:]
                if p, err := strconv.Atoi(portStr); err == nil {
                        host.Port = p
                        clean = clean[:idx]
                }
        }
        host.Domain = strings.ToLower(strings.TrimSpace(clean))
        if host.Domain == "" {
                return nil
        }

        // Status code — multiple possible field names across versions
        sc := firstOf(line, "status-code", "status_code", "StatusCode", "status")
        host.StatusCode, _ = strconv.Atoi(sc)

        host.Title  = firstOf(line, "title", "Title", "page-title")
        host.Server = firstOf(line, "webserver", "web-server", "server", "Server")
        // httpx JSON: "host" is the input hostname (same as Domain), "a" is the
        // first A-record IP, "ip" is the resolved IP. We want an IP here, not a
        // repeat of the hostname.
        host.IP     = firstOf(line, "a", "ip", "IP")

        // Content length
        cl := firstOf(line, "content-length", "content_length")
        if cl != "" {
                host.Meta["content-length"] = cl
        }

        // Tech stack array
        if idx := strings.Index(line, `"tech":`); idx != -1 {
                rest := line[idx+7:]
                if end := strings.Index(rest, "]"); end != -1 {
                        for _, t := range strings.Split(rest[:end], `"`) {
                                t = strings.Trim(t, `[]," `)
                                if t != "" && t != "null" && t != "," {
                                        host.TechStack = append(host.TechStack, t)
                                }
                        }
                }
        }

        // Technologies (newer httpx field name)
        if idx := strings.Index(line, `"technologies":`); idx != -1 {
                rest := line[idx+15:]
                if end := strings.Index(rest, "]"); end != -1 {
                        for _, t := range strings.Split(rest[:end], `"`) {
                                t = strings.Trim(t, `[]," `)
                                if t != "" && t != "null" {
                                        host.TechStack = append(host.TechStack, t)
                                }
                        }
                }
        }

        tagHost(host)
        return host
}

func tagHost(h *store.Host) {
        switch {
        case h.StatusCode == 403:
                h.Tags = append(h.Tags, "403-bypass-candidate")
        case h.StatusCode == 401:
                h.Tags = append(h.Tags, "auth-required")
        case h.StatusCode >= 500:
                h.Tags = append(h.Tags, "server-error")
        case h.StatusCode == 301 || h.StatusCode == 302:
                h.Tags = append(h.Tags, "redirect")
        case h.StatusCode == 200:
                h.Tags = append(h.Tags, "200-ok")
        }
}

func firstOf(s string, keys ...string) string {
        for _, key := range keys {
                if v := util.JsonStr(s, key); v != "" {
                        return v
                }
        }
        return ""
}
