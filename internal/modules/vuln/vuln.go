package vuln

import (
        "context"
        "fmt"
        "strings"
        "time"

        "github.com/reconx/reconx/internal/config"
        "github.com/reconx/reconx/internal/store"
        "github.com/reconx/reconx/pkg/logger"
        "github.com/reconx/reconx/pkg/runner"
        "github.com/reconx/reconx/pkg/util"
)

type Module struct {
        cfg    *config.Config
        store  *store.Store
        log    *logger.Logger
        outDir string
}

func New(cfg *config.Config, st *store.Store, log *logger.Logger, outDir string) *Module {
        return &Module{cfg: cfg, store: st, log: log, outDir: outDir}
}

func (m *Module) Run(ctx context.Context) error {
        m.log.Phase("Vulnerability Scanning",
                "nuclei templates: exposures, CVEs, misconfigs, takeovers, default-logins")

        start := time.Now()
        hosts := m.store.GetHosts()
        if len(hosts) == 0 {
                m.log.Warn("No live hosts to scan — vuln scanning skipped")
                return nil
        }

        tcfg := m.cfg.Tools["nuclei"]
        nucleiPath := "nuclei"
        if tcfg.Path != "" {
                nucleiPath = tcfg.Path
        }

        if !runner.IsAvailable(nucleiPath) {
                m.log.ToolSkipped("nuclei",
                        "binary not found — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
                m.log.Info("After installing: nuclei -update-templates")
                return nil
        }

        m.log.Debug("nuclei version: %s (path: %s)", runner.Version(nucleiPath), runner.WhichPath(nucleiPath))

        // Build and save target list
        urls := make([]string, 0, len(hosts))
        for _, h := range hosts {
                if u, ok := h.Meta["url"]; ok {
                        urls = append(urls, u)
                } else {
                        urls = append(urls, "https://"+h.Domain)
                }
        }
        targetFile := m.outDir + "/nuclei_targets.txt"
        if err := store.SaveRaw(targetFile, urls); err != nil {
                m.log.Error("Could not write nuclei targets: %v", err)
                return err
        }
        m.log.Info("nuclei targets: %d URLs → %s", len(urls), targetFile)

        // Template categories ordered by speed (fast first)
        categories := []struct {
                name     string
                template string
                timeout  int // per-category timeout in seconds
        }{
                {"tech-detect",    "http/technologies",      120},
                {"exposures",      "http/exposures",          300},
                {"misconfigs",     "http/misconfiguration",   300},
                {"takeovers",      "http/takeovers",          180},
                {"default-logins", "http/default-logins",     300},
                {"cves",           "http/cves",               600},
        }

        totalFindings := 0
        baseArgs := []string{
                "-l", targetFile,
                "-json",
                "-silent",
                "-no-color",
                "-retries", "2",
                "-timeout", "10",
                "-rate-limit", "150",
        }

        // Add custom header if bug bounty program requires it
        if m.cfg.BugBountyHeader != "" {
                baseArgs = append(baseArgs, "-H", m.cfg.BugBountyHeader)
                m.log.Debug("nuclei: adding header %s", m.cfg.BugBountyHeader)
        }

        // Append any config-level nuclei flags
        baseArgs = append(baseArgs, tcfg.Flags...)

        for _, cat := range categories {
                select {
                case <-ctx.Done():
                        m.log.Warn("nuclei: context cancelled — stopping at category %s", cat.name)
                        return ctx.Err()
                default:
                }

                args := append(append([]string{}, baseArgs...), "-t", cat.template)
                m.log.Tool("nuclei:"+cat.name, fmt.Sprintf("%d targets", len(urls)))
                m.log.ToolCmd("nuclei", args, "")

                catStart := time.Now()
                catFindings := 0
                parseErrors := 0

                r := runner.Run(ctx, nucleiPath, args,
                        runner.WithTimeout(time.Duration(cat.timeout)*time.Second),
                        runner.WithStderrCallback(func(line string) {
                                // nuclei writes template loading info to stderr — debug only
                                m.log.Debug("nuclei[%s]: %s", cat.name, util.Truncate(line, 120))
                        }),
                        runner.WithLineCallback(func(line string) {
                                line = strings.TrimSpace(line)
                                if line == "" || !strings.HasPrefix(line, "{") {
                                        return
                                }
                                f := parseNucleiLine(line)
                                if f == nil {
                                        parseErrors++
                                        return
                                }
                                m.store.AddFinding(f)
                                catFindings++
                                totalFindings++
                                m.log.Finding(f.Severity, f.Name, f.Target)
                        }))

                if r.IsTimeout() {
                        m.log.ToolTimeout("nuclei:"+cat.name, catFindings,
                                time.Duration(cat.timeout)*time.Second)
                } else if r.Err != nil && catFindings == 0 {
                        // nuclei returns non-zero when no templates match — not always a real error
                        if len(r.Stderr) > 0 {
                                m.log.ToolError("nuclei:"+cat.name, fmt.Errorf(r.DiagString()), r.Stderr)
                        } else {
                                m.log.Debug("nuclei[%s]: no findings (exit %d)", cat.name, r.ExitCode)
                                m.log.ToolDone("nuclei:"+cat.name, 0, time.Since(catStart))
                        }
                } else {
                        m.log.ToolDone("nuclei:"+cat.name, catFindings, time.Since(catStart))
                }

                if parseErrors > 0 {
                        m.log.Warn("nuclei[%s]: %d JSON parse errors — check reconx.log", cat.name, parseErrors)
                }
        }

        m.log.PhaseComplete("Vulnerability Scanning", totalFindings, time.Since(start))

        if totalFindings > 0 {
                m.logFindingSummary()
                // Save findings.txt for resume support + downstream tools
                lines := make([]string, 0, len(m.store.Findings))
                for _, f := range m.store.Findings {
                        lines = append(lines, fmt.Sprintf("[%s] %s — %s (%s)",
                                strings.ToUpper(f.Severity), f.Name, f.Target, f.Template))
                }
                if err := store.SaveRaw(m.outDir+"/findings.txt", lines); err != nil {
                        m.log.Warn("Could not save findings.txt: %v", err)
                }
        }
        return nil
}

func (m *Module) logFindingSummary() {
        counts := map[string]int{}
        for _, f := range m.store.Findings {
                counts[strings.ToLower(f.Severity)]++
        }
        parts := []string{}
        for _, sev := range []string{"critical", "high", "medium", "low"} {
                if n := counts[sev]; n > 0 {
                        parts = append(parts, fmt.Sprintf("%s:%d", strings.ToUpper(sev), n))
                }
        }
        if len(parts) > 0 {
                m.log.Info("Finding severity breakdown: %s", strings.Join(parts, "  "))
        }
}

func parseNucleiLine(line string) *store.Finding {
        if !strings.Contains(line, "template-id") && !strings.Contains(line, "templateID") {
                return nil
        }

        // Name: prefer info.name over template-id
        name := util.JsonStr(line, "name")
        if name == "" {
                name = util.JsonStr(line, "template-id")
        }
        if name == "" {
                name = util.JsonStr(line, "templateID")
        }
        if name == "" {
                return nil
        }

        severity := strings.ToLower(util.JsonStr(line, "severity"))
        if severity == "" {
                severity = "info"
        }
        // Skip pure info findings to reduce noise
        if severity == "info" {
                return nil
        }

        target := util.JsonStr(line, "matched-at")
        if target == "" {
                target = util.JsonStr(line, "host")
        }
        if target == "" {
                target = util.JsonStr(line, "url")
        }

        return &store.Finding{
                Name:     name,
                Severity: severity,
                Target:   target,
                Template: util.JsonStr(line, "template-id"),
        }
}


