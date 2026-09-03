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

	// Build target lists separated by WAF status
	allURLs := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if u, ok := h.Meta["url"]; ok {
			allURLs = append(allURLs, u)
		} else {
			allURLs = append(allURLs, "https://"+h.Domain)
		}
	}

	dataDir := store.DataDir(m.outDir)
	wafURLs, nowafURLs := m.store.SplitURLsByWAF(allURLs)

	// Save targets in data/
	targetFileNoWAF := dataDir + "/nuclei_targets_nowaf.txt"
	targetFileWAF := dataDir + "/nuclei_targets_waf.txt"
	_ = store.SaveRaw(targetFileNoWAF, nowafURLs)
	_ = store.SaveRaw(targetFileWAF, wafURLs)
	_ = store.SaveRaw(dataDir+"/nuclei_targets_all.txt", allURLs)

	m.log.Info("nuclei targets — non-WAF: %d URLs (fast) | WAF-protected: %d URLs (stealth)",
		len(nowafURLs), len(wafURLs))

	// Template categories ordered by speed (fast first)
	categories := []struct {
		name     string
		template string
		timeout  int // per-category timeout in seconds
	}{
		{"tech-detect", "http/technologies", 120},
		{"exposures", "http/exposures", 300},
		{"misconfigs", "http/misconfiguration", 300},
		{"takeovers", "http/takeovers", 180},
		{"default-logins", "http/default-logins", 300},
		{"cves", "http/cves", 600},
	}

	totalFindings := 0

	type targetGroup struct {
		label      string
		targetFile string
		count      int
		rateLimit  string
		retries    string
		timeoutSec string
	}

	groups := []targetGroup{
		{label: "non-waf", targetFile: targetFileNoWAF, count: len(nowafURLs), rateLimit: "150", retries: "2", timeoutSec: "10"},
		{label: "waf", targetFile: targetFileWAF, count: len(wafURLs), rateLimit: "30", retries: "1", timeoutSec: "15"},
	}

	for _, g := range groups {
		if g.count == 0 {
			continue
		}

		m.log.Info("Running nuclei on %s targets (%d endpoints, rate-limit: %s)...", g.label, g.count, g.rateLimit)

		baseArgs := []string{
			"-l", g.targetFile,
			"-jsonl",
			"-silent",
			"-no-color",
			"-retries", g.retries,
			"-timeout", g.timeoutSec,
			"-rate-limit", g.rateLimit,
		}

		if m.cfg.BugBountyHeader != "" {
			baseArgs = append(baseArgs, "-H", m.cfg.BugBountyHeader)
		}
		baseArgs = append(baseArgs, tcfg.Flags...)

		for _, cat := range categories {
			select {
			case <-ctx.Done():
				m.log.Warn("nuclei: context cancelled — stopping at category %s (%s)", cat.name, g.label)
				return ctx.Err()
			default:
			}

			args := append(append([]string{}, baseArgs...), "-t", cat.template)
			toolTag := fmt.Sprintf("nuclei:%s:%s", g.label, cat.name)
			m.log.Tool(toolTag, fmt.Sprintf("%d targets", g.count))
			m.log.ToolCmd("nuclei", args, "")

			catStart := time.Now()
			catFindings := 0
			parseErrors := 0

			r := runner.Run(ctx, nucleiPath, args,
				runner.WithTimeout(time.Duration(cat.timeout)*time.Second),
				runner.WithStderrCallback(func(line string) {
					m.log.Debug("nuclei[%s/%s]: %s", g.label, cat.name, util.Truncate(line, 120))
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
				m.log.ToolTimeout(toolTag, catFindings, time.Duration(cat.timeout)*time.Second)
			} else if r.Err != nil && catFindings == 0 {
				if len(r.Stderr) > 0 {
					m.log.ToolError(toolTag, fmt.Errorf(r.DiagString()), r.Stderr)
				} else {
					m.log.Debug("nuclei[%s/%s]: no findings (exit %d)", g.label, cat.name, r.ExitCode)
					m.log.ToolDone(toolTag, 0, time.Since(catStart))
				}
			} else {
				m.log.ToolDone(toolTag, catFindings, time.Since(catStart))
			}

			if parseErrors > 0 {
				m.log.Warn("nuclei[%s/%s]: %d JSON parse errors", g.label, cat.name, parseErrors)
			}
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
        for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
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
        // Note: we no longer skip info-severity findings.
        // Tech-detect template results are info level but important for the report.

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


