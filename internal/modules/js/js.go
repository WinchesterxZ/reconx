package js

import (
        "context"
        "fmt"
        "strings"
        "sync"
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
        m.log.Phase("JS & Secret Analysis",
                "Scanning JS files for secrets, API keys, tokens, and hidden endpoints")

        start := time.Now()
        jsFiles := m.store.GetJSFiles()

        if len(jsFiles) == 0 {
                m.log.Warn("No JS files discovered — check that URL discovery ran and found JS files")
                m.log.Warn("Tip: ensure waybackurls/katana/hakrawler are installed and live hosts exist")
                return nil
        }

        m.log.Info("Analyzing %d JavaScript files", len(jsFiles))
        if err := store.SaveRaw(m.outDir+"/js_files.txt", jsFiles); err != nil {
                m.log.Warn("Could not save js_files.txt: %v", err)
        }

        input := strings.Join(jsFiles, "\n")

        type jsTool struct {
                name   string
                binKey string
                fn     func(context.Context, string)
        }

        tools := []jsTool{
                {"subjs",      "subjs",      m.runSubjs},
                {"mantra",     "mantra",     m.runMantra},
                {"jsecret",    "jsecret",    m.runJsecret},
                {"trufflehog", "trufflehog", func(c context.Context, _ string) { m.runTrufflehog(c) }},
        }

        var wg sync.WaitGroup
        anyRan := false

        for _, t := range tools {
                t := t
                if !runner.IsAvailable(t.binKey) {
                        m.log.ToolSkipped(t.name,
                                fmt.Sprintf("not in PATH — install: go install github.com/.../%s@latest", t.binKey))
                        continue
                }
                m.log.Debug("%s found at %s (version: %s)", t.name, runner.WhichPath(t.binKey), runner.Version(t.binKey))
                anyRan = true
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        t.fn(ctx, input)
                }()
        }

        if !anyRan {
                m.log.Warn("No JS analysis tools available — run: bash install.sh")
        }

        wg.Wait()

        // GitHub org scan via trufflehog if token + org are set
        if m.cfg.Tokens["github"] != "" && m.cfg.Target.OrgName != "" {
                m.runTrufflehogGitHub(ctx)
        }

        stats := m.store.Stats()
        m.log.PhaseComplete("JS & Secret Analysis", stats["secrets"], time.Since(start))
        return nil
}

func (m *Module) runSubjs(ctx context.Context, input string) {
        start := time.Now()
        count := strings.Count(input, "\n") + 1
        m.log.Tool("subjs", fmt.Sprintf("%d JS URLs", count))
        m.log.ToolCmd("subjs", []string{}, fmt.Sprintf("[%d JS URLs via stdin]", count))

        r := runner.Run(ctx, "subjs", nil,
                runner.WithStdin(input),
                runner.WithTimeout(5*time.Minute),
                runner.WithStderrCallback(func(line string) { m.log.Debug("subjs: %s", line) }))

        if r.IsTimeout() {
                m.log.ToolTimeout("subjs", len(r.Lines), 5*time.Minute)
        } else if r.Err != nil && len(r.Lines) == 0 {
                m.log.ToolError("subjs", fmt.Errorf(r.DiagString()), r.Stderr)
                return
        }

        newJS := 0
        for _, line := range r.Lines {
                line = strings.TrimSpace(line)
                if strings.HasPrefix(line, "http") && strings.Contains(strings.ToLower(line), ".js") {
                        if m.store.AddJSFile(line) {
                                newJS++
                        }
                }
        }
        m.log.ToolDone("subjs", len(r.Lines), time.Since(start))
        if newJS > 0 {
                m.log.Info("subjs: discovered %d additional JS files (added to analysis queue)", newJS)
        }
}

func (m *Module) runMantra(ctx context.Context, input string) {
        start := time.Now()
        count := strings.Count(input, "\n") + 1
        m.log.Tool("mantra", fmt.Sprintf("%d JS files — pattern matching", count))
        m.log.ToolCmd("mantra", []string{}, fmt.Sprintf("[%d URLs via stdin]", count))

        secretCount := 0
        r := runner.Run(ctx, "mantra", nil,
                runner.WithStdin(input),
                runner.WithTimeout(5*time.Minute),
                runner.WithStderrCallback(func(line string) { m.log.Debug("mantra: %s", line) }),
                runner.WithLineCallback(func(line string) {
                        if !isSecretLine(line) {
                                return
                        }
                        t := classifySecret(line)
                        m.store.AddSecret(&store.Secret{Type: t, Value: util.Truncate(line, 200), Source: "mantra"})
                        secretCount++
                        m.log.Secret(t, "mantra", util.Truncate(line, 80))
                }))

        if r.IsTimeout() {
                m.log.ToolTimeout("mantra", secretCount, 5*time.Minute)
        } else if r.Err != nil {
                m.log.ToolError("mantra", fmt.Errorf(r.DiagString()), r.Stderr)
        } else {
                m.log.ToolDone("mantra", secretCount, time.Since(start))
                m.log.Debug("mantra: scanned %d lines total, %d matched secret patterns", len(r.Lines), secretCount)
        }
}

func (m *Module) runJsecret(ctx context.Context, input string) {
        start := time.Now()
        count := strings.Count(input, "\n") + 1
        m.log.Tool("jsecret", fmt.Sprintf("%d JS files", count))
        m.log.ToolCmd("jsecret", []string{}, fmt.Sprintf("[%d URLs via stdin]", count))

        secretCount := 0
        r := runner.Run(ctx, "jsecret", nil,
                runner.WithStdin(input),
                runner.WithTimeout(5*time.Minute),
                runner.WithStderrCallback(func(line string) { m.log.Debug("jsecret: %s", line) }),
                runner.WithLineCallback(func(line string) {
                        if !isSecretLine(line) {
                                return
                        }
                        t := classifySecret(line)
                        m.store.AddSecret(&store.Secret{Type: t, Value: util.Truncate(line, 200), Source: "jsecret"})
                        secretCount++
                        m.log.Secret(t, "jsecret", util.Truncate(line, 80))
                }))

        if r.IsTimeout() {
                m.log.ToolTimeout("jsecret", secretCount, 5*time.Minute)
        } else if r.Err != nil {
                m.log.ToolError("jsecret", fmt.Errorf(r.DiagString()), r.Stderr)
        } else {
                m.log.ToolDone("jsecret", secretCount, time.Since(start))
        }
}

func (m *Module) runTrufflehog(ctx context.Context) {
        tcfg := m.cfg.Tools["trufflehog"]
        start := time.Now()
        args := []string{"filesystem", m.outDir, "--json", "--results=verified"}
        m.log.Tool("trufflehog", fmt.Sprintf("filesystem: %s", m.outDir))
        m.log.ToolCmd("trufflehog", args, "")

        secretCount := 0
        r := runner.Run(ctx, tcfg.Path, args,
                runner.WithTimeout(time.Duration(tcfg.Timeout)*time.Second),
                runner.WithStderrCallback(func(line string) { m.log.Debug("trufflehog: %s", line) }),
                runner.WithLineCallback(func(line string) {
                        if !strings.Contains(line, `"Verified":true`) && !strings.Contains(line, `"verified":true`) {
                                return
                        }
                        t := util.JsonStr(line, "DetectorName")
                        if t == "" {
                                t = util.JsonStr(line, "detector_name")
                        }
                        if t == "" {
                                t = "unknown"
                        }
                        raw := util.JsonStr(line, "Raw")
                        if raw == "" {
                                raw = util.Truncate(line, 200)
                        }
                        m.store.AddSecret(&store.Secret{Type: t, Value: util.Truncate(raw, 200), Source: "trufflehog"})
                        secretCount++
                        m.log.Secret(t, "trufflehog (verified)", util.Truncate(raw, 60))
                        m.log.Finding("critical", "Verified Secret: "+t, "trufflehog")
                }))

        if r.IsTimeout() {
                m.log.ToolTimeout("trufflehog", secretCount, time.Duration(tcfg.Timeout)*time.Second)
        } else if r.Err != nil && secretCount == 0 {
                m.log.ToolError("trufflehog", fmt.Errorf(r.DiagString()), r.Stderr)
        } else {
                m.log.ToolDone("trufflehog", secretCount, time.Since(start))
                m.log.Debug("trufflehog: processed %d scan lines, %d verified secrets", len(r.Lines), secretCount)
        }
}

func (m *Module) runTrufflehogGitHub(ctx context.Context) {
        if !runner.IsAvailable("trufflehog") {
                return
        }
        start := time.Now()
        org := m.cfg.Target.OrgName
        token := m.cfg.Tokens["github"]
        args := []string{"github", "--org=" + org, "--results=verified", "--json"}

        m.log.Tool("trufflehog-github", org)
        m.log.ToolCmd("trufflehog", []string{"github", "--org=" + org, "--results=verified", "--token=***", "--json"}, "")

        secretCount := 0
        r := runner.Run(ctx, "trufflehog", args,
                runner.WithEnv([]string{"GITHUB_TOKEN=" + token}),
                runner.WithTimeout(10*time.Minute),
                runner.WithStderrCallback(func(line string) { m.log.Debug("trufflehog-github: %s", line) }),
                runner.WithLineCallback(func(line string) {
                        if !strings.Contains(line, `"Verified":true`) {
                                return
                        }
                        t := util.JsonStr(line, "DetectorName")
                        if t == "" {
                                t = "github-secret"
                        }
                        m.store.AddSecret(&store.Secret{Type: t, Value: util.Truncate(line, 200), Source: "trufflehog-github"})
                        secretCount++
                        m.log.Secret(t, "trufflehog-github", org)
                        m.log.Finding("critical", "Verified GitHub Secret: "+t, org)
                }))

        if r.IsTimeout() {
                m.log.ToolTimeout("trufflehog-github", secretCount, 10*time.Minute)
        } else if r.Err != nil && secretCount == 0 {
                m.log.ToolError("trufflehog-github", fmt.Errorf(r.DiagString()), r.Stderr)
        } else {
                m.log.ToolDone("trufflehog-github", secretCount, time.Since(start))
        }
}

func classifySecret(line string) string {
        ll := strings.ToLower(line)
        switch {
        case strings.Contains(ll, "akia") || strings.Contains(ll, "aws_access"):
                return "AWS Access Key"
        case strings.Contains(ll, "aws_secret"):
                return "AWS Secret Key"
        case strings.Contains(ll, "ghp_"):
                return "GitHub Token"
        case strings.Contains(ll, "eyj"):
                return "JWT Token"
        case strings.Contains(ll, "xox"):
                return "Slack Token"
        case strings.Contains(ll, "aiza"):
                return "Google API Key"
        case strings.Contains(ll, "sk_live"):
                return "Stripe Secret Key"
        case strings.Contains(ll, "-----begin"):
                return "Private Key"
        case strings.Contains(ll, "password") || strings.Contains(ll, "passwd"):
                return "Password"
        case strings.Contains(ll, "api_key") || strings.Contains(ll, "apikey"):
                return "API Key"
        case strings.Contains(ll, "token"):
                return "Auth Token"
        default:
                return "Potential Secret"
        }
}

func isSecretLine(line string) bool {
        ll := strings.ToLower(line)
        for _, kw := range []string{
                "api_key", "apikey", "api-key", "token", "secret",
                "password", "passwd", "auth", "credential", "bearer",
                "akia", "eyj", "private", "-----begin", "xox", "ghp_",
                "sk_live", "sg.", "aiza",
        } {
                if strings.Contains(ll, kw) {
                        return true
                }
        }
        return false
}
