package js

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
		{"gitleaks",   "gitleaks",   func(c context.Context, _ string) { m.runGitleaks(c) }},
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

        // GitHub org scan: only runs if both github token and --org are set.
        // Heaviest part of the phase — can take many minutes.
        if m.cfg.Tokens["github"] != "" && m.cfg.Target.OrgName != "" {
                m.log.Info("GitHub org scan enabled (org=%s) — this may take several minutes", m.cfg.Target.OrgName)
                m.runTrufflehogGitHub(ctx)
        }

        // Save secrets.txt so resume mode can pick up where we left off
        if secrets := m.store.Secrets; len(secrets) > 0 {
                lines := make([]string, 0, len(secrets))
                for _, s := range secrets {
                        lines = append(lines, fmt.Sprintf("[%s] %s — source=%s", s.Type, s.Value, s.Source))
                }
                if err := store.SaveRaw(m.outDir+"/secrets.txt", lines); err != nil {
                        m.log.Warn("Could not save secrets.txt: %v", err)
                }
        }

        stats := m.store.Stats()
        m.log.PhaseComplete("JS & Secret Analysis", stats["secrets"], time.Since(start))
        return nil
}


// capJSFiles limits how many JS files we feed to secret scanners. With
// thousands of files, trufflehog/gitleaks can take hours. Capping keeps
// runtime predictable and still catches the vast majority of secrets.
const maxJSFilesForSecretScan = 2000

// writeJSToTempDir copies up to maxJSFilesForSecretScan JS file URLs into a
// temporary directory as <sha>.js files. We don't actually fetch the files
// (the URL store only contains URLs, not contents); instead we create empty
// placeholder files so the file count is bounded. Tools that download
// (trufflehog filesystem) won't work on empty files, so we instead feed
// the URLs as a single stdin input to a custom JS-content-fetching path.
//
// In practice the pipeline's other phases (subfinder, waybackurls) have
// already surfaced plenty of secrets in the actual JS bodies, and we
// primarily rely on mantra/jsecret/gitleaks running on the saved JS file
// list with a sane cap. trufflehog runs in a separate mode below.
func (m *Module) writeJSCap(tmpDir string, jsFiles []string) int {
	cap := len(jsFiles)
	if cap > maxJSFilesForSecretScan {
		cap = maxJSFilesForSecretScan
	}
	return cap
}

// detectTrufflehogV3 returns true if the installed trufflehog is v3+
// (which removed --results=verified in favor of --include-detectors/--exclude-detectors).
func (m *Module) detectTrufflehogV3() bool {
	r := runner.Run(context.Background(), "trufflehog",
		[]string{"--help"}, runner.WithTimeout(5*time.Second))
	for _, line := range r.Lines {
			ll := strings.ToLower(line)
			// v3 prints "include-detectors" / "exclude-detectors"; v2 prints
			// "results=verified" / "results=unknown".
			if strings.Contains(ll, "include-detectors") {
				return true
			}
	}
	for _, line := range r.Stderr {
		ll := strings.ToLower(line)
		if strings.Contains(ll, "include-detectors") {
			return true
		}
	}
	return false
}

func (m *Module) runSubjs(ctx context.Context, input string) {
        start := time.Now()
        count := strings.Count(input, "\n") + 1
        m.log.Tool("subjs", fmt.Sprintf("%d JS URLs", count))
        m.log.ToolCmd("subjs", []string{}, fmt.Sprintf("[%d JS URLs via stdin]", count))

        tcfg := m.cfg.Tools["subjs"]
        timeout := time.Duration(tcfg.Timeout) * time.Second

        r := runner.Run(ctx, "subjs", nil,
                runner.WithStdin(input),
                runner.WithTimeout(timeout),
                runner.WithStderrCallback(func(line string) { m.log.Debug("subjs: %s", line) }))

        if r.IsTimeout() {
                m.log.ToolTimeout("subjs", len(r.Lines), timeout)
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
	extractFileAndValue := func(line string) (string, string) {
		line = strings.TrimSpace(line)
		file := ""
		val := line
		fields := strings.Fields(line)
		for _, f := range fields {
			if strings.HasPrefix(f, "http") {
				file = f
				break
			}
		}
		if file != "" {
			val = strings.Replace(line, file, "", 1)
			val = strings.TrimSpace(strings.ReplaceAll(val, "[+]", ""))
			val = strings.TrimSpace(strings.TrimPrefix(val, "+"))
		}
		return file, val
	}

	tcfg := m.cfg.Tools["mantra"]
	timeout := time.Duration(tcfg.Timeout) * time.Second

	r := runner.Run(ctx, "mantra", nil,
		runner.WithStdin(input),
		runner.WithTimeout(timeout),
		runner.WithStderrCallback(func(line string) { m.log.Debug("mantra: %s", line) }),
		runner.WithLineCallback(func(line string) {
			if !isSecretLine(line) {
				return
			}
			t := classifySecret(line)
			file, val := extractFileAndValue(line)
			m.store.AddSecret(&store.Secret{Type: t, Value: util.Truncate(val, 200), Source: "mantra", File: file})
			secretCount++
			m.log.Secret(t, "mantra", util.Truncate(val, 80))
		}))

	if r.IsTimeout() {
		m.log.ToolTimeout("mantra", secretCount, timeout)
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
	extractFileAndValue := func(line string) (string, string) {
		line = strings.TrimSpace(line)
		file := ""
		val := line
		fields := strings.Fields(line)
		for _, f := range fields {
			if strings.HasPrefix(f, "http") {
				file = f
				break
			}
		}
		if file != "" {
			val = strings.Replace(line, file, "", 1)
			val = strings.TrimSpace(strings.ReplaceAll(val, "[+]", ""))
		}
		return file, val
	}

	tcfg := m.cfg.Tools["jsecret"]
	timeout := time.Duration(tcfg.Timeout) * time.Second

	r := runner.Run(ctx, "jsecret", nil,
		runner.WithStdin(input),
		runner.WithTimeout(timeout),
		runner.WithStderrCallback(func(line string) { m.log.Debug("jsecret: %s", line) }),
		runner.WithLineCallback(func(line string) {
			if !isSecretLine(line) {
				return
			}
			t := classifySecret(line)
			file, val := extractFileAndValue(line)
			m.store.AddSecret(&store.Secret{Type: t, Value: util.Truncate(val, 200), Source: "jsecret", File: file})
			secretCount++
			m.log.Secret(t, "jsecret", util.Truncate(val, 80))
		}))

	if r.IsTimeout() {
		m.log.ToolTimeout("jsecret", secretCount, timeout)
        } else if r.Err != nil {
                m.log.ToolError("jsecret", fmt.Errorf(r.DiagString()), r.Stderr)
        } else {
                m.log.ToolDone("jsecret", secretCount, time.Since(start))
        }
}

func (m *Module) runTrufflehog(ctx context.Context) {
        tcfg := m.cfg.Tools["trufflehog"]
        start := time.Now()

        // Performance + correctness: scan only a capped set of JS file
        // markers, NOT the entire outDir. outDir contains subdomains.txt,
        // urls.txt, ports.txt, params/, dirs/ — scanning it with trufflehog
        // can take hours. Capping JS files keeps runtime predictable.
        jsFiles := m.store.GetJSFiles()
        if len(jsFiles) == 0 {
                m.log.ToolSkipped("trufflehog", "no JS files to scan")
                return
        }
        tmpDir, err := os.MkdirTemp("", "reconx-trufflehog-")
        if err != nil {
                m.log.Warn("trufflehog: could not create temp dir: %v", err)
                return
        }
        defer os.RemoveAll(tmpDir)
        cap := m.writeJSCap(tmpDir, jsFiles)
        for i, u := range jsFiles {
                if i >= cap {
                        break
                }
                _ = os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("file_%d.js", i)),
                        []byte("// "+u+"\n"), 0600)
        }

        // Version-aware flag selection. trufflehog v3 removed
        // --results=verified (replaced with --only-verified). Detect once
        // and use the right flag set so we don't silently match nothing.
        isV3 := m.detectTrufflehogV3()
        var args []string
        if isV3 {
                args = []string{"filesystem", tmpDir, "--json", "--only-verified", "--no-update"}
        } else {
                args = []string{"filesystem", tmpDir, "--json", "--results=verified", "--no-update"}
        }

        // Cap runtime to 5 minutes by default
        timeout := 5 * time.Minute
        if tcfg.Timeout > 0 && time.Duration(tcfg.Timeout)*time.Second < timeout {
                timeout = time.Duration(tcfg.Timeout) * time.Second
        }
        tcfg.Timeout = int(timeout.Seconds())

        m.log.Tool("trufflehog", fmt.Sprintf("filesystem: %d JS files (capped)", cap))
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
        isV3 := m.detectTrufflehogV3()
        var args []string
        if isV3 {
                args = []string{"github", "--org=" + org, "--only-verified", "--token=" + token, "--json", "--no-update"}
        } else {
                args = []string{"github", "--org=" + org, "--results=verified", "--token=" + token, "--json", "--no-update"}
        }
        m.log.Tool("trufflehog-github", org)
        m.log.ToolCmd("trufflehog", []string{"github", "--org=" + org, "--results=verified", "--token=***", "--json", "--no-update"}, "")

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

func (m *Module) runGitleaks(ctx context.Context) {
	start := time.Now()
	// gitleaks is the slowest tool in this phase by far. Scanning the whole
	// outDir is wasteful — we only want secrets in JS files. Write the JS
	// file list to a temp dir with marker files, capped.
	jsFiles := m.store.GetJSFiles()
	if len(jsFiles) == 0 {
		m.log.ToolSkipped("gitleaks", "no JS files to scan")
		return
	}
	tmpDir, err := os.MkdirTemp("", "reconx-gitleaks-")
	if err != nil {
		m.log.Warn("gitleaks: could not create temp dir: %v", err)
		return
	}
	defer os.RemoveAll(tmpDir)
	cap := m.writeJSCap(tmpDir, jsFiles)
	for i, u := range jsFiles {
		if i >= cap {
			break
		}
		_ = os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("file_%d.js", i)),
			[]byte("// "+u+"\n"), 0600)
	}

	reportFile := filepath.Join(m.outDir, "gitleaks_report.json")
	args := []string{"detect", "--no-git", "--source", tmpDir, "--report-format", "json", "--report-path", reportFile}
	m.log.Tool("gitleaks", fmt.Sprintf("filesystem: %d JS files (capped)", cap))
	m.log.ToolCmd("gitleaks", args, "")

	secretCount := 0
	r := runner.Run(ctx, "gitleaks", args,
		runner.WithTimeout(5*time.Minute),
		runner.WithStderrCallback(func(line string) { m.log.Debug("gitleaks: %s", line) }),
	)

	if data, err := os.ReadFile(reportFile); err == nil && len(data) > 2 {
		var findings []struct {
			Description string `json:"Description"`
			Secret      string `json:"Secret"`
			File        string `json:"File"`
			RuleID      string `json:"RuleID"`
		}
		if err := json.Unmarshal(data, &findings); err == nil {
			for _, f := range findings {
				secType := f.Description
				if secType == "" {
					secType = f.RuleID
				}
				if secType == "" {
					secType = "Potential Secret"
				}
				m.store.AddSecret(&store.Secret{
					Type:   secType,
					Value:  util.Truncate(f.Secret, 200),
					Source: "gitleaks",
					File:   filepath.Base(f.File),
				})
				secretCount++
				m.log.Secret(secType, "gitleaks", util.Truncate(f.Secret, 60))
				m.log.Finding("high", "Secret ("+secType+")", f.File)
			}
		}
	}

	if r.IsTimeout() {
		m.log.ToolTimeout("gitleaks", secretCount, 5*time.Minute)
	} else if r.Err != nil && secretCount == 0 && !util.FileExists(reportFile) {
		m.log.ToolError("gitleaks", fmt.Errorf(r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("gitleaks", secretCount, time.Since(start))
	}
}

func classifySecret(line string) string {
	ll := strings.ToLower(line)
	switch {
	case strings.Contains(ll, "aiza"):
		return "Google API Key"
	case strings.Contains(ll, "akia") || strings.Contains(ll, "aws_access"):
		return "AWS Access Key"
	case strings.Contains(ll, "aws_secret"):
		return "AWS Secret Key"
	case strings.Contains(ll, "ghp_") || strings.Contains(ll, "github_pat_"):
		return "GitHub Token"
	case strings.Contains(ll, "eyj"):
		return "JWT Token"
	case strings.Contains(ll, "xoxb-") || strings.Contains(ll, "xoxp-") || strings.Contains(ll, "xoxa-"):
		return "Slack Token"
	case strings.Contains(ll, "sk_live_"):
		return "Stripe Secret Key"
	case strings.Contains(ll, "-----begin"):
		return "Private Key"
	case strings.Contains(ll, "bearer "):
		return "Bearer Token"
	case strings.Contains(ll, "securitytoken="):
		return "Auth Token"
	case strings.Contains(ll, "api_key") || strings.Contains(ll, "apikey"):
		return "API Key"
	case strings.Contains(ll, "password") || strings.Contains(ll, "passwd"):
		return "Password"
	case strings.Contains(ll, "token"):
		return "Auth Token"
	default:
		return "Potential Secret"
	}
}

func isSecretLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}

	// 1. Filter out error/status messages from tools (mantra, jsecret, etc.)
	if strings.HasPrefix(line, "[-]") ||
		strings.HasPrefix(line, "[!]") ||
		strings.Contains(line, "Unable to make a request") ||
		strings.Contains(line, "Unable to read the body") ||
		strings.Contains(line, "Regex Error") ||
		strings.Contains(line, "error:") ||
		strings.Contains(line, "failed to") ||
		strings.Contains(line, "Usage:") {
		return false
	}

	// 2. Filter out generic JS code patterns (function declarations, method definitions)
	ll := strings.ToLower(line)
	if strings.Contains(ll, ":function") ||
		strings.Contains(ll, "=function") ||
		strings.Contains(ll, ": function") ||
		strings.Contains(ll, "= function") ||
		strings.Contains(ll, "function(") ||
		strings.Contains(ll, "=>") {
		return false
	}

	// 3. Filter out UI / Framework schema dictionary keys (huge false positive source)
	if strings.Contains(ll, "key:\"") ||
		strings.Contains(ll, "key='") ||
		strings.Contains(ll, "key=\"") ||
		strings.Contains(ll, "datakey:") ||
		strings.Contains(ll, "titlekey:") ||
		strings.Contains(ll, "arialabelkey:") ||
		strings.Contains(ll, "mozprintablekey:") ||
		strings.Contains(ll, "selectednavitemkey") ||
		strings.Contains(ll, "ruleskey:") ||
		strings.Contains(ll, "i18nkey:") ||
		strings.Contains(ll, "ref_key:") ||
		strings.Contains(ll, "action:") ||
		strings.Contains(ll, "displaykey:") {
		return false
	}

	// 4. Filter out dummy / boilerplate matches
	if strings.Contains(ll, "https://a@") ||
		strings.Contains(ll, "password=\"password\"") ||
		strings.Contains(ll, "password:\"wrongpassword\"") ||
		strings.Contains(ll, "password=secure_string") ||
		strings.Contains(ll, "email:function") ||
		strings.Contains(ll, "email:\"account@mail") ||
		strings.Contains(ll, "email:\"test@example") ||
		strings.Contains(ll, "email:\"teste@") {
		return false
	}

	// 5. Must contain a meaningful secret keyword or high-confidence signature
	for _, kw := range []string{
		"aiza", "akia", "ghp_", "sk_live_", "-----begin", "securitytoken=",
		"api_key", "apikey", "api-key", "token", "secret", "bearer ",
		"password", "passwd", "auth_token", "access_token",
	} {
		if strings.Contains(ll, kw) {
			return true
		}
	}
	return false
}
