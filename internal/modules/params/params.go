package params

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
)

// Module discovers hidden GET/POST/JSON parameters using multiple tools.
type Module struct {
	cfg    *config.Config
	store  *store.Store
	log    *logger.Logger
	outDir string
}

// New creates a parameter discovery module
func New(cfg *config.Config, st *store.Store, log *logger.Logger, outDir string) *Module {
	return &Module{cfg: cfg, store: st, log: log, outDir: outDir}
}

// Run scans live URLs for hidden parameters using arjun + dalfox in parallel.
func (m *Module) Run(ctx context.Context) error {
	m.log.Phase("Hidden Parameter Discovery",
"arjun (GET/POST/JSON brute), dalfox (param analysis), getJS (JS param extraction)")

	paramsDir := filepath.Join(m.outDir, "params")
	if err := os.MkdirAll(paramsDir, 0755); err != nil {
		m.log.Warn("Could not create params/ directory: %v", err)
	}

	// Build smart target list: prioritize URLs with existing params, then API endpoints
	targetURLs := m.buildTargetList(500)

	if len(targetURLs) == 0 {
		m.log.Warn("No URLs or live hosts to test for parameters")
		return nil
	}

	targetsFile := filepath.Join(paramsDir, "targets.txt")
	if err := store.SaveRaw(targetsFile, targetURLs); err != nil {
		m.log.Warn("Could not save targets.txt: %v", err)
		return err
	}

	m.log.Info("Parameter discovery: %d target endpoints selected", len(targetURLs))

	start := time.Now()
	total := 0
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Tool 1: arjun
	if runner.IsAvailable("arjun") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := m.runArjun(ctx, targetsFile, paramsDir)
			mu.Lock()
			total += n
			mu.Unlock()
		}()
	} else {
		m.log.ToolSkipped("arjun", "not found — install: pip3 install arjun")
	}

	// Tool 2: dalfox --only-discovery
	if runner.IsAvailable("dalfox") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := m.runDalfox(ctx, targetURLs, paramsDir)
			mu.Lock()
			total += n
			mu.Unlock()
		}()
	} else {
		m.log.ToolSkipped("dalfox", "not found — install: go install github.com/hahwul/dalfox/v2@latest")
	}

	// Tool 3: getJS — extract endpoints from JS files
	if runner.IsAvailable("getJS") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := m.runGetJS(ctx, paramsDir)
			mu.Lock()
			total += n
			mu.Unlock()
		}()
	} else {
		m.log.ToolSkipped("getJS", "not found — install: go install github.com/003random/getJS@latest")
	}

	wg.Wait()

	m.log.PhaseComplete("Hidden Parameter Discovery", total, time.Since(start))
	return nil
}

// runArjun runs arjun against a file of target URLs.
func (m *Module) runArjun(ctx context.Context, targetsFile, paramsDir string) int {
	tcfg := m.cfg.Tools["arjun"]
	path := "arjun"
	if tcfg.Path != "" {
		path = tcfg.Path
	}

	outFile := filepath.Join(paramsDir, "arjun_results.json")
	args := []string{
		"-i", targetsFile,
		"-oJ", outFile,
		"-t", "5",
		"--stable",
	}

	// Inject bug bounty header
	if m.cfg.BugBountyHeader != "" {
		args = append(args, "--headers", m.cfg.BugBountyHeader)
	}

	// Extra user flags (no-dup guard)
	seen := make(map[string]bool)
	for _, a := range args {
		seen[a] = true
	}
	for _, f := range tcfg.Flags {
		if !seen[f] {
			args = append(args, f)
			seen[f] = true
		}
	}

	timeout := time.Duration(tcfg.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Minute
	}

	m.log.Tool("arjun", fmt.Sprintf("%d endpoints → %s", countLines(targetsFile), outFile))
	m.log.ToolCmd("arjun", args, "")
	start := time.Now()

	board := m.log.NewProgressBoard()
	board.Register("arjun", fmt.Sprintf("%d endpoints", countLines(targetsFile)))

	r := runner.Run(ctx, path, args,
		runner.WithTimeout(timeout),
		runner.WithLineCallback(func(line string) { board.Heartbeat("arjun") }),
		runner.WithStderrCallback(func(line string) {
			m.log.Debug("arjun: %s", line)
			board.Heartbeat("arjun")
		}),
	)

	totalParams := 0
	if data, err := os.ReadFile(outFile); err == nil && len(data) > 2 {
		totalParams = m.parseArjunResults(data)
	} else if r.Err != nil && totalParams == 0 {
		m.log.ToolError("arjun", fmt.Errorf(r.DiagString()), r.Stderr)
	}

	board.Done("arjun", totalParams)
	board.Stop()
	m.log.ToolDone("arjun", totalParams, time.Since(start))
	return totalParams
}

// parseArjunResults handles multiple arjun JSON output formats.
// Format A (current): {"https://url": {"params": ["p1","p2"], "method":"GET"}}
// Format B (older):   {"https://url": {"params": {"GET": ["p1","p2"]}}}
func (m *Module) parseArjunResults(data []byte) int {
	total := 0

	// Format A
	var formatA map[string]struct {
		Params []string `json:"params"`
		Method string   `json:"method"`
	}
	if err := json.Unmarshal(data, &formatA); err == nil {
		for u, pData := range formatA {
			if len(pData.Params) == 0 {
				continue
			}
			method := pData.Method
			if method == "" {
				method = "GET"
			}
			m.store.AddParamFinding(&store.ParamFinding{
				URL:    u,
				Method: method,
				Params: pData.Params,
				Tool:   "arjun",
			})
			total += len(pData.Params)
			m.log.Info("  [Param/arjun] %s → %s (%s)", u, strings.Join(pData.Params, ", "), method)
		}
		if total > 0 {
			return total
		}
	}

	// Format B — nested by method
	var formatB map[string]struct {
		Params map[string][]string `json:"params"`
	}
	if err := json.Unmarshal(data, &formatB); err == nil {
		for u, pData := range formatB {
			for method, params := range pData.Params {
				if len(params) == 0 {
					continue
				}
				m.store.AddParamFinding(&store.ParamFinding{
					URL:    u,
					Method: method,
					Params: params,
					Tool:   "arjun",
				})
				total += len(params)
				m.log.Info("  [Param/arjun] %s → %s (%s)", u, strings.Join(params, ", "), method)
			}
		}
	}

	if total == 0 {
		m.log.Warn("arjun: could not parse results — raw output saved in params/arjun_results.json")
	}
	return total
}

// runDalfox runs dalfox in --only-discovery mode (param analysis, no XSS payloads).
func (m *Module) runDalfox(ctx context.Context, urls []string, paramsDir string) int {
	outFile := filepath.Join(paramsDir, "dalfox_params.txt")

	args := []string{
		"pipe",
		"--only-discovery",
		"--no-color",
		"--format", "json",
		"-o", outFile,
	}
	if m.cfg.BugBountyHeader != "" {
		args = append(args, "-H", m.cfg.BugBountyHeader)
	}

	input := strings.Join(urls, "\n")
	timeout := 15 * time.Minute

	m.log.Tool("dalfox", fmt.Sprintf("%d URLs — param analysis only", len(urls)))
	m.log.ToolCmd("dalfox", args, fmt.Sprintf("[%d URLs via stdin]", len(urls)))
	start := time.Now()

	count := 0
	r := runner.Run(ctx, "dalfox", args,
		runner.WithStdin(input),
		runner.WithTimeout(timeout),
		runner.WithStderrCallback(func(line string) { m.log.Debug("dalfox: %s", line) }),
		runner.WithLineCallback(func(line string) {
			line = strings.TrimSpace(line)
			if line == "" || !strings.HasPrefix(line, "{") {
				return
			}
			// dalfox JSON: {"type":"POC","method":"GET","param":"name","url":"..."}
			paramName := jsonStr(line, "param")
			targetURL := jsonStr(line, "url")
			method := jsonStr(line, "method")
			if paramName == "" || targetURL == "" {
				return
			}
			m.store.AddParamFinding(&store.ParamFinding{
				URL:    targetURL,
				Method: method,
				Params: []string{paramName},
				Tool:   "dalfox",
			})
			count++
			m.log.Info("  [Param/dalfox] %s → %s (%s)", targetURL, paramName, method)
		}),
	)

	if r.IsTimeout() {
		m.log.ToolTimeout("dalfox", count, timeout)
	} else if r.Err != nil && count == 0 && !strings.Contains(strings.Join(r.Stderr, " "), "UNREACHABLE") {
		m.log.ToolError("dalfox", fmt.Errorf(r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("dalfox", count, time.Since(start))
	}
	return count
}

// runGetJS extracts hidden endpoint URLs from JS files.
func (m *Module) runGetJS(ctx context.Context, paramsDir string) int {
	jsFiles := m.store.GetJSFiles()
	if len(jsFiles) == 0 {
		m.log.Debug("getJS: no JS files in store, skipping")
		return 0
	}

	tmpFile, err := os.CreateTemp("", "getjs-input-*.txt")
	if err != nil {
		m.log.Warn("getJS: could not create temp file: %v", err)
		return 0
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.WriteString(strings.Join(jsFiles, "\n")); err != nil {
		tmpFile.Close()
		return 0
	}
	tmpFile.Close()

	outFile := filepath.Join(paramsDir, "getjs_endpoints.txt")
	args := []string{"-input", tmpFile.Name(), "-output", outFile, "-complete", "-resolve"}
	if m.cfg.BugBountyHeader != "" {
		args = append(args, "-header", m.cfg.BugBountyHeader)
	}

	m.log.Tool("getJS", fmt.Sprintf("%d JS files — extracting endpoint URLs", len(jsFiles)))
	m.log.ToolCmd("getJS", args, "")
	start := time.Now()

	r := runner.Run(ctx, "getJS", args,
		runner.WithTimeout(10*time.Minute),
		runner.WithStderrCallback(func(line string) { m.log.Debug("getJS: %s", line) }),
	)

	count := 0
	for _, line := range r.Lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http") {
			m.store.AddURL(line)
			count++
		}
	}

	if r.Err != nil && count == 0 {
		m.log.ToolError("getJS", fmt.Errorf(r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("getJS", count, time.Since(start))
		if count > 0 {
			m.log.Info("getJS: %d new endpoints discovered from JS files", count)
		}
	}
	return count
}

// buildTargetList selects the best endpoints for param discovery with smart prioritization.
// Priority order: 1) URLs with existing params (already have =), 2) API paths,
// 3) auth/search pages, 4) everything else. Capped at maxURLs.
func (m *Module) buildTargetList(maxURLs int) []string {
	allURLs := m.store.GetURLs()

	// Fall back to live hosts if no URLs discovered
	if len(allURLs) == 0 {
		var fallback []string
		for _, h := range m.store.GetHosts() {
			if u, ok := h.Meta["url"]; ok {
				fallback = append(fallback, u)
			} else {
				fallback = append(fallback, "https://"+h.Domain)
			}
		}
		return fallback
	}

	skipExt := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
		".zip", ".tar", ".gz", ".map",
	}

	var withParams, apiPaths, loginPaths, other []string
	seen := make(map[string]bool)

	for _, u := range allURLs {
		lower := strings.ToLower(u)
		skip := false
		for _, ext := range skipExt {
			if strings.HasSuffix(lower, ext) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// Deduplicate by base path (ignore query string)
		base := u
		if idx := strings.Index(base, "?"); idx != -1 {
			base = base[:idx]
		}
		if seen[base] {
			continue
		}
		seen[base] = true

		switch {
		case strings.Contains(u, "="):
			withParams = append(withParams, u)
		case matchAny(lower, "/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", ".json", ".xml"):
			apiPaths = append(apiPaths, u)
		case matchAny(lower, "login", "signin", "auth", "register", "account", "reset", "forgot", "search", "query", "filter"):
			loginPaths = append(loginPaths, u)
		default:
			other = append(other, u)
		}
	}

	var result []string
	for _, bucket := range [][]string{withParams, apiPaths, loginPaths, other} {
		for _, u := range bucket {
			result = append(result, u)
			if len(result) >= maxURLs {
				return result
			}
		}
	}
	return result
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func matchAny(s string, patterns ...string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func countLines(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(data), "\n") + 1
}

// jsonStr extracts a string value from a flat JSON line without a full JSON parser.
func jsonStr(line, key string) string {
	needle := `"` + key + `":"`
	idx := strings.Index(line, needle)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(needle):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}
