package params

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reconx/reconx/internal/config"
	"github.com/reconx/reconx/internal/store"
	"github.com/reconx/reconx/pkg/logger"
	"github.com/reconx/reconx/pkg/runner"
)

// Module discovers hidden GET/POST/JSON parameters using arjun.
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

// Run scans live URLs for hidden parameters.
func (m *Module) Run(ctx context.Context) error {
	m.log.Phase("Hidden Parameter Discovery", "Arjun — identifying hidden GET/POST parameters")

	tcfg := m.cfg.Tools["arjun"]
	path := "arjun"
	if tcfg.Path != "" {
		path = tcfg.Path
	}

	if !runner.IsAvailable(path) {
		m.log.ToolSkipped("arjun", "not found — install: pip3 install arjun")
		return nil
	}

	urls := m.store.GetURLs()
	if len(urls) == 0 {
		hosts := m.store.GetHosts()
		for _, h := range hosts {
			if u, ok := h.Meta["url"]; ok {
				urls = append(urls, u)
			} else {
				urls = append(urls, "https://"+h.Domain)
			}
		}
	}

	if len(urls) == 0 {
		m.log.Warn("No URLs or live hosts to test for parameters")
		return nil
	}

	targetURLs := sampleEndpoints(urls, 50)
	paramsDir := filepath.Join(m.outDir, "params")
	if err := os.MkdirAll(paramsDir, 0755); err != nil {
		m.log.Warn("Could not create params/ directory: %v", err)
	}

	targetsFile := filepath.Join(paramsDir, "targets.txt")
	if err := store.SaveRaw(targetsFile, targetURLs); err != nil {
		m.log.Warn("Could not save targets.txt: %v", err)
		return err
	}

	outFile := filepath.Join(paramsDir, "arjun_results.json")
	args := []string{
		"-i", targetsFile,
		"-oJ", outFile,
		"-t", "20",
		"--stable",
	}
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

	m.log.Tool("arjun", fmt.Sprintf("%d endpoints → %s", len(targetURLs), outFile))
	m.log.ToolCmd("arjun", args, "")
	start := time.Now()

	board := m.log.NewProgressBoard()
	board.Register("arjun", fmt.Sprintf("%d endpoints", len(targetURLs)))

	onLine := func(line string) {
		board.Heartbeat("arjun")
	}

	r := runner.Run(ctx, path, args, 
		runner.WithTimeout(timeout),
		runner.WithLineCallback(onLine),
		runner.WithStderrCallback(onLine),
	)
	
	if r.Err != nil && !runner.IsAvailable(path) {
		board.Fail("arjun", r.DiagString())
		board.Stop()
		m.log.ToolError("arjun", fmt.Errorf(r.DiagString()), r.Stderr)
		return nil
	}

	totalParams := 0
	if data, err := os.ReadFile(outFile); err == nil {
		var simpleMap map[string][]string
		if err := json.Unmarshal(data, &simpleMap); err == nil {
			for u, pList := range simpleMap {
				if len(pList) > 0 {
					m.store.AddParamFinding(&store.ParamFinding{
						URL:    u,
						Method: "GET",
						Params: pList,
						Tool:   "arjun",
					})
					totalParams += len(pList)
					m.log.Info("  [Param] %s -> %s", u, strings.Join(pList, ", "))
				}
			}
		}
	}

	board.Done("arjun", totalParams)
	board.Stop()
	m.log.ToolDone("arjun", totalParams, time.Since(start))
	m.log.PhaseComplete("Hidden Parameter Discovery", totalParams, time.Since(start))
	return nil
}

func sampleEndpoints(urls []string, max int) []string {
	seen := make(map[string]bool)
	var sampled []string
	for _, u := range urls {
		lower := strings.ToLower(u)
		if strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".jpg") ||
			strings.HasSuffix(lower, ".css") || strings.HasSuffix(lower, ".woff") ||
			strings.HasSuffix(lower, ".svg") || strings.HasSuffix(lower, ".ico") {
			continue
		}
		base := u
		if idx := strings.Index(base, "?"); idx != -1 {
			base = base[:idx]
		}
		if !seen[base] {
			seen[base] = true
			sampled = append(sampled, u)
			if len(sampled) >= max {
				break
			}
		}
	}
	return sampled
}
