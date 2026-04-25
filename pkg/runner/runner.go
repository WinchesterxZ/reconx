package runner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Result holds the output of a tool run
type Result struct {
	Tool     string
	Args     []string
	Lines    []string        // stdout lines only (clean results)
	Stderr   []string        // stderr lines captured separately
	Duration time.Duration
	ExitCode int
	Err      error
}

// HasResults returns true if any stdout lines were captured
func (r *Result) HasResults() bool { return len(r.Lines) > 0 }

// IsTimeout returns true if the run exceeded its deadline
func (r *Result) IsTimeout() bool {
	return r.Err != nil && strings.Contains(r.Err.Error(), "timeout")
}

// IsNotFound returns true if the binary was not found
func (r *Result) IsNotFound() bool {
	return r.Err != nil && strings.Contains(r.Err.Error(), "executable file not found")
}

// DiagString returns a human-readable diagnosis of why a tool failed
func (r *Result) DiagString() string {
	if r.Err == nil {
		return ""
	}
	switch {
	case r.IsNotFound():
		return fmt.Sprintf("%s: binary not found in PATH — install it or check 'which %s'", r.Tool, r.Tool)
	case r.IsTimeout():
		return fmt.Sprintf("%s: timed out after %s — increase timeout or use --skip-%s", r.Tool, r.Duration.Round(time.Second), r.Tool)
	case r.ExitCode == 2:
		return fmt.Sprintf("%s: exit 2 — likely bad flags or missing config (stderr: %s)", r.Tool, strings.Join(r.Stderr, " | "))
	case r.ExitCode != 0:
		return fmt.Sprintf("%s: exit %d (stderr: %s)", r.Tool, r.ExitCode, strings.Join(r.Stderr, " | "))
	default:
		return fmt.Sprintf("%s: %v", r.Tool, r.Err)
	}
}

// Option configures a Run call
type Option func(*runConfig)

type runConfig struct {
	timeout        time.Duration
	stdin          string
	onLine         func(string)   // called for each stdout line
	onStderrLine   func(string)   // called for each stderr line
	env            []string
	captureStderr  bool
	filterStderr   bool           // if true, don't add stderr to Lines
}

// WithTimeout sets execution timeout
func WithTimeout(d time.Duration) Option {
	return func(c *runConfig) { c.timeout = d }
}

// WithStdin pipes a string to the tool's stdin
func WithStdin(s string) Option {
	return func(c *runConfig) { c.stdin = s }
}

// WithLineCallback calls fn for each stdout line in real-time
func WithLineCallback(fn func(string)) Option {
	return func(c *runConfig) { c.onLine = fn }
}

// WithStderrCallback calls fn for each stderr line
func WithStderrCallback(fn func(string)) Option {
	return func(c *runConfig) { c.onStderrLine = fn }
}

// WithEnv sets additional environment variables
func WithEnv(env []string) Option {
	return func(c *runConfig) { c.env = env }
}

// Run executes a command and returns its output.
// Stdout and stderr are captured separately.
// onLine is called for stdout only.
// Stderr is always captured into Result.Stderr for diagnostics.
// If timeout is 0, the command runs with no deadline until it completes naturally
// or the parent context is cancelled.
func Run(ctx context.Context, name string, args []string, opts ...Option) *Result {
	cfg := &runConfig{
		timeout:       0, // 0 = no timeout, use parent ctx only
		captureStderr: true,
		filterStderr:  true,
	}
	for _, o := range opts {
		o(cfg)
	}

	var runCtx context.Context
	var cancel context.CancelFunc
	if cfg.timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, cfg.timeout)
	} else {
		runCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	cmd := exec.CommandContext(runCtx, name, args...)

	// Environment
	if len(cfg.env) > 0 {
		cmd.Env = append(cmd.Environ(), cfg.env...)
	}

	// Stdin
	if cfg.stdin != "" {
		cmd.Stdin = strings.NewReader(cfg.stdin)
	}

	// Pipes
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return &Result{Tool: name, Args: args, Err: fmt.Errorf("stdout pipe: %w", err)}
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return &Result{Tool: name, Args: args, Err: fmt.Errorf("stderr pipe: %w", err)}
	}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return &Result{Tool: name, Args: args, Err: fmt.Errorf("start: %w", err)}
	}

	var (
		mu          sync.Mutex
		stdoutLines []string
		stderrLines []string
		stderrBuf   bytes.Buffer
	)

	// Collect stdout
	collectStdout := func() {
		sc := bufio.NewScanner(stdoutPipe)
		sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			mu.Lock()
			stdoutLines = append(stdoutLines, line)
			mu.Unlock()
			if cfg.onLine != nil {
				cfg.onLine(line)
			}
		}
	}

	// Collect stderr — always captured, never mixed into Lines
	collectStderr := func() {
		sc := bufio.NewScanner(stderrPipe)
		sc.Buffer(make([]byte, 1*1024*1024), 1*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			mu.Lock()
			stderrLines = append(stderrLines, line)
			stderrBuf.WriteString(line + "\n")
			mu.Unlock()
			if cfg.onStderrLine != nil {
				cfg.onStderrLine(line)
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); collectStdout() }()
	go func() { defer wg.Done(); collectStderr() }()
	wg.Wait()

	runErr := cmd.Wait()
	dur := time.Since(start)

	// Extract exit code
	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}

	// Classify timeout
	if runCtx.Err() == context.DeadlineExceeded {
		runErr = fmt.Errorf("timeout after %s", cfg.timeout.Round(time.Second))
	}

	return &Result{
		Tool:     name,
		Args:     args,
		Lines:    stdoutLines,
		Stderr:   stderrLines,
		Duration: dur,
		ExitCode: exitCode,
		Err:      runErr,
	}
}

// IsAvailable checks whether a binary exists in PATH
func IsAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// WhichPath returns the full path of a binary, or empty string
func WhichPath(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

// Version runs `name --version` and returns the first line of output
func Version(name string) string {
	r := Run(context.Background(), name, []string{"--version"},
		WithTimeout(5*time.Second))
	if r.HasResults() {
		return r.Lines[0]
	}
	if len(r.Stderr) > 0 {
		return r.Stderr[0]
	}
	return "unknown"
}

// CheckTools returns a map of tool name → available
func CheckTools(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = IsAvailable(n)
	}
	return out
}
