package logger

import (
	"fmt"
	"sync"
	"time"
)

// ToolStatus represents the current state of a running tool
type ToolStatus struct {
	Name    string
	Target  string
	State   string // "running", "done", "error", "timeout", "skipped"
	Count   int
	Start   time.Time
	Message string // final message for done/error
}

// ProgressBoard shows all running tools in a live-updating table.
// It redraws in-place using ANSI cursor movement so parallel tools
// never mix their output — you always see a clean status for every tool.
type ProgressBoard struct {
	mu       sync.Mutex
	tools    map[string]*ToolStatus
	order    []string // insertion order for stable display
	logger   *Logger
	done     chan struct{}
	stopped  bool
	lines    int  // how many lines we drew last frame (for cursor-up)
	paused   bool // paused while printing a permanent log line
}

// NewProgressBoard creates and starts a progress board
func (l *Logger) NewProgressBoard() *ProgressBoard {
	b := &ProgressBoard{
		tools:  make(map[string]*ToolStatus),
		logger: l,
		done:   make(chan struct{}),
	}
	go b.run()
	return b
}

// Register adds a tool to the board as "running"
func (b *ProgressBoard) Register(name, target string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.tools[name]; !exists {
		b.order = append(b.order, name)
	}
	b.tools[name] = &ToolStatus{
		Name:   name,
		Target: target,
		State:  "running",
		Start:  time.Now(),
	}
}

// Update sets live count for a running tool
func (b *ProgressBoard) Update(name string, count int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if t, ok := b.tools[name]; ok {
		t.Count = count
	}
}

// Done marks a tool as finished
func (b *ProgressBoard) Done(name string, count int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if t, ok := b.tools[name]; ok {
		t.State   = "done"
		t.Count   = count
		t.Message = fmt.Sprintf("%d results", count)
	}
}

// Fail marks a tool as failed
func (b *ProgressBoard) Fail(name, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if t, ok := b.tools[name]; ok {
		t.State   = "error"
		t.Message = reason
	}
}

// Timeout marks a tool as timed-out with partial results
func (b *ProgressBoard) Timeout(name string, partial int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if t, ok := b.tools[name]; ok {
		t.State   = "timeout"
		t.Count   = partial
		t.Message = fmt.Sprintf("kept %d partial results", partial)
	}
}

// Skip marks a tool as skipped
func (b *ProgressBoard) Skip(name, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.tools[name]; !exists {
		b.order = append(b.order, name)
	}
	b.tools[name] = &ToolStatus{
		Name:    name,
		State:   "skipped",
		Message: reason,
		Start:   time.Now(),
	}
}

// Stop ends the progress board and clears it
func (b *ProgressBoard) Stop() {
	b.mu.Lock()
	if b.stopped {
		b.mu.Unlock()
		return
	}
	b.stopped = true
	b.mu.Unlock()
	close(b.done)
	time.Sleep(100 * time.Millisecond)
	b.clear()
}

// PauseForLog clears the board temporarily so a permanent log line can print cleanly
func (b *ProgressBoard) PauseForLog() {
	b.mu.Lock()
	b.paused = true
	b.mu.Unlock()
	b.clear()
}

// ResumeAfterLog re-enables the board after a permanent log line was printed
func (b *ProgressBoard) ResumeAfterLog() {
	b.mu.Lock()
	b.paused = false
	b.mu.Unlock()
}

func (b *ProgressBoard) run() {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	frame := 0
	for {
		select {
		case <-b.done:
			return
		case <-ticker.C:
			b.redraw(frame)
			frame++
		}
	}
}

var boardFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func (b *ProgressBoard) redraw(frame int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.paused || len(b.order) == 0 {
		return
	}

	// Move cursor up to overwrite previous board
	if b.lines > 0 {
		fmt.Printf("\033[%dA", b.lines)
	}

	spin := boardFrames[frame%len(boardFrames)]
	drawn := 0

	// Header
	running := 0
	for _, name := range b.order {
		if b.tools[name].State == "running" {
			running++
		}
	}

	fmt.Printf("\r\033[2K  %s %s\n",
		c(magenta, "◆"),
		c(hBlack, fmt.Sprintf("Active tools: %d running", running)))
	drawn++

	// One line per tool
	for _, name := range b.order {
		t := b.tools[name]
		elapsed := time.Since(t.Start).Round(time.Second)

		var icon, nameStr, detail, elapsedStr string

		switch t.State {
		case "running":
			icon      = c(cyan, spin)
			nameStr   = c(cyan, fmt.Sprintf("%-20s", name))
			if t.Count > 0 {
				detail = c(hGreen, fmt.Sprintf("%-30s", fmt.Sprintf("%d found so far", t.Count)))
			} else {
				detail = c(hBlack, fmt.Sprintf("%-30s", truncate(t.Target, 30)))
			}
			elapsedStr = c(yellow, fmt.Sprintf("  %s", elapsed))

		case "done":
			icon      = cb(green, "✓")
			nameStr   = c(hBlack, fmt.Sprintf("%-20s", name))
			detail    = c(hGreen, fmt.Sprintf("%-30s", t.Message))
			elapsedStr = c(hBlack, fmt.Sprintf("  %s", elapsed))

		case "timeout":
			icon      = c(yellow, "⏱")
			nameStr   = c(hBlack, fmt.Sprintf("%-20s", name))
			detail    = c(yellow, fmt.Sprintf("%-30s", t.Message))
			elapsedStr = c(hBlack, fmt.Sprintf("  %s", elapsed))

		case "error":
			icon      = cb(red, "✗")
			nameStr   = c(hBlack, fmt.Sprintf("%-20s", name))
			detail    = c(hRed, fmt.Sprintf("%-30s", truncate(t.Message, 30)))
			elapsedStr = c(hBlack, fmt.Sprintf("  %s", elapsed))

		case "skipped":
			icon      = c(hBlack, "○")
			nameStr   = c(hBlack, fmt.Sprintf("%-20s", name))
			detail    = c(hBlack, fmt.Sprintf("%-30s", truncate(t.Message, 30)))
			elapsedStr = ""
		}

		fmt.Printf("\r\033[2K    %s %s %s%s\n", icon, nameStr, detail, elapsedStr)
		drawn++
	}

	b.lines = drawn
}

func (b *ProgressBoard) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lines > 0 {
		fmt.Printf("\033[%dA", b.lines)
		for i := 0; i < b.lines; i++ {
			fmt.Printf("\r\033[2K\n")
		}
		fmt.Printf("\033[%dA", b.lines)
		b.lines = 0
	}
}

// ── Logger integration: permanent log lines pause/resume the board ────────────

// InfoBoard prints a permanent info line, pausing the board
func (l *Logger) InfoBoard(board *ProgressBoard, format string, args ...interface{}) {
	if board != nil {
		board.PauseForLog()
		defer board.ResumeAfterLog()
	}
	l.Info(format, args...)
}

// WarnBoard prints a permanent warning line
func (l *Logger) WarnBoard(board *ProgressBoard, format string, args ...interface{}) {
	if board != nil {
		board.PauseForLog()
		defer board.ResumeAfterLog()
	}
	l.Warn(format, args...)
}

// FindingBoard prints a permanent finding line
func (l *Logger) FindingBoard(board *ProgressBoard, severity, name, target string) {
	if board != nil {
		board.PauseForLog()
		defer board.ResumeAfterLog()
	}
	l.Finding(severity, name, target)
}
