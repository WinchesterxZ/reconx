package store

import (
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "sync"
        "time"
)

// Host represents a discovered live host
type Host struct {
        Domain     string            `json:"domain"`
        IP         string            `json:"ip,omitempty"`
        StatusCode int               `json:"status_code,omitempty"`
        Title      string            `json:"title,omitempty"`
        Server     string            `json:"server,omitempty"`
        Port       int               `json:"port,omitempty"`
        TechStack  []string          `json:"tech_stack,omitempty"`
        Tags       []string          `json:"tags,omitempty"`
        Meta       map[string]string `json:"meta,omitempty"`
}

// Port holds a discovered open port
type Port struct {
        Host     string `json:"host"`
        Port     int    `json:"port"`
        Protocol string `json:"protocol"`
        Service  string `json:"service,omitempty"`
        Banner   string `json:"banner,omitempty"`
}

// Finding represents a vulnerability or sensitive finding
type Finding struct {
        Name        string    `json:"name"`
        Severity    string    `json:"severity"`
        Target      string    `json:"target"`
        Description string    `json:"description,omitempty"`
        Evidence    string    `json:"evidence,omitempty"`
        Template    string    `json:"template,omitempty"`
        FoundAt     time.Time `json:"found_at"`
}

// Secret represents a discovered credential/token
type Secret struct {
        Type   string `json:"type"`
        Value  string `json:"value"`
        Source string `json:"source"`
        File   string `json:"file,omitempty"`
}

// Store is the central thread-safe data store
type Store struct {
        mu sync.RWMutex

        Subdomains map[string]bool   // deduplicated subdomain set
        Hosts      map[string]*Host  // domain → host info
        Ports      []*Port
        URLs       map[string]bool   // deduplicated URL set
        JSFiles    map[string]bool
        Findings   []*Finding
        Secrets    []*Secret

        ScanID    string
        StartTime time.Time
}

// New creates a fresh Store
func New(scanID string) *Store {
        return &Store{
                Subdomains: make(map[string]bool),
                Hosts:      make(map[string]*Host),
                URLs:       make(map[string]bool),
                JSFiles:    make(map[string]bool),
                ScanID:     scanID,
                StartTime:  time.Now(),
        }
}

// AddSubdomain adds a subdomain, returns true if it's new
func (s *Store) AddSubdomain(sub string) bool {
        s.mu.Lock()
        defer s.mu.Unlock()
        if s.Subdomains[sub] {
                return false
        }
        s.Subdomains[sub] = true
        return true
}

// AddSubdomains bulk-adds subdomains, returns count of new ones
func (s *Store) AddSubdomains(subs []string) int {
        count := 0
        for _, sub := range subs {
                if s.AddSubdomain(sub) {
                        count++
                }
        }
        return count
}

// GetSubdomains returns all unique subdomains as a slice
func (s *Store) GetSubdomains() []string {
        s.mu.RLock()
        defer s.mu.RUnlock()
        out := make([]string, 0, len(s.Subdomains))
        for sub := range s.Subdomains {
                out = append(out, sub)
        }
        return out
}

// AddHost records a live host
func (s *Store) AddHost(h *Host) {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.Hosts[h.Domain] = h
}

// GetHosts returns all live hosts
func (s *Store) GetHosts() []*Host {
        s.mu.RLock()
        defer s.mu.RUnlock()
        out := make([]*Host, 0, len(s.Hosts))
        for _, h := range s.Hosts {
                out = append(out, h)
        }
        return out
}

// AddPort records an open port
func (s *Store) AddPort(p *Port) {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.Ports = append(s.Ports, p)
}

// AddURL adds a URL, returns true if new
func (s *Store) AddURL(u string) bool {
        s.mu.Lock()
        defer s.mu.Unlock()
        if s.URLs[u] {
                return false
        }
        s.URLs[u] = true
        return true
}

// AddURLs bulk-adds URLs
func (s *Store) AddURLs(urls []string) int {
        count := 0
        for _, u := range urls {
                if s.AddURL(u) {
                        count++
                }
        }
        return count
}

// GetURLs returns all unique URLs
func (s *Store) GetURLs() []string {
        s.mu.RLock()
        defer s.mu.RUnlock()
        out := make([]string, 0, len(s.URLs))
        for u := range s.URLs {
                out = append(out, u)
        }
        return out
}

// AddJSFile records a JS file URL
func (s *Store) AddJSFile(u string) bool {
        s.mu.Lock()
        defer s.mu.Unlock()
        if s.JSFiles[u] {
                return false
        }
        s.JSFiles[u] = true
        return true
}

// GetJSFiles returns all JS file URLs
func (s *Store) GetJSFiles() []string {
        s.mu.RLock()
        defer s.mu.RUnlock()
        out := make([]string, 0, len(s.JSFiles))
        for u := range s.JSFiles {
                out = append(out, u)
        }
        return out
}

// AddFinding records a vulnerability finding
func (s *Store) AddFinding(f *Finding) {
        f.FoundAt = time.Now()
        s.mu.Lock()
        defer s.mu.Unlock()
        s.Findings = append(s.Findings, f)
}

// AddSecret records a discovered secret
func (s *Store) AddSecret(sec *Secret) {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.Secrets = append(s.Secrets, sec)
}

// Stats returns a summary map
func (s *Store) Stats() map[string]int {
        s.mu.RLock()
        defer s.mu.RUnlock()
        return map[string]int{
                "subdomains": len(s.Subdomains),
                "live_hosts": len(s.Hosts),
                "open_ports": len(s.Ports),
                "urls":       len(s.URLs),
                "js_files":   len(s.JSFiles),
                "findings":   len(s.Findings),
                "secrets":    len(s.Secrets),
        }
}

// SaveJSON persists the store as JSON to outDir
func (s *Store) SaveJSON(outDir string) error {
        s.mu.RLock()
        defer s.mu.RUnlock()

        type snapshot struct {
                ScanID     string      `json:"scan_id"`
                StartTime  time.Time   `json:"start_time"`
                Duration   string      `json:"duration"`
                Subdomains []string    `json:"subdomains"`
                Hosts      []*Host     `json:"hosts"`
                Ports      []*Port     `json:"ports"`
                URLs       []string    `json:"urls"`
                Findings   []*Finding  `json:"findings"`
                Secrets    []*Secret   `json:"secrets"`
        }

        subs := make([]string, 0, len(s.Subdomains))
        for sub := range s.Subdomains {
                subs = append(subs, sub)
        }
        hosts := make([]*Host, 0, len(s.Hosts))
        for _, h := range s.Hosts {
                hosts = append(hosts, h)
        }

        urls_slice := make([]string, 0, len(s.URLs))
        for u := range s.URLs {
                urls_slice = append(urls_slice, u)
        }

        snap := snapshot{
                ScanID:    s.ScanID,
                StartTime: s.StartTime,
                Duration:  time.Since(s.StartTime).Round(time.Second).String(),
                Subdomains: subs,
                Hosts:     hosts,
                Ports:     s.Ports,
                URLs:      urls_slice,
                Findings:  s.Findings,
                Secrets:   s.Secrets,
        }

        data, err := json.MarshalIndent(snap, "", "  ")
        if err != nil {
                return err
        }
        path := filepath.Join(outDir, "results.json")
        if err := os.WriteFile(path, data, 0644); err != nil {
                return fmt.Errorf("writing JSON: %w", err)
        }
        return nil
}

// SaveRaw saves a plain text list to a file
func SaveRaw(path string, lines []string) error {
        f, err := os.Create(path)
        if err != nil {
                return err
        }
        defer f.Close()
        for _, l := range lines {
                fmt.Fprintln(f, l)
        }
        return nil
}
