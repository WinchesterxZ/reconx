package store

import (
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "sort"
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

// DirResult represents a directory/file discovered during content fuzzing
type DirResult struct {
        URL        string `json:"url"`
        StatusCode int    `json:"status_code"`
        Size       int    `json:"size,omitempty"`
        Tool       string `json:"tool"`
        Target     string `json:"target"`
}

// WAFResult holds WAF detection output for a host
type WAFResult struct {
        Host     string `json:"host"`
        WAF      string `json:"waf"`
        Detected bool   `json:"detected"`
}

// CloudAsset represents an enumerated cloud storage bucket or asset
type CloudAsset struct {
        Provider   string `json:"provider"` // aws, gcp, azure
        Name       string `json:"name"`
        URL        string `json:"url"`
        Status     string `json:"status"` // public, authenticated, private
        Accessible bool   `json:"accessible"`
}

// CORSFinding represents a CORS misconfiguration finding
type CORSFinding struct {
        URL         string `json:"url"`
        Origin      string `json:"origin"`
        ACAO        string `json:"acao"`
        ACAC        string `json:"acac"`
        Severity    string `json:"severity"`
        Description string `json:"description"`
}

// ParamFinding represents hidden parameters discovered on a URL
type ParamFinding struct {
        URL     string   `json:"url"`
        Method  string   `json:"method"`
        Params  []string `json:"params"`
        Tool    string   `json:"tool"`
}

// Store is the central thread-safe data store
type Store struct {
	mu sync.RWMutex

	Subdomains   map[string]bool   // deduplicated subdomain set
	SubSources   map[string]string // subdomain → source that found it (for report filter)
	Hosts        map[string]*Host  // domain → host info
	Ports        []*Port
	URLs         map[string]bool // deduplicated URL set
	JSFiles      map[string]bool
	Findings     []*Finding
	Secrets      []*Secret
	DirResults   []*DirResult
	WAFResults   []*WAFResult
	CloudAssets  []*CloudAsset
	CORSResults  []*CORSFinding
	ParamResults []*ParamFinding

	ScanID    string
	StartTime time.Time
}

// New creates a fresh Store
func New(scanID string) *Store {
	return &Store{
		Subdomains: make(map[string]bool),
		SubSources: make(map[string]string),
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

// AddSubdomainFromSource adds a subdomain and records which source found it.
// If the subdomain was already known, the source is updated only if the
// existing source is empty (first source wins for stability).
func (s *Store) AddSubdomainFromSource(sub, source string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	isNew := !s.Subdomains[sub]
	s.Subdomains[sub] = true
	if isNew || s.SubSources[sub] == "" {
		if source != "" {
			s.SubSources[sub] = source
		}
	}
	return isNew
}

// AddSubdomainsFromSource bulk-adds subdomains from a named source.
func (s *Store) AddSubdomainsFromSource(subs []string, source string) int {
	count := 0
	for _, sub := range subs {
		if s.AddSubdomainFromSource(sub, source) {
			count++
		}
	}
	return count
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

// GetSubdomainsWithSource returns a sorted slice of (subdomain, source) pairs.
// Used by the report to show which tool found each subdomain.
func (s *Store) GetSubdomainsWithSource() []SubdomainEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SubdomainEntry, 0, len(s.Subdomains))
	for sub := range s.Subdomains {
		out = append(out, SubdomainEntry{
			Subdomain: sub,
			Source:    s.SubSources[sub],
		})
	}
	return out
}

// SubdomainEntry pairs a subdomain with the source that discovered it.
type SubdomainEntry struct {
	Subdomain string `json:"subdomain"`
	Source    string `json:"source"`
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

// AddDirResult records a directory/file fuzzing hit
func (s *Store) AddDirResult(d *DirResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DirResults = append(s.DirResults, d)
}

// AddWAFResult records WAF detection for a host
func (s *Store) AddWAFResult(w *WAFResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.WAFResults = append(s.WAFResults, w)
}

// AddCloudAsset records a discovered cloud bucket/asset
func (s *Store) AddCloudAsset(c *CloudAsset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CloudAssets = append(s.CloudAssets, c)
}

// AddCORSFinding records a CORS misconfiguration
func (s *Store) AddCORSFinding(c *CORSFinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CORSResults = append(s.CORSResults, c)
}

// AddParamFinding records discovered hidden parameters
func (s *Store) AddParamFinding(p *ParamFinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ParamResults = append(s.ParamResults, p)
}

// Stats returns a summary map
func (s *Store) Stats() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]int{
		"subdomains":    len(s.Subdomains),
		"live_hosts":    len(s.Hosts),
		"open_ports":    len(s.Ports),
		"urls":          len(s.URLs),
		"js_files":      len(s.JSFiles),
		"findings":      len(s.Findings),
		"secrets":       len(s.Secrets),
		"dir_results":   len(s.DirResults),
		"waf_results":   len(s.WAFResults),
		"cloud_assets":  len(s.CloudAssets),
		"cors_results":  len(s.CORSResults),
		"param_results": len(s.ParamResults),
	}
}

// SaveJSON persists the store as JSON to outDir
func (s *Store) SaveJSON(outDir string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	type snapshot struct {
		ScanID       string           `json:"scan_id"`
		StartTime    time.Time        `json:"start_time"`
		Duration     string           `json:"duration"`
		Subdomains   []string         `json:"subdomains"`
		SubSources   []SubdomainEntry `json:"subdomain_sources"`
		Hosts        []*Host          `json:"hosts"`
		Ports        []*Port          `json:"ports"`
		URLs         []string         `json:"urls"`
		Findings     []*Finding       `json:"findings"`
		Secrets      []*Secret        `json:"secrets"`
		DirResults   []*DirResult     `json:"dir_results,omitempty"`
		WAFResults   []*WAFResult     `json:"waf_results,omitempty"`
		CloudAssets  []*CloudAsset    `json:"cloud_assets,omitempty"`
		CORSResults  []*CORSFinding   `json:"cors_results,omitempty"`
		ParamResults []*ParamFinding  `json:"param_results,omitempty"`
	}

	subs := make([]string, 0, len(s.Subdomains))
	for sub := range s.Subdomains {
		subs = append(subs, sub)
	}
	sort.Strings(subs)

	subSources := make([]SubdomainEntry, 0, len(subs))
	for _, sub := range subs {
		subSources = append(subSources, SubdomainEntry{
			Subdomain: sub,
			Source:    s.SubSources[sub],
		})
	}

	hosts := make([]*Host, 0, len(s.Hosts))
	for _, h := range s.Hosts {
		hosts = append(hosts, h)
	}

	urls_slice := make([]string, 0, len(s.URLs))
	for u := range s.URLs {
		urls_slice = append(urls_slice, u)
	}
	jsonURLs := urls_slice
	if len(jsonURLs) > 10000 {
		jsonURLs = jsonURLs[:10000]
	}

	snap := snapshot{
		ScanID:       s.ScanID,
		StartTime:    s.StartTime,
		Duration:     time.Since(s.StartTime).Round(time.Second).String(),
		Subdomains:   subs,
		SubSources:   subSources,
		Hosts:        hosts,
		Ports:        s.Ports,
		URLs:         jsonURLs,
		Findings:     s.Findings,
		Secrets:      s.Secrets,
		DirResults:   s.DirResults,
		WAFResults:   s.WAFResults,
		CloudAssets:  s.CloudAssets,
		CORSResults:  s.CORSResults,
		ParamResults: s.ParamResults,
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
