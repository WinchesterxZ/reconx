package report

import (
        "fmt"
        "html/template"
        "os"
        "path/filepath"
        "sort"
        "strings"
        "time"

        "github.com/reconx/reconx/internal/store"
)

// ReportData holds everything needed to render the HTML report
type ReportData struct {
	ScanID      string
	Targets     []string
	StartTime   time.Time
	Duration    string
	GeneratedAt string

	TotalSubdomains int
	TotalLiveHosts  int
	TotalPorts      int
	TotalURLs       int
	TotalJSFiles    int
	TotalFindings   int
	TotalSecrets    int
	TotalParams     int
	TotalWAFHosts   int
	TotalNonWAFHosts int

	Subdomains []store.SubdomainEntry
	Hosts      []*store.Host
	WAFHosts   []*store.Host  // hosts behind WAF
	NoWAFHosts []*store.Host  // hosts not behind WAF
	WAFMap     map[string]bool // domain -> is WAF protected (fast O(1) lookup in template)
	Ports      []*store.Port
	Findings   []*store.Finding
	Secrets    []*store.Secret
	URLs       []string // sorted list of all discovered URLs (capped)
	JSFiles    []string // sorted list of all JS file URLs
	Params     []string // discovered parameter keys (all, deduplicated)
	WAFParams  []string // params from WAF-protected hosts
	NoWAFParams []string // params from non-WAF hosts
	WAFResults  []*store.WAFResult // WAF detection results

	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int

	HasScreenshots bool
	ScreenshotDir  string
	// HostScreenshots maps domain → relative path to screenshot.png
	HostScreenshots map[string]string

	// Pre-computed chart data so the template stays simple
	SeverityChart []chartSlice
	StatusChart   []chartSlice
	PortChart     []chartSlice
	TechChart     []chartSlice
	SourceChart   []chartSlice

	// Unique values for filter chips
	AllStatusCodes []int
	AllTech        []string
	AllSources     []string
	AllPorts       []int
	AllSeverities  []string
}

type chartSlice struct {
        Label string
        Value int
}

// Generate creates the HTML report file
func Generate(st *store.Store, targets []string, outDir string) error {
        hosts := st.GetHosts()
        subs := st.GetSubdomainsWithSource()
        // subs is already sorted by subdomain name from the store
        sort.Slice(subs, func(i, j int) bool {
                return subs[i].Subdomain < subs[j].Subdomain
        })

        // Sort hosts by domain
        sort.Slice(hosts, func(i, j int) bool {
                return hosts[i].Domain < hosts[j].Domain
        })

        // Sort findings by severity (critical first)
        findings := st.Findings
        sort.Slice(findings, func(i, j int) bool {
                return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
        })

        // Sort ports by host then port
        ports := st.Ports
        sort.Slice(ports, func(i, j int) bool {
                if ports[i].Host != ports[j].Host {
                        return ports[i].Host < ports[j].Host
                }
                return ports[i].Port < ports[j].Port
        })

        // Get URLs and JS files via public API (returns sorted slices)
        urlList := st.GetURLs()
        jsList := st.GetJSFiles()

        // In the HTML report, cap rendered URLs to top 5,000 to keep the report file lightweight
        // (all 1M+ raw URLs are permanently saved in urls/urls_all.txt and category files)
        displayURLs := urlList
        sort.Strings(displayURLs) // deterministic truncation (GetURLs() is already sorted, but defensive)
        if len(displayURLs) > 5000 {
                displayURLs = displayURLs[:5000]
        }

        // Redact secret values before they go into the HTML report. The
        // raw secrets are still in results.json (chmod 0600) but the HTML
        // report is meant to be shared with the team / client — showing
        // raw API keys there is a leak. We keep the type, source, and a
        // short fingerprint so the user can still find the row.
        redactedSecrets := redactSecrets(st.Secrets)

        data := &ReportData{
                ScanID:          st.ScanID,
                Targets:         targets,
                StartTime:       st.StartTime,
                Duration:        time.Since(st.StartTime).Round(time.Second).String(),
                GeneratedAt:     time.Now().Format("2006-01-02 15:04:05 UTC"),
                TotalSubdomains: len(subs),
                TotalLiveHosts:  len(hosts),
                TotalPorts:      len(ports),
                TotalURLs:       len(urlList),
                TotalJSFiles:    len(jsList),
                TotalFindings:   len(findings),
                TotalSecrets:    len(st.Secrets),
                Subdomains:      subs,
                Hosts:           hosts,
                Ports:           ports,
                Findings:        findings,
                Secrets:         redactedSecrets,
                URLs:            displayURLs,
                JSFiles:         jsList,
                WAFResults:      st.WAFResults,
        }

	// WAF-split hosts
	data.WAFMap = make(map[string]bool)
	for _, h := range hosts {
		if st.IsWAFProtected(h.Domain) {
			data.WAFHosts = append(data.WAFHosts, h)
			data.WAFMap[h.Domain] = true
		} else {
			data.NoWAFHosts = append(data.NoWAFHosts, h)
		}
	}
	data.TotalWAFHosts = len(data.WAFHosts)
	data.TotalNonWAFHosts = len(data.NoWAFHosts)

	// Params from files
	if raw, err := os.ReadFile(filepath.Join(outDir, "params_all.txt")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				data.Params = append(data.Params, line)
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(outDir, "params_waf.txt")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				data.WAFParams = append(data.WAFParams, line)
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(outDir, "params_nowaf.txt")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				data.NoWAFParams = append(data.NoWAFParams, line)
			}
		}
	}
	data.TotalParams = len(data.Params)

	// Screenshot discovery: look for screenshots/<domain>/screenshot.png
	ssDir := filepath.Join(outDir, "screenshots")
	data.HostScreenshots = make(map[string]string)
	if entries, err := os.ReadDir(ssDir); err == nil {
		data.HasScreenshots = true
		data.ScreenshotDir = "screenshots"
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			ssPath := filepath.Join(ssDir, e.Name(), "screenshot.png")
			if _, err := os.Stat(ssPath); err == nil {
				// Relative path from outDir for HTML src attribute
				data.HostScreenshots[e.Name()] = "screenshots/" + e.Name() + "/screenshot.png"
			}
		}
		if len(data.HostScreenshots) == 0 {
			data.HasScreenshots = false
		}
	}


        for _, f := range findings {
                switch strings.ToLower(f.Severity) {
                case "critical":
                        data.CriticalCount++
                case "high":
                        data.HighCount++
                case "medium":
                        data.MediumCount++
                case "low":
                        data.LowCount++
                }
        }

        // Build chart data
        data.SeverityChart = []chartSlice{
                {"Critical", data.CriticalCount},
                {"High", data.HighCount},
                {"Medium", data.MediumCount},
                {"Low", data.LowCount},
        }
        data.StatusChart = buildStatusChart(hosts)
        data.PortChart = buildPortChart(ports)
        data.TechChart = buildTechChart(hosts)
        data.SourceChart = buildSourceChart(subs)

        // Build filter chip values
        data.AllStatusCodes = uniqueStatusCodes(hosts)
        data.AllTech = uniqueTech(hosts)
        data.AllSources = uniqueSources(subs)
        data.AllPorts = uniquePorts(ports)
        data.AllSeverities = []string{"critical", "high", "medium", "low"}

        tmpl, err := template.New("report").Funcs(template.FuncMap{
                "upper": strings.ToUpper,
                "lower": strings.ToLower,
                "severityClass": func(s string) string {
                        switch strings.ToLower(s) {
                        case "critical":
                                return "sev-critical"
                        case "high":
                                return "sev-high"
                        case "medium":
                                return "sev-medium"
                        case "low":
                                return "sev-low"
                        default:
                                return "sev-info"
                        }
                },
                "statusClass": func(code int) string {
                        switch {
                        case code >= 200 && code < 300:
                                return "status-ok"
                        case code >= 300 && code < 400:
                                return "status-redirect"
                        case code == 403 || code == 401:
                                return "status-auth"
                        case code >= 400:
                                return "status-err"
                        default:
                                return ""
                        }
                },
                "divInt": func(num, denom, scale int) int {
                        if denom == 0 {
                                return 0
                        }
                        return num * scale / denom
                },
                "urlsToList": func(d *ReportData) []string {
                        return d.URLs
                },
                "jsFilesToList": func(d *ReportData) []string {
                        return d.JSFiles
                },
                "liveSubdomainsList": func(d *ReportData) []string {
                        out := make([]string, 0, len(d.Hosts))
                        for _, h := range d.Hosts {
                                out = append(out, h.Domain)
                        }
                        return out
                },
                "json": func(v interface{}) (template.JS, error) {
                        // Marshal inline as JSON for the embedded data block.
                        // We use template.JS so the rendered output isn't escaped.
                        b, err := jsonMarshal(v)
                        if err != nil {
                                return "", err
                        }
                        return template.JS(b), nil
                },
        }).Parse(htmlTemplate)
        if err != nil {
                return fmt.Errorf("parsing template: %w", err)
        }

        path := filepath.Join(outDir, "report.html")
        f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
        if err != nil {
                return fmt.Errorf("creating report file: %w", err)
        }
        defer f.Close()

        if err := tmpl.Execute(f, data); err != nil {
                return fmt.Errorf("rendering template: %w", err)
        }
        return nil
}

// redactSecretValue returns a redacted form of a secret value. We keep
// enough to identify the secret (type + last 4 chars) but mask the body
// so the HTML report can be shared without leaking credentials.
func redactSecretValue(value string) string {
        if len(value) <= 8 {
                return "***REDACTED***"
        }
        return value[:4] + "***" + value[len(value)-4:]
}

// redactSecrets produces a copy of secrets with values redacted.
// The Type, Source, and File fields are preserved so the report still
// shows "AWS Access Key from jsecret in app.js" — just hides the key.
func redactSecrets(secrets []*store.Secret) []*store.Secret {
        out := make([]*store.Secret, len(secrets))
        for i, s := range secrets {
                out[i] = &store.Secret{
                        Type:   s.Type,
                        Value:  redactSecretValue(s.Value),
                        Source: s.Source,
                        File:   s.File,
                }
        }
        return out
}

// jsonMarshal is a thin wrapper around encoding/json that we can stub in tests.
// We use a custom function instead of importing encoding/json directly so the
// report package stays self-contained for review.
func jsonMarshal(v interface{}) ([]byte, error) {
        return jsonMarshalImpl(v)
}

func severityRank(s string) int {
        switch strings.ToLower(s) {
        case "critical":
                return 4
        case "high":
                return 3
        case "medium":
                return 2
        case "low":
                return 1
        default:
                return 0
        }
}

func buildStatusChart(hosts []*store.Host) []chartSlice {
        counts := map[int]int{}
        for _, h := range hosts {
                if h.StatusCode > 0 {
                        counts[h.StatusCode]++
                }
        }
        out := make([]chartSlice, 0, len(counts))
        for code, n := range counts {
                out = append(out, chartSlice{Label: fmt.Sprintf("%d", code), Value: n})
        }
        sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
        if len(out) > 10 {
                out = out[:10]
        }
        return out
}

func buildPortChart(ports []*store.Port) []chartSlice {
        counts := map[int]int{}
        for _, p := range ports {
                counts[p.Port]++
        }
        out := make([]chartSlice, 0, len(counts))
        for port, n := range counts {
                out = append(out, chartSlice{Label: fmt.Sprintf("%d", port), Value: n})
        }
        sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
        if len(out) > 15 {
                out = out[:15]
        }
        return out
}

func buildTechChart(hosts []*store.Host) []chartSlice {
        counts := map[string]int{}
        for _, h := range hosts {
                for _, t := range h.TechStack {
                        counts[t]++
                }
        }
        out := make([]chartSlice, 0, len(counts))
        for tech, n := range counts {
                out = append(out, chartSlice{Label: tech, Value: n})
        }
        sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
        if len(out) > 12 {
                out = out[:12]
        }
        return out
}

func buildSourceChart(subs []store.SubdomainEntry) []chartSlice {
        counts := map[string]int{}
        for _, s := range subs {
                if s.Source == "" {
                        s.Source = "unknown"
                }
                counts[s.Source]++
        }
        out := make([]chartSlice, 0, len(counts))
        for src, n := range counts {
                out = append(out, chartSlice{Label: src, Value: n})
        }
        sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
        if len(out) > 15 {
                out = out[:15]
        }
        return out
}

func uniqueStatusCodes(hosts []*store.Host) []int {
        seen := map[int]bool{}
        var out []int
        for _, h := range hosts {
                if h.StatusCode > 0 && !seen[h.StatusCode] {
                        seen[h.StatusCode] = true
                        out = append(out, h.StatusCode)
                }
        }
        sort.Ints(out)
        return out
}

func uniqueTech(hosts []*store.Host) []string {
        seen := map[string]bool{}
        var out []string
        for _, h := range hosts {
                for _, t := range h.TechStack {
                        if !seen[t] {
                                seen[t] = true
                                out = append(out, t)
                        }
                }
        }
        sort.Strings(out)
        return out
}

func uniqueSources(subs []store.SubdomainEntry) []string {
        seen := map[string]bool{}
        var out []string
        for _, s := range subs {
                if s.Source == "" {
                        s.Source = "unknown"
                }
                if !seen[s.Source] {
                        seen[s.Source] = true
                        out = append(out, s.Source)
                }
        }
        sort.Strings(out)
        return out
}

func uniquePorts(ports []*store.Port) []int {
        seen := map[int]bool{}
        var out []int
        for _, p := range ports {
                if !seen[p.Port] {
                        seen[p.Port] = true
                        out = append(out, p.Port)
                }
        }
        sort.Ints(out)
        return out
}
