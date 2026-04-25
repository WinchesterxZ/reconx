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
	ScanID     string
	Targets    []string
	StartTime  time.Time
	Duration   string
	GeneratedAt string

	TotalSubdomains int
	TotalLiveHosts  int
	TotalPorts      int
	TotalURLs       int
	TotalJSFiles    int
	TotalFindings   int
	TotalSecrets    int

	Subdomains []string
	Hosts      []*store.Host
	Ports      []*store.Port
	Findings   []*store.Finding
	Secrets    []*store.Secret

	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
}

// Generate creates the HTML report file
func Generate(st *store.Store, targets []string, outDir string) error {
	hosts := st.GetHosts()
	subs := st.GetSubdomains()
	sort.Strings(subs)

	// Sort findings by severity
	findings := st.Findings
	sort.Slice(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})

	data := &ReportData{
		ScanID:          st.ScanID,
		Targets:         targets,
		StartTime:       st.StartTime,
		Duration:        time.Since(st.StartTime).Round(time.Second).String(),
		GeneratedAt:     time.Now().Format("2006-01-02 15:04:05 UTC"),
		TotalSubdomains: len(subs),
		TotalLiveHosts:  len(hosts),
		TotalPorts:      len(st.Ports),
		TotalURLs:       len(st.URLs),
		TotalJSFiles:    len(st.JSFiles),
		TotalFindings:   len(findings),
		TotalSecrets:    len(st.Secrets),
		Subdomains:      subs,
		Hosts:           hosts,
		Ports:           st.Ports,
		Findings:        findings,
		Secrets:         st.Secrets,
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

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"upper": strings.ToUpper,
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
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	path := filepath.Join(outDir, "report.html")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating report file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("rendering template: %w", err)
	}
	return nil
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

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconX Report — {{.ScanID}}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@300;400;500;600;700&display=swap');

  :root {
    --bg: #0a0c0f; --bg2: #0f1215; --bg3: #151a1f; --bg4: #1c2229;
    --border: rgba(255,255,255,0.07); --border2: rgba(255,255,255,0.13);
    --text: #e2e8f0; --muted: #64748b; --accent: #00ff88;
    --critical: #ff3d5a; --high: #ff6b35; --medium: #ffd93d; --low: #6bcb77; --info: #4d9fff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; font-size: 14px; line-height: 1.6; }
  a { color: var(--info); text-decoration: none; }
  a:hover { text-decoration: underline; }

  .header {
    background: linear-gradient(135deg, #0f1215 0%, #0a0c0f 100%);
    border-bottom: 1px solid var(--border2);
    padding: 32px 40px;
  }
  .header-top { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px; }
  .logo { font-family: 'JetBrains Mono', monospace; font-size: 24px; font-weight: 700; color: var(--accent); letter-spacing: -1px; }
  .scan-meta { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--muted); text-align: right; }
  .targets { margin-top: 16px; display: flex; flex-wrap: wrap; gap: 8px; }
  .target-tag { background: rgba(0,255,136,0.08); border: 1px solid rgba(0,255,136,0.2); color: var(--accent); padding: 4px 12px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 12px; }

  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1px; background: var(--border); border-bottom: 1px solid var(--border2); }
  .stat-card { background: var(--bg2); padding: 20px 24px; }
  .stat-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
  .stat-value { font-size: 28px; font-weight: 700; font-family: 'JetBrains Mono', monospace; color: #fff; }
  .stat-card.danger .stat-value { color: var(--critical); }
  .stat-card.warn .stat-value { color: var(--medium); }
  .stat-card.good .stat-value { color: var(--accent); }

  .nav { display: flex; gap: 0; border-bottom: 1px solid var(--border2); background: var(--bg2); padding: 0 40px; overflow-x: auto; }
  .nav-btn { padding: 12px 20px; font-size: 13px; font-weight: 500; color: var(--muted); cursor: pointer; border: none; background: none; border-bottom: 2px solid transparent; white-space: nowrap; transition: all 0.15s; }
  .nav-btn:hover { color: var(--text); }
  .nav-btn.active { color: var(--accent); border-bottom-color: var(--accent); }

  .section { display: none; padding: 32px 40px; }
  .section.active { display: block; }
  .section-title { font-size: 16px; font-weight: 600; color: #fff; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }
  .count-badge { background: var(--bg3); border: 1px solid var(--border2); padding: 2px 10px; border-radius: 4px; font-size: 12px; font-family: 'JetBrains Mono', monospace; color: var(--muted); }

  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px 14px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); background: var(--bg3); border-bottom: 1px solid var(--border2); }
  td { padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  .table-wrap { background: var(--bg2); border: 1px solid var(--border2); border-radius: 8px; overflow: hidden; margin-bottom: 24px; overflow-x: auto; }

  .sev-critical { background: rgba(255,61,90,0.15); color: #ff3d5a; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
  .sev-high     { background: rgba(255,107,53,0.15); color: #ff6b35; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
  .sev-medium   { background: rgba(255,217,61,0.15); color: #ffd93d; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
  .sev-low      { background: rgba(107,203,119,0.15); color: #6bcb77; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
  .sev-info     { background: rgba(77,159,255,0.12); color: #4d9fff; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }

  .status-ok       { color: var(--accent); font-family: 'JetBrains Mono', monospace; }
  .status-redirect { color: var(--info); font-family: 'JetBrains Mono', monospace; }
  .status-auth     { color: var(--medium); font-family: 'JetBrains Mono', monospace; }
  .status-err      { color: var(--critical); font-family: 'JetBrains Mono', monospace; }

  .mono { font-family: 'JetBrains Mono', monospace; font-size: 12px; }
  .muted { color: var(--muted); }
  .tag { background: var(--bg3); border: 1px solid var(--border); padding: 1px 6px; border-radius: 3px; font-size: 11px; color: var(--muted); margin-right: 4px; }

  .summary-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 28px; }
  .sev-card { border-radius: 8px; padding: 16px 20px; border: 1px solid; }
  .sev-card.critical { background: rgba(255,61,90,0.08); border-color: rgba(255,61,90,0.25); }
  .sev-card.high     { background: rgba(255,107,53,0.08); border-color: rgba(255,107,53,0.25); }
  .sev-card.medium   { background: rgba(255,217,61,0.08); border-color: rgba(255,217,61,0.25); }
  .sev-card.low      { background: rgba(107,203,119,0.08); border-color: rgba(107,203,119,0.25); }
  .sev-card .num { font-size: 32px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
  .sev-card.critical .num { color: #ff3d5a; }
  .sev-card.high     .num { color: #ff6b35; }
  .sev-card.medium   .num { color: #ffd93d; }
  .sev-card.low      .num { color: #6bcb77; }
  .sev-card .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-top: 4px; }

  .search-box { width: 100%; padding: 10px 14px; background: var(--bg3); border: 1px solid var(--border2); border-radius: 6px; color: var(--text); font-family: 'JetBrains Mono', monospace; font-size: 13px; margin-bottom: 16px; outline: none; }
  .search-box:focus { border-color: var(--accent); }

  .no-data { text-align: center; padding: 48px; color: var(--muted); font-style: italic; }
  .footer { padding: 24px 40px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; font-family: 'JetBrains Mono', monospace; display: flex; justify-content: space-between; }
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div>
      <div class="logo">⬡ ReconX</div>
      <div style="color:var(--muted);font-size:12px;margin-top:4px">Automated Bug Bounty Recon Framework</div>
    </div>
    <div class="scan-meta">
      <div>Scan ID: {{.ScanID}}</div>
      <div>Started: {{.StartTime.Format "2006-01-02 15:04:05"}}</div>
      <div>Duration: {{.Duration}}</div>
      <div>Generated: {{.GeneratedAt}}</div>
    </div>
  </div>
  <div class="targets">
    {{range .Targets}}<span class="target-tag">{{.}}</span>{{end}}
  </div>
</div>

<div class="stats-grid">
  <div class="stat-card"><div class="stat-label">Subdomains</div><div class="stat-value">{{.TotalSubdomains}}</div></div>
  <div class="stat-card good"><div class="stat-label">Live Hosts</div><div class="stat-value">{{.TotalLiveHosts}}</div></div>
  <div class="stat-card"><div class="stat-label">Open Ports</div><div class="stat-value">{{.TotalPorts}}</div></div>
  <div class="stat-card"><div class="stat-label">URLs Found</div><div class="stat-value">{{.TotalURLs}}</div></div>
  <div class="stat-card"><div class="stat-label">JS Files</div><div class="stat-value">{{.TotalJSFiles}}</div></div>
  <div class="stat-card {{if gt .TotalFindings 0}}danger{{end}}"><div class="stat-label">Findings</div><div class="stat-value">{{.TotalFindings}}</div></div>
  <div class="stat-card {{if gt .TotalSecrets 0}}danger{{end}}"><div class="stat-label">Secrets</div><div class="stat-value">{{.TotalSecrets}}</div></div>
</div>

<div class="nav">
  <button class="nav-btn active" onclick="showTab('findings')">Findings</button>
  <button class="nav-btn" onclick="showTab('hosts')">Live Hosts</button>
  <button class="nav-btn" onclick="showTab('subdomains')">Subdomains</button>
  <button class="nav-btn" onclick="showTab('ports')">Ports</button>
  <button class="nav-btn" onclick="showTab('secrets')">Secrets</button>
</div>

<!-- FINDINGS TAB -->
<div id="tab-findings" class="section active">
  <div class="section-title">Vulnerability Findings <span class="count-badge">{{.TotalFindings}}</span></div>
  <div class="summary-cards">
    <div class="sev-card critical"><div class="num">{{.CriticalCount}}</div><div class="lbl">Critical</div></div>
    <div class="sev-card high"><div class="num">{{.HighCount}}</div><div class="lbl">High</div></div>
    <div class="sev-card medium"><div class="num">{{.MediumCount}}</div><div class="lbl">Medium</div></div>
    <div class="sev-card low"><div class="num">{{.LowCount}}</div><div class="lbl">Low</div></div>
  </div>
  {{if .Findings}}
  <div class="table-wrap">
    <table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Target</th><th>Template</th><th>Time</th></tr></thead>
      <tbody>
        {{range .Findings}}
        <tr>
          <td><span class="{{severityClass .Severity}}">{{upper .Severity}}</span></td>
          <td>{{.Name}}</td>
          <td class="mono">{{.Target}}</td>
          <td class="mono muted">{{.Template}}</td>
          <td class="muted" style="white-space:nowrap">{{.FoundAt.Format "15:04:05"}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
  {{else}}<div class="no-data">No findings — either clean or tools not available</div>{{end}}
</div>

<!-- HOSTS TAB -->
<div id="tab-hosts" class="section">
  <div class="section-title">Live Hosts <span class="count-badge">{{.TotalLiveHosts}}</span></div>
  <input class="search-box" type="text" placeholder="Filter hosts..." onkeyup="filterTable(this,'hosts-tbody')">
  {{if .Hosts}}
  <div class="table-wrap">
    <table>
      <thead><tr><th>Domain</th><th>Status</th><th>Title</th><th>Server</th><th>Tech</th><th>Tags</th></tr></thead>
      <tbody id="hosts-tbody">
        {{range .Hosts}}
        <tr>
          <td class="mono"><a href="{{index .Meta "url"}}" target="_blank">{{.Domain}}</a></td>
          <td><span class="{{statusClass .StatusCode}}">{{.StatusCode}}</span></td>
          <td>{{.Title}}</td>
          <td class="muted mono">{{.Server}}</td>
          <td>{{range .TechStack}}<span class="tag">{{.}}</span>{{end}}</td>
          <td>{{range .Tags}}<span class="tag" style="color:#ffd93d">{{.}}</span>{{end}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
  {{else}}<div class="no-data">No live hosts found</div>{{end}}
</div>

<!-- SUBDOMAINS TAB -->
<div id="tab-subdomains" class="section">
  <div class="section-title">All Subdomains <span class="count-badge">{{.TotalSubdomains}}</span></div>
  <input class="search-box" type="text" placeholder="Filter subdomains..." onkeyup="filterTable(this,'subs-tbody')">
  {{if .Subdomains}}
  <div class="table-wrap">
    <table>
      <thead><tr><th>#</th><th>Subdomain</th></tr></thead>
      <tbody id="subs-tbody">
        {{range $i, $s := .Subdomains}}
        <tr><td class="muted mono">{{$i}}</td><td class="mono">{{$s}}</td></tr>
        {{end}}
      </tbody>
    </table>
  </div>
  {{else}}<div class="no-data">No subdomains found</div>{{end}}
</div>

<!-- PORTS TAB -->
<div id="tab-ports" class="section">
  <div class="section-title">Open Ports <span class="count-badge">{{.TotalPorts}}</span></div>
  {{if .Ports}}
  <div class="table-wrap">
    <table>
      <thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th></tr></thead>
      <tbody>
        {{range .Ports}}
        <tr>
          <td class="mono">{{.Host}}</td>
          <td class="mono" style="color:var(--accent)">{{.Port}}</td>
          <td class="muted">{{.Protocol}}</td>
          <td class="muted">{{.Service}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
  {{else}}<div class="no-data">No open ports found or port scan not run</div>{{end}}
</div>

<!-- SECRETS TAB -->
<div id="tab-secrets" class="section">
  <div class="section-title">Discovered Secrets <span class="count-badge">{{.TotalSecrets}}</span></div>
  {{if .Secrets}}
  <div class="table-wrap">
    <table>
      <thead><tr><th>Type</th><th>Source</th><th>File</th><th>Value (truncated)</th></tr></thead>
      <tbody>
        {{range .Secrets}}
        <tr>
          <td><span class="sev-critical">{{.Type}}</span></td>
          <td class="muted mono">{{.Source}}</td>
          <td class="muted mono">{{.File}}</td>
          <td class="mono" style="font-size:11px;word-break:break-all">{{.Value}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
  {{else}}<div class="no-data">No secrets found</div>{{end}}
</div>

<div class="footer">
  <span>ReconX — Automated Bug Bounty Framework</span>
  <span>{{.GeneratedAt}}</span>
</div>

<script>
function showTab(name) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
}
function filterTable(input, tbodyId) {
  const q = input.value.toLowerCase();
  document.querySelectorAll('#' + tbodyId + ' tr').forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
</script>
</body>
</html>`
