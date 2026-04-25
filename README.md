# ReconX — Automated Bug Bounty Recon Framework

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║ ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║ ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║██╔╝╚██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝╚═╝  ╚═╝
```

> Give it a domain. Walk away. Come back to findings.

---

## Architecture

```
Input (domains / IPs / ASNs / scope)
        │
        ▼
┌─────────────────────────────────────────────┐
│              Pipeline Engine                │
│  ┌──────────┐ ┌──────────┐ ┌─────────────┐ │
│  │ Phase 1  │ │ Phase 2  │ │  Phase 3    │ │
│  │ Subdomain│→│  Alive   │→│  Port Scan  │ │
│  │   Enum   │ │  Check   │ │   (naabu)   │ │
│  └──────────┘ └──────────┘ └─────────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌─────────────┐ │
│  │ Phase 4  │ │ Phase 5  │ │  Phase 6    │ │
│  │   URL    │→│    JS    │→│    Vuln     │ │
│  │Discovery │ │ Secrets  │ │   Scanning  │ │
│  └──────────┘ └──────────┘ └─────────────┘ │
└─────────────────────────────────────────────┘
        │
        ▼
  ┌──────────────────┐
  │  Central Store   │  (thread-safe in-memory)
  │  subdomains      │
  │  live hosts      │
  │  ports           │
  │  URLs            │
  │  JS files        │
  │  findings        │
  │  secrets         │
  └──────────────────┘
        │
        ▼
  Output: colored terminal + HTML report + raw TXT files
```

## Installation

```bash
git clone https://github.com/yourorg/reconx
cd reconx
bash install.sh
```

The installer:
1. Installs all Go-based tools (subfinder, httpx, nuclei, katana, etc.)
2. Downloads nuclei templates
3. Downloads fresh DNS resolvers
4. Builds the `reconx` binary and puts it in PATH

## Quick Start

```bash
# Single domain, full auto
reconx -d example.com

# Multiple domains
reconx -d example.com -d api.example.com -d dev.example.com

# With scope enforcement
reconx -d example.com --scope scope.txt

# With IP ranges and ASN
reconx -d example.com --ip 10.20.0.0/16 --asn AS12345

# Skip slow phases for quick recon
reconx -d example.com --skip-ports --skip-vuln

# Full run with API tokens
reconx -d example.com \
  --github-token ghp_xxxx \
  --chaos-key your_chaos_key \
  --output ./my-scans \
  --verbose
```

## Scope File Format

Create a `scope.txt`:
```
# Lines starting with + are IN scope
# Lines starting with - are OUT OF scope
# Bare lines are treated as in-scope

+*.example.com
+api.example.com
+example.com
-staging.example.com
-dev.example.com
-internal.example.com
```

Then run:
```bash
reconx -d example.com --scope scope.txt
```

## Config File (`reconx.yaml`)

Generate a default config:
```bash
reconx init
```

Full config reference — all values can be overridden per-run via CLI flags:
```yaml
workers: 10

scope:
  in_scope:     ["*.example.com"]
  out_of_scope: ["staging.example.com"]

phases:
  subdomain_enum: true
  alive_check:    true
  port_scan:      true
  url_discovery:  true
  js_analysis:    true
  vuln_scan:      true
  report:         true

output:
  output_dir:       "./reconx-output"
  html_report:      true
  json_report:      true
  colored_terminal: true
  verbose:          false

tokens:
  github:     "ghp_xxxx"
  chaos:      "your_chaos_key"
  shodan:     ""
  virustotal: ""

tools:
  subfinder:
    enabled: true
    flags: ["-all", "-recursive"]
    timeout_seconds: 300
  nuclei:
    enabled: true
    flags: ["-severity", "critical,high,medium"]
    timeout_seconds: 900
  # ... (all tools configurable)
```

## Phase Details

| Phase | Tools Used | Output Files |
|-------|-----------|--------------|
| **Subdomain Enum** | subfinder, assetfinder, amass, findomain, chaos, crt.sh | `subdomains.txt` |
| **Alive Check** | httpx | `alive.txt` |
| **Port Scan** | naabu | (stored in report) |
| **URL Discovery** | waybackurls, gau, katana, hakrawler, gospider | `urls.txt`, `urls_js.txt`, `urls_admin.txt`, etc. |
| **JS Analysis** | mantra, jsecret, trufflehog, subjs | `js_files.txt` |
| **Vuln Scan** | nuclei (exposures, CVEs, misconfigs, takeovers) | (in report) |
| **Report** | built-in | `report.html`, `results.json` |

## Output Structure

```
reconx-output/
└── example.com-1714000000/
    ├── report.html          ← full interactive HTML report
    ├── results.json         ← machine-readable JSON
    ├── subdomains.txt       ← all unique subdomains
    ├── alive.txt            ← live hosts
    ├── urls.txt             ← all discovered URLs
    ├── urls_js.txt          ← JS files only
    ├── urls_admin.txt       ← admin panel URLs
    ├── urls_login.txt       ← login/auth URLs
    ├── urls_params.txt      ← parameterized URLs
    ├── urls_api.txt         ← API endpoints
    ├── urls_sensitive.txt   ← .env, .bak, .sql etc.
    ├── urls_idor.txt        ← numeric ID URLs
    ├── js_files.txt         ← JS file URLs
    └── nuclei_targets.txt   ← targets fed to nuclei
```

## Environment Variables

```bash
export GITHUB_TOKEN=ghp_xxxx       # github-subdomains
export PDCP_API_KEY=your_key       # chaos dataset
export SHODAN_API_KEY=xxxx         # shodan enrichment
export VT_API_KEY=xxxx             # VirusTotal
```

## Adding Custom Modules

The pipeline is modular. To add a new phase:

1. Create `internal/modules/yourmodule/yourmodule.go`
2. Implement `func (m *Module) Run(ctx context.Context) error`
3. Register it in `internal/pipeline/pipeline.go`

## Legal Notice

This tool is for authorized security testing only. Only run against
targets you have explicit written permission to test. The authors
assume no liability for misuse.

## License

MIT
