"use client";

import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  BookOpen,
  Terminal,
  Globe,
  Download,
  Key,
  Zap,
  FolderOpen,
  Settings,
  AlertTriangle,
  CheckCircle2,
  ArrowRight,
  Code,
  Shield,
} from "lucide-react";

export default function GuidePage() {
  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <BookOpen className="w-6 h-6 text-[#00ff88]" />
          Quick Guide
        </h2>
        <p className="text-sm text-gray-400 mt-1">
          Everything you need to know about running ReconX
        </p>
      </div>

      {/* What is ReconX */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-3">
          <CardTitle className="text-white text-base flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#00ff88]" />
            What is ReconX?
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-gray-300">
          <p>
            ReconX is an automated bug bounty reconnaissance framework that chains together
            industry-standard tools to perform full-spectrum recon on your targets. It
            automates subdomain enumeration, alive host detection, port scanning, URL discovery,
            JavaScript secret extraction, and vulnerability scanning in a single pipeline.
          </p>
          <p>
            Instead of manually running 20+ tools and managing their outputs, ReconX handles
            everything for you — from input to final structured reports with all findings
            organized and ready to use.
          </p>
          <div className="flex flex-wrap gap-2 mt-3">
            <Badge variant="outline" className="border-emerald-500/20 text-emerald-400">subfinder</Badge>
            <Badge variant="outline" className="border-emerald-500/20 text-emerald-400">amass</Badge>
            <Badge variant="outline" className="border-emerald-500/20 text-emerald-400">assetfinder</Badge>
            <Badge variant="outline" className="border-emerald-500/20 text-emerald-400">findomain</Badge>
            <Badge variant="outline" className="border-emerald-500/20 text-emerald-400">httpx</Badge>
            <Badge variant="outline" className="border-emerald-500/20 text-emerald-400">naabu</Badge>
            <Badge variant="outline" className="border-emerald-500/20 text-emerald-400">nuclei</Badge>
            <Badge variant="outline" className="border-emerald-500/20 text-emerald-400">katana</Badge>
            <Badge variant="outline" className="border-emerald-500/20 text-emerald-400">trufflehog</Badge>
            <Badge variant="outline" className="border-emerald-500/20 text-emerald-400">gau</Badge>
            <Badge variant="outline" className="border-emerald-500/20 text-emerald-400">waybackurls</Badge>
            <Badge variant="outline" className="border-emerald-500/20 text-emerald-400">+ more</Badge>
          </div>
        </CardContent>
      </Card>

      {/* Step 1: Install Tools */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-3">
          <CardTitle className="text-white text-base flex items-center gap-2">
            <Download className="w-4 h-4 text-[#00ff88]" />
            Step 1: Install Required Tools
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-gray-300">
            ReconX uses external tools that need to be installed on your system first.
            Install them using the quick install script or manually:
          </p>
          <div className="bg-[#050709] rounded-lg p-4 font-mono text-xs text-gray-300 space-y-1">
            <p className="text-gray-500"># Quick install (run as root/sudo):</p>
            <p><span className="text-[#00ff88]">cd</span> reconx</p>
            <p><span className="text-[#00ff88]">bash</span> install.sh</p>
          </div>
          <div className="bg-[#050709] rounded-lg p-4 font-mono text-xs text-gray-300 space-y-1">
            <p className="text-gray-500"># Or install tools individually (Go-based):</p>
            <p>go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest</p>
            <p>go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest</p>
            <p>go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest</p>
            <p>go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest</p>
            <p>go install -v github.com/projectdiscovery/katana/cmd/katana@latest</p>
            <p>go install -v github.com/owasp-amass/amass/v4/...@latest</p>
            <p>go install -v github.com/tomnomnom/assetfinder@latest</p>
            <p>go install -v github.com/tomnomnom/waybackurls@latest</p>
            <p>go install -v github.com/lc/gau/v2/cmd/gau@latest</p>
          </div>
          <div className="flex items-start gap-2 p-3 rounded-lg bg-yellow-500/5 border border-yellow-500/10">
            <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5 shrink-0" />
            <p className="text-xs text-yellow-300">
              Make sure <code className="bg-yellow-500/10 px-1 rounded">go</code> is installed
              and <code className="bg-yellow-500/10 px-1 rounded">$GOPATH/bin</code> is in your PATH.
              Tools must be accessible as commands in your terminal.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Step 2: Build ReconX */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-3">
          <CardTitle className="text-white text-base flex items-center gap-2">
            <Code className="w-4 h-4 text-[#00ff88]" />
            Step 2: Build ReconX Binary
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-gray-300">
            Compile the ReconX binary from source. The build script creates a static
            Linux amd64 binary in the <code className="bg-white/5 px-1.5 py-0.5 rounded text-[#00ff88]">dist/</code> directory.
          </p>
          <div className="bg-[#050709] rounded-lg p-4 font-mono text-xs text-gray-300 space-y-1">
            <p><span className="text-gray-500"># Clone and build:</span></p>
            <p><span className="text-[#00ff88]">cd</span> reconx</p>
            <p><span className="text-[#00ff88]">make</span></p>
            <p className="text-gray-500"># Binary will be at: dist/reconx-linux-amd64</p>
          </div>
        </CardContent>
      </Card>

      {/* Step 3: Run the Web GUI */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-3">
          <CardTitle className="text-white text-base flex items-center gap-2">
            <Terminal className="w-4 h-4 text-[#00ff88]" />
            Step 3: Run the Web GUI
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-gray-300">
            The web GUI is a Next.js application that provides a browser interface for
            configuring and running scans. Start it with these commands:
          </p>
          <div className="bg-[#050709] rounded-lg p-4 font-mono text-xs text-gray-300 space-y-1">
            <p><span className="text-gray-500"># Navigate to the web directory:</span></p>
            <p><span className="text-[#00ff88]">cd</span> reconx/web</p>
            <p></p>
            <p><span className="text-gray-500"># Install dependencies (first time only):</span></p>
            <p><span className="text-[#00ff88]">npm</span> install</p>
            <p></p>
            <p><span className="text-gray-500"># Start the development server:</span></p>
            <p><span className="text-[#00ff88]">npm</span> run dev</p>
            <p></p>
            <p><span className="text-gray-500"># Or build for production:</span></p>
            <p><span className="text-[#00ff88]">npm</span> run build</p>
            <p><span className="text-[#00ff88]">npm</span> start</p>
          </div>
          <div className="flex items-start gap-2 p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/10">
            <CheckCircle2 className="w-4 h-4 text-[#00ff88] mt-0.5 shrink-0" />
            <p className="text-xs text-gray-300">
              The GUI will be available at <code className="bg-white/5 px-1.5 py-0.5 rounded text-[#00ff88]">http://localhost:3000</code>.
              Open it in your browser and start configuring scans.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Step 4: Configure Scan */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-3">
          <CardTitle className="text-white text-base flex items-center gap-2">
            <Settings className="w-4 h-4 text-[#00ff88]" />
            Step 4: Configure and Launch a Scan
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-gray-300">
            In the web GUI, go to the <strong className="text-white">New Scan</strong> page and fill in your targets:
          </p>
          <div className="space-y-3">
            <div className="flex items-start gap-3">
              <div className="flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500/10 text-[#00ff88] text-xs font-bold shrink-0 mt-0.5">
                1
              </div>
              <div>
                <p className="text-sm font-medium text-white">Add Targets</p>
                <p className="text-xs text-gray-400">
                  Enter domain names (e.g., example.com), IP ranges (e.g., 10.0.0.0/24),
                  or ASNs (e.g., AS12345). You can add multiple targets at once.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <div className="flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500/10 text-[#00ff88] text-xs font-bold shrink-0 mt-0.5">
                2
              </div>
              <div>
                <p className="text-sm font-medium text-white">Set API Keys (Optional)</p>
                <p className="text-xs text-gray-400">
                  Expand the <strong>API Tokens</strong> section and enter your keys. Click{" "}
                  <strong>Save Settings</strong> to persist them — you won&apos;t need to re-enter them next time.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <div className="flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500/10 text-[#00ff88] text-xs font-bold shrink-0 mt-0.5">
                3
              </div>
              <div>
                <p className="text-sm font-medium text-white">Choose Phases</p>
                <p className="text-xs text-gray-400">
                  Toggle scan phases on/off. For a quick scan, disable Port Scan and Vuln Scan.
                  For a deep recon, keep everything enabled.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <div className="flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500/10 text-[#00ff88] text-xs font-bold shrink-0 mt-0.5">
                4
              </div>
              <div>
                <p className="text-sm font-medium text-white">Click Launch Scan</p>
                <p className="text-xs text-gray-400">
                  Hit the green button and monitor progress in real-time. You can stop the scan
                  at any time from the progress page.
                </p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Step 5: Results */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-3">
          <CardTitle className="text-white text-base flex items-center gap-2">
            <FolderOpen className="w-4 h-4 text-[#00ff88]" />
            Step 5: View Results
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-gray-300">
          <p>
            When the scan completes, results are available in two places:
          </p>
          <ul className="list-disc list-inside space-y-1.5 text-xs text-gray-400 ml-2">
            <li>
              <strong className="text-white">Web GUI</strong> — Results dashboard with tabs for
              findings, hosts, subdomains, ports, secrets, and URLs with filtering and copy-to-clipboard.
            </li>
            <li>
              <strong className="text-white">Output files</strong> — JSON and HTML reports in the
              scan output directory, plus raw tool output for each phase.
            </li>
          </ul>
        </CardContent>
      </Card>

      {/* CLI Alternative */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-3">
          <CardTitle className="text-white text-base flex items-center gap-2">
            <Terminal className="w-4 h-4 text-gray-500" />
            CLI Alternative
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-gray-300">
            You can also run ReconX directly from the command line without the web GUI:
          </p>
          <div className="bg-[#050709] rounded-lg p-4 font-mono text-xs text-gray-300 space-y-2">
            <p className="text-gray-500"># Basic scan:</p>
            <p>./dist/reconx-linux-amd64 -d example.com</p>
            <p></p>
            <p className="text-gray-500"># Full scan with no timeouts (large targets):</p>
            <p>./dist/reconx-linux-amd64 -d airbnb.com --scope scope.txt \</p>
            <p>  --header &quot;X-Bug-Bounty: True&quot; --no-timeout --skip-ports</p>
            <p></p>
            <p className="text-gray-500"># Resume a suspended scan:</p>
            <p>./dist/reconx-linux-amd64 --resume ./airbnb-scan/airbnb.com-1774175844 --no-timeout</p>
            <p></p>
            <p className="text-gray-500"># Quick scan (skip slow phases):</p>
            <p>./dist/reconx-linux-amd64 -d target.com --skip-ports --skip-vuln</p>
            <p></p>
            <p className="text-gray-500"># With API keys via environment variables:</p>
            <p>GITHUB_TOKEN=ghp_xxx PDCP_API_KEY=xxx \</p>
            <p>  ./dist/reconx-linux-amd64 -d example.com -v</p>
          </div>
        </CardContent>
      </Card>

      {/* API Keys Info */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-3">
          <CardTitle className="text-white text-base flex items-center gap-2">
            <Key className="w-4 h-4 text-[#00ff88]" />
            API Keys Reference
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <p className="text-sm font-medium text-white flex items-center gap-2">
                GitHub Token
                <Badge variant="outline" className="border-white/10 text-gray-500 text-[10px]">Optional</Badge>
              </p>
              <p className="text-xs text-gray-400 mt-1">
                Used for GitHub code search dorking to find sensitive info, API keys, and
                internal URLs in the target&apos;s repositories. Get it from GitHub Settings &gt;
                Developer Settings &gt; Personal Access Tokens.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <p className="text-sm font-medium text-white flex items-center gap-2">
                Chaos Project Key (PDCP)
                <Badge variant="outline" className="border-white/10 text-gray-500 text-[10px]">Optional</Badge>
              </p>
              <p className="text-xs text-gray-400 mt-1">
                ProjectDiscovery Chaos dataset for discovering subdomains that may not
                appear through traditional DNS enumeration. Get it from pdcp.projectdiscovery.io.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <p className="text-sm font-medium text-white flex items-center gap-2">
                Shodan API Key
                <Badge variant="outline" className="border-white/10 text-gray-500 text-[10px]">Optional</Badge>
              </p>
              <p className="text-xs text-gray-400 mt-1">
                Internet-wide scanning intelligence. Used via environment variable SHODAN_API_KEY
                for additional host discovery and service fingerprinting data.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <p className="text-sm font-medium text-white flex items-center gap-2">
                VirusTotal API Key
                <Badge variant="outline" className="border-white/10 text-gray-500 text-[10px]">Optional</Badge>
              </p>
              <p className="text-xs text-gray-400 mt-1">
                Domain and IP reputation analysis. Used via environment variable VT_API_KEY
                for detecting potentially malicious infrastructure.
              </p>
            </div>
          </div>
          <div className="flex items-start gap-2 p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/10 mt-4">
            <CheckCircle2 className="w-4 h-4 text-[#00ff88] mt-0.5 shrink-0" />
            <p className="text-xs text-gray-300">
              All API keys are <strong>optional</strong> — ReconX works without them. They enhance
              results but aren&apos;t required for the core scanning pipeline. Keys are saved locally
              and never sent to any third-party server.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Tips */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-3">
          <CardTitle className="text-white text-base flex items-center gap-2">
            <Zap className="w-4 h-4 text-yellow-400" />
            Tips & Best Practices
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2.5">
            <div className="flex items-start gap-2">
              <ArrowRight className="w-3.5 h-3.5 text-yellow-400 mt-0.5 shrink-0" />
              <p className="text-xs text-gray-300">
                For <strong className="text-white">large targets</strong> (1000+ subdomains), enable{" "}
                <strong className="text-[#00ff88]">No Timeout</strong> and consider disabling{" "}
                <strong>Port Scan</strong> to save time.
              </p>
            </div>
            <div className="flex items-start gap-2">
              <ArrowRight className="w-3.5 h-3.5 text-yellow-400 mt-0.5 shrink-0" />
              <p className="text-xs text-gray-300">
                Use <strong className="text-white">Scope Files</strong> to filter results.
                Format: <code className="bg-white/5 px-1 rounded">+*.example.com</code> (include)
                and <code className="bg-white/5 px-1 rounded">-staging.example.com</code> (exclude).
              </p>
            </div>
            <div className="flex items-start gap-2">
              <ArrowRight className="w-3.5 h-3.5 text-yellow-400 mt-0.5 shrink-0" />
              <p className="text-xs text-gray-300">
                If a scan gets interrupted, use <strong className="text-white">Resume from Directory</strong>{" "}
                to continue from where it stopped. Already-completed phases are skipped.
              </p>
            </div>
            <div className="flex items-start gap-2">
              <ArrowRight className="w-3.5 h-3.5 text-yellow-400 mt-0.5 shrink-0" />
              <p className="text-xs text-gray-300">
                Add a <strong className="text-white">Custom Header</strong> like{" "}
                <code className="bg-white/5 px-1 rounded">X-Bug-Bounty: True</code> to identify
                yourself to the target and avoid potential IP blocks.
              </p>
            </div>
            <div className="flex items-start gap-2">
              <ArrowRight className="w-3.5 h-3.5 text-yellow-400 mt-0.5 shrink-0" />
              <p className="text-xs text-gray-300">
                Check <strong className="text-white">Scan History</strong> to see past scans, view
                results, or monitor running scans from any browser tab.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Scan Phases Explained */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-3">
          <CardTitle className="text-white text-base flex items-center gap-2">
            <Globe className="w-4 h-4 text-[#00ff88]" />
            Scan Phases Explained
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <div className="flex items-center gap-2 mb-1">
                <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20 border text-[10px]">Phase 1</Badge>
                <p className="text-sm font-medium text-white">Subdomain Enumeration</p>
              </div>
              <p className="text-xs text-gray-400">
                Discovers all subdomains using subfinder, amass, assetfinder, findomain,
                chaos, puredns (bruteforce), and dnsx (validation). This builds your complete
                attack surface map.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <div className="flex items-center gap-2 mb-1">
                <Badge className="bg-cyan-500/10 text-cyan-400 border-cyan-500/20 border text-[10px]">Phase 2</Badge>
                <p className="text-sm font-medium text-white">Alive Host Detection</p>
              </div>
              <p className="text-xs text-gray-400">
                Probes discovered subdomains with httpx to find which ones have live
                web servers. Extracts status codes, titles, web servers, and content lengths.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <div className="flex items-center gap-2 mb-1">
                <Badge className="bg-orange-500/10 text-orange-400 border-orange-500/20 border text-[10px]">Phase 3</Badge>
                <p className="text-sm font-medium text-white">Port Scanning</p>
              </div>
              <p className="text-xs text-gray-400">
                Scans all live hosts for open ports using naabu. Identifies running
                services that may not be accessible via HTTP. Can be time-consuming on large targets.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <div className="flex items-center gap-2 mb-1">
                <Badge className="bg-purple-500/10 text-purple-400 border-purple-500/20 border text-[10px]">Phase 4</Badge>
                <p className="text-sm font-medium text-white">URL Discovery</p>
              </div>
              <p className="text-xs text-gray-400">
                Crawls and collects URLs from Wayback Machine, CommonCrawl (GAU/GAU+),
                katana (headless crawler), hakrawler, gospider, and paramspider.
                Builds a comprehensive endpoint map.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <div className="flex items-center gap-2 mb-1">
                <Badge className="bg-yellow-500/10 text-yellow-400 border-yellow-500/20 border text-[10px]">Phase 5</Badge>
                <p className="text-sm font-medium text-white">JavaScript Analysis</p>
              </div>
              <p className="text-xs text-gray-400">
                Downloads and analyzes JS files from live hosts. Extracts secrets,
                API keys, endpoints, and sensitive data using trufflehog, mantra,
                jsecret, and subjs.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <div className="flex items-center gap-2 mb-1">
                <Badge className="bg-red-500/10 text-red-400 border-red-500/20 border text-[10px]">Phase 6</Badge>
                <p className="text-sm font-medium text-white">Vulnerability Scanning</p>
              </div>
              <p className="text-xs text-gray-400">
                Runs nuclei templates against live hosts with severity filter
                (critical, high, medium). Detects CVEs, misconfigurations,
                exposed panels, and common vulnerability patterns.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
