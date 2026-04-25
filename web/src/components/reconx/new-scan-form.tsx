"use client";

import React, { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Plus,
  X,
  Globe,
  Network,
  Hash,
  ChevronDown,
  ChevronRight,
  Play,
  Settings,
  Key,
  Zap,
  Save,
  RotateCcw,
  Building2,
  FolderInput,
  FileOutput,
  Users,
  RefreshCw,
} from "lucide-react";
import type { ScanConfig, PhaseKey, SavedSettings } from "@/lib/reconx-types";
import { useToast } from "@/hooks/use-toast";

interface NewScanFormProps {
  onStartScan: (config: ScanConfig) => void;
}

const phases: { key: PhaseKey; label: string; desc: string }[] = [
  { key: "subs", label: "Subdomains", desc: "Enumerate subdomains via subfinder, amass, assetfinder, findomain, chaos, puredns" },
  { key: "alive", label: "Alive Hosts", desc: "Probe for live hosts using httpx" },
  { key: "ports", label: "Port Scan", desc: "Scan open ports with naabu" },
  { key: "urls", label: "URL Discovery", desc: "Discover endpoints with waybackurls, waymore, gau, katana, hakrawler, gospider, paramspider" },
  { key: "js", label: "JS Analysis", desc: "Extract secrets from JS files using trufflehog, mantra, jsecret, subjs" },
  { key: "vuln", label: "Vulnerability Scan", desc: "Detect vulnerabilities with nuclei (critical, high, medium)" },
];

const defaultSettings: SavedSettings = {
  githubToken: "",
  chaosKey: "",
  shodanKey: "",
  virustotalKey: "",
  orgName: "",
  customHeader: "",
  outputDir: "",
  verbose: true,
  noTimeout: false,
  htmlReport: true,
  jsonReport: true,
  saveRaw: true,
  workers: 10,
};

export default function NewScanForm({ onStartScan }: NewScanFormProps) {
  const { toast } = useToast();
  const [isStarting, setIsStarting] = useState(false);
  const [showTokens, setShowTokens] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showOutput, setShowOutput] = useState(false);
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  const [domains, setDomains] = useState<string[]>([""]);
  const [ips, setIps] = useState<string[]>([""]);
  const [asns, setAsns] = useState<string[]>([""]);

  const [phasesEnabled, setPhasesEnabled] = useState<Record<PhaseKey, boolean>>({
    subs: true,
    alive: true,
    ports: true,
    urls: true,
    js: true,
    vuln: true,
  });

  const [githubToken, setGithubToken] = useState("");
  const [chaosKey, setChaosKey] = useState("");
  const [shodanKey, setShodanKey] = useState("");
  const [virustotalKey, setVirustotalKey] = useState("");
  const [orgName, setOrgName] = useState("");
  const [scopeFile, setScopeFile] = useState("");
  const [outputDir, setOutputDir] = useState("");
  const [resumeDir, setResumeDir] = useState("");
  const [noTimeout, setNoTimeout] = useState(false);
  const [verbose, setVerbose] = useState(true);
  const [customHeader, setCustomHeader] = useState("");
  const [workers, setWorkers] = useState(10);
  const [htmlReport, setHtmlReport] = useState(true);
  const [jsonReport, setJsonReport] = useState(true);
  const [saveRaw, setSaveRaw] = useState(true);

  // Load saved settings on mount
  useEffect(() => {
    const loadSettings = async () => {
      try {
        // First try localStorage
        const localSettings = localStorage.getItem("reconx-settings");
        if (localSettings) {
          const parsed = JSON.parse(localSettings) as SavedSettings;
          applySettings(parsed);
          setSettingsLoaded(true);
          return;
        }

        // Then try server API
        const res = await fetch("/api/settings");
        if (res.ok) {
          const data = await res.json();
          applySettings(data.settings);
        }
      } catch {
        // silent
      } finally {
        setSettingsLoaded(true);
      }
    };
    loadSettings();
  }, []);

  const applySettings = (s: SavedSettings) => {
    if (s.githubToken) setGithubToken(s.githubToken);
    if (s.chaosKey) setChaosKey(s.chaosKey);
    if (s.shodanKey) setShodanKey(s.shodanKey);
    if (s.virustotalKey) setVirustotalKey(s.virustotalKey);
    if (s.orgName) setOrgName(s.orgName);
    if (s.customHeader) setCustomHeader(s.customHeader);
    if (s.outputDir) setOutputDir(s.outputDir);
    if (s.verbose !== undefined) setVerbose(s.verbose);
    if (s.noTimeout !== undefined) setNoTimeout(s.noTimeout);
    if (s.htmlReport !== undefined) setHtmlReport(s.htmlReport);
    if (s.jsonReport !== undefined) setJsonReport(s.jsonReport);
    if (s.saveRaw !== undefined) setSaveRaw(s.saveRaw);
    if (s.workers !== undefined) setWorkers(s.workers);
  };

  const getCurrentSettings = (): SavedSettings => ({
    githubToken,
    chaosKey,
    shodanKey,
    virustotalKey,
    orgName,
    customHeader,
    outputDir,
    verbose,
    noTimeout,
    htmlReport,
    jsonReport,
    saveRaw,
    workers,
  });

  const saveSettings = async () => {
    const settings = getCurrentSettings();
    setIsSaving(true);

    try {
      // Save to localStorage
      localStorage.setItem("reconx-settings", JSON.stringify(settings));

      // Save to server API
      const res = await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings),
      });

      if (res.ok) {
        toast({
          title: "Settings saved",
          description: "Your API keys and preferences have been saved. They will auto-load next time.",
        });
      }
    } catch {
      // Still saved to localStorage
      toast({
        title: "Settings saved locally",
        description: "Saved to browser storage. Server sync may have failed.",
      });
    } finally {
      setIsSaving(false);
    }
  };

  const resetSettings = () => {
    applySettings(defaultSettings);
    localStorage.removeItem("reconx-settings");
    toast({
      title: "Settings reset",
      description: "All fields reset to defaults.",
    });
  };

  const addItem = (setter: React.Dispatch<React.SetStateAction<string[]>>) => {
    setter((prev) => [...prev, ""]);
  };

  const removeItem = (
    setter: React.Dispatch<React.SetStateAction<string[]>>,
    index: number
  ) => {
    setter((prev) => prev.filter((_, i) => i !== index));
    if (setter === setDomains && domains.length <= 1) setDomains([""]);
    if (setter === setIps && ips.length <= 1) setIps([""]);
    if (setter === setAsns && asns.length <= 1) setAsns([""]);
  };

  const updateItem = (
    setter: React.Dispatch<React.SetStateAction<string[]>>,
    index: number,
    value: string
  ) => {
    setter((prev) => prev.map((item, i) => (i === index ? value : item)));
  };

  const handleStart = () => {
    const validDomains = domains.filter((d) => d.trim() !== "");
    const validIps = ips.filter((ip) => ip.trim() !== "");
    const validAsns = asns.filter((a) => a.trim() !== "");

    if (
      validDomains.length === 0 &&
      validIps.length === 0 &&
      validAsns.length === 0 &&
      !scopeFile.trim() &&
      !resumeDir.trim()
    ) {
      toast({
        title: "Missing targets",
        description: "Add at least one domain, IP range, ASN, scope file, or resume directory.",
        variant: "destructive",
      });
      return;
    }

    const config: ScanConfig = {
      domains: validDomains,
      ips: validIps,
      asns: validAsns,
      orgName: orgName.trim() || undefined,
      outputDir: outputDir.trim() || `./reconx-output/${Date.now()}`,
      verbose,
      noTimeout,
      customHeader: customHeader.trim() || undefined,
      githubToken: githubToken.trim() || undefined,
      chaosKey: chaosKey.trim() || undefined,
      shodanKey: shodanKey.trim() || undefined,
      virustotalKey: virustotalKey.trim() || undefined,
      scopeFile: scopeFile.trim() || undefined,
      resumeDir: resumeDir.trim() || undefined,
      workers,
      htmlReport,
      jsonReport,
      saveRaw,
      skipSubs: !phasesEnabled.subs,
      skipAlive: !phasesEnabled.alive,
      skipPorts: !phasesEnabled.ports,
      skipUrls: !phasesEnabled.urls,
      skipJs: !phasesEnabled.js,
      skipVuln: !phasesEnabled.vuln,
    };

    // Auto-save settings before starting scan
    const settings = getCurrentSettings();
    localStorage.setItem("reconx-settings", JSON.stringify(settings));

    setIsStarting(true);
    onStartScan(config);
    setTimeout(() => setIsStarting(false), 1000);
  };

  return (
    <div className="space-y-6">
      {/* Header with save button */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Zap className="w-6 h-6 text-[#00ff88]" />
            New Scan
          </h2>
          <p className="text-sm text-gray-400 mt-1">
            Configure your reconnaissance targets and scan phases
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={resetSettings}
            className="text-gray-500 hover:text-red-400 hover:bg-red-500/10 text-xs"
          >
            <RotateCcw className="w-3.5 h-3.5 mr-1" />
            Reset
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={saveSettings}
            disabled={isSaving}
            className="border-emerald-500/20 text-[#00ff88] hover:bg-emerald-500/10 text-xs"
          >
            {isSaving ? (
              <RefreshCw className="w-3.5 h-3.5 mr-1 animate-spin" />
            ) : (
              <Save className="w-3.5 h-3.5 mr-1" />
            )}
            Save Settings
          </Button>
        </div>
      </div>

      {/* Targets */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-4">
          <CardTitle className="text-white text-base flex items-center gap-2">
            <Globe className="w-4 h-4 text-[#00ff88]" />
            Targets
          </CardTitle>
          <CardDescription className="text-gray-400">
            Define the domains, IP ranges, and ASNs to scan
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {/* Domains */}
          <div className="space-y-2">
            <Label className="text-gray-300 text-sm font-medium flex items-center gap-2">
              <Globe className="w-3.5 h-3.5 text-gray-500" />
              Domains
            </Label>
            {domains.map((domain, index) => (
              <div key={index} className="flex gap-2">
                <Input
                  placeholder="example.com"
                  value={domain}
                  onChange={(e) => updateItem(setDomains, index, e.target.value)}
                  className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
                />
                {domains.length > 1 && (
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => removeItem(setDomains, index)}
                    className="shrink-0 text-gray-500 hover:text-red-400 hover:bg-red-500/10 h-9 w-9"
                  >
                    <X className="w-4 h-4" />
                  </Button>
                )}
              </div>
            ))}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => addItem(setDomains)}
              className="text-gray-500 hover:text-[#00ff88] text-xs"
            >
              <Plus className="w-3 h-3 mr-1" /> Add domain
            </Button>
          </div>

          <Separator className="bg-white/5" />

          {/* IPs */}
          <div className="space-y-2">
            <Label className="text-gray-300 text-sm font-medium flex items-center gap-2">
              <Network className="w-3.5 h-3.5 text-gray-500" />
              IP Ranges (CIDR)
            </Label>
            {ips.map((ip, index) => (
              <div key={index} className="flex gap-2">
                <Input
                  placeholder="10.0.0.0/24"
                  value={ip}
                  onChange={(e) => updateItem(setIps, index, e.target.value)}
                  className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
                />
                {ips.length > 1 && (
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => removeItem(setIps, index)}
                    className="shrink-0 text-gray-500 hover:text-red-400 hover:bg-red-500/10 h-9 w-9"
                  >
                    <X className="w-4 h-4" />
                  </Button>
                )}
              </div>
            ))}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => addItem(setIps)}
              className="text-gray-500 hover:text-[#00ff88] text-xs"
            >
              <Plus className="w-3 h-3 mr-1" /> Add IP range
            </Button>
          </div>

          <Separator className="bg-white/5" />

          {/* ASNs */}
          <div className="space-y-2">
            <Label className="text-gray-300 text-sm font-medium flex items-center gap-2">
              <Hash className="w-3.5 h-3.5 text-gray-500" />
              ASNs
            </Label>
            {asns.map((asn, index) => (
              <div key={index} className="flex gap-2">
                <Input
                  placeholder="AS12345"
                  value={asn}
                  onChange={(e) => updateItem(setAsns, index, e.target.value)}
                  className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
                />
                {asns.length > 1 && (
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => removeItem(setAsns, index)}
                    className="shrink-0 text-gray-500 hover:text-red-400 hover:bg-red-500/10 h-9 w-9"
                  >
                    <X className="w-4 h-4" />
                  </Button>
                )}
              </div>
            ))}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => addItem(setAsns)}
              className="text-gray-500 hover:text-[#00ff88] text-xs"
            >
              <Plus className="w-3 h-3 mr-1" /> Add ASN
            </Button>
          </div>

          <Separator className="bg-white/5" />

          {/* Organization Name */}
          <div className="space-y-2">
            <Label className="text-gray-300 text-sm font-medium flex items-center gap-2">
              <Building2 className="w-3.5 h-3.5 text-gray-500" />
              Organization Name
            </Label>
            <Input
              placeholder="Acme Corp (optional)"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
            />
            <p className="text-xs text-gray-500">
              Used for context in scan results and reports
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Phases */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-4">
          <CardTitle className="text-white text-base flex items-center gap-2">
            <Settings className="w-4 h-4 text-[#00ff88]" />
            Scan Phases
          </CardTitle>
          <CardDescription className="text-gray-400">
            Toggle which reconnaissance phases to run
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {phases.map((phase) => (
              <div
                key={phase.key}
                className="flex items-center justify-between p-3 rounded-lg bg-[#0a0c0f] border border-white/5"
              >
                <div className="min-w-0 flex-1 mr-3">
                  <p className="text-sm font-medium text-white">{phase.label}</p>
                  <p className="text-xs text-gray-500 truncate">{phase.desc}</p>
                </div>
                <Switch
                  checked={phasesEnabled[phase.key]}
                  onCheckedChange={(checked) =>
                    setPhasesEnabled((prev) => ({
                      ...prev,
                      [phase.key]: checked,
                    }))
                  }
                  className="data-[state=checked]:bg-[#00ff88]/80 shrink-0"
                />
              </div>
            ))}
          </div>
          <div className="mt-3 flex gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() =>
                setPhasesEnabled({
                  subs: true,
                  alive: true,
                  ports: true,
                  urls: true,
                  js: true,
                  vuln: true,
                })
              }
              className="text-gray-500 hover:text-[#00ff88] text-xs"
            >
              Select All
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() =>
                setPhasesEnabled({
                  subs: false,
                  alive: false,
                  ports: false,
                  urls: false,
                  js: false,
                  vuln: false,
                })
              }
              className="text-gray-500 hover:text-[#00ff88] text-xs"
            >
              Deselect All
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* API Tokens */}
      <Card className="bg-[#111827] border-white/5">
        <button
          className="w-full text-left"
          onClick={() => setShowTokens(!showTokens)}
        >
          <CardHeader className="pb-4 cursor-pointer">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-white text-base flex items-center gap-2">
                  <Key className="w-4 h-4 text-[#00ff88]" />
                  API Tokens
                  {settingsLoaded && (githubToken || chaosKey || shodanKey || virustotalKey) && (
                    <Badge variant="outline" className="border-emerald-500/20 text-emerald-400 text-[10px] ml-2">
                      Saved
                    </Badge>
                  )}
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Optional API keys for enhanced scanning
                </CardDescription>
              </div>
              {showTokens ? (
                <ChevronDown className="w-4 h-4 text-gray-500" />
              ) : (
                <ChevronRight className="w-4 h-4 text-gray-500" />
              )}
            </div>
          </CardHeader>
        </button>
        {showTokens && (
          <CardContent className="pt-0 space-y-4">
            <div className="space-y-2">
              <Label className="text-gray-300 text-sm">GitHub Token</Label>
              <Input
                type="password"
                placeholder="ghp_xxxxxxxxxxxx"
                value={githubToken}
                onChange={(e) => setGithubToken(e.target.value)}
                className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
              />
              <p className="text-xs text-gray-500">
                Used for GitHub dorking and code search
              </p>
            </div>
            <div className="space-y-2">
              <Label className="text-gray-300 text-sm">Chaos Project Key (PDCP)</Label>
              <Input
                type="password"
                placeholder="xxxxxxxxxxxx"
                value={chaosKey}
                onChange={(e) => setChaosKey(e.target.value)}
                className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
              />
              <p className="text-xs text-gray-500">
                ProjectDiscovery Chaos dataset API key for subdomain discovery
              </p>
            </div>
            <div className="space-y-2">
              <Label className="text-gray-300 text-sm">Shodan API Key</Label>
              <Input
                type="password"
                placeholder="xxxxxxxxxxxx"
                value={shodanKey}
                onChange={(e) => setShodanKey(e.target.value)}
                className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
              />
              <p className="text-xs text-gray-500">
                Shodan API key for internet-wide service scanning intelligence
              </p>
            </div>
            <div className="space-y-2">
              <Label className="text-gray-300 text-sm">VirusTotal API Key</Label>
              <Input
                type="password"
                placeholder="xxxxxxxxxxxx"
                value={virustotalKey}
                onChange={(e) => setVirustotalKey(e.target.value)}
                className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
              />
              <p className="text-xs text-gray-500">
                VirusTotal API key for domain/IP reputation analysis
              </p>
            </div>
          </CardContent>
        )}
      </Card>

      {/* Advanced Options */}
      <Card className="bg-[#111827] border-white/5">
        <button
          className="w-full text-left"
          onClick={() => setShowAdvanced(!showAdvanced)}
        >
          <CardHeader className="pb-4 cursor-pointer">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-white text-base flex items-center gap-2">
                  <Settings className="w-4 h-4 text-gray-500" />
                  Advanced Options
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Fine-tune scan behavior
                </CardDescription>
              </div>
              {showAdvanced ? (
                <ChevronDown className="w-4 h-4 text-gray-500" />
              ) : (
                <ChevronRight className="w-4 h-4 text-gray-500" />
              )}
            </div>
          </CardHeader>
        </button>
        {showAdvanced && (
          <CardContent className="pt-0 space-y-4">
            <div className="space-y-2">
              <Label className="text-gray-300 text-sm">Output Directory</Label>
              <Input
                placeholder="Auto-generated if empty"
                value={outputDir}
                onChange={(e) => setOutputDir(e.target.value)}
                className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-gray-300 text-sm">Scope File Path</Label>
              <Input
                placeholder="/path/to/scope.txt"
                value={scopeFile}
                onChange={(e) => setScopeFile(e.target.value)}
                className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
              />
              <p className="text-xs text-gray-500">
                Format: +*.example.com (in-scope) / -staging.example.com (out-of-scope)
              </p>
            </div>
            <div className="space-y-2">
              <Label className="text-gray-300 text-sm flex items-center gap-2">
                <FolderInput className="w-3.5 h-3.5 text-gray-500" />
                Resume from Directory
              </Label>
              <Input
                placeholder="./reconx-output/target.com-1234567"
                value={resumeDir}
                onChange={(e) => setResumeDir(e.target.value)}
                className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
              />
              <p className="text-xs text-gray-500">
                Continue a previous scan from where it left off. Skips already-completed phases.
              </p>
            </div>
            <div className="space-y-2">
              <Label className="text-gray-300 text-sm">Custom Header</Label>
              <Input
                placeholder='X-Bug-Bounty: True'
                value={customHeader}
                onChange={(e) => setCustomHeader(e.target.value)}
                className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
              />
              <p className="text-xs text-gray-500">
                Added to all HTTP requests (e.g., to identify yourself to the target)
              </p>
            </div>
            <div className="space-y-2">
              <Label className="text-gray-300 text-sm flex items-center gap-2">
                <Users className="w-3.5 h-3.5 text-gray-500" />
                Workers
              </Label>
              <Input
                type="number"
                min={1}
                max={100}
                value={workers}
                onChange={(e) => setWorkers(parseInt(e.target.value) || 10)}
                className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm w-24"
              />
              <p className="text-xs text-gray-500">
                Number of concurrent worker threads (default: 10)
              </p>
            </div>
            <Separator className="bg-white/5" />
            <div className="flex items-center justify-between p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <div>
                <p className="text-sm font-medium text-white">Verbose Mode</p>
                <p className="text-xs text-gray-500">Show detailed tool output in logs</p>
              </div>
              <Switch
                checked={verbose}
                onCheckedChange={setVerbose}
                className="data-[state=checked]:bg-[#00ff88]/80"
              />
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <div>
                <p className="text-sm font-medium text-white">No Timeout</p>
                <p className="text-xs text-gray-500">
                  Disable all tool timeouts. Recommended for large targets (1000+ subdomains).
                </p>
              </div>
              <Switch
                checked={noTimeout}
                onCheckedChange={setNoTimeout}
                className="data-[state=checked]:bg-[#00ff88]/80"
              />
            </div>
          </CardContent>
        )}
      </Card>

      {/* Output Options */}
      <Card className="bg-[#111827] border-white/5">
        <button
          className="w-full text-left"
          onClick={() => setShowOutput(!showOutput)}
        >
          <CardHeader className="pb-4 cursor-pointer">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-white text-base flex items-center gap-2">
                  <FileOutput className="w-4 h-4 text-[#00ff88]" />
                  Output Options
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Configure report generation and data saving
                </CardDescription>
              </div>
              {showOutput ? (
                <ChevronDown className="w-4 h-4 text-gray-500" />
              ) : (
                <ChevronRight className="w-4 h-4 text-gray-500" />
              )}
            </div>
          </CardHeader>
        </button>
        {showOutput && (
          <CardContent className="pt-0 space-y-3">
            <div className="flex items-center justify-between p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <div>
                <p className="text-sm font-medium text-white">HTML Report</p>
                <p className="text-xs text-gray-500">Generate a formatted HTML report</p>
              </div>
              <Switch
                checked={htmlReport}
                onCheckedChange={setHtmlReport}
                className="data-[state=checked]:bg-[#00ff88]/80"
              />
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <div>
                <p className="text-sm font-medium text-white">JSON Report</p>
                <p className="text-xs text-gray-500">Export structured results as JSON</p>
              </div>
              <Switch
                checked={jsonReport}
                onCheckedChange={setJsonReport}
                className="data-[state=checked]:bg-[#00ff88]/80"
              />
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <div>
                <p className="text-sm font-medium text-white">Save Raw Output</p>
                <p className="text-xs text-gray-500">Keep raw tool output files for debugging</p>
              </div>
              <Switch
                checked={saveRaw}
                onCheckedChange={setSaveRaw}
                className="data-[state=checked]:bg-[#00ff88]/80"
              />
            </div>
          </CardContent>
        )}
      </Card>

      {/* Start Button */}
      <div className="flex items-center gap-4 pt-2">
        <Button
          onClick={handleStart}
          disabled={isStarting}
          className="bg-[#00ff88] text-[#0a0c0f] hover:bg-[#00cc6e] font-semibold px-8 h-11 text-sm"
        >
          {isStarting ? (
            <span className="flex items-center gap-2">
              <span className="w-4 h-4 border-2 border-[#0a0c0f] border-t-transparent rounded-full animate-spin" />
              Launching...
            </span>
          ) : (
            <span className="flex items-center gap-2">
              <Play className="w-4 h-4" />
              Launch Scan
            </span>
          )}
        </Button>
        <p className="text-xs text-gray-500">
          <Badge variant="outline" className="border-white/10 text-gray-400 mr-1">
            {domains.filter((d) => d.trim()).length} domains
          </Badge>
          <Badge variant="outline" className="border-white/10 text-gray-400 mr-1">
            {ips.filter((ip) => ip.trim()).length} IPs
          </Badge>
          <Badge variant="outline" className="border-white/10 text-gray-400 mr-1">
            {asns.filter((a) => a.trim()).length} ASNs
          </Badge>
          {resumeDir.trim() && (
            <Badge variant="outline" className="border-yellow-500/20 text-yellow-400 mr-1">
              Resume
            </Badge>
          )}
        </p>
      </div>
    </div>
  );
}
