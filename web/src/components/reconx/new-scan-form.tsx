"use client";

import React, { useState } from "react";
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
} from "lucide-react";
import type { ScanConfig, PhaseKey } from "@/lib/reconx-types";
import { useToast } from "@/hooks/use-toast";

interface NewScanFormProps {
  onStartScan: (config: ScanConfig) => void;
}

const phases: { key: PhaseKey; label: string; desc: string }[] = [
  { key: "subs", label: "Subdomains", desc: "Enumerate subdomains" },
  { key: "alive", label: "Alive Hosts", desc: "Probe for live hosts" },
  { key: "ports", label: "Port Scan", desc: "Scan open ports" },
  { key: "urls", label: "URL Discovery", desc: "Discover endpoints" },
  { key: "js", label: "JS Analysis", desc: "Extract secrets from JS" },
  { key: "vuln", label: "Vulnerability Scan", desc: "Detect vulnerabilities" },
];

export default function NewScanForm({ onStartScan }: NewScanFormProps) {
  const { toast } = useToast();
  const [isStarting, setIsStarting] = useState(false);
  const [showTokens, setShowTokens] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

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
  const [scopeFile, setScopeFile] = useState("");
  const [outputDir, setOutputDir] = useState("");
  const [noTimeout, setNoTimeout] = useState(false);
  const [verbose, setVerbose] = useState(true);
  const [customHeader, setCustomHeader] = useState("");

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
      !scopeFile.trim()
    ) {
      toast({
        title: "Missing targets",
        description: "Add at least one domain, IP range, ASN, or scope file.",
        variant: "destructive",
      });
      return;
    }

    const config: ScanConfig = {
      domains: validDomains,
      ips: validIps,
      asns: validAsns,
      outputDir: outputDir.trim() || `./reconx-output/${Date.now()}`,
      verbose,
      noTimeout,
      customHeader: customHeader.trim() || undefined,
      githubToken: githubToken.trim() || undefined,
      chaosKey: chaosKey.trim() || undefined,
      scopeFile: scopeFile.trim() || undefined,
      skipSubs: !phasesEnabled.subs,
      skipAlive: !phasesEnabled.alive,
      skipPorts: !phasesEnabled.ports,
      skipUrls: !phasesEnabled.urls,
      skipJs: !phasesEnabled.js,
      skipVuln: !phasesEnabled.vuln,
    };

    setIsStarting(true);
    onStartScan(config);
    setTimeout(() => setIsStarting(false), 1000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Zap className="w-6 h-6 text-[#00ff88]" />
          New Scan
        </h2>
        <p className="text-sm text-gray-400 mt-1">
          Configure your reconnaissance targets and scan phases
        </p>
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
              IP Ranges
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
                <div>
                  <p className="text-sm font-medium text-white">{phase.label}</p>
                  <p className="text-xs text-gray-500">{phase.desc}</p>
                </div>
                <Switch
                  checked={phasesEnabled[phase.key]}
                  onCheckedChange={(checked) =>
                    setPhasesEnabled((prev) => ({
                      ...prev,
                      [phase.key]: checked,
                    }))
                  }
                  className="data-[state=checked]:bg-[#00ff88]/80"
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
              <Label className="text-gray-300 text-sm">Chaos Project Key</Label>
              <Input
                type="password"
                placeholder="xxxxxxxxxxxx"
                value={chaosKey}
                onChange={(e) => setChaosKey(e.target.value)}
                className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
              />
              <p className="text-xs text-gray-500">
                Chaos dataset API key for subdomain discovery
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
            </div>
            <div className="space-y-2">
              <Label className="text-gray-300 text-sm">Custom Header</Label>
              <Input
                placeholder='X-Bug-Bounty: True'
                value={customHeader}
                onChange={(e) => setCustomHeader(e.target.value)}
                className="bg-[#0a0c0f] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
              />
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-[#0a0c0f] border border-white/5">
              <div>
                <p className="text-sm font-medium text-white">Verbose Mode</p>
                <p className="text-xs text-gray-500">Show detailed output</p>
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
                <p className="text-xs text-gray-500">Disable scan timeouts</p>
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
          <Badge variant="outline" className="border-white/10 text-gray-400">
            {asns.filter((a) => a.trim()).length} ASNs
          </Badge>
        </p>
      </div>
    </div>
  );
}
