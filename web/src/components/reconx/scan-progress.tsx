"use client";

import React, { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Square,
  CheckCircle2,
  XCircle,
  Circle,
  Loader2,
  SkipForward,
  ArrowRight,
  ExternalLink,
} from "lucide-react";
import type { ScanMetadata, PhaseStatus, PhaseKey } from "@/lib/reconx-types";
import { useToast } from "@/hooks/use-toast";

interface ScanProgressProps {
  scanId: string;
  onViewResults: (scanId: string) => void;
  onBack: () => void;
}

const phaseLabels: Record<PhaseKey, string> = {
  subs: "Subdomain Enumeration",
  alive: "Alive Hosts Detection",
  ports: "Port Scanning",
  urls: "URL Discovery",
  js: "JavaScript Analysis",
  vuln: "Vulnerability Scanning",
};

const phaseOrder: PhaseKey[] = ["subs", "alive", "ports", "urls", "js", "vuln"];

export default function ScanProgress({
  scanId,
  onViewResults,
  onBack,
}: ScanProgressProps) {
  const { toast } = useToast();
  const [meta, setMeta] = useState<ScanMetadata | null>(null);
  const [logs, setLogs] = useState("");
  const [isStopping, setIsStopping] = useState(false);
  const logEndRef = useRef<HTMLDivElement>(null);
  const prevLogLength = useRef(0);

  // Fetch scan status
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await fetch(`/api/scans/${scanId}`);
        if (res.ok) {
          const data = await res.json();
          setMeta(data.meta);
        }
      } catch {
        // silent
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 2000);
    return () => clearInterval(interval);
  }, [scanId]);

  // Fetch logs
  useEffect(() => {
    let intervalId: ReturnType<typeof setInterval>;
    let stopped = false;

    const fetchLogs = async () => {
      if (stopped) return;
      try {
        const res = await fetch(`/api/scans/${scanId}/logs`);
        if (res.ok) {
          const data = await res.json();
          setLogs(data.log || "");
        }
      } catch {
        // silent
      }
    };

    fetchLogs();
    intervalId = setInterval(fetchLogs, 1500);

    return () => {
      stopped = true;
      clearInterval(intervalId);
    };
  }, [scanId]);

  // Auto-scroll logs
  useEffect(() => {
    if (logs.length !== prevLogLength.current) {
      prevLogLength.current = logs.length;
      logEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  // Detect phases from logs
  const detectPhases = (log: string, scanMeta: ScanMetadata | null): PhaseStatus[] => {
    const config = scanMeta?.config;
    return phaseOrder.map((key) => {
      const isSkipped =
        key === "subs" && config?.skipSubs ||
        key === "alive" && config?.skipAlive ||
        key === "ports" && config?.skipPorts ||
        key === "urls" && config?.skipUrls ||
        key === "js" && config?.skipJs ||
        key === "vuln" && config?.skipVuln;

      if (isSkipped) {
        return { key, label: phaseLabels[key], status: "skipped" };
      }

      const logLower = log.toLowerCase();
      let status: PhaseStatus["status"] = "pending";

      // Detect phase-specific keywords in the log
      const patterns: Record<PhaseKey, string[]> = {
        subs: ["subdomain", "subdomains", "dns", "enumerat"],
        alive: ["alive", "http probe", "httpx", "probing"],
        ports: ["port", "nmap", "scan", "naabu", "services"],
        urls: ["url", "endpoint", "path", "gau", "wayback", "katana"],
        js: ["javascript", "js file", "secret", "nuclei", "extract", "parameter"],
        vuln: ["vuln", "vulnerability", "finding", "exploit", "cve", "critical"],
      };

      // Check if this phase has started
      const startedPatterns = patterns[key].some((p) => logLower.includes(p));

      // Find the index of this phase in the order
      const phaseIndex = phaseOrder.indexOf(key);
      const hasStartedAnyLaterPhase = phaseOrder
        .slice(phaseIndex + 1)
        .some((laterKey) => {
          const laterSkipped =
            laterKey === "subs" && config?.skipSubs ||
            laterKey === "alive" && config?.skipAlive ||
            laterKey === "ports" && config?.skipPorts ||
            laterKey === "urls" && config?.skipUrls ||
            laterKey === "js" && config?.skipJs ||
            laterKey === "vuln" && config?.skipVuln;
          if (laterSkipped) return false;
          return patterns[laterKey].some((p) => logLower.includes(p));
        });

      if (hasStartedAnyLaterPhase) {
        status = "done";
      } else if (startedPatterns) {
        status = scanMeta?.status === "running" ? "running" : "done";
      }

      return { key, label: phaseLabels[key], status };
    });
  };

  const phases = detectPhases(logs, meta);
  const currentPhaseIndex = phases.findIndex((p) => p.status === "running");
  const isRunning = meta?.status === "running";
  const isCompleted = meta?.status === "completed";
  const isFailed = meta?.status === "failed";
  const isStopped = meta?.status === "stopped";
  const isDone = isCompleted || isFailed || isStopped;

  const handleStop = async () => {
    setIsStopping(true);
    try {
      const res = await fetch(`/api/scans/${scanId}/stop`, { method: "POST" });
      if (res.ok) {
        toast({
          title: "Scan stopped",
          description: "The scan has been terminated.",
        });
      } else {
        const data = await res.json();
        toast({
          title: "Failed to stop",
          description: data.error || "Could not stop the scan.",
          variant: "destructive",
        });
      }
    } catch {
      toast({
        title: "Error",
        description: "Failed to communicate with the server.",
        variant: "destructive",
      });
    }
    setIsStopping(false);
  };

  const getPhaseIcon = (status: PhaseStatus["status"]) => {
    switch (status) {
      case "done":
        return <CheckCircle2 className="w-4 h-4 text-[#00ff88]" />;
      case "running":
        return <Loader2 className="w-4 h-4 text-[#00ff88] animate-spin" />;
      case "failed":
        return <XCircle className="w-4 h-4 text-red-400" />;
      case "skipped":
        return <SkipForward className="w-4 h-4 text-gray-600" />;
      default:
        return <Circle className="w-4 h-4 text-gray-600" />;
    }
  };

  const getStatusBadge = () => {
    switch (meta?.status) {
      case "running":
        return (
          <Badge className="bg-emerald-500/10 text-[#00ff88] border-emerald-500/20 border gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#00ff88] animate-pulse" />
            Running
          </Badge>
        );
      case "completed":
        return (
          <Badge className="bg-emerald-500/10 text-[#00ff88] border-emerald-500/20 border">
            <CheckCircle2 className="w-3 h-3 mr-1" />
            Completed
          </Badge>
        );
      case "failed":
        return (
          <Badge className="bg-red-500/10 text-red-400 border-red-500/20 border">
            <XCircle className="w-3 h-3 mr-1" />
            Failed
          </Badge>
        );
      case "stopped":
        return (
          <Badge className="bg-yellow-500/10 text-yellow-400 border-yellow-500/20 border">
            <Square className="w-3 h-3 mr-1" />
            Stopped
          </Badge>
        );
      default:
        return null;
    }
  };

  const elapsed = meta
    ? (() => {
        const start = new Date(meta.startTime).getTime();
        const end = meta.endTime
          ? new Date(meta.endTime).getTime()
          : Date.now();
        const diff = Math.floor((end - start) / 1000);
        const m = Math.floor(diff / 60);
        const s = diff % 60;
        return `${m}m ${s}s`;
      })()
    : "0m 0s";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            Scan Progress
          </h2>
          <p className="text-sm text-gray-400 mt-1 font-mono">
            ID: {scanId} · Elapsed: {elapsed}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {getStatusBadge()}
          {isRunning && (
            <Button
              variant="destructive"
              size="sm"
              onClick={handleStop}
              disabled={isStopping}
              className="bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 hover:text-red-300"
            >
              {isStopping ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Square className="w-4 h-4" />
              )}
              Stop
            </Button>
          )}
          {isDone && (
            <Button
              size="sm"
              onClick={() => onViewResults(scanId)}
              className="bg-[#00ff88] text-[#0a0c0f] hover:bg-[#00cc6e]"
            >
              <ExternalLink className="w-4 h-4 mr-1" />
              View Results
            </Button>
          )}
          <Button variant="ghost" size="sm" onClick={onBack}>
            Back
          </Button>
        </div>
      </div>

      {/* Target Info */}
      {meta && (
        <Card className="bg-[#111827] border-white/5">
          <CardContent className="p-4">
            <div className="flex flex-wrap gap-2">
              {meta.config.domains.map((d) => (
                <Badge key={d} variant="outline" className="border-emerald-500/20 text-emerald-400 font-mono text-xs">
                  {d}
                </Badge>
              ))}
              {meta.config.ips.map((ip) => (
                <Badge key={ip} variant="outline" className="border-cyan-500/20 text-cyan-400 font-mono text-xs">
                  {ip}
                </Badge>
              ))}
              {meta.config.asns.map((a) => (
                <Badge key={a} variant="outline" className="border-purple-500/20 text-purple-400 font-mono text-xs">
                  {a}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Phase Progress */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-3">
          <CardTitle className="text-white text-base">Pipeline Progress</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {phases.map((phase, index) => (
              <div
                key={phase.key}
                className={`flex items-center gap-3 p-3 rounded-lg transition-colors ${
                  phase.status === "running"
                    ? "bg-emerald-500/5 border border-emerald-500/20"
                    : phase.status === "done"
                    ? "bg-[#0a0c0f]"
                    : "bg-[#0a0c0f]"
                }`}
              >
                {getPhaseIcon(phase.status)}
                <div className="flex-1 min-w-0">
                  <p
                    className={`text-sm font-medium ${
                      phase.status === "running"
                        ? "text-[#00ff88]"
                        : phase.status === "done"
                        ? "text-white"
                        : phase.status === "skipped"
                        ? "text-gray-600"
                        : "text-gray-500"
                    }`}
                  >
                    {phase.label}
                  </p>
                </div>
                {phase.status === "done" && index < phases.length - 1 && (
                  <ArrowRight className="w-3 h-3 text-gray-600" />
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Error display */}
      {isFailed && meta?.error && (
        <Card className="bg-red-500/5 border-red-500/20">
          <CardContent className="p-4">
            <p className="text-sm text-red-400 font-mono">{meta.error}</p>
          </CardContent>
        </Card>
      )}

      {/* Live Log Output */}
      <Card className="bg-[#111827] border-white/5">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-white text-base flex items-center gap-2">
              {isRunning && (
                <span className="w-2 h-2 rounded-full bg-[#00ff88] animate-pulse" />
              )}
              Live Output
            </CardTitle>
            <Badge variant="outline" className="border-white/10 text-gray-500 text-xs font-mono">
              {logs.split("\n").length} lines
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="bg-[#050709] rounded-b-lg border-t border-white/5">
            <div className="p-4 max-h-[500px] overflow-y-auto font-mono text-xs leading-relaxed custom-scrollbar">
              {logs ? (
                <pre className="text-gray-300 whitespace-pre-wrap break-all">
                  {logs}
                </pre>
              ) : (
                <p className="text-gray-600 animate-pulse">
                  {isRunning
                    ? "Waiting for output..."
                    : "No output yet. The scan may not have started."}
                </p>
              )}
              <div ref={logEndRef} />
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
