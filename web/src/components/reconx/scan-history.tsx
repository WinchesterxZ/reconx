"use client";

import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Trash2,
  Eye,
  Clock,
  Globe,
  Server,
  Network,
  FileText,
  ShieldAlert,
  Key,
  CheckCircle2,
  XCircle,
  Square,
  Loader2,
  RefreshCw,
} from "lucide-react";
import type { ScanMetadata, ScanResult } from "@/lib/reconx-types";
import { useToast } from "@/hooks/use-toast";

interface ScanHistoryProps {
  onViewResults: (scanId: string) => void;
  onViewProgress: (scanId: string) => void;
  onRefresh: () => void;
}

export default function ScanHistory({
  onViewResults,
  onViewProgress,
  onRefresh,
}: ScanHistoryProps) {
  const { toast } = useToast();
  const [scans, setScans] = useState<
    Array<ScanMetadata & { resultCounts?: Partial<ScanResult> }>
  >([]);
  const [loading, setLoading] = useState(true);
  const [deleting, setDeleting] = useState<string | null>(null);

  const fetchScans = async () => {
    try {
      const res = await fetch("/api/scans");
      if (res.ok) {
        const data = await res.json();
        setScans(data.scans || []);
      }
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const handleDelete = async (scanId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDeleting(scanId);
    try {
      const res = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
      if (res.ok) {
        toast({
          title: "Scan deleted",
          description: `Scan ${scanId} has been removed.`,
        });
        setScans((prev) => prev.filter((s) => s.id !== scanId));
      } else {
        toast({
          title: "Delete failed",
          description: "Could not delete the scan.",
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
    setDeleting(null);
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
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
        return <Badge variant="outline" className="text-gray-400">{status}</Badge>;
    }
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const getDuration = (scan: ScanMetadata) => {
    const start = new Date(scan.startTime).getTime();
    const end = scan.endTime
      ? new Date(scan.endTime).getTime()
      : Date.now();
    const diff = Math.floor((end - start) / 1000);
    if (diff < 60) return `${diff}s`;
    const m = Math.floor(diff / 60);
    const s = diff % 60;
    if (m < 60) return `${m}m ${s}s`;
    const h = Math.floor(m / 60);
    return `${h}h ${m % 60}m`;
  };

  const getTargetsSummary = (scan: ScanMetadata) => {
    const parts: string[] = [];
    if (scan.config.domains.length > 0) {
      parts.push(
        scan.config.domains.length === 1
          ? scan.config.domains[0]
          : `${scan.config.domains.length} domains`
      );
    }
    if (scan.config.ips.length > 0) {
      parts.push(
        scan.config.ips.length === 1
          ? scan.config.ips[0]
          : `${scan.config.ips.length} IPs`
      );
    }
    if (scan.config.asns.length > 0) {
      parts.push(
        scan.config.asns.length === 1
          ? scan.config.asns[0]
          : `${scan.config.asns.length} ASNs`
      );
    }
    const result = parts.join(" · ") || "No targets";
    return result;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-gray-400 animate-pulse flex items-center gap-2">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading scan history...
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Scan History</h2>
          <p className="text-sm text-gray-400 mt-1">
            {scans.length} scan{scans.length !== 1 ? "s" : ""} total
          </p>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={fetchScans}
          className="text-gray-400 hover:text-[#00ff88]"
        >
          <RefreshCw className="w-4 h-4 mr-1" />
          Refresh
        </Button>
      </div>

      {/* Scan Cards */}
      {scans.length === 0 ? (
        <Card className="bg-[#111827] border-white/5">
          <CardContent className="p-12 text-center">
            <ShieldAlert className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400 text-lg font-medium">No scans yet</p>
            <p className="text-gray-500 text-sm mt-1">
              Start your first reconnaissance scan to see results here.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {scans.map((scan) => (
            <Card
              key={scan.id}
              className="bg-[#111827] border-white/5 hover:border-white/10 transition-colors cursor-pointer group"
              onClick={() =>
                scan.status === "running"
                  ? onViewProgress(scan.id)
                  : onViewResults(scan.id)
              }
            >
              <CardContent className="p-4">
                {/* Top row */}
                <div className="flex items-start justify-between gap-2 mb-3">
                  <div className="min-w-0 flex-1">
                    <p className="font-mono text-sm text-white font-semibold truncate">
                      {scan.config.domains[0] ||
                        scan.config.ips[0] ||
                        scan.config.asns[0] ||
                        "Scope File"}
                    </p>
                    <p className="text-xs text-gray-500 font-mono mt-0.5">
                      ID: {scan.id}
                    </p>
                  </div>
                  {getStatusBadge(scan.status)}
                </div>

                {/* Targets */}
                <p className="text-xs text-gray-400 mb-3 truncate">
                  {getTargetsSummary(scan)}
                </p>

                {/* Meta info */}
                <div className="flex items-center gap-3 text-xs text-gray-500 mb-3">
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {formatDate(scan.startTime)}
                  </span>
                  <span>·</span>
                  <span>{getDuration(scan)}</span>
                </div>

                {/* Phase summary */}
                <div className="flex flex-wrap gap-1.5 mb-3">
                  {!scan.config.skipSubs && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/5 text-emerald-400 border border-emerald-500/10">
                      Subs
                    </span>
                  )}
                  {!scan.config.skipAlive && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/5 text-cyan-400 border border-cyan-500/10">
                      Alive
                    </span>
                  )}
                  {!scan.config.skipPorts && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/5 text-orange-400 border border-orange-500/10">
                      Ports
                    </span>
                  )}
                  {!scan.config.skipUrls && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/5 text-purple-400 border border-purple-500/10">
                      URLs
                    </span>
                  )}
                  {!scan.config.skipJs && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-yellow-500/5 text-yellow-400 border border-yellow-500/10">
                      JS
                    </span>
                  )}
                  {!scan.config.skipVuln && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/5 text-red-400 border border-red-500/10">
                      Vulns
                    </span>
                  )}
                </div>

                {/* Actions */}
                <div className="flex items-center justify-between pt-3 border-t border-white/5">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-gray-400 hover:text-[#00ff88] text-xs h-7"
                    onClick={(e) => {
                      e.stopPropagation();
                      if (scan.status === "running") {
                        onViewProgress(scan.id);
                      } else {
                        onViewResults(scan.id);
                      }
                    }}
                  >
                    <Eye className="w-3 h-3 mr-1" />
                    {scan.status === "running" ? "Monitor" : "View"}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-gray-500 hover:text-red-400 hover:bg-red-500/10 text-xs h-7"
                    onClick={(e) => handleDelete(scan.id, e)}
                    disabled={deleting === scan.id}
                  >
                    {deleting === scan.id ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : (
                      <Trash2 className="w-3 h-3" />
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
