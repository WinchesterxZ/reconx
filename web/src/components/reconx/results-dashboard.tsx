"use client";

import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import {
  Search,
  Globe,
  Server,
  Network,
  FileText,
  ShieldAlert,
  Key,
  ArrowLeft,
  Download,
  Copy,
  CheckCircle2,
  AlertTriangle,
  AlertCircle,
  Info,
  ExternalLink,
  FolderOpen,
} from "lucide-react";
import type {
  ScanMetadata,
  ScanResult,
  VulnEntry,
  SecretEntry,
  PortEntry,
} from "@/lib/reconx-types";
import { useToast } from "@/hooks/use-toast";

interface ResultsDashboardProps {
  scanId: string;
  onBack: () => void;
}

export default function ResultsDashboard({
  scanId,
  onBack,
}: ResultsDashboardProps) {
  const { toast } = useToast();
  const [meta, setMeta] = useState<ScanMetadata | null>(null);
  const [results, setResults] = useState<ScanResult>({});
  const [loading, setLoading] = useState(true);
  const [filterText, setFilterText] = useState("");
  const [outputFiles, setOutputFiles] = useState<string[]>([]);

  useEffect(() => {
    const fetchResults = async () => {
      try {
        const res = await fetch(`/api/scans/${scanId}`);
        if (res.ok) {
          const data = await res.json();
          setMeta(data.meta);
          setResults(data.results || {});
          setOutputFiles(data.outputFileList || []);
        }
      } catch {
        // silent
      } finally {
        setLoading(false);
      }
    };

    fetchResults();
    // Poll for updates in case scan is still running
    const interval = setInterval(fetchResults, 5000);
    return () => clearInterval(interval);
  }, [scanId]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      toast({ title: "Copied to clipboard", description: "Value copied." });
    });
  };

  const getSeverityBadge = (severity: string) => {
    const s = severity.toLowerCase();
    if (s === "critical") {
      return (
        <Badge className="bg-red-500/10 text-red-400 border-red-500/20 border text-xs">
          <AlertCircle className="w-3 h-3 mr-1" />
          Critical
        </Badge>
      );
    }
    if (s === "high") {
      return (
        <Badge className="bg-orange-500/10 text-orange-400 border-orange-500/20 border text-xs">
          <AlertTriangle className="w-3 h-3 mr-1" />
          High
        </Badge>
      );
    }
    if (s === "medium") {
      return (
        <Badge className="bg-yellow-500/10 text-yellow-400 border-yellow-500/20 border text-xs">
          <Info className="w-3 h-3 mr-1" />
          Medium
        </Badge>
      );
    }
    return (
      <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20 border text-xs">
        <CheckCircle2 className="w-3 h-3 mr-1" />
        Low
      </Badge>
    );
  };

  const subdomains = results.subdomains || [];
  const liveHosts = results.liveHosts || [];
  const ports = results.ports || [];
  const urls = results.urls || [];
  const secrets = results.secrets || [];
  const vulns = results.vulnerabilities || [];

  const filterItems = (items: string[], text: string) => {
    if (!text) return items;
    return items.filter((item) => item.toLowerCase().includes(text.toLowerCase()));
  };

  const filterVulns = (items: VulnEntry[], text: string) => {
    if (!text) return items;
    return items.filter(
      (v) =>
        v.name.toLowerCase().includes(text.toLowerCase()) ||
        v.url.toLowerCase().includes(text.toLowerCase()) ||
        v.severity.toLowerCase().includes(text.toLowerCase())
    );
  };

  const filterSecrets = (items: SecretEntry[], text: string) => {
    if (!text) return items;
    return items.filter(
      (s) =>
        s.type.toLowerCase().includes(text.toLowerCase()) ||
        s.source.toLowerCase().includes(text.toLowerCase())
    );
  };

  const filterPorts = (items: PortEntry[], text: string) => {
    if (!text) return items;
    return items.filter(
      (p) =>
        p.host.toLowerCase().includes(text.toLowerCase()) ||
        String(p.port).includes(text) ||
        (p.service || "").toLowerCase().includes(text.toLowerCase())
    );
  };

  const statCards = [
    {
      label: "Subdomains",
      count: subdomains.length,
      icon: Globe,
      color: "text-emerald-400",
      bg: "bg-emerald-500/10",
    },
    {
      label: "Live Hosts",
      count: liveHosts.length,
      icon: Server,
      color: "text-cyan-400",
      bg: "bg-cyan-500/10",
    },
    {
      label: "Open Ports",
      count: ports.length,
      icon: Network,
      color: "text-orange-400",
      bg: "bg-orange-500/10",
    },
    {
      label: "URLs",
      count: urls.length,
      icon: FileText,
      color: "text-purple-400",
      bg: "bg-purple-500/10",
    },
    {
      label: "Vulnerabilities",
      count: vulns.length,
      icon: ShieldAlert,
      color: "text-red-400",
      bg: "bg-red-500/10",
    },
    {
      label: "Secrets",
      count: secrets.length,
      icon: Key,
      color: "text-yellow-400",
      bg: "bg-yellow-500/10",
    },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-gray-400 animate-pulse">Loading results...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            Scan Results
          </h2>
          <p className="text-sm text-gray-400 mt-1 font-mono">
            ID: {scanId}{" "}
            {meta?.endTime &&
              `· Completed ${new Date(meta.endTime).toLocaleString()}`}
          </p>
        </div>
        <Button variant="ghost" size="sm" onClick={onBack}>
          <ArrowLeft className="w-4 h-4 mr-1" /> Back
        </Button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {statCards.map((stat) => {
          const Icon = stat.icon;
          return (
            <Card key={stat.label} className="bg-[#111827] border-white/5">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <div className={`p-1.5 rounded-lg ${stat.bg}`}>
                    <Icon className={`w-4 h-4 ${stat.color}`} />
                  </div>
                </div>
                <p className="text-2xl font-bold text-white">{stat.count.toLocaleString()}</p>
                <p className="text-xs text-gray-500">{stat.label}</p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Filter */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
        <Input
          placeholder="Filter results..."
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          className="pl-9 bg-[#111827] border-white/10 text-white placeholder:text-gray-600 font-mono text-sm"
        />
      </div>

      {/* Tabs */}
      <Tabs defaultValue="findings" className="w-full">
        <TabsList className="bg-[#111827] border border-white/5 p-1 w-full flex-wrap h-auto">
          <TabsTrigger value="findings" className="data-[state=active]:bg-[#0a0c0f] data-[state=active]:text-[#00ff88] text-gray-400 text-xs sm:text-sm flex-1 min-w-0">
            <ShieldAlert className="w-3.5 h-3.5 mr-1 hidden sm:inline" />
            Findings ({vulns.length})
          </TabsTrigger>
          <TabsTrigger value="hosts" className="data-[state=active]:bg-[#0a0c0f] data-[state=active]:text-[#00ff88] text-gray-400 text-xs sm:text-sm flex-1 min-w-0">
            <Server className="w-3.5 h-3.5 mr-1 hidden sm:inline" />
            Hosts ({liveHosts.length})
          </TabsTrigger>
          <TabsTrigger value="subdomains" className="data-[state=active]:bg-[#0a0c0f] data-[state=active]:text-[#00ff88] text-gray-400 text-xs sm:text-sm flex-1 min-w-0">
            <Globe className="w-3.5 h-3.5 mr-1 hidden sm:inline" />
            Subs ({subdomains.length})
          </TabsTrigger>
          <TabsTrigger value="ports" className="data-[state=active]:bg-[#0a0c0f] data-[state=active]:text-[#00ff88] text-gray-400 text-xs sm:text-sm flex-1 min-w-0">
            <Network className="w-3.5 h-3.5 mr-1 hidden sm:inline" />
            Ports ({ports.length})
          </TabsTrigger>
          <TabsTrigger value="secrets" className="data-[state=active]:bg-[#0a0c0f] data-[state=active]:text-[#00ff88] text-gray-400 text-xs sm:text-sm flex-1 min-w-0">
            <Key className="w-3.5 h-3.5 mr-1 hidden sm:inline" />
            Secrets ({secrets.length})
          </TabsTrigger>
          <TabsTrigger value="urls" className="data-[state=active]:bg-[#0a0c0f] data-[state=active]:text-[#00ff88] text-gray-400 text-xs sm:text-sm flex-1 min-w-0">
            <FileText className="w-3.5 h-3.5 mr-1 hidden sm:inline" />
            URLs ({urls.length})
          </TabsTrigger>
        </TabsList>

        {/* Findings Tab */}
        <TabsContent value="findings">
          <Card className="bg-[#111827] border-white/5">
            <CardContent className="p-0">
              <div className="max-h-96 overflow-y-auto custom-scrollbar">
                <Table>
                  <TableHeader>
                    <TableRow className="border-white/5 hover:bg-transparent">
                      <TableHead className="text-gray-400 text-xs">Severity</TableHead>
                      <TableHead className="text-gray-400 text-xs">Name</TableHead>
                      <TableHead className="text-gray-400 text-xs hidden md:table-cell">URL</TableHead>
                      <TableHead className="text-gray-400 text-xs hidden lg:table-cell">Description</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filterVulns(vulns, filterText).map((vuln, i) => (
                      <TableRow key={i} className="border-white/5 hover:bg-white/5">
                        <TableCell>{getSeverityBadge(vuln.severity)}</TableCell>
                        <TableCell className="text-white text-sm font-medium font-mono">
                          {vuln.name}
                        </TableCell>
                        <TableCell className="hidden md:table-cell">
                          <span className="text-gray-300 text-xs font-mono truncate max-w-48 block">
                            {vuln.url}
                          </span>
                        </TableCell>
                        <TableCell className="hidden lg:table-cell">
                          <span className="text-gray-400 text-xs line-clamp-1">
                            {vuln.description || "-"}
                          </span>
                        </TableCell>
                      </TableRow>
                    ))}
                    {filterVulns(vulns, filterText).length === 0 && (
                      <TableRow>
                        <TableCell colSpan={4} className="text-gray-500 text-center py-8">
                          No vulnerabilities found
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Hosts Tab */}
        <TabsContent value="hosts">
          <Card className="bg-[#111827] border-white/5">
            <CardContent className="p-0">
              <div className="max-h-96 overflow-y-auto custom-scrollbar">
                <Table>
                  <TableHeader>
                    <TableRow className="border-white/5 hover:bg-transparent">
                      <TableHead className="text-gray-400 text-xs">#</TableHead>
                      <TableHead className="text-gray-400 text-xs">Host</TableHead>
                      <TableHead className="text-gray-400 text-xs w-16">Action</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filterItems(liveHosts, filterText).map((host, i) => (
                      <TableRow key={i} className="border-white/5 hover:bg-white/5">
                        <TableCell className="text-gray-500 text-xs font-mono">
                          {i + 1}
                        </TableCell>
                        <TableCell className="text-white text-sm font-mono">
                          {host}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7 text-gray-500 hover:text-[#00ff88]"
                            onClick={() => copyToClipboard(host)}
                          >
                            <Copy className="w-3 h-3" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                    {filterItems(liveHosts, filterText).length === 0 && (
                      <TableRow>
                        <TableCell colSpan={3} className="text-gray-500 text-center py-8">
                          No live hosts found
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Subdomains Tab */}
        <TabsContent value="subdomains">
          <Card className="bg-[#111827] border-white/5">
            <CardContent className="p-0">
              <div className="max-h-96 overflow-y-auto custom-scrollbar">
                <Table>
                  <TableHeader>
                    <TableRow className="border-white/5 hover:bg-transparent">
                      <TableHead className="text-gray-400 text-xs">#</TableHead>
                      <TableHead className="text-gray-400 text-xs">Subdomain</TableHead>
                      <TableHead className="text-gray-400 text-xs w-16">Action</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filterItems(subdomains, filterText).map((sub, i) => (
                      <TableRow key={i} className="border-white/5 hover:bg-white/5">
                        <TableCell className="text-gray-500 text-xs font-mono">
                          {i + 1}
                        </TableCell>
                        <TableCell className="text-white text-sm font-mono">
                          {sub}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7 text-gray-500 hover:text-[#00ff88]"
                            onClick={() => copyToClipboard(sub)}
                          >
                            <Copy className="w-3 h-3" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                    {filterItems(subdomains, filterText).length === 0 && (
                      <TableRow>
                        <TableCell colSpan={3} className="text-gray-500 text-center py-8">
                          No subdomains found
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Ports Tab */}
        <TabsContent value="ports">
          <Card className="bg-[#111827] border-white/5">
            <CardContent className="p-0">
              <div className="max-h-96 overflow-y-auto custom-scrollbar">
                <Table>
                  <TableHeader>
                    <TableRow className="border-white/5 hover:bg-transparent">
                      <TableHead className="text-gray-400 text-xs">Host</TableHead>
                      <TableHead className="text-gray-400 text-xs">Port</TableHead>
                      <TableHead className="text-gray-400 text-xs">Protocol</TableHead>
                      <TableHead className="text-gray-400 text-xs hidden sm:table-cell">Service</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filterPorts(ports, filterText).map((port, i) => (
                      <TableRow key={i} className="border-white/5 hover:bg-white/5">
                        <TableCell className="text-white text-sm font-mono">
                          {port.host}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="border-orange-500/20 text-orange-400 font-mono text-xs">
                            {port.port}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-gray-400 text-xs font-mono">
                          {port.protocol}
                        </TableCell>
                        <TableCell className="hidden sm:table-cell text-gray-400 text-xs">
                          {port.service || "-"}
                        </TableCell>
                      </TableRow>
                    ))}
                    {filterPorts(ports, filterText).length === 0 && (
                      <TableRow>
                        <TableCell colSpan={4} className="text-gray-500 text-center py-8">
                          No ports found
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Secrets Tab */}
        <TabsContent value="secrets">
          <Card className="bg-[#111827] border-white/5">
            <CardContent className="p-0">
              <div className="max-h-96 overflow-y-auto custom-scrollbar">
                <Table>
                  <TableHeader>
                    <TableRow className="border-white/5 hover:bg-transparent">
                      <TableHead className="text-gray-400 text-xs">Type</TableHead>
                      <TableHead className="text-gray-400 text-xs">Value</TableHead>
                      <TableHead className="text-gray-400 text-xs hidden md:table-cell">Source</TableHead>
                      <TableHead className="text-gray-400 text-xs hidden sm:table-cell">Severity</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filterSecrets(secrets, filterText).map((secret, i) => (
                      <TableRow key={i} className="border-white/5 hover:bg-white/5">
                        <TableCell>
                          <Badge variant="outline" className="border-yellow-500/20 text-yellow-400 text-xs">
                            {secret.type}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-white text-xs font-mono max-w-48 truncate">
                          {secret.value}
                        </TableCell>
                        <TableCell className="hidden md:table-cell text-gray-400 text-xs font-mono truncate max-w-36">
                          {secret.source}
                        </TableCell>
                        <TableCell className="hidden sm:table-cell">
                          {getSeverityBadge(secret.severity)}
                        </TableCell>
                      </TableRow>
                    ))}
                    {filterSecrets(secrets, filterText).length === 0 && (
                      <TableRow>
                        <TableCell colSpan={4} className="text-gray-500 text-center py-8">
                          No secrets found
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* URLs Tab */}
        <TabsContent value="urls">
          <Card className="bg-[#111827] border-white/5">
            <CardContent className="p-0">
              <div className="max-h-96 overflow-y-auto custom-scrollbar">
                <Table>
                  <TableHeader>
                    <TableRow className="border-white/5 hover:bg-transparent">
                      <TableHead className="text-gray-400 text-xs">#</TableHead>
                      <TableHead className="text-gray-400 text-xs">URL</TableHead>
                      <TableHead className="text-gray-400 text-xs w-16">Action</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filterItems(urls, filterText).map((url, i) => (
                      <TableRow key={i} className="border-white/5 hover:bg-white/5">
                        <TableCell className="text-gray-500 text-xs font-mono">
                          {i + 1}
                        </TableCell>
                        <TableCell className="text-white text-xs font-mono max-w-lg truncate">
                          {url}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7 text-gray-500 hover:text-[#00ff88]"
                            onClick={() => copyToClipboard(url)}
                          >
                            <Copy className="w-3 h-3" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                    {filterItems(urls, filterText).length === 0 && (
                      <TableRow>
                        <TableCell colSpan={3} className="text-gray-500 text-center py-8">
                          No URLs found
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Output Files */}
      {outputFiles.length > 0 && (
        <Card className="bg-[#111827] border-white/5">
          <CardHeader className="pb-3">
            <CardTitle className="text-white text-base flex items-center gap-2">
              <FolderOpen className="w-4 h-4 text-[#00ff88]" />
              Output Files
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {outputFiles.map((file) => (
                <Badge
                  key={file}
                  variant="outline"
                  className="border-white/10 text-gray-300 font-mono text-xs py-1.5 px-3"
                >
                  <FileText className="w-3 h-3 mr-1" />
                  {file}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
