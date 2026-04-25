// ReconX Types

export interface ScanConfig {
  domains: string[];
  ips: string[];
  asns: string[];
  orgName?: string;
  scopeFile?: string;
  outputDir: string;
  verbose: boolean;
  noTimeout: boolean;
  customHeader?: string;
  githubToken?: string;
  chaosKey?: string;
  shodanKey?: string;
  virustotalKey?: string;
  skipSubs: boolean;
  skipAlive: boolean;
  skipPorts: boolean;
  skipUrls: boolean;
  skipJs: boolean;
  skipVuln: boolean;
  resumeDir?: string;
  workers?: number;
  htmlReport: boolean;
  jsonReport: boolean;
  saveRaw: boolean;
}

export interface ScanMetadata {
  id: string;
  config: ScanConfig;
  status: "running" | "completed" | "failed" | "stopped";
  pid: number;
  startTime: string;
  endTime?: string;
  outputDir: string;
  error?: string;
}

export interface ScanResult {
  subdomains?: string[];
  liveHosts?: string[];
  ports?: PortEntry[];
  urls?: string[];
  secrets?: SecretEntry[];
  vulnerabilities?: VulnEntry[];
}

export interface PortEntry {
  host: string;
  port: number;
  protocol: string;
  service?: string;
}

export interface SecretEntry {
  type: string;
  value: string;
  source: string;
  severity: string;
}

export interface VulnEntry {
  name: string;
  severity: string;
  url: string;
  description?: string;
  solution?: string;
  reference?: string;
}

export type PhaseKey = "subs" | "alive" | "ports" | "urls" | "js" | "vuln";

export interface PhaseStatus {
  key: PhaseKey;
  label: string;
  status: "pending" | "running" | "done" | "failed" | "skipped";
}

export type ViewMode = "new-scan" | "history" | "progress" | "results" | "guide";

export interface SavedSettings {
  githubToken: string;
  chaosKey: string;
  shodanKey: string;
  virustotalKey: string;
  orgName: string;
  customHeader: string;
  outputDir: string;
  verbose: boolean;
  noTimeout: boolean;
  htmlReport: boolean;
  jsonReport: boolean;
  saveRaw: boolean;
  workers: number;
}
