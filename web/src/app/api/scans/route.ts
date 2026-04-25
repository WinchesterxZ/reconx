import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import { promises as fs } from "fs";
import path from "path";
import { v4 as uuidv4 } from "uuid";
import type { ScanConfig, ScanMetadata } from "@/lib/reconx-types";

const BINARY_PATH = "/home/z/my-project/reconx/dist/reconx-linux-amd64";
const SCANS_DIR = "/home/z/my-project/reconx/scans";
const RECONX_OUTPUT_BASE = "/home/z/my-project/reconx/output";

// GET /api/scans - List all scans
export async function GET() {
  try {
    await fs.mkdir(SCANS_DIR, { recursive: true });
    const files = await fs.readdir(SCANS_DIR);
    const scans: ScanMetadata[] = [];

    for (const file of files) {
      if (!file.endsWith(".json")) continue;
      try {
        const content = await fs.readFile(path.join(SCANS_DIR, file), "utf-8");
        const scan = JSON.parse(content) as ScanMetadata;
        // Check if process is still running
        if (scan.status === "running" && scan.pid) {
          try {
            process.kill(scan.pid, 0); // Check if process exists
          } catch {
            // Process is dead, mark as completed
            scan.status = "completed";
            scan.endTime = scan.endTime || new Date().toISOString();
            await fs.writeFile(
              path.join(SCANS_DIR, file),
              JSON.stringify(scan, null, 2)
            );
          }
        }
        scans.push(scan);
      } catch {
        // skip corrupt files
      }
    }

    // Sort by newest first
    scans.sort(
      (a, b) =>
        new Date(b.startTime).getTime() - new Date(a.startTime).getTime()
    );

    return NextResponse.json({ scans });
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to list scans", details: String(error) },
      { status: 500 }
    );
  }
}

// POST /api/scans - Start a new scan
export async function POST(request: NextRequest) {
  try {
    const config: ScanConfig = await request.json();

    // Validate config
    if (
      config.domains.length === 0 &&
      config.ips.length === 0 &&
      config.asns.length === 0 &&
      !config.scopeFile
    ) {
      return NextResponse.json(
        { error: "At least one target (domain, IP range, ASN, or scope file) is required" },
        { status: 400 }
      );
    }

    // Generate unique scan ID
    const scanId = uuidv4().slice(0, 8);
    const outputDir = path.join(RECONX_OUTPUT_BASE, scanId);
    await fs.mkdir(outputDir, { recursive: true });

    // Build CLI arguments
    const args: string[] = [];

    for (const domain of config.domains) {
      args.push("-d", domain);
    }

    for (const ip of config.ips) {
      args.push("--ip", ip);
    }

    for (const asn of config.asns) {
      args.push("--asn", asn);
    }

    if (config.scopeFile) {
      args.push("--scope", config.scopeFile);
    }

    args.push("--output", outputDir);

    if (config.verbose) args.push("-v");
    if (config.noTimeout) args.push("--no-timeout");
    if (config.customHeader) args.push("--header", config.customHeader);
    if (config.githubToken) args.push("--github-token", config.githubToken);
    if (config.chaosKey) args.push("--chaos-key", config.chaosKey);

    if (config.skipSubs) args.push("--skip-subs");
    if (config.skipAlive) args.push("--skip-alive");
    if (config.skipPorts) args.push("--skip-ports");
    if (config.skipUrls) args.push("--skip-urls");
    if (config.skipJs) args.push("--skip-js");
    if (config.skipVuln) args.push("--skip-vuln");

    if (config.orgName) args.push("--org", config.orgName);
    if (config.resumeDir) args.push("--resume", config.resumeDir);

    // Spawn the process
    const logFile = path.join(outputDir, "reconx.log");
    const logStream = (await fs.open(logFile, "w")).createWriteStream();

    const childProcess = spawn(BINARY_PATH, args, {
      stdio: ["ignore", "pipe", "pipe"],
      detached: false,
    });

    // Pipe stdout and stderr to log file
    childProcess.stdout?.on("data", (data: Buffer) => {
      logStream.write(data);
    });

    childProcess.stderr?.on("data", (data: Buffer) => {
      logStream.write(data);
    });

    const pid = childProcess.pid || 0;

    // Create scan metadata
    const scan: ScanMetadata = {
      id: scanId,
      config,
      status: "running",
      pid,
      startTime: new Date().toISOString(),
      outputDir,
    };

    // Save metadata
    await fs.mkdir(SCANS_DIR, { recursive: true });
    await fs.writeFile(
      path.join(SCANS_DIR, `${scanId}.json`),
      JSON.stringify(scan, null, 2)
    );

    // Handle process completion
    childProcess.on("close", async (code) => {
      logStream.end();
      try {
        const metaPath = path.join(SCANS_DIR, `${scanId}.json`);
        const content = await fs.readFile(metaPath, "utf-8");
        const meta = JSON.parse(content) as ScanMetadata;
        meta.status = code === 0 ? "completed" : "failed";
        meta.endTime = new Date().toISOString();
        if (code !== 0) {
          meta.error = `Process exited with code ${code}`;
        }
        await fs.writeFile(metaPath, JSON.stringify(meta, null, 2));
      } catch {
        // ignore errors during cleanup
      }
    });

    childProcess.on("error", async (err) => {
      logStream.end();
      try {
        const metaPath = path.join(SCANS_DIR, `${scanId}.json`);
        const content = await fs.readFile(metaPath, "utf-8");
        const meta = JSON.parse(content) as ScanMetadata;
        meta.status = "failed";
        meta.endTime = new Date().toISOString();
        meta.error = err.message;
        await fs.writeFile(metaPath, JSON.stringify(meta, null, 2));
      } catch {
        // ignore
      }
    });

    return NextResponse.json({ scanId, status: "started", pid });
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to start scan", details: String(error) },
      { status: 500 }
    );
  }
}
