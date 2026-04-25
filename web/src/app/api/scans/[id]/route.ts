import { NextRequest, NextResponse } from "next/server";
import { promises as fs } from "fs";
import path from "path";
import type { ScanMetadata, ScanResult } from "@/lib/reconx-types";
import { SCANS_DIR } from "@/lib/paths";

// GET /api/scans/[id] - Get scan details
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const metaPath = path.join(SCANS_DIR, `${id}.json`);

    let meta: ScanMetadata;
    try {
      const content = await fs.readFile(metaPath, "utf-8");
      meta = JSON.parse(content) as ScanMetadata;
    } catch {
      return NextResponse.json(
        { error: "Scan not found" },
        { status: 404 }
      );
    }

    // Check if running process still exists
    if (meta.status === "running" && meta.pid) {
      try {
        process.kill(meta.pid, 0);
      } catch {
        meta.status = "completed";
        meta.endTime = meta.endTime || new Date().toISOString();
        await fs.writeFile(metaPath, JSON.stringify(meta, null, 2));
      }
    }

    // Try to read results
    let results: ScanResult = {};
    let logExists = false;
    let outputFileList: string[] = [];

    try {
      const resultsPath = path.join(meta.outputDir, "results.json");
      const resultsContent = await fs.readFile(resultsPath, "utf-8");
      results = JSON.parse(resultsContent);
    } catch {
      // results.json may not exist yet
    }

    try {
      await fs.access(path.join(meta.outputDir, "reconx.log"));
      logExists = true;
    } catch {
      // no log file yet
    }

    try {
      const files = await fs.readdir(meta.outputDir);
      outputFileList = files.filter(
        (f) => f !== "." && f !== ".."
      );
    } catch {
      // output dir might not exist
    }

    return NextResponse.json({
      meta,
      results,
      logExists,
      outputFileList,
    });
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to get scan details", details: String(error) },
      { status: 500 }
    );
  }
}

// DELETE /api/scans/[id] - Delete scan
export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const metaPath = path.join(SCANS_DIR, `${id}.json`);

    let meta: ScanMetadata;
    try {
      const content = await fs.readFile(metaPath, "utf-8");
      meta = JSON.parse(content) as ScanMetadata;
    } catch {
      return NextResponse.json(
        { error: "Scan not found" },
        { status: 404 }
      );
    }

    // Delete metadata
    await fs.unlink(metaPath);

    // Delete output directory
    try {
      const { rm } = await import("fs/promises");
      await rm(meta.outputDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to delete scan", details: String(error) },
      { status: 500 }
    );
  }
}
