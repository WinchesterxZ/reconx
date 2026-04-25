import { NextRequest, NextResponse } from "next/server";
import { promises as fs } from "fs";
import path from "path";
import type { ScanMetadata } from "@/lib/reconx-types";
import { SCANS_DIR } from "@/lib/paths";

// POST /api/scans/[id]/stop - Stop a running scan
export async function POST(
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

    if (meta.status !== "running") {
      return NextResponse.json(
        { error: `Scan is not running (current status: ${meta.status})` },
        { status: 400 }
      );
    }

    if (meta.pid) {
      try {
        // Try graceful SIGTERM first
        process.kill(meta.pid, "SIGTERM");

        // Force kill after 3 seconds if still running
        setTimeout(() => {
          try {
            process.kill(meta.pid, 0); // check if alive
            process.kill(meta.pid, "SIGKILL");
          } catch {
            // already dead
          }
        }, 3000);
      } catch {
        return NextResponse.json(
          { error: "Failed to kill process - it may have already exited" },
          { status: 400 }
        );
      }
    }

    // Update metadata
    meta.status = "stopped";
    meta.endTime = new Date().toISOString();
    await fs.writeFile(metaPath, JSON.stringify(meta, null, 2));

    return NextResponse.json({ success: true, message: "Scan stop signal sent" });
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to stop scan", details: String(error) },
      { status: 500 }
    );
  }
}
