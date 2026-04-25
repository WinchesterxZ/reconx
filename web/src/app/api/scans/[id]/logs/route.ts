import { NextRequest, NextResponse } from "next/server";
import { promises as fs } from "fs";
import path from "path";
import type { ScanMetadata } from "@/lib/reconx-types";

const SCANS_DIR = "/home/z/my-project/reconx/scans";

// GET /api/scans/[id]/logs - Get scan logs
export async function GET(
  request: NextRequest,
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

    const logPath = path.join(meta.outputDir, "reconx.log");

    try {
      const logContent = await fs.readFile(logPath, "utf-8");

      // Strip ANSI color codes for clean output
      const cleanLog = logContent.replace(
        /\x1B\[[0-9;]*[a-zA-Z]/g,
        ""
      );

      // Check if client wants SSE stream
      const accept = request.headers.get("accept") || "";
      if (accept.includes("text/event-stream")) {
        // Return SSE with last chunk
        const encoder = new TextEncoder();
        const stream = new ReadableStream({
          start(controller) {
            controller.enqueue(
              encoder.encode(
                `data: ${JSON.stringify({ log: cleanLog, status: meta.status })}\n\n`
              )
            );
            controller.close();
          },
        });
        return new Response(stream, {
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
          },
        });
      }

      return NextResponse.json({
        log: cleanLog,
        status: meta.status,
        scanId: id,
      });
    } catch {
      return NextResponse.json({
        log: "",
        status: meta.status,
        scanId: id,
        message: "Log file not available yet",
      });
    }
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to read logs", details: String(error) },
      { status: 500 }
    );
  }
}
