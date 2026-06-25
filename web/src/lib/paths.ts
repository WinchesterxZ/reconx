import path from "path";

// Auto-detect reconx project root (parent of web/)
// Works no matter where the project is cloned
const RECONX_ROOT = path.resolve(process.cwd(), "..");

export const BINARY_PATH = path.join(RECONX_ROOT, "dist", "reconx-linux-amd64");
export const SCANS_DIR = path.join(RECONX_ROOT, "scans");
export const OUTPUT_DIR = path.join(RECONX_ROOT, "output");
