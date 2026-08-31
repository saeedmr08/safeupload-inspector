/**
 * SafeUpload Inspector — pure file metadata inspection.
 * Reads magic bytes / declared MIME / extension / size / filename only.
 * Never executes, interprets, or unpacks file payloads.
 */

export type DetectedKind =
  | "png"
  | "jpeg"
  | "gif"
  | "pdf"
  | "zip"
  | "svg"
  | "html"
  | "pe"
  | "elf"
  | "unknown";

export type QuarantineDecision = "allow" | "reject" | "review";

export interface FilenameSanitization {
  original: string;
  sanitized: string;
  changed: boolean;
  issues: string[];
}

export interface SignatureMatch {
  kind: DetectedKind;
  label: string;
  confidence: "high" | "medium" | "low";
}

export interface ExtensionInfo {
  extension: string;
  expectedKinds: DetectedKind[];
}

export interface InspectionInput {
  filename: string;
  sizeBytes: number;
  declaredMime?: string;
  /** First bytes of the file (magic header). Prefer at least 16 bytes. */
  header: Uint8Array;
}

export interface InspectionResult {
  filename: FilenameSanitization;
  sizeBytes: number;
  sizeStatus: "ok" | "large" | "oversized";
  declaredMime: string | null;
  signature: SignatureMatch;
  extension: ExtensionInfo;
  extensionMismatch: boolean;
  mimeMismatch: boolean;
  findings: string[];
  decision: QuarantineDecision;
  decisionReasons: string[];
}

/** Soft review threshold (bytes). */
export const SIZE_REVIEW_BYTES = 5 * 1024 * 1024;
/** Hard reject threshold (bytes). */
export const SIZE_REJECT_BYTES = 25 * 1024 * 1024;
/** Maximum retained filename length after sanitization. */
export const MAX_FILENAME_LENGTH = 180;

const EXT_MAP: Record<string, DetectedKind[]> = {
  png: ["png"],
  jpg: ["jpeg"],
  jpeg: ["jpeg"],
  jpe: ["jpeg"],
  gif: ["gif"],
  pdf: ["pdf"],
  zip: ["zip"],
  svg: ["svg"],
  html: ["html"],
  htm: ["html"],
  exe: ["pe"],
  dll: ["pe"],
  scr: ["pe"],
  elf: ["elf"],
  so: ["elf"],
  bin: ["elf", "pe", "unknown"],
};

const MIME_MAP: Record<string, DetectedKind[]> = {
  "image/png": ["png"],
  "image/jpeg": ["jpeg"],
  "image/jpg": ["jpeg"],
  "image/gif": ["gif"],
  "application/pdf": ["pdf"],
  "application/zip": ["zip"],
  "application/x-zip-compressed": ["zip"],
  "image/svg+xml": ["svg"],
  "text/html": ["html"],
  "application/xhtml+xml": ["html"],
  "application/x-msdownload": ["pe"],
  "application/vnd.microsoft.portable-executable": ["pe"],
  "application/x-elf": ["elf"],
  "application/octet-stream": ["unknown", "pe", "elf", "zip"],
};

const EXECUTABLE_KINDS: DetectedKind[] = ["pe", "elf"];

function startsWithBytes(buf: Uint8Array, sig: number[]): boolean {
  if (buf.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) {
    if (buf[i] !== sig[i]) return false;
  }
  return true;
}

function asUint8(header: Uint8Array): Uint8Array {
  return header;
}

function headerAsAscii(header: Uint8Array, max = 256): string {
  const n = Math.min(header.length, max);
  let out = "";
  for (let i = 0; i < n; i++) {
    const c = header[i];
    if (c === 0) break;
    out += String.fromCharCode(c);
  }
  return out;
}

/**
 * Detect file kind from magic bytes / textual markers only.
 */
export function detectSignature(header: Uint8Array): SignatureMatch {
  const bytes = asUint8(header);

  // PNG
  if (
    startsWithBytes(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
  ) {
    return { kind: "png", label: "PNG image", confidence: "high" };
  }

  // JPEG
  if (startsWithBytes(bytes, [0xff, 0xd8, 0xff])) {
    return { kind: "jpeg", label: "JPEG image", confidence: "high" };
  }

  // GIF87a / GIF89a
  if (
    startsWithBytes(bytes, [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]) ||
    startsWithBytes(bytes, [0x47, 0x49, 0x46, 0x38, 0x39, 0x61])
  ) {
    return { kind: "gif", label: "GIF image", confidence: "high" };
  }

  // PDF
  if (startsWithBytes(bytes, [0x25, 0x50, 0x44, 0x46])) {
    return { kind: "pdf", label: "PDF document", confidence: "high" };
  }

  // ZIP (local file, empty archive, or spanned)
  if (
    startsWithBytes(bytes, [0x50, 0x4b, 0x03, 0x04]) ||
    startsWithBytes(bytes, [0x50, 0x4b, 0x05, 0x06]) ||
    startsWithBytes(bytes, [0x50, 0x4b, 0x07, 0x08])
  ) {
    return { kind: "zip", label: "ZIP archive", confidence: "high" };
  }

  // PE / DOS MZ
  if (startsWithBytes(bytes, [0x4d, 0x5a])) {
    return { kind: "pe", label: "Windows PE / MZ executable", confidence: "high" };
  }

  // ELF
  if (startsWithBytes(bytes, [0x7f, 0x45, 0x4c, 0x46])) {
    return { kind: "elf", label: "ELF binary", confidence: "high" };
  }

  const text = headerAsAscii(bytes).trimStart().toLowerCase();

  // SVG (text markers — medium confidence)
  if (
    text.startsWith("<svg") ||
    (text.startsWith("<?xml") && text.includes("<svg"))
  ) {
    return { kind: "svg", label: "SVG markup", confidence: "medium" };
  }

  // HTML
  if (
    text.startsWith("<!doctype html") ||
    text.startsWith("<html") ||
    text.startsWith("<head") ||
    text.startsWith("<body")
  ) {
    return { kind: "html", label: "HTML document", confidence: "medium" };
  }

  return { kind: "unknown", label: "Unrecognized signature", confidence: "low" };
}

/**
 * Strip path traversal, null bytes, control chars; cap length.
 */
export function sanitizeFilename(raw: string): FilenameSanitization {
  const issues: string[] = [];
  let name = raw ?? "";

  if (name.includes("\0")) {
    issues.push("null_byte");
    name = name.replace(/\0/g, "");
  }

  if (/[/\\]/.test(name) || name.includes("..")) {
    issues.push("path_traversal");
  }

  // Keep only the final path segment
  name = name.replace(/\\/g, "/");
  const segments = name.split("/");
  name = segments[segments.length - 1] || "";

  if (name === "." || name === ".." || name === "") {
    issues.push("empty_or_dot_name");
    name = "unnamed";
  }

  // Strip ASCII control characters
  const cleaned = name.replace(/[\x00-\x1f\x7f]/g, "");
  if (cleaned !== name) {
    issues.push("control_characters");
    name = cleaned;
  }

  if (name.length > MAX_FILENAME_LENGTH) {
    issues.push("overlong_name");
    const dot = name.lastIndexOf(".");
    if (dot > 0 && name.length - dot <= 12) {
      const ext = name.slice(dot);
      const base = name.slice(0, MAX_FILENAME_LENGTH - ext.length);
      name = base + ext;
    } else {
      name = name.slice(0, MAX_FILENAME_LENGTH);
    }
  }

  if (!name.trim()) {
    issues.push("blank_after_sanitize");
    name = "unnamed";
  }

  const sanitized = name;
  return {
    original: raw,
    sanitized,
    changed: sanitized !== raw,
    issues,
  };
}

export function parseExtension(filename: string): ExtensionInfo {
  const base = filename.split(/[/\\]/).pop() ?? filename;
  const dot = base.lastIndexOf(".");
  if (dot <= 0 || dot === base.length - 1) {
    return { extension: "", expectedKinds: [] };
  }
  const extension = base.slice(dot + 1).toLowerCase();
  return {
    extension,
    expectedKinds: EXT_MAP[extension] ?? [],
  };
}

function normalizeMime(mime?: string): string | null {
  if (!mime || !mime.trim()) return null;
  return mime.split(";")[0].trim().toLowerCase();
}

function evaluateSize(sizeBytes: number): "ok" | "large" | "oversized" {
  if (sizeBytes > SIZE_REJECT_BYTES) return "oversized";
  if (sizeBytes > SIZE_REVIEW_BYTES) return "large";
  return "ok";
}

/**
 * Produce a quarantine decision from header bytes and metadata only.
 */
export function inspectFile(input: InspectionInput): InspectionResult {
  const filename = sanitizeFilename(input.filename);
  const signature = detectSignature(input.header);
  const extension = parseExtension(filename.sanitized);
  const declaredMime = normalizeMime(input.declaredMime);
  const sizeStatus = evaluateSize(input.sizeBytes);
  const findings: string[] = [];
  const decisionReasons: string[] = [];

  const extensionMismatch =
    extension.expectedKinds.length > 0 &&
    !extension.expectedKinds.includes(signature.kind) &&
    signature.kind !== "unknown";

  let mimeMismatch = false;
  if (declaredMime && MIME_MAP[declaredMime]) {
    const allowed = MIME_MAP[declaredMime];
    if (
      signature.kind !== "unknown" &&
      !allowed.includes(signature.kind) &&
      !allowed.includes("unknown")
    ) {
      mimeMismatch = true;
    }
  }

  if (filename.issues.length) {
    findings.push(`Filename issues: ${filename.issues.join(", ")}`);
  }
  if (extensionMismatch) {
    findings.push(
      `Extension .${extension.extension} does not match signature (${signature.kind})`,
    );
  }
  if (mimeMismatch) {
    findings.push(
      `Declared MIME ${declaredMime} does not match signature (${signature.kind})`,
    );
  }
  if (sizeStatus === "large") {
    findings.push(
      `Size ${input.sizeBytes} exceeds review threshold (${SIZE_REVIEW_BYTES})`,
    );
  }
  if (sizeStatus === "oversized") {
    findings.push(
      `Size ${input.sizeBytes} exceeds hard limit (${SIZE_REJECT_BYTES})`,
    );
  }
  if (EXECUTABLE_KINDS.includes(signature.kind)) {
    findings.push(`Executable signature detected (${signature.kind})`);
  }
  if (signature.kind === "unknown") {
    findings.push("No recognized magic signature");
  }

  let decision: QuarantineDecision = "allow";

  if (sizeStatus === "oversized") {
    decision = "reject";
    decisionReasons.push("File exceeds maximum allowed size");
  }

  if (EXECUTABLE_KINDS.includes(signature.kind)) {
    decision = "reject";
    decisionReasons.push("Executable binaries are not accepted for upload");
  }

  if (filename.issues.includes("path_traversal")) {
    if (decision !== "reject") {
      decision = "review";
      decisionReasons.push("Filename contained path traversal patterns");
    } else {
      decisionReasons.push("Filename contained path traversal patterns");
    }
  }

  if (filename.issues.includes("null_byte")) {
    decision = "reject";
    decisionReasons.push("Filename contained null bytes");
  }

  if (extensionMismatch || mimeMismatch) {
    if (decision === "allow") {
      decision = "review";
    }
    decisionReasons.push("Metadata / signature mismatch requires human review");
  }

  if (sizeStatus === "large" && decision === "allow") {
    decision = "review";
    decisionReasons.push("Large file queued for review");
  }

  if (signature.kind === "unknown" && decision === "allow") {
    decision = "review";
    decisionReasons.push("Unrecognized content type");
  }

  if (signature.kind === "html" || signature.kind === "svg") {
    if (decision === "allow") {
      decision = "review";
      decisionReasons.push(
        "Markup uploads can embed active content — manual review recommended",
      );
    } else if (!decisionReasons.some((r) => r.includes("Markup"))) {
      decisionReasons.push(
        "Markup uploads can embed active content — manual review recommended",
      );
    }
  }

  if (decision === "allow" && decisionReasons.length === 0) {
    decisionReasons.push("Signature, extension, size, and filename look consistent");
  }

  return {
    filename,
    sizeBytes: input.sizeBytes,
    sizeStatus,
    declaredMime,
    signature,
    extension,
    extensionMismatch,
    mimeMismatch,
    findings,
    decision,
    decisionReasons,
  };
}

/** Hex dump of header bytes for UI display (inspection only). */
export function formatHexPreview(header: Uint8Array, max = 16): string {
  const bytes = asUint8(header);
  const n = Math.min(bytes.length, max);
  const parts: string[] = [];
  for (let i = 0; i < n; i++) {
    parts.push(bytes[i].toString(16).padStart(2, "0"));
  }
  return parts.join(" ").toUpperCase();
}
