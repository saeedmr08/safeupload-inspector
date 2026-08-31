/**
 * Tiny synthetic Uint8Array fixtures for demos and tests.
 * These are NOT real malware — only forged magic headers / short markers.
 * Client-safe: no Buffer / node:crypto.
 */

/** Minimal valid-looking PNG signature + IHDR stub (not a renderable image). */
export function fixturePng(): Uint8Array {
  return new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
    0x00, 0x00, 0x00, 0x0d, // IHDR length
    0x49, 0x48, 0x44, 0x52, // "IHDR"
    0x00, 0x00, 0x00, 0x01, // width 1
    0x00, 0x00, 0x00, 0x01, // height 1
    0x08, 0x02, 0x00, 0x00, 0x00, // bit depth / color / etc.
  ]);
}

/** JPEG SOI + APP0 stub. */
export function fixtureJpeg(): Uint8Array {
  return new Uint8Array([
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
  ]);
}

/** GIF89a header stub. */
export function fixtureGif(): Uint8Array {
  return new Uint8Array([
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
  ]);
}

/** PDF header line. */
export function fixturePdf(): Uint8Array {
  return new TextEncoder().encode(
    "%PDF-1.4\n%SafeUpload synthetic fixture\n",
  );
}

/** ZIP local-file header magic only. */
export function fixtureZip(): Uint8Array {
  return new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
}

/** Tiny SVG markup (not executed). */
export function fixtureSvg(): Uint8Array {
  return new TextEncoder().encode(
    '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>',
  );
}

/** Tiny HTML document marker. */
export function fixtureHtml(): Uint8Array {
  return new TextEncoder().encode(
    "<!DOCTYPE html><html><head><title>t</title></head></html>",
  );
}

/**
 * Synthetic PE/MZ stub — DOS "MZ" magic only.
 * Not a runnable executable; used solely for signature detection tests.
 */
export function fixturePeStub(): Uint8Array {
  const buf = new Uint8Array(64);
  buf[0] = 0x4d; // M
  buf[1] = 0x5a; // Z
  // e_lfanew placeholder at 0x3c (little-endian 0x0040)
  buf[0x3c] = 0x40;
  buf[0x3d] = 0x00;
  return buf;
}

/**
 * Synthetic ELF identification bytes only (EI_MAG).
 * Not a runnable binary.
 */
export function fixtureElfStub(): Uint8Array {
  return new Uint8Array([
    0x7f, 0x45, 0x4c, 0x46, // magic
    0x02, // 64-bit
    0x01, // little endian
    0x01, // version
    0x00, // System V
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ]);
}

/** Polyglot-style mismatch helper: PE bytes with a .png name in tests. */
export function fixtureMismatchPeAsPng(): {
  filename: string;
  header: Uint8Array;
} {
  return { filename: "invoice.png", header: fixturePeStub() };
}

export const DEMO_FIXTURES = [
  {
    id: "clean-png",
    label: "Clean PNG header",
    filename: "badge.png",
    mime: "image/png",
    build: fixturePng,
  },
  {
    id: "pe-as-png",
    label: "PE stub disguised as PNG",
    filename: "photo.png",
    mime: "image/png",
    build: fixturePeStub,
  },
  {
    id: "traversal-pdf",
    label: "PDF with traversal filename",
    filename: "../../etc/passwd.pdf",
    mime: "application/pdf",
    build: fixturePdf,
  },
  {
    id: "clean-jpeg",
    label: "Clean JPEG header",
    filename: "shot.jpg",
    mime: "image/jpeg",
    build: fixtureJpeg,
  },
  {
    id: "double-ext",
    label: "Double extension .png.exe",
    filename: "invoice.png.exe",
    mime: "image/png",
    build: fixturePng,
  },
  {
    id: "html-markup",
    label: "HTML markup",
    filename: "page.html",
    mime: "text/html",
    build: fixtureHtml,
  },
] as const;
