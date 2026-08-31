import { describe, expect, it } from "vitest";
import {
  detectSignature,
  formatHexPreview,
  inspectFile,
  sanitizeFilename,
  SIZE_REJECT_BYTES,
  SIZE_REVIEW_BYTES,
} from "@/lib/inspect-file";
import {
  fixtureElfStub,
  fixtureGif,
  fixtureHtml,
  fixtureJpeg,
  fixturePdf,
  fixturePeStub,
  fixturePng,
  fixtureSvg,
  fixtureZip,
} from "@/lib/fixtures";

describe("detectSignature", () => {
  it("identifies PNG / JPEG / GIF / PDF / ZIP", () => {
    expect(detectSignature(fixturePng()).kind).toBe("png");
    expect(detectSignature(fixtureJpeg()).kind).toBe("jpeg");
    expect(detectSignature(fixtureGif()).kind).toBe("gif");
    expect(detectSignature(fixturePdf()).kind).toBe("pdf");
    expect(detectSignature(fixtureZip()).kind).toBe("zip");
  });

  it("identifies SVG and HTML text markers", () => {
    expect(detectSignature(fixtureSvg()).kind).toBe("svg");
    expect(detectSignature(fixtureHtml()).kind).toBe("html");
  });

  it("identifies PE/MZ and ELF stubs", () => {
    expect(detectSignature(fixturePeStub()).kind).toBe("pe");
    expect(detectSignature(fixtureElfStub()).kind).toBe("elf");
  });

  it("returns unknown for empty or random bytes", () => {
    expect(detectSignature(new Uint8Array()).kind).toBe("unknown");
    expect(detectSignature(new Uint8Array([0x00, 0x11, 0x22])).kind).toBe("unknown");
  });
});

describe("sanitizeFilename", () => {
  it("strips path traversal to the final segment", () => {
    const result = sanitizeFilename("../../etc/passwd.pdf");
    expect(result.sanitized).toBe("passwd.pdf");
    expect(result.issues).toContain("path_traversal");
    expect(result.changed).toBe(true);
  });

  it("removes null bytes", () => {
    const result = sanitizeFilename("safe\0.jpg");
    expect(result.sanitized).toBe("safe.jpg");
    expect(result.issues).toContain("null_byte");
  });

  it("truncates overly long names", () => {
    const long = `${"a".repeat(300)}.png`;
    const result = sanitizeFilename(long);
    expect(result.sanitized.length).toBeLessThanOrEqual(180);
    expect(result.sanitized.endsWith(".png")).toBe(true);
    expect(result.issues).toContain("overlong_name");
  });
});

describe("inspectFile quarantine decisions", () => {
  it("allows a consistent small PNG", () => {
    const result = inspectFile({
      filename: "badge.png",
      sizeBytes: fixturePng().length,
      declaredMime: "image/png",
      header: fixturePng(),
    });
    expect(result.decision).toBe("allow");
    expect(result.extensionMismatch).toBe(false);
    expect(result.signature.kind).toBe("png");
  });

  it("rejects PE stub even when named .png", () => {
    const result = inspectFile({
      filename: "photo.png",
      sizeBytes: 64,
      declaredMime: "image/png",
      header: fixturePeStub(),
    });
    expect(result.signature.kind).toBe("pe");
    expect(result.extensionMismatch).toBe(true);
    expect(result.decision).toBe("reject");
  });

  it("rejects ELF stubs", () => {
    const result = inspectFile({
      filename: "tool.bin",
      sizeBytes: 16,
      header: fixtureElfStub(),
    });
    expect(result.decision).toBe("reject");
    expect(result.signature.kind).toBe("elf");
  });

  it("reviews extension mismatch for non-executables", () => {
    const result = inspectFile({
      filename: "notes.png",
      sizeBytes: fixturePdf().length,
      declaredMime: "image/png",
      header: fixturePdf(),
    });
    expect(result.extensionMismatch).toBe(true);
    expect(result.decision).toBe("review");
  });

  it("reviews HTML markup", () => {
    const result = inspectFile({
      filename: "page.html",
      sizeBytes: fixtureHtml().length,
      declaredMime: "text/html",
      header: fixtureHtml(),
    });
    expect(result.decision).toBe("review");
  });

  it("rejects null-byte filenames", () => {
    const result = inspectFile({
      filename: "ok\0.png",
      sizeBytes: fixturePng().length,
      header: fixturePng(),
    });
    expect(result.decision).toBe("reject");
  });

  it("reviews large files and rejects oversized ones", () => {
    const large = inspectFile({
      filename: "big.png",
      sizeBytes: SIZE_REVIEW_BYTES + 1,
      header: fixturePng(),
    });
    expect(large.sizeStatus).toBe("large");
    expect(large.decision).toBe("review");

    const huge = inspectFile({
      filename: "huge.png",
      sizeBytes: SIZE_REJECT_BYTES + 1,
      header: fixturePng(),
    });
    expect(huge.sizeStatus).toBe("oversized");
    expect(huge.decision).toBe("reject");
  });

  it("formats a hex preview of header bytes", () => {
    expect(formatHexPreview(fixturePng(), 4)).toBe("89 50 4E 47");
  });
});
