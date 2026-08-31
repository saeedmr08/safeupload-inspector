"use client";

import { useCallback, useState, type DragEvent } from "react";
import {
  formatHexPreview,
  inspectFile,
  type InspectionResult,
  SIZE_REJECT_BYTES,
  SIZE_REVIEW_BYTES,
} from "@/lib/inspect-file";
import { DEMO_FIXTURES } from "@/lib/fixtures";

const HEADER_BYTES = 64;

async function readHeader(file: File): Promise<Uint8Array> {
  const slice = file.slice(0, HEADER_BYTES);
  const buffer = await slice.arrayBuffer();
  return new Uint8Array(buffer);
}

function decisionClass(decision: InspectionResult["decision"]): string {
  if (decision === "allow") return "decision allow";
  if (decision === "reject") return "decision reject";
  return "decision review";
}

export function UploadInspector() {
  const [result, setResult] = useState<InspectionResult | null>(null);
  const [hex, setHex] = useState<string>("");
  const [sourceLabel, setSourceLabel] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [decisionLog, setDecisionLog] = useState<
    { at: number; label: string; filename: string; decision: InspectionResult["decision"] }[]
  >([]);

  const runInspection = useCallback(
    (input: {
      filename: string;
      sizeBytes: number;
      declaredMime?: string;
      header: Uint8Array;
      label: string;
    }) => {
      const inspection = inspectFile({
        filename: input.filename,
        sizeBytes: input.sizeBytes,
        declaredMime: input.declaredMime,
        header: input.header,
      });
      setResult(inspection);
      setHex(formatHexPreview(input.header, 16));
      setSourceLabel(input.label);
      setError(null);
      setDecisionLog((prev) =>
        [
          {
            at: Date.now(),
            label: input.label,
            filename: inspection.filename.sanitized,
            decision: inspection.decision,
          },
          ...prev,
        ].slice(0, 5),
      );
    },
    [],
  );

  const onFile = useCallback(
    async (file: File | null) => {
      if (!file) return;
      setBusy(true);
      try {
        const header = await readHeader(file);
        runInspection({
          filename: file.name,
          sizeBytes: file.size,
          declaredMime: file.type || undefined,
          header,
          label: file.name,
        });
      } catch {
        setError("Could not read file header in the browser.");
        setResult(null);
      } finally {
        setBusy(false);
      }
    },
    [runInspection],
  );

  const onDrop = useCallback(
    (event: DragEvent<HTMLLabelElement>) => {
      event.preventDefault();
      const file = event.dataTransfer.files?.[0] ?? null;
      void onFile(file);
    },
    [onFile],
  );

  const loadFixture = useCallback(
    (id: string) => {
      const demo = DEMO_FIXTURES.find((f) => f.id === id);
      if (!demo) return;
      const header = demo.build();
      runInspection({
        filename: demo.filename,
        sizeBytes: header.byteLength,
        declaredMime: demo.mime,
        header,
        label: `Fixture: ${demo.label}`,
      });
    },
    [runInspection],
  );

  return (
    <div className="inspector">
      <section className="panel drop-panel">
        <label
          className="dropzone"
          onDragOver={(e) => e.preventDefault()}
          onDrop={onDrop}
        >
          <input
            type="file"
            className="sr-only"
            onChange={(e) => void onFile(e.target.files?.[0] ?? null)}
          />
          <span className="drop-kicker">Local header scan</span>
          <span className="drop-title">Drop a file or browse</span>
          <span className="drop-sub">
            Only the first {HEADER_BYTES} bytes are read. Nothing is uploaded
            or executed.
          </span>
          {busy ? <span className="drop-busy">Reading header…</span> : null}
        </label>

        <div className="fixture-row">
          <span className="fixture-label">Synthetic fixtures</span>
          <div className="fixture-buttons">
            {DEMO_FIXTURES.map((f) => (
              <button
                key={f.id}
                type="button"
                className="fixture-btn"
                onClick={() => loadFixture(f.id)}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        <p className="limits">
          Review above {(SIZE_REVIEW_BYTES / (1024 * 1024)).toFixed(0)} MB ·
          Reject above {(SIZE_REJECT_BYTES / (1024 * 1024)).toFixed(0)} MB
        </p>
      </section>

      {error ? <p className="error-banner">{error}</p> : null}

      {result ? (
        <section className="panel result-panel" aria-live="polite">
          <div className="result-head">
            <div>
              <p className="source">{sourceLabel}</p>
              <h2 className="sanitized-name">{result.filename.sanitized}</h2>
              {result.filename.changed ? (
                <p className="muted">
                  Original: <code>{result.filename.original}</code>
                </p>
              ) : null}
            </div>
            <div className={decisionClass(result.decision)}>
              <span className="decision-label">Quarantine</span>
              <strong>{result.decision}</strong>
            </div>
          </div>

          <div className="grid">
            <div className="stat">
              <span>Signature</span>
              <strong>{result.signature.label}</strong>
              <em>{result.signature.confidence} confidence</em>
            </div>
            <div className="stat">
              <span>Extension</span>
              <strong>
                {result.extension.extension
                  ? `.${result.extension.extension}`
                  : "(none)"}
              </strong>
              <em>
                {result.extensionMismatch ? "mismatch" : "aligned or unknown"}
              </em>
            </div>
            <div className="stat">
              <span>Declared MIME</span>
              <strong>{result.declaredMime ?? "—"}</strong>
              <em>{result.mimeMismatch ? "mismatch" : "ok / n/a"}</em>
            </div>
            <div className="stat">
              <span>Size</span>
              <strong>{result.sizeBytes.toLocaleString()} B</strong>
              <em>{result.sizeStatus}</em>
            </div>
          </div>

          <div className="hex-block">
            <span>Header hex</span>
            <code>{hex || "—"}</code>
          </div>

          <div className="lists">
            <div>
              <h3>Decision reasons</h3>
              <ul>
                {result.decisionReasons.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            </div>
            <div>
              <h3>Findings</h3>
              {result.findings.length === 0 ? (
                <p className="muted">No issues flagged.</p>
              ) : (
                <ul>
                  {result.findings.map((f) => (
                    <li key={f}>{f}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </section>
      ) : (
        <section className="panel placeholder">
          <p>
            Choose a local file or load a synthetic fixture to see signature,
            mismatch, and quarantine output.
          </p>
        </section>
      )}

      <section className="panel log-panel" aria-live="polite">
        <h2>Decision log</h2>
        {decisionLog.length === 0 ? (
          <p className="muted">
            Last 5 inspections stay in this session — nothing is written to disk.
          </p>
        ) : (
          <ol className="decision-log">
            {decisionLog.map((entry) => (
              <li key={entry.at}>
                <span className={`log-stamp ${entry.decision}`}>{entry.decision}</span>
                <span>
                  {entry.filename}
                  <em> · {entry.label}</em>
                </span>
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  );
}
