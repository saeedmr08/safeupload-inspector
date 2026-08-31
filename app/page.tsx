import { UploadInspector } from "@/components/UploadInspector";

export default function HomePage() {
  return (
    <main className="shell">
      <header className="hero">
        <p className="brand">SafeUpload Inspector</p>
        <h1>Inspect uploads before they ever touch a worker.</h1>
        <p className="lede">
          Magic bytes, extension and MIME checks, filename sanitization, and a
          quarantine verdict — all in the browser. Files are never executed.
        </p>
      </header>
      <UploadInspector />
      <footer className="foot">
        <span>Saeed Rumaneh · portfolio lab · inspection only</span>
        <span>MIT 2026</span>
      </footer>
    </main>
  );
}
