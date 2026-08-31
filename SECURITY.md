# Security Policy — SafeUpload Inspector

## Scope

SafeUpload Inspector is a **demonstration** portfolio project. It performs **metadata and magic-byte inspection only**.

## Hard invariants

1. **No execution** — uploaded or fixture bytes are never executed, evaluated, spawned, or interpreted as code.
2. **No unpacking** — ZIP and other containers are identified by magic only; contents are not extracted.
3. **Header slice only** — the UI reads a small prefix via `File.slice` / `FileReader`-equivalent `arrayBuffer` on that slice.
4. **Local processing** — inspection runs in the browser (or Node tests with Uint8Array fixtures). There is no malware sandbox and no remote detonation.
5. **Synthetic fixtures** — PE/ELF/PDF/image fixtures are short forged headers for signature tests, not real malware samples.

## What this is not

- Not an antivirus engine
- Not a substitute for server-side upload validation
- Not a content disarmament / CDR pipeline
- Not authorization to analyze or distribute real malware

## Reporting

If you find a defect that causes the demo to execute or exfiltrate file contents, contact the author (Saeed Rumaneh) through the portfolio contact channel. Please do not attach live malware samples.
