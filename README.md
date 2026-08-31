# SafeUpload Inspector

Client-side upload inspection lab by **Saeed Rumaneh**. Drop a file in the browser; the app reads only the first header bytes, checks magic signatures against extension/MIME claims, sanitizes the filename, and returns a quarantine decision: **allow**, **reject**, or **review**.

Files are never uploaded to a server worker for execution, never unpacked, and never run.

## What it checks

| Signal | Behavior |
| --- | --- |
| Magic bytes | PNG, JPEG, GIF, PDF, ZIP, SVG, HTML, Windows PE/MZ, ELF |
| Extension mismatch | Flags when `.ext` disagrees with the detected signature |
| Declared MIME | Flags browser-reported MIME vs signature (when present) |
| Filename | Strips path traversal, null bytes, control chars; truncates long names |
| Size | Review above 5 MB; reject above 25 MB |
| Executables | PE/ELF signatures always reject |

## Quarantine rules (summary)

- **allow** — consistent image/PDF/ZIP-style content, safe size, clean name
- **review** — mismatches, unknown signatures, large files, HTML/SVG markup
- **reject** — executables, null-byte names, oversized payloads

## Stack

- Next.js 15 + React 19 + TypeScript
- Pure inspection logic in `lib/inspect-file.ts` (Uint8Array only — no Buffer in client)
- Vitest coverage with synthetic fixtures in `__tests__/`
- Synthetic demos in `lib/fixtures.ts` (forged headers only — not malware)

## Run

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Use the synthetic fixture buttons or drop a local file (header bytes only via FileReader).

```bash
npm test
npm run typecheck
npm run build
```

## Complete product flows

1. Click **Clean PNG header** — quarantine is allow; the decision log records it.
2. Click **Double extension .png.exe** — quarantine is review (PNG bytes, last extension `.exe`).
3. Drop a local file — only header bytes are read; the last 5 inspections stay in component state (not disk).

## Security posture

This project demonstrates **inspection-only** upload triage. See [SECURITY.md](./SECURITY.md). Do not treat allow decisions as a substitute for server-side validation, AV scanning, or content security policy.

## Privacy

All fixtures are synthetic. No client data, private repositories, or prior project code is included.

## License

MIT © 2026 Saeed Rumaneh
