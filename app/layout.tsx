import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SafeUpload Inspector — Saeed Rumaneh",
  description:
    "Client-side upload inspection: magic bytes, extension/MIME mismatch, filename sanitization, and quarantine decisions — without executing files.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Sora:wght@500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
