"use client";

import { useEffect } from "react";

// Next.js root-level error boundary. Catches errors that happen in the
// root layout itself (above app/error.tsx). Must render its own <html>
// + <body> because the regular layout chain didn't get to run.
//
// Intentionally plain HTML — no Chakra components — because the Chakra
// provider lives in the regular layout which already failed.
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[panel/global-error.tsx]", error);
  }, [error]);

  return (
    <html lang="en">
      <body
        style={{
          fontFamily:
            "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
          background: "#0b0d12",
          color: "#fca5a5",
          padding: "32px",
          margin: 0,
          minHeight: "100vh",
        }}
      >
        <div style={{ maxWidth: 900 }}>
          <h1 style={{ marginTop: 0, fontSize: 20 }}>
            Panel root failed to render
          </h1>
          <p style={{ color: "#cbd5e1", fontSize: 14 }}>
            The error escaped the per-route boundary. The panel process
            itself is still up — pick a page from the side nav to retry,
            or click reset below.
          </p>
          <pre
            style={{
              fontSize: 12,
              whiteSpace: "pre-wrap",
              background: "#111827",
              padding: 12,
              borderRadius: 6,
              border: "1px solid #1f2937",
              color: "#e5e7eb",
            }}
          >
            {error?.message ?? String(error)}
            {error?.digest ? `\n\ndigest: ${error.digest}` : ""}
          </pre>
          <button
            type="button"
            onClick={() => reset()}
            style={{
              marginTop: 16,
              padding: "8px 14px",
              borderRadius: 6,
              background: "#dc2626",
              color: "white",
              border: "none",
              cursor: "pointer",
              fontSize: 13,
            }}
          >
            Reset
          </button>
        </div>
      </body>
    </html>
  );
}
