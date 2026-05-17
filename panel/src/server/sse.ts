

export type SSEEvent = { event: string; data: unknown; id?: string };

export function sseResponse(
  req: Request,
  source: (push: (event: SSEEvent) => void) => () => void,
): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      const enc = new TextEncoder();
      let closed = false;
      const safe = (chunk: string) => {
        if (closed) return;
        try {
          controller.enqueue(enc.encode(chunk));
        } catch {
          closed = true;
        }
      };
      const push = (e: SSEEvent) => {
        const lines: string[] = [];
        if (e.id) lines.push(`id: ${e.id}`);
        lines.push(`event: ${e.event}`);
        const data = typeof e.data === "string" ? e.data : JSON.stringify(e.data);
        for (const line of data.split("\n")) lines.push(`data: ${line}`);
        safe(lines.join("\n") + "\n\n");
      };
      const keepAlive = setInterval(() => safe(": ping\n\n"), 15000);
      const detach = source(push);
      const teardown = () => {
        if (closed) return;
        closed = true;
        clearInterval(keepAlive);
        try {
          detach();
        } catch {}
        try {
          controller.close();
        } catch {}
      };
      if (req.signal.aborted) teardown();
      else req.signal.addEventListener("abort", teardown);
      // emit a hello event so clients know they are live
      push({ event: "open", data: { ts: Date.now() } });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
