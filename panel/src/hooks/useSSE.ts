"use client";
import { useEffect, useRef } from "react";

export interface SSEHandlers {
  [event: string]: (data: any) => void;
}

export function useSSE(url: string | null, handlers: SSEHandlers, deps: unknown[] = []) {
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  useEffect(() => {
    if (!url) return;
    const es = new EventSource(url);
    const wrapped: { event: string; cb: (e: MessageEvent) => void }[] = [];
    for (const event of Object.keys(handlersRef.current)) {
      const cb = (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data);
          handlersRef.current[event]?.(data);
        } catch {
          handlersRef.current[event]?.(e.data);
        }
      };
      es.addEventListener(event, cb as EventListener);
      wrapped.push({ event, cb });
    }
    return () => {
      for (const w of wrapped) es.removeEventListener(w.event, w.cb as EventListener);
      es.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, ...deps]);
}
