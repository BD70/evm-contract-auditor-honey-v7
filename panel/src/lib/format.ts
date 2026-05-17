export function fmtBytes(n: number | null | undefined): string {
  if (n == null) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}

export function fmtDuration(ms: number | null | undefined): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = s / 60;
  if (m < 60) return `${m.toFixed(1)} m`;
  return `${(m / 60).toFixed(1)} h`;
}

export function fmtAge(ts: number | null | undefined): string {
  if (!ts) return "—";
  const d = Date.now() - ts;
  if (d < 0) return "now";
  return fmtDuration(d) + " ago";
}

export function shortHash(s: string | null | undefined, head = 6, tail = 4): string {
  if (!s) return "—";
  if (s.length <= head + tail + 1) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

export function fmtTs(ts: number | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return d.toLocaleString();
}

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "red",
  high: "orange",
  medium: "yellow",
  low: "blue",
  info: "gray",
  informational: "gray",
  unknown: "gray",
};
