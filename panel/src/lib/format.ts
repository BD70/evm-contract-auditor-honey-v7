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

/**
 * Format a base-unit amount (e.g. wei) into a short human-readable string
 * with the right number of significant digits for at-a-glance reading. Uses
 * BigInt so we never lose precision on 18-decimal token balances.
 *
 *   fmtTokenAmount("1234567890000000000", 18) -> "1.23"
 *   fmtTokenAmount("4500000",            6 ) -> "4.50"
 *   fmtTokenAmount("0",                  18) -> "0"
 */
export function fmtTokenAmount(
  base: string | bigint | null | undefined,
  decimals: number,
  maxFrac = 4,
): string {
  if (base == null) return "—";
  let bi: bigint;
  try {
    bi = typeof base === "bigint" ? base : BigInt(base);
  } catch {
    return "—";
  }
  if (bi === 0n) return "0";
  const neg = bi < 0n;
  if (neg) bi = -bi;
  const d = Math.max(0, decimals | 0);
  const divisor = 10n ** BigInt(d);
  const whole = bi / divisor;
  const frac = bi % divisor;
  // For amounts >= 1, show 2 fractional digits; for very small amounts, expand
  // until we have at least one non-zero digit (up to maxFrac).
  let fracStr = frac.toString().padStart(d, "0");
  if (whole >= 1n) {
    fracStr = fracStr.slice(0, 2).replace(/0+$/, "");
  } else {
    let cut = Math.min(maxFrac, fracStr.length);
    let firstNonZero = fracStr.search(/[^0]/);
    if (firstNonZero === -1) firstNonZero = 0;
    cut = Math.max(cut, firstNonZero + 2);
    fracStr = fracStr.slice(0, cut).replace(/0+$/, "");
  }
  const wholeStr = whole.toLocaleString("en-US");
  const out = fracStr ? `${wholeStr}.${fracStr}` : wholeStr;
  return neg ? `-${out}` : out;
}

/**
 * Compact label such as "12.4 ETH" or "0 ETH". Wraps {@link fmtTokenAmount}
 * and tacks the symbol on the end.
 */
export function fmtNativeAmount(
  wei: string | bigint | null | undefined,
  symbol: string,
  decimals = 18,
): string {
  return `${fmtTokenAmount(wei, decimals)} ${symbol}`;
}

/**
 * Compact USD amount for the exposure UI:
 *   $42,113   ≥ 1k
 *   $123.45   ≥ 1
 *   $0.42     < 1
 *   $0        zero
 *   —         null/undefined
 */
export function fmtUsd(v: number | null | undefined, opts: { dashOnNull?: boolean } = {}): string {
  if (v == null || Number.isNaN(v)) return opts.dashOnNull === false ? "" : "—";
  if (v === 0) return "$0";
  const abs = Math.abs(v);
  if (abs >= 1_000_000) return `$${(v / 1_000_000).toFixed(2)}M`;
  if (abs >= 1_000) return `$${v.toLocaleString("en-US", { maximumFractionDigits: 0 })}`;
  if (abs >= 1) return `$${v.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  return `$${v.toFixed(2)}`;
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
