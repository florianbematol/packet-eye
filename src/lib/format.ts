// Number / byte formatting helpers shared by panels.

export function formatNumber(n: number, decimals = 0): string {
  if (!Number.isFinite(n)) return "0";
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}G`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toFixed(decimals);
}

const UNITS_BPS = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
const UNITS_BYTES = ["B", "KB", "MB", "GB", "TB"];

function fmt(n: number, units: string[]): string {
  if (!Number.isFinite(n) || n <= 0) return `0 ${units[0]}`;
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${units[i]}`;
}

export function formatBps(n: number, asTotal = false): string {
  return fmt(n, asTotal ? UNITS_BYTES : UNITS_BPS);
}

export function formatBytes(n: number): string {
  return fmt(n, UNITS_BYTES);
}
