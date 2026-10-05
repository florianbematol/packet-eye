// Time-range presets shared by the History and Apps views.

export type RangePreset = "1h" | "6h" | "24h" | "7d" | "30d";

export const RANGE_OPTIONS: { value: RangePreset; label: string }[] = [
  { value: "1h", label: "1 h" },
  { value: "6h", label: "6 h" },
  { value: "24h", label: "24 h" },
  { value: "7d", label: "7 d" },
  { value: "30d", label: "30 d" },
];

const SECONDS: Record<RangePreset, number> = {
  "1h": 3600,
  "6h": 6 * 3600,
  "24h": 86_400,
  "7d": 7 * 86_400,
  "30d": 30 * 86_400,
};

export interface TimeRange {
  from: number;
  to: number;
}

/** Unix-seconds range ending now. */
export function presetRange(p: RangePreset): TimeRange {
  const to = Math.floor(Date.now() / 1000);
  return { from: to - SECONDS[p], to };
}

/** Same bucket choice as the agent: roughly ≤200 points per range. */
export function autoBucket(spanSecs: number): number {
  const steps = [60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 86_400];
  for (const s of steps) if (spanSecs / s <= 200) return s;
  return 86_400;
}

export function fmtDateTime(secs: number): string {
  return new Date(secs * 1000).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function fmtAgo(secs: number): string {
  const d = Math.max(0, Math.floor(Date.now() / 1000) - secs);
  if (d < 60) return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86_400) return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86_400)}d ago`;
}
