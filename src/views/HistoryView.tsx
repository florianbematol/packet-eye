// Traffic history: timeline of bytes over time, top connections and
// alerts for the selected period, plus retention settings.

import { useCallback, useEffect, useMemo, useState } from "react";
import { History as HistoryIcon, RefreshCcw, Settings2, Trash2, ZoomOut } from "lucide-react";
import ViewShell, { Segmented } from "@/components/ViewShell";
import BlockButton from "@/components/BlockButton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api } from "@/lib/api";
import { formatBytes, formatNumber } from "@/lib/format";
import {
  RANGE_OPTIONS,
  autoBucket,
  fmtDateTime,
  presetRange,
  type RangePreset,
  type TimeRange,
} from "@/lib/range";
import type {
  HistoryAlert,
  HistoryFlow,
  HistoryInfo,
  Severity,
  TimelinePoint,
} from "@/lib/types";

const SEVERITY_VARIANT: Record<Severity, "destructive" | "amber" | "pink" | "violet" | "default"> = {
  critical: "destructive",
  high: "amber",
  medium: "pink",
  low: "violet",
  info: "default",
};

export default function HistoryView() {
  const [preset, setPreset] = useState<RangePreset>("24h");
  const [zoom, setZoom] = useState<TimeRange | null>(null);
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [tick, setTick] = useState(0);
  const [showSettings, setShowSettings] = useState(false);

  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [flows, setFlows] = useState<HistoryFlow[]>([]);
  const [alerts, setAlerts] = useState<HistoryAlert[]>([]);
  const [info, setInfo] = useState<HistoryInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Debounce the search box.
  useEffect(() => {
    const t = setTimeout(() => setQ(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search]);

  const range = useMemo(() => zoom ?? presetRange(preset), [zoom, preset, tick]); // eslint-disable-line react-hooks/exhaustive-deps
  const bucket = autoBucket(range.to - range.from);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [tl, fl, al, inf] = await Promise.all([
        api.historyTimeline({ ...range, bucket }),
        api.historyFlows({ ...range, q, limit: 300 }),
        api.historyAlerts({ ...range, limit: 200 }),
        api.historyInfo(),
      ]);
      setTimeline(tl);
      setFlows(fl);
      setAlerts(al);
      setInfo(inf);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [range, bucket, q]);

  useEffect(() => {
    void load();
  }, [load]);

  const totals = useMemo(
    () => ({
      bytes: timeline.reduce((s, p) => s + p.bytes, 0),
      packets: timeline.reduce((s, p) => s + p.packets, 0),
    }),
    [timeline],
  );

  return (
    <ViewShell
      title="History"
      icon={<HistoryIcon className="h-3.5 w-3.5" />}
      actions={
        <>
          <Input
            className="h-7 w-56 text-xs"
            placeholder="Search IP, domain, app, ASN, country…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {zoom && (
            <Button size="sm" variant="outline" className="h-7" onClick={() => setZoom(null)}>
              <ZoomOut className="h-3.5 w-3.5 mr-1" /> Reset zoom
            </Button>
          )}
          <Segmented<RangePreset>
            value={preset}
            onChange={(p) => {
              setZoom(null);
              setPreset(p);
            }}
            options={RANGE_OPTIONS}
          />
          <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => setTick((t) => t + 1)} title="Refresh">
            <RefreshCcw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          </Button>
          <Button
            size="icon"
            variant={showSettings ? "secondary" : "ghost"}
            className="h-7 w-7"
            onClick={() => setShowSettings((v) => !v)}
            title="History settings"
          >
            <Settings2 className="h-3.5 w-3.5" />
          </Button>
        </>
      }
    >
      <div className="p-4 space-y-4">
        {showSettings && info && <SettingsBar info={info} onChanged={setInfo} />}
        {error && <div className="mono text-xs text-destructive">{error}</div>}
        {info && !info.settings.enabled && (
          <div className="mono text-xs text-neon-amber">
            Recording is disabled — new traffic isn't being saved. Enable it in the settings (⚙).
          </div>
        )}

        <div>
          <div className="flex items-baseline justify-between mb-1.5">
            <div className="mono text-[10px] uppercase tracking-[0.25em] text-muted-foreground">
              {fmtDateTime(range.from)} → {fmtDateTime(range.to)}
            </div>
            <div className="mono text-[11px] text-foreground/80">
              <span className="neon-text">{formatBytes(totals.bytes)}</span>
              <span className="text-muted-foreground"> · {formatNumber(totals.packets)} packets</span>
            </div>
          </div>
          <Timeline
            points={timeline}
            range={range}
            bucket={bucket}
            onPick={(t) => setZoom({ from: t, to: t + bucket - 1 })}
          />
          <div className="mono text-[10px] text-muted-foreground/70 mt-1">
            Bars = bytes per {bucket >= 3600 ? `${bucket / 3600} h` : `${bucket / 60} min`}. Click a bar to zoom in.
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-[1fr_380px] gap-4">
          <FlowsTable flows={flows} />
          <AlertsList alerts={alerts} />
        </div>
      </div>
    </ViewShell>
  );
}

function Timeline({
  points,
  range,
  bucket,
  onPick,
}: {
  points: TimelinePoint[];
  range: TimeRange;
  bucket: number;
  onPick: (ts: number) => void;
}) {
  // Fill empty buckets so time stays linear on the x axis.
  const series = useMemo(() => {
    const byTs = new Map(points.map((p) => [p.ts, p]));
    const start = Math.floor(range.from / bucket) * bucket;
    const out: TimelinePoint[] = [];
    for (let t = start; t <= range.to; t += bucket) {
      out.push(byTs.get(t) ?? { ts: t, bytes: 0, packets: 0, endpoints: 0 });
      if (out.length > 1000) break;
    }
    return out;
  }, [points, range, bucket]);

  const max = Math.max(1, ...series.map((p) => p.bytes));
  const W = 1000;
  const H = 140;
  const bw = W / Math.max(1, series.length);

  return (
    <div className="rounded-md border border-border/50 bg-secondary/10 overflow-hidden">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="w-full h-36 block">
        {[0.25, 0.5, 0.75].map((f) => (
          <line key={f} x1={0} x2={W} y1={H * f} y2={H * f} stroke="hsl(var(--border))" strokeWidth={1} vectorEffect="non-scaling-stroke" />
        ))}
        {series.map((p, i) => {
          const h = p.bytes > 0 ? Math.max(2, (p.bytes / max) * (H - 6)) : 0;
          return (
            <g key={p.ts} onClick={() => p.bytes > 0 && onPick(p.ts)} className={p.bytes > 0 ? "cursor-pointer" : ""}>
              <rect x={i * bw} y={0} width={bw} height={H} fill="transparent" />
              <rect
                x={i * bw + bw * 0.1}
                y={H - h}
                width={Math.max(1, bw * 0.8)}
                height={h}
                className="fill-primary/60 hover:fill-primary"
              />
              <title>
                {`${fmtDateTime(p.ts)}\n${formatBytes(p.bytes)} · ${formatNumber(p.packets)} packets · ${p.endpoints} endpoints`}
              </title>
            </g>
          );
        })}
      </svg>
      {series.every((p) => p.bytes === 0) && (
        <div className="mono text-xs text-muted-foreground text-center -mt-20 pb-14 pointer-events-none">
          No recorded traffic in this period.
        </div>
      )}
    </div>
  );
}

function FlowsTable({ flows }: { flows: HistoryFlow[] }) {
  return (
    <div className="rounded-md border border-border/50 overflow-hidden">
      <div className="px-3 py-2 border-b border-border/50 mono text-[10px] uppercase tracking-[0.25em] text-primary">
        Top connections · {flows.length}
      </div>
      <div className="max-h-[52vh] overflow-auto">
        <table className="w-full text-xs mono">
          <thead className="sticky top-0 bg-card/95 backdrop-blur text-muted-foreground">
            <tr>
              <th className="text-left px-2 py-1.5 font-normal">proto</th>
              <th className="text-left px-2 py-1.5 font-normal">remote</th>
              <th className="text-left px-2 py-1.5 font-normal">domain</th>
              <th className="text-left px-2 py-1.5 font-normal">geo</th>
              <th className="text-left px-2 py-1.5 font-normal">asn</th>
              <th className="text-left px-2 py-1.5 font-normal">process</th>
              <th className="text-right px-2 py-1.5 font-normal">bytes</th>
              <th className="text-right px-2 py-1.5 font-normal">seen</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {flows.length === 0 && (
              <tr>
                <td colSpan={9} className="px-3 py-8 text-center text-muted-foreground">
                  Nothing recorded for this period / search.
                </td>
              </tr>
            )}
            {flows.map((f) => (
              <tr key={`${f.proto}-${f.remote_ip}-${f.remote_port}-${f.process}`} className="border-t border-border/40 hover:bg-accent/30">
                <td className="px-2 py-1 text-primary">{f.proto}</td>
                <td className="px-2 py-1 whitespace-nowrap">
                  {f.remote_ip}
                  <span className="text-muted-foreground/70">:{f.remote_port}</span>
                </td>
                <td className="px-2 py-1 text-neon-green/90 max-w-[200px] truncate" title={f.domain ?? ""}>
                  {f.domain ?? <span className="text-muted-foreground/40">—</span>}
                </td>
                <td className="px-2 py-1 whitespace-nowrap">
                  <span className="text-primary">{f.country_iso ?? ""}</span>{" "}
                  <span className="text-muted-foreground">{f.city ?? ""}</span>
                </td>
                <td className="px-2 py-1 text-muted-foreground max-w-[160px] truncate" title={f.asn_org ?? ""}>
                  {f.asn ? `AS${f.asn} ${f.asn_org ?? ""}` : "—"}
                </td>
                <td className="px-2 py-1 max-w-[140px] truncate">{f.process ?? "—"}</td>
                <td className="px-2 py-1 text-right tabular-nums">{formatBytes(f.bytes)}</td>
                <td className="px-2 py-1 text-right text-muted-foreground whitespace-nowrap" title={`${fmtDateTime(f.first_seen)} → ${fmtDateTime(f.last_seen)}`}>
                  {fmtDateTime(f.last_seen)}
                </td>
                <td className="px-1 py-0.5 text-right">
                  <BlockButton
                    target={{ kind: "ip", value: f.remote_ip }}
                    label={f.remote_ip}
                    buttonLabel=""
                    size="sm"
                    variant="ghost"
                    className="h-6 px-1.5"
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AlertsList({ alerts }: { alerts: HistoryAlert[] }) {
  return (
    <div className="rounded-md border border-border/50 overflow-hidden">
      <div className="px-3 py-2 border-b border-border/50 mono text-[10px] uppercase tracking-[0.25em] text-primary">
        Alerts · {alerts.length}
      </div>
      <div className="max-h-[52vh] overflow-auto divide-y divide-border/40">
        {alerts.length === 0 && (
          <div className="px-3 py-8 text-center mono text-xs text-muted-foreground">No alerts.</div>
        )}
        {alerts.map((a, i) => (
          <div key={`${a.ts_ms}-${i}`} className="px-3 py-1.5">
            <div className="flex items-center gap-2 mono text-[10px]">
              <Badge variant={SEVERITY_VARIANT[a.severity] ?? "default"}>{a.severity}</Badge>
              <span className="text-muted-foreground">{new Date(a.ts_ms).toLocaleString()}</span>
              <span className="text-muted-foreground/70">{a.rule}</span>
            </div>
            <div className="mono text-[11px] text-foreground/85 break-all mt-0.5">{a.message}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SettingsBar({ info, onChanged }: { info: HistoryInfo; onChanged: (i: HistoryInfo) => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const save = async (patch: Partial<HistoryInfo["settings"]>) => {
    setBusy(true);
    setErr(null);
    try {
      const settings = await api.historySettings({ ...info.settings, ...patch });
      onChanged({ ...info, settings });
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const clear = async () => {
    setBusy(true);
    try {
      onChanged(await api.historyClear());
      setConfirmClear(false);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-md border border-border/50 bg-secondary/20 px-3 py-2.5 flex flex-wrap items-center gap-x-6 gap-y-2 text-xs">
      <label className="flex items-center gap-2">
        <Switch checked={info.settings.enabled} disabled={busy} onCheckedChange={(v) => save({ enabled: v })} />
        Record history
      </label>
      <label className="flex items-center gap-2">
        <span className="text-muted-foreground">Keep</span>
        <Select
          value={String(info.settings.retention_days)}
          onValueChange={(v) => save({ retention_days: Number(v) })}
          disabled={busy}
        >
          <SelectTrigger className="h-7 w-28 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="text-xs">
            {[1, 3, 7, 14, 30, 90].map((d) => (
              <SelectItem key={d} value={String(d)}>
                {d} day{d > 1 ? "s" : ""}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </label>
      <span className="mono text-[10px] text-muted-foreground" title={info.path}>
        {formatBytes(info.size_bytes)} on disk · {formatNumber(info.flow_rows)} flow rows ·{" "}
        {formatNumber(info.alert_rows)} alerts
      </span>
      <div className="ml-auto flex items-center gap-2">
        {confirmClear ? (
          <>
            <span className="text-destructive">Delete all history?</span>
            <Button size="sm" variant="destructive" className="h-7" onClick={clear} disabled={busy}>
              Delete
            </Button>
            <Button size="sm" variant="ghost" className="h-7" onClick={() => setConfirmClear(false)}>
              Cancel
            </Button>
          </>
        ) : (
          <Button size="sm" variant="outline" className="h-7" onClick={() => setConfirmClear(true)}>
            <Trash2 className="h-3.5 w-3.5 mr-1" /> Clear history
          </Button>
        )}
      </div>
      {err && <div className="w-full mono text-[11px] text-destructive">{err}</div>}
    </div>
  );
}
