// Per-application view: who on this machine talks to the network, how
// much, and to which countries / domains. "Live" aggregates the current
// connections table; the time presets query the SQLite history.

import { Fragment, useEffect, useMemo, useState } from "react";
import { AppWindow, ChevronDown, ChevronRight, RefreshCcw, ShieldBan } from "lucide-react";
import ViewShell, { Segmented } from "@/components/ViewShell";
import BlockButton from "@/components/BlockButton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { useConnectionsStore, type ConnectionAgg } from "@/store/connectionsStore";
import { rulesBlockingProcess, useFirewallStore } from "@/store/firewallStore";
import { useSelectionStore } from "@/store/selectionStore";
import { useViewStore } from "@/store/viewStore";
import { api } from "@/lib/api";
import { formatBps, formatBytes } from "@/lib/format";
import { RANGE_OPTIONS, fmtAgo, presetRange, type RangePreset } from "@/lib/range";
import type { HistoryFlow } from "@/lib/types";

type Mode = "live" | RangePreset;

interface AppRow {
  process: string | null;
  pids: number[];
  bytes: number;
  bps: number | null;
  connections: number;
  endpoints: number;
  countries: string[];
  domains: string[];
  lastSeen: number; // unix secs
}

const UNKNOWN = "(unknown process)";

function aggregateLive(conns: Map<string, ConnectionAgg>): AppRow[] {
  const by = new Map<string, AppRow & { _ips: Set<string>; _cc: Set<string>; _dom: Map<string, number> }>();
  for (const c of conns.values()) {
    const key = c.process ?? "";
    let r = by.get(key);
    if (!r) {
      r = {
        process: c.process,
        pids: [],
        bytes: 0,
        bps: 0,
        connections: 0,
        endpoints: 0,
        countries: [],
        domains: [],
        lastSeen: 0,
        _ips: new Set(),
        _cc: new Set(),
        _dom: new Map(),
      };
      by.set(key, r);
    }
    r.bytes += c.bytes;
    r.bps = (r.bps ?? 0) + c.bytes_per_sec;
    r.connections += 1;
    r._ips.add(c.remote_ip);
    if (c.remote_geo?.country_iso) r._cc.add(c.remote_geo.country_iso);
    if (c.remote_domain) r._dom.set(c.remote_domain, (r._dom.get(c.remote_domain) ?? 0) + c.bytes);
    if (c.pid && !r.pids.includes(c.pid)) r.pids.push(c.pid);
    r.lastSeen = Math.max(r.lastSeen, Math.floor(c.last_seen_ms / 1000));
  }
  return [...by.values()].map(({ _ips, _cc, _dom, ...r }) => ({
    ...r,
    endpoints: _ips.size,
    countries: [..._cc].sort(),
    domains: [..._dom.entries()].sort((a, b) => b[1] - a[1]).map(([d]) => d),
  }));
}

export default function AppsView() {
  const [mode, setMode] = useState<Mode>("live");
  const [filter, setFilter] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [historyRows, setHistoryRows] = useState<AppRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  const connections = useConnectionsStore((s) => s.connections);
  const rules = useFirewallStore((s) => s.rules);
  const rulesLoaded = useFirewallStore((s) => s.loaded);
  const refreshRules = useFirewallStore((s) => s.refresh);

  useEffect(() => {
    if (!rulesLoaded) void refreshRules();
  }, [rulesLoaded, refreshRules]);

  useEffect(() => {
    if (mode === "live") return;
    let alive = true;
    setLoading(true);
    setError(null);
    api
      .historyApps({ ...presetRange(mode), limit: 500 })
      .then((rows) => {
        if (!alive) return;
        setHistoryRows(
          rows.map((r) => ({
            process: r.process,
            pids: [],
            bytes: r.bytes,
            bps: null,
            connections: 0,
            endpoints: r.endpoints,
            countries: r.countries.filter(Boolean).sort(),
            domains: r.domains.filter(Boolean),
            lastSeen: r.last_seen,
          })),
        );
      })
      .catch((e) => alive && setError(e instanceof Error ? e.message : String(e)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [mode, tick]);

  const rows = useMemo(() => {
    const base = mode === "live" ? aggregateLive(connections) : historyRows;
    const q = filter.trim().toLowerCase();
    return base
      .filter(
        (r) =>
          !q ||
          (r.process ?? UNKNOWN).toLowerCase().includes(q) ||
          r.domains.some((d) => d.includes(q)) ||
          r.countries.some((c) => c.toLowerCase() === q),
      )
      .sort((a, b) => b.bytes - a.bytes);
  }, [mode, connections, historyRows, filter]);

  const maxBytes = rows[0]?.bytes ?? 1;

  return (
    <ViewShell
      title="Applications"
      icon={<AppWindow className="h-3.5 w-3.5" />}
      actions={
        <>
          <Input
            className="h-7 w-48 text-xs"
            placeholder="Filter app, domain, country…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <Segmented<Mode>
            value={mode}
            onChange={(m) => {
              setExpanded(null);
              setMode(m);
            }}
            options={[{ value: "live", label: "Live" }, ...RANGE_OPTIONS]}
          />
          {mode !== "live" && (
            <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => setTick((t) => t + 1)} title="Refresh">
              <RefreshCcw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            </Button>
          )}
        </>
      }
    >
      {error && <div className="px-4 py-2 mono text-xs text-destructive">{error}</div>}
      <table className="w-full text-xs mono">
        <thead className="sticky top-0 bg-card/95 backdrop-blur z-10 text-muted-foreground">
          <tr>
            <th className="w-6" />
            <th className="text-left px-2 py-2 font-normal">application</th>
            <th className="text-left px-2 py-2 font-normal w-[28%]">traffic</th>
            {mode === "live" && <th className="text-right px-2 py-2 font-normal">bps</th>}
            <th className="text-right px-2 py-2 font-normal">endpoints</th>
            <th className="text-left px-2 py-2 font-normal">countries</th>
            <th className="text-left px-2 py-2 font-normal">top domains</th>
            <th className="text-right px-2 py-2 font-normal">last seen</th>
            <th className="px-2 py-2" />
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td colSpan={9} className="px-3 py-10 text-center text-muted-foreground">
                {mode === "live"
                  ? "No live connections. Start a capture from the Live view."
                  : loading
                    ? "Loading…"
                    : "No history for this period yet."}
              </td>
            </tr>
          )}
          {rows.map((r) => {
            const key = r.process ?? "";
            const open = expanded === key;
            const blocked = rulesBlockingProcess(rules, r.process).length > 0;
            return (
              <Fragment key={key}>
                <tr
                  className="border-t border-border/40 hover:bg-accent/30 cursor-pointer"
                  onClick={() => setExpanded(open ? null : key)}
                >
                  <td className="pl-3 text-muted-foreground">
                    {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex items-center gap-2">
                      <span className={r.process ? "text-foreground" : "text-muted-foreground italic"}>
                        {r.process ?? UNKNOWN}
                      </span>
                      {blocked && (
                        <Badge variant="destructive" className="gap-1">
                          <ShieldBan className="h-3 w-3" /> blocked
                        </Badge>
                      )}
                    </div>
                    {r.pids.length > 0 && (
                      <div className="text-[10px] text-muted-foreground/70">pid {r.pids.join(", ")}</div>
                    )}
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 flex-1 rounded-full bg-secondary/60 overflow-hidden">
                        <div
                          className="h-full bg-primary/70"
                          style={{ width: `${Math.max(2, (r.bytes / maxBytes) * 100)}%` }}
                        />
                      </div>
                      <span className="tabular-nums w-20 text-right">{formatBytes(r.bytes)}</span>
                    </div>
                  </td>
                  {mode === "live" && (
                    <td className="px-2 py-2 text-right tabular-nums">
                      {r.bps ? formatBps(r.bps) : "—"}
                    </td>
                  )}
                  <td className="px-2 py-2 text-right tabular-nums">{r.endpoints}</td>
                  <td className="px-2 py-2 text-primary/90 max-w-[180px] truncate" title={r.countries.join(", ")}>
                    {r.countries.slice(0, 8).join(" ") || "—"}
                    {r.countries.length > 8 && <span className="text-muted-foreground"> +{r.countries.length - 8}</span>}
                  </td>
                  <td className="px-2 py-2 text-neon-green/90 max-w-[260px] truncate" title={r.domains.join("\n")}>
                    {r.domains.slice(0, 3).join(", ") || <span className="text-muted-foreground/40">—</span>}
                  </td>
                  <td className="px-2 py-2 text-right text-muted-foreground whitespace-nowrap">
                    {r.lastSeen ? fmtAgo(r.lastSeen) : "—"}
                  </td>
                  <td className="px-2 py-1.5 text-right" onClick={(e) => e.stopPropagation()}>
                    {r.process && (
                      <BlockButton
                        target={{ kind: "process", pid: r.pids[0] ?? null, name: r.process }}
                        label={r.process}
                        buttonLabel="Block"
                      />
                    )}
                  </td>
                </tr>
                {open && (
                  <tr className="bg-secondary/20">
                    <td />
                    <td colSpan={8} className="px-2 py-2">
                      {mode === "live" ? (
                        <LiveConnections process={r.process} connections={connections} />
                      ) : (
                        <HistoryFlows process={r.process} mode={mode} />
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </ViewShell>
  );
}

function LiveConnections({
  process,
  connections,
}: {
  process: string | null;
  connections: Map<string, ConnectionAgg>;
}) {
  const select = useSelectionStore((s) => s.select);
  const setView = useViewStore((s) => s.setView);
  const list = [...connections.values()]
    .filter((c) => c.process === process)
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 50);
  return (
    <SubTable
      rows={list.map((c) => ({
        key: c.id,
        proto: c.proto,
        remote: `${c.remote_ip}:${c.remote_port}`,
        domain: c.remote_domain,
        geo: [c.remote_geo?.country_iso, c.remote_geo?.city].filter(Boolean).join(" "),
        asn: c.remote_geo?.asn_org ?? null,
        bytes: c.bytes,
        onClick: () => {
          select(c.id);
          setView("live");
        },
      }))}
      hint="Click a connection to inspect it on the globe."
    />
  );
}

function HistoryFlows({ process, mode }: { process: string | null; mode: RangePreset }) {
  const [rows, setRows] = useState<HistoryFlow[] | null>(null);
  useEffect(() => {
    let alive = true;
    // `process` IS NULL can't be expressed through the API filter; for the
    // unknown bucket fall back to the unfiltered top list.
    api
      .historyFlows({ ...presetRange(mode), process: process ?? undefined, limit: 50 })
      .then((r) => alive && setRows(process ? r : r.filter((f) => !f.process)))
      .catch(() => alive && setRows([]));
    return () => {
      alive = false;
    };
  }, [process, mode]);
  if (!rows) return <div className="text-muted-foreground px-2 py-1">Loading…</div>;
  return (
    <SubTable
      rows={rows.map((f) => ({
        key: `${f.proto}-${f.remote_ip}-${f.remote_port}`,
        proto: f.proto,
        remote: `${f.remote_ip}:${f.remote_port}`,
        domain: f.domain,
        geo: [f.country_iso, f.city].filter(Boolean).join(" "),
        asn: f.asn_org,
        bytes: f.bytes,
      }))}
    />
  );
}

function SubTable({
  rows,
  hint,
}: {
  rows: {
    key: string;
    proto: string;
    remote: string;
    domain: string | null;
    geo: string;
    asn: string | null;
    bytes: number;
    onClick?: () => void;
  }[];
  hint?: string;
}) {
  if (rows.length === 0) return <div className="text-muted-foreground px-2 py-1">No connections.</div>;
  return (
    <div>
      <table className="w-full text-[11px]">
        <tbody>
          {rows.map((r) => (
            <tr
              key={r.key}
              onClick={r.onClick}
              className={`border-t border-border/30 ${r.onClick ? "cursor-pointer hover:bg-accent/30" : ""}`}
            >
              <td className="px-2 py-1 w-12 text-primary">{r.proto}</td>
              <td className="px-2 py-1">{r.remote}</td>
              <td className="px-2 py-1 text-neon-green/90">{r.domain ?? "—"}</td>
              <td className="px-2 py-1 text-foreground/70">{r.geo || "—"}</td>
              <td className="px-2 py-1 text-muted-foreground truncate max-w-[200px]">{r.asn ?? "—"}</td>
              <td className="px-2 py-1 text-right tabular-nums">{formatBytes(r.bytes)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {hint && <div className="px-2 pt-1 text-[10px] text-muted-foreground/70">{hint}</div>}
    </div>
  );
}
