// Live connections table with resizable columns and click-to-sort headers.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { useConnectionsStore } from "@/store/connectionsStore";
import { useSelectionStore } from "@/store/selectionStore";
import { formatBps, formatBytes } from "@/lib/format";
import type { ConnectionAgg } from "@/store/connectionsStore";

const PROTO_VARIANTS: Record<string, "default" | "violet" | "pink" | "outline"> = {
  tcp: "default",
  udp: "violet",
  icmp: "pink",
  other: "outline",
};

type ColumnKey =
  | "proto"
  | "dir"
  | "remote"
  | "domain"
  | "geo"
  | "asn"
  | "process"
  | "bps"
  | "bytes";

type SortDir = "asc" | "desc";

interface ColumnDef {
  key: ColumnKey;
  label: string;
  align: "left" | "right" | "center";
  initialWidth: number;
  minWidth: number;
  /** Whether the column can be sorted by clicking its header. */
  sortable: boolean;
  /** Default direction on first click. */
  defaultDir: SortDir;
  /** Comparator. Returns negative when `a` < `b`. */
  compare: (a: ConnectionAgg, b: ConnectionAgg) => number;
}

const cmpStr = (a: string | null | undefined, b: string | null | undefined) => {
  const av = (a ?? "").toLowerCase();
  const bv = (b ?? "").toLowerCase();
  if (av < bv) return -1;
  if (av > bv) return 1;
  return 0;
};
const cmpNum = (a: number | null | undefined, b: number | null | undefined) => {
  const av = a ?? 0;
  const bv = b ?? 0;
  return av - bv;
};

const COLUMNS: ColumnDef[] = [
  {
    key: "proto",
    label: "proto",
    align: "left",
    initialWidth: 64,
    minWidth: 50,
    sortable: true,
    defaultDir: "asc",
    compare: (a, b) => cmpStr(a.proto, b.proto),
  },
  {
    key: "dir",
    label: "",
    align: "center",
    initialWidth: 28,
    minWidth: 24,
    sortable: false,
    defaultDir: "asc",
    compare: () => 0,
  },
  {
    key: "remote",
    label: "remote",
    align: "left",
    initialWidth: 230,
    minWidth: 100,
    sortable: true,
    defaultDir: "asc",
    compare: (a, b) =>
      cmpStr(a.remote_ip, b.remote_ip) ||
      cmpNum(a.remote_port, b.remote_port),
  },
  {
    key: "domain",
    label: "domain",
    align: "left",
    initialWidth: 200,
    minWidth: 80,
    sortable: true,
    defaultDir: "asc",
    compare: (a, b) => cmpStr(a.remote_domain, b.remote_domain),
  },
  {
    key: "geo",
    label: "geo",
    align: "left",
    initialWidth: 160,
    minWidth: 60,
    sortable: true,
    defaultDir: "asc",
    compare: (a, b) =>
      cmpStr(a.remote_geo?.country_iso, b.remote_geo?.country_iso) ||
      cmpStr(a.remote_geo?.city, b.remote_geo?.city),
  },
  {
    key: "asn",
    label: "asn",
    align: "left",
    initialWidth: 200,
    minWidth: 60,
    sortable: true,
    defaultDir: "asc",
    compare: (a, b) =>
      cmpNum(a.remote_geo?.asn ?? null, b.remote_geo?.asn ?? null) ||
      cmpStr(a.remote_geo?.asn_org, b.remote_geo?.asn_org),
  },
  {
    key: "process",
    label: "process",
    align: "left",
    initialWidth: 160,
    minWidth: 80,
    sortable: true,
    defaultDir: "asc",
    compare: (a, b) => cmpStr(a.process, b.process),
  },
  {
    key: "bps",
    label: "bps",
    align: "right",
    initialWidth: 96,
    minWidth: 60,
    sortable: true,
    defaultDir: "desc",
    compare: (a, b) => cmpNum(a.bytes_per_sec, b.bytes_per_sec),
  },
  {
    key: "bytes",
    label: "bytes",
    align: "right",
    initialWidth: 100,
    minWidth: 60,
    sortable: true,
    defaultDir: "desc",
    compare: (a, b) => cmpNum(a.bytes, b.bytes),
  },
];

const COL_BY_KEY: Record<ColumnKey, ColumnDef> = Object.fromEntries(
  COLUMNS.map((c) => [c.key, c]),
) as Record<ColumnKey, ColumnDef>;

const WIDTHS_KEY = "packet-eye:connections:cols:v1";
const SORT_KEY = "packet-eye:connections:sort:v1";

interface SortState {
  by: ColumnKey | null;
  dir: SortDir;
}

function loadWidths(): Record<ColumnKey, number> {
  const fallback = Object.fromEntries(
    COLUMNS.map((c) => [c.key, c.initialWidth]),
  ) as Record<ColumnKey, number>;
  if (typeof localStorage === "undefined") return fallback;
  try {
    const raw = localStorage.getItem(WIDTHS_KEY);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw) as Partial<Record<ColumnKey, number>>;
    const merged = { ...fallback };
    for (const c of COLUMNS) {
      const v = parsed[c.key];
      if (typeof v === "number" && v >= c.minWidth) merged[c.key] = v;
    }
    return merged;
  } catch {
    return fallback;
  }
}

function loadSort(): SortState {
  if (typeof localStorage === "undefined") return { by: null, dir: "desc" };
  try {
    const raw = localStorage.getItem(SORT_KEY);
    if (!raw) return { by: null, dir: "desc" };
    const parsed = JSON.parse(raw) as Partial<SortState>;
    if (parsed.by && (parsed.by in COL_BY_KEY)) {
      return {
        by: parsed.by as ColumnKey,
        dir: parsed.dir === "asc" ? "asc" : "desc",
      };
    }
    return { by: null, dir: "desc" };
  } catch {
    return { by: null, dir: "desc" };
  }
}

export default function ConnectionsList() {
  const connections = useConnectionsStore((s) => s.connections);
  const selectedId = useSelectionStore((s) => s.selectedId);
  const select = useSelectionStore((s) => s.select);
  const [widths, setWidths] = useState<Record<ColumnKey, number>>(loadWidths);
  const [sort, setSort] = useState<SortState>(loadSort);
  const draggingRef = useRef<{
    key: ColumnKey;
    startX: number;
    startWidth: number;
    min: number;
  } | null>(null);
  const [draggingKey, setDraggingKey] = useState<ColumnKey | null>(null);
  // Suppress the click-to-sort that would fire after a drag-resize ends.
  const justDraggedRef = useRef(false);

  // Persist widths on settled change.
  useEffect(() => {
    if (draggingKey) return;
    try {
      localStorage.setItem(WIDTHS_KEY, JSON.stringify(widths));
    } catch {
      /* ignore */
    }
  }, [widths, draggingKey]);

  // Persist sort.
  useEffect(() => {
    try {
      localStorage.setItem(SORT_KEY, JSON.stringify(sort));
    } catch {
      /* ignore */
    }
  }, [sort]);

  const onHandlePointerDown = useCallback(
    (e: React.PointerEvent, col: ColumnDef) => {
      e.preventDefault();
      e.stopPropagation();
      (e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId);
      draggingRef.current = {
        key: col.key,
        startX: e.clientX,
        startWidth: widths[col.key],
        min: col.minWidth,
      };
      setDraggingKey(col.key);
    },
    [widths],
  );

  useEffect(() => {
    if (!draggingKey) return;
    const onMove = (e: PointerEvent) => {
      const d = draggingRef.current;
      if (!d) return;
      const delta = e.clientX - d.startX;
      const next = Math.max(d.min, d.startWidth + delta);
      setWidths((w) => ({ ...w, [d.key]: next }));
    };
    const onUp = () => {
      draggingRef.current = null;
      setDraggingKey(null);
      // Block the sort-on-click that the browser would dispatch right after.
      justDraggedRef.current = true;
      setTimeout(() => {
        justDraggedRef.current = false;
      }, 0);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onUp);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onUp);
    };
  }, [draggingKey]);

  const onHeaderClick = useCallback((col: ColumnDef) => {
    if (!col.sortable) return;
    if (justDraggedRef.current) return;
    setSort((cur) => {
      if (cur.by !== col.key) {
        return { by: col.key, dir: col.defaultDir };
      }
      // Same column: toggle direction; on third click, clear sort.
      if (cur.dir === col.defaultDir) {
        return { by: col.key, dir: col.defaultDir === "asc" ? "desc" : "asc" };
      }
      return { by: null, dir: "desc" };
    });
  }, []);

  const rows = useMemo(() => {
    const arr = Array.from(connections.values());
    if (sort.by && COL_BY_KEY[sort.by]?.sortable) {
      const col = COL_BY_KEY[sort.by];
      const factor = sort.dir === "asc" ? 1 : -1;
      arr.sort((a, b) => {
        const c = col.compare(a, b);
        // Stable tiebreaker on last-seen so rows feel "live" within ties.
        return c !== 0 ? c * factor : b.last_seen_ms - a.last_seen_ms;
      });
    } else {
      // Default: most recent activity first.
      arr.sort((a, b) => b.last_seen_ms - a.last_seen_ms);
    }
    return arr.slice(0, 200);
  }, [connections, sort]);

  return (
    <Card className="glass flex h-full flex-col overflow-hidden">
      <CardHeader className="flex flex-row items-center justify-between py-2 px-3 space-y-0 border-b">
        <CardTitle className="mono text-[11px] uppercase tracking-[0.25em] text-primary">
          Live connections
        </CardTitle>
        <span className="mono text-[10px] text-muted-foreground">
          {connections.size}
          {sort.by && (
            <>
              {" · sorted by "}
              <span className="text-primary">{sort.by}</span>{" "}
              {sort.dir}
            </>
          )}
        </span>
      </CardHeader>
      <CardContent className="p-0 flex-1 overflow-hidden">
        <ScrollArea className="h-full w-full">
          <table
            className="text-xs mono border-separate"
            style={{ borderSpacing: 0 }}
          >
            <colgroup>
              {COLUMNS.map((c) => (
                <col key={c.key} style={{ width: widths[c.key] }} />
              ))}
            </colgroup>
            <thead className="sticky top-0 bg-card/95 backdrop-blur z-10">
              <tr className="text-muted-foreground">
                {COLUMNS.map((c) => {
                  const isSorted = sort.by === c.key;
                  const SortIcon = !c.sortable
                    ? null
                    : !isSorted
                      ? ArrowUpDown
                      : sort.dir === "asc"
                        ? ArrowUp
                        : ArrowDown;
                  return (
                    <th
                      key={c.key}
                      className={`relative px-2 py-2 font-normal whitespace-nowrap ${
                        c.align === "right"
                          ? "text-right"
                          : c.align === "center"
                            ? "text-center"
                            : "text-left"
                      } ${c.sortable ? "cursor-pointer select-none hover:text-foreground" : ""} ${
                        isSorted ? "text-primary" : ""
                      }`}
                      style={{ width: widths[c.key] }}
                      onClick={c.sortable ? () => onHeaderClick(c) : undefined}
                      title={
                        c.sortable
                          ? `Sort by ${c.label || c.key}`
                          : undefined
                      }
                    >
                      <span
                        className={`inline-flex items-center gap-1 ${
                          c.align === "right" ? "justify-end" : ""
                        }`}
                      >
                        {c.label}
                        {SortIcon && (
                          <SortIcon
                            className={`h-3 w-3 ${
                              isSorted ? "opacity-100" : "opacity-30"
                            }`}
                          />
                        )}
                      </span>
                      {/* Resize handle on the right edge of the header */}
                      <span
                        onPointerDown={(e) => onHandlePointerDown(e, c)}
                        onClick={(e) => e.stopPropagation()}
                        className={`absolute top-0 right-0 h-full w-1.5 cursor-col-resize select-none touch-none group ${
                          draggingKey === c.key ? "z-20" : ""
                        }`}
                      >
                        <span
                          className={`block h-full w-px mx-auto transition-colors ${
                            draggingKey === c.key
                              ? "bg-primary"
                              : "bg-transparent group-hover:bg-primary/60"
                          }`}
                        />
                      </span>
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td
                    colSpan={COLUMNS.length}
                    className="px-3 py-8 text-center text-muted-foreground"
                  >
                    No traffic yet. Start the capture.
                  </td>
                </tr>
              )}
              {rows.map((c) => {
                const country = c.remote_geo?.country_iso ?? null;
                const city = c.remote_geo?.city ?? null;
                const asn = c.remote_geo?.asn ?? null;
                const asnOrg = c.remote_geo?.asn_org ?? null;
                const flashing = c.flash_until_ms > Date.now();
                const isSelected = selectedId === c.id;
                return (
                  <tr
                    key={c.id}
                    onClick={() => select(isSelected ? null : c.id)}
                    className={`cursor-pointer ${
                      isSelected
                        ? "border-t border-primary/60 bg-primary/15 hover:bg-primary/20"
                        : flashing
                          ? "border-t border-border/50 bg-destructive/10 hover:bg-destructive/20"
                          : "border-t border-border/50 hover:bg-accent/40"
                    }`}
                  >
                    <td className="px-2 py-1.5 whitespace-nowrap overflow-hidden">
                      <Badge variant={PROTO_VARIANTS[c.proto] ?? "outline"}>
                        {c.proto}
                      </Badge>
                    </td>
                    <td className="px-1 py-1.5 text-center text-muted-foreground whitespace-nowrap overflow-hidden">
                      {c.direction === "inbound" && (
                        <ArrowDown className="h-3 w-3 inline text-neon-pink" />
                      )}
                      {c.direction === "outbound" && (
                        <ArrowUp className="h-3 w-3 inline text-neon-cyan" />
                      )}
                    </td>
                    <td
                      className="px-2 py-1.5 text-foreground/85 whitespace-nowrap overflow-hidden text-ellipsis"
                      title={`${c.remote_ip}:${c.remote_port}`}
                    >
                      {c.remote_ip}
                      <span className="text-muted-foreground/70">
                        :{c.remote_port}
                      </span>
                    </td>
                    <td
                      className="px-2 py-1.5 text-neon-green/90 whitespace-nowrap overflow-hidden text-ellipsis"
                      title={
                        c.remote_domain
                          ? `${c.remote_domain}${c.remote_domain_source ? ` (${c.remote_domain_source})` : ""}`
                          : ""
                      }
                    >
                      {c.remote_domain || (
                        <span className="text-muted-foreground/40">—</span>
                      )}
                    </td>
                    <td
                      className="px-2 py-1.5 text-foreground/70 whitespace-nowrap overflow-hidden text-ellipsis"
                      title={[country, city].filter(Boolean).join(" / ")}
                    >
                      {country ? (
                        <>
                          <span className="text-primary">{country}</span>
                          {city && (
                            <span className="text-muted-foreground/70">
                              {" "}
                              {city}
                            </span>
                          )}
                        </>
                      ) : (
                        <span className="text-muted-foreground/40">—</span>
                      )}
                    </td>
                    <td
                      className="px-2 py-1.5 text-foreground/70 whitespace-nowrap overflow-hidden text-ellipsis"
                      title={asn ? `AS${asn}${asnOrg ? " " + asnOrg : ""}` : ""}
                    >
                      {asn ? (
                        <span className="text-neon-violet">AS{asn}</span>
                      ) : (
                        <span className="text-muted-foreground/40">—</span>
                      )}
                      {asnOrg && (
                        <span className="text-muted-foreground/70"> {asnOrg}</span>
                      )}
                    </td>
                    <td
                      className="px-2 py-1.5 text-foreground/85 whitespace-nowrap overflow-hidden text-ellipsis"
                      title={c.pid ? `${c.process ?? ""} (pid ${c.pid})` : c.process ?? ""}
                    >
                      {c.process || (
                        <span className="text-muted-foreground/40">—</span>
                      )}
                    </td>
                    <td className="px-2 py-1.5 text-right text-foreground/70 tabular-nums whitespace-nowrap overflow-hidden">
                      {c.bytes_per_sec > 0 ? formatBps(c.bytes_per_sec) : <span className="text-muted-foreground/40">—</span>}
                    </td>
                    <td className="px-2 py-1.5 text-right text-foreground/70 tabular-nums whitespace-nowrap overflow-hidden">
                      {formatBytes(c.bytes)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <ScrollBar orientation="horizontal" />
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
