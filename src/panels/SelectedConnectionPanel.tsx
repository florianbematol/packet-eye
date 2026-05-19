// Floating info card for the selected connection. Sits above the
// alerts panel on the bottom-left so it doesn't fight the connections
// table for space. Closes when the user clicks the same point again or
// the X button.

import { X, Globe, Server, Cpu, Activity, MapPin, Hash, ListTree } from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useConnectionsStore, connKey } from "@/store/connectionsStore";
import { useSelectionStore } from "@/store/selectionStore";
import { formatBps, formatBytes } from "@/lib/format";
import { useMemo, useState } from "react";
import HexDump from "@/components/HexDump";
import type { EnrichedPacket } from "@/lib/types";

const PROTO_VARIANTS: Record<string, "default" | "violet" | "pink" | "outline"> = {
  tcp: "default",
  udp: "violet",
  icmp: "pink",
  other: "outline",
};

export default function SelectedConnectionPanel() {
  const selectedId = useSelectionStore((s) => s.selectedId);
  const select = useSelectionStore((s) => s.select);
  const conn = useConnectionsStore((s) =>
    selectedId ? s.connections.get(selectedId) ?? null : null,
  );
  const recentPackets = useConnectionsStore((s) => s.recentPackets);

  // Filter the global packet ring buffer to those belonging to the
  // selected connection (same 5-tuple). Most recent first, capped at 50.
  const packets = useMemo<EnrichedPacket[]>(() => {
    if (!selectedId) return [];
    const out: EnrichedPacket[] = [];
    for (let i = recentPackets.length - 1; i >= 0; i--) {
      if (connKey(recentPackets[i]) === selectedId) {
        out.push(recentPackets[i]);
        if (out.length >= 50) break;
      }
    }
    return out;
  }, [recentPackets, selectedId]);

  if (!selectedId || !conn) return null;

  const country = conn.remote_geo?.country ?? null;
  const countryIso = conn.remote_geo?.country_iso ?? null;
  const city = conn.remote_geo?.city ?? null;
  const lat = conn.remote_geo?.lat;
  const lon = conn.remote_geo?.lon;
  const asn = conn.remote_geo?.asn ?? null;
  const asnOrg = conn.remote_geo?.asn_org ?? null;
  const flashing = conn.flash_until_ms > Date.now();

  const ageSec = Math.max(
    0,
    Math.floor((Date.now() - conn.first_seen_ms) / 1000),
  );

  return (
    <Card
      className={`glass-strong w-full overflow-hidden ${
        flashing ? "ring-1 ring-destructive/60" : ""
      }`}
    >
      <CardHeader className="flex flex-row items-center justify-between py-2 px-3 space-y-0 border-b">
        <CardTitle className="mono text-[11px] uppercase tracking-[0.25em] text-primary flex items-center gap-1.5">
          <Server className="h-3.5 w-3.5" />
          Connection details
        </CardTitle>
        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6"
          onClick={() => select(null)}
          title="Close"
        >
          <X className="h-3.5 w-3.5" />
        </Button>
      </CardHeader>
      <CardContent className="p-3 space-y-2.5">
        {/* Top row: proto + direction + IP */}
        <div className="flex items-center gap-2 mono">
          <Badge variant={PROTO_VARIANTS[conn.proto] ?? "outline"}>
            {conn.proto}
          </Badge>
          <span className="text-[10px] uppercase text-muted-foreground tracking-wider">
            {conn.direction}
          </span>
        </div>

        <div className="font-mono text-sm text-foreground/95 break-all">
          {conn.remote_hostname || conn.remote_ip}
          <span className="text-muted-foreground/70">:{conn.remote_port}</span>
        </div>
        {conn.remote_hostname && conn.remote_hostname !== conn.remote_ip && (
          <div className="font-mono text-[10px] text-muted-foreground break-all">
            {conn.remote_ip}
          </div>
        )}

        <Separator />

        {/* Geo */}
        <Row icon={<Globe className="h-3.5 w-3.5" />} label="Location">
          {country ? (
            <span>
              <span className="text-primary">{countryIso}</span> {country}
              {city && (
                <>
                  <span className="text-muted-foreground/70"> · </span>
                  {city}
                </>
              )}
            </span>
          ) : (
            <span className="text-muted-foreground/40">Unknown</span>
          )}
        </Row>

        {(lat != null && lon != null) && (
          <Row icon={<MapPin className="h-3.5 w-3.5" />} label="Coordinates">
            <span className="tabular-nums text-foreground/80">
              {lat.toFixed(2)}, {lon.toFixed(2)}
            </span>
          </Row>
        )}

        {/* ASN */}
        <Row icon={<Hash className="h-3.5 w-3.5" />} label="ASN">
          {asn ? (
            <span>
              <span className="text-neon-violet">AS{asn}</span>
              {asnOrg && (
                <span className="text-foreground/80"> · {asnOrg}</span>
              )}
            </span>
          ) : (
            <span className="text-muted-foreground/40">—</span>
          )}
        </Row>

        {/* Process */}
        <Row icon={<Cpu className="h-3.5 w-3.5" />} label="Process">
          {conn.process ? (
            <span>
              <span className="text-foreground/85">{conn.process}</span>
              {conn.pid && (
                <span className="text-muted-foreground/70"> (pid {conn.pid})</span>
              )}
            </span>
          ) : (
            <span className="text-muted-foreground/40">—</span>
          )}
        </Row>

        <Separator />

        {/* Live counters */}
        <div className="grid grid-cols-3 gap-2 text-[10px]">
          <Stat
            label="bps"
            value={
              conn.bytes_per_sec > 0
                ? formatBps(conn.bytes_per_sec)
                : "—"
            }
          />
          <Stat label="bytes" value={formatBytes(conn.bytes)} />
          <Stat label="packets" value={String(conn.packets)} />
        </div>

        <Row icon={<Activity className="h-3.5 w-3.5" />} label="Tracked for">
          <span className="text-foreground/80 tabular-nums">
            {ageSec >= 60
              ? `${Math.floor(ageSec / 60)}m ${ageSec % 60}s`
              : `${ageSec}s`}
          </span>
        </Row>

        <div className="font-mono text-[10px] text-muted-foreground/70 break-all pt-1 border-t border-border/40">
          local: {conn.src_ip}:{conn.src_port}
          {" ↔ "}
          {conn.dst_ip}:{conn.dst_port}
        </div>

        {/* ---- Recent packets ---- */}
        <Separator />
        <RecentPacketsTable packets={packets} />
      </CardContent>
    </Card>
  );
}

interface RecentPacketsTableProps {
  packets: EnrichedPacket[];
}

function RecentPacketsTable({ packets }: RecentPacketsTableProps) {
  const [selectedTs, setSelectedTs] = useState<number | null>(null);

  // Keep selection valid when the buffer rotates.
  const selected = packets.find((p) => p.ts_ms === selectedTs) ?? null;

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <div className="mono text-[10px] uppercase tracking-[0.25em] text-primary flex items-center gap-1.5">
          <ListTree className="h-3 w-3" />
          Recent packets
        </div>
        <span className="mono text-[10px] text-muted-foreground">
          {packets.length}
          {packets.length === 50 ? "+" : ""}
        </span>
      </div>
      {packets.length === 0 ? (
        <div className="mono text-[10px] text-muted-foreground/60 px-1 py-2">
          No packets buffered yet — they'll appear here as traffic flows.
        </div>
      ) : (
        <div className="rounded-md border border-border/50 overflow-hidden">
          <ScrollArea className="max-h-[180px]">
            <table className="w-full mono text-[10px]">
              <thead className="text-muted-foreground bg-secondary/40 sticky top-0">
                <tr>
                  <th className="text-left px-1.5 py-1 font-normal">time</th>
                  <th className="text-center px-1 py-1 font-normal">→</th>
                  <th className="text-left px-1.5 py-1 font-normal">flags</th>
                  <th className="text-right px-1.5 py-1 font-normal">size</th>
                </tr>
              </thead>
              <tbody>
                {packets.map((p, i) => {
                  const isSel = selectedTs === p.ts_ms;
                  return (
                    <tr
                      key={`${p.ts_ms}-${i}`}
                      onClick={() =>
                        setSelectedTs(isSel ? null : p.ts_ms)
                      }
                      className={`cursor-pointer border-t border-border/40 ${
                        isSel
                          ? "bg-primary/15 hover:bg-primary/20"
                          : "hover:bg-accent/30"
                      }`}
                    >
                      <td className="px-1.5 py-0.5 text-foreground/85 tabular-nums whitespace-nowrap">
                        {fmtTime(p.ts_ms)}
                      </td>
                      <td className="px-1 py-0.5 text-center">
                        {p.direction === "outbound" && (
                          <span className="text-neon-cyan">↑</span>
                        )}
                        {p.direction === "inbound" && (
                          <span className="text-neon-pink">↓</span>
                        )}
                        {p.direction === "unknown" && (
                          <span className="text-muted-foreground/60">·</span>
                        )}
                      </td>
                      <td className="px-1.5 py-0.5 text-foreground/70 whitespace-nowrap">
                        {p.proto === "tcp" ? (
                          <span className="text-neon-cyan/90">
                            {tcpFlagsToString(p.tcp_flags) || "—"}
                          </span>
                        ) : (
                          <span className="text-muted-foreground/60">
                            {p.proto}
                          </span>
                        )}
                      </td>
                      <td className="px-1.5 py-0.5 text-right text-foreground/70 tabular-nums whitespace-nowrap">
                        {formatBytes(p.len)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </ScrollArea>
        </div>
      )}

      {/* Hex dump for the selected packet */}
      {selected && (
        <div className="mt-2 rounded-md border border-border/50 overflow-hidden">
          <div className="flex items-center justify-between px-2 py-1 border-b border-border/40 bg-secondary/30">
            <span className="mono text-[9px] uppercase tracking-[0.25em] text-muted-foreground">
              Raw frame · {fmtTime(selected.ts_ms)} · {selected.len} bytes
            </span>
            <button
              onClick={() => setSelectedTs(null)}
              className="mono text-[10px] text-muted-foreground hover:text-foreground"
              title="Close"
            >
              ✕
            </button>
          </div>
          {selected.payload_hex ? (
            <ScrollArea className="max-h-[200px]">
              <div className="px-2 py-1.5">
                <HexDump hex={selected.payload_hex} />
              </div>
            </ScrollArea>
          ) : (
            <div className="px-3 py-2 mono text-[10px] text-muted-foreground/60">
              No raw payload available for this packet.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function fmtTime(ts_ms: number): string {
  const d = new Date(ts_ms);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms}`;
}

function tcpFlagsToString(bits: number): string {
  // Mirror of the bitflags in src-tauri/src/capture/types.rs::TcpFlags.
  const flags: string[] = [];
  if (bits & 0b0000_0010) flags.push("SYN");
  if (bits & 0b0001_0000) flags.push("ACK");
  if (bits & 0b0000_0001) flags.push("FIN");
  if (bits & 0b0000_0100) flags.push("RST");
  if (bits & 0b0000_1000) flags.push("PSH");
  if (bits & 0b0010_0000) flags.push("URG");
  return flags.join(" ");
}

function Row({
  icon,
  label,
  children,
}: {
  icon: React.ReactNode;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-2 text-xs">
      <span className="text-muted-foreground/80 mt-0.5">{icon}</span>
      <div className="flex-1 min-w-0">
        <div className="mono text-[9px] uppercase tracking-[0.2em] text-muted-foreground">
          {label}
        </div>
        <div className="mono text-[11px] text-foreground/85 break-all">
          {children}
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border/60 bg-secondary/30 px-2 py-1.5">
      <div className="mono text-[9px] uppercase tracking-[0.2em] text-muted-foreground">
        {label}
      </div>
      <div className="mono text-xs tabular-nums text-foreground/90 truncate">
        {value}
      </div>
    </div>
  );
}
