// Top-of-screen stats: packets/s, bandwidth, active connections.

import { useConnectionsStore } from "@/store/connectionsStore";
import { formatBps, formatBytes, formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";

export default function StatsBar() {
  const stats = useConnectionsStore((s) => s.stats);
  const active = useConnectionsStore((s) => s.connections.size);

  return (
    <div className="glass-strong px-5 py-2.5 flex items-center gap-6">
      <Metric label="pkt/s" value={formatNumber(stats.packets_per_sec, 1)} />
      <Metric label="throughput" value={formatBps(stats.bytes_per_sec)} />
      <Metric label="active" value={String(active)} />
      <div className="h-7 w-px bg-border/60" />
      <Metric label="total pkts" value={formatNumber(stats.total_packets)} dim />
      <Metric label="total bytes" value={formatBytes(stats.total_bytes)} dim />
    </div>
  );
}

function Metric({
  label,
  value,
  dim,
}: {
  label: string;
  value: string;
  dim?: boolean;
}) {
  return (
    <div className="flex flex-col leading-tight">
      <span className="mono text-[9px] uppercase tracking-[0.2em] text-muted-foreground">
        {label}
      </span>
      <span
        className={cn(
          "mono text-base tabular-nums",
          dim ? "text-foreground/60" : "neon-text",
        )}
      >
        {value}
      </span>
    </div>
  );
}
