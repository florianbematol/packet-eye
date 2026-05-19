// Live alert feed — bottom-left panel.
// Each alert is a one-line entry colour-coded by severity, with the
// human-readable rule message and optional remote IP.

import { useMemo } from "react";
import { ShieldAlert, Trash2 } from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useAlertsStore } from "@/store/alertsStore";
import { cn } from "@/lib/utils";
import type { Alert as AlertEvt, Severity } from "@/lib/types";

const SEVERITY_STYLE: Record<
  Severity,
  { label: string; cls: string; dot: string }
> = {
  critical: {
    label: "CRIT",
    cls: "text-destructive",
    dot: "bg-destructive shadow-[0_0_10px_rgba(255,77,109,0.7)]",
  },
  high: {
    label: "HIGH",
    cls: "text-neon-amber",
    dot: "bg-neon-amber shadow-[0_0_10px_rgba(255,176,32,0.6)]",
  },
  medium: {
    label: "MED",
    cls: "text-neon-pink",
    dot: "bg-neon-pink",
  },
  low: {
    label: "LOW",
    cls: "text-neon-violet",
    dot: "bg-neon-violet",
  },
  info: {
    label: "INFO",
    cls: "text-primary",
    dot: "bg-primary",
  },
};

export default function AlertsFeed() {
  const alerts = useAlertsStore((s) => s.alerts);
  const clear = useAlertsStore((s) => s.clear);

  const rows = useMemo(() => {
    // Most recent first.
    return [...alerts].reverse();
  }, [alerts]);

  return (
    <Card className="glass flex h-full flex-col overflow-hidden">
      <CardHeader className="flex flex-row items-center justify-between py-2 px-3 space-y-0 border-b">
        <CardTitle className="mono text-[11px] uppercase tracking-[0.25em] text-primary flex items-center gap-2">
          <ShieldAlert className="h-3.5 w-3.5" />
          Alerts
        </CardTitle>
        <div className="flex items-center gap-2">
          <span className="mono text-[10px] text-muted-foreground">
            {alerts.length}
          </span>
          {alerts.length > 0 && (
            <Button
              size="icon"
              variant="ghost"
              className="h-6 w-6"
              onClick={clear}
              title="Clear alerts"
            >
              <Trash2 className="h-3 w-3" />
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="p-0 flex-1 overflow-hidden">
        <ScrollArea className="h-full">
          {rows.length === 0 ? (
            <div className="px-3 py-6 mono text-[11px] text-muted-foreground text-center">
              No alerts yet.
            </div>
          ) : (
            <ul className="divide-y divide-border/50">
              {rows.map((a, i) => (
                <AlertRow key={`${a.ts_ms}-${i}`} alert={a} />
              ))}
            </ul>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

function AlertRow({ alert }: { alert: AlertEvt }) {
  const s = SEVERITY_STYLE[alert.severity];
  const time = new Date(alert.ts_ms).toLocaleTimeString();
  return (
    <li className="px-3 py-2 flex items-start gap-2 hover:bg-accent/40">
      <span
        className={cn("mt-1.5 h-1.5 w-1.5 rounded-full shrink-0", s.dot)}
      />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 text-[10px] mono">
          <Badge
            variant="outline"
            className={cn("px-1 py-0 h-4 leading-4", s.cls)}
          >
            {s.label}
          </Badge>
          <span className="text-muted-foreground">{time}</span>
          <span className="text-muted-foreground/70">
            {alert.rule}
          </span>
        </div>
        <div className="mono text-[11px] text-foreground/85 mt-0.5 break-all">
          {alert.message}
        </div>
      </div>
    </li>
  );
}
