// Capture controls panel: device picker, filter toggles, custom BPF, start/stop.

import { useEffect, useState } from "react";
import { Play, Square, RefreshCcw, AlertTriangle, Download } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { api, downloadPcapng } from "@/lib/api";
import { captureFilterToBpf } from "@/lib/bpf";
import { formatBytes } from "@/lib/format";
import type { CaptureFilter, DeviceInfo, RingInfo } from "@/lib/types";

interface Props {
  running: boolean;
  setRunning: (b: boolean) => void;
}

export default function CapturePanel({ running, setRunning }: Props) {
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<CaptureFilter>({
    include_lan: true,
    include_localhost: true,
    include_broadcast: true,
    custom: null,
  });

  const refresh = async () => {
    setError(null);
    try {
      const [devs, status] = await Promise.all([api.listDevices(), api.status()]);
      setDevices(devs);
      setRunning(status.running);
      if (!selected) {
        const preferred =
          devs.find((d) => !d.is_loopback && d.addresses.length > 0) ?? devs[0];
        if (preferred) setSelected(preferred.name);
      }
    } catch (e) {
      setError(formatErr(e));
    }
  };

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const start = async () => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      await api.startCapture(selected, filter);
      setRunning(true);
    } catch (e) {
      setError(formatErr(e));
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.stopCapture();
      setRunning(false);
    } catch (e) {
      setError(formatErr(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="glass w-[360px]">
      <CardHeader className="pb-2 flex flex-row items-center justify-between space-y-0">
        <CardTitle className="mono text-[11px] uppercase tracking-[0.25em] text-primary">
          Capture
        </CardTitle>
        <Button
          size="icon"
          variant="ghost"
          className="h-7 w-7"
          onClick={refresh}
          title="Refresh devices"
          disabled={busy}
        >
          <RefreshCcw className="h-3.5 w-3.5" />
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="space-y-1.5">
          <Label className="text-xs text-muted-foreground">Interface</Label>
          <Select
            value={selected}
            onValueChange={setSelected}
            disabled={running || busy}
          >
            <SelectTrigger className="font-mono text-xs">
              <SelectValue placeholder="Pick a device" />
            </SelectTrigger>
            <SelectContent className="font-mono text-xs">
              {devices.map((d) => (
                <SelectItem key={d.name} value={d.name}>
                  {(d.description || d.name).slice(0, 60)}
                  {d.is_loopback ? " (loopback)" : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <Separator className="my-2" />

        <div className="space-y-2">
          <ToggleRow
            label="Include LAN traffic (RFC1918)"
            checked={!!filter.include_lan}
            disabled={running || busy}
            onChange={(v) => setFilter({ ...filter, include_lan: v })}
          />
          <ToggleRow
            label="Include localhost"
            checked={!!filter.include_localhost}
            disabled={running || busy}
            onChange={(v) => setFilter({ ...filter, include_localhost: v })}
          />
          <ToggleRow
            label="Include broadcast / multicast"
            checked={!!filter.include_broadcast}
            disabled={running || busy}
            onChange={(v) => setFilter({ ...filter, include_broadcast: v })}
          />
        </div>

        <div className="space-y-1.5">
          <Label className="text-xs text-muted-foreground">
            Custom BPF (optional)
          </Label>
          <Input
            placeholder="e.g. tcp port 443"
            className="font-mono text-xs"
            value={filter.custom ?? ""}
            disabled={running || busy}
            onChange={(e) =>
              setFilter({ ...filter, custom: e.target.value || null })
            }
          />
        </div>

        {!running ? (
          <Button
            className="w-full"
            onClick={start}
            disabled={!selected || busy}
          >
            <Play className="mr-2 h-4 w-4" />
            {busy ? "Starting…" : "Start capture"}
          </Button>
        ) : (
          <Button
            className="w-full"
            variant="destructive"
            onClick={stop}
            disabled={busy}
          >
            <Square className="mr-2 h-4 w-4" />
            {busy ? "Stopping…" : "Stop capture"}
          </Button>
        )}

        {error && (
          <div className="flex items-start gap-2 mono text-[11px] text-destructive">
            <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
            <span className="break-all">{error}</span>
          </div>
        )}

        {/* Active BPF expression preview — what the agent will actually
            ask Npcap to keep. Shown in muted small text so it doesn't
            steal attention but lets the user understand what's filtered. */}
        <div className="rounded-md border border-border/40 bg-secondary/20 px-2 py-1.5">
          <div className="mono text-[9px] uppercase tracking-[0.25em] text-muted-foreground mb-0.5">
            Active BPF
          </div>
          <code className="mono text-[10px] text-foreground/80 break-all whitespace-pre-wrap">
            {captureFilterToBpf(filter) || "(no filter — capture everything)"}
          </code>
        </div>

        <div className="mono text-[10px] text-muted-foreground/70 pt-1">
          {running ? "● capturing" : "○ idle"} · {devices.length} interfaces
        </div>

        <ExportRow running={running} />
      </CardContent>
    </Card>
  );
}

/** Buffer status + "download the whole capture as .pcapng". */
function ExportRow({ running }: { running: boolean }) {
  const [info, setInfo] = useState<RingInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .exportInfo()
        .then((i) => alive && setInfo(i))
        .catch(() => {});
    load();
    const t = window.setInterval(load, running ? 2000 : 10_000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [running]);

  const download = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const n = await downloadPcapng();
      setMsg(n ? `${n} packets exported` : "exported");
    } catch (e) {
      setMsg(formatErr(e));
    } finally {
      setBusy(false);
    }
  };

  if (info && info.budget_bytes === 0) return null;

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        <Button
          size="sm"
          variant="outline"
          className="flex-1"
          onClick={download}
          disabled={busy || !info?.frames}
          title="Download the buffered capture, open it in Wireshark"
        >
          <Download className="h-3.5 w-3.5 mr-1.5" />
          {busy ? "Exporting…" : "Export .pcapng"}
        </Button>
        {info && (
          <span
            className="mono text-[10px] text-muted-foreground tabular-nums"
            title={`Ring buffer: ${formatBytes(info.bytes)} / ${formatBytes(info.budget_bytes)}${
              info.evicted_frames ? `, ${info.evicted_frames} older frames evicted` : ""
            }`}
          >
            {info.frames.toLocaleString()} pkts · {formatBytes(info.bytes)}
          </span>
        )}
      </div>
      {msg && <div className="mono text-[10px] text-muted-foreground break-all">{msg}</div>}
    </div>
  );
}

function ToggleRow({
  label,
  checked,
  disabled,
  onChange,
}: {
  label: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-xs text-foreground/80">{label}</span>
      <Switch checked={checked} disabled={disabled} onCheckedChange={onChange} />
    </div>
  );
}

function formatErr(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}
