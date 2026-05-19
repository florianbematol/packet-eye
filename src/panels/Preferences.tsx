// Preferences modal: tweak alert rules (server-side) and alert sounds
// (client-side). Opens from the header gear button.

import { useEffect, useState } from "react";
import { Save, Volume2, VolumeX, Bell, Play, Globe, RefreshCw, CheckCircle2, AlertTriangle } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Slider } from "@/components/ui/slider";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { api } from "@/lib/api";
import {
  defaultAlertSoundConfig,
  playAlertSound,
  type AlertSoundConfig,
} from "@/lib/audio";
import { usePrefsStore } from "@/store/prefsStore";
import { formatBytes } from "@/lib/format";
import type {
  AlertRules,
  GeoIpInfo,
  Severity,
} from "@/lib/types";

interface Props {
  open: boolean;
  onOpenChange: (b: boolean) => void;
}

export default function PreferencesDialog({ open, onOpenChange }: Props) {
  const sound = usePrefsStore((s) => s.sound);
  const setSound = usePrefsStore((s) => s.setSound);

  const [rules, setRules] = useState<AlertRules | null>(null);
  const [threatCount, setThreatCount] = useState<number | null>(null);
  const [savingRules, setSavingRules] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    let alive = true;
    (async () => {
      try {
        const [r, t] = await Promise.all([
          api.getRules(),
          api.threatStats(),
        ]);
        if (!alive) return;
        setRules(r);
        setThreatCount(t.total_ranges);
      } catch (e) {
        if (alive) setError(String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [open]);

  const saveRules = async () => {
    if (!rules) return;
    setSavingRules(true);
    setError(null);
    try {
      const updated = await api.putRules(rules);
      setRules(updated);
    } catch (e) {
      setError(String(e));
    } finally {
      setSavingRules(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle className="mono uppercase tracking-[0.2em] text-primary">
            Preferences
          </DialogTitle>
          <DialogDescription>
            Configure alert rules (synced with the agent) and alert sounds
            (browser-side).
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="rules">
          <TabsList>
            <TabsTrigger value="rules">
              <Bell className="h-3.5 w-3.5 mr-1.5" />
              Alert rules
            </TabsTrigger>
            <TabsTrigger value="sound">
              <Volume2 className="h-3.5 w-3.5 mr-1.5" />
              Sounds
            </TabsTrigger>
            <TabsTrigger value="geoip">
              <Globe className="h-3.5 w-3.5 mr-1.5" />
              GeoIP
            </TabsTrigger>
          </TabsList>

          <TabsContent value="rules">
            {rules ? (
              <RulesEditor
                rules={rules}
                threatCount={threatCount}
                onChange={setRules}
              />
            ) : (
              <div className="mono text-xs text-muted-foreground py-4">
                Loading rules…
              </div>
            )}
          </TabsContent>

          <TabsContent value="sound">
            <SoundEditor cfg={sound} onChange={setSound} />
          </TabsContent>

          <TabsContent value="geoip">
            <GeoIpPanel />
          </TabsContent>
        </Tabs>

        {error && (
          <div className="mono text-xs text-destructive break-all">
            {error}
          </div>
        )}

        <DialogFooter>
          <Button onClick={saveRules} disabled={!rules || savingRules}>
            <Save className="h-4 w-4 mr-2" />
            {savingRules ? "Saving…" : "Save rules"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RulesEditor({
  rules,
  threatCount,
  onChange,
}: {
  rules: AlertRules;
  threatCount: number | null;
  onChange: (r: AlertRules) => void;
}) {
  const set = <K extends keyof AlertRules>(k: K, v: AlertRules[K]) =>
    onChange({ ...rules, [k]: v });

  return (
    <div className="space-y-3">
      <Row
        label="Alerts enabled (master switch)"
        checked={rules.enabled}
        onChange={(v) => set("enabled", v)}
        bold
      />
      <Separator />
      <Row
        label="Threat list match (Spamhaus DROP, FireHOL, Tor, custom)"
        sub={
          threatCount != null
            ? `${threatCount.toLocaleString()} ranges loaded`
            : undefined
        }
        checked={rules.threat_list}
        onChange={(v) => set("threat_list", v)}
      />
      <Row
        label="Burst toward a single remote IP"
        sub="High packet rate (e.g. floods, scans)"
        checked={rules.burst}
        onChange={(v) => set("burst", v)}
      />
      <div className="ml-6 flex items-center gap-2 text-xs">
        <Label className="text-muted-foreground">Threshold (pkt/s)</Label>
        <Input
          type="number"
          min={50}
          max={50000}
          step={50}
          className="h-7 w-24 font-mono"
          value={rules.burst_threshold_pps}
          onChange={(e) =>
            set("burst_threshold_pps", Math.max(50, parseInt(e.target.value) || 50))
          }
          disabled={!rules.burst}
        />
      </div>

      <Row
        label="Suspicious destination ports"
        sub={`Currently watching ${rules.suspicious_ports.length} ports`}
        checked={rules.suspicious_port}
        onChange={(v) => set("suspicious_port", v)}
      />
      <Row
        label="New process opens an external connection"
        sub="Helps spot unknown apps reaching out"
        checked={rules.new_process_external}
        onChange={(v) => set("new_process_external", v)}
      />
      <Row
        label="First connection to a new ASN"
        checked={rules.new_asn}
        onChange={(v) => set("new_asn", v)}
      />
      <Row
        label="First connection to a new country"
        checked={rules.new_country}
        onChange={(v) => set("new_country", v)}
      />
    </div>
  );
}

function SoundEditor({
  cfg,
  onChange,
}: {
  cfg: AlertSoundConfig;
  onChange: (c: AlertSoundConfig) => void;
}) {
  const set = <K extends keyof AlertSoundConfig>(k: K, v: AlertSoundConfig[K]) =>
    onChange({ ...cfg, [k]: v });
  const setSeverity = (sev: Severity, v: boolean) =>
    onChange({ ...cfg, perSeverity: { ...cfg.perSeverity, [sev]: v } });

  const test = (sev: Severity) => playAlertSound(sev, { ...cfg, enabled: true });

  return (
    <div className="space-y-3">
      <Row
        label="Sounds enabled"
        checked={cfg.enabled}
        onChange={(v) => set("enabled", v)}
        bold
      />
      <div className="space-y-1">
        <Label className="text-xs text-muted-foreground flex items-center gap-2">
          {cfg.enabled ? (
            <Volume2 className="h-3.5 w-3.5" />
          ) : (
            <VolumeX className="h-3.5 w-3.5" />
          )}
          Volume — {Math.round(cfg.volume * 100)}%
        </Label>
        <Slider
          min={0}
          max={1}
          step={0.05}
          value={[cfg.volume]}
          onValueChange={(v) => set("volume", v[0])}
          disabled={!cfg.enabled}
        />
      </div>
      <Separator />
      <div className="space-y-2">
        {(["critical", "high", "medium", "low", "info"] as Severity[]).map(
          (sev) => (
            <div key={sev} className="flex items-center gap-3">
              <Switch
                checked={cfg.perSeverity[sev]}
                onCheckedChange={(v) => setSeverity(sev, v)}
                disabled={!cfg.enabled}
              />
              <span className="text-xs flex-1 capitalize mono">{sev}</span>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 px-2"
                onClick={() => test(sev)}
                disabled={!cfg.enabled}
              >
                <Play className="h-3 w-3 mr-1" />
                Test
              </Button>
            </div>
          ),
        )}
      </div>
      <p className="text-[10px] text-muted-foreground/80 mono">
        Same severity sounds are debounced (1.5s) to avoid spam.
      </p>
      <Button
        variant="outline"
        size="sm"
        onClick={() => onChange(defaultAlertSoundConfig())}
      >
        Reset to defaults
      </Button>
    </div>
  );
}

function Row({
  label,
  sub,
  checked,
  onChange,
  bold,
}: {
  label: string;
  sub?: string;
  checked: boolean;
  onChange: (b: boolean) => void;
  bold?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-3">
      <div className="flex-1">
        <div className={bold ? "text-sm font-medium" : "text-xs"}>{label}</div>
        {sub && (
          <div className="text-[10px] text-muted-foreground mono">{sub}</div>
        )}
      </div>
      <Switch checked={checked} onCheckedChange={onChange} />
    </div>
  );
}

function GeoIpPanel() {
  const [info, setInfo] = useState<GeoIpInfo | null>(null);
  const [loadingInfo, setLoadingInfo] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [progressMsg, setProgressMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<{
    elapsed_ms: number;
  } | null>(null);

  const refresh = async () => {
    setLoadingInfo(true);
    setError(null);
    try {
      const i = await api.geoipInfo();
      setInfo(i);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoadingInfo(false);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const update = async () => {
    if (updating) return;
    setUpdating(true);
    setError(null);
    setProgressMsg("Downloading from P3TERX mirror…");
    try {
      const resp = await api.geoipUpdate();
      setLastUpdate({ elapsed_ms: resp.elapsed_ms });
      setInfo({
        city: resp.city,
        asn: resp.asn,
        override_dir: info?.override_dir ?? "",
      });
      setProgressMsg(null);
    } catch (e) {
      setError(String(e));
      setProgressMsg(null);
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-muted-foreground">
        GeoIP databases come from the{" "}
        <a
          href="https://github.com/P3TERX/GeoLite.mmdb"
          target="_blank"
          rel="noreferrer"
          className="text-primary underline-offset-2 hover:underline"
        >
          P3TERX/GeoLite.mmdb
        </a>{" "}
        mirror (MaxMind GeoLite2 EULA). Updating fetches the latest
        snapshot and reloads the resolver in place.
      </div>

      {info ? (
        <>
          <DbCard label="GeoLite2-City" file={info.city} />
          <DbCard label="GeoLite2-ASN" file={info.asn} />
          <div className="text-[10px] text-muted-foreground/70 mono break-all">
            override dir: {info.override_dir}
          </div>
        </>
      ) : (
        <div className="mono text-xs text-muted-foreground py-2">
          {loadingInfo ? "Loading…" : "—"}
        </div>
      )}

      <Separator />

      <div className="flex items-center gap-2">
        <Button onClick={update} disabled={updating}>
          <RefreshCw
            className={`h-4 w-4 mr-2 ${updating ? "animate-spin" : ""}`}
          />
          {updating ? "Updating…" : "Update now"}
        </Button>
        <Button variant="outline" onClick={refresh} disabled={loadingInfo}>
          Refresh info
        </Button>
      </div>

      {progressMsg && (
        <div className="mono text-[11px] text-muted-foreground">
          {progressMsg}
        </div>
      )}

      {lastUpdate && !updating && !error && (
        <div className="flex items-center gap-2 mono text-[11px] text-neon-green">
          <CheckCircle2 className="h-3.5 w-3.5" />
          Updated in {(lastUpdate.elapsed_ms / 1000).toFixed(1)}s
        </div>
      )}

      {error && (
        <div className="flex items-start gap-2 mono text-[11px] text-destructive">
          <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
          <span className="break-all">{error}</span>
        </div>
      )}
    </div>
  );
}

function DbCard({
  label,
  file,
}: {
  label: string;
  file: GeoIpInfo["city"];
}) {
  const date = file.modified_iso
    ? new Date(file.modified_iso).toLocaleString()
    : "—";
  const sourceLabel: Record<string, string> = {
    override: "user override",
    cwd: "bundled (cwd)",
    exe: "bundled (exe dir)",
    missing: "MISSING",
  };
  return (
    <div className="rounded-md border border-border/60 bg-secondary/30 p-3 space-y-0.5">
      <div className="flex items-center justify-between">
        <span className="mono text-xs text-foreground/90">{label}</span>
        <span
          className={`mono text-[10px] ${
            file.exists ? "text-neon-green" : "text-destructive"
          }`}
        >
          {file.exists ? formatBytes(file.size_bytes) : "missing"}
        </span>
      </div>
      <div className="mono text-[10px] text-muted-foreground">
        modified: {date}
      </div>
      <div className="mono text-[10px] text-muted-foreground">
        source: {sourceLabel[file.source] ?? file.source}
      </div>
    </div>
  );
}
