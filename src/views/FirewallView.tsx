// Firewall dashboard: every Windows Firewall rule created by Packet Eye
// (group "Packet Eye"), with toggles, deletion, manual creation and
// one-click blocking of endpoints flagged by recent alerts.

import { useEffect, useMemo, useState } from "react";
import {
  Ban,
  Loader2,
  RefreshCcw,
  Shield,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  Trash2,
} from "lucide-react";
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
import { rulesBlockingIp, useFirewallStore } from "@/store/firewallStore";
import { useAlertsStore } from "@/store/alertsStore";
import type { BlockDirection, FirewallRule, Severity } from "@/lib/types";

type Filter = "all" | "enabled" | "disabled";

export default function FirewallView() {
  const { rules, loaded, loading, error, refresh, setEnabled, remove } = useFirewallStore();
  const [filter, setFilter] = useState<Filter>("all");
  const [rowError, setRowError] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const shown = rules.filter((r) =>
    filter === "all" ? true : filter === "enabled" ? r.enabled : !r.enabled,
  );
  const enabledCount = rules.filter((r) => r.enabled).length;

  const act = async (id: string, fn: () => Promise<void>) => {
    setPending(id);
    setRowError(null);
    try {
      await fn();
    } catch (e) {
      setRowError(e instanceof Error ? e.message : String(e));
    } finally {
      setPending(null);
    }
  };

  return (
    <ViewShell
      title="Firewall"
      icon={<Shield className="h-3.5 w-3.5" />}
      actions={
        <>
          <Segmented<Filter>
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: `All ${rules.length}` },
              { value: "enabled", label: `Active ${enabledCount}` },
              { value: "disabled", label: `Off ${rules.length - enabledCount}` },
            ]}
          />
          <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => void refresh()} title="Refresh">
            <RefreshCcw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          </Button>
        </>
      }
    >
      <div className="p-4 grid grid-cols-1 xl:grid-cols-[1fr_380px] gap-4">
        <div className="space-y-3 min-w-0">
          <div className="grid grid-cols-3 gap-3">
            <Stat icon={<ShieldBan className="h-4 w-4 text-destructive" />} label="Active rules" value={enabledCount} />
            <Stat icon={<Shield className="h-4 w-4 text-muted-foreground" />} label="Disabled" value={rules.length - enabledCount} />
            <Stat
              icon={<ShieldCheck className="h-4 w-4 text-primary" />}
              label="IP / app rules"
              value={`${rules.filter(isIpRule).length} / ${rules.length - rules.filter(isIpRule).length}`}
            />
          </div>

          {(error || rowError) && (
            <div className="mono text-xs text-destructive break-all">{rowError ?? error}</div>
          )}

          <div className="rounded-md border border-border/50 overflow-hidden">
            <table className="w-full text-xs mono">
              <thead className="bg-card/95 text-muted-foreground">
                <tr>
                  <th className="text-left px-3 py-2 font-normal">on</th>
                  <th className="text-left px-2 py-2 font-normal">rule</th>
                  <th className="text-left px-2 py-2 font-normal">direction</th>
                  <th className="text-left px-2 py-2 font-normal">target</th>
                  <th className="px-2 py-2" />
                </tr>
              </thead>
              <tbody>
                {!loaded && loading && (
                  <tr>
                    <td colSpan={5} className="px-3 py-8 text-center text-muted-foreground">
                      Reading Windows Firewall…
                    </td>
                  </tr>
                )}
                {loaded && shown.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-3 py-8 text-center text-muted-foreground">
                      {rules.length === 0
                        ? "No Packet Eye rule yet. Block an IP or an app from a connection, the Apps view, or the form on the right."
                        : "No rule matches this filter."}
                    </td>
                  </tr>
                )}
                {shown.map((r) => (
                  <RuleRow
                    key={r.id}
                    rule={r}
                    busy={pending === r.id}
                    onToggle={(v) => act(r.id, () => setEnabled(r.id, v))}
                    onDelete={() => act(r.id, () => remove(r.id))}
                  />
                ))}
              </tbody>
            </table>
          </div>
          <p className="mono text-[10px] text-muted-foreground/70">
            Rules live in Windows Firewall (group “Packet Eye”) and keep working when the agent is
            stopped. Changes require the agent to run as Administrator. Traffic that a rule blocks
            never reaches the network card, so it doesn't show up in the capture.
          </p>
        </div>

        <div className="space-y-4">
          <AddRuleForm />
          <FlaggedEndpoints rules={rules} />
        </div>
      </div>
    </ViewShell>
  );
}

function isIpRule(r: FirewallRule) {
  return !r.program || r.program === "Any";
}

function RuleRow({
  rule,
  busy,
  onToggle,
  onDelete,
}: {
  rule: FirewallRule;
  busy: boolean;
  onToggle: (v: boolean) => void;
  onDelete: () => void;
}) {
  const [confirm, setConfirm] = useState(false);
  const target = isIpRule(rule) ? rule.remote.join(", ") : rule.program;
  return (
    <tr className={`border-t border-border/40 ${rule.enabled ? "" : "opacity-60"}`}>
      <td className="px-3 py-2">
        <Switch checked={rule.enabled} disabled={busy} onCheckedChange={onToggle} />
      </td>
      <td className="px-2 py-2">
        <div className="text-foreground/90">{rule.name}</div>
        {rule.description && (
          <div className="text-[10px] text-muted-foreground/80 break-all">{rule.description}</div>
        )}
      </td>
      <td className="px-2 py-2 whitespace-nowrap">
        <Badge variant={rule.direction === "Inbound" ? "pink" : "default"}>{rule.direction.toLowerCase()}</Badge>
      </td>
      <td className="px-2 py-2 break-all max-w-[320px]">
        <span className={isIpRule(rule) ? "text-primary" : "text-neon-green/90"}>{target}</span>
      </td>
      <td className="px-2 py-2 text-right whitespace-nowrap">
        {busy ? (
          <Loader2 className="h-4 w-4 animate-spin inline text-muted-foreground" />
        ) : confirm ? (
          <span className="inline-flex gap-1">
            <Button size="sm" variant="destructive" className="h-7" onClick={onDelete}>
              Delete
            </Button>
            <Button size="sm" variant="ghost" className="h-7" onClick={() => setConfirm(false)}>
              Cancel
            </Button>
          </span>
        ) : (
          <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => setConfirm(true)} title="Delete rule">
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        )}
      </td>
    </tr>
  );
}

function AddRuleForm() {
  const block = useFirewallStore((s) => s.block);
  const [kind, setKind] = useState<"ip" | "program">("ip");
  const [value, setValue] = useState("");
  const [direction, setDirection] = useState<BlockDirection>("out");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const submit = async () => {
    setBusy(true);
    setMsg(null);
    try {
      await block(
        kind === "ip" ? { kind: "ip", value } : { kind: "program", path: value },
        direction,
        note.trim() || undefined,
      );
      setMsg({ ok: true, text: "Rule created." });
      setValue("");
      setNote("");
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-md border border-border/50 p-3 space-y-2.5">
      <div className="mono text-[10px] uppercase tracking-[0.25em] text-primary">New block rule</div>
      <Segmented<"ip" | "program">
        value={kind}
        onChange={setKind}
        options={[
          { value: "ip", label: "IP / CIDR" },
          { value: "program", label: "Application" },
        ]}
      />
      <Input
        className="text-xs font-mono"
        placeholder={kind === "ip" ? "203.0.113.7, 198.51.100.0/24" : "C:\\Program Files\\App\\app.exe"}
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
      <Select value={direction} onValueChange={(v) => setDirection(v as BlockDirection)}>
        <SelectTrigger className="text-xs">
          <SelectValue />
        </SelectTrigger>
        <SelectContent className="text-xs">
          <SelectItem value="out">Outbound</SelectItem>
          <SelectItem value="in">Inbound</SelectItem>
          <SelectItem value="both">Both directions</SelectItem>
        </SelectContent>
      </Select>
      <Input
        className="text-xs"
        placeholder="Note (optional)"
        maxLength={200}
        value={note}
        onChange={(e) => setNote(e.target.value)}
      />
      <Button className="w-full" variant="destructive" onClick={submit} disabled={busy || !value.trim()}>
        {busy ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Ban className="h-4 w-4 mr-2" />}
        Block
      </Button>
      {msg && (
        <div className={`mono text-[11px] break-all ${msg.ok ? "text-neon-green" : "text-destructive"}`}>
          {msg.text}
        </div>
      )}
    </div>
  );
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Remote IPs that triggered alerts this session, worst first. */
function FlaggedEndpoints({ rules }: { rules: FirewallRule[] }) {
  const alerts = useAlertsStore((s) => s.alerts);
  const flagged = useMemo(() => {
    const by = new Map<string, { ip: string; severity: Severity; count: number; message: string }>();
    for (const a of alerts) {
      if (!a.remote_ip || a.severity === "info") continue;
      const cur = by.get(a.remote_ip);
      if (!cur) {
        by.set(a.remote_ip, { ip: a.remote_ip, severity: a.severity, count: 1, message: a.message });
      } else {
        cur.count += 1;
        if (SEVERITY_RANK[a.severity] < SEVERITY_RANK[cur.severity]) {
          cur.severity = a.severity;
          cur.message = a.message;
        }
      }
    }
    return [...by.values()]
      .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || b.count - a.count)
      .slice(0, 30);
  }, [alerts]);

  return (
    <div className="rounded-md border border-border/50 overflow-hidden">
      <div className="px-3 py-2 border-b border-border/50 mono text-[10px] uppercase tracking-[0.25em] text-primary flex items-center gap-1.5">
        <ShieldAlert className="h-3.5 w-3.5" /> Flagged this session · {flagged.length}
      </div>
      <div className="max-h-[40vh] overflow-auto divide-y divide-border/40">
        {flagged.length === 0 && (
          <div className="px-3 py-6 text-center mono text-xs text-muted-foreground">
            No suspicious endpoint so far.
          </div>
        )}
        {flagged.map((f) => {
          const blocked = rulesBlockingIp(rules, f.ip).length > 0;
          return (
            <div key={f.ip} className="px-3 py-2 flex items-center gap-2">
              <div className="flex-1 min-w-0">
                <div className="mono text-xs flex items-center gap-2">
                  <span className="text-foreground">{f.ip}</span>
                  <Badge variant={f.severity === "critical" ? "destructive" : f.severity === "high" ? "amber" : "pink"}>
                    {f.severity}
                  </Badge>
                  {f.count > 1 && <span className="text-muted-foreground text-[10px]">×{f.count}</span>}
                </div>
                <div className="mono text-[10px] text-muted-foreground truncate" title={f.message}>
                  {f.message}
                </div>
              </div>
              {blocked ? (
                <Badge variant="destructive" className="gap-1">
                  <ShieldBan className="h-3 w-3" /> blocked
                </Badge>
              ) : (
                <BlockButton target={{ kind: "ip", value: f.ip }} label={f.ip} />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Stat({ icon, label, value }: { icon: React.ReactNode; label: string; value: number | string }) {
  return (
    <div className="rounded-md border border-border/50 bg-secondary/20 px-3 py-2 flex items-center gap-3">
      {icon}
      <div>
        <div className="mono text-[9px] uppercase tracking-[0.2em] text-muted-foreground">{label}</div>
        <div className="mono text-lg tabular-nums">{value}</div>
      </div>
    </div>
  );
}
