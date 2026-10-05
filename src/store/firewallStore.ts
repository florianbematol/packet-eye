// Packet Eye firewall rules (Windows Firewall, group "Packet Eye").
// Shared by the Firewall view, the Apps view and the connection panel.

import { create } from "zustand";
import { api } from "@/lib/api";
import type { BlockDirection, BlockTarget, FirewallRule } from "@/lib/types";

interface FirewallState {
  rules: FirewallRule[];
  loaded: boolean;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  block: (target: BlockTarget, direction: BlockDirection, note?: string) => Promise<void>;
  setEnabled: (id: string, enabled: boolean) => Promise<void>;
  remove: (id: string) => Promise<void>;
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export const useFirewallStore = create<FirewallState>((set, get) => ({
  rules: [],
  loaded: false,
  loading: false,
  error: null,

  refresh: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      set({ rules: await api.firewallRules(), loaded: true });
    } catch (e) {
      set({ error: errMsg(e) });
    } finally {
      set({ loading: false });
    }
  },

  // Mutations rethrow so callers can show the error next to the button.
  block: async (target, direction, note) => {
    const { rules } = await api.firewallBlock(target, direction, note);
    set({ rules, loaded: true, error: null });
  },
  setEnabled: async (id, enabled) => {
    set({ rules: await api.firewallSetEnabled(id, enabled), error: null });
  },
  remove: async (id) => {
    set({ rules: await api.firewallDelete(id), error: null });
  },
}));

/** Enabled rules that block this exact IP (CIDR rules are matched too). */
export function rulesBlockingIp(rules: FirewallRule[], ip: string): FirewallRule[] {
  return rules.filter(
    (r) => r.enabled && r.remote.some((addr) => addrMatches(addr, ip)),
  );
}

/** Enabled rules that block a program by file name (e.g. "chrome.exe"). */
export function rulesBlockingProcess(
  rules: FirewallRule[],
  processName: string | null | undefined,
): FirewallRule[] {
  if (!processName) return [];
  const name = processName.toLowerCase();
  return rules.filter((r) => {
    if (!r.enabled || !r.program || r.program === "Any") return false;
    const file = r.program.split(/[\\/]/).pop()?.toLowerCase();
    return file === name;
  });
}

function addrMatches(rule: string, ip: string): boolean {
  if (rule === "Any") return false;
  if (!rule.includes("/")) return rule === ip;
  // Windows reports CIDRs either as a/len or a/mask; only handle IPv4 a/len.
  const [base, lenStr] = rule.split("/");
  const len = Number(lenStr);
  const a = ipv4ToInt(base);
  const b = ipv4ToInt(ip);
  if (a === null || b === null || !Number.isInteger(len) || len < 0 || len > 32) {
    return false;
  }
  const mask = len === 0 ? 0 : (~0 << (32 - len)) >>> 0;
  return (a & mask) === (b & mask);
}

function ipv4ToInt(s: string): number | null {
  const p = s.split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const part of p) {
    const v = Number(part);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}
