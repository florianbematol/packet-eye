// Zustand store for alerts: a ring buffer of the most recent N entries.

import { create } from "zustand";
import type { Alert, Severity } from "@/lib/types";

const MAX_ALERTS = 200;

interface AlertsStoreState {
  alerts: Alert[];
  /** Monotonic counter so React keys are stable even if two alerts share ts. */
  seq: number;
  ingest: (batch: Alert[]) => void;
  clear: () => void;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const useAlertsStore = create<AlertsStoreState>((set, get) => ({
  alerts: [],
  seq: 0,
  ingest: (batch) => {
    if (!batch.length) return;
    const state = get();
    const merged = state.alerts.concat(batch);
    if (merged.length > MAX_ALERTS) {
      merged.splice(0, merged.length - MAX_ALERTS);
    }
    set({ alerts: merged, seq: state.seq + batch.length });
  },
  clear: () => set({ alerts: [], seq: 0 }),
}));
