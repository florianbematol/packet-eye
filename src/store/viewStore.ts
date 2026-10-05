// Which top-level view is shown over the globe.

import { create } from "zustand";

export type View = "live" | "apps" | "history" | "firewall";

const KEY = "packet-eye:view";

function load(): View {
  const v = typeof localStorage !== "undefined" ? localStorage.getItem(KEY) : null;
  return v === "apps" || v === "history" || v === "firewall" ? v : "live";
}

interface ViewState {
  view: View;
  setView: (v: View) => void;
}

export const useViewStore = create<ViewState>((set) => ({
  view: load(),
  setView: (view) => {
    try {
      localStorage.setItem(KEY, view);
    } catch {
      /* ignore */
    }
    set({ view });
  },
}));
