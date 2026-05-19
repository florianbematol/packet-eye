// Persisted UI preferences (alert sound config). Stored in localStorage
// because they are purely client-side: nothing on the agent depends on
// these, only the browser plays the sounds.

import { create } from "zustand";
import {
  defaultAlertSoundConfig,
  type AlertSoundConfig,
} from "@/lib/audio";

const STORAGE_KEY = "packet-eye:prefs:v1";

interface PrefsState {
  sound: AlertSoundConfig;
  setSound: (cfg: AlertSoundConfig) => void;
}

function load(): PrefsState["sound"] {
  if (typeof localStorage === "undefined") return defaultAlertSoundConfig();
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return defaultAlertSoundConfig();
    const parsed = JSON.parse(raw) as { sound?: AlertSoundConfig };
    if (!parsed?.sound) return defaultAlertSoundConfig();
    return { ...defaultAlertSoundConfig(), ...parsed.sound };
  } catch {
    return defaultAlertSoundConfig();
  }
}

function save(sound: AlertSoundConfig) {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ sound }));
  } catch {
    /* ignore quota etc. */
  }
}

export const usePrefsStore = create<PrefsState>((set) => ({
  sound: load(),
  setSound: (cfg) => {
    save(cfg);
    set({ sound: cfg });
  },
}));
