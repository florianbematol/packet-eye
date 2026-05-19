// Synthesised alert sounds via the Web Audio API.
//
// We generate short tonal beeps in code so we don't have to ship audio
// files. Each severity gets a distinct frequency / envelope so a user
// can recognise the alert without looking at the screen.

import type { Severity } from "@/lib/types";

interface ToneSpec {
  freq: number;
  duration: number;
  type: OscillatorType;
  sweep?: number;
}

const TONES: Record<Severity, ToneSpec> = {
  critical: { freq: 880, duration: 0.32, type: "square", sweep: -380 },
  high: { freq: 660, duration: 0.22, type: "sawtooth", sweep: -180 },
  medium: { freq: 520, duration: 0.18, type: "triangle" },
  low: { freq: 420, duration: 0.14, type: "sine" },
  info: { freq: 700, duration: 0.1, type: "sine" },
};

let ctx: AudioContext | null = null;
let masterGain: GainNode | null = null;
const lastPlayed: Partial<Record<Severity, number>> = {};
const DEBOUNCE_MS = 1500;

function ensureCtx(): AudioContext | null {
  if (typeof window === "undefined") return null;
  if (!ctx) {
    const Ctx =
      (window.AudioContext as typeof AudioContext) ||
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ((window as any).webkitAudioContext as typeof AudioContext | undefined);
    if (!Ctx) return null;
    ctx = new Ctx();
    masterGain = ctx.createGain();
    masterGain.gain.value = 0.18;
    masterGain.connect(ctx.destination);
  }
  return ctx;
}

export interface AlertSoundConfig {
  enabled: boolean;
  /** 0..1 master volume multiplier. */
  volume: number;
  /** Per-severity toggle. */
  perSeverity: Record<Severity, boolean>;
}

export const defaultAlertSoundConfig = (): AlertSoundConfig => ({
  enabled: true,
  volume: 0.7,
  perSeverity: {
    critical: true,
    high: true,
    medium: true,
    low: false,
    info: false,
  },
});

export function setMasterVolume(v: number) {
  if (!masterGain) return;
  masterGain.gain.value = Math.max(0, Math.min(1, v)) * 0.25;
}

export function playAlertSound(severity: Severity, cfg: AlertSoundConfig) {
  if (!cfg.enabled) return;
  if (!cfg.perSeverity[severity]) return;
  const now = performance.now();
  const last = lastPlayed[severity] ?? 0;
  if (now - last < DEBOUNCE_MS) return;
  lastPlayed[severity] = now;

  const audio = ensureCtx();
  if (!audio || !masterGain) return;
  // Resume context lazily — many browsers require user gesture.
  if (audio.state === "suspended") {
    audio.resume().catch(() => {});
  }
  setMasterVolume(cfg.volume);

  const tone = TONES[severity];
  const t0 = audio.currentTime;
  const osc = audio.createOscillator();
  const gain = audio.createGain();
  osc.type = tone.type;
  osc.frequency.setValueAtTime(tone.freq, t0);
  if (tone.sweep) {
    osc.frequency.exponentialRampToValueAtTime(
      Math.max(60, tone.freq + tone.sweep),
      t0 + tone.duration,
    );
  }
  // ADSR-ish envelope.
  gain.gain.setValueAtTime(0, t0);
  gain.gain.linearRampToValueAtTime(1.0, t0 + 0.01);
  gain.gain.exponentialRampToValueAtTime(0.001, t0 + tone.duration);

  osc.connect(gain);
  gain.connect(masterGain);
  osc.start(t0);
  osc.stop(t0 + tone.duration + 0.05);
}

/** Forces a no-op sound to unlock the audio graph after first user click. */
export function unlockAudio() {
  const audio = ensureCtx();
  if (!audio) return;
  if (audio.state === "suspended") {
    audio.resume().catch(() => {});
  }
}
