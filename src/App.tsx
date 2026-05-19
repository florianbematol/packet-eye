import { lazy, Suspense, useEffect, useState } from "react";
import {
  Wifi,
  WifiOff,
  AlertCircle,
  Settings,
  Pause,
  Play,
} from "lucide-react";
import CapturePanel from "@/panels/CapturePanel";
import StatsBar from "@/panels/StatsBar";
import ConnectionsList from "@/panels/ConnectionsList";
import AlertsFeed from "@/panels/AlertsFeed";
import SelectedConnectionPanel from "@/panels/SelectedConnectionPanel";
import DraggablePanel from "@/components/DraggablePanel";
import ResizableRightPanel from "@/components/ResizableRightPanel";
import { Button } from "@/components/ui/button";
import { useConnectionsStore } from "@/store/connectionsStore";
import { useAlertsStore } from "@/store/alertsStore";
import { usePrefsStore } from "@/store/prefsStore";
import { useSelectionStore } from "@/store/selectionStore";
import { createPacketStream, type ConnStatus } from "@/lib/ws";
import { playAlertSound, unlockAudio } from "@/lib/audio";
import { cn } from "@/lib/utils";

// The heavy 3D scene (three + r3f + postprocessing) is split into its
// own chunk and loaded after the initial paint.
const GlobeScene = lazy(() => import("@/scene/GlobeScene"));
// Preferences dialog is rarely opened — lazy load too.
const PreferencesDialog = lazy(() => import("@/panels/Preferences"));

export default function App() {
  const ingestBatch = useConnectionsStore((s) => s.ingestBatch);
  const setStats = useConnectionsStore((s) => s.setStats);
  const flashRemote = useConnectionsStore((s) => s.flashRemote);
  const ingestAlerts = useAlertsStore((s) => s.ingest);
  const soundCfg = usePrefsStore((s) => s.sound);
  const [running, setRunning] = useState(false);
  const [conn, setConn] = useState<ConnStatus>("connecting");
  const [prefsOpen, setPrefsOpen] = useState(false);
  const [autoRotate, setAutoRotate] = useState(false);

  // Unlock the audio context on the first click anywhere.
  useEffect(() => {
    const handler = () => unlockAudio();
    window.addEventListener("pointerdown", handler, { once: true });
    return () => window.removeEventListener("pointerdown", handler);
  }, []);

  useEffect(() => {
    const stream = createPacketStream({
      onPackets: ingestBatch,
      onStats: setStats,
      onAlerts: (alerts) => {
        ingestAlerts(alerts);
        // Flash the affected remote(s) on the globe and play a sound for
        // the highest-severity alert in this batch.
        const cfg = usePrefsStore.getState().sound;
        let top = alerts[0];
        for (const a of alerts) {
          if (severityWeight(a.severity) < severityWeight(top.severity)) {
            top = a;
          }
          if (a.remote_ip) {
            const dur =
              a.severity === "critical"
                ? 8000
                : a.severity === "high"
                  ? 5000
                  : 3000;
            flashRemote(a.remote_ip, dur);
          }
        }
        playAlertSound(top.severity, cfg);
      },
      onStatus: setConn,
    });
    return () => stream.close();
  }, [ingestBatch, setStats, ingestAlerts, flashRemote]);

  // Keep the audio config in sync with the prefs (volume changes etc.).
  useEffect(() => {
    // no-op: playAlertSound reads the current store state, but reading
    // soundCfg here keeps us subscribed for re-renders.
    void soundCfg;
  }, [soundCfg]);

  return (
    <div className="relative h-screen w-screen overflow-hidden">
      {/* Globe scene fills the background (lazy-loaded chunk) */}
      <div className="absolute inset-0 z-0">
        <Suspense
          fallback={
            <div className="absolute inset-0 flex items-center justify-center mono text-xs text-muted-foreground">
              Loading 3D engine…
            </div>
          }
        >
          <GlobeScene autoRotate={autoRotate} />
        </Suspense>
      </div>

      {/* Header */}
      <header className="absolute top-0 left-0 right-0 z-20 flex items-center justify-between px-5 py-3 pointer-events-none">
        <div className="flex items-center gap-3 pointer-events-auto">
          <div
            className={cn(
              "h-2 w-2 rounded-full",
              conn === "open"
                ? "bg-neon-green animate-pulse-glow shadow-[0_0_12px_rgba(57,255,138,0.6)]"
                : conn === "error"
                  ? "bg-destructive"
                  : "bg-muted-foreground",
            )}
          />
          <div className="mono text-xs uppercase tracking-[0.4em] text-foreground/80">
            packet eye
          </div>
          <ConnIndicator status={conn} />
        </div>
        <div className="flex items-center gap-3 pointer-events-auto">
          <div className="pointer-events-auto">
            <StatsBar />
          </div>
          <Button
            variant="outline"
            size="icon"
            className="h-9 w-9 glass"
            onClick={() => setAutoRotate((v) => !v)}
            title={autoRotate ? "Pause auto-rotate" : "Resume auto-rotate"}
          >
            {autoRotate ? (
              <Pause className="h-4 w-4" />
            ) : (
              <Play className="h-4 w-4" />
            )}
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="h-9 w-9 glass"
            onClick={() => setPrefsOpen(true)}
            title="Preferences"
          >
            <Settings className="h-4 w-4" />
          </Button>
        </div>
      </header>

      <Suspense fallback={null}>
        {prefsOpen && (
          <PreferencesDialog open={prefsOpen} onOpenChange={setPrefsOpen} />
        )}
      </Suspense>

      {/* Left panel: capture controls (draggable) */}
      <DraggablePanel
        storageKey="packet-eye:panel:capture"
        initial={{ x: 20, y: 80 }}
        width={360}
      >
        <CapturePanel running={running} setRunning={setRunning} />
      </DraggablePanel>

      {/* Bottom-left: alerts (draggable) */}
      <DraggablePanel
        storageKey="packet-eye:panel:alerts"
        initial={{
          x: 20,
          y:
            (typeof window !== "undefined" ? window.innerHeight : 900) -
            260 -
            20,
        }}
        width={360}
        height={260}
      >
        <AlertsFeed />
      </DraggablePanel>

      {/* Floating selection card (draggable) — only visible when a
          connection is selected (via globe click or table row click). */}
      <SelectionOverlay />

      {/* Right panel: live connections. Width is user-resizable via a
          vertical handle on the panel's left edge, persisted to
          localStorage. */}
      <ResizableRightPanel
        storageKey="packet-eye:panel:connections:width"
        initial={640}
        min={360}
      >
        <ConnectionsList />
      </ResizableRightPanel>
    </div>
  );
}

function severityWeight(s: string): number {
  switch (s) {
    case "critical":
      return 0;
    case "high":
      return 1;
    case "medium":
      return 2;
    case "low":
      return 3;
    default:
      return 4;
  }
}

function SelectionOverlay() {
  const selectedId = useSelectionStore((s) => s.selectedId);
  if (!selectedId) return null;
  // Initial centre-bottom position; the user can drag from there.
  const initial = {
    x:
      typeof window !== "undefined"
        ? Math.max(20, window.innerWidth / 2 - 240)
        : 400,
    y:
      typeof window !== "undefined"
        ? Math.max(20, window.innerHeight - 460)
        : 400,
  };
  return (
    <DraggablePanel
      storageKey="packet-eye:panel:selection"
      initial={initial}
      width={480}
    >
      <SelectedConnectionPanel />
    </DraggablePanel>
  );
}

function ConnIndicator({ status }: { status: ConnStatus }) {
  const { Icon, label, cls } = (() => {
    switch (status) {
      case "open":
        return { Icon: Wifi, label: "connected", cls: "text-neon-green" };
      case "connecting":
        return {
          Icon: Wifi,
          label: "connecting…",
          cls: "text-muted-foreground",
        };
      case "closed":
        return {
          Icon: WifiOff,
          label: "disconnected",
          cls: "text-muted-foreground",
        };
      case "error":
        return {
          Icon: AlertCircle,
          label: "agent unreachable",
          cls: "text-destructive",
        };
    }
  })();
  return (
    <span className={cn("flex items-center gap-1 mono text-[10px]", cls)}>
      <Icon className="h-3 w-3" />
      {label}
    </span>
  );
}
