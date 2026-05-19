// 3D globe scene driven by the live connection store.

import { Suspense, useEffect, useMemo, useState } from "react";
import { Canvas } from "@react-three/fiber";
import { OrbitControls, Stars } from "@react-three/drei";
import { EffectComposer, Bloom } from "@react-three/postprocessing";
import * as THREE from "three";
import Earth, { EARTH_RADIUS } from "@/scene/Earth";
import Hotspot from "@/scene/Hotspot";
import Arc from "@/scene/Arc";
import { latLonToVec3 } from "@/lib/geo";
import { api } from "@/lib/api";
import { useConnectionsStore } from "@/store/connectionsStore";
import { useSelectionStore } from "@/store/selectionStore";
import type { GeoLookup } from "@/lib/types";

const ACTIVITY_WINDOW_MS = 30_000;
const FALLBACK_USER = { lat: 48.8566, lon: 2.3522, label: "Paris (fallback)" };
const MAX_ARCS = 80;

// Calibration for bytes/s -> "thickness" / brightness.
// 1 KB/s already noticeable, 1 MB/s = full intensity boost.
const RATE_LOW = 1_000;
const RATE_HIGH = 1_000_000;

interface RemoteHit {
  id: string;
  lat: number;
  lon: number;
  proto: string;
  freshness: number;
  rate: number; // 0..1 normalised
  intensity: number; // combined 0..1
  reverse: boolean;
  flashing: boolean;
  seed: number;
}

interface Props {
  autoRotate?: boolean;
}

export default function GlobeScene({ autoRotate = true }: Props) {
  const connections = useConnectionsStore((s) => s.connections);
  const selectedId = useSelectionStore((s) => s.selectedId);
  const hoveredId = useSelectionStore((s) => s.hoveredId);
  const select = useSelectionStore((s) => s.select);
  const hover = useSelectionStore((s) => s.hover);
  const [self, setSelf] = useState<{
    lat: number;
    lon: number;
    label: string;
  } | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const resp = await api.self();
        if (!alive) return;
        if (resp.geo?.lat != null && resp.geo?.lon != null) {
          setSelf({
            lat: resp.geo.lat,
            lon: resp.geo.lon,
            label:
              [resp.geo.city, resp.geo.country].filter(Boolean).join(", ") ||
              resp.ip ||
              "you",
          });
          return;
        }
      } catch {
        /* ignore */
      }
      if (alive) setSelf(FALLBACK_USER);
    })();
    return () => {
      alive = false;
    };
  }, []);

  const remotes = useMemo<RemoteHit[]>(() => {
    if (!self) return [];
    const now = Date.now();
    const out: RemoteHit[] = [];
    let seedCounter = 0;
    for (const c of connections.values()) {
      const g: GeoLookup | null = c.remote_geo;
      if (!g || g.lat == null || g.lon == null) continue;
      const age = now - c.last_seen_ms;
      if (age > ACTIVITY_WINDOW_MS) continue;
      const freshness = Math.max(0.18, 1 - age / ACTIVITY_WINDOW_MS);
      // Normalise bytes_per_sec on a log scale.
      const rate = normaliseRate(c.bytes_per_sec);
      // Combined intensity: freshness gates everything, rate boosts.
      const intensity = Math.min(1, 0.4 * freshness + 0.6 * rate);
      const flashing = c.flash_until_ms > now;
      out.push({
        id: c.id,
        lat: g.lat,
        lon: g.lon,
        proto: c.proto,
        freshness,
        rate,
        intensity: Math.max(intensity, flashing ? 1 : 0),
        reverse: c.direction === "inbound",
        flashing,
        seed: seedCounter++,
      });
    }
    out.sort((a, b) => b.intensity - a.intensity);
    return out.slice(0, MAX_ARCS);
  }, [connections, self]);

  const userPos = useMemo(
    () =>
      self
        ? latLonToVec3(self.lat, self.lon, EARTH_RADIUS * 1.005)
        : new THREE.Vector3(0, EARTH_RADIUS * 1.005, 0),
    [self],
  );

  return (
    <Canvas
      camera={{ position: [0, 1.4, 4.6], fov: 42 }}
      gl={{ antialias: true, alpha: true, powerPreference: "high-performance" }}
      style={{ background: "transparent" }}
      dpr={[1, 2]}
    >
      <color attach="background" args={["#02030a"]} />
      <ambientLight intensity={0.55} />
      <directionalLight position={[6, 4, 7]} intensity={1.1} color="#ffffff" />
      <pointLight position={[-5, -3, -4]} intensity={0.4} color="#3a7bff" />
      <Stars
        radius={120}
        depth={50}
        count={5000}
        factor={3}
        saturation={0}
        fade
        speed={0.3}
      />

      <Suspense fallback={null}>
        <Earth />
      </Suspense>

      {self && (
        <Hotspot position={userPos} color="#39ff8a" size={0.022} intensity={1.2} />
      )}

      {remotes.map((r) => {
        const pos = latLonToVec3(r.lat, r.lon, EARTH_RADIUS * 1.005);
        const baseColor = r.flashing ? "#ff4d6d" : protoColor(r.proto);
        const isSelected = selectedId === r.id;
        const isHovered = hoveredId === r.id;
        return (
          <group key={r.id}>
            <Hotspot
              position={pos}
              color={baseColor}
              intensity={r.intensity}
              size={0.012 + r.rate * 0.008}
              flash={r.flashing}
              selected={isSelected}
              hovered={isHovered}
              onClick={() =>
                select(selectedId === r.id ? null : r.id)
              }
              onPointerOver={() => hover(r.id)}
              onPointerOut={() => hover(null)}
            />
            <Arc
              a={userPos}
              b={pos}
              proto={r.proto}
              intensity={r.intensity}
              rate={r.rate}
              reverse={r.reverse}
              flash={r.flashing}
              seed={r.seed}
            />
          </group>
        );
      })}

      <OrbitControls
        enablePan={false}
        enableZoom
        zoomSpeed={0.7}
        rotateSpeed={0.45}
        minDistance={1.7}
        maxDistance={14}
        autoRotate={autoRotate}
        autoRotateSpeed={0.18}
      />

      <EffectComposer multisampling={0}>
        <Bloom
          intensity={0.7}
          luminanceThreshold={0.22}
          luminanceSmoothing={0.6}
          mipmapBlur
        />
      </EffectComposer>
    </Canvas>
  );
}

/** Map bytes/s to a 0..1 visual weight on a log curve. */
function normaliseRate(bps: number): number {
  if (!Number.isFinite(bps) || bps <= 0) return 0;
  if (bps <= RATE_LOW) return 0;
  const t = (Math.log10(bps) - Math.log10(RATE_LOW)) /
    (Math.log10(RATE_HIGH) - Math.log10(RATE_LOW));
  return Math.max(0, Math.min(1, t));
}

function protoColor(proto: string): string {
  switch (proto) {
    case "tcp":
      return "#00e5ff";
    case "udp":
      return "#a855f7";
    case "icmp":
      return "#ff3ea5";
    default:
      return "#39ff8a";
  }
}
