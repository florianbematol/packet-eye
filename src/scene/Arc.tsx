// Connection arc rendered as a thin screen-space line.
//
// We use `Line` from @react-three/drei which delegates to three's
// `Line2` (Lines2 from examples/webgl_lines_fat). The width is given
// in *pixels*, so it stays consistent regardless of zoom level.
//
// Visual: a faint base trail (whole curve, 30% opacity) + a brighter
// segmented trail behind a bright animated comet head. Bloom takes
// care of the glow.

import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import { Line } from "@react-three/drei";
import * as THREE from "three";
import { buildArc } from "@/lib/geo";

const PROTO_COLORS: Record<string, string> = {
  tcp: "#00e5ff",
  udp: "#a855f7",
  icmp: "#ff3ea5",
  other: "#39ff8a",
};
const FLASH_COLOR = "#ff4d6d";

interface Props {
  a: THREE.Vector3;
  b: THREE.Vector3;
  proto?: string;
  intensity?: number;
  rate?: number;
  reverse?: boolean;
  flash?: boolean;
  seed?: number;
}

const SEGMENTS = 80;
// Length (as a fraction of the curve) of the bright trail behind the head.
const TRAIL_FRACTION = 0.22;
// Constant on-screen pixel widths.
const BASE_WIDTH_PX = 1.0;
const TRAIL_WIDTH_PX = 2.4;
// Constant on-screen size for the comet head.
const REFERENCE_DISTANCE = 4;
const HEAD_BASE_SIZE = 0.012;

export default function Arc({
  a,
  b,
  proto = "tcp",
  intensity = 1,
  rate = 0,
  reverse = false,
  flash = false,
  seed = 0,
}: Props) {
  const colorHex = flash ? FLASH_COLOR : PROTO_COLORS[proto] ?? PROTO_COLORS.other;
  const color = useMemo(() => new THREE.Color(colorHex), [colorHex]);

  const animDurationMs = flash ? 1100 : 1900;

  // Pre-built points for the curve (recomputed only when endpoints change).
  const points = useMemo(
    () => buildArc(a, b, SEGMENTS, 0.45),
    [a, b],
  );
  const curve = useMemo(
    () => new THREE.CatmullRomCurve3(points, false, "centripetal"),
    [points],
  );

  // The "trail" line is a sub-array of points. We rebuild it in-place
  // each frame by mutating the existing geometry positions to avoid
  // allocations on the hot path.
  const trailRef = useRef<THREE.Object3D>(null);
  const headRef = useRef<THREE.Mesh>(null);
  const tStartRef = useRef(performance.now() - seed * 600);

  // Initial trail points (shape is preserved across frames; only their
  // values are mutated below).
  const trailPoints = useMemo(() => {
    const n = Math.max(2, Math.round(SEGMENTS * TRAIL_FRACTION));
    return new Array(n).fill(0).map(() => new THREE.Vector3());
  }, []);

  useFrame((state) => {
    const elapsed = performance.now() - tStartRef.current;
    const t = (elapsed % animDurationMs) / animDurationMs;
    const u = reverse ? 1 - t : t;
    const headU = THREE.MathUtils.clamp(u, 0.001, 0.999);

    // Position the comet head along the curve.
    if (headRef.current) {
      const p = curve.getPointAt(headU);
      headRef.current.position.copy(p);
      // Constant screen size.
      const d = state.camera.position.distanceTo(p);
      const factor = d / REFERENCE_DISTANCE;
      headRef.current.scale.setScalar(factor);
    }

    // Rebuild the bright trail: from `headU - TRAIL_FRACTION` up to `headU`.
    const trail = trailRef.current as unknown as {
      geometry?: { setPositions: (p: number[]) => void };
    };
    if (trail?.geometry?.setPositions) {
      const n = trailPoints.length;
      const start = headU - TRAIL_FRACTION;
      const flat: number[] = new Array(n * 3);
      for (let i = 0; i < n; i++) {
        const ui = start + (TRAIL_FRACTION * i) / (n - 1);
        const clamped = THREE.MathUtils.clamp(ui, 0.0001, 0.9999);
        const p = curve.getPointAt(clamped);
        flat[i * 3 + 0] = p.x;
        flat[i * 3 + 1] = p.y;
        flat[i * 3 + 2] = p.z;
      }
      trail.geometry.setPositions(flat);
    }
  });

  // Slight per-arc width modulation by bandwidth.
  const baseWidth = BASE_WIDTH_PX + rate * 0.6;
  const trailWidth = TRAIL_WIDTH_PX + rate * 1.0;

  return (
    <group>
      {/* Base full-curve line, faint */}
      <Line
        points={points}
        color={color}
        lineWidth={baseWidth}
        transparent
        opacity={(0.18 + rate * 0.18) * intensity}
        depthWrite={false}
      />
      {/* Bright trail (mutated each frame) */}
      <Line
        ref={trailRef as unknown as React.Ref<never>}
        points={trailPoints}
        color={color}
        lineWidth={trailWidth}
        transparent
        opacity={Math.min(1, 0.85 * intensity)}
        depthWrite={false}
      />
      {/* Comet head */}
      <mesh ref={headRef}>
        <sphereGeometry args={[HEAD_BASE_SIZE, 12, 12]} />
        <meshBasicMaterial
          color={color}
          transparent
          opacity={Math.min(1, intensity)}
          depthWrite={false}
          toneMapped={false}
        />
      </mesh>
    </group>
  );
}
