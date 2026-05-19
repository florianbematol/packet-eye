// Minimalist hotspot marker.
//
// Visual: a single bright disc + a slowly pulsing thin ring.
// No additive halos, no flash rings stacked on top of each other.
// The bloom postprocess provides the soft glow.
//
// Apparent size: the marker keeps a (near-)constant pixel size at any
// zoom level. We achieve this by scaling proportionally to the camera
// distance, so as the user zooms in the world-space size shrinks in
// lockstep and the screen-space size stays put.

import { useMemo, useRef } from "react";
import { useFrame, type ThreeEvent } from "@react-three/fiber";
import * as THREE from "three";

interface Props {
  position: THREE.Vector3;
  color?: string;
  /** Base size at the reference camera distance. */
  size?: number;
  pulse?: boolean;
  intensity?: number;
  flash?: boolean;
  selected?: boolean;
  hovered?: boolean;
  onClick?: (e: ThreeEvent<MouseEvent>) => void;
  onPointerOver?: (e: ThreeEvent<PointerEvent>) => void;
  onPointerOut?: (e: ThreeEvent<PointerEvent>) => void;
}

// At which camera distance the marker is rendered at 100%.
// Scene zoom range now: ~1.7 (very close) → ~14 (far). Anchor at a
// comfortable mid-range value so the marker keeps a sensible apparent
// size at default zoom.
const REFERENCE_DISTANCE = 4;
const FLASH_COLOR = "#ff4d6d";
const SELECT_COLOR = "#ffffff";

export default function Hotspot({
  position,
  color = "#00e5ff",
  size = 0.018,
  pulse = true,
  intensity = 1,
  flash = false,
  selected = false,
  hovered = false,
  onClick,
  onPointerOver,
  onPointerOut,
}: Props) {
  const baseColor = useMemo(() => new THREE.Color(color), [color]);
  const flashColor = useMemo(() => new THREE.Color(FLASH_COLOR), []);
  const selectColor = useMemo(() => new THREE.Color(SELECT_COLOR), []);

  const groupRef = useRef<THREE.Group>(null);
  const ringRef = useRef<THREE.Mesh>(null);

  // Orient the local +Z axis along the surface normal so any flat
  // children (rings) lay tangent to the sphere.
  const orientation = useMemo(() => {
    const q = new THREE.Quaternion();
    q.setFromUnitVectors(new THREE.Vector3(0, 0, 1), position.clone().normalize());
    return q;
  }, [position]);

  useFrame((state) => {
    // Constant-screen-size scaling.
    if (groupRef.current) {
      const d = state.camera.position.distanceTo(position);
      const factor = d / REFERENCE_DISTANCE;
      const boost = selected ? 1.45 : hovered ? 1.2 : 1;
      groupRef.current.scale.setScalar(factor * boost);
    }
    // Subtle ring pulsation (radius only, fixed thickness, no opacity loop).
    if (pulse && ringRef.current) {
      const t = state.clock.elapsedTime;
      const s = 1 + 0.1 * Math.sin(t * 2 + (position.x + position.z) * 5);
      ringRef.current.scale.setScalar(s);
    }
  });

  const handleClick = (e: ThreeEvent<MouseEvent>) => {
    if (!onClick) return;
    e.stopPropagation();
    onClick(e);
  };
  const handleOver = (e: ThreeEvent<PointerEvent>) => {
    if (onClick) document.body.style.cursor = "pointer";
    if (onPointerOver) {
      e.stopPropagation();
      onPointerOver(e);
    }
  };
  const handleOut = (e: ThreeEvent<PointerEvent>) => {
    if (onClick) document.body.style.cursor = "";
    if (onPointerOut) {
      e.stopPropagation();
      onPointerOut(e);
    }
  };

  const dotColor = selected ? selectColor : flash ? flashColor : baseColor;
  const ringColor = flash ? flashColor : baseColor;

  return (
    <group ref={groupRef} position={position} quaternion={orientation}>
      {/* Invisible hit target (larger than the dot for easy clicks). */}
      {onClick && (
        <mesh
          onClick={handleClick}
          onPointerOver={handleOver}
          onPointerOut={handleOut}
        >
          <sphereGeometry args={[size * 3, 12, 12]} />
          <meshBasicMaterial transparent opacity={0} depthWrite={false} />
        </mesh>
      )}

      {/* Single bright dot */}
      <mesh>
        <sphereGeometry args={[size, 20, 20]} />
        <meshBasicMaterial
          color={dotColor}
          toneMapped={false}
          transparent
          opacity={Math.min(1, intensity)}
        />
      </mesh>

      {/* Thin ring tangent to the sphere */}
      <mesh ref={ringRef}>
        <ringGeometry args={[size * 1.6, size * 1.85, 64]} />
        <meshBasicMaterial
          color={ringColor}
          transparent
          opacity={(selected ? 0.95 : 0.55) * intensity}
          side={THREE.DoubleSide}
          toneMapped={false}
          depthWrite={false}
        />
      </mesh>

      {/* Selection: extra outer ring, steady, white */}
      {selected && (
        <mesh>
          <ringGeometry args={[size * 2.2, size * 2.4, 64]} />
          <meshBasicMaterial
            color={selectColor}
            transparent
            opacity={0.9}
            side={THREE.DoubleSide}
            toneMapped={false}
            depthWrite={false}
          />
        </mesh>
      )}
    </group>
  );
}
