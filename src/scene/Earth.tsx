// Realistic Earth: NASA Blue Marble day texture + normal + specular maps,
// wrapped in a multi-layer atmospheric Fresnel glow.
//
// The Earth mesh is intentionally STATIC: we don't rotate the geometry
// itself, otherwise the markers/arcs (placed in world space at geographic
// lat/lon) would slide off the surface. To create a "rotating planet"
// feel we instead let the OrbitControls autoRotate the whole camera —
// this rotates the Earth AND its markers together.
//
// Source of textures: https://threejs.org/examples/textures/planets/
// (NASA imagery, public domain).

import { useMemo } from "react";
import { useLoader } from "@react-three/fiber";
import * as THREE from "three";

interface Props {
  radius?: number;
}

export const EARTH_RADIUS = 1.5;

const dayUrl = "/textures/earth-day.jpg";
const normalUrl = "/textures/earth-normal.jpg";
const specularUrl = "/textures/earth-specular.jpg";
const lightsUrl = "/textures/earth-lights.jpg";

export default function Earth({ radius = EARTH_RADIUS }: Props) {
  const [dayMap, normalMap, specularMap, lightsMap] = useLoader(
    THREE.TextureLoader,
    [dayUrl, normalUrl, specularUrl, lightsUrl],
  ) as THREE.Texture[];

  useMemo(() => {
    [dayMap, lightsMap].forEach((t) => {
      if (t) t.colorSpace = THREE.SRGBColorSpace;
    });
    [dayMap, normalMap, specularMap, lightsMap].forEach((t) => {
      if (t) {
        t.anisotropy = 16;
        t.minFilter = THREE.LinearMipmapLinearFilter;
        t.magFilter = THREE.LinearFilter;
        t.generateMipmaps = true;
        t.needsUpdate = true;
      }
    });
  }, [dayMap, normalMap, specularMap, lightsMap]);

  // The texture is mapped so that lon=0 (Greenwich) lands at +Z. Our
  // latLonToVec3 uses the same convention, so we don't need any rotation
  // offset on the mesh itself.
  return (
    <group>
      <mesh>
        <sphereGeometry args={[radius, 256, 256]} />
        <meshPhongMaterial
          map={dayMap}
          normalMap={normalMap}
          normalScale={new THREE.Vector2(0.6, 0.6)}
          specularMap={specularMap}
          specular={new THREE.Color(0x1a3560)}
          shininess={16}
          emissiveMap={lightsMap}
          emissive={new THREE.Color(0xffd28a)}
          emissiveIntensity={0.45}
        />
      </mesh>

      {/* Single thin atmospheric rim (kept subtle) */}
      <mesh scale={[1.015, 1.015, 1.015]}>
        <sphereGeometry args={[radius, 64, 64]} />
        <shaderMaterial
          transparent
          depthWrite={false}
          side={THREE.BackSide}
          uniforms={{
            uColor: { value: new THREE.Color(0x4ad8ff) },
            uIntensity: { value: 0.35 },
            uPower: { value: 3.6 },
          }}
          vertexShader={atmosphereVertex}
          fragmentShader={atmosphereFragment}
        />
      </mesh>

      {/* Outer faint blue glow */}
      <mesh scale={[1.06, 1.06, 1.06]}>
        <sphereGeometry args={[radius, 48, 48]} />
        <shaderMaterial
          transparent
          depthWrite={false}
          side={THREE.BackSide}
          uniforms={{
            uColor: { value: new THREE.Color(0x2a6cff) },
            uIntensity: { value: 0.15 },
            uPower: { value: 1.8 },
          }}
          vertexShader={atmosphereVertex}
          fragmentShader={atmosphereFragment}
        />
      </mesh>
    </group>
  );
}

const atmosphereVertex = /* glsl */ `
  varying vec3 vNormal;
  varying vec3 vViewDir;
  void main() {
    vec4 wp = modelMatrix * vec4(position, 1.0);
    vNormal = normalize(normalMatrix * normal);
    vViewDir = normalize(cameraPosition - wp.xyz);
    gl_Position = projectionMatrix * viewMatrix * wp;
  }
`;

const atmosphereFragment = /* glsl */ `
  uniform vec3 uColor;
  uniform float uIntensity;
  uniform float uPower;
  varying vec3 vNormal;
  varying vec3 vViewDir;
  void main() {
    float fres = pow(
      1.0 - max(dot(normalize(vNormal), normalize(vViewDir)), 0.0),
      uPower
    );
    gl_FragColor = vec4(uColor, fres * uIntensity);
  }
`;
