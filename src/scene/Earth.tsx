// Realistic Earth: Natural Earth III 16K daymap + bump map + water mask
// + nightlights + 8K cloud layer floating slightly above the surface.
//
// Day texture is 16200×8100 (Natural Earth III, public domain). The
// water mask (white on oceans, black on land) drives the specularity
// so only oceans glint. The bump map gives mountains visible relief
// at zoom-in. A separate cloud sphere rotates *very* slowly above the
// surface to add depth. City lights are baked into the emissive map.
//
// Sources: http://www.shadedrelief.com/natural3/ (public domain).

import { useMemo, useRef } from "react";
import { useFrame, useLoader } from "@react-three/fiber";
import * as THREE from "three";

interface Props {
  radius?: number;
}

export const EARTH_RADIUS = 1.5;

const dayUrl = "/textures/earth-day.jpg";
const bumpUrl = "/textures/earth-bump.jpg";
const specularUrl = "/textures/earth-specular.png";
const lightsUrl = "/textures/earth-lights.jpg";
const cloudsUrl = "/textures/earth-clouds.jpg";

export default function Earth({ radius = EARTH_RADIUS }: Props) {
  const cloudsRef = useRef<THREE.Mesh>(null);

  const [dayMap, bumpMap, specularMap, lightsMap, cloudsMap] = useLoader(
    THREE.TextureLoader,
    [dayUrl, bumpUrl, specularUrl, lightsUrl, cloudsUrl],
  ) as THREE.Texture[];

  useMemo(() => {
    [dayMap, lightsMap].forEach((t) => {
      if (t) t.colorSpace = THREE.SRGBColorSpace;
    });
    [dayMap, bumpMap, specularMap, lightsMap, cloudsMap].forEach((t) => {
      if (t) {
        t.anisotropy = 16;
        t.minFilter = THREE.LinearMipmapLinearFilter;
        t.magFilter = THREE.LinearFilter;
        t.generateMipmaps = true;
        t.needsUpdate = true;
      }
    });
  }, [dayMap, bumpMap, specularMap, lightsMap, cloudsMap]);

  // Slowly rotate the cloud layer for atmospheric realism.
  useFrame((_, dt) => {
    if (cloudsRef.current) {
      cloudsRef.current.rotation.y += dt * 0.005;
    }
  });

  return (
    <group>
      {/* Solid Earth */}
      <mesh>
        <sphereGeometry args={[radius, 256, 256]} />
        <meshPhongMaterial
          map={dayMap}
          bumpMap={bumpMap}
          bumpScale={0.04}
          specularMap={specularMap}
          specular={new THREE.Color(0x2a4a80)}
          shininess={22}
          emissiveMap={lightsMap}
          emissive={new THREE.Color(0xffd28a)}
          emissiveIntensity={0.5}
        />
      </mesh>

      {/* Cloud layer — slightly larger sphere with the cloud map as alpha */}
      <mesh ref={cloudsRef} scale={[1.005, 1.005, 1.005]}>
        <sphereGeometry args={[radius, 128, 128]} />
        <meshPhongMaterial
          map={cloudsMap}
          alphaMap={cloudsMap}
          transparent
          opacity={0.85}
          depthWrite={false}
          color={new THREE.Color(0xffffff)}
        />
      </mesh>

      {/* Inner atmosphere (tight cyan rim) */}
      <mesh scale={[1.018, 1.018, 1.018]}>
        <sphereGeometry args={[radius, 64, 64]} />
        <shaderMaterial
          transparent
          depthWrite={false}
          side={THREE.BackSide}
          uniforms={{
            uColor: { value: new THREE.Color(0x4ad8ff) },
            uIntensity: { value: 0.5 },
            uPower: { value: 3.4 },
          }}
          vertexShader={atmosphereVertex}
          fragmentShader={atmosphereFragment}
        />
      </mesh>

      {/* Outer faint blue glow */}
      <mesh scale={[1.07, 1.07, 1.07]}>
        <sphereGeometry args={[radius, 48, 48]} />
        <shaderMaterial
          transparent
          depthWrite={false}
          side={THREE.BackSide}
          uniforms={{
            uColor: { value: new THREE.Color(0x2a6cff) },
            uIntensity: { value: 0.2 },
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
