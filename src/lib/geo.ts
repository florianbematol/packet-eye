// Geometry helpers for placing markers / arcs on a unit sphere.

import * as THREE from "three";

/**
 * Convert latitude / longitude (degrees) to a 3D point on the surface of
 * a sphere centred at the origin.
 */
export function latLonToVec3(
  latDeg: number,
  lonDeg: number,
  radius = 1,
): THREE.Vector3 {
  const lat = THREE.MathUtils.degToRad(latDeg);
  const lon = THREE.MathUtils.degToRad(lonDeg);
  // Standard mapping: equator on the XZ plane, north pole on +Y.
  // We negate the Z so that lon=0 (Greenwich) faces the camera at z=+1.
  const x = radius * Math.cos(lat) * Math.cos(lon);
  const y = radius * Math.sin(lat);
  const z = -radius * Math.cos(lat) * Math.sin(lon);
  return new THREE.Vector3(x, y, z);
}

/**
 * Build a quadratic bezier arc that starts at `a`, ends at `b` and
 * bulges out away from the sphere centre. The bulge height is
 * proportional to the great-circle distance between the points.
 */
export function buildArc(
  a: THREE.Vector3,
  b: THREE.Vector3,
  segments = 64,
  liftFactor = 0.45,
): THREE.Vector3[] {
  // Midpoint then push outward.
  const mid = new THREE.Vector3().addVectors(a, b).multiplyScalar(0.5);
  // Estimate angular distance via dot product of unit vectors.
  const ua = a.clone().normalize();
  const ub = b.clone().normalize();
  const angle = Math.acos(THREE.MathUtils.clamp(ua.dot(ub), -1, 1));
  const lift = 1 + Math.min(0.7, angle * liftFactor);
  mid.normalize().multiplyScalar(a.length() * lift);

  const curve = new THREE.QuadraticBezierCurve3(a, mid, b);
  return curve.getPoints(segments);
}
