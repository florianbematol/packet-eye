# The 3D globe

The dark blue centerpiece is a real Earth (NASA Blue Marble texture +
specular + normal + city lights night map) wrapped in a thin Fresnel
atmosphere. It does **not** rotate by itself — the camera does, when
auto-rotate is on. This way the markers and arcs stay locked to their
geographic coordinates instead of sliding under a spinning sphere.

## Markers

| Symbol | Colour | Meaning |
|---|---|---|
| Steady dot + thin ring | **Green `#39ff8a`** | You — placed at the geo of your public IP (resolved by `/api/self`). |
| Steady dot + thin ring | **Cyan `#00e5ff`** | A remote endpoint reached via TCP. |
| Steady dot + thin ring | **Violet `#a855f7`** | A remote endpoint reached via UDP. |
| Steady dot + thin ring | **Pink `#ff3ea5`** | ICMP. |
| Steady dot + thin ring | **Green `#39ff8a`** | Other (non-TCP/UDP/ICMP). |
| Pulsing **red** outer ring | Crimson `#ff4d6d` | This endpoint just triggered an alert. The flash lasts 3–8 s depending on severity. |
| White outer ring | White | Selected (you clicked it or its row in the table). |

Markers keep a (near-)constant pixel size at any zoom level — they
shrink in world-space proportionally to the camera distance, so they
never become disc-of-doom when you zoom in.

## Arcs

Each active connection draws an arc between you and the remote
endpoint. The line itself is thin and faint; what catches the eye is
a moving **comet** that travels along the curve, leaving a brighter
trail behind it.

- The comet **travels in the direction of the data**: outbound arcs go
  from you → them, inbound arcs go from them → you. (When direction
  is `unknown`, we default to outbound.)
- The arc's thickness scales **logarithmically with throughput**.
  A 100 KB/s flow is visibly chunkier than a 1 KB/s ping; a 10 MB/s
  download is conspicuously thick.
- Arcs **fade** within 30 s of the connection's last activity, then
  disappear.
- During an alert flash, the comet turns crimson and the animation
  speeds up.

## Camera controls

The globe uses
[`OrbitControls`](https://threejs.org/docs/#examples/en/controls/OrbitControls)
from drei.

| Action | Mouse | Touchpad |
|---|---|---|
| Rotate | Left-click + drag | Two-finger drag |
| Zoom | Scroll wheel | Pinch / two-finger scroll |
| Pan | Disabled (we want the Earth centred) | — |

Auto-rotation can be toggled with the Play/Pause button in the header.

## What gets drawn vs. what's tracked

The scene caps active arcs at **80 hits**, sorted by intensity (a mix
of recency + bandwidth). The connections table on the right has its
own cap at 200 rows. Both buffers are independent of the global
`recentPackets` ring buffer (4096 packets) used by the inspector.

## Performance notes

- Arc lines use drei's `Line` (Lines2 under the hood) → constant
  pixel-width regardless of zoom, no geometry rebuild on camera move.
- The Earth sphere is 256-segment subdivided so the silhouette stays
  smooth at extreme zoom-in.
- Bloom is on (intensity 0.7, threshold 0.22) which boosts the
  saturated colours nicely without melting the globe.
- Texture anisotropy is 16 ⇒ no shimmering at glancing angles.

If you want to see what's behind a marker, click it — see
[Inspecting connections](inspect.md).
