// A small, dependency-free draggable panel.
//
// Wrap any UI element to make it floatable: the user grabs the drag
// handle (left of header, indicated by the GripVertical icon) and the
// panel moves with the cursor. Position (relative to the viewport)
// is persisted in localStorage so it survives reloads.
//
// The panel keeps itself inside the visible viewport via a small clamp
// margin. It's positioned with translate3d so we don't trigger layout.

import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { GripVertical } from "lucide-react";
import { cn } from "@/lib/utils";

interface Position {
  x: number;
  y: number;
}

interface Props {
  /** localStorage key under which the position is persisted. */
  storageKey: string;
  /** Initial position (relative to top-left of the viewport). */
  initial: Position;
  /** Optional fixed pixel size. If omitted, the panel sizes to its content. */
  width?: number | string;
  height?: number | string;
  className?: string;
  children: React.ReactNode;
  /** Margin from viewport edges to clamp against. Default 8 px. */
  edgeMargin?: number;
  /** ZIndex; defaults to 30 so it floats above the regular overlays. */
  zIndex?: number;
}

function loadPos(key: string, fallback: Position): Position {
  if (typeof localStorage === "undefined") return fallback;
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    const p = JSON.parse(raw) as Position;
    if (typeof p?.x === "number" && typeof p?.y === "number") return p;
  } catch {
    /* ignore */
  }
  return fallback;
}

export default function DraggablePanel({
  storageKey,
  initial,
  width,
  height,
  className,
  children,
  edgeMargin = 8,
  zIndex = 30,
}: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<Position>(() => loadPos(storageKey, initial));
  const dragRef = useRef<{
    pointerId: number;
    startX: number;
    startY: number;
    posX: number;
    posY: number;
  } | null>(null);
  const [dragging, setDragging] = useState(false);

  const clamp = useCallback(
    (p: Position): Position => {
      const el = ref.current;
      if (!el || typeof window === "undefined") return p;
      const w = el.offsetWidth || 0;
      const h = el.offsetHeight || 0;
      const maxX = Math.max(edgeMargin, window.innerWidth - w - edgeMargin);
      const maxY = Math.max(edgeMargin, window.innerHeight - h - edgeMargin);
      return {
        x: Math.min(maxX, Math.max(edgeMargin, p.x)),
        y: Math.min(maxY, Math.max(edgeMargin, p.y)),
      };
    },
    [edgeMargin],
  );

  // Re-clamp when window resizes so the panel doesn't slip off-screen.
  useEffect(() => {
    const onResize = () => setPos((p) => clamp(p));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [clamp]);

  // First-mount clamp once the element has its real size.
  useLayoutEffect(() => {
    setPos((p) => clamp(p));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onPointerDown = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      e.preventDefault();
      (e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId);
      dragRef.current = {
        pointerId: e.pointerId,
        startX: e.clientX,
        startY: e.clientY,
        posX: pos.x,
        posY: pos.y,
      };
      setDragging(true);
    },
    [pos.x, pos.y],
  );

  useEffect(() => {
    if (!dragging) return;
    const onMove = (e: PointerEvent) => {
      const d = dragRef.current;
      if (!d) return;
      const next = clamp({
        x: d.posX + (e.clientX - d.startX),
        y: d.posY + (e.clientY - d.startY),
      });
      setPos(next);
    };
    const onUp = () => {
      setDragging(false);
      dragRef.current = null;
      try {
        localStorage.setItem(storageKey, JSON.stringify(pos));
      } catch {
        /* ignore */
      }
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onUp);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onUp);
    };
  }, [dragging, clamp, storageKey, pos]);

  // Persist on settled position changes (e.g. resize-clamp).
  useEffect(() => {
    if (dragging || typeof localStorage === "undefined") return;
    try {
      localStorage.setItem(storageKey, JSON.stringify(pos));
    } catch {
      /* ignore */
    }
  }, [pos, dragging, storageKey]);

  return (
    <div
      ref={ref}
      className={cn("absolute select-none", className)}
      style={{
        left: pos.x,
        top: pos.y,
        width,
        height,
        zIndex,
        cursor: dragging ? "grabbing" : undefined,
      }}
    >
      {/* Drag handle bar — grab here to move the panel. */}
      <div
        onPointerDown={onPointerDown}
        className={cn(
          "absolute top-0 left-0 right-0 h-5 z-10",
          "flex items-center pointer-events-auto",
          "rounded-t-[var(--radius)]",
          dragging
            ? "bg-primary/15 cursor-grabbing"
            : "bg-transparent hover:bg-primary/10 cursor-grab",
          "transition-colors",
        )}
        title="Drag to move"
      >
        <GripVertical
          className={cn(
            "h-3 w-3 ml-1.5",
            dragging ? "text-primary" : "text-muted-foreground/60",
          )}
        />
      </div>
      <div className="h-full w-full">{children}</div>
    </div>
  );
}
