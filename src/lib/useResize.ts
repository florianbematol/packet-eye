// Drag handle utilities for resizing panels and table columns.

import { useCallback, useEffect, useRef, useState } from "react";

export interface UseResizeOptions {
  /** Initial size in pixels. */
  initial: number;
  /** Min size (px). */
  min?: number;
  /** Max size (px). */
  max?: number;
  /** "left" handle drags expand toward the left (panel width grows when
   *  cursor moves left), "right" handle expands toward the right.
   *  For columns we always use "right". */
  direction?: "left" | "right";
  /** Persist value under this localStorage key. */
  storageKey?: string;
}

interface UseResizeReturn {
  /** Current size in pixels. */
  size: number;
  /** onMouseDown / onPointerDown to attach to the handle. */
  onPointerDown: (e: React.PointerEvent) => void;
  /** True while the user is actively dragging. */
  dragging: boolean;
  /** Reset to the initial value. */
  reset: () => void;
}

export function useResize(opts: UseResizeOptions): UseResizeReturn {
  const {
    initial,
    min = 0,
    max = Number.POSITIVE_INFINITY,
    direction = "right",
    storageKey,
  } = opts;

  const loadInitial = useCallback(() => {
    if (storageKey && typeof localStorage !== "undefined") {
      const raw = localStorage.getItem(storageKey);
      const n = raw ? Number(raw) : NaN;
      if (Number.isFinite(n) && n >= min && n <= max) return n;
    }
    return initial;
  }, [storageKey, initial, min, max]);

  const [size, setSize] = useState<number>(loadInitial);
  const [dragging, setDragging] = useState(false);
  const startRef = useRef<{ x: number; size: number } | null>(null);

  const onPointerDown = useCallback(
    (e: React.PointerEvent) => {
      e.preventDefault();
      (e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId);
      startRef.current = { x: e.clientX, size };
      setDragging(true);
    },
    [size],
  );

  useEffect(() => {
    if (!dragging) return;

    const onMove = (e: PointerEvent) => {
      const start = startRef.current;
      if (!start) return;
      const delta = e.clientX - start.x;
      const next =
        direction === "left" ? start.size - delta : start.size + delta;
      const clamped = Math.max(min, Math.min(max, next));
      setSize(clamped);
    };
    const onUp = () => {
      setDragging(false);
      startRef.current = null;
      if (storageKey && typeof localStorage !== "undefined") {
        try {
          localStorage.setItem(storageKey, String(size));
        } catch {
          /* quota etc. */
        }
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
  }, [dragging, direction, min, max, size, storageKey]);

  // Persist on every settled size change too (covers reset / setSize externally).
  useEffect(() => {
    if (!storageKey || dragging || typeof localStorage === "undefined") return;
    try {
      localStorage.setItem(storageKey, String(size));
    } catch {
      /* ignore */
    }
  }, [size, dragging, storageKey]);

  const reset = useCallback(() => setSize(initial), [initial]);

  return { size, onPointerDown, dragging, reset };
}
