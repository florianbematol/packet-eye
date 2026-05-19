// Right-side resizable panel hosting the connections table.
//
// A vertical handle on the LEFT edge lets the user drag to resize.
// Width is persisted in localStorage so it survives reloads.

import { useEffect, useMemo, useState } from "react";
import { useResize } from "@/lib/useResize";

interface Props {
  storageKey: string;
  initial: number;
  min?: number;
  max?: number;
  /** Distance from the right viewport edge (default 20px = `right-5`). */
  rightInset?: number;
  /** Top offset (default 80px = `top-20`). */
  top?: number;
  /** Bottom offset (default 20px = `bottom-5`). */
  bottom?: number;
  className?: string;
  children: React.ReactNode;
}

export default function ResizableRightPanel({
  storageKey,
  initial,
  min = 360,
  max,
  rightInset = 20,
  top = 80,
  bottom = 20,
  className = "",
  children,
}: Props) {
  // Compute a sensible viewport-aware max if none given.
  const [vw, setVw] = useState<number>(
    typeof window !== "undefined" ? window.innerWidth : 1440,
  );
  useEffect(() => {
    const onResize = () => setVw(window.innerWidth);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const computedMax = useMemo(
    () => max ?? Math.max(min, vw - rightInset - 24),
    [max, min, vw, rightInset],
  );

  const { size, onPointerDown, dragging } = useResize({
    initial,
    min,
    max: computedMax,
    direction: "left",
    storageKey,
  });

  return (
    <aside
      className={`absolute z-20 ${className}`}
      style={{
        right: rightInset,
        top,
        bottom,
        width: size,
      }}
    >
      {/* Drag handle on the left edge — wider hit area, visible bar */}
      <div
        onPointerDown={onPointerDown}
        className={`absolute left-0 top-0 bottom-0 w-2.5 -ml-2.5 cursor-ew-resize group select-none touch-none ${
          dragging ? "z-30" : ""
        }`}
        title="Drag to resize"
      >
        <div
          className={`h-full w-0.5 mx-auto rounded-sm transition-all ${
            dragging
              ? "bg-primary shadow-[0_0_8px_rgba(0,229,255,0.6)]"
              : "bg-border/40 group-hover:bg-primary/80 group-hover:w-1"
          }`}
        />
      </div>
      <div className="h-full w-full">{children}</div>
    </aside>
  );
}
