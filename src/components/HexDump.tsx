// Wireshark-style hex dump component.
//
// Takes a hex-encoded string (lower or upper case) and renders it as a
// classic 16-bytes-per-line dump with offset, hex bytes and ASCII gutter.

import { useMemo } from "react";
import { cn } from "@/lib/utils";

interface Props {
  hex: string;
  /** Bytes per line. Default 16 (Wireshark default). */
  bytesPerRow?: number;
  className?: string;
}

interface ParsedRow {
  offset: number;
  bytes: number[];
  ascii: string;
}

function hexToBytes(hex: string): number[] {
  const clean = hex.replace(/\s+/g, "");
  const out: number[] = [];
  for (let i = 0; i + 1 < clean.length; i += 2) {
    const b = parseInt(clean.slice(i, i + 2), 16);
    if (!Number.isNaN(b)) out.push(b);
  }
  return out;
}

function byteToAscii(b: number): string {
  return b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
}

function pad2(n: number): string {
  return n.toString(16).padStart(2, "0");
}

function pad4(n: number): string {
  return n.toString(16).padStart(4, "0");
}

export default function HexDump({ hex, bytesPerRow = 16, className }: Props) {
  const rows = useMemo<ParsedRow[]>(() => {
    const bytes = hexToBytes(hex);
    const out: ParsedRow[] = [];
    for (let i = 0; i < bytes.length; i += bytesPerRow) {
      const slice = bytes.slice(i, i + bytesPerRow);
      out.push({
        offset: i,
        bytes: slice,
        ascii: slice.map(byteToAscii).join(""),
      });
    }
    return out;
  }, [hex, bytesPerRow]);

  if (rows.length === 0) {
    return (
      <div className={cn("text-[10px] text-muted-foreground/60 mono", className)}>
        empty
      </div>
    );
  }

  return (
    <pre
      className={cn(
        "mono text-[10px] leading-tight whitespace-pre overflow-x-auto",
        "text-foreground/85",
        className,
      )}
    >
      {rows.map((r) => (
        <div key={r.offset} className="flex gap-3">
          <span className="text-muted-foreground/60 select-none">
            {pad4(r.offset)}
          </span>
          <span className="text-primary/90">
            {r.bytes
              .map((b, i) => pad2(b) + (i === 7 ? "  " : " "))
              .join("")
              .trimEnd()
              .padEnd(bytesPerRow * 3 + 1, " ")}
          </span>
          <span className="text-foreground/70">{r.ascii}</span>
        </div>
      ))}
    </pre>
  );
}
