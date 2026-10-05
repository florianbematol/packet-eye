// Full-screen glass container for the non-live views (Apps, History,
// Firewall). The globe keeps rendering behind it.

import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface Props {
  title: string;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}

export default function ViewShell({ title, icon, actions, children, className }: Props) {
  return (
    <section
      className={cn(
        "absolute z-20 left-5 right-5 top-20 bottom-5 glass-strong flex flex-col overflow-hidden",
        className,
      )}
    >
      <header className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-border/60">
        <h2 className="mono text-[11px] uppercase tracking-[0.25em] text-primary flex items-center gap-2">
          {icon}
          {title}
        </h2>
        <div className="flex items-center gap-2">{actions}</div>
      </header>
      <div className="flex-1 min-h-0 overflow-auto">{children}</div>
    </section>
  );
}

/** Small segmented control (pill buttons). */
export function Segmented<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
}) {
  return (
    <div className="inline-flex rounded-md border border-border/60 bg-secondary/30 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          className={cn(
            "mono text-[10px] uppercase tracking-wider px-2.5 py-1 rounded-[5px] transition-colors",
            value === o.value
              ? "bg-primary/20 text-primary"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
