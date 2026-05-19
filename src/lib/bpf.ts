// Compute the BPF expression that the agent will apply, mirroring the
// logic in agent/src/capture/bpf.rs::to_bpf so the UI can show the user
// exactly what filter is in effect.

import type { CaptureFilter } from "@/lib/types";

export function captureFilterToBpf(f: CaptureFilter): string {
  const clauses: string[] = [];

  if (!f.include_localhost) {
    clauses.push(
      "not (ip and net 127.0.0.0/8) and not (ip6 and host ::1)",
    );
  }

  if (!f.include_lan) {
    clauses.push(
      "not (ip and net 10.0.0.0/8) and " +
        "not (ip and net 172.16.0.0/12) and " +
        "not (ip and net 192.168.0.0/16) and " +
        "not (ip and net 169.254.0.0/16) and " +
        "not (ip6 and net fe80::/10) and " +
        "not (ip6 and net fc00::/7)",
    );
  }

  if (!f.include_broadcast) {
    clauses.push(
      "not (ip and host 255.255.255.255) and " +
        "not (ip and net 224.0.0.0/4) and " +
        "not (ip6 and net ff00::/8)",
    );
  }

  if (f.custom) {
    const t = f.custom.trim();
    if (t) clauses.push(`(${t})`);
  }

  return clauses.join(" and ");
}
