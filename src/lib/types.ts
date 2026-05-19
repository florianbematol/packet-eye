// Domain types shared with the Rust agent.

export type Protocol = "tcp" | "udp" | "icmp" | "other";
export type Direction = "inbound" | "outbound" | "unknown";

export interface GeoLookup {
  country?: string | null;
  country_iso?: string | null;
  city?: string | null;
  lat?: number | null;
  lon?: number | null;
  asn?: number | null;
  asn_org?: string | null;
}

export interface SideInfo {
  geo?: GeoLookup | null;
  hostname?: string | null;
}

export interface EnrichedPacket {
  ts_ms: number;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  proto: Protocol;
  len: number;
  tcp_flags: number;
  direction: Direction;
  src: SideInfo;
  dst: SideInfo;
  process?: string | null;
  pid?: number | null;
  /** Hex string of the first ≤256 bytes of the raw frame, if captured. */
  payload_hex?: string | null;
}

export interface DeviceInfo {
  name: string;
  description: string | null;
  addresses: string[];
  flags: number;
  is_loopback: boolean;
}

export interface CaptureFilter {
  include_lan?: boolean;
  include_localhost?: boolean;
  include_broadcast?: boolean;
  custom?: string | null;
}

export interface StatsTick {
  ts_ms: number;
  packets_per_sec: number;
  bytes_per_sec: number;
  active_connections: number;
  total_packets: number;
  total_bytes: number;
}

export interface StatusResp {
  running: boolean;
}

export interface SelfResp {
  ip: string | null;
  geo: GeoLookup | null;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Alert {
  ts_ms: number;
  severity: Severity;
  rule: string;
  message: string;
  remote_ip?: string | null;
  context?: Record<string, unknown> | null;
}

export interface AlertRules {
  enabled: boolean;
  threat_list: boolean;
  burst: boolean;
  burst_threshold_pps: number;
  suspicious_port: boolean;
  suspicious_ports: number[];
  new_process_external: boolean;
  new_asn: boolean;
  new_country: boolean;
}

export interface ThreatStats {
  total_ranges: number;
}

export interface DbFileInfo {
  filename: string;
  path: string | null;
  exists: boolean;
  size_bytes: number;
  modified_iso: string | null;
  source: "override" | "cwd" | "exe" | "missing";
}

export interface GeoIpInfo {
  city: DbFileInfo;
  asn: DbFileInfo;
  override_dir: string;
}

export interface GeoIpUpdateResp {
  ok: boolean;
  elapsed_ms: number;
  city: DbFileInfo;
  asn: DbFileInfo;
}

export type WsMessage =
  | { type: "packets"; data: EnrichedPacket[] }
  | { type: "stats"; data: StatsTick }
  | { type: "alerts"; data: Alert[] };
