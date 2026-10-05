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
}

/** Where the domain name of a connection was learned from. */
export type DomainSource = "sni" | "http" | "dns";

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
  /** Domain of the remote endpoint (TLS SNI, HTTP Host or DNS answer). */
  domain?: string | null;
  domain_source?: DomainSource | null;
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

export interface ThreatListInfo {
  id: "spamhaus_drop" | "firehol_l1" | "tor_exit" | "custom";
  label: string;
  file: string;
  exists: boolean;
  size_bytes: number;
  modified_iso: string | null;
  entries: number;
  updatable: boolean;
}

export interface ThreatStats {
  total_ranges: number;
  dir: string;
  lists: ThreatListInfo[];
}

export interface ThreatUpdateResp {
  results: { file: string; ok: boolean; error: string | null; size_bytes: number }[];
  info: ThreatStats;
}

export interface RingInfo {
  frames: number;
  bytes: number;
  budget_bytes: number;
  evicted_frames: number;
  oldest_ts_ms: number | null;
  newest_ts_ms: number | null;
}

// ---- History ------------------------------------------------------------

export interface HistorySettings {
  enabled: boolean;
  retention_days: number;
}

export interface HistoryInfo {
  path: string;
  size_bytes: number;
  flow_rows: number;
  alert_rows: number;
  oldest_ts: number | null;
  newest_ts: number | null;
  settings: HistorySettings;
}

export interface TimelinePoint {
  ts: number;
  packets: number;
  bytes: number;
  endpoints: number;
}

export interface HistoryFlow {
  proto: Protocol;
  direction: Direction;
  remote_ip: string;
  remote_port: number;
  process: string | null;
  domain: string | null;
  country_iso: string | null;
  city: string | null;
  asn: number | null;
  asn_org: string | null;
  packets: number;
  bytes: number;
  first_seen: number;
  last_seen: number;
}

export interface HistoryApp {
  process: string | null;
  packets: number;
  bytes: number;
  endpoints: number;
  countries: string[];
  domains: string[];
  first_seen: number;
  last_seen: number;
}

export interface HistoryAlert {
  ts_ms: number;
  severity: Severity;
  rule: string;
  message: string;
  remote_ip: string | null;
}

export interface HistoryQuery {
  from?: number;
  to?: number;
  limit?: number;
  q?: string;
  process?: string;
  bucket?: number;
}

// ---- Firewall -----------------------------------------------------------

export interface FirewallRule {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  direction: "Inbound" | "Outbound" | string;
  action: string;
  remote: string[];
  program: string | null;
}

export type BlockTarget =
  | { kind: "ip"; value: string }
  | { kind: "program"; path: string }
  | { kind: "process"; pid?: number | null; name?: string | null };

export type BlockDirection = "in" | "out" | "both";

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
