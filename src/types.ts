/** Mirrors the Rust `Snapshot` in src-tauri/src/types.rs.
 *
 * Kept as a hand-written mirror rather than generated: the surface is small,
 * and an explicit copy means a Rust-side field rename shows up as a TypeScript
 * error at the point of use instead of a silent `undefined` in the card.
 */

export type Band = "green" | "blue" | "yellow" | "orange" | "red";

export interface Scores {
  purity: number;
  risk: number;
  confidence: number;
  consistency: number;
}

export interface Check {
  key: string;
  label: string;
  /** true = clean, false = mismatch, null = could not test. */
  agrees: boolean | null;
  detail: string;
}

export interface SourceStatus {
  name: string;
  ok: boolean;
  note: string;
  provenance: "local" | "freeSource" | "keyedSource" | "derived";
  tookMs: number;
  /** False when we skipped this source by our own configuration (no API key).
   *  Such a source is shown, but is not evidence we failed to gather. */
  configured: boolean;
}

export interface Conflict {
  field: string;
  a: string;
  b: string;
  delta: number;
}

export interface Snapshot {
  ip: string;
  domesticIp: string | null;
  internationalIp: string | null;
  domesticAgree: number;
  domesticResponded: number;
  internationalAgree: number;
  internationalResponded: number;
  ipVersion: number;
  countryCode: string;
  country: string;
  city: string;
  region: string;
  asn: string;
  org: string;
  isp: string;
  ipType: string;
  isProxy: boolean | null;
  isVpn: boolean | null;
  isTor: boolean | null;
  isHosting: boolean | null;
  isMobile: boolean | null;
  timezone: string;
  flagEmoji: string;
  blacklistHits: string[];
  /** Consumer-range policy matches (e.g. Spamhaus PBL) — not abuse findings. */
  blacklistPolicy: string[];
  blacklistChecked: number;
  scores: Scores;
  composite: number;
  checks: Check[];
  sources: SourceStatus[];
  conflicts: Conflict[];
  fetchedAt: number;
  tookMs: number;
}

export interface Update {
  snapshot: Snapshot;
  ipChanged: boolean;
  riskBandChanged: boolean;
  stale: boolean;
  error: string | null;
}

/** Mirrors `Config` in src-tauri/src/lib.rs. */
export interface Config {
  refreshSeconds: number;
  abuseipdbKey: string;
  scamalyticsKey: string;
  ipqsKey: string;
  enableDnsbl: boolean;
  enableStun: boolean;
  enableSources: boolean;
  label: string;
}
