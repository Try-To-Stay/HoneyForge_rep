export interface Honeypot {
  id: string;
  name: string;
  profile_id: string;
  status: string;
  last_seen_at: string | null;
  host_label: string | null;
  exposure_score?: number;
  auto_deployed?: boolean;
  created_at: string;
}

export interface Attacker {
  source_ip: string;
  events: number;
  honeypots_touched: number;
  techniques: number;
  first_seen: string | null;
  last_seen: string | null;
  threat_score: number;
}

export interface Technique { id: string; name: string; tactic: string; count: number }

export interface AttackerDetail extends Attacker {
  techniques_list?: Technique[];
}

export interface DeceptionAction {
  id: number;
  action: string;
  source_ip: string | null;
  honeypot_id: string | null;
  detail: Record<string, unknown>;
  created_at: string | null;
}

export interface AttackEvent {
  id: number;
  honeypot_id: string;
  session_id?: string | null;
  technique?: string | null;
  event_type: string;
  source_ip: string | null;
  source_port: number | null;
  dest_port: number | null;
  protocol: string | null;
  severity: string;
  payload: Record<string, unknown>;
  occurred_at: string;
}

export interface Summary {
  total_events: number;
  by_type: Record<string, number>;
  top_sources: { source_ip: string; count: number }[];
}

const TOKEN_KEY = "hf_token";

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(t: string | null) {
  try {
    if (t) localStorage.setItem(TOKEN_KEY, t);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* ignore */
  }
}

async function authed<T>(path: string, params?: Record<string, string>): Promise<T> {
  const url = new URL(path, window.location.origin);
  if (params) Object.entries(params).forEach(([k, v]) => v && url.searchParams.set(k, v));
  const resp = await fetch(url.toString(), {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (resp.status === 401) {
    setToken(null);
    throw new Error("unauthorized");
  }
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json() as Promise<T>;
}

export async function login(username: string, password: string): Promise<void> {
  const body = new URLSearchParams({ username, password });
  const resp = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!resp.ok) throw new Error("Invalid username or password");
  const data = await resp.json();
  setToken(data.access_token);
}

export interface SessionDetail {
  id: string;
  honeypot_id: string;
  service: string;
  source_ip: string | null;
  started_at: string;
  ended_at: string | null;
  auth_attempts: { id: number; username: string | null; password_preview: string | null; success: boolean; occurred_at: string }[];
  commands: AttackEvent[];
}

export interface Profile {
  id: string;
  name: string;
  level: string;
}

export const getHoneypots = () => authed<Honeypot[]>("/api/v1/honeypots");
export const getProfiles = () => authed<Profile[]>("/api/v1/profiles");
export const getCapabilities = () => authed<{ orchestrator: boolean }>("/api/v1/stats/capabilities");
export const getSession = (id: string) => authed<SessionDetail>(`/api/v1/sessions/${id}`);

export async function deployHoneypot(profile_id: string, name: string, host_label: string) {
  const resp = await fetch("/api/v1/honeypots/deploy", {
    method: "POST",
    headers: { Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" },
    body: JSON.stringify({ profile_id, name, host_label }),
  });
  if (!resp.ok) throw new Error(`deploy failed: HTTP ${resp.status}`);
  return resp.json();
}
export const getSummary = () => authed<Summary>("/api/v1/stats/summary");
export const getEvents = (params: Record<string, string>) =>
  authed<{ items: AttackEvent[]; next_cursor: number | null }>("/api/v1/events", params);

export interface Alert {
  id: number;
  honeypot_id: string | null;
  source_ip: string | null;
  rule: string;
  severity: string;
  message: string;
  event_count: number;
  created_at: string;
}

export const getAlerts = () => authed<Alert[]>("/api/v1/alerts");
export const getAttackers = () => authed<Attacker[]>("/api/v1/attackers");
export const getAttacker = (ip: string) =>
  authed<Attacker & { techniques: Technique[] }>(`/api/v1/attackers/${ip}`);
export const getDeception = () => authed<DeceptionAction[]>("/api/v1/deception");

export async function downloadIocs(format: "csv" | "stix") {
  const resp = await fetch(`/api/v1/export/iocs?format=${format}`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (!resp.ok) throw new Error(`export failed: HTTP ${resp.status}`);
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = format === "csv" ? "honeyforge-iocs.csv" : "honeyforge-iocs.stix.json";
  a.click();
  URL.revokeObjectURL(url);
}

export function openEventSocket(
  onEvent: (ev: AttackEvent) => void,
  onAlert: (a: Alert) => void,
): WebSocket {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${window.location.host}/api/v1/ws?token=${getToken()}`);
  ws.onmessage = (m) => {
    try {
      const msg = JSON.parse(m.data);
      if (msg.type === "event") onEvent(msg.data as AttackEvent);
      else if (msg.type === "alert") onAlert(msg.data as Alert);
    } catch {
      /* ignore malformed */
    }
  };
  return ws;
}
