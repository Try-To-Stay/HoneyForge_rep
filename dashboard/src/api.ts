export interface Honeypot {
  id: string;
  name: string;
  profile_id: string;
  status: string;
  last_seen_at: string | null;
  host_label: string | null;
  created_at: string;
}

export interface AttackEvent {
  id: number;
  honeypot_id: string;
  session_id?: string | null;
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

export const getHoneypots = () => authed<Honeypot[]>("/api/v1/honeypots");
export const getSession = (id: string) => authed<SessionDetail>(`/api/v1/sessions/${id}`);
export const getSummary = () => authed<Summary>("/api/v1/stats/summary");
export const getEvents = (params: Record<string, string>) =>
  authed<{ items: AttackEvent[]; next_cursor: number | null }>("/api/v1/events", params);

export function openEventSocket(onEvent: (ev: AttackEvent) => void): WebSocket {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${window.location.host}/api/v1/ws?token=${getToken()}`);
  ws.onmessage = (m) => {
    try {
      const msg = JSON.parse(m.data);
      if (msg.type === "event") onEvent(msg.data as AttackEvent);
    } catch {
      /* ignore malformed */
    }
  };
  return ws;
}
