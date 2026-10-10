import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AttackEvent,
  Honeypot,
  Profile,
  SessionDetail,
  Summary,
  deployHoneypot,
  getEvents,
  getHoneypots,
  getProfiles,
  getSession,
  getSummary,
  getToken,
  login,
  openEventSocket,
  setToken,
} from "./api";

export function App() {
  const [authed, setAuthed] = useState<boolean>(!!getToken());
  if (!authed) return <Login onLogin={() => setAuthed(true)} />;
  return <Dashboard onLogout={() => { setToken(null); setAuthed(false); }} />;
}

function Login({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
      onLogin();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <h1>HoneyForge</h1>
        <p className="muted">Operator console</p>
        <label>Username<input value={username} onChange={(e) => setUsername(e.target.value)} /></label>
        <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        {error && <div className="error">{error}</div>}
        <button disabled={busy}>{busy ? "…" : "Sign in"}</button>
      </form>
    </div>
  );
}

function Dashboard({ onLogout }: { onLogout: () => void }) {
  const [honeypots, setHoneypots] = useState<Honeypot[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [events, setEvents] = useState<AttackEvent[]>([]);
  const [live, setLive] = useState(false);
  const [filterHp, setFilterHp] = useState("");
  const [filterType, setFilterType] = useState("");
  const [filterIp, setFilterIp] = useState("");
  const [session, setSession] = useState<SessionDetail | null>(null);

  const openSession = useCallback(async (id: string) => {
    try {
      setSession(await getSession(id));
    } catch { /* ignore */ }
  }, []);

  const hpName = useMemo(() => {
    const m: Record<string, string> = {};
    honeypots.forEach((h) => (m[h.id] = h.name));
    return m;
  }, [honeypots]);

  const matchesFilter = useCallback(
    (ev: AttackEvent) =>
      (!filterHp || ev.honeypot_id === filterHp) &&
      (!filterType || ev.event_type === filterType) &&
      (!filterIp || (ev.source_ip ?? "").includes(filterIp)),
    [filterHp, filterType, filterIp],
  );

  // Poll honeypots + summary.
  useEffect(() => {
    let active = true;
    const tick = async () => {
      try {
        const [hps, sum] = await Promise.all([getHoneypots(), getSummary()]);
        if (active) { setHoneypots(hps); setSummary(sum); }
      } catch { /* ignore transient */ }
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => { active = false; clearInterval(id); };
  }, []);

  // Initial events + filters refetch.
  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const params: Record<string, string> = { limit: "200" };
        if (filterHp) params.honeypot_id = filterHp;
        if (filterType) params.type = filterType;
        if (filterIp) params.source_ip = filterIp;
        const page = await getEvents(params);
        if (active) setEvents(page.items);
      } catch { /* ignore */ }
    })();
    return () => { active = false; };
  }, [filterHp, filterType, filterIp]);

  // Live WebSocket stream.
  const wsRef = useRef<WebSocket | null>(null);
  useEffect(() => {
    const ws = openEventSocket((ev) => {
      setEvents((prev) => (prev.some((e) => e.id === ev.id) ? prev : [ev, ...prev].slice(0, 500)));
    });
    ws.onopen = () => setLive(true);
    ws.onclose = () => setLive(false);
    wsRef.current = ws;
    return () => ws.close();
  }, []);

  const shown = events.filter(matchesFilter);

  return (
    <div className="app">
      <header>
        <strong>HoneyForge</strong>
        <span className={`live ${live ? "on" : "off"}`}>{live ? "● live" : "○ offline"}</span>
        {summary && <span className="muted">{summary.total_events} events</span>}
        <div className="spacer" />
        <button className="ghost" onClick={onLogout}>Logout</button>
      </header>

      <div className="grid">
        <aside>
          <h2>Honeypots</h2>
          {honeypots.length === 0 && <p className="muted">none registered</p>}
          {honeypots.map((h) => (
            <div key={h.id} className="hp-card" onClick={() => setFilterHp(filterHp === h.id ? "" : h.id)}>
              <div className="hp-top">
                <span className={`dot ${h.status}`} />
                <b>{h.name}</b>
              </div>
              <div className="muted small">{h.host_label ?? "—"} · {h.status}</div>
              <div className="muted small">last seen: {fmt(h.last_seen_at)}</div>
            </div>
          ))}

          {summary && summary.top_sources.length > 0 && (
            <>
              <h2>Top sources</h2>
              {summary.top_sources.map((s) => (
                <div key={s.source_ip} className="muted small">{s.source_ip} — {s.count}</div>
              ))}
            </>
          )}

          <DeployPanel />
        </aside>

        <main>
          <div className="filters">
            <select value={filterHp} onChange={(e) => setFilterHp(e.target.value)}>
              <option value="">all honeypots</option>
              {honeypots.map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}
            </select>
            <select value={filterType} onChange={(e) => setFilterType(e.target.value)}>
              <option value="">all types</option>
              {["scan", "connect", "auth_attempt", "command", "http_request"].map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
            <input placeholder="source ip" value={filterIp} onChange={(e) => setFilterIp(e.target.value)} />
            {(filterHp || filterType || filterIp) && (
              <button className="ghost" onClick={() => { setFilterHp(""); setFilterType(""); setFilterIp(""); }}>clear</button>
            )}
          </div>

          <h2>Event feed <span className="muted small">({shown.length})</span></h2>
          <table className="events">
            <thead>
              <tr><th>time</th><th>type</th><th>honeypot</th><th>source</th><th>dst</th><th>details</th></tr>
            </thead>
            <tbody>
              {shown.map((ev) => (
                <tr
                  key={ev.id}
                  className={`sev-${ev.severity} ${ev.session_id ? "clickable" : ""}`}
                  onClick={() => ev.session_id && openSession(ev.session_id)}
                >
                  <td className="mono">{fmtTime(ev.occurred_at)}</td>
                  <td><span className={`tag t-${ev.event_type}`}>{ev.event_type}</span></td>
                  <td>{hpName[ev.honeypot_id] ?? ev.honeypot_id.slice(0, 8)}</td>
                  <td className="mono">{ev.source_ip ?? "—"}{ev.source_port ? `:${ev.source_port}` : ""}</td>
                  <td className="mono">{ev.protocol ?? ""}/{ev.dest_port ?? "—"}</td>
                  <td className="mono small">{details(ev)}</td>
                </tr>
              ))}
              {shown.length === 0 && <tr><td colSpan={6} className="muted">no events</td></tr>}
            </tbody>
          </table>
        </main>
      </div>

      {session && <SessionModal session={session} hpName={hpName} onClose={() => setSession(null)} />}
    </div>
  );
}

function DeployPanel() {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profileId, setProfileId] = useState("");
  const [name, setName] = useState("edge-node");
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getProfiles().then((p) => {
      setProfiles(p);
      if (p[0]) setProfileId(p[0].id);
    }).catch(() => { /* ignore */ });
  }, []);

  const deploy = async () => {
    if (!profileId) return;
    setBusy(true);
    setMsg(null);
    try {
      const r = await deployHoneypot(profileId, name, "deployed");
      setMsg(`deployed · ${r.container_id}`);
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <h2>Deploy honeypot</h2>
      <div className="deploy">
        <select value={profileId} onChange={(e) => setProfileId(e.target.value)}>
          {profiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="name" />
        <button disabled={busy || !profileId} onClick={deploy}>{busy ? "…" : "Deploy"}</button>
        {msg && <div className="muted small">{msg}</div>}
      </div>
    </>
  );
}

function SessionModal({
  session,
  hpName,
  onClose,
}: {
  session: SessionDetail;
  hpName: Record<string, string>;
  onClose: () => void;
}) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <b>Session · {session.service}</b>
          <button className="ghost" onClick={onClose}>close</button>
        </div>
        <div className="muted small">
          source {session.source_ip ?? "—"} · started {fmt(session.started_at)}
          {session.ended_at ? ` · ended ${fmtTime(session.ended_at)}` : " · active"}
        </div>

        <h3>Login attempts ({session.auth_attempts.length})</h3>
        <table className="events">
          <tbody>
            {session.auth_attempts.map((a) => (
              <tr key={a.id} className={a.success ? "sev-high" : ""}>
                <td className="mono">{a.username ?? "—"}</td>
                <td className="mono">{a.password_preview ?? "—"}</td>
                <td>{a.success ? "✓ success" : "✗ failed"}</td>
                <td className="mono small">{fmtTime(a.occurred_at)}</td>
              </tr>
            ))}
            {session.auth_attempts.length === 0 && <tr><td className="muted">none</td></tr>}
          </tbody>
        </table>

        <h3>Commands ({session.commands.length})</h3>
        <div className="terminal">
          {session.commands.map((c) => (
            <div key={c.id} className="mono small">$ {String((c.payload as Record<string, unknown>).command ?? "")}</div>
          ))}
          {session.commands.length === 0 && <div className="muted">none</div>}
        </div>
        <div className="muted small" style={{ marginTop: 8 }}>honeypot: {hpName[session.honeypot_id ?? ""] ?? ""}</div>
      </div>
    </div>
  );
}

function details(ev: AttackEvent): string {
  const p = ev.payload as Record<string, string>;
  if (p.username) return `user=${p.username} pw=${p.password_masked ?? p.password_preview ?? ""}`;
  if (p.command) return `cmd: ${p.command}`;
  if (p.probe) return `probe: ${String(p.probe).replace(/[\r\n]+/g, " ").trim()}`;
  if (p.banner_sent) return `banner: ${String(p.banner_sent).replace(/[\r\n]+/g, " ").trim()}`;
  return "";
}

function fmt(iso: string | null): string {
  if (!iso) return "never";
  return new Date(iso).toLocaleString();
}
function fmtTime(iso: string): string {
  return new Date(iso).toLocaleTimeString();
}
