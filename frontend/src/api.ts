import { getState, setState, toast } from "./store";

const plain = (j: any, status: number) => {
  const d = j?.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d) && d[0]?.msg) return `Please check '${(d[0].loc || []).slice(1).join(".")}': ${d[0].msg}`;
  return status === 429 ? "Too many requests: slow down a little" : status === 403 ? "Your role may not do this" : "Request failed";
};

export async function api(path: string, opts: { method?: string; body?: any } = {}) {
  const { token } = getState();
  let r: Response;
  try {
    r = await fetch(path, { method: opts.method || (opts.body ? "POST" : "GET"), headers: { "Content-Type": "application/json", ...(token ? { Authorization: "Bearer " + token } : {}) }, body: opts.body ? JSON.stringify(opts.body) : undefined });
  } catch {
    throw new Error("Server not reachable");
  }
  if (r.status === 401 && token && !path.startsWith("/api/auth")) { logout(); throw new Error("Session expired, please sign in again"); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const msg = plain(j, r.status); if (!path.startsWith("/api/auth")) toast(r.status === 409 ? "ok" : "warn", msg); throw new Error(msg); }
  if ((opts.method || (opts.body ? "POST" : "GET")) === "POST") noteAction(path, opts.body);
  return j;
}

/** Every action the person takes leaves a mark on the heartbeat, so its effect can be read straight off the line. */
const ACTIONS: [RegExp, string][] = [[/^\/api\/fix$/, "Fix applied"], [/^\/api\/decoy$/, "Decoy placed"], [/^\/api\/attack$/, "Attack launched"], [/^\/api\/zeroday$/, "Zero-day launched"], [/^\/api\/freeze$/, "Emergency stop"], [/^\/api\/resume$/, "Resumed"],
  [/approve$/, "Plan approved"], [/reject$/, "Plan rejected"], [/^\/api\/autonomy$/, "Defence mode changed"], [/mitigations\/apply$/, "Simulated control applied"], [/^\/api\/answer$/, "Answer given"], [/^\/api\/autopilot$/, "Autopilot changed"], [/simulate\/compromise$/, "Simulated compromise"], [/scenarios\/[^/]+\/run$/, "Scenario run"]];
function noteAction(path: string, _body: any) {
  const hit = ACTIONS.find(([re]) => re.test(path)); if (!hit) return; const s = getState();
  setState({ marks: [...s.marks, { t: s.snap?.t ?? 0, label: hit[1], wall: Date.now(), before: s.ana?.summary?.sar99 }].slice(-14) });
}

export function logout() {
  sessionStorage.clear(); ws?.close(); clearInterval(anaTimer); setState({ token: null, user: null, role: null, snap: null, st: null, ana: null, hist: [], selected: null, pathSel: null });
}

let ws: WebSocket | null = null;
let anaTimer: any = null;
let retry = 0;

export async function boot() {
  const [st, geo] = await Promise.all([api("/api/static"), api("/api/geo")]);
  setState({ st, geo, booting: false });
  connect(); pollAnalytics();
  api("/api/experiments").then((exp) => setState({ exp })).catch(() => {});
  api("/api/v2/forecast?top=6").catch(() => {});   // warm the forecast on the server so the Predict page opens instantly
}

function connect() {
  const { token } = getState(); if (!token) return;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(token)}`);
  let pending: any = null, timer: any = null;
  const flush = () => {   // the server may send 8 frames a second; the interface updates 3 times a second, which keeps it light
    timer = null; if (!pending) return; const snap = pending; pending = null;
    const s = getState(); const hist = s.hist.length > 360 ? s.hist.slice(-300) : s.hist; const last = hist[hist.length - 1];
    const item = { t: snap.t, cs: snap.watch.cusum ?? 0, line: snap.watch.cusum_line || 1, raw: snap.watch.p, p: snap.watch.shown ?? snap.watch.p, live: snap.services.served_frac, none: snap.compare.none_served, iso: snap.compare.iso_served };
    setState({ snap, hist: last && last.t === snap.t ? hist : [...hist, item] });
  };
  ws.onopen = () => { retry = 0; setState({ connected: true }); };
  ws.onclose = () => { setState({ connected: false }); clearTimeout(timer); if (getState().token) setTimeout(connect, Math.min(5000, 800 * ++retry)); };
  ws.onmessage = (m) => {
    let f: any; try { f = JSON.parse(m.data); } catch { return; }
    if (pending?.events?.length) f.events = [...pending.events, ...(f.events || [])];   // never drop one-shot events when frames are merged
    pending = f; if (!timer) timer = setTimeout(flush, 330);
  };
}

export function pollAnalytics() {
  clearInterval(anaTimer);
  const f = async () => { if (document.hidden) return; try { const a = await api("/api/risk"); if (a && a.version && a.version !== getState().ana?.version) { const ms = getState().marks; const m = ms[ms.length - 1]; setState({ ana: a, marks: m && m.after === undefined && m.before !== undefined && Date.now() - m.wall < 40000 ? [...ms.slice(0, -1), { ...m, after: a.summary?.sar99 }] : ms }); } } catch {} };
  f(); anaTimer = setInterval(f, 5000);
}

export async function login(username: string, password: string, totp: string) {
  const user = username.trim().toLowerCase(), code = totp.replace(/\s/g, "");
  if (!user || !password) throw new Error("Enter your user name and password");
  if (!/^\d{6}$/.test(code)) throw new Error("Enter the 6-digit code from the authenticator");
  const r = await api("/api/auth/login", { body: { username: user, password, totp: code } });
  sessionStorage.setItem("decoy_token", r.token); sessionStorage.setItem("decoy_user", r.user); sessionStorage.setItem("decoy_role", r.role);
  setState({ token: r.token, user: r.user, role: r.role, booting: true });
  await boot();
}
