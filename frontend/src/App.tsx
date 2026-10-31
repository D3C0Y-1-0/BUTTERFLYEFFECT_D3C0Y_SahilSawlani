import React, { useEffect, useMemo, useRef, useState } from "react";
import { api, boot, login, logout } from "./api";
import { CityScene } from "./scene/CityScene";
import { scene } from "./scene/ref";
import { getState, setState, useStore, View } from "./store";
import { C } from "./palette";
import { Heartbeat, Ring, k, riskColor } from "./components/Charts";
import { Box, Ic, Num, Stat } from "./components/ui";
import { ZeroDayView } from "./components/ZeroDay";
import { CityView, DefendView, FixView, PathView, ProofView, SafetyView } from "./components/Views";
import { LabView } from "./components/Lab";
import { can, nameOf, statusOf } from "./components/status";

const NAV: { id: View; label: string; icon: string }[] = [
  { id: "city", label: "City", icon: "city" }, { id: "path", label: "Paths", icon: "route" }, { id: "fix", label: "Fix", icon: "wrench" }, { id: "lab", label: "What-if", icon: "target" }, { id: "defend", label: "Defend", icon: "shield" },
  { id: "zeroday", label: "Zero-day", icon: "bolt" }, { id: "proof", label: "Proof", icon: "chart" }, { id: "safety", label: "Safety", icon: "lock" },
];
const PANEL: Record<View, () => JSX.Element> = { city: CityView, path: PathView, fix: FixView, lab: LabView, defend: DefendView, zeroday: ZeroDayView, proof: ProofView, safety: SafetyView };

const Mark = ({ size = 30 }) => (
  <svg width={size} height={size} viewBox="0 0 64 64"><defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#E89B5B" /><stop offset="1" stopColor="#D46743" /></linearGradient></defs>
    <path d="M32 6 54 19v26L32 58 10 45V19z" fill="#FFEAD3" stroke="url(#lg)" strokeWidth="5" strokeLinejoin="round" /><circle cx="32" cy="32" r="8" fill="#BFE7EA" stroke="#2F7A84" strokeWidth="3" /></svg>
);

/* ------------------------------------------------------------------ login */
function Login() {
  const [u, setU] = useState("admin"), [p, setP] = useState(""), [c, setC] = useState(""), [err, setErr] = useState(""), [hint, setHint] = useState<any>(null), [busy, setBusy] = useState(false);
  useEffect(() => { fetch("/api/auth/hint").then((r) => (r.ok ? r.json() : null)).then(setHint).catch(() => {}); }, []);
  const go = async (e?: any) => {
    e?.preventDefault(); setBusy(true); setErr("");
    try {
      let code = c;
      if (hint) { const h = await fetch("/api/auth/hint").then((r) => (r.ok ? r.json() : null)).catch(() => null); const acc = h?.accounts?.find((a: any) => a.user === u.trim().toLowerCase() && a.password === p); if (acc) code = acc.totp_now; }   // demo only: codes rotate every 30 s, so use a fresh one
      await login(u, p, code);
    } catch (x: any) { setErr(x.message || "Sign-in failed"); }
    setBusy(false);
  };
  return (
    <div className="login-wrap">
      <form className="panel login" onSubmit={go}>
        <div className="logo" style={{ marginBottom: 4 }}><Mark size={42} /><h1>DECOY</h1></div>
        <div className="sub">Predict. Explain. Heal. Without switching the city off.</div>
        <label htmlFor="u">User</label><input id="u" type="text" value={u} onChange={(e) => setU(e.target.value)} autoComplete="username" />
        <label htmlFor="p">Password</label><input id="p" type="password" value={p} onChange={(e) => setP(e.target.value)} autoComplete="current-password" />
        <label htmlFor="c">6-digit code (MFA)</label><input id="c" type="text" value={c} onChange={(e) => setC(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" placeholder="123456" />
        <button className="btn primary big" style={{ marginTop: 16 }} disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        {err && <div className="err" role="alert">{err}</div>}
        {hint && (
          <div className="demo"><b>Demo accounts</b> <span className="dim">(tap one to fill)</span>
            <div>{hint.accounts.map((a: any) => <button key={a.user} type="button" className="btn small" onClick={() => { setU(a.user); setP(a.password); setC(a.totp_now); setErr(""); }}>{a.user} · {a.role}</button>)}</div></div>
        )}
      </form>
    </div>
  );
}

/* ------------------------------------------------------------------ top bar */
const MODES: [string, string][] = [["observe", "Watch only"], ["suggest", "Ask me first"], ["auto_low", "Auto (safe steps)"], ["auto_all", "Full auto"]];
function TopBar() {
  const snap = useStore((s) => s.snap), ana = useStore((s) => s.ana), role = useStore((s) => s.role), user = useStore((s) => s.user), hist = useStore((s) => s.hist);
  if (!snap) return null;
  const stt = statusOf(snap); const sar = ana?.summary; const inc = [...(snap.incidents || [])].reverse().find((i: any) => i.status === "open" || i.status === "contained");
  const h = hist.slice(-90); const ok = snap.services.served_frac;
  return (
    <div className="panel top">
      <div className="logo"><Mark /><div>DECOY<small>Mumbai ward · {snap.clock}</small></div></div>
      <div className="kpi" title="Share of homes with water and power right now"><div className="l">Homes served</div><div className="v" style={{ color: ok > 0.99 ? C.aquaD : ok > 0.9 ? C.apricot : C.terra }}><Num v={ok * 100} d={1} suffix="%" /></div></div>
      <div className="kpi" title="Worst-case service lost in 95 of 100 simulated attacks"><div className="l">Worst case</div><div className="v">{sar ? k(sar.sar95) : "…"}</div></div>
      <div className="kpi hb" title="Attack probability: flat = calm, spike = something is wrong"><div className="l row between"><span>Heartbeat</span><span className="hbword" style={{ color: stt.color }}>{stt.word} · {(snap.watch.p * 100).toFixed(0)}%</span></div><Heartbeat data={h.map((x) => x.p)} h={30} color={stt.color} thr={0.85} /></div>
      {inc && <div className="kpi" style={{ minWidth: 120 }} title="CERT-In: report within 6 hours"><div className="l">Report due in</div><div className="row"><Ring value={inc.left_min} max={360} size={34} stroke={4} color={C.terra}>{""}</Ring><b>{Math.floor(inc.left_min / 60)}h {inc.left_min % 60}m</b></div></div>}
      <div className="spacer" />
      <select value={snap.autonomy} disabled={!can(role, "operator")} onChange={(e) => api("/api/autonomy", { body: { mode: e.target.value } }).catch(() => {})} aria-label="Who acts" title="Who may act on its own?">{MODES.filter(([m]) => m !== "auto_all" || role === "admin").map(([m, l]) => <option key={m} value={m}>{l}</option>)}</select>
      {can(role, "operator") && <select value={snap.speed} onChange={(e) => api("/api/speed", { body: { x: +e.target.value } })} aria-label="Speed" title="Simulation speed">{[1, 4, 16].map((x) => <option key={x} value={x}>×{x}</option>)}</select>}
      {can(role, "operator") && <button className="btn small danger" title="Kill switch: stop autonomy now" onClick={() => api("/api/freeze", { method: "POST" })}>■ Stop</button>}
      <button className="btn small primary" onClick={() => setState({ judge: 0 })}><Ic n="play" cls="" /> Tour</button>
      <div style={{ textAlign: "right", fontSize: 11.5, lineHeight: 1.3 }}><b>{user}</b><div className="dim">{role} · <a style={{ color: C.terraD, cursor: "pointer", fontWeight: 700 }} onClick={logout}>sign out</a></div></div>
    </div>
  );
}

/* ------------------------------------------------------------------ device passport (short) */
function Passport({ id }: { id: string }) {
  const st = useStore((s) => s.st), ana = useStore((s) => s.ana), snap = useStore((s) => s.snap), role = useStore((s) => s.role);
  const [tab, setTab] = useState("why");
  const a = st.assets[id], ph = st.physical[id]; const row = ana?.ranking?.find((r: any) => r.id === id); const cve = a?.cve ? st.threat_snapshot.cves[a.cve] : null;
  const edges = st.edges.filter((e: any) => e.target === id || e.source === id); const fixes = (ana?.catalog || []).filter((c: any) => c.target === id || c.id.includes(id));
  const close = () => setState({ selected: null });
  if (!a && !ph) return null;
  return (
    <section className="box open hot" style={{ borderColor: C.apricot, boxShadow: "none" }}>
      <header style={{ cursor: "default" }}><Ic n="target" /><span className="t">{(a || ph).name}</span>{a && can(role, "analyst") && <button className="btn small primary" onClick={() => setState({ view: "lab", labStart: id })}>Simulate</button>}<button className="btn small" onClick={close} aria-label="Close">✕</button></header>
      <div className="collapse"><div><div className="body">
        <div className="row wrap">{a && <><span className="pill info">{a.layer}</span><span className={"pill " + (a.provenance === "REAL" ? "safe" : "info")}>{a.provenance === "REAL" ? "real data" : "synthetic"}</span>{a.legacy && <span className="pill watch">old system</span>}</>}{ph && <span className={"pill " + (ph.geo?.source === "OSM" ? "safe" : "info")}>{ph.geo?.source === "OSM" ? "real location" : "synthetic"}</span>}</div>
        {a && row && <div className="grid3"><Stat v={k(row.raw)} l="harm if hacked" color={riskColor(row.raw / 31000)} /><Stat v={k(row.rrw)} l="harm saved if guarded" color={C.aquaD} /><Stat v={"#" + row.rank_sar} l="priority" /></div>}
        {ph && snap && ph.kind === "tank" && <Stat v={snap.levels[id].toFixed(1) + " m"} l="water level" />}
        {ph && snap && ph.kind === "hospital" && <div className="grid2"><Stat v={snap.press[id]?.toFixed(1) + " m"} l="pressure (min 15)" /><Stat v={snap.services.hospitals[id].ok ? "OK" : "AT RISK"} l="water supply" color={snap.services.hospitals[id].ok ? C.aquaD : C.terra} /></div>}
        {ph && snap && ph.kind === "zone" && <Stat v={(snap.services.zones[id] * 100).toFixed(0) + "%"} l="homes served" />}
        {a && <><div className="seg">{[["why", "Why"], ["links", "Links"], ["fix", "Fixes"]].map(([t, l]) => <button key={t} className={tab === t ? "on" : ""} onClick={() => setTab(t)}>{l}</button>)}</div>
          {tab === "why" && <div className="tip">{a.controls ? <>Runs <b>{st.actions[a.controls].label.toLowerCase()}</b>. </> : null}{cve ? <>Known weakness <b>{a.cve}</b> · chance of use {(cve.epss * 100).toFixed(0)}%{cve.in_kev ? " · seen in real attacks" : ""}.</> : <>No known CVE. Risk comes from weak settings.</>}</div>}
          {tab === "links" && <div className="col" style={{ gap: 4 }}>{edges.slice(0, 7).map((e: any) => <div key={e.id} className="row between" style={{ fontSize: 12 }}><span>{e.target === id ? "← " + nameOf(st, e.source) : "→ " + nameOf(st, e.target)}</span><span className={"pill " + (e.known ? "info" : "watch")}>{e.known ? e.protocol : "hidden"}</span></div>)}{!edges.length && <span className="dim">No links.</span>}</div>}
          {tab === "fix" && (fixes.length ? fixes.slice(0, 3).map((f: any) => <div key={f.id} className="row between"><span style={{ fontSize: 12.5 }}>{f.label.length > 44 ? f.label.slice(0, 43) + "…" : f.label}</span>{can(role, "operator") && <button className="btn small heal" onClick={() => api("/api/fix", { body: { id: f.id } })}>Apply</button>}</div>) : <div className="tip">No open fixes.</div>)}</>}
      </div></div></div>
    </section>
  );
}

/* ------------------------------------------------------------------ tour */
const JUDGE: { view: View; act?: string; title: string; text: string }[] = [
  { view: "city", title: "A real Mumbai ward", text: "Pipes, power lines and hospitals below. The computers that control them float above." },
  { view: "proof", title: "Severity is not risk", text: "We rank devices by people harmed, not by CVSS scores." },
  { view: "path", title: "How a hacker gets in", text: "Follow the numbered red route from the internet to a pump." },
  { view: "fix", title: "What to fix first", text: "Risk drops from before to after. Risky restarts wait for 2 AM." },
  { view: "lab", title: "What if it is hacked?", text: "Pick a device and press Simulate: plausible paths, services lost, and the fixes that close them." },
  { view: "defend", act: "attack:standard", title: "A live attack", text: "Watch DECOY detect it, cut one link, and keep water flowing." },
  { view: "defend", act: "attack:spoof", title: "Fake sensor readings", text: "No signature needed: a physics law breaks and the alarm rings." },
  { view: "zeroday", act: "zeroday", title: "A zero-day nobody has seen", text: "DECOY spots the behaviour, learns a rule and protects the whole product family." },
  { view: "safety", title: "Built on CERT-In rules", text: "6-hour report clock, 180-day logs, time-sync guard." },
  { view: "safety", title: "Secure by design", text: "MFA, signed files, tamper-proof logs. We never claim unhackable." },
];
function Tour() {
  const j = useStore((s) => s.judge), role = useStore((s) => s.role); const [auto, setAuto] = useState(true);
  useEffect(() => {
    if (j === null) return; const s = JUDGE[j];
    setState({ view: s.view, selected: null, ...(s.view === "path" ? {} : { pathSel: null }), safetyTab: s.title === "Secure by design" ? "security" : "certin" }); scene.current?.flyTo("overview");
    if (s.act === "zeroday" && can(role, "analyst")) api("/api/zeroday", { body: { mode: "standard" } }).catch(() => {});
    if (s.act?.startsWith("attack:") && can(role, "analyst")) api("/api/attack", { body: { mode: s.act.split(":")[1], entry: s.act.endsWith("spoof") ? null : "VPN_VENDOR", goal: "PLC_PS2", stealth: 4 } }).catch(() => {});
  }, [j]);
  useEffect(() => { if (j === null || !auto) return; const t = setTimeout(() => setState({ judge: j + 1 >= JUDGE.length ? null : j + 1 }), 20000); return () => clearTimeout(t); }, [j, auto]);
  if (j === null) return null; const s = JUDGE[j];
  return (
    <div className="tour" role="dialog" aria-label="Guided tour">
      <div className="row between"><span className="n">STEP {j + 1} OF {JUDGE.length}</span><button className="btn small" onClick={() => setState({ judge: null })}>Skip</button></div>
      <h3>{s.title}</h3><p>{s.text}</p>
      <div className="row" style={{ marginTop: 10 }}><button className="btn small" onClick={() => setState({ judge: Math.max(0, j - 1) })}>← Back</button><button className="btn small primary" onClick={() => setState({ judge: j + 1 >= JUDGE.length ? null : j + 1 })}>{j + 1 >= JUDGE.length ? "Finish" : "Next →"}</button><button className="btn small" onClick={() => setAuto(!auto)}><Ic n={auto ? "pause" : "play"} /></button></div>
      <div className="prog" style={{ width: `${((j + 1) / JUDGE.length) * 100}%` }} />
    </div>
  );
}

/* ------------------------------------------------------------------ the map + its small controls */
function useHold(fn: () => void) {
  const t = useRef<any>(null); const stop = () => { clearInterval(t.current); t.current = null; };
  useEffect(() => stop, []);
  return { onPointerDown: (e: React.PointerEvent) => { e.preventDefault(); fn(); stop(); t.current = setInterval(fn, 70); }, onPointerUp: stop, onPointerLeave: stop, onPointerCancel: stop };
}
const PadBtn = ({ icon, tip, fn }: { icon: string; tip: string; fn: () => void }) => <button aria-label={tip} title={tip} {...useHold(fn)}><Ic n={icon} /></button>;

function MapOverlay() {
  const layers = useStore((s) => s.layers), stack = useStore((s) => s.stack), xray = useStore((s) => s.xray), toast = useStore((s) => s.toast), connected = useStore((s) => s.connected);
  const [hint, setHint] = useState(true); useEffect(() => { const t = setTimeout(() => setHint(false), 14000); return () => clearTimeout(t); }, []);
  const S = () => scene.current;
  const tog = (key: string) => setState((s) => ({ layers: { ...s.layers, [key]: !s.layers[key] } }));
  const tools = [["link", "Network links", layers.links !== false, () => tog("links")], ["hill", "Risk hills", !!layers.risk, () => tog("risk")], ["mask", "Decoys", xray, () => setState({ xray: !xray })], ["layers", "3D layers", stack, () => setState({ stack: !stack })], ["question", "Help", hint, () => setHint(!hint)]] as const;
  return (
    <>
      <div className="maptools">{tools.map(([ic, tip, on, fn]) => <button key={tip} className={"mapbtn" + (on ? " on" : "")} data-tip={tip} aria-label={tip} aria-pressed={on} onClick={fn}><Ic n={ic} /></button>)}</div>
      <div className="views">{[["overview", "Overview"], ["hospital", "Hospitals"], ["water", "Water"]].map(([v, l]) => <button key={v} onClick={() => { setState({ stack: false }); S()?.flyTo(v); }}>{l}</button>)}</div>
      <div className="pad" aria-label="Move the map">
        <PadBtn icon="rotl" tip="Turn left" fn={() => S()?.turn(0.08)} /><PadBtn icon="up" tip="Move forward" fn={() => S()?.nudge(0, 0.08)} /><PadBtn icon="rotr" tip="Turn right" fn={() => S()?.turn(-0.08)} />
        <PadBtn icon="left" tip="Move left" fn={() => S()?.nudge(-0.08, 0)} /><button aria-label="Reset view" title="Reset view" onClick={() => S()?.flyTo("overview")}><Ic n="target" /></button><PadBtn icon="right" tip="Move right" fn={() => S()?.nudge(0.08, 0)} />
        <PadBtn icon="minus" tip="Zoom out" fn={() => S()?.zoom(1.04)} /><PadBtn icon="down" tip="Move back" fn={() => S()?.nudge(0, -0.08)} /><PadBtn icon="plus" tip="Zoom in" fn={() => S()?.zoom(0.96)} />
      </div>
      {hint && <div className="hint"><span><i style={{ background: C.aquaD }} />safe</span><span><i style={{ background: C.apricot }} />watch</span><span><i style={{ background: C.terra }} />attacker</span><span className="dim">drag turn · right-drag move · scroll zoom · W A S D fly</span></div>}
      {toast && <div key={toast.id} className={"toast " + toast.sev}>{toast.text}</div>}
      {!connected && <div className="reconnect">Reconnecting to the server…</div>}
    </>
  );
}

function SceneHost() {
  const host = useRef<HTMLDivElement>(null); const st = useStore((s) => s.st), geo = useStore((s) => s.geo), snap = useStore((s) => s.snap), ana = useStore((s) => s.ana), view = useStore((s) => s.view), sel = useStore((s) => s.selected);
  const layers = useStore((s) => s.layers), stack = useStore((s) => s.stack), xray = useStore((s) => s.xray), pathSel = useStore((s) => s.pathSel), role = useStore((s) => s.role), labNodes = useStore((s) => s.labNodes);
  useEffect(() => {
    if (!st || !geo || !host.current) return;
    const sc = new CityScene(host.current, (id) => setState({ selected: id })); scene.current = sc;
    sc.onHover = (id) => setState({ hovered: id }); sc.onQuality = (q) => setState({ quality: q }); sc.setStatic(st, geo);
    return () => { sc.dispose(); scene.current = null; };
  }, [st, geo]);
  useEffect(() => { scene.current?.setSnapshot(snap); }, [snap]);
  useEffect(() => { scene.current?.setAnalytics(ana); }, [ana]);
  const draw = useMemo(() => {   // which route to draw: the chosen route (Paths) or the live attacker (Defend / Zero-day)
    if ((view === "path" || view === "lab") && pathSel) return { nodes: pathSel.nodes as string[], edges: pathSel.edges as string[], kind: "attack" };
    const inc = [...(snap?.incidents || [])].reverse().find((i: any) => i.status === "open" || i.status === "contained");
    if ((view === "defend" || view === "zeroday") && snap?.adversary?.length && can(role, "operator")) { const c = [...snap.adversary].reverse().find((x: any) => x.state !== "done" && x.state !== "contained") || snap.adversary[snap.adversary.length - 1]; if (c && c.compromised.length > 1) return { nodes: c.compromised as string[], edges: c.hops.map((h: any) => h.edge) as string[], kind: "attack" }; }
    if ((view === "defend" || view === "zeroday") && inc?.next_hops?.length) { const h = inc.next_hops[0]; return { nodes: [h.src, h.dst], edges: [h.edge], kind: "predicted" }; }
    return { nodes: [] as string[], edges: [] as string[], kind: "none" };
  }, [view, pathSel, snap?.adversary, snap?.incidents, role]);
  const dkey = draw.nodes.join(">") + "|" + draw.edges.join(",") + "|" + draw.kind;
  useEffect(() => {
    const labOn = view === "lab" && labNodes.length > 0;
    scene.current?.setUI({ mode: stack ? "stack" : "city", layers, selected: labOn ? labNodes[0] : sel, xray, pathNodes: draw.nodes, pathEdges: draw.edges, pathKind: draw.kind, role, hotNodes: labOn ? labNodes : sel ? st.edges.filter((e: any) => e.source === sel || e.target === sel).flatMap((e: any) => [e.source, e.target]) : null });
  }, [stack, layers, sel, xray, dkey, role, st, view, labNodes]);
  useEffect(() => { if (view === "path" && pathSel) scene.current?.flyTo("path"); }, [view, pathSel]);
  useEffect(() => { if (sel) scene.current?.flyTo("node", sel); }, [sel]);
  return <div className="stage" ref={host} />;
}

function Hover() {
  const h = useStore((s) => s.hovered), st = useStore((s) => s.st), ana = useStore((s) => s.ana); const [pos, setPos] = useState([0, 0]);
  useEffect(() => { if (!h) return; const f = (e: MouseEvent) => setPos([e.clientX, e.clientY]); window.addEventListener("mousemove", f); return () => window.removeEventListener("mousemove", f); }, [!!h]);
  if (!h || !st) return null; const a = st.assets[h] || st.physical[h]; if (!a) return null; const r = ana?.ranking?.find((x: any) => x.id === h);
  return <div className="hover" style={{ left: pos[0] + 14, top: pos[1] + 12 }}><b>{a.name}</b>{r && <div className="dim">harm if hacked {k(r.raw)} · #{r.rank_sar}</div>}<div className="dim">click for details</div></div>;
}

/* ------------------------------------------------------------------ app */
export default function App() {
  const token = useStore((s) => s.token), booting = useStore((s) => s.booting), view = useStore((s) => s.view), sel = useStore((s) => s.selected), snap = useStore((s) => s.snap), st = useStore((s) => s.st);
  useEffect(() => { if (token && !getState().st) boot().catch(() => {}); }, [token]);
  useEffect(() => {
    const f = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement; if (["INPUT", "SELECT", "TEXTAREA"].includes(t?.tagName) || e.ctrlKey || e.metaKey || e.altKey) return;
      const k = e.key.toLowerCase(); const S = scene.current;
      if (k === "1") S?.flyTo("overview"); if (k === "2") S?.flyTo("water"); if (k === "3") S?.flyTo("hospital");
      if (k === "x") setState({ xray: !getState().xray }); if (k === "j") setState({ judge: 0 }); if (k === "l") setState((s) => ({ layers: { ...s.layers, links: !s.layers.links } })); if (k === "r") setState((s) => ({ layers: { ...s.layers, risk: !s.layers.risk } }));
    };
    window.addEventListener("keydown", f); return () => window.removeEventListener("keydown", f);
  }, []);
  if (!token) return <Login />;
  if (booting || !st || !snap) return <div className="login-wrap"><div className="panel login" style={{ textAlign: "center" }}><Mark size={56} /><h1 style={{ fontSize: 22 }}>Loading the city…</h1><div className="sub">Building 7,400 real buildings and connecting to the live twin.</div></div></div>;
  const Panel = PANEL[view]; const hasIncident = (snap.incidents || []).some((i: any) => i.status === "open");
  return (
    <div className="app">
      <TopBar />
      <nav className="panel rail" aria-label="Pages">{NAV.map((n) => <button key={n.id} className={view === n.id ? "on" : ""} onClick={() => setState({ view: n.id, selected: null })} aria-current={view === n.id}><Ic n={n.icon} />{n.label}{(n.id === "defend" || n.id === "zeroday") && hasIncident && <span className="dot" />}</button>)}</nav>
      <div className="stagewrap"><SceneHost /><MapOverlay /></div>
      <main className="panel side"><Tour />{sel && <Passport id={sel} />}<Panel /></main>
      <Hover />
    </div>
  );
}
