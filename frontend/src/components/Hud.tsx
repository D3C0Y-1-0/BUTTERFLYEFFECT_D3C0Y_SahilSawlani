import React, { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import { scene } from "../scene/ref";
import { LAYER_COL, SECTOR_COL } from "../scene/CityScene";
import { getState, setState, toast, useStore } from "../store";
import { C } from "../palette";
import { Ic, Move } from "./ui";
import { k, riskColor } from "./Charts";
import { brief, can, nameOf, plainMove, statusOf } from "./status";
import { blastOf, pickNode, showBlast, showEdges, showNodeRoute } from "../focus";

const hexc = (n: number) => "#" + n.toString(16).padStart(6, "0");
export const HOT = "#E11D48";
const mm = (m: number) => `${String(Math.floor((m % 1440) / 60)).padStart(2, "0")}:${String(Math.floor(m % 60)).padStart(2, "0")}`;

/* ------------------------------------------------------------------ what each thing is, in one plain line */
const ASSET_DESC: Record<string, string> = {
  INTERNET: "The public internet: where every outside attacker starts.",
  FW_PERIM: "Firewall at the edge of the city network. It decides what may come in.",
  VPN_VENDOR: "Remote door for outside vendors. A shared password here is a favourite way in.",
  MAIL_01: "City e-mail server. Phishing mails land here.",
  JUMP_RDS: "Stepping-stone computer staff use to reach the control systems.",
  SCADA_WEB: "Web page that shows plant status to staff. It faces the internet, so it gets probed.",
  HIST_01: "Records plant readings and watches the network.",
  SCADA_SRV: "The brain that sends commands to pumps, valves and breakers.",
  HMI_01: "Operator screen used to control equipment.",
  ENG_WS: "Engineer's PC that programs the controllers. Old software makes it risky.",
  BMS_KEM: "Runs the water and building systems of KEM Hospital.",
  WIFI_PUB_01: "Public Wi-Fi in Parel. Anyone can connect, so it is a common way in.",
  EVC_01: "EV charging station connected to the city network.",
  GW_METER_01: "Collects smart-meter readings and sends them to the grid.",
  CCTV_01: "Street camera near Sion Hospital.", CCTV_02: "Street camera at Parel junction.",
};
const LAYER_DESC: Record<string, string> = { iot: "Smart-city device on the public edge.", it: "Office computer or server.", dmz: "Gateway between outside and inside.", control: "Control-room system for the utilities.", field: "Controller that physically runs a pump, valve or breaker.", internet: "Outside world." };
const KIND_DESC: Record<string, string> = { pump: "Pumps water up to the service reservoir.", tank: "Stores water for the ward. Low level means trouble.", valve: "Opens or closes a water pipe.", breaker: "Switches power to a feeder on or off.", hospital: "Needs water and power at all times.", zone: "Homes that depend on this water and power.", site: "" };
const SECTOR_WORD: Record<string, string> = { nuclear: "Nuclear research", it_hub: "IT hub", factory: "Factory", hospital: "Hospital", tourist: "Tourist spot", transport: "Transport" };
export const describe = (id: string, a: any) => ASSET_DESC[id] || (a?.layer ? (id.startsWith("OFFICE_PC") ? "Office computer used by ward staff. Old software makes it an easy foothold." : id.startsWith("GW_LIGHT") ? "Street-light controller connected over the network." : id.startsWith("PLC") || id.startsWith("RTU") ? "Controller that physically runs a pump, valve or breaker." : LAYER_DESC[a.layer]) : KIND_DESC[a?.kind] || "");

/* ------------------------------------------------------------------ title + legend (corners only; the middle of the map stays free) */
export function MapTitle() {
  return <div className="maptitle"><h1>City Digital Twin</h1><p>Real-time attack spread and impact · Mumbai</p></div>;
}

export function Legend() {
  const [open, setOpen] = useState(true);
  const rows: [string, string][] = [["Internet", hexc(LAYER_COL.internet)], ["Smart-city edge", hexc(LAYER_COL.iot)], ["Office IT", hexc(LAYER_COL.it)], ["Gateway (DMZ)", hexc(LAYER_COL.dmz)], ["Control room", hexc(LAYER_COL.control)], ["Pump / valve / breaker controller", hexc(LAYER_COL.field)]];
  return (
    <div className={"legend" + (open ? " open" : "")}>
      <button className="lh" onClick={() => setOpen(!open)}>Map legend <Ic n="chevron" cls={"chev" + (open ? " up" : "")} /></button>
      {open && <div className="lb">
        {rows.map(([l, c]) => <div key={l}><i style={{ background: c }} />{l}</div>)}
        <div className="sep" />
        <div><s style={{ background: HOT }} />Attack path / blast radius</div>
        <div><s style={{ background: "#F28C1B" }} />Predicted next step</div>
        <div><s style={{ background: C.aquaD }} />Defence / protected</div>
        <div><b className="dia" style={{ background: hexc(SECTOR_COL.nuclear) }} />Mumbai site (not to scale)</div>
        <div className="dim" style={{ marginTop: 3 }}>Drag = move · right-drag = turn · wheel = zoom</div>
      </div>}
    </div>
  );
}

/* ------------------------------------------------------------------ incident card (compact, top-right) */
const STAGES = ["Detected", "Predicted route", "Cut made", "Verified", "Recovered"];
export function IncidentCard() {
  const snap = useStore((s) => s.snap), st = useStore((s) => s.st), role = useStore((s) => s.role), side = useStore((s) => s.side);
  const [open, setOpen] = useState(true);
  const stt = statusOf(snap); const inc = [...(snap.incidents || [])].reverse().find((i: any) => i.status !== "reported") || null;
  const camp = can(role, "analyst") ? [...(snap.adversary || [])].reverse().find((c: any) => c.hops?.length) : null;
  const items = useMemo(() => {
    if (!inc) return [] as any[];
    const out: any[] = [];
    if (camp) for (const h of camp.hops) out.push({ m: h.minute, text: nameOf(st, h.dst) + " taken over", sub: "from " + nameOf(st, h.src), kind: "hit" });
    for (const s of inc.stages) out.push({ m: s.minute, text: s.stage === "Cut made" ? "Attacker cut off" : s.stage, sub: "", kind: s.stage === "Detected" ? "warn" : "ok" });
    return out.sort((a, b) => a.m - b.m).slice(-5);
  }, [inc, camp?.hops?.length, st]);
  const next = inc?.next_hops?.[0];
  const status = !inc ? "Calm" : inc.status === "resolved" ? "Resolved" : inc.stages.some((s: any) => s.stage === "Recovered") ? "Recovered" : inc.stages.some((s: any) => s.stage === "Verified") ? "Verified" : inc.stages.some((s: any) => s.stage === "Cut made") ? "Containment in progress" : inc.stages.some((s: any) => s.stage === "Predicted route") ? "Route predicted" : "Investigating";
  return (
    <div className={"inccard" + (side ? "" : " wide")}>
      <button className="ih" onClick={() => setOpen(!open)}>
        <span className={"ibadge " + stt.tone}><Ic n={inc ? "bolt" : "shield"} /></span>
        <span className="grow"><b>{inc ? "Incident " + inc.id.replace("INC-", "") : "No incident"}</b><small>{inc ? inc.clock0 : "All calm"}</small></span>
        <span className={"pill " + stt.tone + (stt.key === "attack" ? " pulse" : "")}>{stt.label}</span><Ic n="chevron" cls={"chev" + (open ? " up" : "")} />
      </button>
      {open && <div className="ib">
        {inc ? <>
          <div className={"ibanner " + stt.tone}><b>{stt.key === "attack" ? "Attack spreading" : stt.key === "healing" ? "Healing" : "Incident"}</b><span>{stt.line}</span></div>
          <div className="itl">{items.map((it, i) => <div key={i} className={it.kind}><i /><span><b>{it.text}</b>{it.sub && <small> {it.sub}</small>}</span><em>{mm(it.m)}</em></div>)}
            {next && <div className="pred"><i /><span><b>Next: {nameOf(st, next.dst)}</b><small> {(next.p * 100).toFixed(0)}% likely</small></span><em>predicted</em></div>}</div>
          <div className="irow"><div><small>Affected devices</small><b>{String(inc.evidence_nodes.length).padStart(2, "0")}</b></div><div><small>Response</small><span className={"pill " + (status === "Containment in progress" ? "safe" : "watch")}>{status}</span></div></div>
        </> : <div className="tip">No attack right now. The heartbeat is flat and ATHENA is learning what normal looks like. Launch one from <b>Defend</b>.</div>}
      </div>}
    </div>
  );
}

/* ------------------------------------------------------------------ bottom timeline */
export function Timeline() {
  const snap = useStore((s) => s.snap), hist = useStore((s) => s.hist), role = useStore((s) => s.role), paused = useStore((s) => s.snap?.paused);
  const inc = [...(snap.incidents || [])].reverse().find((i: any) => i.status !== "reported") || null;
  const camp = can(role, "analyst") ? [...(snap.adversary || [])].reverse().find((c: any) => c.hops?.length) : null;
  const stt = statusOf(snap); const now = snap.t;
  const t0 = inc ? Math.max(0, Math.min(inc.t0, camp?.started ?? inc.t0) - 8) : now - 120; const t1 = Math.max(now + 4, t0 + 40);
  const x = (m: number) => Math.max(0, Math.min(100, ((m - t0) / (t1 - t0)) * 100));
  const marks: { m: number; kind: string; label: string }[] = [];
  if (inc) { for (const s of inc.stages) marks.push({ m: s.minute, kind: "ok", label: s.stage === "Cut made" ? "Cut" : s.stage.replace(" route", "") }); if (camp) for (const h of camp.hops) marks.push({ m: h.minute, kind: "hit", label: "" }); }
  const hp = hist.filter((h) => h.t >= t0);
  return (
    <div className="timeline">
      <button className={"tbtn" + (paused ? "" : " on")} aria-label={paused ? "Play" : "Pause"} title={paused ? "Play" : "Pause the simulation"} onClick={() => can(role, "operator") && api("/api/pause", { body: { on: !paused } })}><Ic n={paused ? "play" : "pause"} /></button>
      <div className="tlab"><b>{inc ? "Attack timeline" : "Heartbeat"}</b><small>{inc ? inc.id : "last 2 hours"}</small></div>
      <div className="track">
        <svg viewBox="0 0 100 12" preserveAspectRatio="none" className="spark">{hp.length > 2 && <polyline fill="none" stroke={stt.color} strokeWidth="0.6" vectorEffect="non-scaling-stroke" points={hp.map((h) => `${x(h.t)},${11 - Math.min(1, h.p) * 10}`).join(" ")} />}</svg>
        <div className="fill" style={{ width: x(now) + "%", background: inc ? "linear-gradient(90deg,#F5B7A5,#E11D48)" : "linear-gradient(90deg,#BFE7EA,#6FC3CB)" }} />
        {marks.map((mk, i) => <div key={i} className={"mk " + mk.kind} style={{ left: x(mk.m) + "%" }} title={mk.label}></div>)}
        <div className="now" style={{ left: x(now) + "%" }} />
        <div className="ticks"><span>{mm(t0)}</span><span>{mm((t0 + t1) / 2)}</span><span>{mm(t1)}</span></div>
      </div>
      <div className="tclock"><b>{snap.clock}</b><small>{paused ? "paused" : "live"}</small></div>
    </div>
  );
}

/* ------------------------------------------------------------------ floating card beside the selected device */
export function NodeCard() {
  const sel = useStore((s) => s.selected), st = useStore((s) => s.st), snap = useStore((s) => s.snap), ana = useStore((s) => s.ana), role = useStore((s) => s.role), blastOn = useStore((s) => s.blast), focus = useStore((s) => s.focus);
  const [pos, setPos] = useState<{ x: number; y: number; left: boolean } | null>(null);
  const [fixOpen, setFixOpen] = useState(false);
  useEffect(() => {
    if (!sel) { setPos(null); return; }
    const f = () => {
      const sp = scene.current?.screenPos(sel); const host = document.querySelector(".mapcol") as HTMLElement | null; if (!sp || !host) return;
      const r = host.getBoundingClientRect(); const x = sp.x - r.left, y = sp.y - r.top; if (sp.behind) { setPos(null); return; }
      const left = x > r.width - 360; setPos({ x: Math.max(8, Math.min(r.width - 8, x)), y: Math.max(70, Math.min(r.height - 230, y - 40)), left });
    };
    f(); const t = setInterval(f, 90); return () => clearInterval(t);
  }, [sel]);
  useEffect(() => setFixOpen(false), [sel]);
  if (!sel || !st) return null;
  const a = st.assets[sel], ph = st.physical[sel]; const d = a || ph; if (!d) return null;
  const row = ana?.ranking?.find((r: any) => r.id === sel); const cve = a?.cve ? st.threat_snapshot.cves[a.cve] : null;
  const state = snap?.nodes?.[sel] || "normal"; const adv = new Set<string>((snap?.adversary || []).flatMap((c: any) => c.compromised));
  const stateWord = adv.has(sel) ? ["Taken over", "crit"] : state === "suspect" ? ["Suspected", "watch"] : state === "quarantined" ? ["Cut off", "safe"] : ["Normal", "safe"];
  const b = a && sel !== "INTERNET" ? blastOf(st, sel) : null;
  const fixes = (ana?.catalog || []).filter((c: any) => c.target === sel || c.id.endsWith(":" + sel));
  const site = ph?.kind === "site" ? ph : null;
  const exposed = site ? (site.depends_on || []).filter((x: string) => adv.has(x) || (snap?.nodes?.[x] && snap.nodes[x] !== "normal")) : [];
  const col = a ? hexc(LAYER_COL[a.layer] ?? 0x2F7A84) : site ? hexc(SECTOR_COL[site.sector] ?? 0x555555) : C.aquaD;
  const place = () => api("/api/decoy", { body: { node: sel } }).then(() => { toast("ok", "Decoy placed next to " + brief(d.name)); setState({ xray: true }); }).catch(() => {});
  const style: React.CSSProperties = pos ? { left: pos.left ? undefined : pos.x + 26, right: pos.left ? `calc(100% - ${pos.x - 26}px)` : undefined, top: pos.y } : { right: 16, top: 130 };
  return (
    <div className="nodecard" style={style} role="dialog" aria-label={d.name}>
      <header><span className="nic" style={{ background: col }}><Ic n={site ? "target" : a ? "shield" : "water"} /></span><b className="grow">{brief(d.name)}</b><button className="x" aria-label="Close" onClick={() => setState({ selected: null, focus: null })}>✕</button></header>
      <div className="nbody">
        <div className="row wrap" style={{ gap: 5 }}>
          {a && <span className="pill" style={{ background: col, color: "#fff" }}>{({ iot: "Smart-city edge", it: "Office IT", dmz: "Gateway", control: "Control room", field: "Controller", internet: "Internet" } as any)[a.layer]}</span>}
          {site && <><span className="pill" style={{ background: col, color: "#fff" }}>{SECTOR_WORD[site.sector]}</span><span className={"pill " + (site.priority === "critical" ? "crit" : site.priority === "high" ? "watch" : "info")}>{site.priority} priority</span></>}
          {!a && !site && <span className="pill info">{ph.kind}</span>}
          {a && <span className={"pill " + (stateWord[1] as string)}>{stateWord[0]}</span>}
          {a && <span className="pill info">{a.provenance === "REAL" ? "real data" : "synthetic"}</span>}
          {a?.legacy && <span className="pill watch">old system</span>}
        </div>
        <p className="ndesc">{site ? site.why + "." : describe(sel, d)}</p>
        {a && row && <div className="nstats"><div><b style={{ color: riskColor(row.raw / 31000) }}>{k(row.raw)}</b><small>harm if hacked</small></div><div><b>#{row.rank_sar}</b><small>priority</small></div><div><b>{b ? b.devices.length + b.sites.length : 0}</b><small>others at risk</small></div></div>}
        {a && cve && <div className="ntip">Known weakness <b>{a.cve}</b> · {(cve.epss * 100).toFixed(0)}% chance of use{cve.in_kev ? " · used in real attacks" : ""}</div>}
        {a && !cve && <div className="ntip">No known CVE. Risk comes from weak settings and its position in the network.</div>}
        {site && <><div className="ntip"><b>Relies on:</b> {(site.depends_on || []).map((x: string) => nameOf(st, x)).join(", ")}</div>
          <div className={"ntip " + (exposed.length ? "bad" : "")}>{exposed.length ? `Exposed now: ${exposed.map((x: string) => nameOf(st, x)).join(", ")}` : "No device it relies on is compromised right now."}</div>
          <div className="ntip dim"></div></>}
        {!a && !site && ph && snap && ph.kind === "tank" && <div className="ntip">Water level <b>{snap.levels[sel]?.toFixed(1)} m</b></div>}
        {!a && !site && ph && snap && ph.kind === "hospital" && <div className="ntip">Water supply <b>{snap.services.hospitals[sel]?.ok ? "OK" : "AT RISK"}</b> · pressure {snap.press[sel]?.toFixed(1)} m</div>}
        {!a && !site && ph && snap && ph.kind === "zone" && <div className="ntip">Homes served <b>{(snap.services.zones[sel] * 100).toFixed(0)}%</b></div>}
        {b && (b.devices.length > 0 || b.sites.length > 0) && <div className="nblast">
          <div className="row between"><b>If this is taken over</b><div className="seg2"><button className={blastOn ? "on" : ""} onClick={() => { setState({ blast: true }); showBlast(st, sel); }}>Blast radius</button><button className={!blastOn ? "on" : ""} onClick={() => { setState({ blast: false }); showNodeRoute(st, sel); }}>Way in</button></div></div>
          {b.devices.slice(0, 3).map((n) => <div key={n} className="row between"><span>{nameOf(st, n)}</span><span className="dim">{(b.blast[n] * 100).toFixed(0)}% likely</span></div>)}
          {b.sites.length > 0 && <div className="ntip">Also exposes: {b.sites.slice(0, 3).map((n) => brief(st.physical[n].name).replace(/ \(.*/, "")).join(", ")}{b.sites.length > 3 ? ` +${b.sites.length - 3}` : ""}</div>}
        </div>}
        <div className="row wrap" style={{ gap: 6 }}>
          {a && can(role, "analyst") && <button className="btn small primary" onClick={() => setState({ view: "lab", labStart: sel, side: true })}>Simulate</button>}
          {a && sel !== "INTERNET" && can(role, "operator") && <button className="btn small" onClick={place}>Place decoy</button>}
          {a && fixes.length > 0 && <button className="btn small heal" onClick={() => setFixOpen(!fixOpen)}>{fixOpen ? "Hide fixes" : `Fixes (${fixes.length})`}</button>}
        </div>
        {fixOpen && fixes.slice(0, 3).map((f: any) => <div key={f.id} className="row between" style={{ alignItems: "flex-start" }}><span style={{ fontSize: 12 }}><Move label={f.label} detail={<>Effort {f.cost}</>} /></span>{can(role, "operator") && <button className="btn small heal" onClick={() => api("/api/fix", { body: { id: f.id } }).then(() => toast("ok", "Fix applied")).catch(() => {})}>Apply</button>}</div>)}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ 2D view: the same network as a layered graph that grows as the attack spreads */
const COLS = ["internet", "iot", "it", "dmz", "control", "field", "site"]; const COLN = ["Internet", "Edge", "Office", "Gateway", "Control", "Field", "Sites"];
export function GraphPanel() {
  const st = useStore((s) => s.st), snap = useStore((s) => s.snap), role = useStore((s) => s.role), focus = useStore((s) => s.focus), sel = useStore((s) => s.selected);
  const W = 560, H = 560, padX = 44;
  const lay = useMemo(() => {
    const cols: Record<string, any[]> = {}; for (const a of Object.values<any>(st.assets)) (cols[a.layer] ||= []).push({ id: a.id, name: a.name, layer: a.layer });
    cols.site = Object.values<any>(st.physical).filter((p) => p.kind === "site").map((p) => ({ id: p.id, name: p.name, layer: "site" }));
    const pos: Record<string, { x: number; y: number }> = {};
    COLS.forEach((c, ci) => { const L = cols[c] || []; L.forEach((n, i) => { pos[n.id] = { x: padX + (ci * (W - 2 * padX)) / (COLS.length - 1), y: 56 + ((i + 0.5) * (H - 130)) / Math.max(1, L.length) }; }); });
    return pos;
  }, [st]);
  const adv = new Set<string>(can(role, "analyst") ? (snap.adversary || []).flatMap((c: any) => c.compromised) : []);
  const evid = new Set<string>((snap.incidents || []).filter((i: any) => i.status === "open" || i.status === "contained").flatMap((i: any) => i.evidence_nodes));
  const hot = new Set<string>([...adv, ...evid]); hot.delete("INTERNET");
  const hopEdges = new Set<string>(can(role, "analyst") ? (snap.adversary || []).flatMap((c: any) => c.hops.map((h: any) => h.edge)) : []);
  const blocked = new Set<string>(snap.defence.blocked || []); const fe = new Set<string>(focus?.edges || []);
  const hist = useRef<{ t: number; n: number }[]>([]); const [, force] = useState(0);
  useEffect(() => { const h = hist.current; if (h.length && snap.t < h[h.length - 1].t) h.length = 0; if (!h.length || snap.t !== h[h.length - 1].t) { h.push({ t: snap.t, n: hot.size }); if (h.length > 90) h.shift(); force((x) => x + 1); } }, [snap.t]);
  const sites = Object.values<any>(st.physical).filter((p) => p.kind === "site");
  const siteHit = (p: any) => (p.depends_on || []).some((d: string) => hot.has(d));
  const colOf = (id: string, layer: string) => hot.has(id) ? HOT : snap.nodes?.[id] === "quarantined" ? C.sand : snap.nodes?.[id] === "suspect" ? C.apricot : layer === "site" ? hexc(SECTOR_COL[st.physical[id]?.sector] ?? 0x555) : hexc(LAYER_COL[layer] ?? 0x2F7A84);
  const curve = (a: any, b: any) => `M${a.x},${a.y} Q${(a.x + b.x) / 2},${(a.y + b.y) / 2 + (a.y === b.y ? -18 : 0)} ${b.x},${b.y}`;
  const hh = hist.current; const mx = Math.max(4, ...hh.map((q) => q.n));
  return (
    <div className="graph">
      <div className="gh"><b>2D network view</b><span className="dim">grows red as the attack spreads · tap a device</span><button className="x" aria-label="Close 2D view" onClick={() => setState({ graph: false })}>✕</button></div>
      <svg viewBox={`0 0 ${W} ${H}`} className="gsvg">
        {COLN.map((n, i) => <text key={n} x={padX + (i * (W - 2 * padX)) / (COLS.length - 1)} y={22} textAnchor="middle" className="gcol">{n}</text>)}
        {st.edges.map((e: any) => { const a = lay[e.source], b = lay[e.target]; if (!a || !b) return null; const on = hopEdges.has(e.id) || fe.has(e.id); const bl = blocked.has(e.id);
          return <path key={e.id} d={curve(a, b)} fill="none" stroke={on ? HOT : bl ? C.sand : e.known ? "#C8B09A" : C.apricot} strokeWidth={on ? 3.6 : 1} strokeDasharray={bl ? "3 4" : e.known ? undefined : "4 3"} opacity={on ? 1 : hot.size ? 0.28 : 0.5} className={on ? "flow" : ""} />; })}
        {sites.map((p) => { const q = lay[p.id]; return (p.depends_on || []).map((d: string) => lay[d] && (siteHit(p) && hot.has(d)) ? <path key={p.id + d} d={curve(lay[d], q)} fill="none" stroke={HOT} strokeWidth={2.4} strokeDasharray="5 4" className="flow" /> : null); })}
        {Object.entries(lay).map(([id, q]) => { const a = st.assets[id]; const layer = a ? a.layer : "site"; const isSite = layer === "site"; const c = colOf(id, layer); const bp = focus?.blast?.[id];
          return (
            <g key={id} transform={`translate(${q.x},${q.y})`} onClick={() => pickNode(st, id)} style={{ cursor: "pointer" }}>
              {(hot.has(id) || (isSite && siteHit(st.physical[id]))) && <circle r={15} fill="none" stroke={HOT} strokeWidth={2} className="gping" />}
              {bp !== undefined && <circle r={13} fill="none" stroke={HOT} strokeWidth={1.6} strokeDasharray="3 3" />}
              {isSite ? <rect x={-7} y={-7} width={14} height={14} rx={3} transform="rotate(45)" fill={c} stroke="#fff" strokeWidth={1.5} /> : <circle r={sel === id ? 10 : 8} fill={c} stroke="#fff" strokeWidth={sel === id ? 3 : 1.6} />}
              <text y={isSite ? 20 : 19} textAnchor="middle" className="gnm">{(isSite ? st.physical[id].name : brief(a.name)).replace(/ \(.*/, "").slice(0, 15)}</text>
            </g>); })}
      </svg>
      <div className="gfoot"><div><b>{hot.size}</b><small>devices affected now</small></div>
        <svg viewBox="0 0 100 24" preserveAspectRatio="none" className="gspark"><polyline fill="rgba(225,29,72,.14)" stroke={HOT} strokeWidth="1.2" vectorEffect="non-scaling-stroke" points={hh.length > 1 ? `0,24 ${hh.map((q, i) => `${(i / Math.max(1, hh.length - 1)) * 100},${24 - (q.n / mx) * 22}`).join(" ")} 100,24` : "0,24 100,24"} /></svg>
        <div><b>{sites.filter(siteHit).length}</b><small>Mumbai sites exposed</small></div></div>
    </div>
  );
}

/* ------------------------------------------------------------------ the chosen device, shown at the top of every page */
export function SelectedBar() {
  const sel = useStore((s) => s.selected), st = useStore((s) => s.st), snap = useStore((s) => s.snap), ana = useStore((s) => s.ana), role = useStore((s) => s.role), view = useStore((s) => s.view);
  if (!sel || !st) return <div className="selbar empty"><Ic n="target" /> Click any device on the map and its details appear here, on every page.</div>;
  const a = st.assets[sel], ph = st.physical[sel], d = a || ph; if (!d) return null;
  const row = ana?.ranking?.find((r: any) => r.id === sel); const adv = new Set<string>((snap?.adversary || []).flatMap((c: any) => c.compromised));
  const state = adv.has(sel) ? ["Taken over", "crit"] : snap?.nodes?.[sel] === "suspect" ? ["Suspected", "watch"] : snap?.nodes?.[sel] === "quarantined" ? ["Cut off", "safe"] : ["Normal", "safe"];
  const fixes = (ana?.catalog || []).filter((c: any) => c.target === sel || c.id.endsWith(":" + sel));
  const b = a && sel !== "INTERNET" ? blastOf(st, sel) : null;
  const line = view === "path" ? "Its way in is drawn on the map; the box below says what a takeover would cost." : view === "fix" ? (fixes.length ? `${fixes.length} fix${fixes.length === 1 ? "" : "es"} available for this device.` : "No single fix targets this device.") : view === "lab" ? "Press Simulate to see what an attacker could reach from here." : view === "defend" || view === "zeroday" ? `Right now: ${state[0].toLowerCase()}.` : view === "predict" ? "See how likely it is to be attacked next below." : b ? `If taken over it could reach ${b.devices.length} other device${b.devices.length === 1 ? "" : "s"}${b.sites.length ? ` and ${b.sites.length} Mumbai site${b.sites.length === 1 ? "" : "s"}` : ""}.` : "";
  return (
    <div className="selbar">
      <div className="row between"><b style={{ fontSize: 13.5, overflowWrap: "anywhere" }}>{brief(d.name)}</b><button className="x" aria-label="Clear selection" onClick={() => setState({ selected: null, focus: null })}>✕</button></div>
      <div className="row wrap" style={{ gap: 5 }}>{a && <span className={"pill " + state[1]}>{state[0]}</span>}{row && <span className="pill info">priority #{row.rank_sar}</span>}{row && <span className="pill info">harm {k(row.raw)}</span>}</div>
      {line && <div className="dim" style={{ fontSize: 12 }}>{line}</div>}
      <div className="row wrap" style={{ gap: 6 }}>
        {view === "fix" && can(role, "operator") && fixes.slice(0, 2).map((f: any) => <button key={f.id} className="btn small heal" onClick={() => api("/api/fix", { body: { id: f.id } }).then(() => toast("ok", "Fix applied")).catch(() => {})}>{plainMove(f.label).title.slice(0, 34)}</button>)}
        {a && can(role, "analyst") && view !== "lab" && <button className="btn small" onClick={() => setState({ view: "lab", labStart: sel, side: true })}>Simulate</button>}
        {a && sel !== "INTERNET" && can(role, "operator") && (view === "defend" || view === "zeroday") && <button className="btn small" onClick={() => api("/api/decoy", { body: { node: sel } }).then(() => { toast("ok", "Decoy placed"); setState({ xray: true }); }).catch(() => {})}>Place decoy</button>}
      </div>
    </div>
  );
}
