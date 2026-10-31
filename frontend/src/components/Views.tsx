import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { setState, toast, useStore } from "../store";
import { C, riskColor } from "../palette";
import { Bars, fmt, Gantt, Heartbeat, Hist, k, LineChart, Ring, RiskTrio, Slope, Timeline } from "./Charts";
import { Box, Check, Ic, Num, PageHead, Stat, Steps, Switch } from "./ui";
import { brief, can, nameOf, plainFix, statusOf } from "./status";

export { can };
const ctrlTarget = (st: any, ctrl: string) => { const a: any = Object.values(st.actions).find((x: any) => x.controller === ctrl); if (!a) return null; return a.kind === "breaker_open" ? "CB_" + a.target : a.target; };
const actionOf = (st: any, ctrl: string) => Object.entries(st.actions).find(([, x]: any) => x.controller === ctrl)?.[0] as string | undefined;
const cut = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1).trimEnd() + "…" : s);
const mmss = (m: number) => `${Math.floor(m / 60)}:${String(m % 60).padStart(2, "0")}`;

export function setPath(st: any, nodes: string[], edges: string[], kind: "attack" | "predicted") {
  const last = nodes[nodes.length - 1]; const ph = ctrlTarget(st, last);
  setState({ pathSel: { nodes: ph ? [...nodes, ph] : nodes, edges, kind, ctrl: last } });
}

/* ================================================================== OVERVIEW */
export function CityView() {
  const ana = useStore((s) => s.ana), snap = useStore((s) => s.snap), st = useStore((s) => s.st);
  const sv = snap.services; const hosp = Object.values<any>(sv.hospitals); const hOk = hosp.filter((h) => h.ok).length; const fOk = Object.values<boolean>(sv.feeders).filter(Boolean).length;
  const stt = statusOf(snap); const rank = ana?.ranking || [];
  return (
    <>
      <PageHead icon="city" title="City now" sub="Is the ward safe right now?" right={<span className={"pill " + stt.tone + (stt.key === "attack" ? " pulse" : "")}>{stt.label}</span>} />
      <Box id="svc" title="Service" icon="home" value={`${(sv.served_frac * 100).toFixed(1)}% homes`} tone={sv.served_frac > 0.99 ? "safe" : sv.served_frac > 0.9 ? "watch" : "crit"} defaultOpen>
        <div className="row" style={{ gap: 14 }}>
          <Ring value={sv.served_frac} size={74} stroke={9} color={sv.served_frac > 0.99 ? C.aquaD : sv.served_frac > 0.9 ? C.apricot : C.terra}><Num v={sv.served_frac * 100} d={1} suffix="%" /></Ring>
          <div className="grid2 grow"><Stat v={`${hOk}/${hosp.length}`} l="hospitals with water" color={hOk === hosp.length ? C.aquaD : C.terra} /><Stat v={`${fOk}/3`} l="power feeders on" color={fOk === 3 ? C.aquaD : C.terra} /></div>
        </div>
        <div className="tip">{fmt(sv.households_served)} of {fmt(sv.households_total)} homes have water and power.</div>
      </Box>
      <Box id="weak" title="Weakest points" icon="shield" value={rank[0] ? cut(brief(rank[0].name), 16) : "…"} tone="watch" defaultOpen>
        {rank.length ? <>
          <div className="tip">If hacked, these hurt the most people. Tap one to see it on the map.</div>
          {rank.slice(0, 5).map((r: any) => (
            <div key={r.id} className="list-row" onClick={() => setState({ selected: r.id })}>
              <div className="grow"><div className="row between" style={{ fontSize: 13 }}><b>{cut(brief(r.name), 26)}</b><span className="dim">{k(r.rrw)}</span></div>
                <div className="bar" style={{ marginTop: 5 }}><div style={{ width: `${(r.rrw / rank[0].rrw) * 100}%`, background: riskColor(r.rrw / rank[0].rrw) }} /></div></div>
            </div>))}
        </> : <div className="tip"><Ic n="clock" cls="spin" /> Calculating risk with the water and power simulator…</div>}
      </Box>
      <Box id="legend" title="Colour guide" icon="eye">
        <div className="row wrap"><span className="pill safe">safe / water</span><span className="pill watch">watch / power</span><span className="pill crit">attacker / danger</span></div>
        <div className="tip">Shapes above the city are computers. Pipes and wires below are the real water and power network.</div>
      </Box>
    </>
  );
}

/* ================================================================== PATHS */
export function PathView() {
  const ana = useStore((s) => s.ana), st = useStore((s) => s.st), sel = useStore((s) => s.pathSel), role = useStore((s) => s.role);
  const [tl, setTl] = useState<any>(null); const [start, setStart] = useState(6); const [breach, setBreach] = useState("WIFI_PUB_01");
  const goalAct = sel ? actionOf(st, sel.ctrl) : null;
  useEffect(() => { if (goalAct) api(`/api/timeline?actions=${goalAct}&start=${start}`).then(setTl).catch(() => setTl(null)); else setTl(null); }, [goalAct, start]);
  useEffect(() => { if (!sel && ana?.paths?.[0]) { const p = ana.paths[0]; setPath(st, p.nodes, p.edges, "attack"); } }, [ana?.paths]);
  const best = useMemo(() => assumeBreach(st, breach), [st, breach]);
  const paths: any[] = ana?.paths || [];
  return (
    <>
      <PageHead icon="route" title="Attack paths" sub="How a hacker could reach water or power" right={<span className="pill info">{paths.length} routes</span>} />
      <Box id="routes" title="Most dangerous routes" icon="route" value="tap to show" defaultOpen>
        {paths.map((p, i) => {
          const on = sel?.nodes?.[1] === p.nodes[1] && sel?.ctrl === p.nodes[p.nodes.length - 1];
          return (
            <div key={i} className={"list-row" + (on ? " on" : "")} style={{ alignItems: "flex-start" }} onClick={() => setPath(st, p.nodes, p.edges, "attack")}>
              <span className="num-chip">{i + 1}</span>
              <div className="grow"><div style={{ fontSize: 13, fontWeight: 700 }}>{cut(nameOf(st, p.nodes[1]), 18)} → {cut(nameOf(st, p.nodes[p.nodes.length - 1]), 20)}</div>
                <div className="dim" style={{ fontSize: 11.5 }}>{p.nodes.length - 1} steps · harm {k(p.weight)}</div></div>
            </div>);
        })}
        {!paths.length && <div className="tip"><Ic n="clock" cls="spin" /> Finding routes…</div>}
        {sel && <div className="col" style={{ gap: 5, marginTop: 4 }}>
          <b style={{ fontSize: 12 }}>The route on the map</b>
          {sel.nodes.map((n: string, i: number) => <div key={n + i} className="row" style={{ gap: 8, fontSize: 12.5 }}><span className={"num-chip" + (i === sel.nodes.length - 1 ? " aqua" : "")} style={{ width: 20, height: 20, fontSize: 11 }}>{i === sel.nodes.length - 1 ? "!" : i + 1}</span>{nameOf(st, n)}</div>)}
        </div>}
      </Box>
      {sel && goalAct && (
        <Box id="what" title="What it would do" icon="water" value={tl ? `${k(tl.result.hh_h)} home-hours` : "…"} tone="crit" defaultOpen>
          <div className="tip">{st.actions[goalAct].label}</div>
          <div className="row between" style={{ fontSize: 12.5 }}><span>Attack starts at</span><b>{String(start).padStart(2, "0")}:00</b></div>
          <input type="range" min={0} max={23} value={start} onChange={(e) => setStart(+e.target.value)} aria-label="Attack start hour" />
          <Timeline data={tl} />
          {tl && <div className="grid3"><Stat v={k(tl.result.hh_h)} l="home-hours dry" /><Stat v={tl.result.hosp_water_h.toFixed(1)} l="hospital hours" /><Stat v={tl.result.mwh.toFixed(1)} l="MWh lost" /></div>}
        </Box>)}
      <Box id="breach" title="If a device is already hacked" icon="mask" value="try it">
        <select value={breach} onChange={(e) => setBreach(e.target.value)} aria-label="Hacked device">{Object.values<any>(st.assets).filter((a) => a.layer !== "field" && a.id !== "INTERNET").map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}</select>
        {best ? <>
          <div className="tip">{best.hops} steps to a controller · success chance {(best.p * 100).toFixed(1)}%</div>
          <div className="row"><button className="btn small primary" onClick={() => setPath(st, best.nodes, best.edges, "attack")}>Show on map</button>
            {can(role, "operator") && best.cut && <button className="btn small heal" onClick={() => api("/api/fix", { body: { id: best.cut } }).then(() => toast("ok", "Link closed"))}>Cut weakest link</button>}</div>
        </> : <div className="tip">No route to a controller from here.</div>}
      </Box>
    </>
  );
}

function assumeBreach(st: any, start: string) {
  const cv = st.threat_snapshot.cves; const A = st.assets; const FLOOR: any = { iot: 0.15, it: 0.15, dmz: 0.2, control: 0.3, field: 0.3 };
  const pn = (id: string) => { const a = A[id]; const c = cv[a.cve || ""]; const ex = c ? (c.in_kev ? Math.max(c.epss, 0.6) : c.epss) : 0; const pc = (1 - a.p_patched) * ex * (a.known_version ? 1 : a.cve_belief); return 1 - (1 - pc) * (1 - a.p_weak) * (1 - (FLOOR[a.layer] || 0)); };
  const dist: any = { [start]: 0 }, prev: any = {}, q = [start]; const targets = Object.values<any>(A).filter((a) => a.layer === "field").map((a) => a.id);
  while (q.length) { q.sort((a, b) => dist[a] - dist[b]); const u = q.shift()!; for (const e of st.edges) { if (e.source !== u) continue; const p = Math.max(1e-3, e.p_access * (e.known ? 1 : e.belief) * pn(e.target)); const nd = dist[u] - Math.log(p); if (nd < (dist[e.target] ?? 1e9)) { dist[e.target] = nd; prev[e.target] = e; q.push(e.target); } } }
  const goal = targets.filter((t) => dist[t] !== undefined).sort((a, b) => dist[a] - dist[b])[0]; if (!goal) return null;
  const nodes = [goal], edges: string[] = []; let v = goal; while (v !== start) { const e = prev[v]; edges.unshift(e.id); v = e.source; nodes.unshift(v); }
  const weakest = edges.map((id) => st.edges.find((e: any) => e.id === id)).filter((e: any) => !e.known || e.misconfig).sort((a: any, b: any) => a.p_access - b.p_access)[0];
  return { nodes, edges, hops: edges.length, p: Math.exp(-dist[goal]), cut: weakest ? "cl:" + weakest.id : null };
}

/* ================================================================== FIX */
export function FixView() {
  const ana = useStore((s) => s.ana), role = useStore((s) => s.role);
  const [what, setWhat] = useState<any>(null); const [picked, setPicked] = useState<string[]>([]);
  const toggle = (id: string) => setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]));
  useEffect(() => { if (picked.length && can(role, "analyst")) api(`/api/whatif?fix=${picked.join(",")}`).then(setWhat).catch(() => setWhat(null)); else setWhat(null); }, [picked.join(",")]);
  if (!ana?.plan) return <><PageHead icon="wrench" title="Fix plan" sub="What to fix first" /><div className="box"><div className="body" style={{ padding: 14 }}><div className="tip"><Ic n="clock" cls="spin" /> Building the plan…</div></div></div></>;
  const refused = ana.plan.refused || []; const voi = (ana.voi || []).slice(0, 3);
  const b = ana.baseline, n = ana.summary, a = ana.after_plan;
  return (
    <>
      <PageHead icon="wrench" title="Fix plan" sub="What to fix first, and how much safer it makes us" right={<span className="pill safe">▼ {Math.round((1 - a.sar99 / Math.max(1, n.sar99)) * 100)}% risk</span>} />
      <Box id="trio" title="Risk before · now · after" icon="shield" value={`${k(n.sar99)} → ${k(a.sar99)}`} tone="safe" defaultOpen>
        <RiskTrio unit="Worst-case service lost: 99 of 100 simulated attacks stay below this" rows={[{ label: "Before", sub: "no fixes ever", value: b.sar99, color: C.terra }, { label: "Now", sub: "today", value: n.sar99, color: C.apricot }, { label: "After", sub: "if the plan is done", value: a.sar99, color: C.aquaD }]} />
        <div className="grid3"><Stat v={`${(b.p_any * 100).toFixed(0)}%`} l="chance of harm · before" color={C.terra} /><Stat v={`${(n.p_any * 100).toFixed(0)}%`} l="now" color={C.apricot} /><Stat v={`${(a.p_any * 100).toFixed(1)}%`} l="after plan" color={C.aquaD} /></div>
      </Box>
      <Box id="plan" title="Do these first" icon="wrench" value={`${ana.plan.steps.length} steps`} defaultOpen>
        {ana.plan.steps.slice(0, 6).map((s: any, i: number) => (
          <div key={s.fix.id} className="list-row" style={{ cursor: "default" }}>
            <span className="num-chip">{i + 1}</span>
            <div className="grow"><div style={{ fontSize: 13, fontWeight: 700 }}>{cut(plainFix(s.fix.label), 40)}</div><div className="dim" style={{ fontSize: 11.5 }}>saves {k(s.gain)} · {s.downtime_loss ? "small outage " + k(s.downtime_loss) : "no outage"}</div></div>
            <div className="col" style={{ gap: 4 }}>
              <button className={"btn small" + (picked.includes(s.fix.id) ? " primary" : "")} onClick={() => toggle(s.fix.id)}>{picked.includes(s.fix.id) ? "✓ preview" : "preview"}</button>
              {can(role, "operator") && <button className="btn small heal" onClick={() => api("/api/fix", { body: { id: s.fix.id } }).then(() => toast("ok", "Fix applied"))}>Apply</button>}
            </div>
          </div>))}
      </Box>
      {what && (
        <Box id="preview" title="Preview of your picks" icon="eye" value={`${k(what.before.sar99)} → ${k(what.after.sar99)}`} tone="safe" kind="good" defaultOpen>
          <Bars rows={[{ label: "Worst case now", value: what.before.sar99, color: C.apricot }, { label: "Worst case after", value: what.after.sar99, color: C.aquaD }]} />
          <div className="tip">Outage from doing them at the best time: <b>{what.downtime_loss ? k(what.downtime_loss) : "none"}</b></div>
        </Box>)}
      {refused.length > 0 && (
        <Box id="refused" title="Not now (unsafe)" icon="x" value={refused.length} tone="watch">
          {refused.slice(0, 4).map((r: any, i: number) => <div key={i}><b style={{ fontSize: 12.5 }}>{cut(r.fix.label, 48)}</b><div className="tip">{cut(r.reason, 110)}</div></div>)}
        </Box>)}
      <Box id="sched" title="Best time to patch" icon="clock" value="Sundays 02:00"><Gantt rows={ana.schedule} /><div className="tip">Amber = small outage. Restarts never share a window if both would stop service.</div></Box>
      <Box id="ask" title="Missing facts" icon="question" value={voi.length ? `${voi.length} questions` : "none"} tone={voi.length ? "watch" : "safe"}>
        {ana.voi_computing && <div className="tip"><Ic n="clock" cls="spin" /> Working out which question matters most…</div>}
        {voi.map((v: any, i: number) => (
          <div key={v.id} className={"list-row" + (i === 0 ? " on" : "")} style={{ cursor: "default", flexDirection: "column", alignItems: "stretch" }}>
            <b style={{ fontSize: 13 }}>{v.text}</b><div className="dim" style={{ fontSize: 11.5 }}>Answering could improve the plan by about {k(v.voi)}.</div>
            {can(role, "operator") && <div className="row" style={{ marginTop: 4 }}><button className="btn small heal" onClick={() => api("/api/answer", { body: { uid: v.id, yes: true } }).then(() => toast("ok", "Thanks, plan updated"))}>Yes</button><button className="btn small" onClick={() => api("/api/answer", { body: { uid: v.id, yes: false } }).then(() => toast("ok", "Thanks, plan updated"))}>No</button></div>}
          </div>))}
      </Box>
      <Box id="hist" title="Risk spread" icon="chart" value="drag"><Hist base={ana.hist_base} now={ana.hist_now} after={ana.hist_after} /></Box>
    </>
  );
}

/* ================================================================== DEFEND */
const ATTACKS: [string, string][] = [["standard", "Known exploit"], ["spoof", "Fake sensor readings"], ["wear", "Breaker wear"], ["insider", "Insider with vendor login"]];
const STAGE_LABELS = ["Detected", "Predicted", "Cut", "Verified", "Recovered"]; const STAGE_KEYS = ["Detected", "Predicted route", "Cut made", "Verified", "Recovered"];

export function DefendView() {
  const snap = useStore((s) => s.snap), st = useStore((s) => s.st), role = useStore((s) => s.role), hist = useStore((s) => s.hist);
  const [mode, setMode] = useState("standard"); const [entry, setEntry] = useState(""); const [goal, setGoal] = useState("");
  const stt = statusOf(snap); const incs = snap.incidents || []; const inc = [...incs].reverse().find((i: any) => i.status !== "reported") || null;
  const props = (snap.proposals || []).filter((p: any) => p.status === "pending");
  const entries = Object.values<any>(st.assets).filter((a) => a.entry_weight > 0); const goals = Object.values<any>(st.actions);
  const cutN = (snap.defence.quarantined?.length || 0) + (snap.defence.blocked?.length || 0); const total = Object.keys(st.assets).length - 1;
  const w = snap.watch; const h = hist.slice(-120); const live = inc && inc.status !== "reported";
  const done = (() => { if (!live) return 0; let n = 0; for (const key of STAGE_KEYS) { if (inc.stages.some((x: any) => x.stage === key)) n++; else break; } return n; })();
  const evs = (snap.events || []);
  const [feed, setFeed] = useState<any[]>([]);
  useEffect(() => { if (evs.length) setFeed((f) => [...evs.filter((e: any) => !e.hidden || can(role, "analyst")).map((e: any) => ({ ...e })).reverse(), ...f].slice(0, 8)); }, [snap.t]);
  return (
    <>
      <PageHead icon="shield" title="Live defence" sub="Watch DECOY stop an attack" right={<span className={"pill " + stt.tone + (stt.key === "attack" ? " pulse" : "")}>{stt.label}</span>} />
      <div className={"hero " + stt.tone}>
        <div className="row between"><div className="big">{stt.label}</div>{live && inc.status !== "resolved" && <div className="row" title="CERT-In: report within 6 hours"><Ring value={inc.left_min} max={360} size={44} stroke={5} color={C.terra}>{Math.floor(inc.left_min / 60)}h</Ring></div>}</div>
        <div style={{ fontSize: 13, margin: "3px 0 10px", maxWidth: "82%" }}>{stt.line}</div>
        {stt.key === "healing" && <div className="heal-anim"><span /><span /><span /><div className="core"><Ic n="shield" /></div></div>}
        {stt.key === "recovered" && <div className="row" style={{ gap: 8, fontWeight: 800 }}><Check /> Service restored</div>}
        {live && stt.key !== "recovered" && <Steps labels={STAGE_LABELS} done={done} attack={stt.key === "attack"} />}
      </div>
      {can(role, "analyst") && (
        <Box id="launch" title="Simulate an attack" icon="bolt" value={snap.autopilot ? "autopilot on" : "manual"} defaultOpen>
          <select value={mode} onChange={(e) => setMode(e.target.value)} aria-label="Attack type">{ATTACKS.map(([m, t]) => <option key={m} value={m}>{t}</option>)}</select>
          <button className="btn primary big" onClick={() => api("/api/attack", { body: { mode, entry: entry || null, goal: goal || null } }).then(() => toast("warn", "Attack launched (simulation)"))}>Launch attack</button>
          <div className="row between"><span style={{ fontSize: 12.5 }}>Attacks by themselves</span>{can(role, "operator") ? <Switch on={!!snap.autopilot} label="Autopilot adversary" onChange={() => api("/api/autopilot", { body: { on: !snap.autopilot } })} /> : <span className="pill info">{snap.autopilot ? "on" : "off"}</span>}</div>
          <details><summary className="tip" style={{ cursor: "pointer" }}>Choose entry and target</summary>
            <div className="col" style={{ marginTop: 6 }}><select value={entry} onChange={(e) => setEntry(e.target.value)} aria-label="Entry"><option value="">Entry: any exposed device</option>{entries.map((a: any) => <option key={a.id} value={a.id}>{a.name}</option>)}</select>
              <select value={goal} onChange={(e) => setGoal(e.target.value)} aria-label="Target"><option value="">Target: any controller</option>{goals.map((a: any) => <option key={a.controller} value={a.controller}>{a.label}</option>)}</select></div></details>
        </Box>)}
      {props.map((p: any) => (
        <Box key={p.id} id={"prop" + p.id} title="Needs your OK" icon="check" value={`saves ${k(Math.max(0, p.observe_J - p.plan_J))}`} tone="watch" kind="warm" defaultOpen>
          {p.steps.map((s: any, i: number) => <div key={i} className="row" style={{ fontSize: 12.5 }}><span className="num-chip aqua" style={{ width: 20, height: 20, fontSize: 11 }}>{i + 1}</span><span className="grow">{cut(plainFix(s.label), 52)}</span>{s.safety?.ok && <span className="pill safe">safe</span>}</div>)}
          <div className="grid3"><Stat v={k(p.observe_J)} l="do nothing" color={C.terra} /><Stat v={k(p.plan_J)} l="this plan" color={C.aquaD} /><Stat v={k(p.isolate_all_J)} l="cut everything" color={C.apricot} /></div>
          {can(role, "operator") && <div className="row"><button className="btn heal grow" onClick={() => api(`/api/proposal/${p.id}/approve`, { method: "POST" }).then((r) => toast(r.status === "awaiting_second" ? "warn" : "ok", r.status === "awaiting_second" ? "A second person must approve" : "Plan applied"))}>Approve</button><button className="btn danger" onClick={() => api(`/api/proposal/${p.id}/reject`, { method: "POST" })}>Reject</button></div>}
        </Box>))}
      {live && (inc.actions.length > 0 || inc.next_hops?.length > 0) && (
        <Box id="did" title="What DECOY did" icon="check" value={`${inc.actions.length} actions`} tone="safe" defaultOpen>
          {inc.actions.map((a: any, i: number) => <div key={i} className="row" style={{ fontSize: 12.5 }}><span style={{ color: C.aquaD }}><Check /></span><span className="grow">{cut(plainFix(a.label), 56)}</span></div>)}
          {inc.next_hops?.length > 0 && <><b style={{ fontSize: 12 }}>Where it may go next</b>{inc.next_hops.slice(0, 2).map((n: any) => <div key={n.edge} className="row"><span style={{ width: 130, fontSize: 12 }}>{cut(nameOf(st, n.dst), 18)}</span><div className="bar grow"><div style={{ width: `${n.p * 100}%`, background: C.apricot }} /></div><b style={{ width: 34, textAlign: "right", fontSize: 12 }}>{(n.p * 100).toFixed(0)}%</b></div>)}</>}
        </Box>)}
      <Box id="kept" title="Service kept" icon="home" value={`${cutN} of ${total} cut off`} tone="safe" defaultOpen>
        <LineChart h={110} series={[{ name: "DECOY", color: C.aquaD, data: h.map((x) => x.live), width: 3.4 }, { name: "No response", color: C.terra, data: h.map((x) => x.none), dash: "5 4" }, { name: "Cut everything", color: C.apricot, data: h.map((x) => x.iso), dash: "2 4" }]} />
        <div className="grid3"><Stat v={(snap.services.served_frac * 100).toFixed(1) + "%"} l="DECOY" color={C.aquaD} /><Stat v={(snap.compare.none_served * 100).toFixed(1) + "%"} l="no response" color={C.terra} /><Stat v={(snap.compare.iso_served * 100).toFixed(1) + "%"} l="cut everything" color={C.apricot} /></div>
        <div className="tip">Homes served over time. DECOY cuts only what is needed.</div>
      </Box>
      <Box id="why" title="Why the alarm rang" icon="eye" value={`${(w.p * 100).toFixed(0)}%`} tone={w.p > 0.85 ? "crit" : w.p > 0.4 ? "watch" : "safe"}>
        <Heartbeat data={h.map((x) => x.p)} h={46} color={w.p > 0.85 ? C.terra : C.aquaD} thr={0.85} />
        <div className="grid3"><Stat v={w.ae?.toFixed?.(1) ?? "–"} l="odd traffic" /><Stat v={w.novelty} l="new links" /><Stat v={w.phys_z} l="physics score" /></div>
        {w.violations?.map((v: any, i: number) => <div key={i} className="pill crit" style={{ whiteSpace: "normal" }}>⚠ {cut(v.text, 90)}</div>)}
        {!w.violations?.length && <div className="tip">Two checks run together: network behaviour and the laws of physics.</div>}
      </Box>
      <Box id="feed" title="Latest events" icon="clock" value={feed.length}>
        {feed.map((e) => <div key={e.id} className="row" style={{ fontSize: 12.5, alignItems: "flex-start" }}><i style={{ width: 8, height: 8, borderRadius: "50%", marginTop: 5, flex: "none", background: e.sev === "crit" ? C.terra : e.sev === "warn" ? C.apricot : e.sev === "ok" ? C.aquaD : C.sand }} />{cut(e.text, 96)}</div>)}
        {!feed.length && <div className="tip">Nothing yet.</div>}
      </Box>
    </>
  );
}

/* ================================================================== PROOF */
export function ProofView() {
  const ana = useStore((s) => s.ana), exp = useStore((s) => s.exp);
  const rows = ana?.ranking || []; const E = exp || {}; const keys = Object.keys(E).filter((x) => x !== "_meta").sort((a, b) => parseInt(a.slice(1)) - parseInt(b.slice(1)));
  const met = keys.filter((x) => E[x].met).length;
  const [open, setOpen] = useState<string | null>(null);
  return (
    <>
      <PageHead icon="chart" title="Proof" sub="Does it really work? Measured in simulation" right={keys.length ? <span className="pill safe">{met} of {keys.length} goals met</span> : undefined} />
      <Box id="slope" title="Severity is not risk" icon="swap" value={ana ? `${ana.reversals} devices move` : "…"} defaultOpen>
        <Slope rows={rows} onPick={(id) => setState({ selected: id })} />
        <div className="tip">Left: the old score. Right: people actually harmed. Red lines moved up a lot.</div>
      </Box>
      <Box id="tests" title="Our tests" icon="check" value={`${met} met · ${keys.length - met} missed`} tone={met === keys.length ? "safe" : "watch"} defaultOpen>
        <div className="tip">Targets were written before the tests ran. Misses are shown too.</div>
        {keys.map((key) => { const e = E[key]; const isOpen = open === key; return (
          <div key={key} className="list-row" style={{ flexDirection: "column", alignItems: "stretch", cursor: "default" }}>
            <div className="row" style={{ cursor: "pointer" }} onClick={() => setOpen(isOpen ? null : key)}>
              <span className={"pill " + (e.met ? "safe" : e.met === false ? "crit" : "info")}>{e.met ? "✓" : e.met === false ? "✗" : "–"} {key}</span>
              <span className="grow" style={{ fontSize: 12.5, fontWeight: 600 }}>{cut(String(e.claim), 60)}</span><Ic n="chevron" cls="chev" />
            </div>
            {isOpen && <div className="col" style={{ marginTop: 8 }}><div className="dim" style={{ fontSize: 11.5 }}>Target: {e.target}</div><ExpBody k={key} e={e} /></div>}
          </div>); })}
        {!keys.length && <div className="tip">Run backend/experiments.py first.</div>}
      </Box>
    </>
  );
}

function ExpBody({ k: key, e }: any) {
  const r = e.result; if (!r) return null;
  const T = (rows: [string, any][]) => <table><tbody>{rows.map(([a, b]) => <tr key={a}><td>{a}</td><td><b>{String(b)}</b></td></tr>)}</tbody></table>;
  if (key === "E1") return T(Object.entries(r).map(([n, v]: any) => [n, `Spearman ${v.spearman} · top-10 overlap ${v.top10_overlap}/10`]));
  if (key === "E2") return <><div className="tip">{r.devices_moved_over_10} devices moved over 10 places.</div>{T(r.examples.slice(0, 4).map((x: any) => [x.device, `CVSS #${x.cvss_rank} → harm #${x.sar_rank}`]))}</>;
  if (key === "E3") return <Bars rows={[{ label: "No fixes", value: r.baseline_loss, color: C.terra }, { label: "Random plan", value: r.random_mean, color: C.apricot }, { label: "CVSS-first", value: r.cvss_first, color: C.sand }, { label: "Our plan", value: r.greedy, color: C.aquaD }, { label: "Best possible", value: r.exhaustive_best, color: C.aquaM }]} />;
  if (key === "E4") return T([["With outage cost: total", `${k(r.with_downtime_term.total)}`], ["Ignoring outage: total", `${k(r.ignoring_downtime.total)}`]]);
  if (key === "E5") return T(Object.entries(r).map(([n, v]: any) => [n, v.value_of_information !== undefined ? `VoI ${k(v.value_of_information)} · random ${k(v.random_mean)}` : `residual ${k(v.residual)}`]));
  if (key === "E6") return T([["Coverage (target 0.90)", r.coverage], ["Spearman, unseen attacks", r.spearman], ["Speed-up", `${fmt(r.speedup)}×`]]);
  if (key === "E7") return T(r.n_kev_cves_with_history ? [["KEV CVEs tested", r.n_kev_cves_with_history], ["EPSS ≥ 0.1 before listing", `${(r.frac_epss_ge_0_1 * 100).toFixed(0)}%`]] : [["note", r.note]]);
  if (key === "E8") return T(Object.entries(r).map(([n, v]: any) => [n, `top-10 overlap ${v.top10_overlap}/10`]));
  if (key === "E9") return <><Bars rows={[{ label: "DECOY", value: r.mean_loss_decoy, color: C.aquaD }, { label: "No response", value: r.mean_loss_no_response, color: C.terra }, { label: "Cut everything", value: r.mean_loss_isolate_all, color: C.apricot }]} />{T([["Scenarios", r.scenarios], ["Detected", r.detected_pct + "%"], ["Devices cut: DECOY vs all", `${r.mean_devices_disconnected_decoy} vs ${r.devices_disconnected_isolate_all}`]])}</>;
  if (key === "E10") return T(Object.entries(r.detection).map(([n, v]: any) => [n, `fused ${v["fused (network + physics)"].detected} · network ${v["network only"].detected} · physics ${v["physics only"].detected}`]));
  if (key === "E11") return T(r.runs.map((x: any) => [`${fmt(x.nodes)} nodes`, `${x.seconds}s · ${x.mem_mb} MB`]));
  if (key === "E12") return T([["Unsafe actions blocked", r.candidate_actions_blocked_in_scenarios], ["Times a response hurt a hospital", r.scenarios_where_response_made_hospital_worse]]);
  if (key === "E13") return T([["Attacker hops with / without decoys", `${r.mean_attacker_hops_with_decoys} / ${r.mean_attacker_hops_without_decoys}`], ["Loss with / without", `${k(r.mean_loss_with)} / ${k(r.mean_loss_without)}`]]);
  if (key === "E15" && r.policies) return T(Object.entries<any>(r.policies).map(([n, v]) => [n, `cost ${k(v.mean_total)} · cut ${v.devices_cut.toFixed(1)}`]));
  return <div className="tip">{cut(JSON.stringify(r), 220)}</div>;
}

/* ================================================================== SAFETY (CERT-In + security) */
const CH = [["4.4 / 5", "Segmentation", "Healer isolates only one cluster"], ["6", "Logins and MFA", "TOTP, Argon2id, roles, lock-out"], ["8.5 / 12", "Logs + 6-hour report", "Log Vault + 6-hour clock"], ["10.1", "Humans decide", "Autonomy dial, two-person rule"], ["13", "API safety", "Validation, rate limit, no public schema"], ["15 / 16", "Incident response", "Detect → contain → verify → recover"], ["17", "Supply chain", "SBOM reader, vendor-VPN fix"], ["18 / 19", "Tests and audits", "Red-team console, audit dates"]];

export function SafetyView() {
  const tab = useStore((s) => s.safetyTab);
  return (
    <>
      <PageHead icon="lock" title="Safety" sub="CERT-In rules and our own security" />
      <div className="seg"><button className={tab === "certin" ? "on" : ""} onClick={() => setState({ safetyTab: "certin" })}>CERT-In</button><button className={tab === "security" ? "on" : ""} onClick={() => setState({ safetyTab: "security" })}>Security</button></div>
      {tab === "certin" ? <CertIn /> : <Security />}
    </>
  );
}

function CertIn() {
  const role = useStore((s) => s.role);
  const [c, setC] = useState<any>(null);
  useEffect(() => { const f = () => { if (!document.hidden) api("/api/compliance").then(setC).catch(() => {}); }; f(); const t = setInterval(f, 5000); return () => clearInterval(t); }, []);
  if (!c) return <div className="tip"><Ic n="clock" cls="spin" /> Loading…</div>;
  const dl = async (id: string) => { const r = await api(`/api/incident/${id}/report`); const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `${id}_CERT-In_report.json`; a.click(); await api(`/api/incident/${id}/reported`, { method: "POST" }); toast("ok", "Report exported"); };
  return (
    <>
      <Box id="clock" title="6-hour report clock" icon="clock" value={c.clocks.length ? `${c.clocks.length} incident(s)` : "none open"} tone={c.clocks.length ? "watch" : "safe"} defaultOpen>
        {c.clocks.length === 0 && <div className="tip">No incidents yet. Launch one in Defend.</div>}
        {c.clocks.map((i: any) => <div key={i.id} className="row between"><div><b>{i.id}</b> <span className="pill info">{i.status}</span><div className="dim" style={{ fontSize: 11.5 }}>detected {i.clock0}</div></div>
          <div className="row"><Ring value={i.left_min} max={360} size={46} stroke={5} color={C.terra}>{mmss(i.left_min)}</Ring>{can(role, "operator") && <button className="btn small primary" disabled={i.reported} onClick={() => dl(i.id)}>{i.reported ? "Reported" : "Export"}</button>}</div></div>)}
      </Box>
      <Box id="logs" title="Logs and clocks" icon="doc" value={c.chain.ok ? "intact" : "BROKEN"} tone={c.chain.ok ? "safe" : "crit"} defaultOpen>
        <div className="grid2"><Stat v={`${c.vault.days_held}/${c.vault.retention_days} d`} l={`${c.vault.written} events kept in India`} /><Stat v={c.chain.checked} l="entries hash-chained" color={c.chain.ok ? C.aquaD : C.terra} /></div>
        <div className="row between"><span className={"pill " + (c.time.ok ? "safe" : "crit")}>{c.time.ok ? "all clocks in sync" : "clock drift"}</span>{can(role, "operator") && <div className="row"><button className="btn small" onClick={() => api("/api/timeguard", { body: { source: "SCADA_SRV", seconds: 42 } })}>Skew a clock</button><button className="btn small" onClick={() => api("/api/timeguard", { body: { source: "SCADA_SRV", seconds: 0 } })}>Fix</button></div>}</div>
        {Object.entries(c.time.drifting).map(([s, v]: any) => <div key={s} className="tip">⚠ {s} is {v}s off. Its events are marked uncertain.</div>)}
      </Box>
      <Box id="local" title="Local threats" icon="eye" value={c.threat_patterns.region}><div className="tip">{c.threat_patterns.malware}. Top weakness: <b>{c.threat_patterns.weakness}</b>.</div>
        {c.misconfigurations.slice(0, 4).map((m: any) => <div key={m.edge} className="row between" style={{ fontSize: 12 }}><span>{cut(m.text, 46)}</span><span className={"pill " + (m.known ? "info" : "watch")}>{m.known ? "known" : "hidden"}</span></div>)}</Box>
      <Box id="sbom" title="Supply chain and audits" icon="doc" value={`${(c.sbom_coverage * 100).toFixed(0)}% SBOM`}><div className="grid2"><Stat v={`${(c.sbom_coverage * 100).toFixed(0)}%`} l="devices with parts list" /><Stat v={c.audits.internal_next_due.slice(0, 10)} l="next internal audit" /></div></Box>
      <Box id="map" title="Guideline map" icon="doc" value={`${CH.length} chapters`}><table><thead><tr><th>Ch.</th><th>Asks</th><th>DECOY</th></tr></thead><tbody>{CH.map((r) => <tr key={r[0]}><td><b>{r[0]}</b></td><td>{r[1]}</td><td className="dim">{r[2]}</td></tr>)}</tbody></table></Box>
    </>
  );
}

function Security() {
  const role = useStore((s) => s.role);
  const [s, setS] = useState<any>(null); const [tamper, setTamper] = useState<any>(null); const [ag, setAg] = useState<any>(null); const [agMsg, setAgMsg] = useState("");
  useEffect(() => { const f = () => { if (!document.hidden) api("/api/security").then(setS).catch(() => {}); }; f(); const t = setInterval(f, 6000); return () => clearInterval(t); }, []);
  if (!s) return <div className="tip"><Ic n="clock" cls="spin" /> Loading…</div>;
  const okN = s.controls.filter((c: any) => c.ok).length;
  const doExport = async () => { const r = await api("/api/airgap/export"); setAg(r); setAgMsg("Signed snapshot v" + r.payload.version + " exported"); };
  const doImport = async (tampered: boolean) => { const doc = JSON.parse(JSON.stringify(ag)); if (tampered) doc.payload.assets[0].cve = "CVE-0000-0000"; else doc.payload.answers = [{ uid: "edge:E000", yes: true }]; const r = await api("/api/airgap/import", { body: doc }).catch(() => ({ message: "rejected" })); setAgMsg(r.message); if (!tampered) setAg(null); };
  return (
    <>
      <Box id="prot" title="Protections" icon="lock" value={`${okN} of ${s.controls.length} on`} tone="safe" defaultOpen>
        <div className="tip">Secure by design and fails safe. We never claim "unhackable".</div>
        {s.controls.map((c: any) => <div key={c.id} className="row" style={{ fontSize: 12.5 }}><span className={"pill " + (c.ok ? "safe" : "watch")} style={{ padding: "1px 7px" }}>{c.ok ? "✓" : "◐"}</span><span className="grow">{cut(c.name, 60)}</span></div>)}
      </Box>
      {s.tests && <Box id="tests2" title="Automated tests" icon="check" value={s.tests.summary?.split(" · ")[0] || "run"} tone="safe">{s.tests.results?.slice(0, 40).map((t: any) => <div key={t.name} className="row" style={{ fontSize: 12 }}><span style={{ color: t.passed ? C.aquaD : C.terra, width: 16 }}>{t.passed ? "✓" : "✗"}</span>{cut(t.name, 56)}</div>)}</Box>}
      {can(role, "admin") && <Box id="tamper" title="Tamper test" icon="eye" value="live demo"><div className="tip">Edit one log entry in a copy and watch the hash chain catch it.</div><button className="btn small primary" onClick={() => api("/api/blackbox/tamper").then(setTamper)}>Tamper with a copy</button>
        {tamper && <div className="row wrap"><span className="pill safe">before: intact</span><span className="pill crit">after: broken at #{tamper.after.broken_at}</span></div>}</Box>}
      <Box id="air" title="Air-gap files" icon="doc" value="signed"><div className="tip">Ed25519-signed, replay-proof snapshots for isolated networks.</div>
        <div className="row wrap"><button className="btn small" onClick={doExport}>Export</button>{can(role, "admin") && ag && <><button className="btn small heal" onClick={() => doImport(false)}>Import valid</button><button className="btn small danger" onClick={() => doImport(true)}>Import tampered</button></>}</div>
        {agMsg && <div className={"pill " + (agMsg.startsWith("REJ") || agMsg === "rejected" ? "crit" : "safe")} style={{ whiteSpace: "normal" }}>{agMsg}</div>}</Box>
      {can(role, "admin") && <Box id="chaos" title="Self-healing test" icon="wrench" value="admin"><div className="tip">DECOY sits beside the plant. If a module dies, a supervisor restarts it.</div><button className="btn small danger" onClick={() => api("/api/chaos/analytics", { method: "POST" }).then(() => toast("ok", "Worker restarted"))}>Kill the analytics worker</button></Box>}
    </>
  );
}
