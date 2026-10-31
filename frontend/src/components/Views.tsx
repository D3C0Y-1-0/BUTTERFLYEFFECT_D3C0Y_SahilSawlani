import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { setState, toast, useStore } from "../store";
import { C, riskColor } from "../palette";
import { Bars, fmt, Gantt, Heartbeat, Hist, k, LineChart, marksOn, Ring, RiskTrio, Slope, Timeline } from "./Charts";
import { Box, Check, Ic, Move, Num, PageHead, Stat, Steps, Switch } from "./ui";
import { assumeBreach } from "../routes";
import { pickNode, showEdges, showFix, showFixes, showTarget, showTargets, showRoute, showNodeRoute } from "../focus";
import { brief, can, nameOf, plainMove, statusOf } from "./status";
import { AttackScore, SeverityRisk } from "./Score";

export { can };
const ctrlTarget = (st: any, ctrl: string) => { const a: any = Object.values(st.actions).find((x: any) => x.controller === ctrl); if (!a) return null; return a.kind === "breaker_open" ? "CB_" + a.target : a.target; };
const actionOf = (st: any, ctrl: string) => Object.entries(st.actions).find(([, x]: any) => x.controller === ctrl)?.[0] as string | undefined;
const cut = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1).trimEnd() + "…" : s);
const mmss = (m: number) => `${Math.floor(m / 60)}:${String(m % 60).padStart(2, "0")}`;

export function setPath(st: any, nodes: string[], edges: string[], kind: "attack" | "predicted") {
  const last = nodes[nodes.length - 1]; const ph = ctrlTarget(st, last);
  const all = ph ? [...nodes, ph] : nodes;
  setState({ pathSel: { nodes: all, edges, kind, ctrl: last }, focus: { key: "r:" + all.join(">"), kind, route: { nodes: all, edges }, edges } });
}

/* ================================================================== OVERVIEW */
export function CityView() {
  const ana = useStore((s) => s.ana), snap = useStore((s) => s.snap), st = useStore((s) => s.st);
  const sv = snap.services; const hosp = Object.values<any>(sv.hospitals); const hOk = hosp.filter((h) => h.ok).length; const fOk = Object.values<boolean>(sv.feeders).filter(Boolean).length;
  const stt = statusOf(snap); const rank = ana?.ranking || [];
  const hot = new Set<string>([...((snap.adversary || []).flatMap((c: any) => c.compromised)), ...(snap.incidents || []).filter((i: any) => i.status === "open" || i.status === "contained").flatMap((i: any) => i.evidence_nodes)]);
  const PR: any = { critical: 0, high: 1, medium: 2 };
  const sites = Object.values<any>(st.physical).filter((p) => p.kind === "site").map((p) => ({ ...p, hit: (p.depends_on || []).some((d: string) => hot.has(d)) })).sort((a, b) => Number(b.hit) - Number(a.hit) || PR[a.priority] - PR[b.priority]);
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
            <div key={r.id} className="list-row" onClick={() => pickNode(st, r.id)}>
              <div className="grow"><div className="row between" style={{ fontSize: 13 }}><b>{cut(brief(r.name), 26)}</b><span className="dim">{k(r.rrw)}</span></div>
                <div className="bar" style={{ marginTop: 5 }}><div style={{ width: `${(r.rrw / rank[0].rrw) * 100}%`, background: riskColor(r.rrw / rank[0].rrw) }} /></div></div>
            </div>))}
        </> : <div className="tip"><Ic n="clock" cls="spin" /> Calculating risk with the water and power simulator…</div>}
      </Box>
      <Box id="sites" title="Mumbai sites" icon="target" value={`${sites.filter((p) => p.hit).length} exposed`} tone={sites.some((p) => p.hit) ? "crit" : "safe"} defaultOpen>
        <div className="tip">Big sites around the ward. A site is exposed when a device it relies on is compromised. Tap one to see why.</div>
        {sites.map((p) => (
          <div key={p.id} className={"list-row" + (p.hit ? " on" : "")} onClick={() => pickNode(st, p.id)}>
            <span className={"pill " + (p.priority === "critical" ? "crit" : p.priority === "high" ? "watch" : "info")} style={{ minWidth: 58, justifyContent: "center" }}>{p.priority}</span>
            <div className="grow" style={{ overflowWrap: "anywhere" }}><div style={{ fontSize: 12.5, fontWeight: 700 }}>{p.name.replace(/ \(.*\)/, "")}</div><div className="dim" style={{ fontSize: 11.5 }}>{p.hit ? "Exposed now" : p.why}</div></div>
          </div>))}
      </Box>
      <Box id="hb" title="What is the heartbeat?" icon="eye">
        <div className="tip">The line at the top is ATHENA's alarm level, from 0 to 100%. <b>Flat and low</b> = calm. <b>A spike</b> = odd traffic or an impossible sensor reading. At <b>85%</b> an incident opens.</div>
        <div className="tip">Once the attacker is cut off, the number <b>fades</b> and the bar says <b>Healing</b> with a countdown while crews restore equipment, so a high number that stays high never means "stuck".</div>
        <div className="tip dim">How it is computed: a network model and a physics check are combined into one probability (logistic fusion).</div>
      </Box>
      <Box id="legend" title="Colour guide" icon="eye">
        <div className="row wrap"><span className="pill" style={{ background: "#1FA2A6", color: "#fff" }}>smart-city edge</span><span className="pill" style={{ background: "#7B61FF", color: "#fff" }}>office IT</span><span className="pill" style={{ background: "#F2A52B", color: "#fff" }}>gateway</span><span className="pill" style={{ background: "#2E6BE6", color: "#fff" }}>control room</span><span className="pill" style={{ background: "#D46743", color: "#fff" }}>controllers</span><span className="pill" style={{ background: "#E11D48", color: "#fff" }}>attacker</span></div>
        <div className="tip">Each device wears an icon for what it is. Pipes and wires below are the real water and power network.</div>
      </Box>
    </>
  );
}

/* ================================================================== PATHS */
const inr = (n: number) => (n >= 1e7 ? `₹${(n / 1e7).toFixed(1)} crore` : n >= 1e5 ? `₹${(n / 1e5).toFixed(1)} lakh` : n >= 1e3 ? `₹${(n / 1e3).toFixed(0)} thousand` : `₹${Math.round(n)}`);
const people = (n: number) => (n >= 1e5 ? `${(n / 1e5).toFixed(1)} lakh` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : String(n));

export function PathView() {
  const ana = useStore((s) => s.ana), st = useStore((s) => s.st), sel = useStore((s) => s.pathSel), chosen = useStore((s) => s.selected), snap = useStore((s) => s.snap);
  const [imp, setImp] = useState<any>(null); const [busy, setBusy] = useState(false);
  useEffect(() => { if (!sel && ana?.paths?.[0]) { const p = ana.paths[0]; setPath(st, p.nodes, p.edges, "attack"); } }, [ana?.paths]);
  const node: string | null = chosen && (st.assets[chosen] || st.physical[chosen]) ? chosen : sel?.nodes?.length > 1 ? sel.nodes[sel.nodes.length - 2] : null;   // the device you clicked, else the last computer on the shown route
  const hour = Math.floor(snap.hour);
  useEffect(() => { if (!node) { setImp(null); return; } let live = true; setBusy(true); api(`/api/v2/impact?node=${node}&start=${hour}`).then((r) => { if (live) setImp(r); }).catch(() => { if (live) setImp(null); }).finally(() => live && setBusy(false)); return () => { live = false; }; }, [node, hour]);
  const paths: any[] = ana?.paths || [];
  return (
    <>
      <PageHead icon="route" title="Attack paths" sub="How a hacker could reach water or power" right={<span className="pill info">{paths.length} entry points</span>} />
      <Box id="what" title="What it would do" icon="water" value={imp ? inr(imp.money_inr) : "…"} tone={imp && imp.people > 0 ? "crit" : "safe"} defaultOpen>
        {node ? <>
          <div className="tip">If <b>{nameOf(st, node)}</b> is taken over{chosen ? "" : " (the last device on the route below; click any device on the map to change this)"}, starting at {String(hour).padStart(2, "0")}:00:</div>
          {imp && imp.people > 0 ? <div className="grid3">
            <Stat v={people(imp.people)} l="people without water or power" color={C.terra} />
            <Stat v={imp.hours >= 24 ? `${(imp.hours / 24).toFixed(1)} days` : `${imp.hours} h`} l="how long it lasts" color={C.apricot} />
            <Stat v={inr(imp.money_inr)} l="estimated loss" color={C.terraD} />
          </div> : <div className="tip">{busy ? <><Ic n="clock" cls="spin" /> Working it out…</> : imp ? "Nothing in water or power can be switched off from this device. It can still be a stepping stone, see the blast radius on the map." : "Not available."}</div>}
          {imp && imp.people > 0 && <div className="tip">{imp.hospitals_hit > 0 ? <><b>{imp.hospitals_hit}</b> hospital{imp.hospitals_hit === 1 ? "" : "s"} would be hit. </> : ""}It could switch off: {imp.labels.slice(0, 3).map((l: string) => plainMove(l).title.replace(/^Send a crew to put /, "")).join("; ")}.</div>}
          {imp && <details><summary className="tip" style={{ cursor: "pointer" }}>How this is worked out</summary><div className="tip">{imp.assumption}</div></details>}
        </> : <div className="tip">Click any device on the map, or pick a route below.</div>}
      </Box>
      <Box id="routes" title="Most dangerous route per entry point" icon="route" value="tap to show" defaultOpen>
        {paths.map((p, i) => {
          const on = sel?.nodes?.[1] === p.nodes[1] && sel?.ctrl === p.nodes[p.nodes.length - 1];
          return (
            <div key={i} className={"list-row" + (on ? " on" : "")} style={{ alignItems: "flex-start" }} onClick={() => { setPath(st, p.nodes, p.edges, "attack"); setState({ selected: null }); }}>
              <span className="num-chip">{i + 1}</span>
              <div className="grow"><div style={{ fontSize: 11, fontWeight: 700, color: C.terraD, letterSpacing: ".04em" }}>ENTERS VIA</div>
                <div style={{ fontSize: 13, fontWeight: 700, overflowWrap: "anywhere" }}>{nameOf(st, p.nodes[1])}</div>
                <div className="dim" style={{ fontSize: 11.5 }}>then {p.nodes.length - 2} more step{p.nodes.length - 2 === 1 ? "" : "s"} to {nameOf(st, p.nodes[p.nodes.length - 1])} · harm {k(p.weight)}</div></div>
            </div>);
        })}
        {!paths.length && <div className="tip"><Ic n="clock" cls="spin" /> Finding routes…</div>}
        {sel && <div className="col" style={{ gap: 5, marginTop: 4 }}>
          <b style={{ fontSize: 12 }}>The route on the map (tap a step to see what it would do)</b>
          {sel.nodes.map((n: string, i: number) => <div key={n + i} className="row" style={{ gap: 8, fontSize: 12.5, cursor: "pointer" }} onClick={() => st.assets[n] && setState({ selected: n })}><span className={"num-chip" + (i === sel.nodes.length - 1 ? " aqua" : "")} style={{ width: 20, height: 20, fontSize: 11 }}>{i === sel.nodes.length - 1 ? "!" : i + 1}</span>{nameOf(st, n)}</div>)}
        </div>}
      </Box>
    </>
  );
}

/* ================================================================== FIX */
export function FixView() {
  const ana = useStore((s) => s.ana), role = useStore((s) => s.role), st = useStore((s) => s.st);
  const [what, setWhat] = useState<any>(null); const [picked, setPicked] = useState<string[]>([]);
  const toggle = (id: string) => setPicked((p) => { const n = p.includes(id) ? p.filter((x) => x !== id) : [...p, id]; setTimeout(() => showFixes(st, n), 0); return n; });
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
          <div key={s.fix.id} className="list-row" onClick={() => showFix(st, s.fix.id)}>
            <span className="num-chip">{i + 1}</span>
            <div className="grow"><Move label={s.fix.label} extra={<> Saves {k(s.gain)} · {s.downtime_loss ? "small outage " + k(s.downtime_loss) : "no outage"}.</>} detail={<>Effort {s.fix.cost} · type {String(s.fix.type).replace("_", " ")} · CERT-In {(s.fix.certin || []).join("; ")}</>} /></div>
            <div className="col" style={{ gap: 4 }}>
              <button className={"btn small" + (picked.includes(s.fix.id) ? " primary" : "")} onClick={(e) => { e.stopPropagation(); toggle(s.fix.id); }}>{picked.includes(s.fix.id) ? "✓ preview" : "preview"}</button>
              {can(role, "operator") && <button className="btn small heal" onClick={(e) => { e.stopPropagation(); showFix(st, s.fix.id); api("/api/fix", { body: { id: s.fix.id } }).then(() => toast("ok", "Fix applied")).catch(() => {}); }}>Apply</button>}
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
          {refused.slice(0, 4).map((r: any, i: number) => <div key={i}><b style={{ fontSize: 12.5 }}>{plainMove(r.fix.label).title}</b><div className="tip">{cut(r.reason, 110)}</div></div>)}
        </Box>)}
      <Box id="sched" title="When to do each fix" icon="clock" value={ana.schedule?.length ? `${ana.schedule.filter((r: any) => !r.no_outage).length} need a restart` : "…"}>
        <div className="tip">Each fix gets its own day and hour. Fixes that need no restart go first, in working hours. A restart goes to the quietest slot that is still soon enough for how urgent the fix is.</div>
        {(ana.schedule || []).slice(0, 8).map((r: any, i: number) => (
          <div key={i} className="list-row" style={{ alignItems: "flex-start", cursor: "default" }}>
            <span className={"pill " + (r.no_outage ? "safe" : "watch")} style={{ minWidth: 86, justifyContent: "center" }}>{r.when}</span>
            <div className="grow"><div style={{ fontSize: 12.5, fontWeight: 700, overflowWrap: "anywhere" }}>{plainMove(r.fix.label).title}</div>
              <div className="dim" style={{ fontSize: 11.5 }}>{r.no_outage ? "No restart" : `${r.downtime_min} min restart · outage cost ${k(r.downtime_loss)}`} · urgency {r.severity}/4 · benefit {k(r.gain)}</div></div>
          </div>))}
        <details><summary className="tip" style={{ cursor: "pointer" }}>Show as a chart</summary><Gantt rows={ana.schedule} /></details>
      </Box>
      {/* Missing facts (value-of-information questions): switched off for now, to be revisited.
      <Box id="ask" title="Missing facts" icon="question" value={voi.length ? `${voi.length} questions` : "none"} tone={voi.length ? "watch" : "safe"}>
        {ana.voi_computing && <div className="tip"><Ic n="clock" cls="spin" /> Working out which question matters most…</div>}
        {voi.map((v: any, i: number) => (
          <div key={v.id} className={"list-row" + (i === 0 ? " on" : "")} style={{ flexDirection: "column", alignItems: "stretch" }} onClick={() => { const [kind, id] = String(v.id).split(":"); if (kind === "edge") showEdges(st, [id], "predicted"); else showNodeRoute(st, id); }}>
            <b style={{ fontSize: 13 }}>{v.text}</b><div className="dim" style={{ fontSize: 11.5 }}>Answering could improve the plan by about {k(v.voi)}.</div>
            {can(role, "operator") && <div className="row" style={{ marginTop: 4 }}><button className="btn small heal" onClick={(e) => { e.stopPropagation(); api("/api/answer", { body: { uid: v.id, yes: true } }).then(() => toast("ok", "Thanks, plan updated")); }}>Yes</button><button className="btn small" onClick={(e) => { e.stopPropagation(); api("/api/answer", { body: { uid: v.id, yes: false } }).then(() => toast("ok", "Thanks, plan updated")); }}>No</button></div>}
          </div>))}
      </Box>
      */}
    </>
  );
}

/* ================================================================== DEFEND */
const ATTACKS: [string, string][] = [["standard", "Known exploit from the internet"], ["spoof", "Fake sensor readings"], ["wear", "Breaker wear"], ["insider", "Insider already inside the network"]];
const STAGE_LABELS = ["Detected", "Predicted", "Cut", "Verified", "Recovered"]; const STAGE_KEYS = ["Detected", "Predicted route", "Cut made", "Verified", "Recovered"];

export function DefendView() {
  const snap = useStore((s) => s.snap), st = useStore((s) => s.st), role = useStore((s) => s.role), hist = useStore((s) => s.hist), marks = useStore((s) => s.marks);
  const [mode, setMode] = useState("standard"); const [entry, setEntry] = useState(""); const [goal, setGoal] = useState("");
  const stt = statusOf(snap); const incs = snap.incidents || []; const inc = [...incs].reverse().find((i: any) => i.status !== "reported") || null;
  const props = (snap.proposals || []).filter((p: any) => p.status === "pending");
  const entries = Object.values<any>(st.assets).filter((a) => mode === "insider" ? ["it", "dmz", "control"].includes(a.layer) && a.exposure !== "internet" : a.entry_weight > 0); const goals = Object.values<any>(st.actions);
  const cutN = (snap.defence.quarantined?.length || 0) + (snap.defence.blocked?.length || 0); const total = Object.keys(st.assets).length - 1;
  const w = snap.watch; const h = hist.slice(-120); const live = inc && inc.status !== "reported";
  const done = (() => { if (!live) return 0; let n = 0; for (const key of STAGE_KEYS) { if (inc.stages.some((x: any) => x.stage === key)) n++; else break; } return n; })();
  const camp = [...(snap.adversary || [])].reverse()[0]; const blockedE = new Set<string>(snap.defence.blocked || []);
  return (
    <>
      <PageHead icon="shield" title="Live defence" sub="Watch ATHENA stop an attack" right={<span className={"pill " + stt.tone + (stt.key === "attack" ? " pulse" : "")}>{stt.label}</span>} />
      <div className={"hero " + stt.tone}>
        <div className="row between"><div className="big">{stt.label}</div>{live && inc.status !== "resolved" && <div className="row" title="CERT-In: report within 6 hours"><Ring value={inc.left_min} max={360} size={44} stroke={5} color={C.terra}>{Math.floor(inc.left_min / 60)}h</Ring></div>}</div>
        <div style={{ fontSize: 13, margin: "3px 0 10px", maxWidth: "82%" }}>{stt.line}</div>
        {stt.key === "healing" && <div className="heal-anim"><span /><span /><span /><div className="core"><Ic n="shield" /></div></div>}
        {stt.key === "recovered" && <div className="row" style={{ gap: 8, fontWeight: 800 }}><Check /> Service restored</div>}
        {live && stt.key !== "recovered" && <Steps labels={STAGE_LABELS} done={done} attack={stt.key === "attack"} />}
      </div>
      {can(role, "analyst") && (
        <Box id="launch" title="Simulate an attack" icon="bolt" value={snap.autopilot ? "autopilot on" : "manual"} defaultOpen>
          <select value={mode} onChange={(e) => { setMode(e.target.value); setEntry(""); }} aria-label="Attack type">{ATTACKS.map(([m, t]) => <option key={m} value={m}>{t}</option>)}</select>
          <button className="btn primary big" onClick={() => api("/api/attack", { body: { mode, entry: entry || null, goal: goal || null } }).then(() => { toast("warn", mode === "insider" ? "Insider attack launched (starts inside)" : "Attack launched (simulation)"); setState({ side: true }); })}>Launch attack</button>
          {mode === "insider" && <div className="tip">An insider already holds an office or control machine, so there is no internet step to block. ATHENA has to notice the odd movement or the physical effect instead.</div>}
          <div className="row between"><span style={{ fontSize: 12.5 }}>Attacks by themselves</span>{can(role, "operator") ? <Switch on={!!snap.autopilot} label="Autopilot adversary" onChange={() => api("/api/autopilot", { body: { on: !snap.autopilot } })} /> : <span className="pill info">{snap.autopilot ? "on" : "off"}</span>}</div>
          <details><summary className="tip" style={{ cursor: "pointer" }}>Choose entry and target</summary>
            <div className="col" style={{ marginTop: 6 }}><select value={entry} onChange={(e) => setEntry(e.target.value)} aria-label="Entry"><option value="">{mode === "insider" ? "Starts on: any internal machine" : "Entry: any exposed device"}</option>{entries.map((a: any) => <option key={a.id} value={a.id}>{a.name}</option>)}</select>
              <select value={goal} onChange={(e) => setGoal(e.target.value)} aria-label="Target"><option value="">Target: any controller</option>{goals.map((a: any) => <option key={a.controller} value={a.controller}>{a.label}</option>)}</select></div></details>
        </Box>)}
      {props.map((p: any) => (
        <Box key={p.id} id={"prop" + p.id} title="Needs your OK" icon="check" value={`saves ${k(Math.max(0, p.observe_J - p.plan_J))}`} tone="watch" kind="warm" defaultOpen>
          {p.steps.map((s: any, i: number) => <div key={i} className="row" style={{ fontSize: 12.5, cursor: "pointer" }} onClick={() => showTarget(st, s.target)}><span className="num-chip aqua" style={{ width: 20, height: 20, fontSize: 11 }}>{i + 1}</span><span className="grow"><Move label={s.label} detail={<>Service cost {k(s.service)} · disruption {k(s.ops)}{s.safety?.note ? " · " + s.safety.note : ""}</>} /></span>{s.safety?.ok && <span className="pill safe">safe</span>}</div>)}
          <div className="grid3"><Stat v={k(p.observe_J)} l="do nothing" color={C.terra} /><Stat v={k(p.plan_J)} l="this plan" color={C.aquaD} /><Stat v={k(p.isolate_all_J)} l="cut everything" color={C.apricot} /></div>
          {can(role, "operator") && <div className="row"><button className="btn heal grow" onClick={() => { showTargets(st, p.steps.map((s: any) => s.target)); api(`/api/proposal/${p.id}/approve`, { method: "POST" }).then((r) => toast(r.status === "awaiting_second" ? "warn" : "ok", r.status === "awaiting_second" ? "A second person must approve" : "Plan applied")); }}>Approve</button><button className="btn danger" onClick={() => api(`/api/proposal/${p.id}/reject`, { method: "POST" })}>Reject</button></div>}
        </Box>))}
      {camp && (
        <Box id="atk" title="1 · The attack, step by step" icon="bolt" value={`${Math.max(0, camp.compromised.length - 1)} device${camp.compromised.length === 2 ? "" : "s"} reached`} tone="crit" defaultOpen>
          <div className="tip">{camp.mode === "insider" ? "Insider: starts inside, no internet hop." : "Starts on the internet."} The route is drawn in red on the map.</div>
          {camp.hops.length === 0 && <div className="tip">{camp.state === "done" || camp.state === "contained" ? "The attacker was stopped at the front door: it never got past its first step." : "The attacker is still looking around…"}</div>}
          {camp.hops.map((h: any, i: number) => <div key={i} className="row" style={{ fontSize: 12.5, cursor: "pointer" }} onClick={() => showEdges(st, [h.edge], "attack")}><span className="num-chip" style={{ width: 20, height: 20, fontSize: 11 }}>{i + 1}</span><span className="grow">{nameOf(st, h.dst)}</span>{blockedE.has(h.edge) ? <span className="pill safe">link cut</span> : snap.defence.quarantined?.includes(h.dst) ? <span className="pill safe">cut off</span> : <span className="pill crit">taken</span>}<span className="dim" style={{ fontSize: 11 }}>+{Math.max(0, h.minute - camp.started)} min</span></div>)}
          {live && inc.next_hops?.length > 0 && <div className="tip">ATHENA predicted the next step: <b>{nameOf(st, inc.next_hops[0].dst)}</b> ({(inc.next_hops[0].p * 100).toFixed(0)}%) and moved to block it.</div>}
        </Box>)}
      {live && (inc.actions.length > 0 || inc.next_hops?.length > 0) && (
        <Box id="did" title="2 · What ATHENA did" icon="check" value={`${inc.actions.length} actions`} tone="safe" defaultOpen>
          {inc.actions.map((a: any, i: number) => <div key={i} className="row" style={{ fontSize: 12.5, cursor: "pointer" }} onClick={() => showTarget(st, a.target, inc.evidence_nodes)}><span style={{ color: C.aquaD }}><Check /></span><span className="grow"><Move label={a.label} detail={<>Done by {a.actor}{a.safety ? " · " + a.safety : ""} · minute {a.minute}</>} /></span></div>)}
          {inc.next_hops?.length > 0 && <><b style={{ fontSize: 12 }}>Where it may go next</b>{inc.next_hops.slice(0, 2).map((n: any) => <div key={n.edge} className="row" style={{ cursor: "pointer" }} onClick={() => showEdges(st, [n.edge], "predicted")}><span style={{ width: 130, fontSize: 12 }}>{cut(nameOf(st, n.dst), 18)}</span><div className="bar grow"><div style={{ width: `${n.p * 100}%`, background: C.apricot }} /></div><b style={{ width: 34, textAlign: "right", fontSize: 12 }}>{(n.p * 100).toFixed(0)}%</b></div>)}</>}
        </Box>)}
      <Box id="kept" title="3 · How well it worked" icon="home" value={camp ? `${cutN} of ${total} cut off` : "no attack yet"} tone="safe" defaultOpen>
        <AttackScore snap={snap} st={st} hist={hist} />
      </Box>
      <Box id="why" title="Why the alarm rang" icon="eye" value={`${((w.shown ?? w.p) * 100).toFixed(0)}%`} tone={(w.shown ?? w.p) > 0.85 ? "crit" : (w.shown ?? w.p) > 0.4 ? "watch" : "safe"}>
        <Heartbeat data={h.map((x) => x.p)} h={46} color={(w.shown ?? w.p) > 0.85 ? C.terra : C.aquaD} thr={0.85} marks={marksOn(h, marks)} />
        {marks.length > 0 && <div className="tip">Circles on the line are your actions: {[...new Set(marks.slice(-4).map((m) => m.label))].join(", ")}.</div>}
        {w.note && <div className="tip"><b>{w.phase === "healing" ? "Healing: " : ""}</b>{w.note}</div>}
        <div className="grid3"><Stat v={w.ae?.toFixed?.(1) ?? "–"} l="odd traffic" /><Stat v={w.novelty} l="new links" /><Stat v={w.phys_z} l="physics score" /></div>
        {w.violations?.map((v: any, i: number) => <div key={i} className="pill crit" style={{ whiteSpace: "normal" }}>⚠ {cut(v.text, 90)}</div>)}
        {!w.violations?.length && <div className="tip">Two checks run together: network behaviour and the laws of physics.</div>}
      </Box>
    </>
  );
}

/* ================================================================== PROOF */
export function ProofView() {
  const ana = useStore((s) => s.ana), exp = useStore((s) => s.exp), st = useStore((s) => s.st);
  const rows = ana?.ranking || []; const E = exp || {}; const keys = Object.keys(E).filter((x) => x !== "_meta").sort((a, b) => parseInt(a.slice(1)) - parseInt(b.slice(1)));
  const met = keys.filter((x) => E[x].met).length;
  const [open, setOpen] = useState<string | null>(null);
  return (
    <>
      <PageHead icon="chart" title="Proof" sub="Does it really work? Measured in simulation" right={keys.length ? <span className="pill safe">{met} of {keys.length} goals met</span> : undefined} />
      <Box id="slope" title="Severity is not risk" icon="swap" value={ana ? `${ana.reversals} devices move` : "…"} defaultOpen>
        <SeverityRisk rows={rows} onPick={(id) => pickNode(st, id)} />
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
  if (key === "E9") return <><Bars rows={[{ label: "ATHENA", value: r.mean_loss_decoy, color: C.aquaD }, { label: "No response", value: r.mean_loss_no_response, color: C.terra }, { label: "Cut everything", value: r.mean_loss_isolate_all, color: C.apricot }]} />{T([["Scenarios", r.scenarios], ["Detected", r.detected_pct + "%"], ["Devices cut: ATHENA vs all", `${r.mean_devices_disconnected_decoy} vs ${r.devices_disconnected_isolate_all}`]])}</>;
  if (key === "E10") return T(Object.entries(r.detection).map(([n, v]: any) => [n, `fused ${v["fused (network + physics)"].detected} · network ${v["network only"].detected} · physics ${v["physics only"].detected}`]));
  if (key === "E11") return T(r.runs.map((x: any) => [`${fmt(x.nodes)} nodes`, `${x.seconds}s · ${x.mem_mb} MB`]));
  if (key === "E12") return T([["Unsafe actions blocked", r.candidate_actions_blocked_in_scenarios], ["Times a response hurt a hospital", r.scenarios_where_response_made_hospital_worse]]);
  if (key === "E13") return T([["Attacker hops with / without decoys", `${r.mean_attacker_hops_with_decoys} / ${r.mean_attacker_hops_without_decoys}`], ["Loss with / without", `${k(r.mean_loss_with)} / ${k(r.mean_loss_without)}`]]);
  if (key === "E15" && r.policies) return T(Object.entries<any>(r.policies).map(([n, v]) => [n, `cost ${k(v.mean_total)} · cut ${v.devices_cut.toFixed(1)}`]));
  return <div className="tip">{cut(JSON.stringify(r), 220)}</div>;
}

/* ================================================================== SAFETY (numbers and charts, not paragraphs) */
function Gauge({ v, label, sub, color = C.aquaD }: { v: number; label: string; sub: string; color?: string }) {
  return <div className="gauge"><Ring value={v} size={64} stroke={8} color={color}><b style={{ fontSize: 12 }}>{Math.round(v * 100)}%</b></Ring><div><b>{label}</b><small>{sub}</small></div></div>;
}

export function SafetyView() {
  const role = useStore((s) => s.role), exp = useStore((s) => s.exp), snap = useStore((s) => s.snap); const E: any = exp || {};
  const [c, setC] = useState<any>(null); const [s, setS] = useState<any>(null);
  useEffect(() => { const f = () => { if (!document.hidden) { api("/api/compliance").then(setC).catch(() => {}); api("/api/security").then(setS).catch(() => {}); } }; f(); const t = setInterval(f, 6000); return () => clearInterval(t); }, []);
  if (!c) return <><PageHead icon="lock" title="Safety" sub="Rules we follow and how we stay safe" /><div className="tip"><Ic n="clock" cls="spin" /> Loading…</div></>;
  const dl = async (id: string) => { const r = await api(`/api/incident/${id}/report`); const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `${id}_CERT-In_report.json`; a.click(); await api(`/api/incident/${id}/reported`, { method: "POST" }); toast("ok", "Report exported"); };
  const open = c.clocks.filter((i: any) => i.status !== "reported");
  const drift = Object.keys(c.time.drifting || {}).length; const nSrc = Math.max(drift + 1, 8);
  const controls: any[] = s?.controls || []; const okN = controls.filter((x) => x.ok).length;
  const hidden = c.misconfigurations.filter((m: any) => !m.known).length; const mis = c.misconfigurations.length;
  const closedLinks = (snap.defence.blocked || []).length;
  const gauges = [
    { label: "CERT-In 6-hour report", v: open.length && open[0].left_min <= 0 ? 0 : 1, sub: open.length ? `on time: ${Math.floor(open[0].left_min / 60)} h ${open[0].left_min % 60} min left for ${open[0].id}` : "ready, no clock running", color: open.length && open[0].left_min < 60 ? C.apricot : C.aquaD },
    { label: "Logs kept in India", v: 1, sub: `${c.vault.retention_days}-day rule active; ${c.vault.days_held} day${c.vault.days_held === 1 ? "" : "s"} stored so far`, color: C.aquaD },
    { label: "Log integrity", v: c.chain.ok ? 1 : 0, sub: c.chain.ok ? `${c.chain.checked} entries checked, none altered` : "a record was altered", color: c.chain.ok ? C.aquaD : C.terra },
    { label: "Clocks in sync", v: 1 - drift / nSrc, sub: drift ? `${drift} device clock${drift === 1 ? "" : "s"} drifting` : "all devices agree", color: drift ? C.apricot : C.aquaD },
    { label: "Software parts list", v: c.sbom_coverage, sub: "devices with a known parts list (SBOM)", color: C.aquaD },
    { label: "Weak links known", v: mis ? (mis - hidden) / mis : 1, sub: mis ? `${mis - hidden} of ${mis} risky links already known` : "none found", color: hidden ? C.apricot : C.aquaD },
  ];
  const green = gauges.filter((g) => g.v >= 0.9).length;
  const e9 = E.E9?.result, e10 = E.E10?.result, e12 = E.E12?.result;
  const det = e10 ? Object.values<any>(e10.detection).map((v: any) => v["fused (network + physics)"]) : [];
  const detOk = det.reduce((a: number, d: any) => a + parseInt(String(d.detected).split("/")[0]), 0), detAll = det.reduce((a: number, d: any) => a + parseInt(String(d.detected).split("/")[1]), 0);
  return (
    <>
      <PageHead icon="lock" title="Safety" sub="Do we follow the rules, and is ATHENA itself safe?" right={<span className="pill safe">Aligned with CERT-In</span>} />
      <Box id="comp" title="Rules we follow (CERT-In)" icon="check" value={`${green} of ${gauges.length} fully green`} tone="safe" defaultOpen>
        <div className="gauges">{gauges.map((g) => <Gauge key={g.label} v={g.v} label={g.label} sub={g.sub} color={g.color} />)}</div>
        {open.length > 0 && can(role, "operator") && <div className="row wrap">{open.slice(0, 2).map((i: any) => <button key={i.id} className="btn small primary" onClick={() => dl(i.id)}>Export report {i.id}</button>)}</div>}
        <div className="chips"><span className="chip ok">CERT-In Directions 2022</span><span className="chip ok">Smart City Guidelines 2025</span><span className="chip">IEC 62443</span><span className="chip">NIST CSF 2.0</span><span className="chip">MITRE ATT&amp;CK for ICS</span></div>
        <div className="dim" style={{ fontSize: 11.5 }}>"Aligned with" these rules. Not a certification.</div>
      </Box>
      <Box id="prot" title="How ATHENA protects itself" icon="shield" value={s ? `${okN} of ${controls.length} on` : "…"} tone="safe" defaultOpen>
        {controls.length > 0 && <><div className="dots">{controls.map((x) => <i key={x.id} className={x.ok ? "on" : ""} title={x.name} />)}</div><div className="tip">Each dot is one protection (logins, tokens, roles, limits, validation, headers…). Hover to read it. Lit = on.</div></>}
        <div className="grid3"><Stat v={`${s?.controls?.find((x: any) => x.id === "rate")?.blocked ?? 0}`} l="requests blocked by limits" color={C.aquaD} /><Stat v={`${c.chain.checked}`} l="log entries sealed" color={C.aquaD} /><Stat v="2" l="people needed for big actions" color={C.aquaD} /></div>
      </Box>
      <Box id="fail" title="Safe even when it acts" icon="wrench" value={e12 ? `${e12.scenarios_where_response_made_hospital_worse} harmful moves` : "…"} tone="safe" defaultOpen>
        {e12 ? <>
          <Bars rows={[{ label: "Unsafe actions stopped before running", value: e12.candidate_actions_blocked_in_scenarios, color: C.aquaD }, { label: "Times a response hurt a hospital", value: e12.scenarios_where_response_made_hospital_worse, color: C.terra }]} />
          {e9 && <Bars rows={[{ label: "Devices cut by ATHENA (average)", value: e9.mean_devices_disconnected_decoy, color: C.aquaD }, { label: "Devices cut by 'cut everything'", value: e9.devices_disconnected_isolate_all, color: C.apricot }]} />}
          {detAll > 0 && <div className="grid3"><Stat v={`${detOk}/${detAll}`} l="unseen attack types caught" color={C.aquaD} /><Stat v={e9 ? `${e9.detected_pct}%` : "–"} l="attacks detected" color={C.aquaD} /><Stat v={e9 ? `${e9.hospital_hours_decoy}h` : "–"} l="hospital water lost" color={C.aquaD} /></div>}
          <div className="tip">Every fix is tested on a copy of the city first, and only goes ahead if no hospital gets worse. Measured in {e9?.scenarios ?? "many"} simulated attacks.</div>
        </> : <div className="tip">Run backend/experiments.py to fill this in.</div>}
        <div className="row between"><span style={{ fontSize: 12.5 }}>Links closed right now</span><b>{closedLinks}</b></div>
      </Box>
    </>
  );
}
