import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { setState, toast, useStore } from "../store";
import { C, riskColor } from "../palette";
import { Bars, k, RiskTrio } from "./Charts";
import { Box, Ic, PageHead, Stat } from "./ui";
import { brief, can, nameOf } from "./status";
import { setPath } from "./Views";

const cut = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1).trimEnd() + "…" : s);
const V2 = "/api/v2";

/** Three kinds of statements, never mixed: plausible (simulated), predicted (ML), confirmed (observed). */
function Kinds({ c }: { c: any }) {
  return (
    <div className="grid3">
      <Stat v={c.plausible_path_assets.length} l="plausible: reachable if every step works" color={C.terra} />
      <Stat v={c.predicted_top_risk?.[0] ? brief(c.predicted_top_risk[0].id) : "–"} l="predicted: highest risk propensity" color={C.apricot} />
      <Stat v={c.confirmed_incident_assets.length ? c.confirmed_incident_assets.length : "none"} l="confirmed: seen by the Watchdog" color={C.aquaD} />
    </div>
  );
}

function Recs({ recs, onApplied }: { recs: any[]; onApplied: () => void }) {
  const role = useStore((s) => s.role);
  const apply = (r: any) => api(V2 + "/mitigations/apply", { body: { controls: r.apply } }).then(() => { toast("ok", "Applied in the simulation only"); onApplied(); });
  return (
    <div className="col">
      {recs.slice(0, 5).map((r, i) => (
        <div key={i} className="list-row" style={{ cursor: "default", alignItems: "flex-start" }}>
          <span className="num-chip aqua">{i + 1}</span>
          <div className="grow"><div style={{ fontSize: 13, fontWeight: 700 }}>{cut(r.label, 70)}</div>
            <div className="dim" style={{ fontSize: 11.5 }}>reaches {r.reached_before} → {r.reached_after} assets · {r.eliminates_all_paths ? "closes every path" : r.reduction > 0 ? "other paths stay open" : "no effect alone"} · effort {r.cost}</div></div>
          {can(role, "analyst") && <button className="btn small heal" onClick={() => apply(r)}>Try it</button>}
        </div>))}
    </div>
  );
}

function SimResult({ r, st, onApplied }: { r: any; st: any; onApplied: () => void }) {
  const names = (ids: string[]) => ids.map((i) => nameOf(st, i));
  return (
    <>
      <Kinds c={r.classification} />
      {r.risk_before !== undefined && <RiskTrio unit="Ward risk index (untouched baseline = 100)" rows={[{ label: "Before", sub: "baseline", value: r.risk_before, color: C.aquaD }, { label: "During", sub: "if this happens", value: r.risk_during, color: C.terra }, { label: "After", sub: "with the best package", value: r.package?.risk_after ?? r.risk_before, color: C.apricot }]} />}
      <div className="tip"><b>Could also reach:</b> {r.compromised.length > 1 ? names(r.compromised.slice(1)).slice(0, 8).join(", ") + (r.compromised.length > 9 ? "…" : "") : "nothing else (every next step fails a precondition)"}</div>
      {r.services_lost.length > 0 && <div className="row wrap">{r.services_lost.slice(0, 6).map((s: string) => <span key={s} className="pill crit">{cut(s, 28)}</span>)}</div>}
      {r.failed?.length > 0 && <details><summary className="tip" style={{ cursor: "pointer" }}>Steps that fail ({r.failed.length})</summary>{r.failed.slice(0, 5).map((f: any, i: number) => <div key={i} className="tip">✗ {nameOf(st, f.source)} → {nameOf(st, f.target)}: {f.reasons[0]}</div>)}</details>}
      {r.recommendations?.length > 0 && <><b style={{ fontSize: 12.5 }}>What to do about it</b><Recs recs={r.recommendations} onApplied={onApplied} /></>}
      {r.package && <div className="tip">Best package: <b>{r.package.controls.length ? r.package.controls.map((c: string) => cut(c, 40)).join(" + ") : "none helps"}</b>. {r.package.reached_after.length === 0 ? "Closes every path." : `${r.package.reached_after.length} asset(s) stay reachable.`}</div>}
    </>
  );
}

export function LabView() {
  const st = useStore((s) => s.st), role = useStore((s) => s.role), sel = useStore((s) => s.selected), labStart = useStore((s) => s.labStart);
  const [model, setModel] = useState<any>(null); const [start, setStart] = useState("VPN_VENDOR"); const [creds, setCreds] = useState(true);
  const [res, setRes] = useState<any>(null); const [scn, setScn] = useState<any[]>([]); const [run, setRun] = useState<any>(null); const [risk, setRisk] = useState<any>(null);
  const [expl, setExpl] = useState<any>(null); const [cmp, setCmp] = useState<any>(null); const [busy, setBusy] = useState("");
  const ids = useMemo(() => Object.values<any>(st.assets).filter((a) => a.id !== "INTERNET"), [st]);
  const load = () => { api(V2 + "/model").then(setModel).catch(() => {}); api(V2 + "/risk").then(setRisk).catch(() => setRisk(null)); api(V2 + "/scenarios").then((r) => setScn(r.scenarios)).catch(() => {}); };
  useEffect(() => { load(); const t = setInterval(() => { if (!risk) load(); }, 3000); return () => clearInterval(t); }, [!!risk]);
  useEffect(() => { if (labStart) { setStart(labStart); setState({ labStart: null }); } else if (sel && st.assets[sel]) setStart(sel); }, [sel, labStart]);
  const show = (r: any) => {   // draw the most damaging plausible path on the map and dim everything else
    const comp: string[] = r.compromised || []; setState({ labNodes: comp });
    const ctrl = Object.values<any>(st.actions).map((a) => a.controller).filter((c) => comp.includes(c) && r.paths?.[c]).sort((a, b) => (r.paths[b].length - r.paths[a].length))[0];
    if (ctrl) { const edges: string[] = r.paths[ctrl]; const nodes = [r.start || start]; for (const eid of edges) { const e = st.edges.find((x: any) => x.id === eid); nodes.push(e ? e.target : eid); } setPath(st, nodes, edges, "attack"); } else setState({ pathSel: null });
  };
  const simulate = () => { setBusy("sim"); setRun(null); api(V2 + "/simulate/compromise", { body: { start, credentials: creds && start === "VPN_VENDOR" ? [start] : [] } }).then((r) => { setRes(r); show(r); }).finally(() => setBusy("")); };
  const runScn = (id: string) => { setBusy(id); setRes(null); api(V2 + `/scenarios/${id}/run`, { method: "POST", body: {} }).then((r) => { setRun(r); show(r); }).finally(() => setBusy("")); };
  const compare = () => api(V2 + "/compare" + (res ? `?start=${res.start}` : "")).then(setCmp);
  const reset = () => api(V2 + "/reset", { method: "POST", body: {} }).then(() => { setCmp(null); setRes(null); setRun(null); setState({ labNodes: [], pathSel: null }); toast("ok", "Simulation reset"); load(); });
  const explain = (id: string) => api(V2 + `/risk/${id}/explain`).then(setExpl);
  const rows = risk?.assets || [];
  const ready = model?.state?.status === "ready";
  return (
    <>
      <PageHead icon="target" title="What-if" sub="Pick a device, press Simulate" right={<span className={"pill " + (ready ? "safe" : "watch")}>{ready ? "model ready" : model?.state?.status || "loading"}</span>} />
      <Box id="sim" title="Simulate a compromise" icon="mask" value="plausible paths" defaultOpen>
        <select value={start} onChange={(e) => { setStart(e.target.value); setRes(null); }} aria-label="Start device">{ids.map((a: any) => <option key={a.id} value={a.id}>{brief(a.name)}</option>)}</select>
        {start === "VPN_VENDOR" && <label className="row" style={{ fontSize: 12.5 }}><input type="checkbox" checked={creds} onChange={(e) => setCreds(e.target.checked)} /> attacker holds a vendor credential (synthetic)</label>}
        <button className="btn primary big" disabled={!can(role, "analyst") || !ready || busy === "sim"} onClick={simulate}>{busy === "sim" ? "Simulating…" : "Simulate compromise"}</button>
        <div className="tip">A link alone never means compromise. Each step needs a reason: a vulnerable service, weak access, or a stolen credential.</div>
        {res && <SimResult r={res} st={st} onApplied={() => { compare(); simulate(); }} />}
      </Box>
      <Box id="scn" title="Five scenarios" icon="bolt" value="synthetic" defaultOpen>
        <div className="col">{scn.map((s) => <button key={s.id} className={"btn" + (run?.id === s.id ? " primary" : "")} style={{ textAlign: "left" }} disabled={!can(role, "analyst") || !ready || !!busy} onClick={() => runScn(s.id)}>{busy === s.id ? "Running…" : s.title}<div className="dim" style={{ fontSize: 11, fontWeight: 500, color: run?.id === s.id ? "#fff" : undefined }}>{s.sector}</div></button>)}</div>
        <div className="tip">All events are generated. Nothing touches a real system.</div>
      </Box>
      {run && (
        <Box id="scnres" title={run.title} icon="eye" value={`${run.timeline.length} events`} kind="warm" defaultOpen>
          <Kinds c={run.classification} />
          <RiskTrio unit="Ward risk index (untouched baseline = 100)" rows={[{ label: "Before", sub: "baseline", value: run.risk.before, color: C.aquaD }, { label: "During", sub: "scenario", value: run.risk.during, color: C.terra }, { label: "After", sub: "best package", value: run.risk.after_package, color: C.apricot }]} />
          <b style={{ fontSize: 12.5 }}>What we learn</b>{run.insights.map((t: string, i: number) => <div key={i} className="tip">• {t}</div>)}
          <details><summary className="tip" style={{ cursor: "pointer" }}>Assumptions and starting state</summary>{run.assumptions.map((t: string, i: number) => <div key={i} className="tip">• {t}</div>)}<div className="tip mono">{cut(JSON.stringify(run.initial_state), 160)}</div></details>
          <details><summary className="tip" style={{ cursor: "pointer" }}>Event timeline (generated)</summary>{run.timeline.slice(0, 12).map((e: any, i: number) => <div key={i} className="row" style={{ fontSize: 12, alignItems: "flex-start" }}><span className="pill info mono">+{e.t}m</span><span>{cut(e.text.replace("Synthetic: ", ""), 100)}</span></div>)}</details>
          <b style={{ fontSize: 12.5 }}>What to do about it</b><Recs recs={run.recommendations} onApplied={compare} />
          {run.package && <div className="tip">Best package: <b>{run.package.controls.map((c: string) => cut(c, 36)).join(" + ") || "none helps"}</b>. {run.package.closes_every_path ? "Closes every path." : `${run.package.still_reachable.length} asset(s) stay reachable.`}</div>}
        </Box>)}
      <Box key={cmp ? "c1" : "c0"} id={cmp ? "cmp1" : "cmp0"} defaultOpen={!!cmp} title="Before and after your changes" icon="swap" value={cmp ? `${cmp.ward_risk_before.toFixed(0)} → ${cmp.ward_risk_after.toFixed(0)}` : "try a fix"} tone={cmp && cmp.ward_risk_after < cmp.ward_risk_before ? "safe" : "info"}>
        <div className="row"><button className="btn small primary" disabled={!ready} onClick={compare}>Compare</button><button className="btn small" onClick={reset}>Reset simulation</button></div>
        {cmp && <>
          <RiskTrio unit="Ward risk index" rows={[{ label: "Before", sub: "baseline", value: cmp.ward_risk_before, color: C.terra }, { label: "After", sub: "your simulated controls", value: cmp.ward_risk_after, color: C.aquaD }]} />
          {cmp.simulation && <div className="tip">From {nameOf(st, cmp.simulation.start)}: {cmp.simulation.reachable_before.length} → {cmp.simulation.reachable_after.length} reachable assets. <b>{cmp.simulation.all_paths_eliminated ? "Every path is closed." : "Some paths remain."}</b></div>}
          {cmp.assets.slice(0, 4).filter((a: any) => a.delta < 0).map((a: any) => <div key={a.id} className="row between" style={{ fontSize: 12.5 }}><span>{cut(brief(a.name), 28)}</span><b style={{ color: C.aquaD }}>{a.risk_before.toFixed(0)} → {a.risk_after.toFixed(0)}</b></div>)}
        </>}
        <div className="dim" style={{ fontSize: 11.5 }}>Simulation only. The live twin and the baseline are untouched.</div>
      </Box>
      <Box id="rank" title="Why this priority?" icon="chart" value={rows[0] ? `#1 ${cut(brief(rows[0].name), 14)}` : "…"}>
        <div className="tip">Risk = likelihood × impact. A moderate-CVSS device that reaches many services can outrank a critical-CVSS one that reaches little.</div>
        {rows.slice(0, 8).map((r: any) => (
          <div key={r.id} className="list-row" onClick={() => explain(r.id)}>
            <span className="num-chip">{r.rank}</span>
            <div className="grow"><div className="row between" style={{ fontSize: 13 }}><b>{cut(brief(r.name), 22)}</b><span className="dim">CVSS #{r.rank_by_cvss}</span></div>
              <div className="bar" style={{ marginTop: 4 }}><div style={{ width: `${r.risk}%`, background: riskColor(r.risk / 100) }} /></div></div>
            <b style={{ width: 32, textAlign: "right" }}>{r.risk.toFixed(0)}</b>
          </div>))}
        {expl && <div className="box open" style={{ borderColor: C.apricot }}><div className="body" style={{ padding: 12 }}>
          <div className="row between"><b>{brief(expl.name)}</b><button className="btn small" onClick={() => setExpl(null)}>✕</button></div>
          <div className="grid3"><Stat v={expl.likelihood.toFixed(2)} l="likelihood" /><Stat v={expl.impact.toFixed(2)} l="impact" /><Stat v={expl.risk.toFixed(0)} l="risk" color={C.terra} /></div>
          <Bars rows={expl.drivers.filter((d: any) => d.contribution > 0).slice(0, 4).map((d: any) => ({ label: d.group, value: d.contribution * 100, color: C.apricot, note: "pts" }))} />
          <div className="tip">{expl.explanation}</div></div></div>}
      </Box>
      <Box id="how" title="How risk is calculated" icon="doc" value="model + rules">
        {model && <>
          <div className="tip"><b>Target:</b> {model.definitions.target}. Horizon: {model.definitions.horizon}.</div>
          <div className="tip"><b>Exploit prediction</b> (EPSS / KEV) is an input, not the output.</div>
          <div className="tip"><b>Likelihood:</b> ML propensity, raised by observed anomalies, lowered by monitoring. A synthetic propensity, not a real incident probability.</div>
          <div className="tip"><b>Impact:</b> expected service loss if the asset is compromised, through links and service dependencies.</div>
          <div className="tip"><b>Overall risk:</b> likelihood × impact, scaled so the top baseline asset is 100.</div>
          {model.state?.meta && <div className="grid3"><Stat v={model.state.meta.rows.toLocaleString()} l="training rows" /><Stat v={model.state.meta.spearman_heldout} l="held-out rank match" /><Stat v={model.state.meta.mae_heldout} l="held-out error" /></div>}
        </>}
      </Box>
    </>
  );
}
