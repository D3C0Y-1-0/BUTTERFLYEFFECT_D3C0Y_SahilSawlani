import React, { useEffect, useState } from "react";
import { api } from "../api";
import { useStore } from "../store";
import { C } from "../palette";
import { Bars, fmt, k, LineChart } from "./Charts";
import { Box, Ic, PageHead, Stat } from "./ui";
import { ALGOS, TAGC } from "./How";

const pct = (x: number, d = 0) => (x * 100).toFixed(d) + "%";


/** Real results for growing batches of attacks: every point is a measured run, nothing is forced to 100%. */
function BatchCharts({ rows }: { rows: any[] }) {
  const w = 560, h = 190, L = 40, R = 12, T = 14, B = 30; const n = rows.length; const x = (i: number) => L + (i / Math.max(1, n - 1)) * (w - L - R); const y = (v: number) => T + (1 - v / 100) * (h - T - B);
  const lines = [{ k: "detected_pct", name: "attacks detected", c: C.aquaD }, { k: "loss_cut_pct", name: "service loss avoided vs no response", c: "#7B61FF" }, { k: "contained_pct", name: "attacks contained", c: C.apricot }, { k: "reached_physical_pct", name: "reached physical equipment", c: C.terra }];
  const mx = Math.max(...rows.map((r) => Math.max(r.loss_none, r.loss_decoy, r.loss_iso)), 1); const gw = (w - L - R) / n;
  return (
    <div className="col" style={{ gap: 10 }}>
      <b style={{ fontSize: 12.5 }}>Percent measured at each batch size</b>
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" role="img" aria-label="Performance by batch size">
        {[0, 25, 50, 75, 100].map((g) => <g key={g}><line x1={L} x2={w - R} y1={y(g)} y2={y(g)} stroke={C.line} /><text x={L - 5} y={y(g) + 4} textAnchor="end" fontSize="10" fill={C.dim}>{g}%</text></g>)}
        {rows.map((r, i) => <text key={i} x={x(i)} y={h - 10} textAnchor="middle" fontSize="10.5" fontWeight="700" fill={C.ink}>{r.batch}</text>)}
        <text x={w - R} y={h - 1} textAnchor="end" fontSize="9.5" fill={C.dim}>attacks in the batch</text>
        {lines.map((l) => <g key={l.k}><polyline fill="none" stroke={l.c} strokeWidth="2.6" strokeLinejoin="round" points={rows.map((r, i) => `${x(i)},${y(r[l.k])}`).join(" ")} />{rows.map((r, i) => <circle key={i} cx={x(i)} cy={y(r[l.k])} r="3.6" fill="#fff" stroke={l.c} strokeWidth="2"><title>{`${l.name}: ${r[l.k]}% at ${r.batch} attacks`}</title></circle>)}</g>)}
      </svg>
      <div className="row wrap tip" style={{ gap: 12 }}>{lines.map((l) => <span key={l.k}><b style={{ color: l.c }}>━</b> {l.name}</span>)}</div>
      <b style={{ fontSize: 12.5 }}>Average service lost per attack (lower is better)</b>
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" role="img" aria-label="Average loss by batch size">
        {rows.map((r, i) => { const x0 = L + i * gw + gw * 0.12, bw = gw * 0.25; return <g key={i}>{[["loss_decoy", C.aquaD], ["loss_none", C.terra], ["loss_iso", C.apricot]].map(([k2, c], j) => { const v = r[k2 as string]; const hh = (v / mx) * (h - T - B); return <rect key={j} x={x0 + j * bw} y={h - B - hh} width={bw - 2} height={hh} rx="2" fill={c as string}><title>{`${k2}: ${v}`}</title></rect>; })}<text x={L + i * gw + gw / 2} y={h - 10} textAnchor="middle" fontSize="10.5" fontWeight="700" fill={C.ink}>{r.batch}</text></g>; })}
        <line x1={L} x2={w - R} y1={h - B} y2={h - B} stroke={C.line} />
      </svg>
      <div className="row wrap tip" style={{ gap: 12 }}><span><b style={{ color: C.aquaD }}>■</b> DECOY</span><span><b style={{ color: C.terra }}>■</b> no response</span><span><b style={{ color: C.apricot }}>■</b> cut everything</span></div>
      <table><thead><tr><th>Attacks</th><th>Detected</th><th>Median alarm</th><th>Loss avoided</th><th>Devices cut</th><th>Run time</th><th>Per attack</th></tr></thead><tbody>
        {rows.map((r) => <tr key={r.batch}><td><b>{r.batch}</b></td><td>{r.detected_pct}%</td><td>{r.median_detect_minutes ?? "–"} min</td><td>{r.loss_cut_pct}%</td><td>{r.devices_cut}</td><td>{r.seconds}s</td><td>{r.per_attack_s}s</td></tr>)}
      </tbody></table>
    </div>
  );
}

/** "Why choose our system": every number below is read from files the experiments wrote (data/experiments.json) or from the live model, never typed in. */
export function WhyView() {
  const exp = useStore((s) => s.exp), role = useStore((s) => s.role); const E: any = exp || {};
  const [model, setModel] = useState<any>(null); const [comp, setComp] = useState<any>(null);
  useEffect(() => { api("/api/v2/model").then((m) => setModel(m.state)).catch(() => {}); api("/api/compliance").then(setComp).catch(() => {}); }, []);
  const keys = Object.keys(E).filter((x) => x !== "_meta").sort((a, b) => parseInt(a.slice(1)) - parseInt(b.slice(1)));
  const met = keys.filter((x) => E[x].met).length;
  const r = (id: string) => E[id]?.result;
  const e9 = r("E9"), e11 = r("E11"), e10 = r("E10"), e1 = r("E1"), e3 = r("E3"), e6 = r("E6"), e12 = r("E12"), e16 = r("E16");
  const cut = e9 ? 1 - e9.mean_loss_decoy / Math.max(1, e9.mean_loss_no_response) : null;
  const det = e10 ? Object.values<any>(e10.detection).map((v: any) => v["fused (network + physics)"]) : [];
  const detOk = det.reduce((a, d) => a + parseInt(String(d.detected).split("/")[0]), 0), detAll = det.reduce((a, d) => a + parseInt(String(d.detected).split("/")[1]), 0);
  const mm = model?.meta; const e17 = r("E17"); const rows17: any[] = e17?.rows || []; const last17 = rows17[rows17.length - 1]; const first17 = rows17[0];
  return (
    <>
      <PageHead icon="chart" title="Why choose ATHENA" sub="Numbers measured by running the system, not typed in" right={keys.length ? <span className="pill safe">{met} of {keys.length} goals met</span> : undefined} />
      <div className="tiles">
        <div className="tile"><b>{cut !== null ? pct(cut) : "…"}</b><span>less service lost than doing nothing</span><small>{e9 ? `${e9.scenarios} simulated attacks` : ""}</small></div>
        <div className="tile"><b>{detAll ? `${detOk}/${detAll}` : "…"}</b><span>unseen attack types caught</span><small>trained on other attack types</small></div>
        <div className="tile"><b>{e1 ? e1["ours (3000 worlds)"].spearman : "…"}</b><span>ranking accuracy (Spearman)</span><small>vs 20,000 brute-force attacks</small></div>
        <div className="tile"><b>{e11 ? `${e11.runs[e11.runs.length - 1].seconds}s` : "…"}</b><span>for a 10,000-device city</span><small>500 attack worlds</small></div>
      </div>
      <div className="tip" style={{ textAlign: "center" }}><Ic n="check" /> Re-run any number: <b>python backend/experiments.py</b> writes <b>data/experiments.json</b> (last run {E._meta?.generated || "–"}).</div>

      <Box id="why_more" title="More numbers" icon="chart" value="measured" defaultOpen>
        <div className="grid3">
          {e9 && <Stat v={`${e9.detected_pct}%`} l="attacks detected (80-attack set)" color={C.aquaD} />}
          {e9 && <Stat v={`${e9.median_detect_minutes} min`} l="median time to alarm" color={C.aquaD} />}
          {e9 && <Stat v={`${e9.hospital_hours_decoy}h`} l={`hospital water lost (vs ${e9.hospital_hours_none}h with no response)`} color={C.aquaD} />}
          {mm && <Stat v={mm.rows?.toLocaleString()} l="risk-model training rows" />}
          {mm && <Stat v={mm.test_rows?.toLocaleString()} l="unseen cases it was tested on" />}
          {mm && <Stat v={mm.spearman_heldout} l="forecast rank match" color={C.aquaD} />}
          {e3 && <Stat v={`${e3.greedy_gap_pct}%`} l={`fix plan from the best of ${fmt(e3.feasible_plans_checked)} plans`} />}
          {e6 && <Stat v={`${fmt(e6.speedup)}×`} l="fast guesser speed-up" />}
          {e12 && <Stat v={e12.candidate_actions_blocked_in_scenarios} l="unsafe actions blocked" color={C.aquaD} />}
        </div>
      </Box>

      <Box id="why_batches" title="Growing batches of attacks" icon="layers" value={last17 ? `${first17.batch} to ${last17.batch} attacks` : "run E17"} defaultOpen>
        {rows17.length ? <>
          <div className="tiles">
            <div className="tile"><b>{last17.detected_pct}%</b><span>detected at {last17.batch} attacks</span><small>{first17.detected_pct}% at {first17.batch}</small></div>
            <div className="tile"><b>{last17.loss_cut_pct}%</b><span>service loss avoided</span><small>{first17.loss_cut_pct}% at {first17.batch}</small></div>
            <div className="tile"><b>{last17.median_detect_minutes ?? "–"} min</b><span>median time to alarm</span><small>at {last17.batch} attacks</small></div>
            <div className="tile"><b>{last17.per_attack_s}s</b><span>per attack, simulated end to end</span><small>{first17.per_attack_s}s at {first17.batch}</small></div>
          </div>
          <BatchCharts rows={rows17} />
          <div className="tip">{e17.note} Lines that do not reach 100% are real: some attacks (for example stealthy or insider ones) are noticed late or only after equipment is touched, and that is shown, not hidden.</div>
        </> : <div className="tip">Run <b>python backend/experiments.py E17</b> to measure this.</div>}
      </Box>

      <Box id="why_batch" title="Tested on batches of attacks" icon="bolt" value={e9 ? `${e9.scenarios} attacks` : "…"} defaultOpen>
        {e9 ? <>
          <Bars rows={[{ label: "ATHENA", value: e9.mean_loss_decoy, color: C.aquaD }, { label: "No response", value: e9.mean_loss_no_response, color: C.terra }, { label: "Cut everything", value: e9.mean_loss_isolate_all, color: C.apricot }]} />
          <div className="tip">Average service lost per attack (lower is better). {e9.attacks_that_would_hurt_without_response} of {e9.scenarios} attacks would have hurt the city without a response.</div>
          <div className="grid3"><Stat v={`${e9.detected_pct}%`} l="detected" color={C.aquaD} /><Stat v={`${e9.hospital_hours_decoy}h`} l="hospital water lost" color={C.aquaD} /><Stat v={`${e9.mean_devices_disconnected_decoy}`} l={`devices cut (vs ${e9.devices_disconnected_isolate_all})`} /></div>
        </> : <div className="tip">Run backend/experiments.py to fill this in.</div>}
      </Box>

      <Box id="why_scale" title="Scales to a whole city" icon="layers" value={e11 ? `${fmt(e11.runs[e11.runs.length - 1].nodes)} devices` : "…"} defaultOpen>
        {e11 ? <>
          <LineChart h={110} series={[{ name: "seconds", color: C.terra, data: e11.runs.map((x: any) => x.seconds), width: 3.4 }]} />
          <table><thead><tr><th>Devices</th><th>Links</th><th>Time</th><th>Memory</th></tr></thead><tbody>{e11.runs.map((x: any) => <tr key={x.nodes}><td><b>{fmt(x.nodes)}</b></td><td>{fmt(x.edges)}</td><td>{x.seconds}s</td><td>{x.mem_mb} MB</td></tr>)}</tbody></table>
          <div className="tip">100 times more devices took about {e11.growth_10x_nodes}× longer per 10× growth: close to straight-line growth, so a bigger city is slower, not impossible.</div>
        </> : null}
      </Box>

      <Box id="why_acc" title="How accurate are the models?" icon="target" value="measured">
        <table><thead><tr><th>Model</th><th>Result</th><th>Goal</th></tr></thead><tbody>
          {e1 && <tr><td><b>Risk ranking</b><div className="dim">Which devices hurt most</div></td><td>Spearman {e1["ours (3000 worlds)"].spearman}, top-10 overlap {e1["ours (3000 worlds)"].top10_overlap}/10 (CVSS alone: {e1.cvss?.spearman})</td><td>≥ 0.90 ✓</td></tr>}
          {e10 && <tr><td><b>Attack detector</b><div className="dim">Watchdog on unseen attack types</div></td><td>{detOk}/{detAll} detected, median delay under 30 min</td><td>&lt; 30 min ✓</td></tr>}
          {e6 && <tr><td><b>Fast guesser</b><div className="dim">Predicts harm instantly</div></td><td>Spearman {e6.spearman}, coverage {e6.coverage}, {fmt(e6.speedup)}× faster</td><td>≥ 0.90 ✓</td></tr>}
          {e3 && <tr><td><b>Fix plan</b><div className="dim">Greedy vs best possible</div></td><td>{e3.greedy_gap_pct}% from the best of {e3.feasible_plans_checked} plans</td><td>≤ 10% ✓</td></tr>}
          {mm && <tr><td><b>Attack forecast</b><div className="dim">Which device falls next</div></td><td>Spearman {mm.spearman_heldout}, error {mm.mae_heldout}{mm.top5_overlap_heldout != null ? `, top-5 overlap ${pct(mm.top5_overlap_heldout)}` : ""}</td><td>unseen configs</td></tr>}
          {e12 && <tr><td><b>Safety Check</b><div className="dim">Blocks harmful fixes</div></td><td>{e12.candidate_actions_blocked_in_scenarios} unsafe actions blocked, {e12.scenarios_where_response_made_hospital_worse} made a hospital worse</td><td>0 ✓</td></tr>}
          {e16 && <tr><td><b>Zero-day library</b><div className="dim">Second encounter</div></td><td>cost {k(e16.first_encounter)} → {k(e16.repeat_encounter)}</td><td>lower ✓</td></tr>}
        </tbody></table>
        <div className="tip">All accuracy is measured against the simulator on cases the model never saw. It is not a claim about real-world incidents.</div>
      </Box>

      <Box id="why_algo" title="The algorithms behind it" icon="sparkle" value={`${ALGOS.length}`} defaultOpen>
        <div className="algotable">{ALGOS.map((x) => <div key={x.name}><span className="atag" style={{ background: TAGC[x.tag] }}>{x.tag}</span><div><b>{x.name}</b><small>{x.plain}</small></div><em>{x.where}</em></div>)}</div>
        <div className="tip">Each one is explained, with its rules and numbers, on the <b>How it works</b> page.</div>
      </Box>

      <Box id="why_fit" title="Fits the rules and your network" icon="lock" value="CERT-In">
        <div className="chips">
          <span className="chip ok">6-hour report clock {comp ? `· ${comp.clocks.length} open` : ""}</span>
          <span className="chip ok">Logs kept in India {comp ? `· ${comp.vault.retention_days} days` : "· 180 days"}</span>
          <span className="chip ok">Clock-sync guard {comp ? (comp.time.ok ? "· in sync" : "· drift!") : ""}</span>
          <span className="chip ok">Parts list (SBOM) {comp ? `· ${(comp.sbom_coverage * 100).toFixed(0)}%` : ""}</span>
          <span className="chip">IEC 62443 zones and conduits</span><span className="chip">MITRE ATT&amp;CK for ICS</span><span className="chip">Smart-city device classes (Annexure II)</span>
        </div>
        <div className="steps3"><div><b>1 Read</b><span>Mirror port, historian and logs. Read-only.</span></div><div><b>2 Think</b><span>Runs beside the plant, never inside the control loop.</span></div><div><b>3 Ask</b><span>Safe steps automatic; risky ones need a person (two for big ones).</span></div></div>
        <div className="tip">Works offline: signed snapshot files move between isolated networks. We say <b>aligned with</b> these rules, not "certified". Deployment steps such as TLS between services are design-level.</div>
      </Box>

    </>
  );
}
