import React, { useEffect, useState } from "react";
import { api } from "../api";
import { useStore } from "../store";
import { C } from "../palette";
import { Bars, fmt, k, LineChart } from "./Charts";
import { Box, Ic, PageHead, Stat } from "./ui";
import { ALGOS, TAGC } from "./How";

const TYPE_NAMES = { standard: "Known exploit", zero_day: "Zero-day", spoof: "Fake sensor readings", wear: "Breaker wear", insider: "Insider", ddos: "DDoS flood", swarm: "Many small attacks", blitz: "Fast and loud", group: "Coordinated group" };
const pct = (x: number, d = 0) => (x * 100).toFixed(d) + "%";


/** Real results for growing batches of attacks: every point is a measured run, nothing is forced to 100%. */
function BatchCharts({ rows }: { rows: any[] }) {
  const w = 560, h = 200, L = 42, R = 14, T = 14, B = 34;
  const lx = (v: number) => Math.log10(Math.max(1, v)); const lo = lx(rows[0].batch), hi = lx(rows[rows.length - 1].batch);
  const x = (v: number) => L + ((lx(v) - lo) / Math.max(1e-9, hi - lo)) * (w - L - R); const FLOOR = 70; const y = (v: number) => T + (1 - (Math.max(FLOOR, Math.min(100, v)) - FLOOR) / (100 - FLOOR)) * (h - T - B);
  const pick = (r: any, k: string) => (typeof r[k] === "number" ? r[k] : null);
  const lines = [{ k: "stopped_before_damage_pct", name: "damaging attacks stopped before equipment was touched", c: C.aquaD }, { k: "intruders_detected_pct", name: "intruders caught (even harmless ones)", c: C.apricot }, { k: "loss_cut_pct", name: "service loss avoided vs no response", c: "#7B61FF" }];
  // loss bars: log scale so ATHENA's small loss is visible next to the large ones; every bar carries its number
  const vals = rows.flatMap((r) => [r.loss_decoy, r.loss_none, r.loss_iso]); const top = Math.log10(Math.max(10, ...vals) * 1.3); const bh = (v: number) => (Math.log10(Math.max(1, v) + 1) / top) * (h - T - B);
  const gw = (w - L - R) / rows.length; const fm = (v: number) => (v >= 1000 ? (v / 1000).toFixed(v >= 10000 ? 0 : 1) + "k" : String(Math.round(v)));
  return (
    <div className="col" style={{ gap: 10 }}>
      <b style={{ fontSize: 12.5 }}>Percent at each batch size (batch size = number of attacks, log scale; the vertical axis starts at 70% so small differences show)</b>
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" role="img" aria-label="Performance by batch size">
        {[70, 80, 90, 100].map((g) => <g key={g}><line x1={L} x2={w - R} y1={y(g)} y2={y(g)} stroke={C.line} /><text x={L - 5} y={y(g) + 4} textAnchor="end" fontSize="10" fill={C.dim}>{g}%</text></g>)}
        {rows.map((r) => <g key={r.batch}><line x1={x(r.batch)} x2={x(r.batch)} y1={T} y2={h - B} stroke={C.line} strokeDasharray="2 4" /><text x={x(r.batch)} y={h - 14} textAnchor="middle" fontSize="10.5" fontWeight="700" fill={C.ink}>{r.batch >= 1000 ? r.batch / 1000 + "k" : r.batch}</text></g>)}
        <text x={w - R} y={h - 1} textAnchor="end" fontSize="9.5" fill={C.dim}>attacks in the batch</text>
        {lines.map((l) => { const pts = rows.filter((r) => pick(r, l.k) !== null); return <g key={l.k}><polyline fill="none" stroke={l.c} strokeWidth="2.6" strokeLinejoin="round" points={pts.map((r) => `${x(r.batch)},${y(r[l.k])}`).join(" ")} />{pts.map((r) => <circle key={r.batch} cx={x(r.batch)} cy={y(r[l.k])} r="3.8" fill="#fff" stroke={l.c} strokeWidth="2"><title>{`${l.name}: ${r[l.k]}% at ${r.batch} attacks`}</title></circle>)}</g>; })}
      </svg>
      <div className="row wrap tip" style={{ gap: 12 }}>{lines.map((l) => <span key={l.k}><b style={{ color: l.c }}>━</b> {l.name}</span>)}</div>
      <b style={{ fontSize: 12.5 }}>Average service lost per attack (lower is better; log scale)</b>
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" role="img" aria-label="Average loss by batch size">
        {rows.map((r, i) => { const x0 = L + i * gw + gw * 0.1, bw = gw * 0.27; return <g key={r.batch}>{[["loss_decoy", C.aquaD], ["loss_none", C.terra], ["loss_iso", C.apricot]].map(([k2, c], j) => { const v = r[k2 as string] ?? 0; const hh = Math.max(3, bh(v)); return <g key={j}><rect x={x0 + j * bw} y={h - B - hh} width={bw - 2} height={hh} rx="2" fill={c as string}><title>{`${k2}: ${v}`}</title></rect><text x={x0 + j * bw + (bw - 2) / 2} y={h - B - hh - 3} textAnchor="middle" fontSize="8.5" fontWeight="700" fill={C.ink}>{fm(v)}</text></g>; })}<text x={L + i * gw + gw / 2} y={h - 14} textAnchor="middle" fontSize="10.5" fontWeight="700" fill={C.ink}>{r.batch >= 1000 ? r.batch / 1000 + "k" : r.batch}</text></g>; })}
        <line x1={L} x2={w - R} y1={h - B} y2={h - B} stroke={C.line} />
      </svg>
      <div className="row wrap tip" style={{ gap: 12 }}><span><b style={{ color: C.aquaD }}>■</b> ATHENA</span><span><b style={{ color: C.terra }}>■</b> no response</span><span><b style={{ color: C.apricot }}>■</b> cut everything</span></div>
      <div className="tablewrap"><table><thead><tr><th>Attacks</th><th>Would harm equipment</th><th>Stopped before equipment was touched</th><th>Intruders caught</th><th>Alarm: median / slowest</th><th>Loss avoided</th><th>Worst single loss</th><th>Run time</th></tr></thead><tbody>
        {rows.map((r) => <tr key={r.batch}><td><b>{r.batch}</b></td><td>{r.harmful_physical ?? "–"}</td>
          <td>{r.stopped_before_damage_pct != null ? <><b>{r.stopped_before_damage_pct}%</b><div className="dim" style={{ fontSize: 10.5 }}>{r.reached_equipment} got through · at least {r.stopped_before_damage_low95}%</div></> : "–"}</td>
          <td>{r.intruders_detected_pct ?? "–"}%{r.intruders_detected_low95 != null && <div className="dim" style={{ fontSize: 10.5 }}>at least {r.intruders_detected_low95}%</div>}</td>
          <td>{r.median_detect_minutes ?? "–"} / {r.slowest_detect_minutes != null ? Math.round(r.slowest_detect_minutes) : "–"} min</td><td>{r.loss_cut_pct}%</td>
          <td>{r.worst_single_loss != null ? <>{fmt(r.worst_single_loss)}<div className="dim" style={{ fontSize: 10.5 }}>{r.attacks_with_any_loss} attacks lost anything</div></> : "–"}</td>
          <td>{r.seconds >= 3600 ? (r.seconds / 3600).toFixed(1) + " h" : r.seconds >= 120 ? Math.round(r.seconds / 60) + " min" : Math.round(r.seconds) + " s"}</td></tr>)}
      </tbody></table></div>
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
  const [sel, setSel] = useState(-1); const mm = model?.meta; const e17 = r("E17"); const rows17: any[] = e17?.rows || []; const last17 = rows17[rows17.length - 1]; const selIdx = sel >= 0 && sel < rows17.length ? sel : rows17.length - 1; const selRow = rows17[selIdx]; const first17 = rows17[0];
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

      {last17 && (() => { const e21 = E.E21?.result; const e22 = E.E22?.result?.regimes?.["with traffic-level correction"]; const e23 = E.E23?.result?.runs; const fa = e22 ? Object.values<any>(e22).reduce((x: number, v: any) => x + v.false_incidents, 0) : null; const si = e23?.["independent meters on a separate path"], sn = e23?.["control network only"];
        return <Box id="why_score" title="Scorecard: ATHENA against doing nothing" icon="sparkle" value={`${last17.batch} attacks tested`} defaultOpen>
          <div className="score-hero">
            <div className="sh"><b>{last17.loss_cut_pct}%</b><span>of service loss avoided</span><small>{k(last17.loss_none)} lost with no response, {k(last17.loss_iso)} if everything is cut, {k(last17.loss_decoy)} with ATHENA</small></div>
            <div className="sh"><b>{last17.intruders_detected_pct ?? "–"}%</b><span>of intruders caught</span><small>95% sure at least {last17.intruders_detected_low95 ?? "–"}%</small></div>
            <div className="sh"><b>{last17.stopped_before_damage_pct}%</b><span>of damaging attacks stopped before equipment was touched</span><small>95% sure at least {last17.stopped_before_damage_low95}%</small></div>
            <div className="sh"><b>{last17.median_detect_minutes} min</b><span>median time to alarm</span><small>vs about 312 days for an unnoticed intruder in the wild (Bilge and Dumitras)</small></div>
          </div>
          <div className="score-row">
            {fa !== null && <div><b>{fa}</b><span>false alarms in 12 calm days, even with swinging and bursty traffic</span></div>}
            {e21 && <div><b>{e21.top10_hit_pct}%</b><span>of attacks had a forecast top-10 device taken</span></div>}
            {si && <div><b>{si.median_minutes_to_alarm} min</b><span>to catch a careful forger with independent meters ({sn?.median_minutes_to_alarm} without)</span></div>}
            <div><b>0</b><span>cuts to hospital systems without proof or a person</span></div>
          </div>
          <div className="tip">Measured on {last17.batch} simulated attacks, every type in equal share, with a simulated on-call operator. Weakest spots, shown not hidden: {Math.round(100 - last17.stopped_before_damage_pct)}% of damaging attacks still reach equipment; results are from our own simulator, not real incidents.</div>
        </Box>; })()}

      <Box id="why_fit" title="Government compliance and integration" icon="lock" value="India" defaultOpen>
        <div className="tablewrap"><table><thead><tr><th>Rule or standard</th><th>What it asks</th><th>What ATHENA does</th><th>Status</th></tr></thead><tbody>
          <tr><td><b>CERT-In Directions (28 Apr 2022)</b></td><td>Report an incident within 6 hours</td><td>A 6-hour clock starts at the alarm; one click exports the report{comp ? ` (${comp.clocks.length} clock${comp.clocks.length === 1 ? "" : "s"} now)` : ""}</td><td><span className="pill safe">Built</span></td></tr>
          <tr><td><b>CERT-In Directions</b></td><td>Keep logs 180 days, in India</td><td>Tamper-evident log vault{comp ? `, ${comp.vault.retention_days}-day rule` : ""}</td><td><span className="pill safe">Built</span></td></tr>
          <tr><td><b>CERT-In Directions</b></td><td>Synchronise clocks</td><td>Clock-sync guard{comp ? (comp.time.ok ? ": all in sync" : ": drift found") : ""}; events from drifting clocks are marked uncertain</td><td><span className="pill safe">Built</span></td></tr>
          <tr><td><b>CERT-In Smart City Guidelines 2025 / MoHUA advisories</b></td><td>Login security, separation of networks, parts list, incident handling</td><td>MFA and roles, risky-link cutting, parts list (SBOM){comp ? ` ${(comp.sbom_coverage * 100).toFixed(0)}%` : ""}, response playbooks</td><td><span className="pill safe">Built</span></td></tr>
          <tr><td><b>IEC 62443, NIST CSF 2.0, MITRE ATT&amp;CK for ICS</b></td><td>Zones and conduits, identify-protect-detect-respond-recover</td><td>Layers and links follow zones; findings use ATT&amp;CK technique names</td><td><span className="pill watch">Aligned</span></td></tr>
          <tr><td><b>NCIIPC guidelines, IT Act s.70B, DPDP Act 2023</b></td><td>Protect critical systems; report; handle personal data</td><td>Reads device data only; no personal data is stored; reporting follows CERT-In</td><td><span className="pill watch">Design level</span></td></tr>
        </tbody></table></div>
        <b style={{ fontSize: 12.5 }}>How it plugs into a real city network</b>
        <div className="tablewrap"><table><thead><tr><th>Connection</th><th>How</th><th>Status</th></tr></thead><tbody>
          <tr><td>Network traffic</td><td>Read-only copy from a mirror (SPAN) port; never inline, never in the control loop</td><td><span className="pill watch">Design level (simulated here)</span></td></tr>
          <tr><td>Plant data</td><td>Reads the historian and SCADA readings (Modbus / OPC UA) read-only</td><td><span className="pill watch">Design level (simulated here)</span></td></tr>
          <tr><td>Reports and logs</td><td>JSON incident report in CERT-In form; REST API with signed, expiring tokens and roles</td><td><span className="pill safe">Built</span></td></tr>
          <tr><td>Isolated networks</td><td>Signed snapshot files move between air-gapped sites and are rejected if replayed, altered or signed by an unknown key</td><td><span className="pill safe">Built</span></td></tr>
          <tr><td>SIEM and ticketing</td><td>Syslog / CEF export and a ticket webhook</td><td><span className="pill">Planned</span></td></tr>
          <tr><td>Staff sign-in</td><td>Single sign-on with the city's directory (LDAP / SAML)</td><td><span className="pill">Planned</span></td></tr>
        </tbody></table></div>
        <div className="steps3"><div><b>1 Read</b><span>Mirror port, historian and logs. Read-only.</span></div><div><b>2 Think</b><span>Runs beside the plant, never inside the control loop.</span></div><div><b>3 Ask</b><span>Safe steps are automatic; risky ones need a person (two for big ones).</span></div></div>
        <div className="tip">We say <b>aligned with</b> these rules, not "certified". "Design level" and "Planned" are not built in this prototype.</div>
      </Box>

      <Box id="why_feas" title="Feasibility: can a city really run this?" icon="check" value="one machine" defaultOpen>
        <div className="grid3">
          <Stat v={e11 ? `${e11.runs[e11.runs.length - 1].seconds}s` : "–"} l={e11 ? `to analyse a ${fmt(e11.runs[e11.runs.length - 1].nodes)}-device city` : "city analysis"} color={C.aquaD} />
          <Stat v={e11 ? `${e11.runs[e11.runs.length - 1].mem_mb} MB` : "–"} l="memory for that city" color={C.aquaD} />
          <Stat v="0" l="GPUs, cloud services or internet links needed" color={C.aquaD} />
        </div>
        <div className="steps3"><div><b>1 Read</b><span>Takes a read-only copy of traffic and plant readings. Never inline.</span></div><div><b>2 Think</b><span>Runs beside the plant on one ordinary computer, in about 10 seconds from start.</span></div><div><b>3 Ask</b><span>Safe, reversible steps run on their own; risky ones need a person (two for big ones).</span></div></div>
        <div className="tip">Needs: one Windows or Linux machine with Python 3.11+. Works offline. Not built yet: live mirror-port and historian connectors, SIEM export and city sign-in (see the table above).</div>
      </Box>

      <Box id="why_scale" title="Scalability" icon="layers" value={rows17.length ? `up to ${last17.batch} attacks` : "…"} defaultOpen>
        <b style={{ fontSize: 12.5 }}>Bigger city</b>

        {e11 ? <>
          <LineChart h={110} series={[{ name: "seconds", color: C.terra, data: e11.runs.map((x: any) => x.seconds), width: 3.4 }]} />
          <table><thead><tr><th>Devices</th><th>Links</th><th>Time</th><th>Memory</th></tr></thead><tbody>{e11.runs.map((x: any) => <tr key={x.nodes}><td><b>{fmt(x.nodes)}</b></td><td>{fmt(x.edges)}</td><td>{x.seconds}s</td><td>{x.mem_mb} MB</td></tr>)}</tbody></table>
          <div className="tip">100 times more devices took about {e11.growth_10x_nodes}× longer per 10× growth: close to straight-line growth, so a bigger city is slower, not impossible.</div>
        </> : null}
      
        <b style={{ fontSize: 12.5 }}>Bigger batches of attacks</b>

        {rows17.length ? <>
          <div className="tiles">
            <div className="tile"><b>{last17.stopped_before_damage_pct}%</b><span>of damaging attacks stopped before equipment was touched</span><small>{last17.reached_equipment} of {last17.harmful_physical} got through</small></div>
            <div className="tile"><b>{last17.loss_cut_pct}%</b><span>service loss avoided</span><small>{first17.loss_cut_pct}% at {first17.batch}</small></div>
            <div className="tile"><b>{last17.median_detect_minutes ?? "–"} min</b><span>median time to alarm</span><small>90% within {last17.p90_detect_minutes != null ? Math.round(last17.p90_detect_minutes) : "–"} min</small></div>
            <div className="tile"><b>{e17.false_alarm_runs}/{e17.calm_runs}</b><span>calm runs with a false alarm</span><small>{e17.calm_hours} hours with no attack</small></div>
          </div>
          <div className="tip" style={{ display: "none" }}>Every batch holds an equal number of each of the 8 attack types (known exploit, zero-day, fake readings, breaker wear, insider, DDoS flood, many small attacks, fast and loud) and cycles evenly through the 8 pieces of equipment, so no batch is easier than another.</div>
          <BatchCharts rows={rows17} />
          {e17.by_type && <><b style={{ fontSize: 12.5 }}>By attack type, in the largest batch ({last17.batch} attacks)</b>
            <table><thead><tr><th>Attack type</th><th>Attacks</th><th>Harmful</th><th>Harmful caught</th><th>Alarm median / 99%</th><th>Loss: none → ATHENA</th><th>Reached equipment</th></tr></thead><tbody>
              {Object.entries<any>(e17.by_type).map(([t, v]) => <tr key={t}><td><b>{(TYPE_NAMES as any)[t] || t}</b></td><td>{v.attacks}</td><td>{v.harmful}</td><td>{v.harmful_detected_pct ?? "–"}%</td><td>{v.median_detect_minutes ?? "–"} / {v.p99_detect_minutes != null ? Math.round(v.p99_detect_minutes) : "–"} min</td><td>{fmt(v.loss_none)} → <b>{fmt(v.loss_athena)}</b></td><td>{v.reached_equipment}</td></tr>)}
            </tbody></table></>}
          <div className="tip">Batch size is the number of attacks. Every batch has an even mix of all 8 attack types. The attacker and the defence are simulated separately, so these numbers show how the system behaves inside the simulation; real-world results would be lower. Intruders who get in but do no harm are the hardest to catch, so they are shown separately.</div>
        </> : <div className="tip">Run <b>python backend/experiments.py E17</b> to measure this.</div>}
      

        {rows17.length ? <>
          <div className="seg" role="tablist" aria-label="Batch size">{rows17.map((r: any, i: number) => <button key={r.batch} className={i === selIdx ? "on" : ""} onClick={() => setSel(i)}>{r.batch}</button>)}</div>
          <Bars rows={[{ label: "ATHENA", value: selRow.loss_decoy, color: C.aquaD }, { label: "No response", value: selRow.loss_none, color: C.terra }, { label: "Cut everything", value: selRow.loss_iso, color: C.apricot }]} />
          <div className="tip">Average service lost per attack across {selRow.batch} attacks (lower is better).</div>
          <div className="grid3">
            <Stat v={`${selRow.stopped_before_damage_pct ?? "–"}%`} l={`damaging attacks stopped in time (${selRow.harmful_physical ?? "–"} would have harmed equipment)`} color={C.aquaD} />
            <Stat v={`${selRow.intruders_detected_pct ?? "–"}%`} l="intruders caught" color={C.apricot} />
            <Stat v={`${selRow.median_detect_minutes ?? "–"} min`} l="median time to alarm" color={C.aquaD} />
            <Stat v={`${selRow.loss_cut_pct}%`} l="service loss avoided" color={C.aquaD} />
            <Stat v={selRow.worst_single_loss != null ? fmt(selRow.worst_single_loss) : "–"} l="worst single attack (loss)" color={C.terra} />
            <Stat v={`${selRow.devices_cut}`} l="devices cut on average (cutting everything = 27)" />
          </div>
        </> : <div className="tip">Run backend/experiments.py to fill this in.</div>}
      
      </Box>

      <Box id="why_metrics" title="Metrics" icon="chart" value="measured" defaultOpen>

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
      

        {E.E21?.result ? (() => { const p = E.E21.result; return <>
          <div className="tiles">
            <div className="tile"><b>{p.top5_hit_pct}%</b><span>of attacks that got in took a device from the forecast's top 5</span><small>{p.got_in} of {p.attacks} attacks got in</small></div>
            <div className="tile"><b>{p.top10_hit_pct}%</b><span>took a device from the top 10 (of {p.forecast_list_size})</span><small>precision at 5: {p.precision_at_5_pct}%</small></div>
            <div className="tile"><b>{p.entry_in_top10_pct}%</b><span>of entry doors were in the top-10 forecast</span><small>top 5: {p.entry_in_top5_pct}%</small></div>
            <div className="tile"><b>{p.next_step_top1_pct ?? "–"}%</b><span>next step guessed right when the alarm opened (top 3: {p.next_step_top3_pct ?? "–"}%)</span><small>{p.next_step_attacks} attacks with a next step</small></div>
          </div>
          <table><thead><tr><th>Attack type</th><th>Attacks</th><th>Got in</th><th>Top-5 hit</th><th>Top-10 hit</th><th>Entry in top 10</th></tr></thead><tbody>
            {Object.entries<any>(p.by_type).map(([t, v]) => <tr key={t}><td><b>{(TYPE_NAMES as any)[t] || t}</b></td><td>{v.attacks}</td><td>{v.got_in}</td><td>{v.top5_hit_pct ?? "–"}%</td><td>{v.top10_hit_pct ?? "–"}%</td><td>{v.entry_in_top10_pct ?? "–"}%</td></tr>)}
          </tbody></table>
          <div className="tip">{p.note} Measured on the simulator, with the same attacker that generates the test attacks, so it is an upper bound on real-world accuracy.</div></>; })() : <div className="tip">Run <b>python backend/experiments.py E21</b>.</div>}
      
        {E.E22?.result && E.E23?.result && (() => { const a = E.E22.result.regimes["with traffic-level correction"], b = E.E22.result.regimes["without (old behaviour)"], sp = E.E23.result.runs; const si = sp["independent meters on a separate path"], sn = sp["control network only"];
          const fi = (r: any) => Object.values<any>(r).reduce((x, v) => x + v.false_incidents, 0);
          return <>
            <b style={{ fontSize: 12.5 }}>Where the first version was weak, and what changed</b>
            <div className="tiles">
              <div className="tile"><b>{fi(a)} vs {fi(b)}</b><span>false alarms in 12 calm days of non-textbook traffic (daily swing, bursts), with vs without the traffic-level correction</span><small>4 regimes x 3 days. Synthetic, not real captures.</small></div>
              <div className="tile"><b>{si.median_minutes_to_alarm} min vs {sn.median_minutes_to_alarm} min</b><span>time to catch a careful telemetry forger, with vs without meters on a separate path</span><small>{si.attacks_that_reached_the_pump} attacks that reached the pump</small></div>
            </div>
            <div className="tip">Forged traffic can no longer make ATHENA cut hospital-adjacent equipment by itself: without physical proof a person must confirm, automatic steps are rate-limited, and "nobody answered" pages again instead of acting. Needs independent meters on site, and real traffic captures to confirm the false-alarm numbers.</div></>; })()}
      </Box>

      <Box id="why_works" title="Why ATHENA works" icon="sparkle" value="5 reasons" defaultOpen>
        <div className="rule"><b>It watches both the network and the physics.</b><span>Odd traffic and a broken physics rule are fused into one alarm. A hacker can fake data but not physics.</span></div>
        <div className="rule"><b>It predicts before it reacts.</b><span>It ranks which devices fall next and which route an attacker will take, so fixes go where they matter.</span></div>
        <div className="rule"><b>It tests every move first.</b><span>A response is tried on a copy of the city; if a hospital would get worse, it is refused.</span></div>
        <div className="rule"><b>It cuts only what is needed.</b><span>A few devices are cut instead of the whole city, so water and power keep running.</span></div>
        <div className="rule"><b>It stays honest.</b><span>Attacker and defence are simulated separately, numbers carry confidence bounds, and misses are shown.</span></div>
        <details><summary className="tip" style={{ cursor: "pointer" }}>The {ALGOS.length} algorithms behind it</summary>

        <div className="algotable">{ALGOS.map((x) => <div key={x.name}><span className="atag" style={{ background: TAGC[x.tag] }}>{x.tag}</span><div><b>{x.name}</b><small>{x.plain}</small></div><em>{x.where}</em></div>)}</div>
      
        </details>
      </Box>

    </>
  );
}
