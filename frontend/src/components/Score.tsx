import React from "react";
import { C } from "../palette";
import { k, LineChart } from "./Charts";
import { Ic, Stat } from "./ui";
import { nameOf, plainMove } from "./status";

const INR_PER_HOME_HOUR = 70;   // SYNTHETIC: same rate the Paths page uses (assumptions.py, inr_per_household_hour)
const mm = (m: number) => (m < 60 ? `${Math.max(0, Math.round(m))} min` : `${Math.floor(m / 60)} h ${Math.round(m % 60)} min`);

/** Everything on this card is worked out from the live attack and the live response: nothing is typed in. */
export function attackFacts(snap: any, st: any, hist: any[]) {
  const camp = [...(snap.adversary || [])].reverse()[0];
  const inc = [...(snap.incidents || [])].reverse().find((i: any) => !camp || i.t0 >= (camp.started ?? 0) - 1) || null;
  if (!camp) return null;
  const stage = (n: string) => inc?.stages?.find((s: any) => s.stage === n)?.minute as number | undefined;
  const det = stage("Detected"), cutAt = stage("Cut made"), ver = stage("Verified"), rec = stage("Recovered");
  const taken = Math.max(0, camp.compromised.length - 1); const total = Object.keys(st.assets).length - 1;
  const cutN = (snap.defence.quarantined?.length || 0) + (snap.defence.blocked?.length || 0);
  const c = snap.compare; const hosp = (o: any) => Object.values<any>(o || {}); const hOk = (o: any) => hosp(o).filter((h) => h.ok).length;
  const since = hist.filter((x) => x.t >= camp.started - 3);
  const low = since.length ? Math.min(...since.map((x) => x.live)) : snap.services.served_frac;
  const saved = Math.max(0, c.none_hh - c.live_hh); const harmCut = c.none_hh > 0 ? Math.max(0, 1 - c.live_hh / c.none_hh) : null;
  const steps: { t: number; kind: string; text: string }[] = [];
  for (const h of camp.hops) steps.push({ t: h.minute, kind: "atk", text: `Attacker reaches ${nameOf(st, h.dst)}` });
  if (det !== undefined) steps.push({ t: det, kind: "det", text: "ATHENA raises the alarm" });
  for (const a of inc?.actions || []) steps.push({ t: a.minute, kind: "act", text: plainMove(a.label).title });
  if (ver !== undefined) steps.push({ t: ver, kind: "ver", text: "Checked: attacker gone" });
  if (rec !== undefined) steps.push({ t: rec, kind: "rec", text: "Service recovered" });
  steps.sort((a, b) => a.t - b.t);
  return { camp, inc, det, cutAt, ver, rec, taken, total, cutN, c, hOk: hOk(snap.services.hospitals), hAll: hosp(snap.services.hospitals).length, hNone: hOk(c.none_hosp), hIso: hOk(c.iso_hosp), low, saved, harmCut, since, steps, start: camp.started as number };
}

/** A small time line: red dots = what the attacker did, amber = alarm, aqua = what ATHENA did. */
export function RunTimeline({ steps, start, now }: { steps: { t: number; kind: string; text: string }[]; start: number; now: number }) {
  const w = 360, h = 74, end = Math.max(now, start + 10, ...steps.map((s) => s.t)); const x = (t: number) => 14 + ((t - start) / Math.max(1, end - start)) * (w - 28);
  const col: Record<string, string> = { atk: "#E11D48", det: C.apricot, act: C.aquaD, ver: C.aquaD, rec: C.aquaD };
  return (
    <svg width="100%" viewBox={`0 0 ${w} ${h}`} role="img" aria-label="Attack and response in time order">
      <line x1={14} x2={w - 14} y1={34} y2={34} stroke={C.line} strokeWidth="3" strokeLinecap="round" />
      <line x1={14} x2={x(now)} y1={34} y2={34} stroke={C.sand} strokeWidth="3" strokeLinecap="round" />
      {steps.map((s, i) => <g key={i}><circle cx={x(s.t)} cy={s.kind === "atk" ? 26 : 42} r="6" fill={col[s.kind]} stroke="#fff" strokeWidth="2"><title>{`+${Math.round(s.t - start)} min: ${s.text}`}</title></circle>
        {s.kind === "det" && <text x={x(s.t)} y={66} textAnchor="middle" fontSize="10" fontWeight="800" fill="#B56400">alarm</text>}
        {s.kind === "ver" && <text x={x(s.t)} y={66} textAnchor="middle" fontSize="10" fontWeight="800" fill={C.aquaD}>checked</text>}</g>)}
      <text x={14} y={14} fontSize="10" fontWeight="800" fill="#E11D48">● attacker</text><text x={86} y={14} fontSize="10" fontWeight="800" fill={C.aquaD}>● ATHENA</text><text x={w - 14} y={14} textAnchor="end" fontSize="10" className="dim">+{Math.round(end - start)} min</text>
    </svg>
  );
}

/** How well ATHENA did in the attack that just ran. */
export function AttackScore({ snap, st, hist }: { snap: any; st: any; hist: any[] }) {
  const f = attackFacts(snap, st, hist);
  if (!f) return <div className="tip"><Ic n="clock" /> Launch an attack above. This card then fills in from what really happens: how fast it was noticed, what was cut and how much service was kept.</div>;
  const { camp, c } = f; const noticed = f.det !== undefined ? f.det - f.start : null; const stopped = f.cutAt !== undefined ? f.cutAt - (f.det ?? f.cutAt) : null;
  const money = f.saved * INR_PER_HOME_HOUR;
  return (
    <div className="col" style={{ gap: 10 }}>
      <RunTimeline steps={f.steps} start={f.start} now={snap.t} />
      <div className="grid3">
        <Stat v={noticed !== null ? mm(noticed) : "not yet"} l="until it was noticed" color={noticed !== null && noticed <= 40 ? C.aquaD : C.apricot} />
        <Stat v={stopped !== null ? mm(stopped) : f.det !== undefined ? "working…" : "–"} l="from alarm to cut-off" color={C.aquaD} />
        <Stat v={`${f.taken} of ${f.total}`} l="devices it took" color={f.taken > 3 ? C.terra : C.apricot} />
      </div>
      <div className="grid3">
        <Stat v={`${f.cutN}`} l={`devices ATHENA cut (cutting everything = ${f.total})`} color={C.aquaD} />
        <Stat v={`${(snap.services.served_frac * 100).toFixed(1)}%`} l={`homes served now (lowest ${(f.low * 100).toFixed(1)}%)`} color={snap.services.served_frac > 0.99 ? C.aquaD : C.apricot} />
        <Stat v={`${f.hOk}/${f.hAll}`} l="hospitals with water" color={f.hOk === f.hAll ? C.aquaD : C.terra} />
      </div>
      <LineChart h={112} yMin={Math.max(0, Math.min(0.9, ...f.since.map((x) => Math.min(x.live, x.none, x.iso))) - 0.03)} series={[{ name: "ATHENA", color: C.aquaD, data: f.since.map((x) => x.live), width: 3.4 }, { name: "No response", color: C.terra, data: f.since.map((x) => x.none), dash: "5 4" }, { name: "Cut everything", color: C.apricot, data: f.since.map((x) => x.iso), dash: "2 4" }]} />
      <div className="row wrap tip" style={{ gap: 12 }}><span><b style={{ color: C.aquaD }}>━</b> ATHENA {(snap.services.served_frac * 100).toFixed(1)}%</span><span><b style={{ color: C.terra }}>┅</b> no response {(c.none_served * 100).toFixed(1)}%</span><span><b style={{ color: C.apricot }}>┈</b> cut everything {(c.iso_served * 100).toFixed(1)}%</span></div>
      <div className="vs">
        <div><small>No response</small><b>{k(c.none_hh)}</b><span>home-hours lost</span></div>
        <div className="win"><small>ATHENA</small><b>{k(c.live_hh)}</b><span>{f.harmCut !== null ? `${Math.round(f.harmCut * 100)}% less lost` : "home-hours lost"}</span></div>
        <div><small>Cut everything</small><b>{k(c.iso_hh)}</b><span>home-hours lost</span></div>
      </div>
      <div className="tip">{f.saved > 0 ? <>ATHENA has kept about <b>{k(f.saved)}</b> home-hours of water and power, worth roughly <b>₹{k(money)}</b> at ₹{INR_PER_HOME_HOUR} per home-hour (assumed rate). </> : "No service has been lost so far, so there is nothing to save yet. "}Hospitals with water: <b>{f.hOk}</b> with ATHENA, {f.hNone} with no response, {f.hIso} if everything were cut.</div>
    </div>
  );
}

/** Severity (CVSS) against real harm: the ten devices that hurt most, with where the old score ranked them. */
export function SeverityRisk({ rows, onPick }: { rows: any[]; onPick?: (id: string) => void }) {
  const top = [...rows].sort((a, b) => a.rank_sar - b.rank_sar).slice(0, 8); if (!top.length) return null;
  const mx = Math.max(...top.map((r) => r.raw), 1); const n = rows.length; const hidden = rows.filter((r) => r.rank_sar <= 10 && r.rank_cvss > 10).length;
  return (
    <div className="col" style={{ gap: 6 }}>
      <div className="tiles"><div className="tile"><b>{hidden}</b><span>of the 10 most harmful devices are NOT in the top 10 by severity score</span></div><div className="tile"><b>{n}</b><span>devices ranked by people harmed, not by CVSS</span></div></div>
      <div className="sr-head"><span>Device</span><span>Old rank</span><span /><span>Harm rank</span><span>Harm if hacked</span></div>
      {top.map((r) => { const up = r.rank_cvss - r.rank_sar; return (
        <div key={r.id} className="sr-row" onClick={() => onPick?.(r.id)}>
          <b>{r.name.replace(/ \(.*\)/, "").replace("Pump-station", "Pump").slice(0, 22)}</b>
          <span className="sr-chip old">#{r.rank_cvss}</span>
          <span className={"sr-arrow" + (up > 3 ? " up" : up < -3 ? " down" : "")}>{up > 3 ? `▲ ${up}` : up < -3 ? `▼ ${-up}` : "="}</span>
          <span className="sr-chip new">#{r.rank_sar}</span>
          <span className="sr-bar"><i style={{ width: `${(r.raw / mx) * 100}%` }} /><em>{k(r.raw)}</em></span>
        </div>); })}
      <div className="tip">Left rank: how the old severity score (CVSS) would order it. Right rank: how it ranks once we count the homes and hospitals that would lose service. A big green or red arrow means severity alone would have misled you.</div>
    </div>
  );
}
