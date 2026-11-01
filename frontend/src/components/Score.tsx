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

/** How ATHENA tells a real attack from noise, with the live numbers of each gate. */
export function FalseAlarmGate({ snap, exp }: { snap: any; exp: any }) {
  const w = snap.watch; const p = w.shown ?? w.p; const raw = w.p; const cs = w.cusum ?? 0, line = w.cusum_line || 1;
  const e17 = exp?.E17?.result; const gate = (n: number, title: string, val: string, frac: number, line_: number | null, on: boolean, how: string) => (
    <div className="gate"><div className="row between"><b>{n} · {title}</b><span className={"pill " + (on ? "crit" : "safe")}>{on ? "tripped" : "quiet"}</span></div>
      <div className="gbar"><i style={{ width: `${Math.min(100, frac * 100)}%`, background: on ? "#E11D48" : C.aquaD }} />{line_ !== null && <u style={{ left: `${line_ * 100}%` }} />}</div>
      <div className="row between" style={{ fontSize: 11.5 }}><span className="dim">{how}</span><b>{val}</b></div></div>);
  return (
    <div className="col" style={{ gap: 8 }}>
      {gate(1, "One-window evidence", `${(raw * 100).toFixed(0)}%`, raw, 0.85, raw > 0.85, "odd traffic + broken physics, fused into one probability; the line is 85%")}
      {gate(2, "Must repeat", `${w.hits ?? 0} of 2`, (w.hits ?? 0) / 2, null, (w.hits ?? 0) >= 2, "two readings in a row above 85% before an incident opens, so one blip does nothing")}
      {gate(3, "Slow build-up (CUSUM)", `${cs.toFixed(1)} / ${line.toFixed(1)}`, cs / line, 1, cs > line, "small repeated signs add up; a quiet city never reaches the line")}
      {gate(4, "Careful response", w.flood ? "flood guard on" : "ask or safe step", 0.0, null, false, "risky steps need a person; every step is safety-checked and reversible")}
      <div className="steps3"><div><b>Learn</b><span>Only windows with no alert nearby teach the model what normal is, so an attacker cannot train it.</span></div><div><b>Undo</b><span>A false alarm resolves by itself after 30 quiet minutes; blocked links are released and re-checked.</span></div><div><b>Record</b><span>{e17 ? `${e17.false_alarm_runs} false alarms in ${e17.calm_runs} calm runs (${e17.calm_hours} hours).` : "Measured by experiment E17."}</span></div></div>
    </div>
  );
}

/** Many quiet attacks: each one stays under the single-alarm line, but their traces add up and the slow-build-up detector crosses its own line. */
export function SwarmChart({ hist, snap }: { hist: any[]; snap: any }) {
  const camps = snap.adversary || []; const start = camps.length ? Math.min(...camps.map((c: any) => c.started)) - 3 : 0; const h = hist.filter((x) => x.t >= start).slice(-150);
  if (h.length < 3) return <div className="tip"><Ic n="clock" /> Launch "Many small attacks" to watch the two lines below.</div>;
  const w = 360, ht = 130, L = 34, x = (i: number) => L + (i / Math.max(1, h.length - 1)) * (w - L - 6), y = (v: number) => ht - 20 - Math.min(1.15, v) * (ht - 34);
  const single = h.map((q) => q.raw ?? q.p), cus = h.map((q) => (q.cs ?? 0) / (q.line || 1)); const pk = Math.max(...single); const crossed = cus.findIndex((v) => v >= 1);
  return (
    <div className="col" style={{ gap: 6 }}>
      <svg viewBox={`0 0 ${w} ${ht}`} width="100%" role="img" aria-label="Single alarm versus slow build-up">
        {[0, 0.5, 1].map((g) => <g key={g}><line x1={L} x2={w - 6} y1={y(g)} y2={y(g)} stroke={C.line} /><text x={L - 4} y={y(g) + 4} fontSize="9.5" textAnchor="end" fill={C.dim}>{g * 100}%</text></g>)}
        <line x1={L} x2={w - 6} y1={y(0.85)} y2={y(0.85)} stroke="#E11D48" strokeDasharray="4 3" /><text x={w - 8} y={y(0.85) - 3} fontSize="9.5" textAnchor="end" fill="#E11D48">single-alarm line 85%</text>
        <polyline fill="none" stroke={C.apricot} strokeWidth="2.4" points={single.map((v, i) => `${x(i)},${y(v)}`).join(" ")} />
        <polyline fill="none" stroke="#7B61FF" strokeWidth="2.8" points={cus.map((v, i) => `${x(i)},${y(v * 0.85)}`).join(" ")} />
        {crossed >= 0 && <g><circle cx={x(crossed)} cy={y(0.85)} r="5" fill="#fff" stroke="#7B61FF" strokeWidth="2.5" /><text x={Math.min(x(crossed) + 7, w - 90)} y={y(0.85) + 14} fontSize="10" fontWeight="800" fill="#7B61FF">slow build-up alarm</text></g>}
      </svg>
      <div className="row wrap tip" style={{ gap: 12 }}><span><b style={{ color: C.apricot }}>━</b> strongest single reading ({Math.round(pk * 100)}% at most)</span><span><b style={{ color: "#7B61FF" }}>━</b> slow build-up (alarm when it touches the red line)</span></div>
      <div className="tip">{camps.length} quiet attackers are active. {crossed >= 0 ? "Each stayed under the single-alarm line, but the build-up crossed its own line, so the incident opened." : "Each one is below the single-alarm line. The purple line keeps adding their small signs."}</div>
    </div>
  );
}

/** Physical equipment: what the attack did to pumps, valves, breakers, tanks and hospitals, now, against doing nothing. */
export function PhysicalPanel({ snap, st }: { snap: any; st: any }) {
  const L = snap.levels || {}, hosp = snap.services.hospitals, cum = snap.services.cum || { hh_h: 0, hosp_h: 0, mwh: 0 }, nc = snap.compare.none_cum || { hh_h: 0, hosp_h: 0, mwh: 0 };
  const pumps = ["PS1", "PS2"].map((p) => ({ id: p, on: !!snap.pumps?.[p] && !snap.forced?.[p], forced: !!snap.forced?.[p] })); const feeders = Object.entries<boolean>(snap.services.feeders || {});
  const valves = ["V1", "V2"].map((v) => ({ id: v, open: (snap.tele?.[v + "_pos"] ?? 1) > 0.5 }));
  const chip = (ok: boolean, label: string) => <span key={label} className={"pill " + (ok ? "safe" : "crit")}>{ok ? "● " : "✕ "}{label}</span>;
  const unit = (v: number, d = 1) => (v >= 1000 ? (v / 1000).toFixed(1) + "k" : v.toFixed(d));
  return (
    <div className="col" style={{ gap: 9 }}>
      <div className="row wrap" style={{ gap: 5 }}>{pumps.map((p) => chip(p.on, `Pump ${p.id.slice(2)} ${p.on ? "running" : "stopped"}`))}{valves.map((v) => chip(v.open, `Valve ${v.id} ${v.open ? "open" : "closed"}`))}{feeders.map(([f, ok]) => chip(ok, `Feeder ${f} ${ok ? "on" : "off"}`))}</div>
      <div className="grid2">{["T1", "T2"].map((t) => { const lv = L[t] ?? 0; return <div key={t} className="gate"><div className="row between"><b>Tank {t.slice(1)}</b><span>{lv.toFixed(1)} m</span></div><div className="gbar"><i style={{ width: `${Math.min(100, (lv / 8) * 100)}%`, background: lv < 2.5 ? "#E11D48" : lv < 4 ? C.apricot : C.aquaD }} /><u style={{ left: "31%" }} /></div><div className="dim" style={{ fontSize: 11 }}>line = low-water mark</div></div>; })}</div>
      <div className="grid3">{Object.entries<any>(hosp).map(([h, v]) => <div key={h} className="gate"><div className="row between"><b>{st.physical[h]?.name?.replace(/ \(.*\)/, "").slice(0, 14) || h}</b><span className={"pill " + (v.ok ? "safe" : "crit")}>{v.ok ? "OK" : "AT RISK"}</span></div><div className="gbar"><i style={{ width: `${Math.min(100, (v.pressure / 30) * 100)}%`, background: v.pressure >= 15 ? C.aquaD : "#E11D48" }} /><u style={{ left: "50%" }} /></div><div className="dim" style={{ fontSize: 11 }}>{v.pressure.toFixed(1)} m (min 15)</div></div>)}</div>
      <div className="vs"><div><small>Homes without service</small><b>{unit(snap.services.households_total - snap.services.households_served, 0)}</b><span>right now</span></div>
        <div className="win"><small>Lost with ATHENA</small><b>{unit(cum.hh_h)}</b><span>home-h · {cum.mwh.toFixed(1)} MWh · {cum.hosp_h.toFixed(2)} hospital-h</span></div>
        <div><small>Lost with no response</small><b>{unit(nc.hh_h)}</b><span>home-h · {nc.mwh.toFixed(1)} MWh · {nc.hosp_h.toFixed(2)} hospital-h</span></div></div>
    </div>
  );
}
