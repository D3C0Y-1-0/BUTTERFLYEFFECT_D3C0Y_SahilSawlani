import React from "react";
import { C, riskColor } from "../palette";

export { riskColor };
export const fmt = (n: number | null | undefined, d = 0) => (n === null || n === undefined || isNaN(n as number) ? "–" : Number(n).toLocaleString("en-IN", { maximumFractionDigits: d, minimumFractionDigits: d }));
export const k = (n: number) => (n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? (n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + "k" : Math.round(n).toString());

export function Ring({ value, max = 1, size = 56, stroke = 6, color = C.aquaD, children, track = "#F4DEC6" }: any) {
  const r = (size - stroke) / 2, c = 2 * Math.PI * r, f = Math.max(0, Math.min(1, value / max));
  return (
    <div style={{ position: "relative", width: size, height: size, flex: "none" }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={size / 2} cy={size / 2} r={r} stroke={track} strokeWidth={stroke} fill="none" />
        <circle cx={size / 2} cy={size / 2} r={r} stroke={color} strokeWidth={stroke} fill="none" strokeDasharray={c} strokeDashoffset={c * (1 - f)} strokeLinecap="round" style={{ transition: "stroke-dashoffset .6s, stroke .4s" }} />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", fontSize: size > 50 ? 13 : 11, fontWeight: 800 }}>{children}</div>
    </div>
  );
}

/** Heartbeat line: flat = calm, spike = something is wrong. Scales to its container. */
export function Heartbeat({ data, h = 40, color = C.aquaD, thr, max = 1 }: { data: number[]; h?: number; color?: string; thr?: number; max?: number }) {
  const w = 200, n = data.length; if (!n) return <svg width="100%" height={h} />;
  const y = (v: number) => h - 3 - (Math.min(v, max) / max) * (h - 8);
  const pts = data.map((v, i) => `${(i / Math.max(1, n - 1)) * w},${y(v)}`).join(" ");
  const gid = "hb" + color.replace("#", "");
  return (
    <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ display: "block", overflow: "visible" }}>
      <defs><linearGradient id={gid} x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor={color} stopOpacity=".35" /><stop offset="1" stopColor={color} stopOpacity="0" /></linearGradient></defs>
      <polygon points={`0,${h} ${pts} ${w},${h}`} fill={`url(#${gid})`} />
      {thr !== undefined && <line x1="0" x2={w} y1={y(thr)} y2={y(thr)} stroke={C.terra} strokeDasharray="4 4" strokeOpacity=".6" vectorEffect="non-scaling-stroke" />}
      <polyline points={pts} fill="none" stroke={color} strokeWidth="2.4" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/** Rank-reversal slope chart: CVSS x importance (left) vs service loss (right). */
export function Slope({ rows, onPick }: { rows: any[]; onPick?: (id: string) => void }) {
  const w = 360, shown = rows.filter((r) => Math.min(r.rank_cvss, r.rank_sar) <= 10);
  const rowH = 21, MAXR = 12, H = MAXR * rowH + 46, xl = 130, xr = w - 130;
  const y = (r: number) => 34 + (Math.min(r, MAXR) - 1) * rowH;
  const short = (n: string) => n.replace(/ \(.*\)/, "").replace("Pump-station", "Pump stn").replace("controller", "ctrl").slice(0, 18);
  return (
    <svg width="100%" viewBox={`0 0 ${w} ${H}`} style={{ overflow: "visible" }}>
      <text x={xl} y={14} textAnchor="end" fill={C.dim} fontSize="11" fontWeight="700">Old way (CVSS)</text>
      <text x={xr} y={14} textAnchor="start" fill={C.terraD} fontSize="11" fontWeight="700">Real harm</text>
      {shown.map((r) => {
        const moved = Math.abs(r.move) > 10; const col = moved ? (r.move > 0 ? C.terra : C.aquaD) : C.sand;
        return (
          <g key={r.id} style={{ cursor: "pointer" }} onClick={() => onPick?.(r.id)}>
            <line x1={xl + 6} x2={xr - 6} y1={y(r.rank_cvss)} y2={y(r.rank_sar)} stroke={col} strokeWidth={moved ? 2.6 : 1} strokeOpacity={moved ? 0.95 : 0.4} />
            <circle cx={xl} cy={y(r.rank_cvss)} r={moved ? 4.5 : 3} fill={col} /><circle cx={xr} cy={y(r.rank_sar)} r={moved ? 4.5 : 3} fill={col} />
            {r.rank_cvss <= MAXR && <text x={xl - 8} y={y(r.rank_cvss) + 4} textAnchor="end" fill={moved ? C.ink : C.dim} fontSize="10.5" fontWeight={moved ? 700 : 500}>{short(r.name)}</text>}
            {r.rank_sar <= MAXR && <text x={xr + 8} y={y(r.rank_sar) + 4} fill={moved ? C.ink : C.dim} fontSize="10.5" fontWeight={moved ? 700 : 500}>{short(r.name)}</text>}
          </g>
        );
      })}
    </svg>
  );
}

/** Loss distribution; drag to read other percentiles. */
export function Hist({ base, now, after }: any) {
  const [pct, setPct] = React.useState(95); const ref = React.useRef<SVGSVGElement>(null);
  if (!base) return null;
  const w = 360, h = 140; const E = base.edges, nb = base.counts.length; const mx = Math.max(1, ...base.counts, ...(now?.counts || []), ...(after?.counts || [])) * 1.1;
  const x = (v: number) => 24 + (v / E[E.length - 1]) * (w - 32), bw = (w - 32) / nb - 1;
  const quant = (hh: any) => { const tot = hh.counts.reduce((a: number, b: number) => a + b, 0), zero = hh.zero_frac; const nn = tot / Math.max(1e-9, 1 - zero); const target = (pct / 100) * nn - zero * nn; if (target <= 0) return 0; let c = 0; for (let i = 0; i < nb; i++) { c += hh.counts[i]; if (c >= target) return (E[i] + E[i + 1]) / 2; } return E[E.length - 1]; };
  const drag = (e: React.PointerEvent) => { const r = ref.current!.getBoundingClientRect(); const px = ((e.clientX - r.left) / r.width) * w; setPct(Math.round(Math.max(50, Math.min(99.5, 50 + ((px - 24) / (w - 32)) * 50)) * 10) / 10); };
  const qb = quant(base);
  return (
    <div>
      <svg ref={ref} width="100%" viewBox={`0 0 ${w} ${h}`} onPointerMove={(e) => e.buttons === 1 && drag(e)} onPointerDown={drag} style={{ touchAction: "none", cursor: "ew-resize" }}>
        {base.counts.map((c: number, i: number) => <rect key={"b" + i} x={x(E[i])} width={bw} y={h - 24 - (c / mx) * (h - 44)} height={(c / mx) * (h - 44)} fill={C.terra} fillOpacity=".45" />)}
        {now && now.counts.map((c: number, i: number) => <rect key={"n" + i} x={x(E[i]) + bw * 0.2} width={bw * 0.6} y={h - 24 - (c / mx) * (h - 44)} height={(c / mx) * (h - 44)} fill={C.apricot} />)}
        {after && after.counts.map((c: number, i: number) => <rect key={"a" + i} x={x(E[i]) + bw * 0.35} width={bw * 0.3} y={h - 24 - (c / mx) * (h - 44)} height={(c / mx) * (h - 44)} fill={C.aquaD} />)}
        <line x1={24} x2={w - 8} y1={h - 24} y2={h - 24} stroke={C.line} />
        {[0, 100000, 200000].map((v) => <text key={v} x={x(v)} y={h - 8} fill={C.dim} fontSize="10" textAnchor="middle">{k(v)}</text>)}
        <line x1={x(qb)} x2={x(qb)} y1={6} y2={h - 24} stroke={C.ink} strokeWidth="2" strokeDasharray="4 3" />
        <text x={Math.min(x(qb) + 5, w - 70)} y={16} fill={C.ink} fontSize="11" fontWeight="700">{pct}% line</text>
      </svg>
      <div className="row wrap tip" style={{ gap: 12 }}><span><b style={{ color: C.terra }}>■</b> before</span><span><b style={{ color: C.apricot }}>■</b> now</span><span><b style={{ color: C.aquaD }}>■</b> after plan</span><span className="dim">drag to move the line</span></div>
    </div>
  );
}

export function Bars({ rows }: { rows: { label: string; value: number; color: string; note?: string }[] }) {
  const mx = Math.max(1, ...rows.map((r) => r.value));
  return (
    <div className="col" style={{ gap: 9 }}>
      {rows.map((r) => (
        <div key={r.label}>
          <div className="row between" style={{ fontSize: 12.5 }}><span>{r.label}</span><b>{k(r.value)}{r.note ? <span className="dim" style={{ fontWeight: 500 }}> {r.note}</span> : null}</b></div>
          <div className="bar"><div style={{ width: `${(r.value / mx) * 100}%`, background: r.color }} /></div>
        </div>
      ))}
    </div>
  );
}

/** Before / now / after: the same bar scale so the drop is obvious. */
export function RiskTrio({ rows, unit }: { rows: { label: string; sub: string; value: number; color: string }[]; unit: string }) {
  const mx = Math.max(1, ...rows.map((r) => r.value)), first = rows[0].value || 1;
  return (
    <div className="col" style={{ gap: 12 }}>
      {rows.map((r, i) => {
        const drop = i === 0 ? 0 : Math.round((1 - r.value / first) * 100);
        return (
          <div key={r.label}>
            <div className="row between"><div><b style={{ fontSize: 13.5 }}>{r.label}</b> <span className="dim" style={{ fontSize: 11.5 }}>{r.sub}</span></div>
              <div className="row" style={{ gap: 6 }}>{i > 0 && <span className={"pill " + (drop > 0 ? "safe" : "watch")}>{drop > 0 ? "▼" : drop < 0 ? "▲" : "="} {Math.abs(drop)}%</span>}<b style={{ fontSize: 17 }}>{k(r.value)}</b></div></div>
            <div className="bar" style={{ height: 14, marginTop: 4 }}><div style={{ width: `${Math.max(2, (r.value / mx) * 100)}%`, background: r.color }} /></div>
          </div>
        );
      })}
      <div className="dim" style={{ fontSize: 11.5 }}>{unit}</div>
    </div>
  );
}

export function LineChart({ series, h = 120, yMin = 0, yMax = 1, fmtY = (v: number) => (v * 100).toFixed(0) + "%" }: { series: { name: string; color: string; data: number[]; dash?: string; width?: number }[]; h?: number; yMin?: number; yMax?: number; fmtY?: (v: number) => string }) {
  const w = 360, n = Math.max(...series.map((s) => s.data.length), 2);
  const y = (v: number) => h - 18 - ((v - yMin) / (yMax - yMin)) * (h - 28);
  return (
    <svg width="100%" viewBox={`0 0 ${w} ${h}`}>
      {[0, 0.5, 1].map((f) => <g key={f}><line x1={34} x2={w} y1={y(yMin + f * (yMax - yMin))} y2={y(yMin + f * (yMax - yMin))} stroke={C.line} /><text x={30} y={y(yMin + f * (yMax - yMin)) + 4} fill={C.dim} fontSize="10" textAnchor="end">{fmtY(yMin + f * (yMax - yMin))}</text></g>)}
      {series.map((s) => <polyline key={s.name} fill="none" stroke={s.color} strokeWidth={s.width || 2.6} strokeDasharray={s.dash} strokeLinecap="round" strokeLinejoin="round" points={s.data.map((v, i) => `${34 + (i / (n - 1)) * (w - 36)},${y(v)}`).join(" ")} />)}
    </svg>
  );
}

/** Hospital pressure + tank level from the physics oracle. */
export function Timeline({ data }: any) {
  if (!data) return null;
  const w = 360, h = 150; const s = data.series, b = data.baseline; const t = s.t; const T = Math.max(...t);
  const x = (v: number) => 30 + (v / T) * (w - 40), y = (v: number, lo: number, hi: number) => h - 26 - ((v - lo) / (hi - lo)) * (h - 40);
  const hosp = data.hospital_min_pressure; const path = (arr: number[], lo: number, hi: number) => arr.map((v, i) => `${x(t[i])},${y(v, lo, hi)}`).join(" ");
  const start = data.start, end = start + 8;
  const pi = (s.p_H1 as number[]).findIndex((v, i) => t[i] >= start && v < hosp); const tHosp = pi >= 0 ? t[pi] : null;
  return (
    <svg width="100%" viewBox={`0 0 ${w} ${h}`}>
      <rect x={x(start)} width={x(Math.min(end, T)) - x(start)} y={6} height={h - 32} fill={C.terra} fillOpacity=".1" />
      <line x1={30} x2={w - 8} y1={y(hosp, 0, 26)} y2={y(hosp, 0, 26)} stroke={C.ink} strokeDasharray="4 3" />
      <text x={w - 10} y={y(hosp, 0, 26) - 4} textAnchor="end" fill={C.ink} fontSize="10" fontWeight="700">hospital minimum</text>
      <polyline points={path(b.p_H1, 0, 26)} fill="none" stroke={C.aquaM} strokeWidth="2" />
      <polyline points={path(s.p_H1, 0, 26)} fill="none" stroke={C.terra} strokeWidth="3" strokeLinejoin="round" />
      {tHosp !== null && <><line x1={x(tHosp)} x2={x(tHosp)} y1={6} y2={h - 26} stroke={C.terraD} /><text x={Math.min(x(tHosp) + 4, w - 130)} y={16} fill={C.terraD} fontSize="11" fontWeight="800">hospital short of water at +{(tHosp - start).toFixed(1)} h</text></>}
      {[0, 12, 24, 36, 48].filter((v) => v <= T).map((v) => <text key={v} x={x(v)} y={h - 8} fill={C.dim} fontSize="10" textAnchor="middle">{v}h</text>)}
      <text x={32} y={h - 28} fill={C.dim} fontSize="10"><tspan fill={C.aquaD}>━</tspan> normal  <tspan fill={C.terra}>━</tspan> with attack</text>
    </svg>
  );
}

export function Gantt({ rows, weeks = 4 }: any) {
  const w = 360, rowH = 26; const h = rows.length * rowH + 26; const x = (wk: number) => 118 + ((wk - 1) / weeks) * (w - 124);
  return (
    <svg width="100%" viewBox={`0 0 ${w} ${h}`}>
      {Array.from({ length: weeks }, (_, i) => <g key={i}><rect x={x(i + 1)} y={18} width={(w - 124) / weeks - 2} height={h - 20} fill="#FFF0E0" rx="5" /><text x={x(i + 1) + 5} y={12} fill={C.dim} fontSize="10">Wk {i + 1}</text></g>)}
      {rows.map((r: any, i: number) => <g key={i}><text x={112} y={36 + i * rowH} fill={C.ink} fontSize="10.5" textAnchor="end">{r.fix.label.replace(/^(Block the known exploit in front of |Update the firmware on |Close the )/, "").slice(0, 20)}</text>
        <rect x={x(r.week) + 3} y={24 + i * rowH} width={(w - 124) / weeks - 8} height={16} rx="8" fill={r.downtime_loss > 0 ? C.apricot : r.fix.type === "firmware_patch" ? C.terra : C.aquaM} />
        <text x={x(r.week) + 9} y={36 + i * rowH} fontSize="10" fill={C.ink} fontWeight="700">{String(Math.round(r.hour)).padStart(2, "0")}:00</text></g>)}
    </svg>
  );
}
