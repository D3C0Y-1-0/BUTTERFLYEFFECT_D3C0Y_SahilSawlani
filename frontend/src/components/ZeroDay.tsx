import React, { useEffect, useState } from "react";
import { api } from "../api";
import { toast, useStore } from "../store";
import { C } from "../palette";
import { Heartbeat, k } from "./Charts";
import { Box, Ic, PageHead, Stat, Steps } from "./ui";
import { can, statusOf } from "./status";

const ZSTAGES = ["Introduced", "Suspected", "Rule made", "Contained"];
const cut = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1).trimEnd() + "…" : s);

export function ZeroDayView() {
  const snap = useStore((s) => s.snap), role = useStore((s) => s.role);
  const [info, setInfo] = useState<any>(null); const [product, setProduct] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => { if (can(role, "analyst")) api("/api/zeroday").then(setInfo).catch(() => {}); }, [role]);
  const z = snap.zero_day; const lab = z.lab[z.lab.length - 1]; const ev = info?.evaluation; const curve = info?.curve || []; const stt = statusOf(snap);
  const noRule = lab?.status === "contained" && !lab?.family;   // stopped by the normal response before a family rule was needed
  const labels = noRule ? ["Introduced", "Suspected", "Contained"] : ZSTAGES;
  const done = lab ? (lab.status === "contained" ? labels.length : lab.status === "rule deployed" ? 3 : lab.status === "suspected" ? 2 : 1) : 0;
  const fp = z.fingerprint; const pol = ev?.policies || {};
  const launch = () => { setBusy(true); api("/api/zeroday", { body: { product: product || null, mode: "standard" } }).then(() => toast("warn", "Zero-day launched: no signature exists")).finally(() => setBusy(false)); };
  return (
    <>
      <PageHead icon="bolt" title="Zero-day" sub="An attack nobody has seen before" right={<span className={"pill " + stt.tone + (stt.key === "attack" ? " pulse" : "")}>{stt.label}</span>} />
      <div className={"hero " + (lab && lab.status !== "contained" ? "crit" : "safe")}>
        <div className="big">{!lab ? "No zero-day yet" : lab.status === "contained" ? "Contained" : lab.status === "rule deployed" ? "Rule deployed" : lab.status === "suspected" ? "Spotted" : "Under attack"}</div>
        <div style={{ fontSize: 13, margin: "3px 0 10px", maxWidth: "82%" }}>{!lab ? "No CVE, no signature. DECOY must work it out." : cut(lab.exploit_text, 70)}</div>
        {lab && <Steps labels={labels} done={done} attack={lab.status !== "contained"} />}
        {lab?.family && <div className="row" style={{ marginTop: 10, fontSize: 12.5, fontWeight: 700 }}><Ic n="shield" /> Family {lab.family}: every {lab.product ? cut(lab.product, 26) : "device"} is now protected</div>}
      </div>
      {can(role, "analyst") && (
        <Box id="zlaunch" title="Launch a zero-day" icon="bolt" value="simulation" defaultOpen>
          <button className="btn primary big" disabled={busy} onClick={launch}>Launch zero-day</button>
          <details><summary className="tip" style={{ cursor: "pointer" }}>Choose the product</summary>
            <select style={{ marginTop: 6 }} value={product} onChange={(e) => setProduct(e.target.value)} aria-label="Product"><option value="">Random product</option>{(info?.products || []).map((p: string) => <option key={p} value={p}>{cut(p, 40)}{info?.held_out_products?.includes(p) ? " · never seen by the AI" : ""}</option>)}</select></details>
          <div className="tip">DECOY is not told which product is hit.</div>
        </Box>)}
      <Box id="how" title="How DECOY handles it" icon="route" value="5 steps" defaultOpen={!lab}>
        {["Notice odd behaviour or broken physics", "No known weakness explains it → flag a zero-day", "Describe how it behaves (a fingerprint)", "Analyse a captured sample, make a rule", "Apply the rule to every device of that product"].map((t, i) => <div key={t} className="row" style={{ fontSize: 12.5 }}><span className="num-chip aqua" style={{ width: 22, height: 22, fontSize: 11 }}>{i + 1}</span>{t}</div>)}
      </Box>
      {z.suspected && fp && (
        <Box id="fp" title="What DECOY learned" icon="eye" value="fingerprint" tone="watch" kind="warm" defaultOpen>
          <div className="row wrap"><span className="pill watch">no CVE explains it</span><span className="pill info">{fp.stealth}</span><span className="pill info">{fp.hops} device(s)</span>{fp.protocols.map((p: string) => <span key={p} className="pill info">{p}</span>)}{fp.techniques.slice(0, 4).map((t: string) => <span key={t} className="pill info">{t}</span>)}</div>
          <div className="tip">No signature exists, so DECOY describes how it behaves.</div>
        </Box>)}
      <Box id="lib" title="Zero-day library" icon="doc" value={`${z.library.length} families`} tone={z.library.length ? "safe" : "info"} defaultOpen={z.library.length > 0}>
        {z.library.length === 0 ? <div className="tip">Empty. Each analysed zero-day adds a rule here, so the next one is stopped faster.</div> :
          z.library.map((l: any) => <div key={l.family} className="list-row" style={{ cursor: "default" }}><span className="num-chip aqua"><Ic n="shield" /></span><div className="grow"><b style={{ fontSize: 13 }}>{l.family}</b><div className="dim" style={{ fontSize: 11.5 }}>{cut(l.product, 30)} · {l.nodes?.length} devices</div></div><span className={"pill " + (l.learned_minute !== null ? "safe" : "watch")}>{l.learned_minute !== null ? "active" : "analysing"}</span></div>)}
      </Box>
      <Box id="who" title="Who responds?" icon="shield" value={z.responder === "ppo" ? "AI" : z.responder === "search" ? "Planner" : "Auto"}>
        <div className="seg">{[["auto", "Auto"], ["ppo", "AI"], ["search", "Planner"]].map(([m, l]) => <button key={m} className={z.responder === m ? "on" : ""} disabled={!can(role, "operator") || (m !== "search" && !z.ppo_loaded)} onClick={() => api("/api/responder", { body: { mode: m } })}>{l}</button>)}</div>
        <div className="tip"><b>Planner</b>: tries each action in the simulator. <b>AI</b>: a PPO policy trained on other products. <b>Auto</b>: AI for suspected zero-days, Planner otherwise. Every action passes the Safety Check first.</div>
        {(z.rl || []).slice().reverse().slice(0, 3).map((r: any, i: number) => (
          <div key={i} className="list-row" style={{ cursor: "default", flexDirection: "column", alignItems: "stretch" }}>
            <div className="row between"><b style={{ fontSize: 12.5 }}>{cut(r.action, 44)}</b><span className={"pill " + (r.applied ? "safe" : "info")}>{r.applied ? "done" : r.kind === "wait" ? "watching" : "advice"}</span></div>
            {r.top.slice(0, 2).map((t: any) => <div key={t.label} className="row"><span style={{ width: 150, fontSize: 11 }} className="dim">{cut(t.label, 26)}</span><div className="bar grow"><div style={{ width: `${t.p * 100}%`, background: C.apricot }} /></div><span style={{ width: 32, textAlign: "right", fontSize: 11 }}>{(t.p * 100).toFixed(0)}%</span></div>)}
          </div>))}
      </Box>
      {info && (
        <Box id="ppo" title="AI training proof" icon="chart" value={pol["PPO responder"] ? `cost ${k(pol["PPO responder"].mean_total)}` : "not run"}>
          {curve.length > 0 && <><Heartbeat data={curve.map((c: any) => c.mean_total_cost)} h={44} color={C.apricot} max={Math.max(...curve.map((c: any) => c.mean_total_cost))} /><div className="dim" style={{ fontSize: 11.5 }}>Cost while learning (lower is better) · {curve[curve.length - 1].steps?.toLocaleString()} steps · {info.train_products?.length} products</div></>}
          {ev ? <table><thead><tr><th>On products it never saw</th><th>Cost</th><th>Devices cut</th></tr></thead><tbody>{Object.entries<any>(pol).map(([n, v]) => <tr key={n}><td>{n}</td><td><b>{k(v.mean_total)}</b></td><td>{v.devices_cut.toFixed(1)}</td></tr>)}</tbody></table> : <div className="tip">Evaluation not run yet.</div>}
          <div className="tip">The AI clearly beats doing nothing or cutting everything, but not the Planner. So Planner stays the default.</div>
        </Box>)}
    </>
  );
}
