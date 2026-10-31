import React, { useEffect, useState } from "react";
import { api } from "../api";
import { toast, useStore } from "../store";
import { C } from "../palette";
import { Bars, Heartbeat, k } from "./Charts";
import { AttackScore } from "./Score";
import { Box, Ic, PageHead, Stat, Steps } from "./ui";
import { can, plainMove, statusOf } from "./status";
import { showNodes } from "../focus";

const ZSTAGES = ["Introduced", "Suspected", "Rule made", "Contained"];
const cut = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1).trimEnd() + "…" : s);

export function ZeroDayView() {
  const snap = useStore((s) => s.snap), role = useStore((s) => s.role), st = useStore((s) => s.st), hist = useStore((s) => s.hist), exp = useStore((s) => s.exp);
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
        <div style={{ fontSize: 13, margin: "3px 0 10px", maxWidth: "82%" }}>{!lab ? "No CVE, no signature. ATHENA must work it out." : cut(lab.exploit_text, 70)}</div>
        {lab && <Steps labels={labels} done={done} attack={lab.status !== "contained"} />}
        {lab?.family && <div className="row" style={{ marginTop: 10, fontSize: 12.5, fontWeight: 700 }}><Ic n="shield" /> Family {lab.family}: every {lab.product ? cut(lab.product, 26) : "device"} is now protected</div>}
      </div>
      {can(role, "analyst") && (
        <Box id="zlaunch" title="Launch a zero-day" icon="bolt" value="simulation" defaultOpen>
          <button className="btn primary big" disabled={busy} onClick={launch}>Launch zero-day</button>
          <details><summary className="tip" style={{ cursor: "pointer" }}>Choose the product</summary>
            <select style={{ marginTop: 6 }} value={product} onChange={(e) => setProduct(e.target.value)} aria-label="Product"><option value="">Random product</option>{(info?.products || []).map((p: string) => <option key={p} value={p}>{cut(p, 40)}{info?.held_out_products?.includes(p) ? " · never seen by the AI" : ""}</option>)}</select></details>
        </Box>)}
      <Box id="how" title="How ATHENA handles it" icon="route" value="5 steps" defaultOpen={!lab}>
        {["Notice odd behaviour or broken physics", "No known weakness explains it → flag a zero-day", "Describe how it behaves (a fingerprint)", "Analyse a captured sample, make a rule", "Apply the rule to every device of that product"].map((t, i) => <div key={t} className="row" style={{ fontSize: 12.5 }}><span className="num-chip aqua" style={{ width: 22, height: 22, fontSize: 11 }}>{i + 1}</span>{t}</div>)}
      </Box>
      {lab && (() => {
        const inc = (snap.incidents || []).find((i: any) => i.id === lab.incident) || [...(snap.incidents || [])].reverse().find((i: any) => i.t0 >= (lab.minute ?? 0) - 2) || null; const acts: any[] = inc?.actions || []; const lib = z.library.find((l: any) => l.family === lab.family);
        const rank = ({ introduced: 0, suspected: 1, "rule deployed": 3, contained: 3 } as any)[lab.status] ?? 0; const e16 = exp?.E16?.result; const suspectIn = lab.detected_minute != null ? lab.detected_minute - lab.minute : null;
        const steps = [
          { done: !!inc || rank >= 1, t: "Alarm from broken physics or odd traffic", d: inc ? `at minute +${Math.max(0, inc.t0 - lab.minute)}` : rank >= 1 ? "noticed" : "waiting for a sign" },
          { done: z.suspected || rank >= 2 || !!lab.family, t: "Flagged as a zero-day: no known weakness explains it", d: suspectIn !== null ? `+${suspectIn} min after it began` : "" },
          { done: acts.length > 0 || rank >= 3, t: "Infected devices cut off", d: acts.length ? `${acts.length} action${acts.length === 1 ? "" : "s"} taken` : "" },
          { done: !!lab.family || rank >= 4, t: "Rule written for the whole product family", d: lab.family || (rank >= 3 ? "not needed: the normal response was enough" : "") },
          { done: lab.status === "contained", t: "Verified: attacker gone, service back", d: "" },
        ];
        return (<>
          <Box id="remedy" title="How we are stopping it" icon="wrench" value={`${steps.filter((x) => x.done).length} of ${steps.length} done`} tone="safe" defaultOpen>
            {steps.map((x, i) => <div key={i} className="row" style={{ fontSize: 12.5, alignItems: "flex-start", opacity: x.done ? 1 : 0.5 }}><span className={"num-chip" + (x.done ? " aqua" : "")} style={{ width: 22, height: 22, fontSize: 11 }}>{x.done ? "✓" : i + 1}</span><span className="grow"><b>{x.t}</b>{x.d && <div className="dim" style={{ fontSize: 11.5 }}>{x.d}</div>}</span></div>)}
            {acts.map((a: any, i: number) => <div key={i} className="row" style={{ fontSize: 12, cursor: "pointer" }} onClick={() => showNodes(a.target?.nodes || (a.target?.node ? [a.target.node] : []), "defence")}><Ic n="shield" /><span className="grow">{cut(plainMove(a.label).title, 70)}</span><span className="dim" style={{ fontSize: 11 }}>by {a.actor}</span></div>)}
          </Box>
          <Box id="eff" title="How well it worked" icon="chart" value={inc ? "measured" : "waiting"} tone="safe" defaultOpen>
            <AttackScore snap={snap} st={st} hist={hist} />
          </Box>
          <Box id="learn" title="What the model learned" icon="eye" value={lab.family ? "new rule" : z.suspected ? "fingerprint" : "nothing yet"} tone={lab.family ? "safe" : "watch"} defaultOpen>
            {fp ? <div className="row wrap"><span className="pill watch">no CVE explains it</span><span className="pill info">{fp.stealth}</span><span className="pill info">{fp.hops} device(s)</span>{fp.protocols.map((p: string) => <span key={p} className="pill info">{p}</span>)}{fp.techniques.slice(0, 4).map((t: string) => <span key={t} className="pill info">{t}</span>)}</div> : <div className="tip">It has not seen enough yet to describe the behaviour.</div>}
            {lab.family && <div className="grid3"><Stat v={lab.family} l="new family rule" color={C.aquaD} /><Stat v={lib?.nodes?.length ?? "–"} l="devices now protected" color={C.aquaD} /><Stat v={z.library.length} l="families in the library" color={C.aquaD} /></div>}
            {e16 && <><div className="tip">Next time the same product is attacked (from the saved experiment):</div><Bars rows={[{ label: "First time (nothing learned)", value: e16.first_encounter, color: C.terra }, { label: "Second time (rule in the library)", value: e16.repeat_encounter, color: C.aquaD }]} /></>}
          </Box></>);
      })()}
      <Box id="lib" title="Zero-day library" icon="doc" value={`${z.library.length} families`} tone={z.library.length ? "safe" : "info"} defaultOpen={z.library.length > 0}>
        {z.library.length === 0 ? <div className="tip">Empty. Each analysed zero-day adds a rule here, so the next one is stopped faster.</div> :
          z.library.map((l: any) => <div key={l.family} className="list-row" onClick={() => showNodes(l.nodes || [], "defence")}><span className="num-chip aqua"><Ic n="shield" /></span><div className="grow"><b style={{ fontSize: 13 }}>{l.family}</b><div className="dim" style={{ fontSize: 11.5 }}>{cut(l.product, 30)} · {l.nodes?.length} devices</div></div><span className={"pill " + (l.learned_minute !== null ? "safe" : "watch")}>{l.learned_minute !== null ? "active" : "analysing"}</span></div>)}
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
