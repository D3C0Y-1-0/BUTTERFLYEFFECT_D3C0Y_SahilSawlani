import React, { useEffect, useState } from "react";
import { api } from "../api";
import { setState, useStore } from "../store";
import { C } from "../palette";
import { Box, Ic, Move, PageHead, Stat } from "./ui";
import { k } from "./Charts";
import { can, nameOf } from "./status";
import { showBlast } from "../focus";

const WHY: Record<string, string> = { vulnerability: "a known weakness", exposure: "it faces the internet", "access control": "weak logins", segmentation: "poor separation", "network position": "where it sits in the network" };

const CACHE: { data: any; at: number } = { data: null, at: 0 };   // survives closing and reopening the page

/** Prediction: which devices the attacker is most likely to take next, why, what is at stake, and what to do about it. */
export function PredictView() {
  const st = useStore((s) => s.st), snap = useStore((s) => s.snap), role = useStore((s) => s.role);
  const [f, setF] = useState<any>(CACHE.data); const [err, setErr] = useState("");
  useEffect(() => {
    let live = true; let t: any;
    if (CACHE.data && Date.now() - CACHE.at < 90000) return () => { live = false; };   // opened again within 90 s: show what we already have, ask for nothing
    const go = () => api("/api/v2/model").then((m) => {   // ask for the model's status first: asking for the forecast while it trains returns 409 and fills the browser console with red lines
      if (!live) return; if (m.state?.status !== "ready") { setErr(m.state?.status === "error" ? "The forecast model failed to train: " + (m.state?.error || "unknown error") : "The forecast model is still training (about 30 seconds)…"); t = setTimeout(go, 3000); return; }
      return api("/api/v2/forecast?top=6").then((x) => { CACHE.data = x; CACHE.at = Date.now(); if (live) { setF(x); setErr(""); } });
    }).catch((e) => { if (live) { setErr(e.message); t = setTimeout(go, 4000); } });
    go(); return () => { live = false; clearTimeout(t); };
  }, []);
  const inc = [...(snap.incidents || [])].reverse().find((i: any) => i.status === "open" || i.status === "contained"); const nx = inc?.next_hops || [];
  const acc = f?.accuracy;
  return (
    <>
      <PageHead icon="eye" title="Predict" sub="Where the next attack is likely to land" />
      {nx.length > 0 && <Box id="pr_live" title="Live warning: next step" icon="bolt" value={`${(nx[0].p * 100).toFixed(0)}%`} tone="crit" defaultOpen>
        {nx.slice(0, 3).map((n: any) => <div key={n.edge} className="row"><span style={{ width: 130, fontSize: 12.5 }}>{nameOf(st, n.dst)}</span><div className="bar grow"><div style={{ width: `${n.p * 100}%`, background: C.apricot }} /></div><b style={{ width: 36, textAlign: "right", fontSize: 12 }}>{(n.p * 100).toFixed(0)}%</b></div>)}
        <div className="tip">While an attack is running, ATHENA predicts the next device from the attacker's position and the network map.</div>
      </Box>}
      <Box id="pr_acc" title="How accurate is this?" icon="target" value={acc ? `Spearman ${acc.spearman}` : "…"} tone="safe" defaultOpen>
        {acc ? <>
          <div className="grid3"><Stat v={acc.spearman} l="rank match" color={C.aquaD} /><Stat v={acc.top5_overlap != null ? Math.round(acc.top5_overlap * 100) + "%" : "–"} l="top-5 right" color={C.aquaD} /><Stat v={acc.mae} l="average error" /></div>
          <div className="tip"><b>How we got these numbers.</b> We simulated {acc.test_rows.toLocaleString()} fresh cases the model had never seen, each a different mix of patches, logins and closed links, and compared its guesses with what really happened in thousands of simulated attacks. Its ordering of devices matches the real one {Math.round(acc.spearman * 100)}% of the way to perfect, it picks about {acc.top5_overlap != null ? (acc.top5_overlap * 5).toFixed(1) : "most"} of the 5 riskiest devices correctly, and its scores are off by only {(acc.mae * 100).toFixed(1)} percentage points on average.</div>
          <details><summary className="tip" style={{ cursor: "pointer" }}>What this is measured against</summary><div className="tip">The answers come from our attack simulator, not from real incidents, so treat these as proof that the model learned the simulator's logic well. Its rule: more exposure never lowers a device's score.</div></details>
        </> : <div className="tip"><Ic n="clock" cls="spin" /> {err || "Loading…"}</div>}
      </Box>
      <Box id="pr_list" title="Most likely targets" icon="target" value={f ? `${f.items.length} devices` : "…"} defaultOpen>
        {f?.items?.map((x: any, i: number) => (
          <div key={x.id} className="pcard">
            <div className="row" style={{ alignItems: "flex-start" }}><span className="num-chip">{i + 1}</span><div className="grow"><b style={{ fontSize: 13 }}>{nameOf(st, x.id)}</b>
              <div className="dim" style={{ fontSize: 11.5 }}>Mostly because of {WHY[x.main_reason] || x.main_reason}. If taken it reaches {x.reaches} more device{x.reaches === 1 ? "" : "s"}.</div></div><b style={{ color: x.likelihood > 0.5 ? C.terra : C.apricot }}>{(x.likelihood * 100).toFixed(0)}%</b></div>
            <div className="bar"><div style={{ width: `${Math.min(100, x.likelihood * 100)}%`, background: x.likelihood > 0.5 ? C.terra : C.apricot }} /></div>
            {x.services_lost?.length > 0 && <div className="tip">Could stop: {x.services_lost.slice(0, 3).join(", ")}</div>}
            {x.steps.map((s: any, j: number) => <div key={j} className="step"><Ic n="wrench" /><span className="grow"><Move label={s.label} detail={<>Effort {s.cost} · harm avoided {k(s.reduction)}</>} /></span></div>)}
            <div className="row wrap" style={{ gap: 6 }}><button className="btn small" onClick={() => { setState({ selected: x.id }); showBlast(st, x.id); }}>Show blast radius</button>{can(role, "analyst") && <button className="btn small primary" onClick={() => setState({ view: "lab", labStart: x.id })}>Try fixes</button>}</div>
          </div>))}
        {!f && <div className="tip"><Ic n="clock" cls="spin" /> {err || "Loading…"}</div>}
      </Box>
    </>
  );
}
