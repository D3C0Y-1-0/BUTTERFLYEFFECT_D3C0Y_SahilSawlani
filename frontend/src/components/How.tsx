import React, { useEffect, useRef, useState } from "react";
import { C } from "../palette";
import { Ic, PageHead } from "./ui";

/* "How our system works": an attack run and a defence run play side by side on the same city, so you can see the attack being stopped mid-run.
   Everything is deterministic (same story every time) and each step names the algorithm that does the work. */
const HOT = "#E11D48";
type Ev = { t: number; kind: "own" | "suspect" | "alarm" | "predict" | "cut" | "shield" | "heal" | "mod" | "bounce" | "learn" | "rule" | "scores" | "fix" | "trap"; a?: number; b?: number; mod?: number; who: "attack" | "defend"; text?: string; algo?: string; p?: number; v?: number[] };
type Story = { id: string; name: string; T: number; nodes: { x: number; y: number; label: string; icon: string }[]; evs: Ev[]; blurb: string };

const NODES = [
  { x: 70, y: 175, label: "Internet", icon: "🌐" }, { x: 190, y: 175, label: "Vendor VPN", icon: "🔑" }, { x: 310, y: 175, label: "Jump host", icon: "🖥" },
  { x: 430, y: 175, label: "SCADA server", icon: "🗄" }, { x: 550, y: 175, label: "Pump controller", icon: "⚙" }, { x: 670, y: 175, label: "Water pump", icon: "💧" },
  { x: 430, y: 246, label: "Same product, other site", icon: "🗄" },
];
const MODS = [["Watchdog", "Autoencoder + physics rules + logistic fusion"], ["Predictor", "Attack graph + Monte-Carlo + Dijkstra"], ["Planner + Safety Check", "CELF greedy + CP-SAT + twin simulation"], ["Healer", "Cut, shield, restore, verify"]];

const STORIES: Story[] = [
  { id: "known", name: "Known attack", T: 22, nodes: NODES, blurb: "A published bug is used to get in. ATHENA sees the odd traffic, predicts the next step, cuts one link and keeps the water running.", evs: [
    { t: 0.5, kind: "own", a: 0, who: "attack", text: "The attacker starts on the public internet." },
    { t: 2.5, kind: "own", a: 1, who: "attack", text: "Uses a known bug (CVE-2025-0282) on the vendor VPN and gets in." },
    { t: 3, kind: "mod", mod: 0, who: "defend", text: "Watchdog listens to normal traffic. Everything looks usual.", algo: "Autoencoder" },
    { t: 5, kind: "own", a: 2, who: "attack", text: "Moves sideways to the jump host." },
    { t: 5.6, kind: "suspect", a: 2, who: "defend" }, { t: 5.6, kind: "alarm", v: [0.91], who: "defend", text: "Odd traffic: a link that is never used is suddenly busy. Alarm probability 91%.", algo: "Autoencoder + logistic fusion" },
    { t: 7.2, kind: "mod", mod: 1, who: "defend" }, { t: 7.2, kind: "predict", a: 2, b: 3, p: 0.78, who: "defend", text: "Predicts the next step: SCADA server (78%), then the pump controller.", algo: "Attack graph + Dijkstra" },
    { t: 9, kind: "mod", mod: 2, who: "defend", text: "Plans the cheapest cut and tests it on a copy of the city first: water stays on.", algo: "CELF greedy + Safety Check" },
    { t: 10.5, kind: "cut", a: 2, b: 3, who: "defend", text: "Cuts the link from the jump host to the SCADA server." },
    { t: 11, kind: "bounce", a: 2, b: 3, who: "attack", text: "The attacker tries to move on and is blocked mid-run." },
    { t: 12, kind: "shield", a: 2, who: "defend", text: "Disconnects the infected jump host. Nothing else is cut.", algo: "Healer (isolate)" },
    { t: 14, kind: "mod", mod: 3, who: "defend", text: "Checks that service is normal and the attacker is gone.", algo: "Verify" },
    { t: 16, kind: "heal", who: "defend", text: "Recovered. Homes keep water and power; only one device was cut off." } ] },
  { id: "zero", name: "Zero-day attack", T: 30, nodes: NODES, blurb: "A bug nobody knows about. There is no signature to match, so ATHENA catches the effect (physics breaks), learns the pattern and protects every device of that product.", evs: [
    { t: 0.5, kind: "own", a: 0, who: "attack", text: "The attacker starts on the internet with an unknown exploit." },
    { t: 2, kind: "own", a: 1, who: "attack", text: "Gets in through the vendor VPN." },
    { t: 4, kind: "own", a: 2, who: "attack" }, { t: 6, kind: "own", a: 3, who: "attack", text: "Uses the zero-day on the SCADA server. No known signature exists." },
    { t: 7, kind: "mod", mod: 0, who: "defend", text: "No signature matches, so signature tools stay silent.", algo: "Signature check: nothing" },
    { t: 8.5, kind: "own", a: 4, who: "attack", text: "Stops the pump through the controller." },
    { t: 9.5, kind: "alarm", v: [0.9], who: "defend", text: "A physics law breaks: the pump says it is ON but no water flows. Alarm 90%, no signature needed.", algo: "Physics invariants" }, { t: 9.5, kind: "suspect", a: 3, who: "defend" }, { t: 9.5, kind: "suspect", a: 4, who: "defend" },
    { t: 12, kind: "mod", mod: 1, who: "defend", text: "Captures the exploit traffic and builds a fingerprint (product, protocol, bytes).", algo: "Capture + fingerprint" },
    { t: 14, kind: "learn", who: "defend", text: "Marks the product as suspect: it matches no known family.", algo: "Zero-day suspicion score" },
    { t: 16, kind: "mod", mod: 2, who: "defend", text: "Plans the response: isolate the infected devices, send a crew for the pump.", algo: "Search planner / PPO responder" },
    { t: 17, kind: "cut", a: 3, b: 4, who: "defend" }, { t: 17.5, kind: "shield", a: 3, who: "defend", text: "Disconnects the SCADA server and the pump controller.", algo: "Healer (isolate)" },
    { t: 19, kind: "rule", who: "defend", text: "Writes a family rule: every device of this product is now protected, even ones not attacked yet.", algo: "Family rule + library" },
    { t: 21, kind: "heal", who: "defend", text: "Crew restores the pump by hand. Service returns." },
    { t: 24, kind: "own", a: 6, who: "attack", text: "Second try: the same exploit against the same product at another site." },
    { t: 24.8, kind: "bounce", a: 6, b: 6, who: "attack", text: "Blocked at once. The library already knows this attack." }, { t: 24.8, kind: "trap", a: 6, who: "defend", text: "Second encounter: handled instantly, with no new alarm.", algo: "Zero-day library" } ] },
  { id: "predict", name: "Prediction", T: 20, nodes: NODES, blurb: "Before any attack, ATHENA scores every device, finds the most dangerous route and suggests fixes that lower the risk.", evs: [
    { t: 1, kind: "mod", mod: 1, who: "defend", text: "Simulates thousands of possible attacks on the city's network map.", algo: "Monte-Carlo attack worlds" },
    { t: 3, kind: "scores", v: [0, 0.62, 0.48, 0.55, 0.4, 0.3, 0], who: "defend", text: "Scores each device: how likely is it to fall, and what would it cost the city?", algo: "Gradient-boosted risk model" },
    { t: 6, kind: "predict", a: 1, b: 2, p: 0.8, who: "defend" }, { t: 6.4, kind: "predict", a: 2, b: 3, p: 0.7, who: "defend" }, { t: 6.8, kind: "predict", a: 3, b: 4, p: 0.66, who: "defend", text: "Finds the most dangerous route: vendor VPN to jump host to SCADA to pump controller.", algo: "Dijkstra on the attack graph" },
    { t: 9, kind: "mod", mod: 2, who: "defend", text: "Chooses fixes that cut the most risk for the least effort and outage.", algo: "CELF greedy + CP-SAT" },
    { t: 11, kind: "fix", a: 1, who: "defend", text: "Fix 1: a second login step on the vendor VPN." },
    { t: 13, kind: "scores", v: [0, 0.18, 0.22, 0.3, 0.22, 0.14, 0], who: "defend", text: "Risk drops. Fixes that need a restart are scheduled for the quietest hour." },
    { t: 16, kind: "heal", who: "defend", text: "The route is closed before anyone attacks." } ] },
];


/** The heartbeat of the story: unease grows as the attacker moves, jumps at the alarm, then fades after the cut. (In the prediction story it is the risk level.) */
function hbLevel(story: Story, tt: number): number {
  const ev = story.evs; const alarm = ev.find((e) => e.kind === "alarm"); const cutE = ev.find((e) => e.kind === "cut" || e.kind === "shield"); const heal = ev.find((e) => e.kind === "heal");
  if (story.id === "predict") { const sc = ev.filter((e) => e.kind === "scores" && e.t <= tt).pop(); return sc?.v ? Math.max(...sc.v) : 0.08; }
  let lvl = 0.06 + 0.035 * Math.max(0, ev.filter((e) => e.kind === "own" && e.t <= tt).length - 1);
  if (alarm && tt >= alarm.t) { const v = alarm.v?.[0] ?? 0.9; lvl = v; if (cutE && tt >= cutE.t) lvl = Math.max(0.06, v * Math.exp(-(tt - cutE.t) / 3.5)); }
  if (heal && tt >= heal.t) lvl = 0.05;
  const trap = ev.find((e) => e.kind === "trap"); if (trap && tt >= trap.t && tt < trap.t + 1.8) lvl = Math.max(lvl, 0.2);
  return lvl;
}
const ecgShape = (ph: number) => ph < 0.12 ? 0.12 * Math.sin((ph / 0.12) * Math.PI) : ph < 0.3 ? 0 : ph < 0.34 ? -0.18 * ((ph - 0.3) / 0.04) : ph < 0.4 ? -0.18 + 1.18 * ((ph - 0.34) / 0.06) : ph < 0.46 ? 1 - 1.3 * ((ph - 0.4) / 0.06) : ph < 0.52 ? -0.3 + 0.3 * ((ph - 0.46) / 0.06) : ph < 0.7 ? 0.22 * Math.sin(((ph - 0.52) / 0.18) * Math.PI) : 0;
function ecg(story: Story, t: number, w: number, h: number) {
  const pts: string[] = []; let ph = 0; const step = 0.06; let lvl = 0.06;
  for (let tt = 0; tt <= t; tt += step) { lvl = hbLevel(story, tt); ph += step * (1.1 + 2.8 * lvl); const x = 6 + (tt / story.T) * (w - 12); const y = h - 12 - lvl * (h - 34) - ecgShape(ph % 1) * (6 + 16 * (0.3 + lvl)); pts.push(`${x.toFixed(1)},${y.toFixed(1)}`); }
  return { pts: pts.join(" "), lvl };
}

/** Every algorithm, in plain words, with the rule or number it uses and why we chose it. */
export const ALGOS: { name: string; tag: string; plain: string; why: string; rules: string; where: string }[] = [
  { name: "Autoencoder (neural network)", tag: "Detect", plain: "Learns what normal network traffic looks like, then flags traffic it cannot rebuild.", why: "It needs no examples of attacks, so it can notice something new.", rules: "Squeezes traffic features through a small bottleneck and rebuilds them; the rebuild error is the 'oddness' score. A link that was never used and is suddenly busy scores high.", where: "Watchdog" },
  { name: "Physics invariants", tag: "Detect", plain: "Checks the laws of water and power: a pump that says ON must move water.", why: "A hacker can fake data, not physics. This works even for a zero-day with no signature.", rules: "Mass balance at tanks, pump-on versus flow, pressure versus level, breaker state versus load. One broken law raises the alarm on its own.", where: "Watchdog" },
  { name: "Logistic fusion (logistic regression)", tag: "Detect", plain: "Combines the network score and the physics score into one alarm probability.", why: "Simple, fast and easy to explain: you can read why the alarm rang.", rules: "An incident opens when the fused probability stays above 85% for two readings in a row, so a single blip does nothing.", where: "Watchdog" },
  { name: "Attack graph + Dijkstra shortest path", tag: "Predict", plain: "Draws every link an attacker could use and finds the likeliest route.", why: "Route finding is exact and instant, so the next step can be predicted while an attack runs.", rules: "Each link costs −ln(chance of success). The cheapest path is the most likely one. The same code gives the blast radius of any device.", where: "Predictor, blast radius" },
  { name: "Monte-Carlo attack worlds", tag: "Predict", plain: "Plays thousands of imagined attacks and counts what falls.", why: "Real attacks are too rare to learn from, but we can simulate many.", rules: "1,500 random worlds with common random numbers, so two defence plans are compared on exactly the same dice rolls. A device falls only if every step has a reason (weakness, weak login or stolen login).", where: "Predictor, risk numbers" },
  { name: "Gradient-boosted trees (monotone)", tag: "Predict", plain: "Scores how likely each device is to fall, in a blink.", why: "Fast and accurate on tables of facts, and the monotone rule keeps it honest.", rules: "15 facts per device (CVSS, EPSS, KEV list, exposure, hops, best-route chance, MFA, patches…). Constraint: more exposure can never lower the score. Trained on 260 defence set-ups; tested on set-ups it never saw.", where: "Predict page, What-if" },
  { name: "CELF lazy greedy", tag: "Fix", plain: "Picks the fixes that remove the most risk per unit of effort, one after another.", why: "Greedy is provably within 63% of the best possible for this kind of problem, and CELF makes it hundreds of times faster.", rules: "Each fix is scored on how much risk it removes now; scores are re-checked lazily. Checked against brute force: within 10% of the best of every feasible plan.", where: "Planner" },
  { name: "CP-SAT scheduling (Google OR-Tools)", tag: "Fix", plain: "Decides which week each fix happens, and the quietest hour for restarts.", why: "A constraint solver guarantees the schedule obeys every rule.", rules: "Limited effort per week; fixes that need a restart go to the quietest hour that is still soon enough for how urgent the fix is (weekday demand and delay cost are assumptions).", where: "Planner" },
  { name: "Minimum cut (max-flow, networkx)", tag: "Fix", plain: "Finds the fewest links to close so no route reaches the equipment.", why: "It is exact: no smaller set of cuts can do the job.", rules: "Treat each link as a pipe of capacity 1, then the smallest cut separating the internet from the controllers is the answer.", where: "What-if recommendations" },
  { name: "Water and power simulators (EPANET + pandapower)", tag: "Safety", plain: "Real physics engines for the pipes and the power grid.", why: "Every fix and every response is tried on a copy of the city first, so no hospital is made worse.", rules: "WNTR/EPANET for water pressure and flow, pandapower for power flow. A move that cuts a hospital below its minimum pressure is refused.", where: "Safety Check, risk numbers" },
  { name: "PPO (reinforcement learning)", tag: "Respond", plain: "A trained policy that chooses the response to an attack nobody has seen.", why: "It reacts in one step without searching, and was trained on other products so it generalises.", rules: "Proximal Policy Optimisation, trained on simulated attacks and tested on products it never saw. Honest result: it beats doing nothing or cutting everything, but not the search Planner, so the Planner stays the default.", where: "Zero-day responder" },
  { name: "Zero-day pipeline", tag: "Learn", plain: "Notices behaviour, describes it, writes a rule and remembers it.", why: "A signature does not exist yet, so we describe how the attack behaves instead.", rules: "Flag when no known weakness explains the alarm, build a fingerprint (protocols, techniques, number of devices), make a family rule and store it in the library so the next attempt is blocked at once.", where: "Zero-day page" },
  { name: "Safety Check (what-if on a twin)", tag: "Safety", plain: "A dry run of every action before it is allowed.", why: "Autonomy is only trusted if it cannot make things worse.", rules: "Safe steps may run automatically; risky ones need a person, and big ones need two.", where: "Healer" },
  { name: "Hash-chained log (SHA-256) + TOTP + Argon2id", tag: "Safety", plain: "Tamper-evident records and strong sign-in.", why: "An incident log is useless if it can be quietly edited.", rules: "Each log entry contains the hash of the one before it, so a secret edit breaks the chain. Passwords use Argon2id, logins need a 6-digit code, sessions are signed and expire.", where: "Safety page" },
];
export const TAGC: Record<string, string> = { Detect: C.apricot, Predict: "#7B61FF", Fix: C.aquaD, Safety: C.terraD, Respond: "#2E6BE6", Learn: "#1FA2A6" };

function stateAt(story: Story, t: number) {
  const own = new Set<number>(), sus = new Set<number>(), shield = new Set<number>(), cut = new Set<string>(), pred: { a: number; b: number; p: number }[] = [];
  let alarm = 0, healed = false, learned = false, rule = false, halted = false, scores: number[] | null = null, fixAt: number | null = null, attacker = 0, atkTarget = -1, trap = false; const mods = [0, 0, 0, 0];
  let atkText = "", defText = "", atkAlgo = "", defAlgo = "";
  for (const e of story.evs) {
    if (e.t > t) break;
    if (e.kind === "own" && e.a !== undefined) { own.add(e.a); attacker = e.a; atkTarget = -1; }
    if (e.kind === "suspect" && e.a !== undefined) sus.add(e.a);
    if (e.kind === "alarm") alarm = Math.max(alarm, e.v?.[0] ?? 0.9);
    if (e.kind === "predict" && e.a !== undefined) pred.push({ a: e.a, b: e.b!, p: e.p! });
    if (e.kind === "cut") cut.add(`${e.a}-${e.b}`);
    if (e.kind === "shield" && e.a !== undefined) shield.add(e.a);
    if (e.kind === "heal") { healed = true; alarm = 0; }
    if (e.kind === "learn") learned = true;
    if (e.kind === "rule") rule = true;
    if (e.kind === "trap") trap = true;
    if (e.kind === "scores") scores = e.v || null;
    if (e.kind === "fix") fixAt = e.a ?? null;
    if (e.kind === "bounce") { halted = true; atkTarget = e.b ?? -1; }
    if (e.kind === "mod" && e.mod !== undefined) mods[e.mod] = Math.max(mods[e.mod], 1 - Math.min(1, (t - e.t) / 3));
    if (e.text) { if (e.who === "attack") { atkText = e.text; atkAlgo = ""; } else { defText = e.text; defAlgo = e.algo || ""; } }
    if (e.algo && e.who === "defend") defAlgo = e.algo;
  }
  if (halted) { for (const e of story.evs) if (e.kind === "own" && e.t <= t && e.a === attacker) { /* keep */ } }
  return { own, sus, shield, cut, pred, alarm, healed, learned, rule, halted, scores, fixAt, attacker, atkTarget, trap, mods, atkText, defText, defAlgo };
}

export function HowView() {
  const [open, setOpen] = useState<string | null>(null); const [tab, setTab] = useState(0); const [t, setT] = useState(0); const [play, setPlay] = useState(true); const [speed, setSpeed] = useState(1);
  const story = STORIES[tab]; const raf = useRef(0); const last = useRef(0);
  useEffect(() => {
    if (!play) return; last.current = performance.now();
    const f = (now: number) => { const dt = (now - last.current) / 1000; last.current = now; setT((x) => { const n = x + dt * speed; return n > story.T + 2 ? 0 : n; }); raf.current = requestAnimationFrame(f); };
    raf.current = requestAnimationFrame(f); return () => cancelAnimationFrame(raf.current);
  }, [play, speed, tab]);
  const s = stateAt(story, t); const N = story.nodes;
  const atkX = N[s.attacker]?.x ?? 70; const lane = (y: number, c: string, l: string) => <g><rect x={8} y={y - 14} width={744} height={28} rx={14} fill={c} opacity=".12" /><text x={20} y={y + 4} fontSize="11" fontWeight="800" fill={c} letterSpacing=".08em">{l}</text></g>;
  const showNodes = tab === 1 ? N : N.slice(0, 6);
  return (
    <>
      <PageHead icon="play" title="How it works" sub="Attack and defence run side by side" />
      <div className="seg">{STORIES.map((x, i) => <button key={x.id} className={tab === i ? "on" : ""} onClick={() => { setTab(i); setT(0); setPlay(true); }}>{x.name}</button>)}</div>
      <div className="tip">{story.blurb}</div>
      <div className="howgrid"><div className="howbox">
        <svg viewBox="0 0 760 436" className="howsvg" role="img" aria-label="Animated attack and defence">
          {lane(34, HOT, "ATTACKER")}{lane(414, C.aquaD, "ATHENA DEFENCE")}
          {/* links */}
          {showNodes.slice(0, 5).map((n, i) => { const m = N[i + 1]; const key = `${i}-${i + 1}`; const on = s.own.has(i + 1) && s.own.has(i); const cut = s.cut.has(key); const pr = s.pred.find((q) => q.a === i && q.b === i + 1);
            return <g key={key}><line x1={n.x} y1={n.y} x2={m.x} y2={m.y} stroke={on ? HOT : "#CDB7A3"} strokeWidth={on ? 5 : 2.2} className={on && !cut ? "flow" : ""} strokeDasharray={on ? "8 5" : undefined} />
              {pr && !on && <line x1={n.x} y1={n.y} x2={m.x} y2={m.y} stroke="#F28C1B" strokeWidth={4} strokeDasharray="3 6" className="flow" />}
              {pr && !on && <text x={(n.x + m.x) / 2} y={n.y - 22} textAnchor="middle" fontSize="11" fontWeight="800" fill="#B56400">{Math.round(pr.p * 100)}%</text>}
              {cut && <g transform={`translate(${(n.x + m.x) / 2},${n.y})`}><circle r="13" fill={C.terraD} stroke="#fff" strokeWidth="2.5" className="pop" /><text textAnchor="middle" y="5" fontSize="15" fontWeight="800" fill="#fff">✕</text></g>}</g>; })}
          {tab === 1 && <line x1={N[3].x} y1={N[3].y} x2={N[6].x} y2={N[6].y} stroke={s.own.has(6) ? HOT : "#CDB7A3"} strokeWidth={s.own.has(6) ? 5 : 2} strokeDasharray="4 5" />}
          {/* nodes */}
          {showNodes.map((n, i) => { const o = s.own.has(i), su = s.sus.has(i), sh = s.shield.has(i); const sc = s.scores?.[i] ?? 0; const fill = sh ? "#A38C7B" : o ? HOT : su ? C.apricot : "#fff"; const ring = s.fixAt === i;
            return <g key={i} transform={`translate(${n.x},${n.y})`}>
              {sc > 0 && <rect x={-9} y={-34 - sc * 60} width={18} height={sc * 60} rx={4} fill={sc > 0.45 ? HOT : sc > 0.25 ? "#F28C1B" : C.aquaM} className="grow-bar" />}
              {sc > 0 && <text y={-38 - sc * 60} textAnchor="middle" fontSize="10.5" fontWeight="800" fill="#3A2216">{Math.round(sc * 100)}%</text>}
              {(o && !sh) && <circle r="27" fill="none" stroke={HOT} strokeWidth="2.5" className="gping" />}
              {su && !o && <circle r="27" fill="none" stroke={C.apricot} strokeWidth="2.5" className="gping" />}
              {sh && <circle r="31" fill="rgba(111,195,203,.3)" stroke={C.aquaD} strokeWidth="3.5" className="pop" />}
              {ring && <circle r="31" fill="none" stroke={C.aquaD} strokeWidth="3.5" strokeDasharray="6 4" className="pop" />}
              {s.trap && i === 6 && <circle r="31" fill="none" stroke={C.aquaD} strokeWidth="3.5" className="pop" />}
              <circle r="22" fill={fill} stroke="#fff" strokeWidth="3" /><text textAnchor="middle" y="7" fontSize="20">{n.icon}</text>
              {i === 6 ? <text x="30" y="5" fontSize="10.5" fontWeight="700" fill="#3A2216">{n.label}</text> : <text y="42" textAnchor="middle" fontSize="11" fontWeight="700" fill="#3A2216">{n.label}</text>}
              {sh && <text y="-31" textAnchor="middle" fontSize="16">🛡</text>}</g>; })}
          {/* attacker */}
          <g transform={`translate(${atkX},62)`} style={{ transition: "transform .8s cubic-bezier(.3,.8,.3,1)" }}><circle r="15" fill={HOT} stroke="#fff" strokeWidth="2.5" opacity={s.halted && s.own.size > 0 && tab !== 1 ? 0.45 : 1} /><text textAnchor="middle" y="5" fontSize="15">☠</text>
            <line x1="0" y1="15" x2="0" y2={101} stroke={HOT} strokeWidth="2" strokeDasharray="3 4" opacity=".6" /></g>
          {s.halted && <text x={atkX} y={96} textAnchor="middle" fontSize="11" fontWeight="800" fill={HOT}>BLOCKED</text>}
          {/* defence modules */}
          {MODS.map(([n, a], i) => { const x = 40 + i * 180; const on = s.mods[i] > 0.01; return (
            <g key={n} transform={`translate(${x},362)`}><rect width="160" height="30" rx="10" fill={on ? C.aquaD : "#fff"} stroke={on ? C.aquaD : "#E5CBB1"} strokeWidth="2" style={{ transition: "fill .3s" }} /><text x="80" y="19" textAnchor="middle" fontSize="11.5" fontWeight="800" fill={on ? "#fff" : "#6B4A36"}>{n}</text></g>); })}
          {/* heartbeat: reacts to everything that happens in the story */}
          {(() => { const w = 680, h = 66; const { pts, lvl } = ecg(story, Math.min(t, story.T), w, h); const hot = lvl > 0.5; const col = hot ? HOT : lvl > 0.15 ? "#F28C1B" : C.aquaD; const word = story.id === "predict" ? "risk" : s.healed ? "calm" : lvl > 0.5 ? "ALARM" : lvl > 0.15 ? "uneasy" : "calm";
            return <g transform="translate(40,282)"><rect width={w} height={h} rx="12" fill="#fff" stroke={hot ? HOT : "#EBC7A5"} strokeWidth={hot ? 2 : 1} />
              <text x="12" y="16" fontSize="10.5" fontWeight="700" fill="#85624C">{story.id === "predict" ? "Risk level" : "Heartbeat"}</text>
              <line x1="6" x2={w - 6} y1={h - 12 - 0.85 * (h - 34)} y2={h - 12 - 0.85 * (h - 34)} stroke={HOT} strokeOpacity=".35" strokeDasharray="4 4" />
              <polyline fill="none" stroke={col} strokeWidth="2.2" strokeLinejoin="round" points={pts} />
              <text x={w - 12} y="18" textAnchor="end" fontSize="13" fontWeight="800" fill={col}>{word} · {Math.round(lvl * 100)}%</text></g>; })()}
          {s.learned && <g transform="translate(40,128)"><rect width="190" height="26" rx="9" fill="#FCD9B8" stroke={C.apricot} className="pop" /><text x="95" y="17" textAnchor="middle" fontSize="11" fontWeight="800" fill="#7A3E12">⚠ unknown product: suspect</text></g>}
          {s.rule && <g transform="translate(40,128)"><rect width="190" height="26" rx="9" fill={C.aqua} stroke={C.aquaD} className="pop" /><text x="95" y="17" textAnchor="middle" fontSize="11" fontWeight="800" fill="#1D5C64">✓ family rule saved</text></g>}
          {s.healed && <g transform="translate(300,128)"><rect width="160" height="26" rx="9" fill={C.aqua} stroke={C.aquaD} className="pop" /><text x="80" y="17" textAnchor="middle" fontSize="12" fontWeight="800" fill="#1D5C64">✓ service kept</text></g>}
        </svg>
        <div className="caps"><div className="cap atk"><b>Attacker</b><span>{s.atkText || "Waiting…"}</span></div><div className="cap def"><b>ATHENA</b><span>{s.defText || "Watching…"}</span>{s.defAlgo && <em className="algo">{s.defAlgo}</em>}</div></div>
        <div className="ctrls"><button className="btn small" onClick={() => setPlay(!play)}><Ic n={play ? "pause" : "play"} /> {play ? "Pause" : "Play"}</button><button className="btn small" onClick={() => { setT(0); setPlay(true); }}>Restart</button>
          <input type="range" min={0} max={story.T} step={0.1} value={Math.min(t, story.T)} onChange={(e) => { setT(+e.target.value); setPlay(false); }} aria-label="Timeline" /><select value={speed} onChange={(e) => setSpeed(+e.target.value)} aria-label="Speed"><option value={0.5}>×0.5</option><option value={1}>×1</option><option value={2}>×2</option></select></div>
      </div>
            <div className="howside">
        <h3 className="algo-h">Algorithms used (tap one to open)</h3>
        {ALGOS.map((x) => (
          <details key={x.name} className="algo" open={open === x.name} onToggle={(e) => { if ((e.target as HTMLDetailsElement).open) setOpen(x.name); else if (open === x.name) setOpen(null); }}>
            <summary><span className="atag" style={{ background: TAGC[x.tag] }}>{x.tag}</span><b>{x.name}</b></summary>
            <div className="abody"><p>{x.plain}</p><dl><dt>Why we chose it</dt><dd>{x.why}</dd><dt>Rules and numbers</dt><dd>{x.rules}</dd><dt>Where in ATHENA</dt><dd>{x.where}</dd></dl></div>
          </details>))}
      </div>
      </div>
    </>
  );
}
