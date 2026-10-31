# ATHENA — A City-Defence System That Predicts, Explains and Heals
**D3COY 1.0 · PS03 · Master build plan (for Claude and the team) · v2**

> **Claude, read in this order:** §1 → §3 → §5 → §6 → §8 → §14. Everything else is reference.
> **Rules for this plan:** (1) real algorithms, not placeholders; (2) plain names everywhere; (3) fallbacks are rare — see §15; (4) never claim "unhackable", claim "hard to attack and designed to fail safely".

---

## 1. The 60-second version (what a judge must understand)

**What it is.** ATHENA watches a simulated Mumbai ward: computers, control devices, water pipes, power lines, hospitals. It answers four questions in plain language:

1. **What can hurt the city most?** (not "which bug is worst" — *which device, if hacked, makes people lose water or power*)
2. **What will the attacker probably do next?** (predicted attack path)
3. **What should we fix first, and when?** (including: "don't patch now, patching would stop a pump")
4. **If an attack is happening, how do we stop it without switching the city off?** (cut one link, redirect to a decoy, keep utilities running)

**Headline number — Service-at-Risk (SaR):** *"On a bad-but-realistic day, no more than X households lose water for Y hours."* Computed with a physics simulator, not guessed.

**Why it's different, in one line:** *Everyone else scores how bad a bug is. We measure how many people it would hurt, and we fix it without shutting the city down.*

**How we prove it:** experiments against brute force, against CVSS ranking, against "isolate everything" (§12).

### Plain-name glossary for the whole system (use these names in code, UI and slides)
| Plain name | What it does | (Technical name, for experts) |
|---|---|---|
| **Map Builder** | Builds the city map of devices and links | Multi-layer heterogeneous graph |
| **Threat Finder** | Matches devices to known bugs and how likely they are to be used | CVE/CPE + EPSS/KEV engine |
| **Path Predictor** | Finds how an attacker could travel, and which route is likely | Probabilistic attack graph + importance sampling |
| **Impact Simulator** | Computes real service loss (water, power, hospital) | WNTR + pandapower physics oracle |
| **Fast Guesser** | Quickly estimates impact so we can test thousands of cases | GNN surrogate + conformal prediction |
| **Risk Scorer** | Service-at-Risk, "harm if hacked", "harm avoided if protected" | SaR, RAW, RRW |
| **Fix Planner** | Chooses and schedules fixes | Lazy-greedy + CP-SAT scheduler |
| **Ask-First** | Tells the operator which missing fact to check first | Value of information |
| **Watchdog** | Spots attacks, including brand-new ones | Dual-core anomaly + physics invariants |
| **Healer** | Responds surgically | Safe reinforcement-learning policy + safety shield |
| **Decoys** | Fake devices that trap attackers | Dynamic honeypots |
| **Safety Check** | Tests every action on a copy of the city before doing it | Digital-twin constraint checker |
| **Black Box Log** | Tamper-proof record of everything | Hash-chained audit log |

---

## 2. What already exists — and how ATHENA uses it (not ignores it)

We **include** every established layer, so a judge sees we know the field, then add what's missing.

| Existing category | Real examples | How ATHENA includes it | What ATHENA adds on top |
|---|---|---|---|
| **SIEM** (collects & correlates logs) | Splunk, IBM QRadar | **Log Collector** ingests syslog/JSON events into the same graph; correlation rules map events to devices | Events are tied to *physical* consequence, not just alerts |
| **SOAR** (automated playbooks) | Cortex XSOAR | **Playbook Runner**: every remedy is a versioned, reviewable playbook with approve / auto / rollback | Playbooks are chosen by simulated service impact; unsafe ones are blocked by the Safety Check |
| **EDR/XDR** (host agents) | CrowdStrike, SentinelOne | **Host Signal Adapter**: accepts endpoint alerts as evidence that raises a node's compromise probability | Evidence updates predicted paths in real time |
| **Firewall / IPS** | Fortinet, Cisco ASA | **Rule Generator**: outputs vendor-neutral rules (exportable to iptables/nftables/Fortinet syntax) for virtual patches and segmentation | Rules are generated, simulated, then applied; blast radius shown first |
| **Passive OT monitoring** | Claroty, Nozomi, Dragos | **Protocol Watcher** parses Modbus/DNP3/MQTT/IEC-104 to discover assets & learn normal behaviour | Learned behaviour feeds physics-aware detection and the impact map |
| **Data diodes / air gaps** | Hardware one-way links | **Air-Gap Mode**: signed one-way file import, fully offline operation | Same engine runs on an offline edge box |
| **Vulnerability scanners** | Nessus, Qualys | **Threat Finder** matches versions → CVEs (NVD) and adds SBOM component CVEs | Bug only counts if it lies on a path to a control action |
| **Attack-surface management** | CyCognito | **Exposure Scanner** (simulated internet view) lists what's reachable from outside | Exposure becomes the *starting points* of predicted attacks |
| **Attack-path tools** | XM Cyber, Tenable, Microsoft Defender for IoT | **Path Predictor** builds attack graphs and choke points | Paths end in *service loss*, not "device hacked" |
| **Severity & priority frameworks** | CVSS, EPSS, KEV, **SSVC (Track/Attend/Act)** | All used as inputs; SSVC label shown on every device next to SaR | We show where SaR and SSVC disagree and why |
| **Architecture standards** | Purdue model, IEC 62443 zones/conduits, NIST CSF 2.0, CISA CPG 2.0, MITRE ATT&CK for ICS | Map Builder uses Purdue layers & zones; every action maps to a conduit, CSF function, CPG goal, ATT&CK technique | Compliance becomes a by-product of operation |
| **Indian guidance** | CERT-In Smart-City guidelines, CERT-In 20-city findings | Misconfiguration rates seeded from the findings; every remedy tagged with the chapter; one-click CERT-In incident export | Local relevance |
| **Consequence-driven method** | Idaho National Lab CCE (workshop-based) | We automate it: start from worst service events, work back to enabling devices | Computed, not workshop-guessed |
| **Honeypots / deception** | Open-source honeypots | **Decoys** generated on predicted paths | Placement chosen by the predictor, not static |

**Accenture-style patents** (attack-graph "digital twins", scored process impact): we use physics-simulated impact, fix-downtime cost and ranked unknowns instead. Technical comparison only, not legal advice.

---

## 3. Features (all are core; none is "optional")

| ID | Feature (plain words) | Why it matters |
|----|----------------------|----------------|
| **F1** | **Service-at-Risk** in real units (household-hours without water, MWh unserved, hospital-hours below pressure) | Harm measured, not labelled |
| **F2** | **Harm-if-hacked / harm-avoided-if-protected** per device (RAW/RRW) | Finds "quiet amplifiers": low score, huge downstream effect |
| **F3** | **Fix Planner that counts the fix's own downtime** and fits maintenance windows; can say "virtual-patch, don't reboot" | Matches how OT really works |
| **F4** | **Surgical self-healing**: isolate the smallest cluster that stops the attack while utilities keep running | The "don't switch off the city" requirement |
| **F5** | **Ask-First**: ranks missing facts by how much they would change the plan | Real inventories are incomplete |
| **F6** | **Zero-day Watchdog**: network behaviour model + physics laws, no signature needed | Catches attacks nobody has seen |
| **F7** | **Decoys**: fake devices placed on the predicted path; attacker redirected and studied | Prediction becomes defence |
| **F8** | **Air-Gap Mode**: signed offline snapshots, runs on an edge box | Real for treatment plants & substations |
| **F9** | **Plain-language explanations**: every alert says why, what happens, what to do | Operators act on what they understand |
| **F10** | **Assume-breach mode**: "attacker is on public Wi-Fi — fastest route to the water supply? Cut it now" | Built-in red-team view |
| **F11** | **Cascade view** power → pumps → tanks → hospital, with time-to-survive vs time-to-repair | Smart-city interdependence |
| **F12** | **Risk-avoided ledger**: service-hours saved by fixes already done | Shows value |
| **F13** | **Self-learning loop**: Watchdog re-learns normal behaviour continuously; Healer trained against thousands of simulated attacks | Autonomous cyber defence |
| **F14** | **Secure-by-design platform** (§10) | A cyber tool must itself be hard to attack |

**Severity ≠ risk** is shown on screen: a CVSS 10 behind a one-way link = LOW; a CVSS 5.3 feeder controller on the vendor-VPN route = TOP.

---

## 4. City choice and real data

**Mumbai first; Bengaluru as proof of portability** (city = one config file: `city_config/mumbai.yaml`, `bengaluru.yaml`).

**Real anchors (verify every name before showing it as REAL; otherwise tag SYNTHETIC):**
- **Water (BMC):** lake supply chain (Upper Vaitarna, Modak Sagar, Tansa, Vihar, Tulsi, Bhatsa), treatment plants (Bhandup, Panjrapur), service reservoirs, pumping stations.
- **Power:** Tata Power, Adani Electricity Mumbai, BEST, MSETCL; Mumbai islanding scheme.
- **Hospitals:** KEM, Sion, JJ, Tata Memorial, Kasturba, major civic hospitals (min pressure, generator-hours).
- **Smart-city layer:** street-light gateways, traffic signals, CCTV, EV chargers, smart meters, metro/rail signalling interfaces (read-only).
- **Hydraulics and electricity:** WNTR **C-Town** relabelled as the ward water model; a pandapower benchmark feeder relabelled as the ward feeder (stated openly).
- **Real public data used:** NVD (CVE/CPE), FIRST **EPSS v4**, CISA **KEV**, MITRE **ATT&CK for ICS**, **OpenStreetMap** (hospitals, substations, pumping stations, water towers), BATADAL/HAI for process structure and attack types, CERT-In 20-city findings for misconfiguration rates.
- **Provenance tag on every data item:** `REAL` · `DERIVED` · `SYNTHETIC`. The UI shows it. Honesty is a feature.

The Oct 2020 Mumbai outage may be used as a motivating example; verify the wording and attribution before quoting.

---

## 5. Internal system design

### 5.1 Principles
Event-driven; **digital twin first** (nothing touches the "live" city before it is simulated); incremental recomputation (only what changed); every module has one job and a typed interface; everything logged to the Black Box.

### 5.2 Architecture
```
 SOURCES                    BRAIN                                      HANDS                    EYES
 ─────────                  ─────                                      ─────                    ────
 Asset lists (JSON)   ─┐
 NVD / EPSS / KEV     ─┤   Map Builder ─► Threat Finder ─► Path Predictor
 Protocol Watcher     ─┤        │              │                │
 Logs / host alerts   ─┼──►     ▼              ▼                ▼
 Telemetry (sim)      ─┤   ┌──────── Twin (live copy of the city state) ───────┐
 Signed offline files ─┘   │  Impact Simulator ◄──► Fast Guesser (+ error bars) │
                           └───────────┬─────────────────────┬──────────────────┘
                                       ▼                     ▼
                                  Risk Scorer           Watchdog (2 cores)
                                       │                     │ anomaly
                                       ▼                     ▼
                                  Fix Planner ◄──────── Healer ──► Safety Check ──► Playbook Runner
                                  Ask-First                          (simulate first)   (approve/auto/rollback)
                                       │                                                     │
                                       └───────────────► API (REST + WebSocket) ◄────────────┘
                                                              │
                                                    UI: 3D city · Judge Mode · Operator · Analyst · Executive
                                                    Black Box Log (hash-chained) records everything
```

### 5.3 The twin (core internal design)
- **Twin state** = graph + current device states + latest telemetry + hidden-link beliefs.
- **Copy-on-write snapshots**: forking the twin to test an action is cheap (store only the diff).
- **Result cache** keyed by `(graph-version hash, attack, action-set, time-bucket)` → no repeated simulation.
- **Incremental update**: when one edge or device changes, only affected paths and affected physical sub-networks are recomputed.
- **Common random numbers**: "before" and "after" a fix use the same random attacks, so differences are clean and need fewer samples.

### 5.4 Storage and plumbing
SQLite/Parquet for assets, edges, runs, results; in-memory graph (NetworkX build, PyTorch-Geometric tensors); **FastAPI + WebSocket** for streaming; async queue between modules (asyncio queues; Redis only when scaling test needs it); Docker Compose (api, engine, ui, worker). Air-gap box = one container, CPU-only.

---

## 6. Algorithms — the best choices for each job

Each row: the problem → algorithm chosen → why it is the right one → how we check it.

### 6.1 Map Builder — representing the city
- **Heterogeneous layered graph** (cyber → control → physical → service) with typed edges (`reaches`, `trusts`, `shares-password`, `vendor-access`, `controls`, `powers`, `feeds-water`, `serves`, `part-of`).
- Edges we are unsure about carry `p_exists` (an **uncertain graph**). ~30% of links/versions are hidden from the system, as in real inventories.
- Asset fields follow the CISA 2025 inventory guidance; zones/conduits follow IEC 62443.

### 6.2 Path Predictor — how an attacker travels
- **Probabilistic attack graph**: each step succeeds with probability from EPSS (≈0.95+ if in KEV), lowered by protections, raised by weak settings (default password, unencrypted Modbus). Steps labelled with ATT&CK-for-ICS techniques.
- **Importance sampling (cross-entropy method)** for the tail: plain Monte Carlo rarely samples the rare, very damaging attacks that decide SaR95; the cross-entropy method steers sampling toward them, giving accurate tail estimates with far fewer runs.
- **Next-step forecast**: a Markov model over the attack graph conditioned on current evidence (alerts, honeypot touches) — answers "where will they go next?" in real time (Bayesian update as evidence arrives).
- **Hidden-link inference**: sample the uncertain graph; paths through hidden links get probability mass proportional to `p_exists`.
- *Check:* tail-estimate error vs a very large brute-force run (E1, E8).

### 6.3 Impact Simulator — what physically happens
- **WNTR (EPANET)** for water: pump off, valve closed, setpoint changed, PLC lies about tank level; **pandapower** for power: breaker open, feeder loss, load shed. Pumps are powered by the feeder, so a power attack cascades into a water outage; hospitals need minimum pressure and have generator-hours.
- Time-of-day demand curves (same attack at 3 am vs 7 pm differs).
- **Partial service model** (low pressure = partly served, not on/off).
- Loss: `L(c) = Σ_s w_s ∫ max(0, demand_s(t) − delivered_s(t | c)) dt`.
- **Time-to-survive vs time-to-repair** per service (tank hours, battery hours vs PLC restore time).

### 6.4 Fast Guesser — speed with guaranteed honesty
- **Heterogeneous graph neural network (GraphSAGE/GAT)** trained on thousands of simulator runs → predicts service loss instantly.
- **Conformal prediction** attaches a *statistically guaranteed* error interval to every estimate. Rule: if the interval is wide, or the case is in the worst tail, **the full simulator is called**. This is the principled version of "trust but verify".
- Reported: agreement with simulator (Spearman), speed-up, error on worst 10% (E6).

### 6.5 Risk Scorer
- `SaR95` = 95th percentile of `L`; also mean loss and worst-case.
- `RAW_i = E[L | i hacked] − E[L]` ; `RRW_i = E[L] − E[L | i protected]` (nuclear-safety measures), estimated with common random numbers.
- **SSVC label** (Track/Attend/Act) computed alongside for comparison with the industry framework.
- **Explanation by attribution**: path trace + SHAP values on the Fast Guesser + counterfactual ("if this link were closed, SaR drops from A to B").

### 6.6 Fix Planner
- **Candidate fixes** come from CISA CPG 2.0 goals + IEC 62443: virtual patch, close a conduit, MFA on vendor access, rotate credentials, firmware patch, enable monitoring, manual-control fallback — each with cost, ease, downtime, reversibility.
- **Selection:** `priority(a) = (E[L] − E[L | a]) / (cost_a + λ·D_a)` where `D_a` is the service lost *by doing the fix itself*. Solved with **CELF lazy-greedy** (fast, near-optimal for diminishing-returns objectives). Because fixes interact (two cheap fixes can beat one dear one), the greedy result is checked against an **exact optimum** (OR-Tools CP-SAT) on a reduced city (E3) and the gap is published.
- **Scheduling:** **CP-SAT constraint model** puts fixes into maintenance windows so that fix downtime never breaks service limits (hospital pressure, N-1 on the feeder).
- Output: ordered plan with dates, reasons, and explicit "**do not patch — use virtual patch**" decisions.

### 6.7 Ask-First (value of information)
- Unknowns = hidden links, unknown versions, unknown credentials. Each has a belief (probability).
- `VoI(u)` = expected improvement in plan quality if `u` were known = (expected best-plan loss given the answer, averaged over possible answers) − (best-plan loss now). Computed by Monte Carlo over the belief.
- Output: top 3 questions in plain words ("Can the historian write to PLC-4?"). Operator answers → belief collapses → graph updates → plan recomputes live.

### 6.8 Watchdog — detecting attacks, including brand-new ones (two cores that must agree or explain)
**Core A: Network behaviour.**
- Parse Modbus/DNP3/MQTT/IEC-104 into features (function code, register, length, timing, sequence, who-talks-to-whom).
- **Temporal graph model** (GNN over the flow graph + sequence model per link) trained only on normal traffic; high reconstruction/prediction error = unusual.
- **Behaviour rules learned from normal** (per device: who may write what, how often, when) = whitelist of normal.

**Core B: Physics laws.**
- **Invariants mined automatically** from normal telemetry (e.g. pump on ⇒ downstream flow rises; reported valve state must match flow/pressure; breaker cycle limits) using decision-tree/regression invariant mining, plus a **state-space residual check** against the twin's own prediction.
- Catches telemetry spoofing and wear-and-tear attacks (breaker flipped 50× in 10 s) that look "valid" on the network.

**Fusion:** each core outputs a calibrated score; combined with a Bayesian fusion rule. Attack declared if physics core fires, or both cores are moderately high. Drift handled with **ADWIN** change-detection: normal behaviour slowly changing (seasonal demand) is re-learned; sudden change is not.

**Self-learning:** online mini-batch gradient updates on **verified-normal windows only** (windows near any alert are quarantined from training — prevents attackers "teaching" the model); a replay buffer prevents forgetting.

### 6.9 Healer — responding without taking the city down
**Response ladder (least → most disruptive):** observe → virtual patch → close one link → rotate credentials/MFA → redirect to Decoy → isolate a small cluster → local/manual control. **Never "isolate everything".** If nothing safe exists, escalate to a human with options and costs.

**How the choice is made:**
1. **Candidate cuts** = minimum-cost cuts on the attacker-reachable subgraph (cut the fewest/least-important links), enumerated with a min-cut/ILP formulation.
2. **Evaluate every candidate in the twin** with the Impact Simulator: cost = remaining SaR + service lost by the action itself.
3. **Policy:** a **PPO reinforcement-learning agent** trained in a Gymnasium environment built from the twin (thousands of simulated attack campaigns per city), with **action masking** (illegal/unsafe actions never offered). Reward = + service availability − attack progress − action cost − unneeded disruption.
4. **Safety shield:** the agent's chosen action is *always* re-simulated by the Safety Check; if it breaks a hard rule (hospital pressure, N-1 grid), it is rejected and the next-best safe action is used. This gives learning-based flexibility with rule-based guarantees.
- **Benchmarks (not fallbacks):** do nothing, rule-based, greedy, isolate-everything. We show PPO+shield beats them on service retained and attack containment (E9).

**Decoys:** placed where the Path Predictor says the attacker will go; made to look slightly weak; any touch = high-confidence alert, session redirected, techniques logged. Decoy count and placement chosen by expected-information-gain and cost. Decoys are marked clearly to authorised staff so no one tries to "fix" them.

**Zero-day flow:** physics invariant or behaviour anomaly fires → Healer takes the least disruptive action (virtual patch derived from the learned whitelist; close the single link; redirect that session to a Decoy) → evidence snapshot → human review; understanding the exploit comes *after* containment.

### 6.10 Forecasting
24-hour rolling SaR forecast from: EPSS updates (daily), new KEV entries (hazard step-ups), demand curves, planned maintenance. Back-tested: did our threat ranking rank CVEs high *before* they entered KEV? (E7).

### 6.11 Uncertainty everywhere
Never show a bare number: show an interval (conformal for the Fast Guesser, sampling interval for SaR) and say how sure the top pick is (rank stability, E8).

---

## 7. Data structures (concrete)

**Asset**
```json
{
  "asset_id": "PLC_WATER_BHANDUP_03",
  "name": "Pump House 3 Valve Controller",
  "sector": "water", "city_zone": "Bhandup-W",
  "geo": {"lat": 19.1498, "lon": 72.9380, "source": "synthetic-near-OSM"},
  "purdue_layer": 1, "iec62443_zone": "Z-WATER-CONTROL",
  "vendor": "Schneider", "model": "Modicon M340",
  "firmware_version": "Modicon_v2.1",
  "cpe": "cpe:2.3:o:schneider-electric:modicon_m340_firmware:2.1",
  "sbom": [{"component": "openssl", "version": "1.0.2k"}],
  "ip_address": "10.20.3.45", "exposure": "internal",
  "protocols": ["modbus_tcp"], "encrypted_comms": false,
  "serves": {"service": "water_supply", "households": 42000, "hospital_dependent": true},
  "known": {"firmware": true, "links": false},
  "fix_options": ["virtual_patch","close_link","mfa_vendor","firmware_patch","manual_fallback"],
  "patch_downtime_min": 25, "maintenance_window": "Sun 02:00-05:00",
  "provenance": "SYNTHETIC"
}
```
**Vulnerability:** `cve_id, cpe_match, cvss, epss, in_kev, attack_vector, ics_technique, virtual_patchable, remediation`.
**Edge:** `{source, target, type, protocol, auth, encrypted, conduit_id, p_exists}`.
**Telemetry:** `{ts, asset_id, tag, value, unit, cmd}`.
**Offline snapshot:** assets + edges + `sha256` + **Ed25519 signature** + monotonic version number (stops replay).
**Importance is never typed in by hand**: it is derived from simulated harm. A hand-typed criticality column exists only as a baseline to compare against.

---

## 8. Human interface (HCI) — simple, explainable, memorable

### 8.1 Design rules we follow (and can name to a judge)
**Norman:** *visibility* (state always shown), *feedback* (every click answers within 100 ms; actions show progress), *signifiers* (buttons look pressable; risky actions look different), *mapping* (physical layout of the screen mirrors the city: water bottom, power side), *constraints* (dangerous actions need confirmation; impossible actions are greyed with a reason), *conceptual model* (one story: "map → danger → fix → proof"), *error prevention and recovery* (preview blast radius, one-click undo).
**Shneiderman:** "Overview first, zoom and filter, details on demand"; consistency; informative feedback; closure (each task ends with a clear "done"); reversible actions; user in control; low short-term memory load.
**Cognitive load:** at most 3 primary actions on any screen; plain words first, technical terms on hover; units and ranges on every number.

### 8.2 Three people, three views (same data underneath)
| Person | Need | View |
|---|---|---|
| **Operator** (night shift, stressed) | One clear action, plain language, undo | **Operator view**: big status, top 3 actions, "why", approve / rollback, large touch targets |
| **Analyst** | Evidence, paths, what-ifs | **Analyst view**: path explorer, ranking table, explanation panels, hunt timeline |
| **Official / judge** | Meaning in minutes | **Executive & Judge Mode** (below) |

### 8.3 Judge Mode (the "understand it in 3 minutes" feature)
A guided, auto-advancing tour with captions in plain words:
1. **"Here is the city."** Overview, layers toggle.
2. **"The usual ranking."** Device list by CVSS.
3. **"Our ranking."** Slope chart animation: the list reorders, mid-score devices rise.
4. **"Why?"** Click the top device → path comet runs → water drains → hospital pressure falls.
5. **"Fix it."** What-if cards; before/after bars.
6. **"Attack now."** Live attack injected; Decoys trap; one cluster cut; utilities stay lit; counter shows "households still served: 99.8%".
7. **"Unknown attack."** Zero-day caught by physics.
8. **"Proof."** Key results. **"Limits."** Honest list.
Every step has *Skip*, *Back* and a *"Explain this"* drawer. No jargon without a hover definition.

### 8.4 Visualisation techniques — one unique visual per task
| Task | Visualisation | How it works |
|---|---|---|
| See the whole city | **3D city twin** with extruded buildings, glowing pipe/feeder networks, hospital "beacons" | Three.js instanced meshes + MapLibre/deck.gl ground; real Mumbai footprints from OSM |
| Understand layers | **Exploded Purdue stack**: translucent glass slabs (internet / office / control / machines / physical) float apart; links drawn between slabs | Lets a judge *see* IT-to-OT paths vertically |
| See where risk is | **Risk terrain**: risk rises as glowing hills above the map (height = SaR contribution) | Instantly shows hotspots; hills shrink when fixes are applied |
| See an attack route | **Comet path**: bright particles travel along arcs with technique labels | Animated along predicted route; thickness = probability |
| See physical effect | **Live fluid & flow**: pipes with moving particles, tanks with real liquid-level shader, feeders with pulse; low-pressure pipes dim | Water level falling is visible; hospital minimum shown as a line on the tank |
| See blast radius | **Ripple dome**: expanding translucent dome from the compromised device over the map, coloured by service lost | Before/after side by side |
| Compare ranking methods | **Rank-reversal slope chart** (CVSS vs SaR) with animated crossing lines | The "aha" slide |
| Understand SaR | **Tail histogram with draggable percentile marker** | Judge drags to 95% and sees the number |
| Choose a fix | **What-if cards with before/after ghost bars** | Hover shows cost, downtime, reversibility |
| See the schedule | **Maintenance-lane Gantt** with refused patches shown as "blocked: would stop Pump 3" | Constraints visible |
| Decide what to ask | **Question cards with information-gain bars** | Longest bar = ask first |
| Watch the self-healing | **"Surgery view"**: the cut link animates as a snip; quarantined cluster is hatched; a counter shows utilities still running | Proves "didn't shut everything" |
| See decoys | **X-ray toggle**: real devices solid, decoys shimmer violet | Clear for staff; invisible to attackers |
| Compare outcomes | **Ghost timeline split-screen**: "no action" vs "ATHENA" tank levels, same scrubber | Replay any incident |
| Show uncertainty | **Soft-edged bands** around values and "unsure" markers | Honest ranges |
| See learning | **Normal-behaviour envelope** that visibly adapts over days | Shows self-learning |

**3D asset approach:** procedurally generated low-poly models (pump house, tank, substation, transformer, PLC cabinet, gateway tower, hospital) with consistent materials and emissive edges, instanced for speed; level-of-detail swapping; 60 fps target on a normal laptop; heavy calculations in web workers. Icons and shapes are always paired with colour so nothing depends on colour alone.

### 8.5 Colour system — "Mumbai Dusk"
Distinct from the usual neon green / red-on-black / corporate blue: a deep aubergine-ink base lit by a sunset gradient. Warm = danger, cool = safe, violet = deception — so meaning never relies on red/green.

| Role | Token | Hex |
|---|---|---|
| Background deepest | `ink-0` | `#0E0818` |
| Panels | `ink-1` / `ink-2` | `#170F29` / `#231838` |
| Lines | `line` | `#3A2B5C` |
| Text | `text` / `muted` | `#F4EFFF` / `#B7A9D6` |
| **Safe / healthy** | `sea-glass` | `#4FE3C1` |
| **Watch** | `marigold` | `#FFB627` |
| **High risk** | `vermilion` | `#FF5A3C` |
| **Critical** | `raspberry` | `#E8236B` |
| **Deception (Decoys)** | `ultraviolet` | `#A78BFF` |
| **Protection / healing** | `ice` | `#5CC8FF` |

**Gradients (always meaningful, not decoration):**
- **Dusk (brand/primary):** `#6A3DF5 → #E8236B → #FFB627` — headers, key buttons, hero charts.
- **Risk ramp:** `#4FE3C1 → #FFB627 → #FF5A3C → #E8236B` — risk terrain, node glow, heat bars.
- **Night backdrop:** `#0E0818 → #1D0F3A` — page background, subtle depth.
- **Healing wave:** `#5CC8FF → #4FE3C1` — fix/recovery animations.

**Contrast rules:** body text ≥ 7:1 on panels, large text and key marks ≥ 4.5:1 (check with a contrast tool before freezing); one **hot accent per screen** (the thing you should look at is the only marigold/raspberry element); everything else is low-chroma so the important item stands out; every colour code is paired with a shape/pattern (hatching = quarantined, dashed = uncertain, ring = anomaly). Light theme provided for printing/projectors.

### 8.6 UI stack
React + Vite + TypeScript; MapLibre + deck.gl for the ground map; react-three-fiber (three.js) for 3D; Cytoscape.js for the path explorer; visx/Recharts for charts (apply the `dataviz` skill palette rules to the colours above); Framer Motion for feedback animation; Zustand for state; WebSocket for live updates. English with Hindi/Marathi label toggle.

---

## 9. Remedy cards (human-explainable)
Every recommendation shows: **What's wrong** · **Why it matters** (path in plain words) · **What happens if ignored** (physical timeline) · **Action** · **Cost & downtime** · **Risk before → after** · **Reversible?** · **Standards** (CERT-In chapter, CPG goal, IEC conduit, CSF function, ATT&CK technique) · **Confidence range**.

Example (all numbers computed, never invented):
> **Street-light gateway GW_LIGHT_12 can reach Pump controller PLC_WATER_01** through an open Modbus link left from commissioning. The controller has CVE-2026-4011 (CVSS 9.8, very likely to be used). If hit at 06:00, the pump stops and Hospital X loses pressure in about 6 hours. **Do:** block the link (no downtime) and allow only approved Modbus writes. **Result:** Service-at-Risk 41k → 3k household-hours. **Maps to:** CERT-In IoT security & vulnerability management; IEC 62443 conduit restriction.

A language model may only reword these structured fields into a short operating procedure; it has no tools, no network and no access to anything else (§10).

---

## 10. Security of ATHENA itself (so we can say it is hard to attack)

> Honest claim for the judge: **"Secure by design, tested, and fails safe."** Never "unhackable".

### 10.1 Security principles we follow (name them to the judge)
| Principle | How ATHENA applies it |
|---|---|
| **Least privilege** | Each module runs with only what it needs; operator, analyst, executive roles differ; the engine cannot change the live plant without a signed, approved action |
| **Fail-safe defaults** | Default autonomy is "suggest"; unknown = deny; if ATHENA crashes, the plant keeps running (it is *beside* control, not in the control path) |
| **Complete mediation** | Every request checked every time (authentication + role + action); no cached "already approved" |
| **Zero trust** | No internal service trusted by location; service-to-service **mutual TLS**; short-lived tokens |
| **Separation of duty** | High-impact actions (isolate a cluster, firmware change) need **two-person approval** unless pre-authorised and twin-verified |
| **Defence in depth** | Network rules + auth + input validation + signed data + monitoring; no single point of failure |
| **Economy of mechanism** | Small trusted core: the Safety Check and Playbook Runner are small, tested modules |
| **Open design** | Security doesn't depend on secrecy; algorithms and threat model are documented |
| **Psychological acceptability** | Secure path is the easy path (clear confirmations, undo) so operators don't bypass it |
| **Assume breach (of ourselves)** | We monitor ATHENA with DECOY: it watches its own services and logs |

### 10.2 Concrete controls
- **Authentication:** strong password hashing (Argon2id), **MFA (TOTP)** for operator/analyst roles; session tokens short-lived, rotated, HttpOnly/Secure/SameSite cookies.
- **Authorisation:** role-based + per-action policy check; object-level checks (no access to other zones' assets).
- **Transport:** TLS everywhere; mTLS between services; HSTS.
- **Input safety:** strict schema validation (Pydantic) on every API and every file; size limits; parsers fuzz-tested; no deserialising untrusted pickles/YAML code.
- **Web hardening:** strict **Content-Security-Policy**, no inline scripts, output escaping, CSRF protection, CORS allow-list, rate limiting and lock-out, security headers (X-Frame-Options/Frame-Ancestors, Referrer-Policy).
- **Data integrity:** all offline snapshots **signed (Ed25519)** with version counter (anti-replay); **threat feeds verified** (source pinning, checksum, sanity-check against last known) so a poisoned feed cannot silently change rankings; inventory changes above a threshold require review.
- **Tamper-evident Black Box Log:** each entry includes the hash of the previous one (hash chain); periodic anchors exported; any edit is detectable.
- **Secrets:** no secrets in code; environment/secret store; keys rotated; private keys never in the UI container.
- **Supply chain:** pinned dependencies with hashes, **SBOM for ATHENA itself**, `pip-audit` / `npm audit` in CI, minimal container images, non-root containers, read-only filesystems.
- **LLM safety (if used):** model receives only structured card fields, outputs plain text only, no tool/network access, output checked against allowed vocabulary; guards against prompt-injection from device names/log text (treated as data, escaped).
- **Safe autonomy:** the Healer cannot act outside the twin-verified action list; **kill switch** and "freeze autonomy" button; rate limit on actions (no action storms).
- **Safe simulation:** the attack simulator only edits the simulated graph/physics; it contains no exploit code and cannot reach real systems.
- **Tool-attack defences (from the research list):** fake inventory → provenance + review; fake threat feed → signed/sanity-checked; poisoned learning → anomaly windows excluded from training.

### 10.3 Threat model and testing (what we show)
- **STRIDE table** for ATHENA itself (spoofing, tampering, repudiation, info disclosure, DoS, privilege escalation) with the control that answers each.
- **Tests run before demo:** `bandit` (Python), `semgrep`, `pip-audit`/`npm audit`, **OWASP ZAP** baseline scan against the running UI/API, API fuzzing of the parsers, hash-chain tamper test, role-escalation tests. Report results honestly (including what was found and fixed).
- **Judge-facing "Security" panel:** shows MFA on, TLS on, signed data verified, log chain intact (green tick = hash verified), dependency scan status.

---

## 11. Repository layout
```
decoy/
  city_config/          mumbai.yaml, bengaluru.yaml
  data/                 raw (nvd, epss, kev, osm, attck-ics), generated (assets.json, edges.json), datasheet.md
  engine/
    map_builder/        schema.py, generator.py, uncertain_graph.py
    threat_finder/      cve_match.py, epss_kev.py, sbom.py, ssvc.py
    path_predictor/     attack_graph.py, importance_sampling.py, next_step.py
    impact_simulator/   water_wntr.py, power_pandapower.py, coupling.py, oracle.py, twin.py, cache.py
    fast_guesser/       gnn.py, conformal.py, train.py
    risk_scorer/        sar.py, raw_rrw.py, explain.py
    fix_planner/        candidates.py, lazy_greedy.py, schedule_cpsat.py, voi.py
    watchdog/           protocol_parsers.py, net_model.py, invariants.py, fusion.py, drift.py, online_learn.py
    healer/             ladder.py, cuts.py, ppo_env.py, ppo_train.py, shield.py, decoys.py, playbooks.py
    existing_layers/    log_collector.py, host_adapter.py, rule_generator.py, exposure_scanner.py
    airgap/             sign_verify.py, snapshot_io.py
    blackbox/           hashchain.py
  api/                  FastAPI, auth, RBAC, WebSocket
  ui/                   React app: city3d/, judge_mode/, operator/, analyst/, executive/, security_panel/
  experiments/          targets.md (written first), e01..e14, results/
  security/             threat_model.md (STRIDE), test_reports/
  docs/                 plain-english guide, limitations
  docker-compose.yml
```

**Fixed technology choices (do not re-debate):** Python 3.11; WNTR, pandapower, NetworkX, PyTorch + PyG, scikit-learn, MAPIE/conformal, pgmpy, OR-Tools CP-SAT, Stable-Baselines3 + Gymnasium, SHAP, river (ADWIN), FastAPI, PyNaCl, Argon2; React/TypeScript as in §8.6. MiniNet is not used (Linux-only); routing/segmentation is modelled in the graph twin. DHALSIM/epanetCPA/MulVAL are references only.

---

## 12. Proof — experiments (targets written *before* running)

| ID | Claim | Measure vs |
|---|---|---|
| E1 | Our ranking matches ground truth | Spearman + top-10 overlap vs simulating every device; vs CVSS×importance, EPSS×importance, choke-point count, centrality |
| E2 | Real harm overturns severity | Devices moving >10 places; worked examples |
| E3 | Fix plan is near-best | Gap to exact CP-SAT optimum on reduced city; vs random / CVSS-first |
| E4 | Counting fix downtime matters | Total loss with vs without downtime term |
| E5 | Ask-First finds better plans faster | Plan quality after 1/3/5 answers vs random / most-uncertain |
| E6 | Fast Guesser is trustworthy | Agreement, speed-up, conformal coverage (target ≥ 90%), worst-10% error |
| E7 | Threat layer anticipates exploitation | Rank of CVEs before KEV addition vs CVSS |
| E8 | Ranking is stable | Top-10 overlap when EPSS, hidden facts, attacker skill vary ±20% |
| **E9** | **Healing is surgical** | Service retained & containment time over 200 simulated campaigns: PPO+shield vs greedy vs rule-based vs isolate-everything vs nothing |
| **E10** | **Zero-days handled** | Detection delay and false-alarm rate on attack types held out of training; invariant-only vs network-only vs fused |
| **E11** | **Scales** | 10²→10⁵ nodes: build time, sampling throughput, memory, latency; Bengaluru generated from config alone |
| E12 | Safety shield works | % unsafe actions blocked; service with vs without shield |
| E13 | Decoys help | Time-to-detection and attacker progress with vs without decoys |
| E14 | Platform security | Scan/fuzz/tamper-test results (§10.3) |

Report misses honestly; a miss with a reason is stronger than a hidden one.

---

## 13. Team split (4 people)
| Role | Owns |
|---|---|
| **Physics & data lead** | Map Builder, Impact Simulator, Twin, real-data ingest, city configs |
| **Threat & prediction lead** | Threat Finder, Path Predictor, Fast Guesser, Risk Scorer, forecasting |
| **Defence lead** | Watchdog, Healer (PPO, shield, decoys), Fix Planner, Ask-First, security hardening |
| **Experience lead** | UI/3D, Judge Mode, colour system, security panel, demo, results slides |

Interfaces between modules are agreed on day 1 (JSON schemas in §7) so work runs in parallel.

---

## 14. Build order (vertical slice first, then deepen)
| Phase | Hours | Outcome |
|---|---|---|
| 0 | 0–4 | Repo, installs verified, schemas frozen, city config loader |
| 1 | 4–14 | Mumbai generator + real feeds + Impact Simulator → first tank-drain curve → first SaR |
| 2 | 10–24 | Path Predictor (+importance sampling), Risk Scorer, CVSS baseline → first rank reversal |
| 3 | 14–30 | UI vertical slice: 3D city, Purdue stack, risk terrain, comet paths (parallel with 2) |
| 4 | 24–36 | Fix Planner (greedy + CP-SAT), Ask-First, Watchdog (both cores) |
| 5 | 30–42 | Fast Guesser + conformal; Healer (PPO train + shield), Decoys; Judge Mode |
| 6 | 36–46 | Security hardening + scans; experiments E1–E14; results slide |
| 7 | 46–48 | Freeze, rehearse twice, record a backup video |

---

## 15. No pre-planned fallbacks — the system solves its own problems instead
v3 removes the list of reductions. Every required component stays required. Where something could go wrong, **the system itself detects it and handles it** (see §21). The only schedule tool is the vertical-slice order in §14, so the demo is runnable at every stage; if a phase slips, the owner and lead re-plan hours — not features.

---

## 16. Honest limits (say these on a slide)
- Everything is validated in simulation; no public dataset links devices + bugs + links + outcomes.
- Mumbai names/geometry are real where tagged REAL; inventory, IPs, firmware and links are synthetic.
- EPSS is trained mostly on office-IT attacks; KEV overrides and E8 mitigate.
- Worst-realistic-action assumption suits skilled attackers and overstates casual ones.
- The RL policy is trained in simulation; live use would need staged rollout (suggest-only → low-risk auto).
- Product and patent comparisons come from public documents; patent notes are not legal advice.

## 17. Pre-pitch checklist
- [ ] Verify every Mumbai fact tagged REAL; retag as SYNTHETIC if unsure
- [ ] Verify Oct 2020 outage wording before quoting
- [ ] Read the full CERT-In smart-city guideline; map each fix type to a chapter
- [ ] Research NCIIPC guidance (not yet covered)
- [ ] Check current OT features of Siemens, Schneider, Palo Alto, Fortinet before comparing
- [ ] WNTR + pandapower + PyG install cleanly on the demo laptop (Windows)
- [ ] Run contrast checks on the colour system; test colour-blind simulation
- [ ] Run all security scans and keep the reports
- [ ] Ask organisers whether simulation-based validation counts as "historical or simulated data"

## 18. Instructions to Claude when executing
1. Follow §14; each phase must run end-to-end before the next begins.
2. Seed all generators; write `data/datasheet.md` labelling REAL/DERIVED/SYNTHETIC.
3. Every number in the UI traces to an engine output; no hard-coded values.
4. Write `experiments/targets.md` before running any experiment.
5. Use the plain names from §1 in UI text, code module names and comments.
6. Apply §10 from the first commit (auth, validation, signed data, hash-chained log), not at the end.
7. When unsure, choose: simpler to explain, measurable, least disruptive to the running city.
8. Follow §19 (CERT-In) and §20 (data) exactly; build §21 self-handling mechanisms as part of each module, not afterwards.
9. Build the UI to §22 and keep [WORKFLOW.md](WORKFLOW.md) in sync: every feature has a "how to show it" entry.

---

## 19. CERT-In compliance — built in, not bolted on

**Sources used (verified in a web search on 2026-10-31):**
- *CERT-In & Kaspersky, "Cyber Security Guidelines for Smart City Infrastructure" (2025)* — themes: IoT security, vulnerability management, supply-chain security with SBOM, penetration testing, monitoring, incident response. **The full chapter list was not retrievable in my search; read the PDF and fill the `chapter` column in `docs/certin_map.csv` before the pitch.** Do not print chapter numbers in the UI until verified.
- *CERT-In Directions of 28 April 2022 (IT Act s.70B(6), effective 27 June 2022)* — report listed incidents to CERT-In **within 6 hours**; keep ICT-system logs **180 days rolling, within Indian jurisdiction**; synchronise system clocks to **NIC or NPL NTP** sources. (Annexure I lists reportable incident types, including attacks on critical infrastructure/SCADA — copy the exact list from the primary text.)
- *CERT-In 20-smart-city study (Feb 2025)* — most common weaknesses: unauthorised remote connections, badly configured SNMP. Used to seed misconfiguration rates.

### 19.1 Compliance features (each is an engine function with a UI element)
| Requirement | ATHENA feature | How the system does it itself |
|---|---|---|
| Report within 6 h | **6-hour Clock** on every confirmed incident, with a countdown ring | Incident created → clock starts at detection time → report package auto-assembled (what, when, affected assets, techniques, actions taken, contact fields) → operator one-click *Review & Export*; escalates visibly at 4 h and 5 h |
| 180-day logs in India | **Log Vault**: all events stored in an India-local store with 180-day rolling retention | Retention enforced by a scheduled job; deletion only after 180 d; a "Vault health" tile shows days retained and chain integrity; deployment docs state in-India hosting |
| NTP time sync | **Time Guard** | Every ingest compares source timestamps to the reference clock; drift beyond threshold raises an alert and flags affected events as "time-uncertain" (so correlation doesn't silently mislead) |
| Vulnerability management | Threat Finder + Fix Planner | Findings carry SSVC label and plan date; overdue items rise automatically |
| Supply-chain / SBOM | **SBOM Reader** | Component CVEs attached to devices; vendor and shared-account nodes exist in the graph |
| Penetration / testing | **Red-Team Mode** (assume-breach) with a saved test report | Simulated attack campaigns exportable as test evidence |
| IoT security | Protocol Watcher + misconfiguration rules | Flags default creds, plaintext Modbus/MQTT, open SNMP, unauthorised remote access (the CERT-In top findings) |
| Monitoring & incident response | Watchdog + Healer + Playbook Runner | Every response is a logged, reversible playbook |
| Point of contact / roles | Role profile includes a named CERT-In contact | Pre-filled into report package |

### 19.2 Compliance dashboard (Executive view)
A "CERT-In Readiness" panel: open incidents with 6-hour rings; log retention days; time-sync status; SBOM coverage %; unresolved IoT misconfigurations; last red-team run. Every tile is clickable to the evidence. A **Compliance map** (`docs/certin_map.csv`) links every remedy type → guideline theme → chapter (once verified) → CISA CPG 2.0 goal → NIST CSF function.

---

## 20. Proper data — real wherever it exists

### 20.1 Data sources and how each is used
| Data | Source | Used for | Freshness rule |
|---|---|---|---|
| CVE records, product names | **NVD API 2.0** (CPE matching) | Bugs per device version | Daily sync; stale > 48 h → badge on affected scores |
| Exploit probability | **FIRST EPSS** daily file | Step success probabilities | Daily; ranking records the EPSS date used |
| Known-exploited list | **CISA KEV** JSON | Near-certain exploitability; back-test target | Daily |
| **Real industrial bugs** | **CISA ICS advisories** (vendor-specific: Siemens, Schneider, ABB, etc.) | Attach *real* OT CVEs to the synthetic devices' real product names — replaces invented IDs | Weekly |
| Indian advisories | **CERT-In vulnerability notes / advisories** | Indian-context bugs and mitigations, linked into Threat Finder | Weekly |
| Attack techniques | **MITRE ATT&CK for ICS** (STIX) | Labels on every attack step | Version-pinned |
| City geometry | **OpenStreetMap** via Overpass (Mumbai buildings, hospitals, substations, pumping stations, water towers, roads) | 3D city, real locations of service nodes | Snapshot, dated |
| Population / demand | **Census ward-level population** and BMC ward boundaries | Households per zone → SaR units | Version-pinned |
| Water supply norms | BMC/Indian per-capita supply norms (verify figures) | Demand in WNTR | Documented constants |
| Water model | **WNTR C-Town** (BATADAL) | Hydraulics | Pinned |
| Process attacks | **BATADAL, HAI**, (SWaT/WADI by request) | Attack types and physics-invariant mining/validation | Pinned |
| Power model | pandapower benchmark MV feeder | Electrical flows | Pinned |
| Misconfig rates | CERT-In 20-city findings | Synthetic misconfig frequencies | Documented |

### 20.2 Rules
1. **Real first:** a real product name gets *real* CVEs/EPSS/KEV; only inventory, IPs, links, credentials and vendor access are synthetic.
2. **Provenance on every record:** `REAL` (fetched, with source + date) · `DERIVED` (computed from real, with formula) · `SYNTHETIC` (generated, with seed). Shown in the UI; summarised in `data/datasheet.md`.
3. **Ingest pipeline (internal, automatic):** fetch → checksum → schema-validate → sanity-check against previous snapshot (sudden 10× change = quarantine and alert) → store with version → trigger incremental rescoring.
4. **Time-travel:** the data store keeps dated snapshots, so any past ranking can be reproduced exactly (needed for E7 back-test and for judges' "why did it change?").
5. **Ethics/safety:** only public data; no scanning of real systems; Mumbai names are used as scenario context, not claims about real vulnerabilities (say so on a slide).

---

## 21. Problems the system solves by itself (replaces fallbacks)
| Problem | Internal solution (automatic) |
|---|---|
| Missing/unknown devices or links | Uncertain graph + **Ask-First**; plan is valid under uncertainty and tells you what to check |
| Simulator too slow | Result cache, incremental recompute, common random numbers, **Fast Guesser** screens, full simulator only where conformal interval is wide |
| Fast Guesser wrong on rare cases | **Conformal escalation**: wide interval or tail case → automatically re-run in the full simulator |
| Normal behaviour drifts | **ADWIN** drift detection → re-learn on verified-normal data |
| Attacker tries to "teach" the model | Windows near alerts are excluded from training |
| Too many noisy alerts | Bayesian fusion of both Watchdog cores; **alert grouping** by incident/path; duplicates merged |
| Unsafe automatic action | **Safety Check** simulates first; blocked if a hard limit would break |
| Action didn't work | **Closed-loop verification**: after an action, Watchdog re-checks; if the attack path remains or service drops, the action is automatically **rolled back** and the next-best is tried |
| Two actions conflict | **Action arbiter** with locks and priority; one change per zone at a time |
| Action storm | Rate limiter and cool-down per asset |
| No operator available | **Autonomy dial**: low-risk, twin-verified actions auto-run; others queue with a clear summary and a timer |
| Poisoned or stale feed | Signature/checksum, sanity-check vs previous snapshot, **staleness badges**, scores record the data date |
| Clock drift | **Time Guard** flags affected events as time-uncertain |
| Missed 6-hour deadline | **6-hour Clock** escalates at 4 h / 5 h; report pre-assembled |
| Model or service crash | Health supervisor restarts modules; ATHENA sits outside the plant control path, so the plant is unaffected; Black Box records the gap |
| UI heavy on slow laptop | **Adaptive quality**: UI measures frame time and automatically lowers effects (bloom, particle count, LOD distance) while keeping all information visible |
| Telemetry gaps | State estimator fills gaps from physics; marks values "estimated" |
| Inventory changes mid-run | Incremental graph diff; only affected paths/sims recomputed |

---

## 22. UI and 3D — detailed specification

### 22.1 Screen map
1. **City (home)** — full-screen 3D twin, thin top bar (SaR, incidents, 6-hour clock, autonomy dial), left layer panel, right context drawer, bottom time scrubber.
2. **Stack** — exploded Purdue layers view.
3. **Path** — focused attack-path view (camera flies to the route).
4. **Fix** — what-if cards + maintenance Gantt.
5. **Ask** — Ask-First questions.
6. **Defend** — live incident / surgery view.
7. **Proof** — experiment results, compare charts.
8. **Compliance & Security** — CERT-In readiness, platform security status.
9. **Judge Mode** — overlays captions on the above.

### 22.2 3D scene design
- **Scene layers (toggle independently):** ground & roads; buildings (extruded OSM footprints, translucent so utilities show through); water network; power network; hospitals; smart-city IoT; control/IT "sky layers" floating above their physical sites; risk terrain; attack paths; decoys; quarantine zones.
- **Camera presets (one key each):** *Overview* (isometric), *Ward focus* (zoom to a ward), *Stack* (side view of Purdue slabs), *Follow path* (travels along the attack), *Hospital view*.
- **Visual language:**
  - Node shape = type (pump = cylinder with rotor ring, tank = glass cylinder with liquid, substation = box with pylons, PLC = small cabinet, gateway = antenna tower, hospital = cross-marked beacon, decoy = same model with violet shimmer).
  - Node glow colour = risk ramp; glow size = households served; pulse ring = active anomaly.
  - Edges: solid = known; dashed = uncertain; thickness = traffic or probability; animated particles = live flow.
- **Shaders/effects (each earns its place):** liquid level shader (tank fill, real data driven), flow shader (pipe particles, speed = flow rate, dim = low pressure), risk terrain height-field (smoothed from node risk), ripple dome (blast radius), hatch shader for quarantine, shimmer shader for decoys, selective bloom only on the "hot" element, depth fog for focus.
- **Focus + context:** selecting an object dims everything not related (paths, dependants, upstream) so the story stands out; hover = tooltip in plain words; click = drawer.
- **Performance budget:** ≥ 55 fps at 10,000 nodes: GPU instancing for nodes and edges, level-of-detail by distance, GPU colour-id picking, simulation and layout in web workers, adaptive quality scaler (§21). Must hold on a normal laptop.
- **Time machine:** scrubber replays any incident; **ghost split** shows "no action" vs "ATHENA" side by side with the same camera.
- **Accessibility:** colour + shape + pattern; labels toggle; keyboard navigation; reduced-motion mode that replaces animations with static arrows; screen-reader summary of the current state ("3 devices at high risk, 1 incident, 6-hour clock 04:12 left").

### 22.3 Unique components by task (extends §8.4)
| Task | Component |
|---|---|
| Notice danger | **Heartbeat strip**: one line across the top, flat when calm, spikes when SaR rises; click a spike to jump to that moment |
| Understand a device fast | **Device passport** drawer: photo-style 3D close-up, one-sentence verdict, 3 numbers (harm if hacked, harm avoided if protected, urgency), tabs (Why / Paths / Fixes / History) |
| Trust a number | **Confidence ribbon** under every figure (range + data date + REAL/SYNTHETIC badge) |
| Compare fixes | **Fix cards** with ghost-bar before/after, cost, downtime, undo icon |
| Approve safely | **Press-and-hold confirm** for high-impact actions, with blast-radius preview ripple on the map |
| See what's learnt | **Normal-behaviour envelope** chart that visibly adapts; drift markers |
| Follow an incident | **Incident timeline** with stages (Detected → Predicted route → Decoy touched → Cut made → Verified), each clickable, 6-hour ring beside it |
| Understand the algorithm | **"How did you know?" panel**: shows inputs used, path, and top 3 reasons, no jargon |
| Teach the judge | **Judge Mode captions** + "Explain this" on every element |

### 22.4 HCI checklist for every screen (review before demo)
Norman: visible state? feedback < 100 ms? signifiers clear? mapping natural? constraints with reasons? undo available? Shneiderman: overview → zoom → details? consistent? closure? user in control? ≤ 3 primary actions? Plain words? Units everywhere? Colour not the only cue?

---

## 23. CERT-In Smart City Guidelines — verified chapter map (read from the supplied PDF)
The chapter list is now confirmed from the PDF's contents page. **Chapter numbers may be shown in the UI.** (Ch. = chapter of *Cyber Security Guidelines for Smart City Infrastructure*, CERT-In with Kaspersky, 2025.)

| ATHENA feature | Guideline chapter / section | What the guideline says that we implement |
|---|---|---|
| Surgical isolation, micro-segmentation, default-deny between zones | **4.4 Network segmentation and isolation**; **5 Network Security** | "Communication within different VLANs should be disabled by default and allowed on need basis"; micro-segmentation to limit lateral movement; air gap / data diode for ultra-sensitive operations |
| Zero-trust, least privilege, threat modelling | **4.1 Security by design**; **6.5 IoT & device authentication** | Zero Trust Architecture, threat modelling, multi-layered defence |
| Automated failover, real-time anomaly detection + automated incident response, cyber-physical resilience | **4.2 Resilience and continuity** | Exactly the Watchdog + Healer + Safety Check loop |
| Scalable, modular, SDN-style policy | **4.2 Scalability** | Modular architecture, AI-driven analytics, vendor-neutral |
| MFA (TOTP), strong passwords, lockout, RBAC, mTLS between services | **6 IAM (6.1–6.7)** | MFA incl. TOTP; 12+ char passwords; lockout after failed attempts; mTLS; RBAC; MFA for critical operations |
| Encryption, retention limits, privacy by design | **7 Data security and privacy** | AES at rest, TLS in transit, data minimisation, DPDP Act |
| Central logging & monitoring | **8.5 Continuous monitoring and logging** | All logs to a central server; maintained per CERT-In directions of 28 Apr 2022 |
| Legacy systems as weak links | **8.1 Legacy technologies** | Flag legacy firmware as a risk multiplier |
| IoT & ICS risks (unauthorised access, control-logic manipulation of PLCs for pumps/valves, ransomware) | **9.1, 9.2** | Attack library of the simulator is built from these |
| Protocol best practices (Modbus, DNP3, IEC 61850, MQTT, SNMP, OPC UA, BACnet…) | **9.3 + Annexure I** | Protocol Watcher flags plaintext Modbus/MQTT etc. and recommends the Annexure I practice (e.g. "Use Modbus TCP with TLS; isolate devices in secure zones") |
| Device-specific threats & practices (traffic lights, water quality sensors, smart meters, smart grids, EV chargers, CCTV, street lighting…) | **9.4 + Annexure II** | Asset library types and their threat/remedy text come from Annexure II |
| AI/ML security: input sanitisation, model validation, adversarial robustness, real-time anomaly monitoring of the AI itself | **10 AI/ML security** | Fast Guesser conformal checks, training-data quarantine, sensor-spoof detection |
| **Explainability; final authority with human operators; accountability** | **10.1 AI ethical considerations** | Every card explains why; **autonomy dial defaults to human approval for high-impact actions**; Black Box Log assigns responsibility |
| DR/BCP, redundancy, drills | **11** | Time-to-survive vs time-to-repair, manual fallback, scheduled drills in Red-Team Mode |
| 6-hour reporting, point of contact, 180-day India logs | **12 Compliance and legal** | 6-hour Clock, contact fields (incident@cert-in.org.in, 1800-11-4949 as shown in guideline), Log Vault |
| API security (BOLA, broken auth, BFLA, resource consumption, SSRF, misconfig, inventory, unsafe consumption; rate limit, gateway, IP allow-list, logging) | **13** | ATHENA's own API is built and tested against this list |
| Incident response phases and playbooks (preparation, detection, containment, eradication, recovery, post-incident review; Who/What/When/Where/How) | **15 Crisis management & IR** | Playbook cards use exactly these phases and fields; severity levels and SLAs shown |
| SIEM/SOAR, CERT-In feeds (CMTX, CSK, NCCC) | **16** | Log Collector (SIEM-style), Playbook Runner (SOAR-style); feed adapters named in the UI |
| SBOM, vendor access control | **17** | SBOM Reader; vendor VPN as an edge with review |
| Pen testing & vulnerability management | **18** | Red-Team Mode and scheduled scans |
| Audits: internal ≥ every 6 months, third-party ≥ yearly | **19** | Compliance panel tracks "last internal audit / next due" |
| **Local threat patterns** | **2.3** (analysis of 20 smart cities, 2024) | **Western/Central/Northern India: trojans (avalanche-andromeda, gamarue); most prevalent weakness = remote connections allowed to unauthorised computers.** **Southern India: botnets (Socks5Systemz); most prevalent weakness = SNMP misconfiguration.** → Mumbai config seeds the first pattern, Bengaluru config the second |
| MoHUA advisories 22, 24, 25 | **3** | Cited in the compliance map |

*Correction to earlier text:* the CERT-In 20-city analysis is for the year **2024** (not "Feb 2025").

---

## 24. Always-on runtime (dynamic, self-running, attackable on demand)
- The backend runs a **continuous simulation clock** (1 real second = 1 simulated minute by default; speed adjustable). Demand follows a daily curve, tanks fill and drain, power flows, telemetry streams to the UI over WebSocket.
- **Autopilot Adversary** (toggle, default ON in demo): a background red-team agent randomly launches attack campaigns (entry point chosen from exposed nodes, techniques sampled by EPSS/KEV probabilities). ATHENA must detect, predict, and heal without any human click.
- **Manual attack console** (always available): choose entry point, technique, target actuator, intensity; or click "Zero-day", "Telemetry spoof", "Breaker wear attack", "Vendor-VPN breach".
- **Autonomy dial:** Observe / Suggest / Auto-low-risk / Auto-all. In Suggest, incidents queue for human approval (CERT-In 10.1 human authority).
- **Reset / replay** buttons; every run is seeded and logged so it can be replayed.
- All state changes go through the **Black Box Log** (hash-chained) and the **Log Vault**.

## 25. Build plan for an 18-hour hackathon (supersedes §14)
| Hours | Outcome |
|---|---|
| 0–3 | Repo, installs, schemas, Mumbai-ward generator, real-data snapshot (KEV/EPSS/NVD) |
| 3–7 | Impact Simulator (water + power), attack graph + sampler, SaR/RAW/RRW, CVSS baseline → first rank reversal |
| 7–10 | Watchdog (physics invariants + behaviour model), Healer (ladder + Safety Check + decoys), live runtime loop + attack console |
| 10–14 | 3D UI: city, stack, comet paths, flow/tank shaders, passport drawer, fix cards, Ask-First, Defend view |
| 14–16 | Compliance + Security panels, Judge Mode, experiments E1–E4, E9, E10, E12 |
| 16–18 | Freeze, rehearse, record backup video |
**Implementation honesty notes (differences from earlier sections, decided at build time):** the ward water model is a custom small network built in WNTR (C-Town remains a reference); the Fast Guesser is a gradient-boosted model with split-conformal intervals over actuator-set features (a graph neural network is a stretch goal); PPO training is replaced at first by a search-based policy over the same action space evaluated in the twin (the PPO environment is kept for later).

## 26. Numbers that cannot be sourced
Where a real figure is unavailable (device counts, patch downtimes, per-capita water norms, costs), the system uses **clearly labelled assumptions** in `data/assumptions.yaml` with a stated rationale and range; they carry `SYNTHETIC` provenance and are shown in the UI. Sensitivity (E8) varies them ±20%.

---

## 27. What was actually built (31 Oct 2026) — honest status

### Built and running
Map Builder (28 devices, 62 links incl. 8 hidden/uncertain, real OSM locations) · Impact Simulator (WNTR/EPANET + pandapower, exact table of 2,040 attack outcomes) · Threat Finder (15 real CVEs with NVD CVSS, FIRST EPSS, CISA KEV) · Path Predictor (probabilistic attack graph, common-random-number worlds, next-hop forecast) · Risk Scorer (SaR95/99, RAW/RRW, CVSS baseline, rank reversals) · Fast Guesser (gradient boosting + split-conformal intervals) · Fix Planner (CELF lazy-greedy, downtime-aware, OR-Tools CP-SAT maintenance scheduling) · Ask-First (value of information) · Watchdog (autoencoder + rate/novelty + 8 physics invariants + learned fusion + online learning on verified-normal windows) · Healer (response ladder, multi-step containment search, Safety Check evaluated together with outages in progress, isolate-everything comparison) · Decoys · live twin + two counterfactual twins · autopilot and manual adversary · Black Box Log, Log Vault, Time Guard, 6-hour Clock, CERT-In report package · secure API (Argon2id, TOTP, RBAC, rate limit, validation, headers, two-person rule, signed air-gap snapshots) · 3D UI (real OSM buildings, flow particles, liquid tanks, exploded Purdue layers, comet attack paths, risk terrain, device passport, Judge Mode).

### Deviations from earlier sections (decided while building)
| Planned | Built | Why |
|---|---|---|
| WNTR **C-Town** network | custom 2-branch ward network in WNTR with real-scale demand | C-Town is not bundled with WNTR; a small ward model keeps simulations at ~0.1 s |
| Graph neural network surrogate | gradient-boosted model + split-conformal intervals | no PyG install risk; same escalate-when-unsure logic |
| PPO healer in a Gymnasium environment | **both**: search-based Healer (default) and a PPO policy trained in a purpose-built environment (§28) | the PPO policy does not beat the search Healer (E15), so search stays the default |
| Cross-entropy importance sampling | plain Monte-Carlo with common random numbers (3,000 worlds; ±exact at 20,000 per E1) | tail is not rare enough in this ward to need it |
| Bengaluru config, Hindi/Marathi, light theme | **not built** | time |
| mTLS between services, ZAP scan | design-level only (single process); bandit + pip-audit + 31 custom tests run instead | time |
| CP-SAT only | CELF for selection, CP-SAT for scheduling | selection is a knapsack-like greedy, scheduling is a constraint problem |

### Results (auto-generated from `data/experiments.json`; targets: `experiments/targets.md`)
<!-- RESULTS:START -->
| ID | Claim | Target met? | Headline numbers |
|---|---|---|---|
| E1 | Ranking matches brute-force ground truth (20,000 simulated attacks) | ✔ yes | Spearman 0.993 / top-10 overlap 10/10 vs CVSS×importance 0.454, EPSS×importance 0.419, betweenness 0.433 |
| E2 | Real harm overturns severity | ✔ yes | 5 devices move >10 places (e.g. KEM hospital building-management system: #4→#19; Operator HMI / programming station: #11→#25; Feeder-F3 breaker RTU (Parel substation): #8→#22) |
| E3 | Greedy plan is near the exhaustive optimum | ✔ yes | greedy 3.7k = exhaustive 3.7k; random 9.7k, CVSS-first 13.4k, no fixes 20.7k |
| E4 | Counting the fix's own outage lowers total harm | ✔ yes | total harm incl. patch outages: downtime-aware 1.7k vs ignoring downtime 2.1k |
| E5 | The highest-value question first yields a better plan | ✘ **missed** | k=1: VoI 5.5k / uncertain-first 5.3k / random 5.3k; k=3: VoI 4.8k / uncertain-first 5.5k / random 5.2k; k=5: VoI 4.8k / uncertain-first 5.5k / random 5.2k |
| E6 | Fast Guesser is accurate, calibrated and fast | ✔ yes | coverage 0.928 (target 0.90), Spearman 0.978, 19641× faster than the exact simulation, worst-10% escalated 100% |
| E7 | Threat layer anticipates exploitation (back-test, 30 days before KEV listing) | ✘ **missed** | 40% of 40 later-KEV CVEs had EPSS ≥ 0.1 thirty days before listing (median percentile 0.541) |
| E8 | Ranking is stable under +-20% assumption changes | ✔ yes | worst top-10 overlap 10/10 over 8 perturbations |
| E9 | Healing is surgical: less service lost than no response or isolate-everything, with far fewer devices cut off | ✔ yes | mean service loss: ATHENA 2.5k vs no response 21.7k vs isolate-everything 44.1k; devices cut 0.2 vs 27; physical effect reached 25.0% vs 58.8%; detected 60.0% (median 32.0 min) |
| E10 | Unseen attack types are caught (trained on standard/insider only; tested on zero-day, wear, spoof) | ✔ yes | fused median detection delay 10–20 min on held-out attack types; false-alarm minutes over 3 normal days: 0 |
| E11 | The reachability engine scales | ✔ yes | 100 nodes: 0.01 s; 1,000 nodes: 0.31 s; 10,000 nodes: 4.62 s per 500 attack worlds |
| E12 | Safety Check blocks unsafe actions | ✔ yes | 16 candidate actions blocked in scenarios; 0 scenario(s) where the response left hospitals worse off; isolate-everything blocked at 17/24 start hours |
| E13 | Decoys reduce attacker progress | ✘ **missed** | hops with policy-chosen decoys 3.26 vs without 3.26 (policy picks a decoy in 4.0% of runs); forced decoys: 3.72 hops, physical effect 76.0% |
| E15 | PPO responder handles held-out zero-day products better than the search Healer and no response | ✘ **missed** | No response 14748 (contained 52%, devices cut 0.0); Isolate everything 11987 (contained 97%, devices cut 19.8); Search Healer 1819 (contained 94%, devices cut 1.0); PPO responder 4610 (contained 88%, devices cut 1.3) on 300 zero-days for held-out products |
| E16 | The zero-day library speeds up the second encounter | ✔ yes | first encounter 2717 vs repeat 2419; family rule learned in 10% of first encounters |
| E14 | Platform security | ✔ yes | 37/37 automated security tests passed · bandit: 0 high / 1 medium / 0 low · pip-audit: 1 packages with known CVEs |
<!-- RESULTS:END -->

### Findings worth saying out loud
* **Severity ≠ risk is measured, not asserted:** against 20,000-attack ground truth, CVSS×importance correlates 0.45 with true harm; our ranking 0.99.
* **Decoys did NOT help in this build (E13 missed):** when the Healer is free to choose it picks one in ~4% of runs, and when a decoy is forced as the first step the attacker reaches a physical effect more often (76%) because the decoy displaces real containment. Decoys stay in the product as an optional, clearly-labelled deception layer; the evidence supports surgical isolation and virtual patching instead.
* **Physics-only detection is slow for a plain pump stop (~2 h)** because the stop only contradicts the controller's own logic once the tank falls below its start level; network evidence usually catches the intrusion earlier, and spoofed readings are caught in ~10–40 min.
* **The cost of "isolate everything" rests on an assumption** (PLCs revert to a 50% duty schedule, 18 h); it is listed in `assumptions.py` and the comparison also reports devices cut off, which does not depend on it.
* **Two more misses are reported as they came out:** E5 (the top-ranked question was not the best single question at k=1, though from k=3 VoI matches full information while random and most-uncertain-first do not) and E7 (only 40% of 40 later-KEV CVEs had EPSS ≥ 0.1 thirty days before listing, below the 50% target).
* **A PPO-trained zero-day responder exists (§28)** but does not beat the model-based Healer (E15 missed); it beats no-response and isolate-everything.
* **Only 8 attacker actions exist**, so the exact outcome table is complete; the Fast Guesser matters for larger cities (not demonstrated here).


---

## 28. Zero-day ingestion, handling and the PPO responder (built 31 Oct 2026)

### What a "zero-day" is in this system
An exploit for a **product** that no CVE, EPSS score or signature covers (`backend/decoy/zeroday.py`). The **Zero-Day Lab** (UI: *Zero-day*, API: `POST /api/zeroday`, or the autopilot) invents one for a chosen or random product, with an exploit class (code execution, authentication bypass, protocol abuse). The defender is **not told the product**. Affected devices fall to it with probability 0.85; a classic virtual patch stops only 30% of attempts (no signature) until a family rule exists.

### Handling pipeline (all automatic)
1. **Detect** — Watchdog (network behaviour + physics laws); no signature needed (E10).
2. **Suspect** — an incident whose compromised devices no known weakness explains is flagged *zero-day suspected*; a **behavioural fingerprint** (protocols, ATT&CK techniques, pace, reach) is extracted.
3. **Capture + analyse** — as soon as evidence includes a device of an unseen product, a sample is captured and analysed (one decision step).
4. **Family rule** — a behavioural rule is deployed to **every device of that product** (zero-day multiplier 0.85 -> 0.15) and stored in the **Zero-Day Library**, so the *next* attack on that product meets the rule already deployed (E16).
5. **Respond** — containment actions chosen by the selected responder (search Healer or PPO policy), each passing the **Safety Check** (action is masked unless hospital limits hold, also together with outages in progress); human approval rules from the autonomy dial still apply.
6. **Verify, recover, learn** — as for any incident; isolation is lifted after verification, rules stay.

### The PPO responder (`backend/decoy/rl.py`, trained by `backend/train_ppo.py`)
* **Environment**: real adversary + live twin; one decision = 10 simulated minutes; 36 decisions per episode; noisy evidence (a hop is observed with probability 0.55; physical effects with realistic delays); 10 h of recovery is simulated at the end so unresolved outages are paid for.
* **Actions (146)**: wait, virtual-patch a device (27), isolate a device (27), close a link (62), rotate credentials (27), send a crew to restore equipment, analyse a sample. **Invalid-action masking** removes illegal moves; the **Safety Check shield** removes unsafe ones.
* **Observation (157)**: observed-compromise, isolated, patched and blocked-link flags per device, attacker-frontier scores, observed physical outages, service state, tanks, hospitals, time of day, library and analysis flags.
* **Reward**: minus service loss, minus operational disruption, small per-isolated-device penalty, +0.6 if the attacker never reaches a physical effect, +0.05 for a deployed family rule (shaping: the rule pays off in *later* encounters, which an episodic learner cannot credit).
* **Algorithm**: PPO with GAE, clipped objective, entropy bonus and invalid-action masking, written in PyTorch (no RL library); 100 iterations x 2,048 steps (205k steps); four seeds trained in parallel, three earlier runs kept for comparison.
* **Generalisation test**: 14 products for training, **6 held out** (D-Link camera, Delta HMI software, Windows 10, Windows 7, TP-Link access point, Zabbix). Model selection used a separate validation set; final numbers use 300 matched test scenarios with paired bootstrap confidence intervals.

### Result (honest)
| Policy (300 zero-days, held-out products) | Mean cost | Median | Contained | Devices cut |
|---|---|---|---|---|
| No response | 14,748 | 0 | 52% | 0.0 |
| Isolate everything | 11,987 | 15,800 | 97% | 19.8 |
| Search Healer | 1,819 | 300 | 94% | 1.0 |
| **PPO responder** | 4,610 | 500 | 88% | 1.3 |

* PPO vs no response: **-10,138** (95% CI -14,563 to -6,350) — significantly better.
* PPO vs isolate-everything: **-7,378** (CI -10,454 to -3,248) — significantly better, with 1.3 instead of 19.8 devices cut off.
* PPO vs the search Healer: **+2,790** (CI -524 to +7,025) — **not better; target E15 missed.** The search Healer uses the full attack model; PPO sees only noisy evidence and mostly waits ("keep watching" in ~78% of decisions), so it contains fewer attacks (88% vs 94%).
* Zero-day library (E16, identical scenarios): first encounter 2,717 -> repeat 2,419 (paired difference -298, CI -719 to -13) — **significant**, though small, because the family rule was learned in only 10% of first encounters (it needs the exploited device to appear in the evidence).
* Seed variance is large: four new training seeds scored 834–1,133 on validation versus 739 for the earlier run that was selected, so a longer or multi-seed search could change the ranking.

### Consequences for the product
* The runtime **defaults to the search Healer**; PPO is selectable (*Zero-day -> Who responds?*: Auto / PPO always / Search). *Auto* gives PPO the incidents that look like zero-days.
* Selling point that holds up: **a learned responder, trained on other products' zero-days, is significantly better than doing nothing or isolating everything on products it has never seen, while cutting 1.3 devices instead of 19.8** — and every action it takes is shielded by the Safety Check. We do **not** claim it beats the model-based Healer.
* Ideas that would likely close the gap: behaviour-cloning warm start from the search Healer, more seeds/steps, multi-action decisions, and richer observations.


---

## 29. Interface v2 and reliability fixes (31 Oct 2026)

### Problems reported and what was found
| Report | Cause found | Fix |
|---|---|---|
| Console `422 Unprocessable Entity` | Login form: the API demands a 6-digit code and a lower-case user name, so a slip (capital letter, spaced code, expired demo code) returned a bare 422 | Client checks before sending, forgives capitals/spaces, demo mode fetches a fresh code at submit; every validation error now returns one plain sentence |
| Heartbeat stuck at 98% (zero-day) | (1) a faked sensor reading (`spoof`) was never switched off, even after the outage ended, so the alarm re-fired hours later; (2) the safe plan waited for a human forever because "Auto (safe steps)" refused crew dispatch; (3) zero-day suspicion rarely fired | spoofs now expire with the outage; crew restore counts as a safe step; **escalation**: if nobody answers for 10 simulated minutes while service is at risk, autonomy applies the safety-checked plan (logged); suspicion now also fires when a protected device falls anyway or when a device a known exploit would rarely reach is compromised |
| Server "suddenly stops" | Could not reproduce a crash in 15,000 ticks of fuzzing (random products, modes, autonomy, responders). Likely causes: the web server waited on the simulation lock inside the event loop, and a Windows console freezes a program when you click in it (QuickEdit) | frames are built in a worker thread, one bad frame no longer ends the stream, the simulation loop cannot die silently, `run.ps1` switches QuickEdit off and **restarts the server automatically**, `/api/health` added |
| Clicks unreliable | picking used the last *hover* result; small devices were hard to hit; camera animation fought the mouse | picks where the finger lifts, invisible larger hit areas, any user input cancels camera animation |

Measured on 24 random zero-day campaigns (autonomy "Auto (safe steps)", search responder): minutes with the heartbeat above 85% fell from **29 to 12** on average, the longest stuck alarm from **236 to 47 min** (the 45-minute crew restore), proposals left waiting at the end from **13 to 0**. The remaining 47 minutes are real: a pump that was switched off stays off until the crew restores it.

### Interface changes
* **Palette**: only the supplied four colours (cream `#FFEAD3`, aqua `#BFE7EA`, apricot `#E89B5B`, terracotta `#D46743`) plus tints/shades of them. Aqua = safe/water, apricot = watch/power, terracotta = attacker/danger. One file: `frontend/src/palette.ts`.
* **Layout**: the map has its own cell and nothing floats over its centre. Left rail = 7 pages (City, Paths, Fix, Defend, Zero-day, Proof, Safety). Right panel = collapsible boxes with one headline value each (progressive disclosure). Heartbeat + service numbers live in the top bar. Automatic pop-ups removed; one small message at a time after your own actions.
* **Every page starts with a one-line answer**: City "Is the ward safe?", Paths "How could a hacker reach water or power?", Fix "What to fix first?", Defend "Watch ATHENA stop an attack", Zero-day "An attack nobody has seen before", Proof "Does it really work?", Safety "CERT-In and our own security".
* **Movement**: drag = turn, right-drag = move, scroll = zoom towards the cursor, **W A S D / arrows = fly forward/back/sideways, Q/E = down/up**, plus an on-map pad (hold to repeat).
* **Attack path**: thick terracotta tube with a dark halo, drawn on top of buildings, numbered stops, name labels, a moving dark comet; everything else fades so the route is unmistakable.
* **Healing animation**: an attacker landing = terracotta ring; a defence working = aqua shield dome, rising beam, sparkles and expanding ring; a cut link shows a ✕; recovery = rings over the hospitals. The Defend page shows a pulsing "healing" badge and an animated 5-step tracker.
* **Risk before / now / after**: three bars on one scale with the percentage drop, on the 99% worst case (the 95% value is 0 after the plan, which reads oddly), plus three chance-of-harm tiles.
* **Lighter**: bloom removed, pixel ratio capped at 1.5, link geometry only recomputed when something moves, interface updates 3x per second, hidden tabs stop drawing and polling.
* **Not built**: light/dark toggle (single light theme), Hindi/Marathi labels.


---

## 30. What-if Lab: audit of the "unique project idea" brief and what was added (31 Oct 2026)

### Audit: what already existed and what was added
| Requirement in the brief | Status before | Now |
|---|---|---|
| Interconnected simulated assets with id, category, sector, function, criticality, firmware, vulnerabilities, CVSS, exposure, weak access, patch status, dependencies, connectivity, event history, risk score, explanation | Mostly present (city.py, passport, risk ranking) | **Exposed per asset** (`GET /api/v2/assets/{id}`: vulnerabilities, links in/out, service dependencies, event history, risk + explanation); sector and function added |
| Network reachability vs service dependency | Links existed; dependencies only as controller -> physical action | **Two separate relations** in the model and in `GET /api/v2/topology` (actual vs documented-only links; operates / monitoring dependencies, cycle-safe) |
| "Simulate Compromise" with explicit preconditions, plausible paths, affected assets, service impact, risk before/after, recommendations | Only probabilistic Monte-Carlo and a client-side "assume breach" | **`lab.simulate_compromise`**: deterministic; a step needs reachability AND (vulnerable service OR weak access OR stolen credential without MFA); failed steps are reported with reasons; plausible / predicted / confirmed are labelled separately |
| Mitigation simulator (MFA, restrict remote access, segmentation, patch, disable exposure, monitoring, vendor permissions, backups/IR) | Fix planner (patch / link / MFA / harden) | **All eight controls**, applied to an in-memory session (never the baseline), ranked by loss avoided per effort, plus minimum-cut options (fewest links or assets that separate attacker from every controller) |
| Five defensive scenarios | Five generic attack modes only | **Five named scenarios**, each with assumptions, initial state, generated event timeline, effects, insights, recommendations, before/during/after risk |
| Risk engine: ML + rules, defined target and horizon, explainable, moderate-CVSS-connected > isolated-critical | SaR via Monte-Carlo; GBM only as a speed-up | **RiskModel**: monotone gradient boosting trained on 260 control configurations x 27 assets, labelled by the Monte-Carlo attack worlds; 15 documented features (incl. best-route chance); counterfactual explanations |
| SQLite | JSON files only | `data/decoy_lab.db`: assets, edges, vulnerabilities, dependencies, events, runs; baseline separate from simulation runs |
| REST API list | Partial | `/api/v2`: assets, asset detail, topology, vulnerabilities, telemetry, model + train, risk, explain, compare, simulate, attack paths, scenarios, mitigations, apply, compare, reset, events, optimize |
| Automated tests incl. edge cases | 37 security tests only | **51 pytest tests** (`python -m pytest backend/tests`) |
| Frontend palette: red critical, amber warning, green healthy | Terracotta / apricot / aqua palette you chose | kept: terracotta = critical, apricot = warning, aqua = healthy |

### Definitions (also returned by `GET /api/v2/model`)
* **Exploit prediction**: EPSS / CISA KEV of the asset's CVE. An input, not an output.
* **Compromise likelihood**: ML propensity that the asset falls within a 30-day horizon. The label is the share of 3,000 simulated attack worlds in which the asset falls (a *synthetic risk propensity*, not a real incident probability). Observed anomaly raises the odds (x (1 + 4a)); monitoring lowers it (x 0.75). Both are stated rules, not learned.
* **Operational impact**: expected service loss (household-hour equivalents, WNTR/EPANET + pandapower oracle) given that the attacker already holds the asset, through links and service dependencies. An isolated asset reaches nothing, so it scores about 0 whatever its CVSS.
* **Overall risk** = likelihood x impact, scaled so the top baseline asset = 100.
* **Features** (14): from data: CVSS, EPSS, KEV, legacy, entry weight; from rules: exploit signal, exposure, hops from the internet, in-degree, weak access, unpatched; controls: MFA, virtual patch, share of inbound links closed. Monotone constraints guarantee that more exposure or weaker access can never lower the score and that a control can never raise it.
* **Held-out quality**: whole control configurations are held out: Spearman 0.91, top-5 overlap 0.74, mean absolute error 0.013 (round 4; before: 0.85 / 0.66 / 0.019).
* **Determinism**: fixed random numbers and fixed seeds; the same scenario and model version give identical output (tested).

### What the lab shows on the real ward
`SCADA_WEB` has CVSS 10 (rank #1 by CVSS) but ranks #9 by risk; `ENG_WS` has CVSS 8.8 (#13 by CVSS) and ranks #1 because compromising it reaches every controller. A critical-CVSS camera that reaches little ranks near the bottom. MFA on the vendor VPN alone does not close every path (the jump host is itself vulnerable); closing the 4 links out of the VPN does.

### Honest limits
* Rules (thresholds EPSS >= 0.05, weak access >= 0.20, monitoring x 0.75, backups x 0.6) are stated assumptions; with them the ward is almost fully connected once a foothold exists, so single-link fixes often show no effect and the minimum-cut options matter.
* The lab keeps a private copy of the threat model taken at start-up; answering "Ask-First" questions later does not change the lab baseline until restart.
* All scenario events are generated; no payloads, credentials or equipment commands exist anywhere.


## 31. UI v3, new pages and fixes (this round)

| Area | What changed | Honest note |
|---|---|---|
| Layout | Side panel is **closed by default** and collapsible; left rail opens a page; full-screen map (`F`); 2D network view beside the 3D map | |
| Map | Green grassy land, trees; one colour per layer; every device wears a pictogram (globe, key, firewall, camera, chip...) | Icons are drawn on a canvas, no image assets |
| Mouse | wheel = zoom, drag = move, right-drag / Shift-drag = turn | |
| Click a device | Floating card beside it (what it is, harm if hacked, priority, **blast radius**, way in, simulate, place decoy, fixes) with a close button | Blast radius uses the same probability weights as the "assume breach" tool |
| Mumbai sites | 14 sites (BARC top priority, IT hubs, factories, hospitals, Marine Drive, Juhu, Gateway, CSMT, airport) on the surrounding land | Locations REAL (approximate) but drawn at their true direction, **not to scale**. What each site relies on is a SYNTHETIC assumption; the water/power physics covers the ward only |
| Predict page | `/api/v2/forecast`: most likely targets, why, best next steps; accuracy shown (Spearman about 0.91, top-5 overlap about 0.74, error about 0.013) | Accuracy is against the simulator on unseen control configurations, not real incidents |
| Scheduler | Replaced the fixed "Sunday" slot. Each restart fix gets the (day, hour) minimising outage cost x weekday demand + waiting cost x urgency (KEV/EPSS); no-restart fixes go first in working hours | Weekday demand factors and the waiting-cost rate are SYNTHETIC parameters (documented in `planner.schedule`) |
| Paths | One most-dangerous route per entry point (before: all routes went through the vendor VPN). Random attacks use flattened entry weights and avoid repeating the last two entries | The vendor VPN remains the single likeliest door (largest entry weight) |
| Insider | New attack that starts on an internal machine (no internet hop) | Detection can be late when the first action looks like an operator command (seen up to about 2 h in simulation) |
| Heartbeat | `watch.shown` fades after the attacker is cut off, with phase and a repair countdown; incidents resolve on the faded level | The raw alarm is still returned as `watch.raw` |
| Stop | Emergency stop halts running attacks, turns automatic attacks off and sets ask-first; Resume restores; Pause / Play for the clock | |
| Fix errors | Applying a fix twice gives HTTP 409 "Already done" (shown calmly) instead of a 404 | |
| How it works / Why us | Animated attack-vs-defence story (known, zero-day, prediction) and an evidence page built from `data/experiments.json` | Misses (E5, E7, E13, E15) are shown on the page |
| Safety | One plain-language page; tamper test, air-gap files, self-healing test, supply-chain and audit boxes removed from the UI (the endpoints still exist) | |
| Launcher | `run.ps1` finds 64-bit Python 3.11-3.13, installs wheels only, verifies the packages, rebuilds a broken `.venv` | numpy 2.4.x has no source build without a C compiler |


## 32. Round 4: aerial-style map, full pages, live defence scoreboard (1 Nov 2026)
| Area | What changed | Honest limit |
|---|---|---|
| Map | Sea in the west, land in the east, pale land; real OpenStreetMap roads and railways (`data/osm_roads.json`, 4,401 ways, served in `/api/geo`); 7,400 buildings in plaster / brick / glass colours with lighter roofs; procedural low blocks around the ward; no locked tiles; Mumbai sites kept on land; Hospitals, Water plants, Power views zoom in | Stylised, not photographic. The coastline is drawn, not surveyed. Roads exist only inside the ward box; roads out to the Mumbai sites are schematic |
| Forecast accuracy | New feature `path_prob` (chance of the best route from the internet, Dijkstra on step chances), deeper trees, 260 set-ups. Held-out Spearman 0.852 -> 0.911, top-5 overlap 0.66 -> 0.74, error 0.0188 -> 0.0134 | Still measured against the simulator, not real incidents |
| Paths | "What it would do" for the selected device (or last device of the route): people without service, hours, rupees (`/api/v2/impact`); "already hacked" box removed | People = homes x 4.5; Rs 70 per home-hour is an assumption |
| Heartbeat | Every action (fix, decoy, attack, stop, plan approval, simulation) leaves a mark on the heartbeat line; the top bar shows "worst case before -> after" | The raw heartbeat is still the attack probability; fixes change risk, not that probability |
| Selected device | A strip at the top of every side page shows the chosen device and page-specific facts | |
| What-if | Spread replay on the map step by step with a climbing, then falling, risk heartbeat; proof tiles (model's top-5 vs what fell, reach before/after, risk removed); "Before and after" box commented out | The replay heartbeat weights steps by closeness to equipment; it is an index, not the live probability |
| Defend | "Attack running" state before the alarm; numbered attack steps, what ATHENA did, and a scoreboard worked out from the live run (time to notice, time to cut, devices taken/cut, homes and hospitals served, home-hours and rupees saved, vs no response and vs cut everything); Latest events removed | |
| Zero-day | Who responds removed; remedial steps, effectiveness scoreboard, what the model learned | |
| Proof / Safety | Severity-vs-harm ranks with arrows and bars; Safety as gauges, dots and bars | |
| How it works / Why us | Full-page (no map); heartbeat reacts to the story; 14 algorithms with plain words, reason and rules in dropdowns; Q&A and misses boxes removed | |
