# ATHENA — Workflow Guide
**How every feature works, and exactly how to show it.** Companion to [PLAN.md](PLAN.md). Written for the team and for explaining to judges.

---

## Quick start for the demo
1. `.\run.ps1` → open http://127.0.0.1:8000 (boot ≈ 10 s, risk analytics ready after ≈ 30 s).
2. On the login page click **admin · admin** (it fills the password and the live TOTP code, because `DECOY_DEMO=1`) → **Sign in securely**.
3. Press **▶ Judge Mode** (9 guided steps, auto-advancing every 22 s; *Skip tour* any time).
4. Keys: `1` overview · `2` ward · `3` layers · `4` path · `5` hospital · `X` decoys · `R` risk terrain · `L` links · `J` tour. Click any object in 3D for its passport.
5. The city keeps running by itself: the **Autopilot adversary** attacks every ~2–4 simulated hours. Use **Defend → Attack console** to attack on demand (modes: standard, zero-day, spoof, wear, insider).
6. Roles: `executive` reads · `analyst` also attacks/what-ifs · `operator` also approves and applies fixes · `admin` also enables full autonomy, resets, tamper and chaos demos.

**What you will see during a live attack:** the heartbeat strip spikes → an incident opens with the CERT-In 6-hour ring → *Where will it go next?* bars → a proposal (or an automatic action if safe) → the surgery panel shows households served staying at ~100 % for ATHENA while the *no response* and *isolate everything* lines drop → incident verified → isolation lifted; patches stay.

---

## 0. The whole system in one picture

```
 REAL DATA ──► Map Builder ──► Threat Finder ──► Path Predictor ──► Impact Simulator ──► Risk Scorer
 (NVD, EPSS,    "what do we    "which bugs      "how could an      "what physically    "how many people
  KEV, OSM,      have?"         matter?"         attacker travel?"   happens?"           lose service?"
  CERT-In…)                                                                                  │
                                                                                             ▼
   Watchdog ◄── live signals                                                      Fix Planner + Ask-First
   "is something wrong now?"                                                       "what to fix, when, and
        │                                                                           what to check first"
        ▼
   Healer ──► Safety Check ──► Playbook Runner ──► Verify (auto-rollback if it didn't work)
   "smallest safe       "test on a copy     "do it, log it,
    response"            of the city first"   CERT-In report ready"
```
**Story to tell:** *Find the danger → predict the route → measure the harm → fix smartly → defend live without a blackout → prove it.*

**Golden rule for showing anything:** (1) say the problem in one sentence, (2) show the 3D picture, (3) show one number with its unit and range, (4) say what the system did by itself.

---

## 1. Feature-by-feature

Format for each: **What / Inside / Show it / Say it / Proof**.

### F1 — Service-at-Risk (SaR)
- **What:** One number: "On a bad-but-realistic day, no more than X households lose water for Y hours."
- **Inside:** Path Predictor samples thousands of attacks → Impact Simulator (water + power physics) measures service lost in each → we take the 95th percentile.
- **Show it:** City screen top bar → click SaR → *tail histogram*; drag the percentile marker to 95%.
- **Say it:** "Like Value-at-Risk in banking, but for water and power."
- **Proof:** E1 (matches brute force).

### F2 — Harm-if-hacked / Harm-avoided-if-protected (per device)
- **What:** Two numbers on every device passport.
- **Inside:** Re-run the same random attacks with the device assumed hacked, then assumed protected; subtract from the average loss (same random numbers, so the difference is clean).
- **Show it:** Click any device → Device passport → three numbers. Open **Risk terrain**: hills are devices with big harm.
- **Say it:** "This small, boring controller looks harmless — but protecting it saves more than any other single fix."
- **Proof:** E2 (rank reversals vs CVSS).

### F3 — Rank-reversal (severity ≠ risk)
- **What:** Side-by-side: ranking by CVSS vs ranking by real harm.
- **Inside:** Both lists computed on the same devices; lines connect each device between the lists.
- **Show it:** *Slope chart*; the 9.8 web screen sinks, the 5.3 feeder controller rises. Click both to see why.
- **Say it:** "A 10 buried behind a one-way link is low risk; a 5 on the vendor route can darken a hospital."
- **Proof:** E1/E2.

### F4 — Fix Planner (with the fix's own cost)
- **What:** A dated plan: what to fix, in what order, and what *not* to patch.
- **Inside:** For every fix, benefit = loss avoided; cost = money + **service lost while doing the fix** (e.g. reboot stops a pump). Picks the best set (lazy-greedy), then a constraint solver fits them into maintenance windows without breaking hospital pressure or grid limits.
- **Show it:** *Fix* screen → what-if cards (ghost bars show before/after) → maintenance Gantt. A red "blocked" bar: "Patch PLC-2 refused — would stop Pump 3 at peak demand. Using virtual patch instead."
- **Say it:** "Our planner knows that fixing can hurt."
- **Proof:** E3 (near optimal), E4 (downtime term matters).

### F5 — Ask-First (value of information)
- **What:** The system asks the operator the one question that would change the plan most.
- **Inside:** Unknown links/versions have probabilities. For each unknown, simulate "if the answer were yes/no", re-plan, and measure how much the plan improves. Highest gain = first question.
- **Show it:** *Ask* screen → three question cards with information-gain bars → click an answer → the map updates and the plan reorders live.
- **Say it:** "Real inventories are incomplete. We don't pretend — we tell you what to check first."
- **Proof:** E5.

### F6 — Watchdog (including zero-days)
- **What:** Detects attacks without needing a known signature.
- **Inside:** Two cores. **Network core** learns normal industrial traffic (who talks to whom, which commands, how often). **Physics core** knows laws of the plant (a closed valve means no flow; a breaker can't flip 50 times in 10 s). Scores are fused; either physics alarm or both moderate → incident.
- **Show it:** Defend screen → inject "unknown exploit that fakes valve readings" → heartbeat strip spikes → panel: *"Valve says closed, but downstream flow says open — readings are being faked."* No CVE involved.
- **Say it:** "A lie about the valve can't beat the water in the pipe."
- **Proof:** E10.

### F7 — Healer (surgical self-healing)
- **What:** Stops the attack by the smallest safe action, never by shutting everything.
- **Inside:** Ladder: observe → virtual patch → close one link → rotate credentials → redirect to decoy → isolate a small cluster → local/manual control. Candidates come from minimum cuts of the attacker's reachable area; each is tested on the twin; a trained policy (PPO) ranks them; the Safety Check vetoes unsafe ones.
- **Show it:** Defend screen → *Surgery view*: the cut link snips, the cluster hatches, a counter shows **"Households still served: 99.8%"**. Press *Compare* → ghost split: "isolate-everything" shows the blackout.
- **Say it:** "We cut the wire, not the city."
- **Proof:** E9, E12.

### F8 — Safety Check (twin first)
- **What:** Nothing touches the city before it's tried on a copy.
- **Inside:** Copy-on-write fork of the twin → apply the action → run physics → compare to hard rules (hospital pressure, grid N-1).
- **Show it:** When the Healer picks an action, a small "Testing on the twin…" card appears, then ✔ Safe / ✖ Blocked with reason.
- **Say it:** "Autonomy with a seatbelt."

### F9 — Decoys
- **What:** Fake devices on the route the attacker is predicted to take.
- **Inside:** Path Predictor gives next-hop probabilities → decoy placed on the most likely hop, made to look slightly weak → any touch = near-certain alert.
- **Show it:** *X-ray* toggle: real devices solid, decoys shimmer violet. Show the attacker comet turning into the decoy; real pump stays untouched.
- **Say it:** "The attacker thinks they found the pump. They found a mirror."
- **Proof:** E13.

### F10 — Assume-breach mode (Red-Team)
- **What:** "Attacker is on public Wi-Fi — what's the fastest way to the water supply, and how do we cut it now?"
- **Inside:** Pick the attacker's starting node → shortest/most-likely path to a service → show the cheapest cut.
- **Show it:** Click a public Wi-Fi/EV-charger node → *Assume breach* → comet path lights up → "Cut here" suggestion with blast-radius ripple.
- **Say it:** "Don't ask if they'll get in. Ask what they could do and cut it."

### F11 — Cascade view
- **What:** How power loss becomes pump stop, tank drain and hospital pressure drop, with time.
- **Inside:** Pumps are powered by feeders in the combined model; tank hours vs repair time.
- **Show it:** Follow-path camera: comet → breaker → feeder dims → pumps stop → tank level falls toward the hospital line. Clock shows "pressure below minimum in 6 h; restore takes 2 h".
- **Say it:** "Time-to-survive vs time-to-repair."

### F12 — Risk-avoided ledger
- **What:** Value of fixes already done.
- **Inside:** Re-compute SaR with and without each applied fix.
- **Show it:** Executive view → "This month your fixes avoided 38,000 household-hours of outage."

### F13 — Self-learning
- **What:** Watchdog and Healer keep improving.
- **Inside:** Watchdog updates on verified-normal data only (drift detection tells seasonal change from sudden change). Healer is trained on thousands of simulated attack campaigns before use.
- **Show it:** *Normal-behaviour envelope* chart adapts over simulated days; training curve for the Healer showing it beats rule-based.
- **Say it:** "It learns normal, so abnormal stands out — and it never learns from an attack."

### F14 — Secure-by-design
- **What:** Our own tool is hard to attack.
- **Show it:** Compliance & Security screen → green ticks: MFA on, TLS/mTLS, signed data verified, Black Box chain intact, dependency scan clean, last ZAP scan. Then live demo: edit one log line in a copy → "chain broken" alarm.
- **Say it:** "Secure by design and fails safe — not 'unhackable', but verifiable."
- **Proof:** E14.

### F15 — CERT-In readiness
- **What:** 6-hour incident reporting, 180-day Indian log retention, India time sync, SBOM, IoT findings.
- **Inside:** Incident starts a 6-hour clock; report package assembled automatically; Log Vault keeps 180 days; Time Guard checks clock drift.
- **Show it:** Compliance screen → ring "04:12 left" on the live incident → *Review & Export* → report preview (what/when/where/actions).
- **Say it:** "Compliance is a by-product of operating, not paperwork afterwards."
- **Note:** Chapter numbers go on screen only after you verify them in the PDF.

---

### F16 — Zero-day lab and pipeline
- **What:** the system *introduces* zero-days (exploits for a product no CVE/EPSS/signature covers), then handles them: detect → suspect → fingerprint → capture and analyse a sample → deploy a **family rule** to every device of that product → remember it in the library.
- **Inside:** `zeroday.py` (lab, library), `rl.py` (pipeline + policy), `runtime.py` (`introduce_zero_day`, `_zd_pipeline`). A classic virtual patch stops only 30% of zero-day attempts; the family rule stops 85%.
- **Show it:** rail → **Zero-day** → pick a product marked *unseen in training* → **Introduce zero-day**. Watch the stage tracker (Introduced → Suspected → Family rule → Contained), the extracted fingerprint chips, the library table. Introduce the *same product again*: the rule is already deployed.
- **Say it:** "Nobody told ATHENA which product was exploited. It saw behaviour, not a signature, and protected the whole product family."
- **Proof:** E16 (repeat encounter cheaper, paired 95% CI excludes 0), E10 (unseen attack types detected).

### F17 — PPO responder (reinforcement learning)
- **What:** a policy trained with PPO on thousands of simulated zero-day campaigns chooses containment actions (146 actions, invalid and unsafe ones masked).
- **Inside:** `rl.py` (environment, masking with the Safety Check as a shield, PPO written in PyTorch), `train_ppo.py` (4 seeds in parallel), `eval_ppo.py` (validation-based selection, 300 matched test scenarios, bootstrap confidence intervals). 14 products for training, 6 held out.
- **Show it:** **Zero-day → Who responds?** choose *PPO always*; launch a zero-day; read the decision cards (chosen action + top-3 probabilities + how many safe actions it had). The evidence card shows the training curve and the held-out comparison.
- **Say it (honestly):** "Trained only on other products' zero-days, it is significantly better than doing nothing or isolating everything while cutting 1.3 devices instead of 19.8. It does **not** beat our model-based search Healer, so search is the default."
- **Proof:** E15 (missed vs search; met vs no response and isolate-everything).

---

## 2. Internal mechanisms that solve problems automatically
(Show these as small status chips in a "System health" popover — judges love seeing the system look after itself.)

| Mechanism | One-line explanation for judges | How to trigger live |
|---|---|---|
| Conformal escalation | "When the fast estimate isn't sure, it asks the slow, accurate simulator." | Inject a rare scenario → chip: "Escalated to full simulation" |
| Drift guard | "Normal changes slowly; attacks change suddenly." | Speed up the clock to show demand shift → "Re-learned normal" |
| Feed sanity check | "A suddenly strange feed is quarantined." | Upload a doctored EPSS file → "Quarantined" chip |
| Auto-rollback | "If the fix didn't work, it undoes itself." | Choose a deliberately weak action → verify fails → rollback |
| Action arbiter | "One change at a time per zone." | Fire two incidents in one zone → second queues |
| Time Guard | "Clocks lie; we notice." | Skew a source clock → events flagged time-uncertain |
| Adaptive quality | "The 3D view keeps up with the laptop." | Throttle CPU → effects auto-reduce, info stays |
| Health supervisor | "A crashed module restarts; the plant never depended on us." | Kill a worker → restarts, Black Box notes the gap |

---

## 3. The 3D/UI experience — how to operate it in the demo

**Controls:** `1` Overview · `2` Ward focus · `3` Stack · `4` Follow path · `5` Hospital · `L` layers · `T` time scrubber · `X` x-ray decoys · `J` Judge Mode · `Space` pause.

**Screens in demo order:** City → Stack → Path → Fix → Ask → Defend → Proof → Compliance & Security.

**What each visual proves:**
| Visual | The point it makes |
|---|---|
| Exploded Purdue stack | Attacks move *down* from office IT to machines |
| Risk terrain | Danger is concentrated, not everywhere |
| Comet path | The attacker's route, with probability as thickness |
| Liquid tank + flow pipes | Harm is physical and timed |
| Ripple dome | Blast radius is bounded and measurable |
| Slope chart | Severity ≠ risk |
| Ghost split | Our action vs no action, same timeline |
| Surgery view | Utilities stay on while the attacker is cut off |
| Confidence ribbon | We don't overclaim |

---

## 4. The 6-minute run-of-show (rehearse twice)

| Min | Screen | Do | Say |
|---|---|---|---|
| 0:00 | City | Orbit Mumbai ward; toggle layers | "A smart-city ward: IT, control devices, pipes, power, hospitals — one connected map." |
| 0:45 | City | Show CVSS-sorted list | "Today's tools stop here." |
| 1:15 | Slope chart | Reorder to SaR | "Real harm reorders the list." |
| 1:45 | Path | Fly along comet path; tank drains | "A street-light gateway to the water supply — hospital loses pressure in 6 hours." |
| 2:30 | Fix | Compare fix cards; show blocked patch | "The 9.8 patch barely helps; closing one link cuts the risk by ~90% [use measured value]." |
| 3:15 | Ask | Answer one question | "We ask the one thing that changes the plan." |
| 3:45 | Defend | Inject breach via public EV charger | "Predicted route… decoy touched… one cluster cut… utilities still on." |
| 4:30 | Defend | Inject zero-day (fake valve) | "No signature — physics caught the lie." |
| 5:00 | Compliance | Show 6-hour ring + export | "Report ready in one click, logs kept in India for 180 days." |
| 5:30 | Proof + Security | Show E9/E11 + green ticks | "Measured, scalable, and the tool defends itself. Limits are on the last slide." |

**All numbers on screen must come from engine output and be tagged SIMULATED / REAL / DERIVED.** Replace bracketed values with measured ones.

---

## 5. Judge Q&A cheat sheet
| Question | Answer |
|---|---|
| Is this real data? | Real: vulnerabilities (NVD, EPSS, KEV, CISA ICS advisories), city geometry (OSM), ward population, standard water/power models. Synthetic: device inventory, links, credentials — tagged on screen. |
| How do you validate without real attacks? | Against brute-force simulation and baselines (E1–E13); threat layer back-tested on KEV (E7). We state the limit openly. |
| Can the AI make a dangerous move? | No: every action is tested on a twin first; unsafe ones are vetoed; high-impact ones need two-person approval; there's a kill switch. |
| What if the AI is wrong? | Every number has a range; the system escalates to the exact simulator when unsure; wrong actions auto-roll back. |
| What about zero-days? | Physics and behaviour checks need no signature; containment first, understanding later. |
| Why not just isolate the network? | In water/power, isolation can itself cause an outage; E9 shows service retained vs isolate-everything. |
| Is it secure? | Secure by design and fails safe (least privilege, MFA, mTLS, signed data, tamper-evident log, scanned). We don't claim unhackable. |
| How does it follow CERT-In? | 6-hour reporting clock, 180-day India-local logs, NTP time check, SBOM, IoT misconfiguration findings, chapter-mapped remedies. |
| Does it scale? | Incremental recompute + cache + fast estimator; E11 shows 10²→10⁵ nodes; second city from config. |
| What's new vs Claroty/Tenable/XM Cyber? | They map paths and score devices; we measure service loss with physics, price the fix's own downtime, rank unknowns, and heal surgically. |

---

## 6. Pre-demo checklist
- [ ] Data snapshot dated and visible; REAL/SYNTHETIC badges on
- [ ] Judge Mode tested end to end; backup recording made
- [ ] Every number on screen traced to an engine output
- [ ] Security panel all green; tamper demo rehearsed
- [ ] CERT-In chapter column verified before any chapter number is shown
- [ ] Adaptive quality tested on the demo laptop; 55+ fps in Overview
- [ ] Contrast and colour-blind checks passed


---

## UI v2 quick reference (supersedes page names above)

| Page | One-line purpose | Show this |
|---|---|---|
| City | Is the ward safe right now? | Service ring, 3/3 hospitals, weakest points (tap one: camera flies to it, passport opens) |
| Paths | How could a hacker reach water or power? | Tap a route: thick numbered path on the map; drag the start hour: hospital pressure line |
| Fix | What to fix first? | Before / now / after bars; preview a fix; "Missing facts" box = Ask-First |
| Defend | Watch ATHENA stop an attack | Launch attack: status turns Under attack -> Healing -> Recovered; map shows shield, beam, rings; "Service kept" lines |
| Zero-day | An attack nobody has seen before | Launch zero-day: 4-step tracker, fingerprint chips, library, "Who responds?" |
| Proof | Does it really work? | Slope chart, then tests with met/missed pills |
| Safety | CERT-In and our own security | 6-hour clock, Log Vault, tamper demo |

Map controls: drag turn, right-drag move, scroll zoom, **W A S D** fly, on-map pad, top chips Overview / Hospitals / Water, left tools: links, risk hills, decoys, 3D layers, help. Keys: 1 overview, 2 water, 3 hospitals, X decoys, L links, R risk hills, J tour.
If the heartbeat stays high after an attack: the pump or breaker stays off until the crew restores it (about 45 simulated minutes); after 10 minutes without an answer, autonomy applies the safe plan by itself.


---

## What-if page (new)

| Step | Do | Say |
|---|---|---|
| 1 | Open **What-if**, pick *Vendor VPN*, press **Simulate compromise** | "A connection alone is not a compromise. Every step needs a reason." |
| 2 | Point at the three boxes: plausible / predicted / confirmed | "Simulated, machine-learned and observed are never mixed." |
| 3 | Show Before / During / After bars and the thick path on the map | "Risk index: baseline 100, during the attack, after the best package." |
| 4 | Press **Try it** on a recommendation, open *Before and after your changes* | "MFA alone does not close every path; closing 4 links does." |
| 5 | Press a scenario (five buttons), open its timeline and assumptions | "Everything here is generated. Nothing touches a real system." |
| 6 | Open **Why this priority?**, tap *SCADA web portal* and *Engineering PC* | "CVSS 10 ranks 9th; CVSS 8.8 ranks 1st because of what it can reach." |
| 7 | **Reset simulation** | "The baseline was never modified." |
Tap any device on the map, then **Simulate** in its panel, to start from it.
Run the tests: `.\.venv\Scripts\python -m pytest backend\tests -q` (51 tests, about 50 s).


## Map highlights and locked districts (new)
* Every button or row in the side panel that refers to a path, link or device now highlights it on the map with the same thick route style, and the camera frames it: City weakest points, Paths routes, Fix plan rows and previews, Missing facts, Defend (proposal steps, "What ATHENA did", predicted next hop), What-if recommendations and ranking, Zero-day library, device-panel links, and clicking a device on the map.
* Terracotta = attacker route (numbered), apricot = predicted next hop, aqua = a defence (a link to close, devices protected). Press the same item again, click empty map, or change page to clear it.
* The empty land around the ward is eight hatched, padlocked districts ("Locked · coming soon"). Clicking one shows a short message.


## UI v3 demo script (3 minutes)
1. Open the map. Point at the **green city**, the **icons** and the **BARC / IT hub / tourist sites** on the surrounding land (`4` or the Mumbai button).
2. Click the **Vendor VPN** icon: the card shows what it is and its **blast radius** (red lines to everything it can reach, including Mumbai sites).
3. **Predict** page: likely targets, reasons, next steps, and the accuracy panel.
4. **Defend**: launch a known attack, then an **insider** attack. Watch the incident card (top right) and the bottom timeline; the heartbeat shows **Healing** with a countdown.
5. Press **■ Stop**: attacks halt; **▶ Resume** restores. 6. **How it works**: play the zero-day story (physics breaks, fingerprint, family rule, second encounter blocked).
7. **Why us**: measured numbers and what did not work.


## Demo additions (round 4)
1. Overview: sea on the left, real roads and railways, coloured buildings. Press Hospitals / Water plants / Power to zoom in.
2. Paths: click any device; the "What it would do" box shows people, hours and rupees for that device.
3. What-if: Simulate compromise. Watch the map replay the spread while the risk heartbeat climbs, then drops after the best fix.
4. Defend: Launch attack. The status says "Attack running", then the alarm; read the three boxes: the attack, what ATHENA did, how well it worked.
5. Zero-day: launch one; read how we are stopping it, how well it worked, what the model learned.
6. How it works and Why us fill the whole page: press an algorithm to read why it was chosen.
