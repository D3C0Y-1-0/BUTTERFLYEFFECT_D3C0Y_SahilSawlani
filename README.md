# ATHENA — predict, explain and heal city infrastructure without switching it off

A working prototype for **D3COY 1.0 · PS03** (AI-based critical-infrastructure cyber-risk prediction), built around a simulated **Mumbai ward (Parel–Sion–Matunga)**.

* **Service-at-Risk**: risk measured as *households / hospitals / MWh that lose service*, computed by a water (WNTR/EPANET) and power (pandapower) simulator — not by CVSS labels.
* **Always-on, self-running**: a live twin runs continuously; an *Autopilot adversary* attacks on its own; the **Watchdog** detects, the **Healer** responds surgically; you can also launch attacks yourself.
* **CERT-In aligned**: 6-hour reporting clock, 180-day India-local log vault, time-sync guard, SBOM coverage, chapter-by-chapter map of the *Cyber Security Guidelines for Smart City Infrastructure*.
* **Zero-day lab + PPO responder**: the system introduces exploits nobody has a signature for, fingerprints them, deploys family rules, and can respond with a PPO-trained policy (honest results in PLAN.md §28).
* **What-if Lab** (`/api/v2`, page "What-if"): deterministic "simulate compromise" with explicit attack preconditions, five defensive scenarios, an explainable risk model (monotone gradient boosting x physics-backed impact), mitigation before/after, SQLite store.
* **Secure by design**: Argon2id + TOTP MFA, RBAC, rate limits, strict validation, tamper-evident log, signed air-gap files — 37/37 automated security tests pass.

Read [PLAN.md](PLAN.md) (design, algorithms, honest deviations in §27) and [WORKFLOW.md](WORKFLOW.md) (how every feature works and how to show it).

## Run it (Windows)

**You need (once):** 64-bit **Python 3.11, 3.12 or 3.13** and **Node.js LTS** (only used to build the interface). Install them with
`winget install Python.Python.3.12` and `winget install OpenJS.NodeJS.LTS` (or from python.org / nodejs.org), then open a **new** PowerShell window.
If PowerShell refuses to run scripts: `Set-ExecutionPolicy -Scope Process Bypass`.

```powershell
.\run.ps1          # creates the venv, builds the UI on first run (and again whenever it is missing, half-built or older than the source), starts http://127.0.0.1:8000 (restarts itself if it ever stops)
```
Open http://127.0.0.1:8000, click a demo account (the login page shows live TOTP codes because `DECOY_DEMO=1`), sign in, press **▶ Tour**.
Boot takes ~10 s; the first risk analytics take ~30 s (they cache to `data/`).

**If the first run fails** with `numpy ... meson ... Unknown compiler` or `No module named uvicorn`: your Python has no ready-made packages (32-bit, or too new / too old). `run.ps1` now checks this, installs wheels only (nothing is compiled) and says what to install. Delete the `.venv` folder after switching Python, then run `.
un.ps1` again.

**Map controls (mouse only):** wheel = zoom · hold + drag = move · right-button drag (or Shift + drag) = turn · click a device = its card, blast radius and way in · `F` = full screen · `1`-`4` = Overview / Water / Hospitals / Mumbai. The side panel starts closed: pick a page on the left rail or press **Panel**.

**Interface build:** you never need to delete `frontend\dist` by hand. `run.ps1` rebuilds it automatically when it is missing, has no `index.html`, or is older than the files in `frontend\src`; a failed build removes the half-built folder and tells you why. The command is the same as always: `.\run.ps1`.

Developing the UI: `cd frontend && npm run dev` (port 5173 proxies to the API).

## Accounts (demo only)
`admin`, `operator`, `analyst`, `executive` — passwords and current TOTP codes are shown on the login page while `DECOY_DEMO=1`. Set `DECOY_DEMO=0` to hide them.
Executives read; analysts also run attacks and what-ifs; operators approve actions; admins also enable full autonomy, reset and run the tamper/chaos demos.

## What is real and what is synthetic
| Real | Synthetic (labelled in the UI) |
|---|---|
| Hospital, substation, water-tower locations and 7,400 buildings (OpenStreetMap, fetched 31 Oct 2026) | Device inventory, IPs, links, credentials, vendor access |
| CVE records (NVD), exploit probabilities (FIRST EPSS), exploited-in-the-wild list (CISA KEV) for 15 real products | Pump/tank sizes, ward household counts, demand pattern |
| CERT-In guideline chapters and local threat patterns (2.3) | Repair times, costs, patch downtimes (`backend/decoy/assumptions.py`) |

## Repository map
```
backend/decoy/      city.py  physics.py  threat.py  planner.py  healer.py  watchdog.py  adversary.py  zeroday.py  rl.py
                    twin.py  runtime.py  blackbox.py  security.py  surrogate.py  api.py
backend/            data_fetch.py  precompute.py  experiments.py  security_tests.py  train_ppo.py  eval_ppo.py
frontend/src/       scene/CityScene.ts (three.js)  components/Views.tsx  App.tsx  store.ts
data/               real-data snapshots, loss cache, experiments.json, security_tests.json
experiments/        targets.md (written before any experiment ran)
```

## Re-running the evidence
```powershell
.\.venv\Scripts\python backend\data_fetch.py all        # refresh NVD/EPSS/KEV/OSM snapshots
.\.venv\Scripts\python backend\precompute.py            # exact attack-outcome table (cached)
.\.venv\Scripts\python backend\experiments.py           # E1-E13  -> data/experiments.json
.\.venv\Scripts\python backend\security_tests.py        # E14    -> data/security_tests.json
.\.venv\Scripts\python -m pytest backend\tests -q       # 51 What-if Lab tests (engine edge cases, REST API, scenarios, ML pipeline)
.\.venv\Scripts\python backend\train_ppo.py 100 2048 1   # PPO zero-day responder, seed 1 (run seeds 1-4 in parallel, ~17 min each)
.\.venv\Scripts\python backend\eval_ppo.py 300         # E15/E16: validation selection + paired held-out test
```

## Honest limits
Everything is validated inside a simulation; no public dataset links devices, vulnerabilities, links and real outcomes. Mumbai names are scenario context, **not** claims about real vulnerabilities at those sites. Assumptions that cannot be sourced are listed in `assumptions.py` and shown in the app.
