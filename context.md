# DECOY: project context

Hand-off notes for a new session. Read this first, then PLAN.md (design and decisions) and WORKFLOW.md (demo script).

## What it is
A predictive, self-healing cyber-risk system for a simulated Mumbai ward (Parel–Sion–Matunga). Built for hackathon D3COY 1.0, PS03.
It predicts how an attack could spread across city infrastructure (water, power, hospitals), detects attacks, and fixes them while keeping services running.

## How to run
- `.\run.ps1` starts the server on port 8000 and restarts it if it stops. It tells you if an old server still holds the port.
- Open http://127.0.0.1:8000 and sign in with a demo account. Use Ctrl+F5 after backend changes.
- Wait for "ATHENA is ready" in the terminal; the PPO model loads in the background.
- Tests: `pytest` in `backend` (65 tests, about 80 s) plus the security tests (37).
- Frontend: `npm run build` in `frontend`. The backend serves `frontend/dist`.

## Architecture
**Backend** (`backend/decoy/`): Python 3.11, FastAPI, WebSocket, uvicorn.
- `twin.py` and `runtime.py`: simulated ward and the live loop. Physics oracle is WNTR/EPANET (water) plus pandapower (power).
- `ThreatModel`: Monte-Carlo attack worlds with common random numbers.
- Watchdog: autoencoder, physics invariants and logistic fusion.
- Healer: response ladder, greedy search, Safety Check.
- Planner: CELF plus OR-Tools CP-SAT.
- PPO responder: PyTorch. It does not beat the Planner, so say that honestly.
- Zero-day pipeline: detect → suspect → fingerprint → capture and analyse → family rule → library.
- What-if Lab: `lab.py`, `lab_service.py`, `lab_scenarios.py`, `lab_api.py` (REST under `/api/v2`, SQLite).
  - Deterministic compromise simulation with explicit preconditions.
  - Monotone `HistGradientBoostingRegressor` propensity model (held-out Spearman 0.91, top-5 overlap 0.74).
  - networkx minimum cuts for mitigations.
  - Five scenarios.
  - The lab works on its own private copy of the ward, so it never changes the live system.

**Frontend** (`frontend/src/`): React 18, TypeScript, Vite, three.js 0.160.1.
- Custom store on `useSyncExternalStore`; websocket frames coalesced to about 3 Hz.
- `scene/CityScene.ts`: 3D map, locked padlock tiles around the ward, path tubes, healing effects.
- `focus.ts` and `routes.ts`: whatever you select on the side console highlights its path on the map.
- `components/ui.tsx` has `Box` and `Move` (a plain title with a "details" dropdown). `components/status.ts` has `plainMove`.
- Palette: cream #FFEAD3, aqua #BFE7EA, apricot #E89B5B, terracotta #D46743.

## Standing preferences from the user
- Plain names and simple language. Show only what matters; use boxes with dropdowns.
- Never cover the centre map. Do not make the site heavy.
- Real algorithms, not fallbacks. Honest results. Never claim "unhackable".
- Label data REAL / DERIVED / SYNTHETIC.
- Keep the .md docs in sync with the code.

## Honest limits
- Zero-day suspicion is still weak (about 3 of 24 flagged).
- PPO does not beat the search Planner (E15 missed).
- Not built: GNN surrogate, Bengaluru config, Hindi/Marathi toggle, dark/light toggle, mTLS, ZAP.
- Experiments E1–E16 were not re-run after the latest changes.
- UI performance was tested only on a software renderer.

## Git
- Remote: https://github.com/D3C0Y-1-0/BUTTERFLYEFFECT_D3C0Y_SahilSawlani (branch `main`, first commit cc9a0e2 pushed).
- **Uncommitted and unpushed:** path highlights for every selection, locked tiles, plain-language moves with the details dropdown, the Lab 409 fix, the WORKFLOW.md additions.
- `.gitignore` excludes secrets (keys, vault, db, logs, `.venv`, `node_modules`, `frontend/dist`). Check before pushing.

## Done in UI v3 (see PLAN.md section 31)
Collapsible closed-by-default sidebar, green map with icons, Mumbai sites, node card with blast radius, 2D graph, Predict / How it works / Why us pages, factor-based scheduler, insider attack, Stop/Resume/Pause, graceful heartbeat, simpler Safety, new run.ps1. Tests: 51 lab tests + 11 in backend/tests/test_v3.py; security 37/37.

## Round 4 (1 Nov 2026), see PLAN.md section 32
Aerial-style map with real OSM roads/rail, full-page How/Why, live defence scoreboard, impact endpoint, better forecast model (0.91 / 0.74 / 0.013). Tests: 51 lab + 14 in test_v3.py.

## Open item (older)
The user sent a mockup ("D3COY City Threat Atlas") and asked whether it is possible. The answer given: yes, except the photoreal look. No work has started; it is waiting on their go-ahead.
- Easy: restyled callouts, top bar with region dropdown (other regions locked), compact collapsible incident card with Attack Progression, icon-only rail, IST clock.
- Medium: bottom timeline bar (pause, step, speed, click a step to highlight that hop), read-only replay from recorded snapshots, warmer lighting, sea plane, trees.
- Not possible: photoreal city. Real OSM extruded buildings are stylised.
- Keep the incident card small and collapsible so it does not cover the centre map.

## Gotchas
- Stopping all python processes can kill the user's own server. Use a spare port (8010) for tests and target a PID.
- On Windows PowerShell, avoid here-strings for multi-line commit messages; write them to a file.
- Do not alias a helper named `R` in PowerShell (it is `Invoke-History`). Use Python patch scripts for multi-line edits.
- The Lab page must request `/risk` only once the model status is "ready", or it returns 409.
