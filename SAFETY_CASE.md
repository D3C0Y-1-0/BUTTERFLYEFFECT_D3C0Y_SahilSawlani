# ATHENA: safety case outline and how it maps to IEC 62443 / CERT-In

This is an outline for a site assessor, not a certificate. Nothing here has been audited.

## Operating model
1. **Observe** (read-only tap: mirror port and historian copy). ATHENA never sits in the control path. If ATHENA stops, the plant runs exactly as before. Start here.
2. **Suggest** (`ATHENA_AUTONOMY=suggest`). Every cut is a proposal a named operator approves; high-impact ones need two different people. A utility should stay here for a long trial period and review the proposals against what its own engineers would have done.
3. **Auto-low** (demo default). Only reversible steps run by themselves, subject to the guards below. Moving here needs the site's change-management approval and a named owner.

## Guards that are in the code and tested (`backend/tests/test_hardening.py`)
- A cut touching a hospital's own systems (building management, water controller) needs a person unless a physical reading or three or more devices back the alarm. Safe steps in the same plan still run.
- At most 4 automatic steps per 120 simulated minutes. "Nobody answered" pages again; it never applies a held plan.
- A lone decoy touch (could be an authorised scanner) never authorises a cut.
- Every automatic physical action is first simulated against hospital pressure and grid limits (Safety Check, water and power only).
- Every action, approval and export is written to a keyed, hash-chained, externally anchored log.

## Mapping (foundational requirements)
| IEC 62443 FR | Where | Gap |
|---|---|---|
| FR1 identification and authentication | Argon2id, TOTP, signed expiring tokens, lock-out | No enterprise SSO |
| FR2 use control | Role-based checks on every route, two-person rule | |
| FR3 system integrity | Keyed log, signed air-gap snapshots, signed model cache | Anchor must be off-box |
| FR4 data confidentiality | TLS option, no secrets in repo | mTLS not built |
| FR5 restricted data flow | Read-only tap, air-gap export/import | Needs real data-diode hardware |
| FR6 timely response to events | Incidents, CERT-In 6 h clock, CEF and JSON export (`/api/export/incidents`) | No live SIEM connector tested |
| FR7 resource availability | Bounded logs, rate limits, shared frames, ATHENA failure leaves the plant unchanged | No high-availability pair, no key rotation |

## Failure modes to review with the site
- ATHENA down: no protection, no harm. Run it as a pair for availability.
- ATHENA wrong (false alarm): worst case is a suggested or rate-limited cut of non-hospital equipment; hospital cuts always need a person.
- Forged or replayed readings: caught early only with independent meters on a separate path.
- Adaptive attacker who learns to trigger cuts: partly bounded by the rate limit; not modelled in the simulator.
- Nobody on shift: held plans wait and page again; measured with a simulated operator who answers 90% of the time after 5 to 20 minutes.

## Before any real deployment
Site-specific hazard analysis, real traffic captures to set thresholds, protocol inspection for Modbus, DNP3 and IEC-104, an independent penetration test, and a named system owner.
