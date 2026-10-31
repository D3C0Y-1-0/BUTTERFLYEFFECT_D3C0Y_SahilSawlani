"""The five defensive simulation scenarios. Each has its own assumptions, initial state, event timeline, effects and insights.
They only build generated events and hypothetical changes to an in-memory copy of the model. No payloads, no credential theft, no equipment commands."""
from __future__ import annotations

import numpy as np

from .lab import Controls, dependents, simulate_compromise, service_loss, RULES, MODEL_VERSION

SCENARIO_LIST = [
    dict(id="vendor_credential", title="Compromised vendor remote access", sector="OT access"),
    dict(id="ransomware_monitoring", title="Ransomware affecting a monitoring server", sector="OT monitoring"),
    dict(id="controller_exposure", title="Water-treatment controller exposure", sector="water"),
    dict(id="iot_compromise", title="Smart-city IoT compromise", sector="smart city"),
    dict(id="hospital_incident", title="Hospital network incident", sector="healthcare"),
]


def _tl_from_sim(model, sim, t0=0, step=4):
    ev = []
    for i, v in enumerate(sim["compromised"][1:], 1):
        eid = sim["paths"][v][-1]
        e = next(x for x in model["edges"] if x["id"] == eid) if not eid.startswith("HYP") else dict(source=sim["start"], protocol="modbus_tcp")
        src = e["source"]
        ev.append(dict(t=t0 + step * i, type="lateral_step", asset=v, status="plausible", synthetic=True,
                       text=f"Synthetic: unusual {e['protocol'].upper()} session {model['assets'][src]['name']} -> {model['assets'][v]['name']} ({sim['why'][v][0]})"))
    return ev


def _finish(lab, sid, title, assumptions, initial, timeline, effects, start, c0, creds, extra, insights, assumed=None, add=()):
    m = lab.model
    sim = simulate_compromise(m, start, c0, creds, extra)
    comp = assumed if assumed is not None else sim["compromised"]
    rec = lab.recommend(start, c0, creds, extra, add=add)
    c2, pack = lab.apply_recommendation_package(start, c0, creds, extra)
    after = simulate_compromise(m, start, c2, creds, extra)
    risk = dict(before=round(lab.ward_index(c0), 2), during=round(lab.ward_index(c0, assumed=comp, extra=extra), 2), after_package=round(lab.ward_index(c2, extra=extra), 2))
    pred = [dict(id=r["id"], likelihood=r["likelihood"], risk=r["risk"]) for r in lab.ranking(c0)[:5]]
    out = dict(id=sid, title=title, start=start, compromised=sim["compromised"], paths=sim["paths"], model_version=MODEL_VERSION, deterministic=True, assumptions=assumptions, initial_state=initial, timeline=sorted(timeline, key=lambda e: e["t"]),
               effects=effects, risk=risk, recommendations=rec, package=dict(controls=pack, still_reachable=after["compromised"][1:], closes_every_path=len(after["compromised"]) == 1),
               insights=insights, classification=dict(confirmed_incident_assets=lab.classify(sim)["confirmed_incident_assets"], plausible_path_assets=sim["compromised"][1:], predicted_top_risk=pred),
               synthetic_notice="All events are generated. Nothing here touches a real system.")
    lab.db.add_run("scenario", sid, out)
    return out


def vendor_credential(lab):
    m, start = lab.model, "VPN_VENDOR"
    c0, creds = Controls(), {start}
    sim = simulate_compromise(m, start, c0, creds)
    rng = np.random.default_rng(101)
    auth = [dict(t=0, type="auth", asset=start, status="synthetic", synthetic=True, text="Synthetic: vendor account signs in from a new country"),
            dict(t=1, type="auth", asset=start, status="synthetic", synthetic=True, text=f"Synthetic: {int(rng.integers(8, 14))} failed sign-ins in 2 minutes, then one success"),
            dict(t=2, type="auth", asset=start, status="synthetic", synthetic=True, text="Synthetic: sign-in at 03:12, outside the vendor maintenance window"),
            dict(t=3, type="auth", asset=start, status="synthetic", synthetic=True, text="Synthetic: 4 parallel sessions (usual: 1)")]
    mon = [a for a in sim["compromised"] if a in m["monitored"] or a == "HIST_01"]
    loss = service_loss(m, sim["compromised"], lab.impact_fn)
    eff = dict(compromised=sim["compromised"][1:], plausible_paths={k: v for k, v in sim["paths"].items() if k != start}, failed_transitions=sim["failed"][:8], monitoring_exposed=mon,
               services_lost=loss["services"], loss=round(loss["loss"], 1), abnormal_auth=dict(sign_ins_per_hour_baseline=2, sign_ins_per_hour_scenario=14))
    mfa = next((r for r in lab.recommend(start, c0, creds, top=60) if r["control"] == "mfa" and "VPN" in r["label"]), None)
    ins = ["A vendor credential is enough: the vendor links need no vulnerability, only the credential.",
           ((("MFA on the VPN closes every path." if mfa["eliminates_all_paths"] else "MFA on the VPN alone does NOT close every path: " + ", ".join(mfa["still_reachable"][:3]) + " stay reachable through other weaknesses (vulnerable services).") + (" It does cut the modelled loss." if mfa["reduction"] > 0 else " On its own it changes nothing, so it must be combined with other controls.")) if mfa else "MFA option not applicable."),
           f"{len(mon)} monitoring-related asset(s) become exposed, so detection itself is at risk."]
    return _finish(lab, "vendor_credential", "Compromised vendor remote access",
                   ["A vendor credential is stolen (hypothetical); no technique is modelled.", "Vendor links exist for maintenance and need a valid credential, not a vulnerability.", "Without MFA a credential works from anywhere."],
                   dict(compromised_start=start, credentials_held=sorted(creds), controls="none"), auth + _tl_from_sim(m, sim, 4), eff, start, c0, creds, (), ins)


def ransomware_monitoring(lab):
    m, start = lab.model, "HIST_01"
    c0 = Controls()
    sim = simulate_compromise(m, start, c0)
    dep = dependents(m, start)
    monitored = [d["consumer"] for d in m["deps"] if d["provider"] == start and d["kind"] == "monitoring"]
    cov = len(set(monitored)) / max(1, len(m["monitored"]))
    loss = service_loss(m, sim["compromised"], lab.impact_fn)
    tl = [dict(t=0, type="file_activity", asset=start, status="synthetic", synthetic=True, text="Synthetic: unusual mass file renames on the monitoring server"),
          dict(t=3, type="state", asset=start, status="synthetic", synthetic=True, text="Synthetic state change: HIST_01 marked OUTAGE (data unavailable)"),
          dict(t=5, type="monitoring", asset=start, status="synthetic", synthetic=True, text=f"Synthetic: telemetry from {len(set(monitored))} assets stops arriving")] + _tl_from_sim(m, sim, 6)
    eff = dict(state="outage (synthetic)", dependent_assets=dep, monitoring_visibility_lost_pct=round(100 * cov, 1), lateral_spread_plausible=sim["compromised"][1:],
               services_lost=loss["services"], loss=round(loss["loss"], 1), recovery_hours=dict(without_tested_backups=48, with_tested_backups=8))
    ins = [f"The server's outage alone blinds {eff['monitoring_visibility_lost_pct']}% of monitored assets, even if nothing else is hit.",
           f"{len(dep)} asset(s) depend on it (cycles in the dependency graph are handled).", "Tested backups cut recovery from about 48 h to about 8 h (assumption); isolation limits spread."]
    return _finish(lab, "ransomware_monitoring", "Ransomware affecting a monitoring server",
                   ["No malware is modelled; only a synthetic outage state.", "Monitoring server holds telemetry for the assets listed in the dependency table.", "Recovery: 48 h without tested backups, 8 h with (assumption)."],
                   dict(outage=[start], backups="untested"), tl, eff, start, c0, (), (), ins)


def controller_exposure(lab):
    m, start = lab.model, "SCADA_WEB"
    c0 = Controls()
    hyp = [dict(id="HYP_E1", source="SCADA_WEB", target="PLC_PS2", kind="network", protocol="modbus_tcp", p_access=0.8, exists=True, documented=False, note="hypothetical: weak segmentation")]
    sim = simulate_compromise(m, start, c0, (), hyp)
    before = simulate_compromise(m, start, c0)
    reach = "PLC_PS2" in sim["compromised"]
    loss = service_loss(m, sim["compromised"], lab.impact_fn)
    P = lab.rt.phys
    series = None
    if "PS2_OFF" in loss["actions"] or reach:
        r = P.loss(P.attack_events(["PS2_OFF"], 6.0), want_series=True)
        s = r["series"]
        series = dict(t=[round(x, 2) for x in s["t"][::6]], hospital_pressure_H1=[round(x, 2) for x in s["p_H1"][::6]], hospital_min_pressure=15.0,
                      result={k: v for k, v in r.items() if k != "series"})
    tl = [dict(t=0, type="exposure", asset="PLC_PS2", status="synthetic", synthetic=True, text="Synthetic: a link from the SCADA web portal to the pump controller exists (weak segmentation)")] + _tl_from_sim(m, sim, 2)
    eff = dict(controller_reachable=reach, plausible_path=sim["paths"].get("PLC_PS2"), path_without_the_weak_link=before["paths"].get("PLC_PS2"), compromised=sim["compromised"][1:], services_lost=loss["services"], loss=round(loss["loss"], 1), operational_model=series,
               water_service="Pump PS2 stops: Parel / Lalbaug / Dadar East lose pressure after the Parel reservoir drains" if reach else "Not reachable")
    hb, ha = len(before["paths"].get("PLC_PS2") or []), len(sim["paths"].get("PLC_PS2") or [])
    ins = ["The hypothetical link alone is not an attack: the portal must also be exploitable (Log4j) before the controller is reachable.", f"It shortens the route to the controller from {hb} hop(s) to {ha}, but closing only that link leaves the older route through the SCADA server open: a real fix needs the minimum cut below."]
    return _finish(lab, "controller_exposure", "Water-treatment controller exposure",
                   ["A link SCADA web portal -> pump controller exists because of weak segmentation (hypothetical, added in memory only).", "Pump controller has a known CVE and an unknown firmware version.", "Water effect from the WNTR/EPANET physics oracle (attack at 06:00)."],
                   dict(hypothetical_link=hyp[0]["id"], attacker_start="internet"), tl, eff, start, c0, (), hyp, ins)


def iot_compromise(lab):
    from sklearn.cluster import DBSCAN
    from sklearn.ensemble import IsolationForest
    m, start = lab.model, "GW_LIGHT_01"
    c0 = Controls()
    sim = simulate_compromise(m, start, c0)
    iot = sorted(a for a, A in m["assets"].items() if A["category"] == "iot")
    truth = sorted(set(iot) & set(sim["compromised"]))
    rng = np.random.default_rng(404)
    W = 24
    base = {a: np.array([40 + 20 * rng.random(), 3 + 2 * rng.random(), 0.2, 0.9]) for a in iot}     # kB out, distinct destinations, failed auth, periodicity
    data = {}
    for a in iot:
        X = base[a] + rng.normal(0, [4, 0.6, 0.15, 0.03], (W, 4))
        if a in truth:
            X[12:] += np.array([150, 9, 6, -0.5]) + rng.normal(0, [10, 1, 1, 0.05], (W - 12, 4))
        data[a] = np.clip(X, 0, None)
    train = np.vstack([data[a][:12] for a in iot])
    forest = IsolationForest(n_estimators=150, contamination=0.02, random_state=0).fit(train)
    score = {a: float((forest.predict(data[a][12:]) == -1).mean()) for a in iot}
    flagged = [a for a in iot if score[a] >= 0.5]
    clusters = {}
    if len(flagged) >= 2:
        F = np.array([data[a][12:].mean(0) for a in flagged])
        F = (F - train.mean(0)) / (train.std(0) + 1e-9)
        lab_ = DBSCAN(eps=4.0, min_samples=2).fit_predict(F)
        for a, l in zip(flagged, lab_):
            clusters.setdefault(int(l), []).append(a)
    tp = len(set(flagged) & set(truth))
    iso = Controls()
    iso.blocked_edges |= {e["id"] for e in m["edges"] if e.get("exists", True) and m["assets"][e["source"]]["category"] == "iot" and m["assets"][e["target"]]["category"] != "iot"}
    tl = [dict(t=0, type="traffic", asset=start, status="synthetic", synthetic=True, text="Synthetic: street-light gateway sends 4x its usual traffic to many new destinations")] + \
         [dict(t=2 * i, type="traffic", asset=a, status="synthetic", synthetic=True, text=f"Synthetic: {m['assets'][a]['name']} shows the same abnormal traffic pattern") for i, a in enumerate(truth[1:], 1)]
    eff = dict(devices=len(iot), truly_affected=truth, flagged_by_detector=flagged, detector=dict(method="IsolationForest on 12 normal windows", precision=round(tp / max(1, len(flagged)), 2), recall=round(tp / max(1, len(truth)), 2)),
               anomaly_share={a: round(s, 2) for a, s in score.items()}, clusters={str(k): v for k, v in clusters.items()}, plausible_downstream=[a for a in sim["compromised"][1:] if a not in iot],
               isolate_iot_segment=dict(links_closed=len(iso.blocked_edges), reached_after=simulate_compromise(m, start, iso)["compromised"][1:]))
    ins = [f"The detector flags {len(flagged)} of {len(iot)} devices; {tp} of {len(truth)} truly affected devices are found.", "Affected devices cluster together, so one segment-level isolation covers them.",
           "Isolating the IoT segment closes its links into office IT, the historian and control systems."]
    return _finish(lab, "iot_compromise", "Smart-city IoT compromise",
                   ["Traffic is generated with a fixed seed: 24 hourly windows per device, abnormal from window 12 on for devices the simulation says an attacker can reach.", "Features: kB out, distinct destinations, failed logins, periodicity.", "Detector is trained on the 12 normal windows only."],
                   dict(attacker_start=start, windows=W), tl, eff, start, c0, (), (), ins,
                   add=[("segmentation", f"Isolate the IoT segment ({len(iso.blocked_edges)} links into other zones)", 4, lambda x, ids=set(iso.blocked_edges): x.blocked_edges.update(ids))])


def hospital_incident(lab):
    m, start = lab.model, "BMS_KEM"
    c0 = Controls()
    sim = simulate_compromise(m, start, c0)
    inbound = simulate_compromise(m, "INTERNET", c0)
    loss = service_loss(m, sim["compromised"], lab.impact_fn)
    hosp = lab.rt.ward["physical"]["H1"]
    tl = [dict(t=0, type="access", asset=start, status="synthetic", synthetic=True, text="Synthetic: building-management console opened from an unfamiliar address at 02:40"),
          dict(t=2, type="access", asset=start, status="synthetic", synthetic=True, text="Synthetic: 11 configuration reads in 3 minutes (usual: 1 per day)"),
          dict(t=4, type="access", asset="VPN_VENDOR", status="synthetic", synthetic=True, text="Synthetic: vendor VPN session active at the same time")] + _tl_from_sim(m, sim, 6)
    guard = lab.protect_target("BMS_KEM", c0)
    eff = dict(entry_paths_plausible=inbound["paths"].get("BMS_KEM"), inbound_protection=guard, reachable_from_bms=sim["compromised"][1:], services_lost=loss["services"], loss=round(loss["loss"], 1),
               high_value_dependency=dict(service="KEM Hospital water supply", beds=hosp.get("beds"), depends_on=["BMS_KEM", "PLC_V2", "PLC_PS2"]), dependents=dependents(m, "PLC_PS2"))
    ins = ["The hospital's building system is the last step: its risk is driven by what depends on it, not only by its own CVSS.", "Restricting who can reach the BMS and watching its access events protects the highest-value dependency."]
    return _finish(lab, "hospital_incident", "Hospital network incident",
                   ["Hospital BMS console credentials are misused (hypothetical).", "KEM Hospital (1,800 beds) depends on the BMS for water isolation valves.", "Access-event anomalies are generated, not observed."],
                   dict(compromised_start=start, anomaly=0.9), tl, eff, start, c0, (), (), ins, assumed=sim["compromised"])


RUNNERS = dict(vendor_credential=vendor_credential, ransomware_monitoring=ransomware_monitoring, controller_exposure=controller_exposure, iot_compromise=iot_compromise, hospital_incident=hospital_incident)


def run_scenario(lab, sid):
    if sid not in RUNNERS:
        raise KeyError(sid)
    lab.require_ready()
    return RUNNERS[sid](lab)
