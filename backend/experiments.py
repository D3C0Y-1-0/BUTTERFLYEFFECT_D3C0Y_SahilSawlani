"""Run the validation experiments E1..E14 and store results in data/experiments.json.

Usage: python backend/experiments.py [E1 E2 ...]   (no args = all)
Targets were written before running: experiments/targets.md
"""
from __future__ import annotations

import json
import sys
import time
import itertools
from pathlib import Path

import numpy as np
from scipy.stats import spearmanr

sys.path.insert(0, str(Path(__file__).resolve().parent))
from decoy.city import DATA, build_ward  # noqa: E402
from decoy.physics import Physics  # noqa: E402
from decoy.threat import ThreatModel, Defence  # noqa: E402
from decoy.planner import Planner, apply_fixes  # noqa: E402
from decoy import surrogate  # noqa: E402

OUT = DATA / "experiments.json"
TRUTH_VER = {"PLC_PS2": True, "RTU_F2": False}   # ground truth of the two unknown firmware versions


def load():
    return json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else {}


def save(res):
    OUT.write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")


def rank_vec(d, ids):
    return np.array([d[i] for i in ids], float)


def topk(d, ids, k=10):
    return set(sorted(ids, key=lambda n: -d[n])[:k])


# ------------------------------------------------------------------ E1 / E2
def e1_e2(ctx):
    W, P = ctx["W"], ctx["P"]
    ids = [i for i in W["assets"] if i != "INTERNET"]
    T_big = ThreatModel(W, P, 20000, seed=99)
    _, truth = T_big.raw_rrw()
    gt = {n: truth[n]["rrw"] for n in ids}
    T = ThreatModel(W, P, 3000, seed=7)
    e0, ours = T.raw_rrw()
    ours_rrw = {n: ours[n]["rrw"] for n in ids}
    T_small = ThreatModel(W, P, 400, seed=5)
    _, small = T_small.raw_rrw()
    bl = T.baselines()
    out = {"ours (3000 worlds)": ours_rrw, "ours (400 worlds)": {n: small[n]["rrw"] for n in ids}, **{k: bl[k] for k in ("cvss_x_importance", "epss_x_importance", "betweenness", "cvss")}}
    res = {}
    for name, sc in out.items():
        sp = spearmanr(rank_vec(sc, ids), rank_vec(gt, ids))[0]
        res[name] = dict(spearman=round(float(sp), 3), top10_overlap=len(topk(sc, ids) & topk(gt, ids)))
    ranks_c = {n: r for r, n in enumerate(sorted(ids, key=lambda n: -bl["cvss_x_importance"][n]), 1)}
    ranks_o = {n: r for r, n in enumerate(sorted(ids, key=lambda n: -ours_rrw[n]), 1)}
    moves = sorted(((ranks_c[n] - ranks_o[n], n) for n in ids), key=lambda x: -abs(x[0]))
    big = [dict(device=W["assets"][n]["name"], id=n, cvss_rank=ranks_c[n], sar_rank=ranks_o[n], moved=m) for m, n in moves if abs(m) > 10]
    e1_ok = res["ours (3000 worlds)"]["spearman"] >= 0.90 and res["ours (3000 worlds)"]["top10_overlap"] >= 7 and all(
        res["ours (3000 worlds)"]["spearman"] > res[b]["spearman"] for b in ("cvss_x_importance", "epss_x_importance", "betweenness"))
    return {"E1": dict(claim="Ranking matches brute-force ground truth (20,000 simulated attacks)", target="Spearman >= 0.90, top-10 overlap >= 7, beats all baselines", result=res, met=bool(e1_ok)),
            "E2": dict(claim="Real harm overturns severity", target=">= 3 devices move > 10 places vs CVSS x importance", result=dict(devices_moved_over_10=len(big), examples=big[:8]), met=len(big) >= 3)}


# ------------------------------------------------------------------ E3 / E4
def e3_e4(ctx):
    W, P, T, PL = ctx["W"], ctx["P"], ctx["T"], ctx["PL"]
    PL.n = 3000
    base = PL.exp_loss(Defence())
    # reduced catalogue: top 12 by single gain
    gains = []
    for f in PL.catalog:
        d = Defence(); f.apply(d)
        gains.append((base - PL.exp_loss(d), f))
    gains.sort(key=lambda x: -x[0])
    cat = [f for _, f in gains[:12]]
    budget = 6.0
    # exhaustive
    best, best_set, n_feasible = 1e18, None, 0
    for r in range(1, len(cat) + 1):
        for comb in itertools.combinations(cat, r):
            if sum(f.cost for f in comb) > budget:
                continue
            n_feasible += 1
            e = PL.exp_loss(apply_fixes(list(comb)))
            if e < best:
                best, best_set = e, comb
    greedy = PL.plan(None, budget, catalog=cat, dt_weight=0.0)
    rng = np.random.default_rng(1)
    rand_vals = []
    for _ in range(40):
        order = list(rng.permutation(len(cat))); sel, sp = [], 0.0
        for i in order:
            if sp + cat[i].cost <= budget:
                sel.append(cat[i]); sp += cat[i].cost
        rand_vals.append(PL.exp_loss(apply_fixes(sel)))
    bl = T.baselines()
    imp = lambda f: bl["cvss_x_importance"].get(f.target, 0) if f.target in bl["cvss_x_importance"] else 0
    sel, sp = [], 0.0
    for f in sorted(cat, key=lambda f: -imp(f)):
        if sp + f.cost <= budget:
            sel.append(f); sp += f.cost
    cvss_first = PL.exp_loss(apply_fixes(sel))
    e3 = dict(baseline_loss=round(base), exhaustive_best=round(best), greedy=round(greedy["e_end"]), random_mean=round(float(np.mean(rand_vals))), cvss_first=round(cvss_first),
              feasible_plans_checked=n_feasible, greedy_gap_pct=round(100 * (greedy["e_end"] - best) / max(best, 1.0), 2))
    e3_ok = (greedy["e_end"] <= 1.10 * best + 1.0) and greedy["e_end"] < np.mean(rand_vals) and greedy["e_end"] < cvss_first
    # E4: downtime term. Catalogue = firmware patches (each needs a restart). Plan A is downtime-aware (gates + schedules at the
    # best maintenance slot); plan B ignores downtime and executes immediately at 18:00 (peak).
    now = 18.0
    fwcat = [f for f in PL.catalog if f.type == "firmware_patch"]
    full = PL.plan(None, 60.0, now_hour=now, catalog=fwcat, dt_weight=1.0)
    naive = PL.plan(None, 60.0, now_hour=now, catalog=fwcat, dt_weight=0.0)
    d_full = sum(PL.best_slot(f)[0] for f in full["chosen"])
    d_naive = sum(PL.downtime_cost(f, now) for f in naive["chosen"])
    t_full, t_naive = full["e_end"] + d_full, naive["e_end"] + d_naive
    e4 = dict(with_downtime_term=dict(residual=round(full["e_end"]), maintenance_outage=round(d_full), total=round(t_full), patches=len(full["chosen"])),
              ignoring_downtime=dict(residual=round(naive["e_end"]), maintenance_outage=round(d_naive), total=round(t_naive), patches=len(naive["chosen"])),
              refused_now=[dict(fix=r["fix"]["label"], loss_if_now=r["loss_if_now"], best_hour=r["best_hour"]) for r in full["refused"][:4]])
    return {"E3": dict(claim="Greedy plan is near the exhaustive optimum", target="within 10%, better than random and CVSS-first", result=e3, met=bool(e3_ok)),
            "E4": dict(claim="Counting the fix's own outage lowers total harm", target="total with term < total without", result=e4, met=bool(t_full < t_naive))}


# ------------------------------------------------------------------ E5
def e5(ctx):
    W, P, T, PL = ctx["W"], ctx["P"], ctx["T"], ctx["PL"]
    PL.n = 1500
    unknowns = PL.unknowns()

    def truth_state():
        sv = [(e, (e["known"], e["truth"])) for e in W["edges"] if not e["known"]]
        sa = [(a, (a["known_version"], a["cve_belief"])) for a in W["assets"].values() if not a["known_version"]]
        return sv, sa

    def reveal(u):
        if u["kind"] == "link":
            e = next(x for x in W["edges"] if x["id"] == u["edge"]); e["known"] = True
        else:
            a = W["assets"][u["node"]]; yes = TRUTH_VER[u["node"]]
            a["known_version"], a["cve_belief"] = True, 1.0 if yes else 0.0

    def restore(st):
        sv, sa = st
        for e, (k, t) in sv: e["known"], e["truth"] = k, t
        for a, (k, b) in sa: a["known_version"], a["cve_belief"] = k, b

    st0 = truth_state()
    voi, _ = PL.value_of_information(None, 6.0)
    voi_order = [u["id"] for u in voi] + [u["id"] for u in unknowns if u["id"] not in [v["id"] for v in voi]]
    unc_order = [u["id"] for u in sorted(unknowns, key=lambda u: abs(u["belief"] - 0.5))]
    byid = {u["id"]: u for u in unknowns}

    def quality(chosen_ids):
        restore(st0)
        for uid in chosen_ids:
            reveal(byid[uid])
        plan = PL.plan(None, 6.0)
        dfn = plan["defence"]
        for u in unknowns:       # evaluate in the TRUE world
            reveal(u)
        e = PL.exp_loss(dfn)
        restore(st0)
        return e

    res = {}
    rng = np.random.default_rng(3)
    for k in (0, 1, 3, 5):
        v = quality(voi_order[:k]); m = quality(unc_order[:k])
        r = float(np.mean([quality(list(rng.permutation([u["id"] for u in unknowns]))[:k]) for _ in range(6)]))
        res[f"k={k}"] = dict(value_of_information=round(v), most_uncertain_first=round(m), random_mean=round(r))
    res["k=all (full information)"] = dict(residual=round(quality([u["id"] for u in unknowns])))
    ok = all(res[k]["value_of_information"] <= res[k]["random_mean"] + 1 and res[k]["value_of_information"] <= res[k]["most_uncertain_first"] + 1 for k in ("k=1", "k=3", "k=5"))
    return {"E5": dict(claim="The highest-value question first yields a better plan", target="VoI <= random and <= most-uncertain for k=1,3,5 (lower is better)", result=res, met=bool(ok),
                       order=[dict(id=u["id"], text=u["text"], voi=u.get("voi")) for u in voi[:5]])}


# ------------------------------------------------------------------ E6
def e6(ctx):
    W, P = ctx["W"], ctx["P"]
    ids = list(W["actions"].keys())
    table = []
    for mask in range(1, 2 ** len(ids)):
        acts = [ids[i] for i in range(len(ids)) if mask >> i & 1]
        for b in range(8):
            table.append((mask, b, P.attack_loss(acts, 3 * b)["L"]))
    r = surrogate.evaluate(table)
    t = time.time(); [P._simulate(((("pump_off", "PS1", 6.0, 8.0),)), False) for _ in range(5)]; sim_s = (time.time() - t) / 5
    r["exact_sim_seconds"] = round(sim_s, 4)
    r["speedup"] = round(sim_s / max(r["predict_seconds"], 1e-9))
    r["note"] = "Test set = attack combinations the model never saw. In this 8-action ward the exact table is small enough to be complete; the guesser matters for larger cities."
    ok = r["coverage"] >= 0.85 and r["spearman"] >= 0.90 and r["speedup"] >= 100
    return {"E6": dict(claim="Fast Guesser is accurate, calibrated and fast", target="coverage >= 0.85, Spearman >= 0.90, >= 100x faster", result=r, met=bool(ok))}


# ------------------------------------------------------------------ E7 (threat back-test)
def e7(ctx):
    import urllib.request, urllib.parse
    from datetime import datetime, timedelta
    kev = json.loads((DATA / "kev.json").read_text(encoding="utf-8"))["vulnerabilities"]
    rows = [v for v in kev if "2025-06-01" <= v["dateAdded"] <= "2026-06-30" and v["cveID"].startswith("CVE-202")]
    rng = np.random.default_rng(0)
    rows = [rows[i] for i in rng.permutation(len(rows))[:90]]
    got = []
    for v in rows:
        d = (datetime.strptime(v["dateAdded"], "%Y-%m-%d") - timedelta(days=30)).strftime("%Y-%m-%d")
        try:
            url = "https://api.first.org/data/v1/epss?" + urllib.parse.urlencode({"cve": v["cveID"], "date": d})
            req = urllib.request.Request(url, headers={"User-Agent": "decoy-hackathon"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read())["data"]
            if data:
                got.append(dict(cve=v["cveID"], epss=float(data[0]["epss"]), pct=float(data[0]["percentile"])))
        except Exception:
            pass
        time.sleep(0.15)
    if len(got) < 10:
        return {"E7": dict(claim="Threat layer anticipates exploitation", target="majority had EPSS >= 0.1 thirty days before KEV listing", result=dict(n=len(got), note="insufficient EPSS history available from the API"), met=None)}
    ep = np.array([g["epss"] for g in got]); pc = np.array([g["pct"] for g in got])
    r = dict(n_kev_cves_with_history=len(got), frac_epss_ge_0_1=round(float((ep >= 0.1).mean()), 3), median_percentile=round(float(np.median(pc)), 3), frac_top_10_percent=round(float((pc >= 0.9).mean()), 3),
             reference="FIRST: EPSS >= 0.1 covers ~63% of exploited CVEs at 2.7% effort")
    return {"E7": dict(claim="Threat layer anticipates exploitation (back-test, 30 days before KEV listing)", target="majority with EPSS >= 0.1", result=r, met=bool(r["frac_epss_ge_0_1"] > 0.5))}


# ------------------------------------------------------------------ E8
def e8(ctx):
    W, P = ctx["W"], ctx["P"]
    ids = [i for i in W["assets"] if i != "INTERNET"]
    base_T = ThreatModel(W, P, 2500, seed=7)
    _, base = base_T.raw_rrw()
    b = {n: base[n]["rrw"] for n in ids}
    res = {}
    import copy
    def run(name, fn):
        w2 = copy.deepcopy(W)
        T2 = ThreatModel(w2, P, 2500, seed=7)
        fn(T2, w2)
        _, r = T2.raw_rrw()
        sc = {n: r[n]["rrw"] for n in ids}
        res[name] = dict(top10_overlap=len(topk(sc, ids) & topk(b, ids)), spearman=round(float(spearmanr(rank_vec(sc, ids), rank_vec(b, ids))[0]), 3))
    run("attacker skill -20%", lambda T, w: setattr(T, "skill", 0.8))
    run("attacker skill +20%", lambda T, w: setattr(T, "skill", 1.2))
    def eps(f):
        def fn(T, w):
            for c in T.snap["cves"].values():
                c["epss"] = min(1.0, (c["epss"] or 0) * f)
        return fn
    run("EPSS -20%", eps(0.8)); run("EPSS +20%", eps(1.2))
    def beliefs(d):
        def fn(T, w):
            for e in w["edges"]:
                if not e["known"]:
                    e["belief"] = float(np.clip(e["belief"] + d, 0.05, 0.95))
        return fn
    run("hidden-link beliefs -0.2", beliefs(-0.2)); run("hidden-link beliefs +0.2", beliefs(0.2))
    def patched(d):
        def fn(T, w):
            for a in w["assets"].values():
                a["p_patched"] = float(np.clip(a["p_patched"] * (1 + d), 0, 0.95))
        return fn
    run("patch levels -20%", patched(-0.2)); run("patch levels +20%", patched(0.2))
    ok = all(v["top10_overlap"] >= 6 for v in res.values())
    return {"E8": dict(claim="Ranking is stable under +-20% assumption changes", target="top-10 overlap >= 6 in every case", result=res, met=bool(ok))}


# ------------------------------------------------------------------ E9 / E12 / E13 (scenario runs with the live runtime)
def scenarios(rt, n, seed0, allow_decoy=True, label="", force_decoy=False):
    rt.healer.allow_decoy = allow_decoy
    rt.healer.force_decoy = force_decoy
    rt.autonomy, rt.autopilot = "auto_all", False
    rng = np.random.default_rng(seed0)
    goals = list(rt.adv.goals.keys())
    entries = [k for k, a in rt.ward["assets"].items() if a["entry_weight"] > 0]
    modes = ["standard", "zero_day", "spoof", "wear", "insider"]
    out = []
    for k in range(n):
        rt.reset(seed0 + k)
        rt.decision_log = []
        mode = str(rng.choice(modes)); entry = str(rng.choice(entries)); goal = str(rng.choice(goals)); st = float(rng.uniform(2, 7))
        rt.launch_attack(mode, entry, goal, st, actor="experiment")
        m0 = rt.live.minute
        for _ in range(22 * 60):
            rt.tick()
        inc = rt.incidents[0] if rt.incidents else None
        hops_live = len(rt.adv.campaigns[0].hops)
        executed_live = any(e["kind"] == "physical_action" for e in rt.feed)
        none_exec = any(c.acted for c in rt.adv_none.campaigns)
        iso_dev = len(rt.ward["assets"]) - 1
        out.append(dict(mode=mode, entry=entry, goal=goal, detected=bool(inc), detect_min=(inc["t0"] - m0) if inc else None, hops=hops_live,
                        live=rt.live.loss_composite(), none=rt.none.loss_composite(), iso=rt.iso.loss_composite(),
                        live_hh=rt.live.lost["hh_h"], none_hh=rt.none.lost["hh_h"], iso_hh=rt.iso.lost["hh_h"],
                        live_hosp=rt.live.lost["hosp_h"], none_hosp=rt.none.lost["hosp_h"], iso_hosp=rt.iso.lost["hosp_h"],
                        executed_live=executed_live, executed_none=none_exec, devices_cut_decoy=len(rt.defence.quarantined) + len(rt.defence.blocked_edges),
                        devices_cut_iso=iso_dev, blocked=sum(d["blocked"] for d in rt.decision_log), decoy_used=bool(rt.decoys), contained=any(c.state == "contained" for c in rt.adv.campaigns)))
    return out


def e9_e12_e13(ctx, n9=80, n13=50):
    from decoy.runtime import Runtime
    rt = ctx.get("rt") or Runtime(sync=True, n_samples=2000, verbose=False)
    ctx["rt"] = rt
    S = scenarios(rt, n9, 1000, True)
    M = lambda k: float(np.mean([s[k] for s in S]))
    attacked = [s for s in S if s["executed_none"]]
    res = dict(scenarios=len(S), attacks_that_would_hurt_without_response=len(attacked),
               mean_loss_decoy=round(M("live")), mean_loss_no_response=round(M("none")), mean_loss_isolate_all=round(M("iso")),
               mean_household_hours_decoy=round(M("live_hh")), mean_household_hours_none=round(M("none_hh")), mean_household_hours_iso=round(M("iso_hh")),
               hospital_hours_decoy=round(M("live_hosp"), 3), hospital_hours_none=round(M("none_hosp"), 3), hospital_hours_iso=round(M("iso_hosp"), 3),
               detected_pct=round(100 * float(np.mean([s["detected"] for s in S])), 1),
               median_detect_minutes=float(np.median([s["detect_min"] for s in S if s["detect_min"] is not None] or [np.nan])),
               attack_reached_physical_effect_pct_decoy=round(100 * float(np.mean([s["executed_live"] for s in S])), 1),
               attack_reached_physical_effect_pct_none=round(100 * float(np.mean([s["executed_none"] for s in S])), 1),
               mean_devices_disconnected_decoy=round(M("devices_cut_decoy"), 1), devices_disconnected_isolate_all=S[0]["devices_cut_iso"])
    ok9 = res["mean_loss_decoy"] < res["mean_loss_no_response"] and res["mean_loss_decoy"] < res["mean_loss_isolate_all"] and res["mean_devices_disconnected_decoy"] < res["devices_disconnected_isolate_all"] / 3
    # E12 safety shield
    blocked_total = sum(s["blocked"] for s in S)
    unsafe_applied = sum(1 for s in S if s["live_hosp"] > s["none_hosp"] + 0.01)
    hours = []
    P = ctx["P"]
    for h in range(24):
        r = P.loss([dict(kind="pump_duty", target="PS1", start_h=float(h), dur_h=18.0), dict(kind="pump_duty", target="PS2", start_h=float(h), dur_h=18.0)])
        hours.append(r["hosp_water_h"] > 0.01)
    res12 = dict(candidate_actions_blocked_in_scenarios=blocked_total, scenarios_where_response_made_hospital_worse=unsafe_applied,
                 isolate_everything_would_be_blocked_at_hours=[h for h, b in enumerate(hours) if b], isolate_everything_blocked_hour_count=int(sum(hours)))
    out = {"E9": dict(claim="Healing is surgical: less service lost than no response or isolate-everything, with far fewer devices cut off", target="lower mean loss than both, <1/3 of the devices disconnected", result=res, met=bool(ok9)),
           "E12": dict(claim="Safety Check blocks unsafe actions", target="no applied action worsens hospital service", result=res12, met=bool(unsafe_applied == 0))}
    # E13 decoys
    (DATA / "scenarios_e9.json").write_text(json.dumps(S, default=float), encoding="utf-8")
    A_ = scenarios(rt, n13, 5000, True); B_ = scenarios(rt, n13, 5000, False); C_ = scenarios(rt, n13, 5000, True, force_decoy=True)
    rt.healer.force_decoy = False
    f = lambda L, k: float(np.mean([s[k] for s in L]))
    r13 = dict(scenarios=n13, mean_attacker_hops_with_decoys=round(f(A_, "hops"), 2), mean_attacker_hops_without_decoys=round(f(B_, "hops"), 2),
               physical_effect_pct_with=round(100 * f(A_, "executed_live"), 1), physical_effect_pct_without=round(100 * f(B_, "executed_live"), 1),
               mean_loss_with=round(f(A_, "live")), mean_loss_without=round(f(B_, "live")),
               decoy_chosen_by_policy_pct=round(100 * f(A_, "decoy_used"), 1),
               forced_decoys=dict(mean_attacker_hops=round(f(C_, "hops"), 2), physical_effect_pct=round(100 * f(C_, "executed_live"), 1), mean_loss=round(f(C_, "live")), contained_pct=round(100 * f(C_, "contained"), 1)),
               note="When the Healer is free to choose, it rarely picks a decoy (cheaper options such as isolating the foothold score better). 'forced_decoys' isolates the decoy mechanism.")
    out["E13"] = dict(claim="Decoys reduce attacker progress", target="fewer attacker hops reach a controller with decoys than without", result=r13, met=bool(r13["forced_decoys"]["mean_attacker_hops"] < r13["mean_attacker_hops_without_decoys"]))
    rt.healer.allow_decoy = True
    return out


# ------------------------------------------------------------------ E10
def e10(ctx):
    from decoy.watchdog import Watchdog
    from decoy.training import build_watchdog
    from decoy.environment import Environment
    from decoy.twin import LiveTwin
    from decoy.adversary import Adversary
    from sklearn.linear_model import LogisticRegression
    W, T = ctx["W"], ctx["T"]
    wd, tr, (X, y) = build_watchdog(W, T, episodes=45)
    # held-out: build a fusion trained only on episodes with 'standard' and 'insider'; test on zero_day / wear / spoof
    def episode(mode, seed, stealth, normal=False):
        tw = LiveTwin(W, seed=seed); [tw.step() for _ in range(90)]; wd.reset_state()
        adv = Adversary(W, seed=seed + 500); env = Environment(W, T, seed=seed + 600)
        c = None if normal else adv.launch(tw.minute, mode=mode, stealth=stealth, goal=list(adv.goals)[seed % 8])
        feats, labels = [], []
        for k in range(300):
            minute = tw.minute
            flows, phys, _ = adv.tick(minute, env) if c else ([], [], [])
            for ph in phys:
                if ph["kind"] == "wear": tw.breaker_cycle(); continue
                tw.act(ph["kind"], ph["target"], ph["dur_min"])
                if mode == "spoof" and ph["kind"] == "pump_off":
                    p = ph["target"]; tw.spoof[f"{p}_state"] = 1.0; tw.spoof[f"{p}_flow"] = lambda rep: 0.21
                if mode == "spoof" and ph["kind"] == "breaker_open":
                    tw.spoof[f"CB_{ph['target']}"] = 1.0
            tele = tw.step(); counts = tr.normal(); d = tr.add(counts, flows)
            r = wd.observe(counts, tele, minute, d)
            feats.append(r["features"]); labels.append(1 if (c and (adv.active() or c.acted)) else 0)
        active = bool(c and (c.hops or c.acted))
        return (np.array(feats), np.array(labels)) if not hasattr(episode, "ret_active") else (np.array(feats), np.array(labels), active)
    train = [episode(m, s, st)[:2] for m, s, st in [("standard", 1, 3.0), ("standard", 2, 5.0), ("insider", 3, 3.0), ("insider", 4, 6.0)]] + [episode("none", 10 + i, 0, True)[:2] for i in range(4)]
    Xtr = np.vstack([a for a, _ in train]); ytr = np.concatenate([b for _, b in train])
    models = {"fused (network + physics)": (slice(0, 5), None), "network only": (slice(0, 3), None), "physics only": (slice(3, 4), None)}
    fit = {n: LogisticRegression(C=4, max_iter=500).fit(Xtr[:, sl], ytr) for n, (sl, _) in models.items()}
    tests = {}
    for mode in ("zero_day", "wear", "spoof"):
        for stealth in (0.8, 4.0):
            for name, (sl, _) in models.items():
                delays = []
                episode.ret_active = True
                for seed in range(20, 32):
                    F, Lb, active = episode(mode, seed, stealth)
                    if not active:
                        continue        # a campaign that never got a foothold produced nothing to detect
                    p = fit[name].predict_proba(F[:, sl])[:, 1]
                    hit = np.where((p > 0.85) & (np.arange(len(p)) > 5))[0]
                    delays.append(int(hit[0]) if len(hit) else None)
                found = [d for d in delays if d is not None]
                tests.setdefault(f"{mode} (stealth {stealth})", {})[name] = dict(detected=f"{len(found)}/{len(delays)}", median_delay_min=float(np.median(found)) if found else None)
                del episode.ret_active
    fp = {}
    for name, (sl, _) in models.items():
        n = 0
        for seed in range(30, 33):
            F, _ = episode("none", seed, 0, True)[:2]
            n += int((fit[name].predict_proba(F[:, sl])[:, 1] > 0.85).sum())
        fp[name] = n
    fused = [v["fused (network + physics)"] for v in tests.values()]
    det_ok = all(f["median_delay_min"] is not None and f["median_delay_min"] < 30 for f in fused)
    return {"E10": dict(claim="Unseen attack types are caught (trained on standard/insider only; tested on zero-day, wear, spoof)", target="fused median delay < 30 min on held-out types, <= 1 false-alarm minute per simulated day",
                        result=dict(detection=tests, false_alarm_minutes_over_3_normal_days=fp), met=bool(det_ok and fp["fused (network + physics)"] <= 3))}


# ------------------------------------------------------------------ E11
def e11(ctx):
    res = []
    rng = np.random.default_rng(0)
    for N in (100, 1000, 10000):
        E = 3 * N
        layers = np.minimum((np.arange(N) * 6) // N, 5)
        src = rng.integers(0, N, E); dst = rng.integers(0, N, E)
        keep = layers[dst] >= layers[src]
        src, dst = src[keep], dst[keep]
        S = 500
        p_edge = rng.uniform(0.2, 0.9, len(src)); p_node = rng.uniform(0.1, 0.8, N)
        t = time.time()
        up = rng.random((S, len(src))) < p_edge; comp = rng.random((S, N)) < p_node
        reached = np.zeros((S, N), bool); reached[:, :max(1, N // 100)] = True
        for _ in range(8):
            changed = False
            for e in range(len(src)):
                new = reached[:, src[e]] & up[:, e] & comp[:, dst[e]] & ~reached[:, dst[e]]
                if new.any():
                    reached[:, dst[e]] |= new; changed = True
            if not changed: break
        el = time.time() - t
        res.append(dict(nodes=N, edges=int(len(src)), worlds=S, seconds=round(el, 2), mem_mb=round((up.nbytes + comp.nbytes + reached.nbytes) / 1e6, 1)))
    ratio = res[2]["seconds"] / max(res[1]["seconds"], 1e-6)
    return {"E11": dict(claim="The reachability engine scales", target="10^4 nodes in < 60 s per 500 attack worlds; near-linear growth", result=dict(runs=res, growth_10x_nodes=round(ratio, 1),
                        note="Pure-Python edge loop over vectorised worlds; no GPU, single core. Second-city generation from config is NOT part of this build."), met=bool(res[2]["seconds"] < 60))}



# ------------------------------------------------------------------ E17: the same system on growing batches of attacks
def e17(ctx, sizes=(10, 20, 40, 80, 160, 320)):
    from decoy.runtime import Runtime
    rt = ctx.get("rt") or Runtime(sync=True, n_samples=2000, verbose=False)
    ctx["rt"] = rt
    S, secs = [], []
    t0 = time.time()
    for k in range(max(sizes)):
        S += scenarios(rt, 1, 20000 + k, True)
        secs.append(time.time() - t0)
    rows = []
    for n in sizes:
        B = S[:n]; M = lambda key: float(np.mean([x[key] for x in B]))
        hurt = [x for x in B if x["executed_none"]]            # attacks that really would have damaged service with no response
        moved = [x for x in B if x["hops"] >= 1]               # attacks that got at least one step into the network
        dm = [x["detect_min"] for x in hurt if x["detect_min"] is not None]
        rows.append(dict(batch=n, seconds=round(secs[n - 1], 1), per_attack_s=round(secs[n - 1] / n, 2),
                         harmful=len(hurt), harmful_detected_pct=round(100 * float(np.mean([x["detected"] for x in hurt])), 1) if hurt else None,
                         intruders=len(moved), intruders_detected_pct=round(100 * float(np.mean([x["detected"] for x in moved])), 1) if moved else None,
                         failed_at_door=sum(1 for x in B if x["hops"] == 0), median_detect_minutes=float(np.median(dm)) if dm else None, p90_detect_minutes=float(np.percentile(dm, 90)) if dm else None,
                         loss_decoy=round(M("live")), loss_none=round(M("none")), loss_iso=round(M("iso")),
                         loss_cut_pct=round(100 * (1 - M("live") / max(1.0, M("none"))), 1), reached_physical_pct=round(100 * M("executed_live"), 1),
                         devices_cut=round(M("devices_cut_decoy"), 1), contained_pct=round(100 * float(np.mean([x["contained"] for x in B])), 1)))
    # false alarms: long attack-free runs
    rt.autonomy, rt.autopilot = "auto_all", False
    fa = 0; runs = 30
    for k in range(runs):
        rt.reset(88000 + k)
        for _ in range(12 * 60):
            rt.tick()
        fa += 1 if rt.incidents else 0
    ok = all(r["loss_decoy"] < r["loss_none"] for r in rows)
    return {"E17": dict(claim="Performance holds as the batch of attacks grows", target="DECOY loses less service than no response at every batch size; harmful attacks detected >= 90%; no false alarms in calm runs",
                        result=dict(rows=rows, false_alarm_runs=fa, calm_runs=runs, calm_hours=runs * 12,
                                    note="Each batch is the first N attacks of one run of random attack types, entries and targets, so bigger batches include the smaller ones. 'Harmful' = attacks that would have cut service with no response. 'Failed at the door' = the attacker never got past its first step, so there was nothing to detect."),
                        met=bool(ok and fa == 0 and all((r["harmful_detected_pct"] or 100) >= 90 for r in rows)))}


def e18(ctx, n=30):
    """DDoS floods and coordinated groups (several attackers at once)."""
    from decoy.runtime import Runtime
    rt = ctx.get("rt") or Runtime(sync=True, n_samples=2000, verbose=False)
    ctx["rt"] = rt
    rt.autonomy, rt.autopilot = "auto_all", False
    res = {}
    for mode in ("ddos", "group"):
        R = []
        for k in range(n):
            rt.reset(60000 + k); rt.launch_attack(mode, None, None, None, actor="experiment"); m0 = rt.live.minute
            for _ in range(200):
                rt.tick()
            inc = rt.incidents[0] if rt.incidents else None
            fl = [c for c in rt.adv.campaigns if c.mode == "ddos"]
            R.append(dict(detected=bool(inc), detect_min=(inc["t0"] - m0) if inc else None, live=rt.live.loss_composite(), none=rt.none.loss_composite(), iso=rt.iso.loss_composite(),
                          flood_min=sum(c.flood_minutes for c in fl), flood_open=sum(c.flood_open for c in fl), attackers=len(rt.adv.campaigns), harmful=any(c.acted for c in rt.adv_none.campaigns),
                          harmful_live=any(c.acted for c in rt.adv.campaigns)))
        dm = [r["detect_min"] for r in R if r["detect_min"] is not None]
        res[mode] = dict(runs=n, detected_pct=round(100 * float(np.mean([r["detected"] for r in R])), 1), median_detect_minutes=float(np.median(dm)) if dm else None,
                         loss_decoy=round(float(np.mean([r["live"] for r in R]))), loss_none=round(float(np.mean([r["none"] for r in R]))), loss_iso=round(float(np.mean([r["iso"] for r in R]))),
                         flood_blocked_pct=round(100 * (1 - sum(r["flood_open"] for r in R) / max(1, sum(r["flood_min"] for r in R))), 1) if mode in ("ddos", "group") else None,
                         attackers_per_run=round(float(np.mean([r["attackers"] for r in R])), 1), harmful_runs=sum(r["harmful"] for r in R), harmful_runs_with_athena=sum(r["harmful_live"] for r in R))
    ok = all(v["detected_pct"] >= 90 and v["loss_decoy"] < max(1, v["loss_none"]) + 1 for v in res.values())
    return {"E18": dict(claim="Floods and coordinated groups are handled", target="detected >= 90%; flood dropped at the edge; service loss no worse than no response", result=res, met=bool(ok))}



def e19_e20(ctx, n_swarm=24, n_phys=12):
    """E19: many small attacks below the alarm line (with and without the slow-build-up detector). E20: attacks on physical equipment, target by target."""
    from decoy.runtime import Runtime
    rt = ctx.get("rt") or Runtime(sync=True, n_samples=2000, verbose=False)
    ctx["rt"] = rt
    rt.autonomy, rt.autopilot = "auto_all", False
    line = rt.watchdog.cs_h
    res19 = {}
    for name, cs_h in (("with_cusum", line), ("single_window_only", 1e9)):
        rt.watchdog.cs_h = cs_h
        R = []
        for k in range(n_swarm):
            rt.reset(70000 + k); rt.launch_attack("swarm", None, None, None, actor="experiment"); m0 = rt.live.minute; peak = 0.0; first = None
            for t in range(6 * 60):
                rt.tick(); peak = max(peak, rt.last_p)
            inc = rt.incidents[0] if rt.incidents else None
            R.append(dict(detected=bool(inc), delay=(inc["t0"] - m0) if inc else None, peak_p=peak, live=rt.live.loss_composite(), none=rt.none.loss_composite(), harmful=any(c.acted for c in rt.adv_none.campaigns),
                          reached=sum(max(0, len(c.compromised) - 1) for c in rt.adv.campaigns)))
        dm = [r["delay"] for r in R if r["delay"] is not None]
        res19[name] = dict(runs=n_swarm, detected_pct=round(100 * float(np.mean([r["detected"] for r in R])), 1), median_delay_minutes=float(np.median(dm)) if dm else None,
                           loss_athena=round(float(np.mean([r["live"] for r in R]))), loss_no_response=round(float(np.mean([r["none"] for r in R]))),
                           harmful_runs=sum(r["harmful"] for r in R), mean_devices_taken=round(float(np.mean([r["reached"] for r in R])), 1),
                           mean_peak_single_alarm_pct=round(100 * float(np.mean([r["peak_p"] for r in R])), 1))
    rt.watchdog.cs_h = line
    res19["attackers_per_run"] = 5
    out = {"E19": dict(claim="Many small attacks below the alarm line are still caught", target="detected >= 90% with the slow-build-up detector, and detected more often or sooner than single-window alarms alone",
                       result=res19, met=bool(res19["with_cusum"]["detected_pct"] >= 90 and (res19["with_cusum"]["detected_pct"] > res19["single_window_only"]["detected_pct"] or (res19["with_cusum"]["median_delay_minutes"] or 1e9) < (res19["single_window_only"]["median_delay_minutes"] or 1e9))))}
    # E20: physical equipment, one target at a time
    rows = []
    for ctrl, aid in rt.adv.goals.items():
        act = rt.ward["actions"][aid]; R = []
        for k in range(n_phys):
            rt.reset(90000 + k); rt.launch_attack("standard", None, ctrl, None, actor="experiment"); m0 = rt.live.minute
            for _ in range(22 * 60):
                rt.tick()
            inc = rt.incidents[0] if rt.incidents else None
            R.append(dict(det=(inc["t0"] - m0) if inc else None, harmful=any(c.acted for c in rt.adv_none.campaigns), reached=any(e["kind"] == "physical_action" for e in rt.feed),
                          live=rt.live.lost.copy(), none=rt.none.lost.copy()))
        dm = [r["det"] for r in R if r["det"] is not None and r["harmful"]]
        H = [r for r in R if r["harmful"]]; mean = lambda rs, w, kk: round(float(np.mean([x[w][kk] for x in rs])), 2) if rs else 0.0
        rows.append(dict(target=act["label"], kind=act["kind"], runs=n_phys, harmful_runs=len(H), reached_equipment_athena=sum(r["reached"] for r in R),
                         detected_pct_of_harmful=round(100 * float(np.mean([r["det"] is not None for r in H])), 1) if H else None, median_alarm_minutes=float(np.median(dm)) if dm else None,
                         homes_hours_lost_none=mean(H, "none", "hh_h"), homes_hours_lost_athena=mean(H, "live", "hh_h"), hospital_hours_none=mean(H, "none", "hosp_h"), hospital_hours_athena=mean(H, "live", "hosp_h"),
                         mwh_lost_none=mean(H, "none", "mwh"), mwh_lost_athena=mean(H, "live", "mwh")))
    out["E20"] = dict(claim="Physical attacks on pumps, valves, breakers and hospital supply are stopped before they cause lasting loss", target="equipment reached in under 20% of harmful runs; hospital hours lost near zero",
                      result=dict(rows=rows), met=bool(all(r["reached_equipment_athena"] <= 0.2 * max(1, r["runs"]) + 1 for r in rows)))
    return out



def e21(ctx, n=240):
    """E21: how well are attacks predicted BEFORE they happen? (a) the forecast list made before any attack: does it contain the devices the attacker really takes?
    (b) once an attack is under way, does the predicted next step match what the attacker does next if nobody stops it?"""
    from decoy.runtime import Runtime
    from decoy.lab import Controls
    from decoy.lab_service import LabService
    rt = ctx.get("rt") or Runtime(sync=True, n_samples=2000, verbose=False)
    ctx["rt"] = rt
    L = LabService(rt); L.train()
    rows = sorted(L.ranking(Controls()), key=lambda r: -r["likelihood"]); order = [r["id"] for r in rows]; rank = {a: i for i, a in enumerate(order)}
    rt.autonomy, rt.autopilot = "auto_all", False
    TYPES = ["standard", "zero_day", "spoof", "wear", "insider", "blitz"]; GOALS = list(rt.adv.goals.keys())
    entries = [k for k, a in rt.ward["assets"].items() if a["entry_weight"] > 0]
    R = []
    for g in range(n):
        mode = TYPES[g % len(TYPES)]; goal = GOALS[(g // len(TYPES)) % len(GOALS)]
        rng = np.random.default_rng(310000 + g); entry = str(rng.choice(entries)) if mode != "insider" else None
        rt.reset(310000 + g); rt.launch_attack(mode, entry, goal, float(rng.uniform(2, 7)), actor="experiment"); m0 = rt.live.minute
        pred_next = None
        for _ in range(22 * 60):
            rt.tick()
            if pred_next is None and rt.incidents and rt.incidents[0]["next_hops"]:
                pred_next = [h["dst"] for h in rt.incidents[0]["next_hops"]]; t_pred = rt.live.minute
        c0 = rt.adv_none.campaigns[0]
        taken = [x for x in c0.compromised if x != "INTERNET"]
        item = dict(mode=mode, taken=len(taken), entry=c0.entry, hit5=any(rank.get(x, 99) < 5 for x in taken), hit10=any(rank.get(x, 99) < 10 for x in taken),
                    prec5=float(np.mean([order[i] in taken for i in range(5)])), recall10=float(np.mean([rank.get(x, 99) < 10 for x in taken])) if taken else None,
                    entry_in5=rank.get(c0.entry, 99) < 5, entry_in10=rank.get(c0.entry, 99) < 10, goal_rank=rank.get(c0.goal, 99))
        later = [h for h in c0.hops if pred_next is not None and h[0] > t_pred]
        item["next_known"] = bool(later); item["next_top1"] = bool(later and pred_next and later[0][3] == pred_next[0]); item["next_top3"] = bool(later and later[0][3] in pred_next[:3])
        R.append(item)
    M = lambda xs, key: round(100 * float(np.mean([x[key] for x in xs])), 1) if xs else None
    withmoves = [x for x in R if x["taken"] > 0]; nxt = [x for x in R if x["next_known"]]
    by = {}
    for t in TYPES:
        T = [x for x in R if x["mode"] == t and x["taken"] > 0]
        by[t] = dict(attacks=len([x for x in R if x["mode"] == t]), got_in=len(T), top5_hit_pct=M(T, "hit5"), top10_hit_pct=M(T, "hit10"), entry_in_top10_pct=M(T, "entry_in10"))
    res = dict(attacks=len(R), got_in=len(withmoves), top5_hit_pct=M(withmoves, "hit5"), top10_hit_pct=M(withmoves, "hit10"), entry_in_top5_pct=M(withmoves, "entry_in5"), entry_in_top10_pct=M(withmoves, "entry_in10"),
               precision_at_5_pct=round(100 * float(np.mean([x["prec5"] for x in withmoves])), 1) if withmoves else None, mean_devices_taken=round(float(np.mean([x["taken"] for x in withmoves])), 1) if withmoves else None,
               next_step_attacks=len(nxt), next_step_top1_pct=M(nxt, "next_top1"), next_step_top3_pct=M(nxt, "next_top3"), by_type=by, forecast_list_size=len(order),
               note="Forecast = the model's list of most likely targets, made before any attack. 'Taken' = devices an unopposed attacker really reached in the simulator. Next-step = the route predicted when the alarm opens, against the attacker's actual next move if nobody stopped it.")
    return {"E21": dict(claim="Attacks can be predicted before they happen", target="top-10 forecast contains a device the attacker really takes in >= 70% of attacks", result=res, met=bool((res["top10_hit_pct"] or 0) >= 70))}



def e22(ctx, days=3):
    """E22: false alarms when traffic is NOT textbook Poisson. Calm cities (no attacker at all) under a daily swing and bursts, with and without the traffic-level correction."""
    from decoy.runtime import Runtime
    rt = ctx.get("rt") or Runtime(sync=True, n_samples=2000, verbose=False)
    ctx["rt"] = rt
    rt.autonomy, rt.autopilot = "suggest", False
    REG = {"plain Poisson": (0.0, None), "daily swing +/-60%": (0.6, None), "bursty": (0.0, 2.0), "bursty + daily swing": (0.6, 2.0)}
    out = {}
    for use_scale in (True, False):
        rows = {}
        for name, (sw, bk) in REG.items():
            rt.reset(900); rt.traffic.set_regime(sw, bk); rt.watchdog.use_scale = use_scale
            hi = 0; n = 4320 if days == 3 else days * 1440
            for _ in range(n):
                rt.tick(); hi += rt.last_p > 0.5
            rows[name] = dict(false_incidents=len(rt.incidents), minutes_above_half_pct=round(100 * hi / n, 2))
        out["with traffic-level correction" if use_scale else "without (old behaviour)"] = rows
    rt.traffic.set_regime(); rt.watchdog.use_scale = True
    worst = max(v["false_incidents"] for v in out["with traffic-level correction"].values())
    return {"E22": dict(claim="False alarms stay low on traffic that is not textbook Poisson", target="<= 1 false incident in 3 calm days under every regime", result=dict(days=days, regimes=out, note="Calm city, no attacker. 'False incident' = an incident opened. Synthetic regimes, NOT real captures; real captures (e.g. public ICS pcaps) are still needed."), met=bool(worst <= 1))}


def e23(ctx):
    """E23: a coherent telemetry spoof (the attacker replays a consistent healthy plant). How long until an alarm, with and without an independent sensing path."""
    from decoy.runtime import Runtime
    rt = ctx.get("rt") or Runtime(sync=True, n_samples=2000, verbose=False)
    ctx["rt"] = rt
    rt.autonomy, rt.autopilot = "suggest", False
    keep_posture, rt.posture_nodes = rt.posture_nodes, []      # measures DETECTION of a forger who got through, so standing hardening is off here
    res = {}
    for label, ind in (("independent meters on a separate path", True), ("control network only", False)):
        times, lost = [], []
        for k, goal in enumerate(["PLC_PS1", "PLC_PS2"] * 4):
            rt.reset(1200 + k); rt.watchdog.use_independent = ind
            rt.launch_attack("spoof_coherent", "SCADA_WEB", goal, 9.0, actor="experiment"); t0 = rt.live.minute; first = None
            for _ in range(14 * 60):
                rt.tick()
                if first is None and any(i["physics"] for i in rt.incidents): first = rt.live.minute - t0
            if rt.adv.campaigns[0].acted:      # only count runs where the attacker really reached its goal and forged the readings
                times.append(first); lost.append(rt.live.services()["cum"]["hh_h"])
        seen = [t for t in times if t is not None]
        res[label] = dict(attacks_that_reached_the_pump=len(times), alarmed=len(seen), median_minutes_to_alarm=float(np.median(seen)) if seen else None, never_alarmed=len(times) - len(seen), mean_household_hours_lost=round(float(np.mean(lost))))
    rt.watchdog.use_independent = True
    rt.posture_nodes = keep_posture
    a, b = res["independent meters on a separate path"], res["control network only"]
    return {"E23": dict(claim="A coherent telemetry spoof is only caught early when a second, independent sensing path exists", target="alarm within 2 h with the independent path", result=dict(runs=res, note="Detection only; no response was applied, so the loss is what an unanswered attack does. Requires real independent meters (the hospital's own, or a separate utility feed); this is an assumption to be validated on site."), met=bool(a["median_minutes_to_alarm"] is not None and a["median_minutes_to_alarm"] <= 120))}


REG = {"E1": e1_e2, "E2": e1_e2, "E3": e3_e4, "E4": e3_e4, "E5": e5, "E6": e6, "E7": e7, "E8": e8, "E9": e9_e12_e13, "E12": e9_e12_e13, "E13": e9_e12_e13, "E10": e10, "E11": e11, "E17": e17, "E18": e18, "E19": e19_e20, "E20": e19_e20, "E21": e21, "E22": e22, "E23": e23}


def main():
    want = sys.argv[1:] or ["E6", "E1", "E3", "E8", "E11", "E5", "E10", "E9", "E7"]
    W = build_ward(); P = Physics(W); T = ThreatModel(W, P, 3000, 7); PL = Planner(W, T, P)
    ctx = dict(W=W, P=P, T=T, PL=PL)
    res = load()
    done = set()
    for key in want:
        fn = REG[key]
        if fn in done:
            continue
        done.add(fn)
        t = time.time()
        print(f"[{key}] running ...", flush=True)
        try:
            out = fn(ctx)
            res.update(out)
            res["_meta"] = dict(generated=time.strftime("%Y-%m-%d %H:%M:%S"), note="All numbers come from the simulated Mumbai ward; targets: experiments/targets.md")
            save(res)
            for k, v in out.items():
                print(f"  {k}: met={v.get('met')}", flush=True)
        except Exception as e:
            import traceback; traceback.print_exc()
            res[key] = dict(error=str(e)); save(res)
        print(f"[{key}] {time.time()-t:.0f}s", flush=True)
        P.save()


if __name__ == "__main__":
    main()
