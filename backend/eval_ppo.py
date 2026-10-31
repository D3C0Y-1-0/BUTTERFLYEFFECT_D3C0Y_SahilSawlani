"""Rigorous evaluation of the PPO zero-day responder on HELD-OUT products (experiments E15 and E16).

1. Model selection on a VALIDATION set of scenarios (candidates: the newly trained policy and the previous one).
2. Final numbers on a separate TEST set: matched scenarios per policy (same zero-day product, entry, goal, stealth for every policy),
   paired differences with bootstrap 95% confidence intervals (outage costs are heavy-tailed, so means alone mislead).

Usage: python backend/eval_ppo.py [test_episodes]
Writes data/ppo_eval.json and merges E15/E16 into data/experiments.json. Targets: experiments/targets.md.
"""
import json
import shutil
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from decoy.city import DATA, build_ward  # noqa: E402
from decoy.physics import Physics  # noqa: E402
from decoy.rl import PPO, RLCore, ZDEnv, run_policy  # noqa: E402
from decoy.threat import ThreatModel  # noqa: E402
from decoy.zeroday import Library, split_products  # noqa: E402


def run_set(core, env, test_p, seeds, policies, ppo):
    out = {k: [] for k in policies}
    for i, sd in enumerate(seeds):
        prod = test_p[i % len(test_p)]
        for name in policies:
            env.reset(seed=sd, product=prod, lib=Library())
            out[name].append(run_policy(core, env, name, ppo=ppo, search=core.healer))
    return out


def boot_ci(diff, n=3000, seed=0):
    rng = np.random.default_rng(seed)
    d = np.asarray(diff, float)
    m = [rng.choice(d, len(d)).mean() for _ in range(n)]
    return float(d.mean()), float(np.percentile(m, 2.5)), float(np.percentile(m, 97.5))


def summarize(rs):
    f = lambda k: float(np.mean([r[k] for r in rs]))
    tot = np.array([r["total"] for r in rs])
    return dict(n=len(rs), mean_total=float(tot.mean()), median_total=float(np.median(tot)), stderr=float(tot.std(ddof=1) / np.sqrt(len(tot))), mean_service=f("service"), mean_ops=f("ops"),
                contained=f("contained"), acted=f("acted"), devices_cut=f("devices_cut"), hosp_h=f("hosp_h"))


def main(n=300):
    W = build_ward(); P = Physics(W); T = ThreatModel(W, P, 1500, 7)
    core = RLCore(W, T, P)
    core.healer.allow_decoy = False
    train_p, test_p = split_products(W)
    env = ZDEnv(core, seed=0, train_products=test_p, lib_prob=0.0)
    cands = {p.stem.replace("ppo_policy_", ""): p for p in sorted(DATA.glob("ppo_policy_*.pt"))}
    if (DATA / "ppo_policy.pt").exists():
        cands["current"] = DATA / "ppo_policy.pt"
    t0 = time.time()
    # ---- model selection on validation scenarios
    val = {}
    for name, path in cands.items():
        ppo, _ = PPO.load(path)
        rs = run_set(core, env, test_p, [20000 + i for i in range(100)], ["ppo"], ppo)["ppo"]
        val[name] = float(np.mean([r["total"] for r in rs]))
        print("validation", name, round(val[name]), flush=True)
    best = min(val, key=val.get)
    if cands[best] != DATA / "ppo_policy.pt":
        shutil.copy(cands[best], DATA / "ppo_policy.pt")
        cj = DATA / f"ppo_train_{best}.json"
        if cj.exists():
            shutil.copy(cj, DATA / "ppo_train.json")
    ppo, meta = PPO.load(DATA / "ppo_policy.pt")
    # ---- final test
    policies = ["none", "iso_all", "search", "ppo"]
    out = run_set(core, env, test_p, [9000 + i for i in range(n)], policies, ppo)
    names = {"none": "No response", "iso_all": "Isolate everything", "search": "Search Healer", "ppo": "PPO responder"}
    pol = {names[k]: summarize(v) for k, v in out.items()}
    tot = {k: np.array([r["total"] for r in v]) for k, v in out.items()}
    paired = {}
    for other in ("search", "none", "iso_all"):
        m, lo, hi = boot_ci(tot["ppo"] - tot[other])
        paired[f"PPO minus {names[other]}"] = dict(mean_diff=m, ci95=[lo, hi])
    modes = {}
    for name in ("search", "ppo"):
        for r in out[name]:
            modes.setdefault(r["mode"], {}).setdefault(name, []).append(r["total"])
    modes = {m: {k: round(float(np.mean(v))) for k, v in d.items()} for m, d in modes.items()}
    acts = {}
    for r in out["ppo"]:
        for a in r["actions"]:
            k = a.split(" in front")[0].split(" from the")[0][:48]
            acts[k] = acts.get(k, 0) + 1
    # ---- E16: repeat encounter (identical scenario, only the library differs)
    first, second, learned = [], [], 0
    for i in range(60):
        prod = test_p[i % len(test_p)]
        lib = Library()
        env.reset(seed=7000 + i, product=prod, lib=lib)
        r1 = run_policy(core, env, "ppo", ppo=ppo); first.append(r1["total"]); learned += int(r1["learned"])
        env.reset(seed=7000 + i, product=prod, lib=env.lib)
        second.append(run_policy(core, env, "ppo", ppo=ppo)["total"])
    md, lo, hi = boot_ci(np.array(second) - np.array(first), seed=1)
    e16 = dict(first_encounter=float(np.mean(first)), repeat_encounter=float(np.mean(second)), diff=md, ci95=[lo, hi], learned_in_first_pct=100 * learned / 60, n=60)

    sp, pp, no, iso = pol["Search Healer"], pol["PPO responder"], pol["No response"], pol["Isolate everything"]
    clauses = dict(cheaper_than_search=bool(pp["mean_total"] < sp["mean_total"]), cheaper_than_no_response=bool(pp["mean_total"] < no["mean_total"]),
                   contains_more_than_search=bool(pp["contained"] > sp["contained"]), fewer_devices_than_isolate_all=bool(pp["devices_cut"] < iso["devices_cut"]))
    e15_ok = all(clauses.values())
    ev = dict(policies=pol, paired=paired, clauses=clauses, held_out_products=test_p, train_products=train_p, episodes=n, by_mode=modes, ppo_actions=dict(sorted(acts.items(), key=lambda kv: -kv[1])[:10]),
              validation=val, selected=best, e16=e16, default_responder=("ppo" if pp["mean_total"] <= sp["mean_total"] * 1.10 else "search"),
              generated=time.strftime("%Y-%m-%d %H:%M:%S"), train_meta=dict(iters=meta["iters"], steps=meta["steps"]))
    (DATA / "ppo_eval.json").write_text(json.dumps(ev, indent=1), encoding="utf-8")
    ex = json.loads((DATA / "experiments.json").read_text(encoding="utf-8")) if (DATA / "experiments.json").exists() else {}
    ex["E15"] = dict(claim="PPO responder handles held-out zero-day products better than the search Healer and no response", target="lower mean total cost than both, larger contained share than search, fewer devices cut than isolate-everything",
                     result=dict(policies=pol, paired=paired, clauses=clauses, by_mode=modes, episodes=n, held_out_products=test_p, selected=best), met=bool(e15_ok))
    ex["E16"] = dict(claim="The zero-day library speeds up the second encounter", target="repeat-encounter cost lower than first-encounter cost", result=e16, met=bool(e16["repeat_encounter"] < e16["first_encounter"]))
    (DATA / "experiments.json").write_text(json.dumps(ex, indent=1, default=float), encoding="utf-8")
    for k, v in pol.items():
        print(f"{k:20s} total {v['mean_total']:8.0f} +-{v['stderr']:.0f} median {v['median_total']:6.0f} service {v['mean_service']:7.0f} ops {v['mean_ops']:6.0f} contained {v['contained']:.2f} devices cut {v['devices_cut']:.1f}")
    for k, v in paired.items():
        print(k, "mean diff", round(v["mean_diff"]), "CI95", [round(x) for x in v["ci95"]])
    print("clauses", clauses, "| E16", {k: (round(v, 1) if isinstance(v, float) else v) for k, v in e16.items() if k != "ci95"}, "ci", [round(x) for x in e16["ci95"]])
    print("PPO actions:", ev["ppo_actions"], "| selected:", best, "| total", round(time.time() - t0), "s")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 300)
