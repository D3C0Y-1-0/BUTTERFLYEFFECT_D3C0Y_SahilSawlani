"""Bigger-data training, hyperparameter tuning, validation and overfitting audit for the risk (where-will-the-attack-land) model.

Usage: python backend/train_lab_v2.py [worlds] [configs_per_world] [tuning_candidates]      (defaults 10 200 16)  ->  data/lab_v2_report.json

HONEST DATA STATEMENT
  Real inputs: CVSS, EPSS and KEV (NVD / FIRST / CISA snapshots) and the device inventory. Real attack-outcome data for a city does not exist anywhere, so the LABEL (share of
  simulated attack worlds in which a device falls) always comes from the Monte-Carlo threat model. The bigger dataset is made by "normalised jitter": every real input is perturbed
  in a normalised space (logit for probabilities, relative for weights, absolute for CVSS) by an amount taken from how much those inputs really vary, a new world is built from the
  perturbed inputs, and its label is RECOMPUTED by the threat model (labels are never noised directly). So the model learns the threat model's behaviour over a family of
  plausible worlds. It is a surrogate; it cannot be better than the simulator it imitates, and accuracy here is NOT real-world accuracy.

SPLITS (nothing leaks)
  - test_worlds: whole jittered worlds the model never saw, in any form (tests transfer to a new inventory)
  - test_configs: control configurations held out inside the training worlds (tests new defences on known worlds); includes the real, un-jittered world 0
  - tuning uses grouped k-fold on the training groups only; the test sets are touched once, at the end
"""
import copy
import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scipy.stats import spearmanr  # noqa: E402
from sklearn.ensemble import HistGradientBoostingRegressor  # noqa: E402
from sklearn.metrics import average_precision_score, mean_absolute_error, mean_squared_error, precision_recall_fscore_support, r2_score, roc_auc_score  # noqa: E402
from sklearn.model_selection import GroupKFold  # noqa: E402

from decoy.city import DATA, build_ward  # noqa: E402
from decoy.lab import FEATURES, Controls, asset_features, graph_features, model_from_ward, vec  # noqa: E402
from decoy.lab_service import to_defence  # noqa: E402
from decoy.physics import Physics  # noqa: E402
from decoy.threat import ThreatModel, load_snapshot  # noqa: E402

W = int(sys.argv[1]) if len(sys.argv) > 1 else 10
C = int(sys.argv[2]) if len(sys.argv) > 2 else 200
NCAND = int(sys.argv[3]) if len(sys.argv) > 3 else 16
MONO = [f[2] for f in FEATURES]
logit = lambda p: np.log(np.clip(p, 1e-4, 1 - 1e-4) / (1 - np.clip(p, 1e-4, 1 - 1e-4)))
expit = lambda z: 1 / (1 + np.exp(-z))


def jitter_world(ward, snap, rng, scale=1.0):
    """A plausible neighbouring world: every real input perturbed in a normalised space. scale=0 returns the real world."""
    w, s = copy.deepcopy(ward), copy.deepcopy(snap)
    for c in s["cves"].values():
        if c.get("epss") is not None:
            c["epss"] = float(expit(logit(c["epss"]) + rng.normal(0, 0.5 * scale)))
        if c.get("cvss") is not None:
            c["cvss"] = float(np.clip(c["cvss"] + rng.normal(0, 0.4 * scale), 0, 10))
    for a in w["assets"].values():
        a["p_weak"] = float(expit(logit(a["p_weak"]) + rng.normal(0, 0.35 * scale))) if 0 < a["p_weak"] < 1 else a["p_weak"]
        a["p_patched"] = float(expit(logit(a["p_patched"]) + rng.normal(0, 0.35 * scale))) if 0 < a["p_patched"] < 1 else a["p_patched"]
        a["entry_weight"] = float(a["entry_weight"] * np.exp(rng.normal(0, 0.25 * scale)))
    for e in w["edges"]:
        if 0 < e["p_access"] < 1:
            e["p_access"] = float(expit(logit(e["p_access"]) + rng.normal(0, 0.25 * scale)))
    return w, s


def make_world_rows(ward, snap, phys, world_id, n_configs, seed, n_worlds=1200):
    T = ThreatModel(ward, phys, n_samples=n_worlds, seed=seed)
    T.snap = snap
    model = model_from_ward(ward, snap)
    rng = np.random.default_rng(seed + 1)
    ids = [i for i in model["assets"] if i != "INTERNET"]
    X, y, g = [], [], []
    for v in range(n_configs):
        c, p = Controls(), (0.0 if v == 0 else float(rng.random()) * 0.4)
        for a in ids:
            r, A_ = rng.random(4), model["assets"][a]
            if r[0] < p and A_["vulns"]:
                c.vpatch.add(a)
            if r[1] < p * 0.5 and A_["vulns"]:
                c.patched.add(a)
            if r[2] < p and A_["p_weak"] > 0:
                (c.mfa if r[3] < 0.5 else c.harden).add(a)
        for e in model["edges"]:
            if rng.random() < p * 0.5:
                c.blocked_edges.add(e["id"])
        reached, _ = T.reach(to_defence(c), n=n_worlds)
        prop, gf = reached.mean(0), graph_features(model, c)
        for a in ids:
            X.append(vec(asset_features(model, a, c, _g=gf)))
            y.append(float(prop[T.idx[a]]))
            g.append(world_id * 100000 + v)
    return np.array(X), np.array(y), np.array(g)


def metrics(m, X, y, g, top_frac=0.10):
    pred = np.clip(m.predict(X), 0, 1)
    out = dict(rows=int(len(y)), mae=round(float(mean_absolute_error(y, pred)), 4), rmse=round(float(np.sqrt(mean_squared_error(y, pred))), 4), r2=round(float(r2_score(y, pred)), 4),
               spearman=round(float(spearmanr(pred, y)[0]), 4))
    # "high-risk device" = in the top 10% by simulated chance of falling (the label is tiny for most devices, so a fixed 30% line would mark almost nothing). The model flags its own top 10%.
    yb, pb = y >= np.quantile(y, 1 - top_frac), pred >= np.quantile(pred, 1 - top_frac)
    if yb.any() and (~yb).any():
        p_, r_, f_, _ = precision_recall_fscore_support(yb, pb, average="binary", zero_division=0)
        out.update(positive_rate=round(float(yb.mean()), 3), precision=round(float(p_), 4), recall=round(float(r_), 4), f1=round(float(f_), 4), auc=round(float(roc_auc_score(yb, pred)), 4), avg_precision=round(float(average_precision_score(yb, pred)), 4))
    hits = []
    for gid in np.unique(g):                  # per configuration: of the 5 devices most likely to fall, how many did the model also put in its top 5 (= precision@5 = recall@5)
        idx = np.where(g == gid)[0]
        if len(idx) >= 5:
            hits.append(len(set(np.argsort(-pred[idx])[:5]) & set(np.argsort(-y[idx])[:5])) / 5.0)
    out["top5_overlap"] = round(float(np.mean(hits)), 4) if hits else None
    return out


def mk(params, seed=0):
    return HistGradientBoostingRegressor(monotonic_cst=MONO, random_state=seed, **params)


V11 = dict(max_iter=500, learning_rate=0.04, max_depth=6, min_samples_leaf=8)


def main():
    t0 = time.time()
    ward = build_ward()
    phys = Physics(ward)
    snap = load_snapshot()
    rng = np.random.default_rng(2026)
    Xs, ys, gs, wid = [], [], [], []
    for w in range(W):
        wd, sn = (ward, snap) if w == 0 else jitter_world(ward, snap, rng)
        X, y, g = make_world_rows(wd, sn, phys, w, C, seed=100 + w)
        Xs.append(X); ys.append(y); gs.append(g); wid.append(np.full(len(y), w))
        print(f"world {w + 1}/{W}: {len(y)} rows, {time.time() - t0:.0f}s", flush=True)
    X, y, g, wid = np.vstack(Xs), np.concatenate(ys), np.concatenate(gs), np.concatenate(wid)
    cfg = g % 100000

    # ---- splits
    test_worlds = {W - 2, W - 1} if W >= 5 else set()
    in_tw = np.isin(wid, list(test_worlds))
    rest = ~in_tw
    ug = np.unique(g[rest])
    held = set(rng.choice(ug, size=len(ug) // 5, replace=False).tolist())
    in_tc = np.array([gg in held for gg in g]) & rest
    tr = rest & ~in_tc
    real_tc = in_tc & (wid == 0)
    print(f"train {tr.sum()} rows | test_configs {in_tc.sum()} (real world: {real_tc.sum()}) | test_worlds {in_tw.sum()}", flush=True)

    # ---- baselines on the SAME tests
    small = tr & (wid == 0) & (cfg < 260)                        # what v1.1 had: the real world only, 260 configurations
    base_small = mk(V11).fit(X[small], y[small])
    cvss_col = [f[0] for f in FEATURES].index("cvss")
    cvss_rank = lambda idx: dict(spearman=round(float(spearmanr(X[idx][:, cvss_col], y[idx])[0]), 4))
    # ---- tuning: grouped CV on training groups only
    space = dict(learning_rate=[0.02, 0.04, 0.06, 0.1], max_depth=[4, 6, 8, None], min_samples_leaf=[8, 20, 50, 120], l2_regularization=[0.0, 0.1, 1.0, 10.0], max_leaf_nodes=[15, 31, 63], max_iter=[200, 400, 800])
    cand = [V11] + [{k: v[int(rng.integers(len(v)))] for k, v in space.items()} for _ in range(NCAND - 1)]
    gkf = GroupKFold(n_splits=3)
    tri = np.where(tr)[0]
    rows = []
    for ci, p in enumerate(cand):
        maes, rhos = [], []
        for a, b in gkf.split(tri, groups=g[tri]):
            pp = dict(p, early_stopping=True, validation_fraction=0.1, n_iter_no_change=15) if ci else p
            m = mk(pp).fit(X[tri[a]], y[tri[a]])
            pr = np.clip(m.predict(X[tri[b]]), 0, 1)
            maes.append(mean_absolute_error(y[tri[b]], pr)); rhos.append(spearmanr(pr, y[tri[b]])[0])
        rows.append(dict(params=p, cv_mae=round(float(np.mean(maes)), 4), cv_spearman=round(float(np.mean(rhos)), 4), cv_mae_sd=round(float(np.std(maes)), 4)))
        print(f"tune {ci + 1}/{len(cand)} mae {rows[-1]['cv_mae']} rho {rows[-1]['cv_spearman']}  ({time.time() - t0:.0f}s)", flush=True)
    best = min(range(len(rows)), key=lambda i: (rows[i]["cv_mae"], -rows[i]["cv_spearman"]))
    bp = dict(cand[best])
    final_p = dict(bp, early_stopping=True, validation_fraction=0.1, n_iter_no_change=15) if best else dict(bp)

    # ---- final fits (train only), then the test sets are touched once
    v11_big = mk(V11).fit(X[tr], y[tr])
    tuned = mk(final_p).fit(X[tr], y[tr])
    report = dict(config=dict(worlds=W, configs_per_world=C, tuning_candidates=len(cand), rows_total=int(len(y)), train_rows=int(tr.sum()), seed=2026),
                  data_statement="Real inputs: NVD/EPSS/KEV + inventory. Labels: Monte-Carlo threat model (synthetic). Augmentation: normalised jitter of the real inputs, labels recomputed. Surrogate accuracy, not real-world accuracy.",
                  tuning=sorted(rows, key=lambda r: r["cv_mae"]), chosen=bp, chosen_was_baseline_params=best == 0)
    sets = dict(test_configs=in_tc, test_configs_real_world_only=real_tc, test_worlds=in_tw)
    res = {}
    for name, idx in sets.items():
        if not idx.any():
            continue
        res[name] = {"A. v1.1 (real world, 260 configs)": metrics(base_small, X[idx], y[idx], g[idx]), "B. v1.1 settings on the big data": metrics(v11_big, X[idx], y[idx], g[idx]),
                     "C. tuned on the big data": metrics(tuned, X[idx], y[idx], g[idx]), "baseline: CVSS only": cvss_rank(idx)}
    report["test"] = res
    # ---- overfitting audit
    report["overfitting"] = dict(train=metrics(tuned, X[tr], y[tr], g[tr]), cv_mean_mae=rows[best]["cv_mae"], cv_mae_sd=rows[best]["cv_mae_sd"], test_configs=res.get("test_configs", {}).get("C. tuned on the big data"),
                                 test_worlds=res.get("test_worlds", {}).get("C. tuned on the big data"), iterations_used=int(getattr(tuned, "n_iter_", 0)))
    lc = []
    tidx = np.where(tr)[0]
    for frac in (0.1, 0.25, 0.5, 1.0):
        sub = rng.choice(tidx, size=int(len(tidx) * frac), replace=False)
        m = mk(final_p).fit(X[sub], y[sub])
        lc.append(dict(train_fraction=frac, train_rows=int(len(sub)), train_mae=metrics(m, X[sub], y[sub], g[sub])["mae"], test_configs_mae=metrics(m, X[in_tc], y[in_tc], g[in_tc])["mae"],
                       test_worlds_mae=metrics(m, X[in_tw], y[in_tw], g[in_tw])["mae"] if in_tw.any() else None))
    report["learning_curve"] = lc
    a, c_ = res["test_configs_real_world_only"]["A. v1.1 (real world, 260 configs)"], res["test_configs_real_world_only"]["C. tuned on the big data"]
    report["verdict"] = dict(better_mae=c_["mae"] < a["mae"], better_spearman=c_["spearman"] >= a["spearman"], better_top5=(c_["top5_overlap"] or 0) >= (a["top5_overlap"] or 0), real_world_mae_before=a["mae"], real_world_mae_after=c_["mae"])
    report["seconds"] = round(time.time() - t0)
    (DATA / "lab_v2_report.json").write_text(json.dumps(report, indent=1, default=float), encoding="utf-8")
    (DATA / "lab_tuned_params.json").write_text(json.dumps(dict(params=final_p, trained_worlds=W, configs=C), default=float), encoding="utf-8")
    print(json.dumps(report["verdict"]), flush=True)


if __name__ == "__main__":
    main()
