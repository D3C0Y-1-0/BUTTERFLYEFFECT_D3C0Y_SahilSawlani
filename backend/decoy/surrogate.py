"""Fast Guesser: gradient-boosted estimator of service loss with split-conformal prediction intervals.

Features: which controllers/actions are hijacked (bit vector), start hour (sin/cos), number of actions.
Rule used by the Impact Simulator front-end: if the conformal interval is wide or the estimate is in the worst tail, run the
exact physics simulation instead (escalation).
"""
from __future__ import annotations

import json
import time

import numpy as np
from scipy.stats import spearmanr
from sklearn.ensemble import GradientBoostingRegressor


def featurise(mask, bucket, n_actions=8):
    bits = [(mask >> i) & 1 for i in range(n_actions)]
    h = 3 * bucket
    return bits + [np.sin(2 * np.pi * h / 24), np.cos(2 * np.pi * h / 24), sum(bits)]


class FastGuesser:
    def __init__(self, alpha=0.1, seed=0):
        self.alpha, self.seed = alpha, seed
        self.model = GradientBoostingRegressor(n_estimators=250, max_depth=4, learning_rate=0.08, random_state=seed)
        self.q = None

    @staticmethod
    def _y(L):
        return np.log1p(np.asarray(L, float))

    def fit(self, X_train, L_train, X_cal, L_cal):
        self.model.fit(X_train, self._y(L_train))
        res = np.abs(self._y(L_cal) - self.model.predict(X_cal))
        n = len(res)
        self.q = float(np.quantile(res, min(1.0, np.ceil((n + 1) * (1 - self.alpha)) / n)))   # split-conformal quantile (log space)
        return self

    def predict(self, X):
        mu = self.model.predict(X)
        return np.expm1(mu), np.expm1(np.maximum(mu - self.q, 0)), np.expm1(mu + self.q)

    def needs_exact(self, X, tail=60000.0, width=2.5):
        """Escalate to the full simulator when the estimate may be in the worst tail or the interval is wide."""
        p, lo, hi = self.predict(X)
        return (hi > tail) | ((hi + 1) / (lo + 1) > np.exp(width * 2))


def experiment(cache: dict, seed=0):
    """E6: train on 40% of the exact loss table, calibrate on 20%, test on 40% (unseen attack combinations)."""
    rows = []
    for k, v in cache.items():
        key = json.loads(k)
        # only attack-table entries (all events share a start hour, kinds from the action set)
        rows.append((key, v["L"]))
    # rebuild (mask,bucket) from keys is brittle; instead the experiment is run from runtime tables (see experiments.py)
    return rows


def evaluate(table, seed=0):
    """table: list of (mask, bucket, L). Returns metrics dict."""
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(table))
    n = len(idx)
    tr, ca, te = idx[: int(.4 * n)], idx[int(.4 * n): int(.6 * n)], idx[int(.6 * n):]
    X = np.array([featurise(m, b) for m, b, _ in table])
    L = np.array([l for _, _, l in table])
    g = FastGuesser(seed=seed).fit(X[tr], L[tr], X[ca], L[ca])
    t = time.time()
    p, lo, hi = g.predict(X[te])
    pred_t = (time.time() - t) / len(te)
    cover = float(np.mean((L[te] >= lo) & (L[te] <= hi)))
    worst = L[te] >= np.quantile(L[te], 0.9)
    esc = g.needs_exact(X[te])
    sp = float(spearmanr(p, L[te])[0])
    mae_log = float(np.mean(np.abs(np.log1p(p) - np.log1p(L[te]))))
    return dict(n_train=len(tr), n_cal=len(ca), n_test=len(te), spearman=round(sp, 3), coverage=round(cover, 3), target_coverage=0.9,
                mae_log=round(mae_log, 3), escalated_frac=round(float(esc.mean()), 3), worst10_escalated=round(float(esc[worst].mean()), 3), predict_seconds=pred_t)
