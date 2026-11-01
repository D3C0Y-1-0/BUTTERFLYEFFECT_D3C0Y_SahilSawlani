"""Live flow detector for the two-laptop demo. It is the same method as the ATHENA Watchdog, re-used on real packet counts instead of simulated ones:

  1. learn what NORMAL looks like on this very laptop (nothing about any attack is hard-coded),
  2. per flow: rate z-score against the learned rate (variance = mu + 0.3 + (0.15 mu)^2), plus NOVELTY of a flow never seen in the baseline,
  3. an autoencoder over the whole window (reconstruction error = "this minute does not look like normal"),
  4. a logistic fusion of those signals, and CUSUM so that a small signal that keeps repeating adds up,
  5. an incident only after two windows in a row above 85%, exactly as in the simulator.

A "flow" is (source address, destination port, protocol) of UNSOLICITED traffic: connection attempts (SYN without ACK) and anything sent to a port this laptop is listening on.
Replies to this laptop's own browsing never count, so ordinary use is quiet by construction.

Honest limit: the fusion needs examples of "attack" windows. There is no labelled attack data for this laptop, so they are made by injecting synthetic floods and scans into this
laptop's own recorded normal windows (the real attacker on the other laptop is never seen in training).
"""
from __future__ import annotations

from collections import Counter

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPRegressor

ALARM_P, ALARM_RUN = 0.85, 2


def new_window():
    return dict(flows=Counter(), syn=0, total=0, data=0, replies=Counter())


def _vec(w):
    f = w["flows"]
    srcs = {k[0] for k in f}
    ports = {k[1] for k in f}
    mx = max(f.values()) if f else 0
    return np.array([np.log1p(w["total"]), np.log1p(w["syn"]), np.log1p(len(srcs)), np.log1p(len(ports)), np.log1p(mx), 0.0], float)


class FlowDetector:
    def __init__(self, learn_windows=90, seed=0):
        self.learn_windows, self.rng = learn_windows, np.random.default_rng(seed)
        self.base: list = []
        self.ready = False
        self.mu: dict = {}
        self.run = 0
        self.cs = 0.0
        self.last: dict = {}

    # ---------------------------------------------------------------- learning
    def learn(self, w) -> float:
        self.base.append(w)
        if len(self.base) >= self.learn_windows and not self.ready:
            self._fit()
        return min(1.0, len(self.base) / self.learn_windows)

    def _zs(self, w):
        out = {}
        for k, c in w["flows"].items():
            m = self.mu.get(k, 0.0)
            out[k] = (c - m) / np.sqrt(m + 0.3 + (0.15 * m) ** 2)
        return out

    def _signals(self, w):
        z = self._zs(w)
        zv = np.array(list(z.values()) or [0.0])
        nov = sum(1 for k, c in w["flows"].items() if self.mu.get(k, 0.0) < 0.02 and c >= 3)
        v = _vec(w)
        v[5] = nov
        x = ((v - self.v_mu) / self.v_sd)[None, :]
        ae = float(((x - self.ae.predict(x)) ** 2).sum()) / self.thr
        zsum = float(np.maximum(zv - 1.0, 0).sum())
        return z, np.array([min(ae, 50) / 10.0, np.log1p(max(float(zv.max()), 0)), min(nov, 10), np.log1p(zsum)]), ae, nov

    def _fit(self):
        cnt = Counter()
        seen = Counter()
        for w in self.base:
            for k, c in w["flows"].items():
                cnt[k] += c
                seen[k] += 1
        self.mu = {k: cnt[k] / len(self.base) for k in cnt}
        V = np.array([_vec(w) for w in self.base])
        for i, w in enumerate(self.base):
            V[i, 5] = sum(1 for k, c in w["flows"].items() if self.mu.get(k, 0) < 0.02 and c >= 3)
        self.v_mu, self.v_sd = V.mean(0), np.maximum(V.std(0), 0.35)
        X = (V - self.v_mu) / self.v_sd
        self.ae = MLPRegressor(hidden_layer_sizes=(8, 3, 8), activation="tanh", max_iter=400, random_state=0, alpha=1e-3).fit(X, X)
        err = ((X - self.ae.predict(X)) ** 2).sum(1)
        self.thr = max(float(np.quantile(err, 0.995)) * 1.6, 4.0)          # floor: one stray packet on an idle laptop must not look like an attack
        F, y = [], []
        for _ in range(500):                                               # normal windows, a third with a couple of stray packets
            w = self._copy(self.base[int(self.rng.integers(len(self.base)))])
            if self.rng.random() < 0.33:
                self._inject(w, "stray")
            F.append(self._signals(w)[1]); y.append(0)
        for kind in ("flood", "scan", "burst"):                            # synthetic attack windows on top of this laptop's own normal windows
            for _ in range(250):
                w = self._copy(self.base[int(self.rng.integers(len(self.base)))])
                self._inject(w, kind)
                F.append(self._signals(w)[1]); y.append(1)
        F, y = np.array(F), np.array(y)
        self.fusion = LogisticRegression(C=4.0, class_weight={0: 4.0, 1: 1.0}, max_iter=800).fit(F, y)
        z0 = self.fusion.decision_function(F[y == 0])
        self.cs_k = float(z0.mean() + z0.std())
        s, mx = 0.0, 0.0
        for z in z0:
            s = max(0.0, 0.97 * s + float(z) - self.cs_k)
            mx = max(mx, s)
        self.cs_h = mx * 1.6 + 2.0
        self.calib = dict(normal_windows=len(self.base), known_flows=len(self.mu), ae_threshold=round(self.thr, 2), cusum_line=round(self.cs_h, 2), normal_max_p=round(float(1 / (1 + np.exp(-z0.max()))), 3))
        self.ready = True

    @staticmethod
    def _copy(w):
        return dict(flows=Counter(w["flows"]), syn=w["syn"], total=w["total"], data=w.get("data", 0), replies=Counter())

    def _inject(self, w, kind):
        r = self.rng
        src = f"192.168.{int(r.integers(0, 255))}.{int(r.integers(2, 250))}"
        if kind == "stray":
            for _ in range(int(r.integers(1, 3))):
                w["flows"][(src, int(r.integers(1024, 60000)), "tcp")] += 1
                w["syn"] += 1
                w["total"] += 1
        elif kind == "flood":                                              # many connection attempts at one port
            n = int(r.integers(15, 400))
            w["flows"][(src, 8080, "tcp")] += n
            w["syn"] += n
            w["total"] += n
        elif kind == "scan":                                               # one source touching many ports
            for p in r.choice(np.arange(1, 10000), size=int(r.integers(20, 300)), replace=False):
                w["flows"][(src, int(p), "tcp")] += 1
            n = sum(c for k, c in w["flows"].items() if k[0] == src)
            w["syn"] += n
            w["total"] += n
        elif kind == "burst":                                              # a heavy request burst at the service port
            n = int(r.integers(30, 400))
            w["flows"][(src, 8080, "tcp")] += n
            w["total"] += n

    # ---------------------------------------------------------------- detection
    def observe(self, w, learn_ok=True):
        z, F, ae, nov = self._signals(w)
        zf = float(self.fusion.decision_function(F[None, :])[0])
        p = float(1 / (1 + np.exp(-zf)))
        self.cs = max(0.0, 0.97 * self.cs + zf - self.cs_k)
        cusum_alarm = self.cs > self.cs_h
        if cusum_alarm:
            p = max(p, 0.9)
        self.run = self.run + 1 if p > ALARM_P else 0
        top = sorted(((k, w["flows"][k], round(float(v), 1)) for k, v in z.items()), key=lambda t: -t[2])[:5]
        if learn_ok and p < 0.05:                                          # learn only from windows that look normal, so an attacker cannot teach the model
            for k, c in w["flows"].items():
                self.mu[k] = 0.98 * self.mu.get(k, 0.0) + 0.02 * c
        self.last = dict(p=p, ae=ae, novelty=nov, zmax=max([t[2] for t in top] or [0]), cusum=self.cs, cusum_line=self.cs_h, alarm=self.run >= ALARM_RUN or cusum_alarm, cusum_alarm=cusum_alarm, top=top)
        return self.last
