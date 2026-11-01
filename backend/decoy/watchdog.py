"""Watchdog: two detection cores plus a learned fusion.

Core A (network behaviour): per-flow rate z-scores, novelty of never-seen flows, and a small autoencoder trained on normal
industrial traffic (reconstruction error). Core B (physics): invariants that must hold in the plant (tank mass balance,
pump state vs flow, breaker vs bus voltage, breaker wear, uncommanded valve/breaker moves, controller contradicting its own
logic). Fusion = logistic regression trained on labelled simulated episodes. Online learning only on verified-normal windows.
"""
from __future__ import annotations

from collections import deque

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPRegressor

from .assumptions import A
from .twin import LiveTwin


import os
CS_K_SD, CS_H_MUL, CS_H_ADD = float(os.environ.get("ATHENA_CS_K", 1.0)), float(os.environ.get("ATHENA_CS_MUL", 1.6)), float(os.environ.get("ATHENA_CS_ADD", 2.0))


class Traffic:
    """Normal OT/IT traffic generator + flow-key feature space (every edge x read/write)."""

    def __init__(self, ward, seed=11):
        self.rng = np.random.default_rng(seed)
        self.edges = ward["edges"]
        self.E = len(self.edges)
        self.eidx = {e["id"]: i for i, e in enumerate(self.edges)}
        lam = np.zeros(2 * self.E)
        table = {
            ("SCADA_SRV", "PLC"): (60, 0.3), ("SCADA_SRV", "RTU"): (60, 0.04), ("HMI_01", "SCADA_SRV"): (8, 0.2), ("SCADA_SRV", "HMI_01"): (8, 0.0),
            ("HIST_01", "SCADA_SRV"): (4, 0.0), ("GW_METER_01", "HIST_01"): (20, 0.0), ("CCTV_01", "OFFICE_PC_03"): (30, 0), ("CCTV_02", "OFFICE_PC_03"): (30, 0),
            ("SCADA_WEB", "SCADA_SRV"): (3, 0), ("VPN_VENDOR", "JUMP_RDS"): (0.25, 0), ("VPN_VENDOR", "BMS_KEM"): (0.1, 0), ("VPN_VENDOR", "HIST_01"): (0.1, 0),
            ("JUMP_RDS", "SCADA_SRV"): (0.2, 0), ("JUMP_RDS", "ENG_WS"): (0.05, 0), ("FW_PERIM", "OFFICE_PC_01"): (6, 0), ("FW_PERIM", "OFFICE_PC_03"): (6, 0),
            ("OFFICE_PC_01", "JUMP_RDS"): (0.05, 0), ("MAIL_01", "OFFICE_PC_01"): (5, 0), ("MAIL_01", "OFFICE_PC_03"): (5, 0), ("OFFICE_PC_01", "OFFICE_PC_02"): (1, 0),
            ("OFFICE_PC_03", "OFFICE_PC_01"): (1, 0), ("SCADA_SRV", "ENG_WS"): (0.2, 0), ("ENG_WS", "SCADA_SRV"): (0.2, 0), ("EVC_01", "WIFI_PUB_01"): (3, 0),
            ("GW_LIGHT_01", "GW_LIGHT_02"): (4, 0), ("OFFICE_PC_02", "JUMP_RDS"): (0.05, 0),
            ("INTERNET", "MAIL_01"): (10, 0), ("INTERNET", "VPN_VENDOR"): (0.3, 0), ("INTERNET", "SCADA_WEB"): (1, 0), ("INTERNET", "EVC_01"): (2, 0),
            ("INTERNET", "WIFI_PUB_01"): (3, 0), ("INTERNET", "GW_LIGHT_01"): (2, 0), ("INTERNET", "GW_LIGHT_02"): (2, 0), ("INTERNET", "CCTV_01"): (0.5, 0),
            ("INTERNET", "CCTV_02"): (0.5, 0), ("INTERNET", "GW_METER_01"): (1, 0), ("INTERNET", "FW_PERIM"): (15, 0),
        }
        for i, e in enumerate(self.edges):
            s, d = e["source"], e["target"]
            for (ks, kd), (r, w) in table.items():
                if (s == ks or (ks == "SCADA_SRV" and False)) and (d == kd or (kd == "PLC" and d.startswith("PLC")) or (kd == "RTU" and d.startswith("RTU"))):
                    if s == ks:
                        lam[i], lam[self.E + i] = r, w
        self.lam = lam
        self.n_keys = 2 * self.E
        self.swing, self.burst_k, self.peak_h = 0.0, None, 14.0      # traffic regime: daily swing (+/- fraction), burstiness (smaller k = burstier), hour of the daily peak

    def set_regime(self, swing=0.0, burst_k=None, peak_h=14.0):
        """Real traffic is not stationary Poisson: it swings over the day and arrives in bursts. These knobs make the generator honest about that."""
        self.swing, self.burst_k, self.peak_h = float(swing), burst_k, float(peak_h)

    def normal(self, minute=None):
        lam = self.lam
        if self.swing and minute is not None:
            lam = lam * (1.0 + self.swing * np.sin(2 * np.pi * (minute / 60.0 - self.peak_h + 6.0) / 24.0))
        if self.burst_k:
            lam = lam * self.rng.gamma(self.burst_k, 1.0 / self.burst_k)      # one shared burst factor per minute (mean 1)
        return self.rng.poisson(lam).astype(float)

    def add(self, vec, flows):
        decoy = 0
        for eid, cls, cnt in flows:
            if eid.startswith("DECOY:"):
                decoy += cnt
                continue
            i = self.eidx.get(eid)
            if i is None:
                continue
            vec[i + (self.E if cls == "write" else 0)] += cnt
        return decoy


class Watchdog:
    def __init__(self, ward, traffic: Traffic, seed=0):
        self.ward, self.tr = ward, traffic
        self.rng = np.random.default_rng(seed)
        self.E = traffic.E
        self.mu = traffic.lam.copy()
        X = np.log1p(np.stack([traffic.normal() for _ in range(1500)]))
        self.ae = MLPRegressor(hidden_layer_sizes=(24, 8, 24), activation="tanh", max_iter=300, random_state=seed, alpha=1e-3)
        self.ae.fit(X, X)
        err = ((X - self.ae.predict(X)) ** 2).mean(axis=1)
        self.thr = float(np.quantile(err, 0.995)) * 1.6 + 1e-6
        zs0 = np.array([np.maximum((c - traffic.lam) / np.sqrt(traffic.lam + 0.3 + (0.15 * traffic.lam) ** 2) - 1.0, 0.0).sum() for c in (traffic.normal() for _ in range(600))])
        self.zs_mu, self.zs_sd = float(zs0.mean()), float(zs0.std() + 1e-6)         # what "a normal minute" looks like for the sum of small oddities
        self.sigma_tank = 0.03
        self.reset_state()
        self.fusion = None
        self.learn_buf = []
        self.drift_events = 0
        self.last_learn = 0
        self.name_of = {i: (e["source"], e["target"]) for i, e in enumerate(ward["edges"])}
        self.hosp_base = {h: v["beds"] * A("hospital_litres_per_bed_day") / 1000 / 86400 for h, v in ward["water"]["hospitals"].items()}
        self.demand_pattern = ward["water"]["demand_pattern"]

    # ---------------------------------------------------------------- state
    def reset_state(self):
        self.hist = deque(maxlen=40)
        self.cnt = dict(pump=0, tank=0, brk=0, logic=0)
        self.offset = getattr(self, "offset", 0.0)
        self.prev_cmd_state = None
        self.expected = {}      # tag -> minute until which a change is expected/authorised
        self.persist = {}
        self.tank_hist = {"T1": deque(maxlen=20), "T2": deque(maxlen=20)}
        self.scale = 1.0              # current overall traffic level relative to the learned normal (1.0 = as usual)
        self.cs = 0.0                 # CUSUM evidence: small, repeated signs add up until they cross a line
        self.ev_buf = deque(maxlen=25)

    def authorise(self, tag, minute, window=6):
        self.expected[tag] = minute + window

    def pattern_at(self, minute):
        h = (minute / 60.0) % 24
        i, f = int(h) % 24, h - int(h)
        p = self.demand_pattern
        return p[i] * (1 - f) + p[(i + 1) % 24] * f

    # ---------------------------------------------------------------- core B: physics invariants
    def physics(self, tele, minute):
        rep = tele["reported"]
        viol = []
        z = 0.0
        pl = self.persist
        def hit(key, cond, n, score, text, node):
            nonlocal z
            pl[key] = pl.get(key, 0) + 1 if cond else 0
            if pl[key] >= n:
                viol.append(dict(rule=key, text=text, score=score, node=node))
                z = max(z, score)
        # I1 pump status contradicts flow
        for p, node in (("PS1", "PLC_PS1"), ("PS2", "PLC_PS2")):
            hit(f"I1:{p}", abs(rep[f"{p}_state"] - (1.0 if rep[f"{p}_flow"] > 0.08 else 0.0)) > 0.5, 3, 9, f"{p} says '{'ON' if rep[p+'_state']>0.5 else 'OFF'}' but its flow meter disagrees", node)
        # I2 tank mass balance over 15 minutes (3-min smoothed level vs integrated reported flows)
        area = {"T1": 380.1, "T2": 452.4}
        for t, p, f, node in (("T1", "PS1", "FLOW_A", "PLC_PS1"), ("T2", "PS2", "FLOW_B", "PLC_PS2")):
            h = self.tank_hist[t]
            h.append((rep[f"{t}_level"], rep[f"{p}_flow"] - rep[f]))
            if len(h) >= 18:
                lv = [x[0] for x in h]
                now = np.mean(lv[-3:]); old = np.mean(lv[:3])
                span = len(h) - 3   # steps between the centres of the two 3-sample means
                pred = sum(x[1] for x in list(h)[2:2 + span]) * 60 / area[t]
                resid = (now - old) - pred
                zz = abs(resid) / 0.045
                hit(f"I2:{t}", zz > 6, 2, min(12.0, zz), f"{t} level is not consistent with the flows reported around it (off by {resid:+.2f} m): a reading is being faked", node)
        # I3 breaker vs bus voltage
        for f, node in (("F1", "RTU_F1"), ("F2", "RTU_F2"), ("F3", "RTU_F3")):
            hit(f"I3:{f}", abs(rep[f"CB_{f}"] - (1.0 if rep[f"BUS_{f}"] > 0.5 else 0.0)) > 0.5, 2, 9, f"Breaker {f} reported {'closed' if rep['CB_'+f]>0.5 else 'open'} but bus voltage says otherwise", node)
        # I4 breaker wear
        hit("I4:wear", rep["BRK_OPS_10M"] >= 4, 1, 10, "A breaker was operated 4+ times in 10 minutes (wear / sabotage pattern)", None)
        # I5 uncommanded valve/breaker change
        cur = {k: rep[k] for k in ("V1_pos", "V2_pos", "CB_F1", "CB_F2", "CB_F3")}
        if self.prev_cmd_state is not None:
            for k, v in cur.items():
                if abs(v - self.prev_cmd_state[k]) > 0.5 and self.expected.get(k, -1) < minute:
                    node = {"V1_pos": "PLC_V1", "V2_pos": "PLC_V2", "CB_F1": "RTU_F1", "CB_F2": "RTU_F2", "CB_F3": "RTU_F3"}[k]
                    viol.append(dict(rule=f"I5:{k}", text=f"{k.replace('_pos','')} changed without any operator command", score=8.0, node=node))
                    z = max(z, 8.0)
        self.prev_cmd_state = cur
        sticky = self.persist.setdefault("_sticky", {})
        for v in list(viol):
            if v["rule"].startswith("I5:"):
                sticky[v["rule"]] = (minute + 10, v)
        for key, (until, v) in list(sticky.items()):
            if until < minute:
                del sticky[key]
            elif not any(x["rule"] == key for x in viol):
                viol.append(v)
                z = max(z, v["score"])
        # I8 hospital receives (almost) no water although the network holds pressure
        hosp_node = {"H1": "BMS_KEM", "H2": None, "H3": None}
        tank_of = {"H1": "T2", "H2": "T2", "H3": "T1"}
        for h, node in hosp_node.items():
            exp = self.hosp_base[h] * self.pattern_at(minute)
            hit(f"I8:{h}", rep[f"{h}_FLOW"] < 0.3 * exp and rep[f"{tank_of[h]}_level"] > 3.5, 5, 9, f"{h} receives almost no water although the network has pressure: its supply was cut inside the hospital", node)
        # I9 / I10 the control network says one thing, the independent meters (separate path) say another: the control path is being lied to or has been taken over
        ind = tele.get("independent")
        if ind is not None and getattr(self, "use_independent", True):
            for t, node in (("T1", "PLC_PS1"), ("T2", "PLC_PS2")):
                hit(f"I9:{t}", abs(rep[f"{t}_level"] - ind[f"IND_{t}_level"]) > 0.4, 3, 9, f"{t} level reported by the control network differs by {rep[t+'_level']-ind['IND_'+t+'_level']:+.1f} m from the independent level sensor: the control readings are being faked", node)
            for h in ("H1", "H2", "H3"):
                exp = self.hosp_base[h] * self.pattern_at(minute)
                dq = self.persist.setdefault(f"_d{h}", deque(maxlen=15))     # one minute of meter noise is as big as the signal, so compare 15-minute averages
                dq.append(rep[f"{h}_FLOW"] - ind[f"IND_{h}_FLOW"])
                hit(f"I10:{h}", len(dq) == 15 and abs(float(np.mean(dq))) > max(0.5 * exp, 0.0007), 3, 9, f"{h} inlet flow reported by the control network disagrees with the hospital's own meter", {"H1": "BMS_KEM"}.get(h))
        # I7 controller contradicts its own control logic
        for p, t, node, f in (("PS1", "T1", "PLC_PS1", "F1"), ("PS2", "T2", "PLC_PS2", "F2")):
            hit(f"I7:{p}", rep[f"{p}_state"] < 0.5 and rep[f"{t}_level"] < 3.6 and rep[f"CB_{f}"] > 0.5, 4, 8, f"{p} is stopped while {t} is low: the controller is not following its own logic", node)
        return z, viol

    # ---------------------------------------------------------------- core A: network behaviour
    def _level(self, counts):
        """Overall traffic level, from the MEDIAN of the busy flows (an attack touches a few flows, so the median ignores it). Lets the detector tell 'everything is busier than
        usual' (a normal busy afternoon) from 'one flow is odd' (an intruder)."""
        if not getattr(self, "use_scale", True):
            return 1.0
        if not hasattr(self, "_busy"):
            self._busy = np.where(self.tr.lam >= 5)[0]
        r = float(np.median(counts[self._busy] / self.tr.lam[self._busy]))
        r = float(np.clip(r, 0.3, 3.0))
        self.scale = 0.8 * self.scale + 0.2 * r          # slow copy, used for learning
        return r                                        # this minute's level, used for judging this minute (a burst hits every flow in the same minute)

    def network(self, counts):
        sc = self._level(counts)
        mu = self.mu * sc
        var = mu + 0.3 + (0.15 * mu) ** 2
        zv = (counts - mu) / np.sqrt(var)
        zmax = float(zv.max())
        novelty = int(((mu < 0.02) & (counts >= 2)).sum())
        x = np.log1p(counts / sc)[None, :]
        err = float(((x - self.ae.predict(x)) ** 2).mean())
        top = np.argsort(-zv)[:3]
        ev = []
        for i in top:
            if zv[i] > 5 or (mu[i] < 0.02 and counts[i] >= 2):
                e = self.ward["edges"][int(i % self.E)]
                ev.append(dict(edge=e["id"], src=e["source"], dst=e["target"], z=round(float(zv[i]), 1), kind="write" if i >= self.E else "read"))
        # SUM OF SMALL ODDITIES: many flows each only slightly above normal (several quiet attackers at once) add up even though none reaches the single-flow line.
        zs = float(np.maximum(zv - 1.0, 0.0).sum())
        zsum = float(np.clip((zs - getattr(self, "zs_mu", 4.5)) / getattr(self, "zs_sd", 2.5), -3.0, 30.0))
        return dict(ae=err / self.thr, zmax=zmax, novelty=novelty, evidence=ev, zsum=zsum)

    # ---------------------------------------------------------------- fusion
    @staticmethod
    def feat(net, phys_z, decoy):
        return np.array([min(net["ae"], 50) / 10.0, np.log1p(max(net["zmax"], 0)), min(net["novelty"], 10), phys_z / 10.0, 1.0 if decoy else 0.0, net.get("zsum", 0.0) / 10.0])

    def fit_fusion(self, X, y, normal_weight=4.0):
        """Logistic fusion. Normal windows are weighted so a calm city sits near p~0.05 (flat heartbeat); strong evidence still saturates."""
        self.fusion = LogisticRegression(C=4.0, class_weight={0: normal_weight, 1: 1.0}, max_iter=800).fit(X, y)
        self.offset = 0.0
        z0 = self.fusion.decision_function(X[y == 0]); z1 = self.fusion.decision_function(X[y == 1])
        self.cs_k, self.cs_h = -1.0, 8.0                                  # defaults; build_watchdog calibrates them on attack-free episodes
        self.calib = dict(normal_mean_p=round(float((1 / (1 + np.exp(-z0))).mean()), 3), normal_max_p=round(float(1 / (1 + np.exp(-z0.max()))), 3),
                          positive_recall_at_0_85=round(float((z1 > 1.73).mean()), 3))

    def observe(self, counts, tele, minute, decoy_hits=0):
        net = self.network(counts)
        pz, viol = self.physics(tele, minute)
        f = self.feat(net, pz, decoy_hits)
        zf = float(self.fusion.decision_function(f[None, :])[0]) if self.fusion is not None else -9.0
        p = float(1 / (1 + np.exp(-(zf - self.offset)))) if self.fusion is not None else 0.0
        if pz >= 8.0:
            p = max(p, 0.9)      # a broken physical law is an alarm on its own (no signature needed)
        if decoy_hits:
            # a decoy touch is strong evidence but not proof: a vulnerability scanner or a confused device does the same. Alarm, but let corroboration (or a person) decide the cut.
            p = max(p, 0.995 if (net["evidence"] or viol) else A("decoy_alarm_p"))
        # sequential detection (CUSUM): a stealthy intruder never trips the single-window alarm, but it keeps the fused score a little above normal for many minutes
        self.cs = max(0.0, 0.97 * self.cs + zf - getattr(self, "cs_k", 9.0))
        if net["evidence"]:
            self.ev_buf.append(net["evidence"])
        cusum_alarm = self.cs > getattr(self, "cs_h", 1e9)
        if cusum_alarm:
            p = max(p, 0.9)
        ev_nodes = []
        for e in net["evidence"] or ([x for grp in self.ev_buf for x in grp] if cusum_alarm else []):
            ev_nodes += [e["src"], e["dst"]]
        for v in viol:
            if v["node"]:
                ev_nodes.append(v["node"])
        return dict(p=p, ae=round(net["ae"], 2), zmax=round(net["zmax"], 1), novelty=net["novelty"], phys_z=round(pz, 1), violations=viol,
                    evidence=net["evidence"], evidence_nodes=sorted(set(ev_nodes) - {"INTERNET"}), features=f.tolist())

    # ---------------------------------------------------------------- self-learning (verified-normal windows only)
    def learn(self, counts, p_attack, minute, quarantined_minutes=15):
        """Online update. Windows near any alert are excluded so an attacker cannot teach the model."""
        if p_attack > 0.05:
            self.last_alert = minute
            self.learn_buf.clear()
            return False
        if minute - getattr(self, "last_alert", -999) < quarantined_minutes:
            return False
        counts = counts / max(self.scale, 0.3)                 # learn the shape of normal traffic, not today's busyness
        self.learn_buf.append(counts)
        self.mu = 0.995 * self.mu + 0.005 * counts           # slow EWMA of normal rates
        if len(self.learn_buf) >= 30:
            X = np.log1p(np.stack(self.learn_buf))
            self.ae.partial_fit(X, X)
            self.learn_buf.clear()
            self.drift_events += 1
            return True
        return False
