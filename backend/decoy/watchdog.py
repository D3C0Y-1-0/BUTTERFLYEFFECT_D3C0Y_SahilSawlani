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

from .twin import LiveTwin


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

    def normal(self):
        return self.rng.poisson(self.lam).astype(float)

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
        self.sigma_tank = 0.03
        self.reset_state()
        self.fusion = None
        self.learn_buf = []
        self.drift_events = 0
        self.last_learn = 0
        self.name_of = {i: (e["source"], e["target"]) for i, e in enumerate(ward["edges"])}
        from .assumptions import A
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
        # I7 controller contradicts its own control logic
        for p, t, node, f in (("PS1", "T1", "PLC_PS1", "F1"), ("PS2", "T2", "PLC_PS2", "F2")):
            hit(f"I7:{p}", rep[f"{p}_state"] < 0.5 and rep[f"{t}_level"] < 3.6 and rep[f"CB_{f}"] > 0.5, 4, 8, f"{p} is stopped while {t} is low: the controller is not following its own logic", node)
        return z, viol

    # ---------------------------------------------------------------- core A: network behaviour
    def network(self, counts):
        mu = self.mu
        var = mu + 0.3 + (0.15 * mu) ** 2
        zv = (counts - mu) / np.sqrt(var)
        zmax = float(zv.max())
        novelty = int(((mu < 0.02) & (counts >= 2)).sum())
        x = np.log1p(counts)[None, :]
        err = float(((x - self.ae.predict(x)) ** 2).mean())
        top = np.argsort(-zv)[:3]
        ev = []
        for i in top:
            if zv[i] > 5 or (mu[i] < 0.02 and counts[i] >= 2):
                e = self.ward["edges"][int(i % self.E)]
                ev.append(dict(edge=e["id"], src=e["source"], dst=e["target"], z=round(float(zv[i]), 1), kind="write" if i >= self.E else "read"))
        return dict(ae=err / self.thr, zmax=zmax, novelty=novelty, evidence=ev)

    # ---------------------------------------------------------------- fusion
    @staticmethod
    def feat(net, phys_z, decoy):
        return np.array([min(net["ae"], 50) / 10.0, np.log1p(max(net["zmax"], 0)), min(net["novelty"], 10), phys_z / 10.0, 1.0 if decoy else 0.0])

    def fit_fusion(self, X, y, normal_weight=4.0):
        """Logistic fusion. Normal windows are weighted so a calm city sits near p~0.05 (flat heartbeat); strong evidence still saturates."""
        self.fusion = LogisticRegression(C=4.0, class_weight={0: normal_weight, 1: 1.0}, max_iter=800).fit(X, y)
        self.offset = 0.0
        z0 = self.fusion.decision_function(X[y == 0]); z1 = self.fusion.decision_function(X[y == 1])
        self.calib = dict(normal_mean_p=round(float((1 / (1 + np.exp(-z0))).mean()), 3), normal_max_p=round(float(1 / (1 + np.exp(-z0.max()))), 3),
                          positive_recall_at_0_85=round(float((z1 > 1.73).mean()), 3))

    def observe(self, counts, tele, minute, decoy_hits=0):
        net = self.network(counts)
        pz, viol = self.physics(tele, minute)
        f = self.feat(net, pz, decoy_hits)
        p = float(1 / (1 + np.exp(-(self.fusion.decision_function(f[None, :])[0] - self.offset)))) if self.fusion is not None else 0.0
        if pz >= 8.0:
            p = max(p, 0.9)      # a broken physical law is an alarm on its own (no signature needed)
        if decoy_hits:
            p = max(p, 0.995)
        ev_nodes = []
        for e in net["evidence"]:
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
        self.learn_buf.append(counts)
        self.mu = 0.995 * self.mu + 0.005 * counts           # slow EWMA of normal rates
        if len(self.learn_buf) >= 30:
            X = np.log1p(np.stack(self.learn_buf))
            self.ae.partial_fit(X, X)
            self.learn_buf.clear()
            self.drift_events += 1
            return True
        return False


def build_watchdog(ward, threat, seed=0, episodes=36, verbose=False):
    """Train the fusion model on labelled simulated episodes (normal vs each attack mode)."""
    from .adversary import Adversary
    tr = Traffic(ward, seed=seed + 11)
    wd = Watchdog(ward, tr, seed=seed)
    rng = np.random.default_rng(seed + 5)
    X, y = [], []
    modes = ["standard", "zero_day", "spoof", "wear", "insider"]
    for ep in range(episodes):
        tw = LiveTwin(ward, seed=seed + ep)
        for _ in range(90):
            tw.step()
        wd.reset_state()
        adv = Adversary(ward, threat, seed=seed + 100 + ep)
        attack = ep % 3 != 0  # one third pure normal
        mode = modes[(ep // 3) % len(modes)] if attack else "none"
        camp = adv.launch(tw.minute, mode=mode, stealth=float(rng.uniform(1.5, 8.0)), goal=str(rng.choice([c for c in adv.goals]))) if attack else None
        started_phys = False
        for k in range(260):
            minute = tw.minute
            flows, phys, evs = adv.tick(minute) if attack else ([], [], [])
            for ph in phys:
                if ph["kind"] == "wear":
                    tw.breaker_cycle()
                    continue
                tw.act(ph["kind"], ph["target"], ph["dur_min"])
                started_phys = True
                if mode == "spoof":
                    tag = {"pump_off": f"{ph['target']}_", }.get(ph["kind"])
                    if ph["kind"] == "pump_off":
                        p = ph["target"]
                        tw.spoof[f"{p}_state"] = 1.0
                        tw.spoof[f"{p}_flow"] = lambda rep: 0.21
                    elif ph["kind"] == "breaker_open":
                        tw.spoof[f"CB_{ph['target']}"] = 1.0
                if ph["kind"] in ("valve_close", "breaker_open", "hospital_isolate") and mode != "spoof":
                    pass
            tele = tw.step()
            counts = tr.normal()
            decoy = tr.add(counts, flows)
            res = wd.observe(counts, tele, minute, decoy)
            label = 1 if (attack and (adv.active() or (started_phys and any(v > tw.minute for v in list(tw.forced_off.values()) + list(tw.breaker_open.values()) + list(tw.valve_closed.values()))))) else 0
            if k > 5:
                X.append(res["features"]); y.append(label)
    X, y = np.array(X), np.array(y)
    wd.fit_fusion(X, y)
    wd.reset_state()
    return wd, tr, (X, y)
