"""Live twin: a fast mass-balance model of the ward, stepped one simulated minute at a time.

Calibrated against the WNTR/pandapower oracle (same tank areas, pump flow, demand pattern, cross-tie law). The oracle answers
"what would this attack cost?"; the live twin answers "what is happening right now?" and feeds telemetry to the Watchdog.
"""
from __future__ import annotations

import math
from collections import deque

import numpy as np

from .assumptions import A, ASSUMPTIONS

Q_PUMP = 0.21           # m3/s when running (WNTR operating point)
TIE_Q3 = 0.0211         # m3/s through the narrow cross-tie at 3 m head difference
BRANCH = {"T1": ["Z1", "Z2", "H3"], "T2": ["Z3", "Z4", "Z5", "H1", "H2"]}
PUMP_TANK = {"PS1": "T1", "PS2": "T2"}
FEEDER_OF_PUMP = {"PS1": "F1", "PS2": "F2"}


class LiveTwin:
    def __init__(self, ward, seed=1, name="live"):
        self.W, self.P = ward["water"], ward["power"]
        self.name = name
        self.rng = np.random.default_rng(seed)
        self.area = {t: math.pi * self.W["tanks"][t]["d"] ** 2 / 4 for t in ("T1", "T2")}
        pph, lpcd = A("persons_per_household"), A("water_lpcd")
        self.base = {}
        for z, v in self.W["zones"].items():
            self.base[z] = v["hh"] * pph * lpcd / 1000 / 86400
        for h, v in self.W["hospitals"].items():
            self.base[h] = v["beds"] * A("hospital_litres_per_bed_day") / 1000 / 86400
        self.hh = {z: v["hh"] for z, v in self.W["zones"].items()}
        self.reset()

    def reset(self, minute=6 * 60):
        self.minute = minute
        self.level = {"T1": 6.2, "T2": 6.3}
        self.pump_on = {"PS1": True, "PS2": True}
        self.forced_off = {}      # pump -> until minute (attack)
        self.breaker_open = {}    # feeder -> until minute
        self.breaker_ops = deque(maxlen=60)  # (minute) of each operation
        self.valve_closed = {}    # V1/V2 -> until minute
        self.h1_isolated_until = 0
        self.local_mode = {}      # pump -> until minute (fixed 50% duty)
        self.spoof = {}           # tag -> value override
        self.spoof_until = {}     # tag -> minute the fake reading stops (a spoof lasts as long as the attacker holds the controller)
        self.served = {k: 1.0 for k in self.base}
        self.lost = dict(hh_h=0.0, hosp_h=0.0, mwh=0.0)
        self.press_h = {h: 22.0 for h in self.W["hospitals"]}
        self.last = {}
        self.events = []

    # ---------------------------------------------------------------- physical interface
    def hour(self):
        return (self.minute / 60.0) % 24

    def pattern(self):
        p = self.W["demand_pattern"]
        h = self.hour()
        i = int(h) % 24
        f = h - int(h)
        return p[i] * (1 - f) + p[(i + 1) % 24] * f

    def act(self, kind, target, dur_min):
        until = self.minute + dur_min
        if kind == "pump_off":
            self.forced_off[target] = max(self.forced_off.get(target, 0), until)
        elif kind == "valve_close":
            self.valve_closed[target] = max(self.valve_closed.get(target, 0), until)
        elif kind == "breaker_open":
            self.breaker_open[target] = max(self.breaker_open.get(target, 0), until)
            self.breaker_ops.append(self.minute)
        elif kind == "hospital_isolate":
            self.h1_isolated_until = max(self.h1_isolated_until, until)
        elif kind == "pump_duty":
            self.local_mode[target] = until

    def breaker_cycle(self):
        """Wear attack: breaker toggled rapidly (counted by the invariant checker)."""
        self.breaker_ops.append(self.minute)

    def restore(self, kind, target):
        """Crew restores equipment locally (manual control): back in service after a short delay."""
        t = self.minute + 45
        if kind == "pump_off":
            self.forced_off[target] = min(self.forced_off.get(target, t), t) if target in self.forced_off else 0
        elif kind == "valve_close" and target in self.valve_closed:
            self.valve_closed[target] = min(self.valve_closed[target], t)
        elif kind == "breaker_open" and target in self.breaker_open:
            self.breaker_open[target] = min(self.breaker_open[target], t)
        elif kind == "hospital_isolate":
            self.h1_isolated_until = min(self.h1_isolated_until, t)

    def active(self, d):
        return {k for k, v in d.items() if v > self.minute}

    # ---------------------------------------------------------------- dynamics
    def step(self, dt=1):
        for _ in range(dt):
            self._step()
        return self.telemetry()

    def _step(self):
        m = self.minute
        for tag in [t for t, u in self.spoof_until.items() if u <= m]:   # expired fake readings must not linger and re-trigger alarms
            self.spoof.pop(tag, None)
            del self.spoof_until[tag]
        pat = self.pattern()
        no_power = {f for f, u in self.breaker_open.items() if u > m}
        forced = self.active(self.forced_off)
        for p, t in PUMP_TANK.items():
            lv = self.level[t]
            if p in forced or FEEDER_OF_PUMP[p] in no_power:
                self.pump_on[p] = False
            elif self.local_mode.get(p, 0) > m:
                self.pump_on[p] = ((m // 30) % 2) == 0 if A("ps2_local_duty") <= 0.5 else True
            elif lv < self.W["pump_on_level"]:
                self.pump_on[p] = True
            elif lv > self.W["pump_off_level"]:
                self.pump_on[p] = False
        q_in = {t: (Q_PUMP if self.pump_on[p] else 0.0) for p, t in PUMP_TANK.items()}
        v1_open = self.valve_closed.get("V1", 0) <= m
        v2_open = self.valve_closed.get("V2", 0) <= m
        dem = {k: self.base[k] * pat for k in self.base}
        if self.h1_isolated_until > m:
            dem["H1"] = 0.0
        # cross-tie transfer (T1 -> T2 positive)
        dL = self.level["T1"] - self.level["T2"]
        q_tie = (TIE_Q3 * (abs(dL) / 3.0) ** 0.54 * (1 if dL > 0 else -1)) if v1_open else 0.0
        out = {t: sum(dem[k] for k in BRANCH[t]) for t in ("T1", "T2")}
        out["T1"] += q_tie
        out["T2"] -= q_tie
        for t in ("T1", "T2"):
            vol = self.level[t] * self.area[t]
            need = out[t] * 60
            have = vol + q_in[t] * 60
            if have >= need:
                new_vol = have - need
                frac = 1.0
            else:
                new_vol, frac = 0.0, max(0.0, have / max(need, 1e-9))
            self.level[t] = min(8.0, new_vol / self.area[t])
            for k in BRANCH[t]:
                self.served[k] = frac
        # hospital pressure (derived from tank head, see WNTR calibration p ~ level + 12.8)
        for h, v in self.W["hospitals"].items():
            if h == "H3":
                lv = self.level["T1"]
            else:
                lv = self.level["T2"] if v2_open else self.level["T1"] - 1.0
            p = lv + 12.8
            self.press_h[h] = p
            if p < A("hospital_min_pressure_m"):
                self.served[h] = min(self.served[h], max(0.0, p / A("hospital_min_pressure_m")))
        # cumulative service loss (household-hours etc.)
        for z in self.hh:
            self.lost["hh_h"] += (1 - self.served[z]) * self.hh[z] / 60.0
        for h in self.W["hospitals"]:
            s_h = 0.0 if (h == "H1" and self.h1_isolated_until > m) else self.served[h]
            self.lost["hosp_h"] += (1 - s_h) / 60.0
        for f in no_power:
            for ln, mw in self.P["feeders"][f]["loads"].items():
                if not ln.startswith("H"):
                    self.lost["mwh"] += mw / 60.0
        self.flows = dict(q_in=q_in, out=out, q_tie=q_tie, dem=dem)
        self.no_power = no_power
        self.minute += 1

    # ---------------------------------------------------------------- telemetry
    def telemetry(self):
        r = self.rng
        n = lambda s: float(r.normal(0, s))
        m = self.minute
        no_power = self.no_power if hasattr(self, "no_power") else set()
        f = getattr(self, "flows", dict(q_in={"T1": 0, "T2": 0}, out={"T1": 0, "T2": 0}, q_tie=0, dem={}))
        truth = {
            "T1_level": self.level["T1"], "T2_level": self.level["T2"],
            "PS1_state": 1.0 if self.pump_on["PS1"] else 0.0, "PS2_state": 1.0 if self.pump_on["PS2"] else 0.0,
            "PS1_flow": f["q_in"]["T1"], "PS2_flow": f["q_in"]["T2"],
            "V1_pos": 0.0 if self.valve_closed.get("V1", 0) > m else 1.0, "V2_pos": 0.0 if self.valve_closed.get("V2", 0) > m else 1.0,
            "CB_F1": 0.0 if "F1" in no_power else 1.0, "CB_F2": 0.0 if "F2" in no_power else 1.0, "CB_F3": 0.0 if "F3" in no_power else 1.0,
            "BUS_F1": 0.0 if "F1" in no_power else 1.0, "BUS_F2": 0.0 if "F2" in no_power else 1.0, "BUS_F3": 0.0 if "F3" in no_power else 1.0,
            "FLOW_A": f["out"]["T1"], "FLOW_B": f["out"]["T2"],
        }
        for h in self.W["hospitals"]:
            truth[f"P_{h}"] = self.press_h[h]
            iso = h == "H1" and self.h1_isolated_until > m
            truth[f"{h}_FLOW"] = 0.0 if iso else self.served[h] * f["dem"].get(h, 0.0)
        rep = dict(truth)
        for tag in ("T1_level", "T2_level", "PS1_flow", "PS2_flow", "FLOW_A", "FLOW_B", "H1_FLOW", "H2_FLOW", "H3_FLOW"):
            rep[tag] += n(0.03 if "level" in tag else (0.0004 if tag.startswith("H") else 0.004))
        for tag in ("BUS_F1", "BUS_F2", "BUS_F3"):
            rep[tag] += n(0.004)
        for tag, val in self.spoof.items():
            if tag in rep:
                rep[tag] = val(rep) if callable(val) else val
        ops10 = sum(1 for t in self.breaker_ops if m - t <= 10)
        rep["BRK_OPS_10M"] = float(ops10)
        truth["BRK_OPS_10M"] = float(ops10)
        # INDEPENDENT PATH: tank-level sensors on their own radio gateway and the hospitals' own inlet meters. They are not on the SCADA/PLC network, so an attacker who controls
        # the control network (and can therefore forge every reading above) cannot forge these. Their own noise is a little larger (cheaper sensors).
        ind = {f"IND_{t}_level": truth[f"{t}_level"] + n(0.05) for t in ("T1", "T2")}
        for h in self.W["hospitals"]:
            ind[f"IND_{h}_FLOW"] = truth[f"{h}_FLOW"] + n(0.0002)
        self.last = dict(reported=rep, truth=truth, independent=ind)
        return self.last

    def services(self):
        """Compact service state for UI and metrics."""
        z = {k: round(self.served[k], 3) for k in self.W["zones"]}
        hosp = {}
        for h in self.W["hospitals"]:
            hosp[h] = dict(served=round(self.served[h], 3), pressure=round(self.press_h[h], 2), ok=bool(self.press_h[h] >= A("hospital_min_pressure_m") and self.served[h] > 0.98))
        hh_total = sum(self.hh.values())
        hh_served = sum(self.hh[k] * self.served[k] for k in self.hh)
        return dict(zones=z, hospitals=hosp, households_total=hh_total, households_served=round(hh_served), served_frac=round(hh_served / hh_total, 4),
                    feeders={f: (f not in getattr(self, "no_power", set())) for f in self.P["feeders"]},
                    cum=dict(hh_h=round(self.lost["hh_h"], 1), hosp_h=round(self.lost["hosp_h"], 3), mwh=round(self.lost["mwh"], 3)))

    def loss_composite(self):
        c = self.lost
        return c["hh_h"] + A("w_hospital_hour") * c["hosp_h"] + A("w_mwh") * c["mwh"]
