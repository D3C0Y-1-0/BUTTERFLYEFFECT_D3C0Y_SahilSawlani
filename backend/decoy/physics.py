"""Impact Simulator: water (WNTR/EPANET, pressure-driven demand) + power (pandapower) -> service loss.

An *event* is a physical action: {"kind", "target", "start_h", "dur_h"}.
Kinds: pump_off, pump_duty (fixed-schedule local mode), valve_close, breaker_open, hospital_isolate.
Everything is deterministic and cached, so thousands of what-ifs stay interactive.
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

import numpy as np
import pandapower as pp
import pandapower.topology as ppt
import wntr
from wntr.network.controls import Control, ControlAction

from .assumptions import A, ASSUMPTIONS
from .city import DATA

STEP = 900  # 15-minute hydraulic step
HORIZON_H = 48


def norm_events(events):
    return tuple(sorted((e["kind"], e["target"], round(e["start_h"] * 4) / 4, round(e["dur_h"] * 4) / 4) for e in events))


class Physics:
    def __init__(self, ward: dict, cache_file: Path | None = None):
        self.W = ward["water"]
        self.P = ward["power"]
        self.actions = ward["actions"]
        self.lock = threading.Lock()
        sig = hashlib.sha1(json.dumps([self.W, self.P], sort_keys=True, default=str).encode(), usedforsecurity=False).hexdigest()[:10]  # cache key only
        self.cache_file = cache_file or (DATA / f"loss_cache_{sig}.json")
        self.cache: dict[str, dict] = {}
        if self.cache_file.exists():
            try:
                self.cache = json.loads(self.cache_file.read_text(encoding="utf-8"))
            except Exception:
                self.cache = {}
        self._power_cache = {}
        self._build_power()
        self.sims_run = 0
        self.baseline = self._simulate(())  # also warms EPANET

    # ------------------------------------------------------------------ power
    def _build_power(self):
        net = pp.create_empty_network(sn_mva=10)
        b_hv = pp.create_bus(net, vn_kv=22, name="Receiving 22kV")
        b_mv = pp.create_bus(net, vn_kv=11, name="Parel 11kV")
        pp.create_ext_grid(net, b_hv, vm_pu=1.0)
        pp.create_transformer_from_parameters(net, b_hv, b_mv, sn_mva=20, vn_hv_kv=22, vn_lv_kv=11, vk_percent=8, vkr_percent=0.4, pfe_kw=20, i0_percent=0.1)
        self.feeder_bus = {}
        self.feeder_switch = {}
        self.load_idx = {}
        for f, fd in self.P["feeders"].items():
            b = pp.create_bus(net, vn_kv=11, name=f"Feeder {f}")
            ln = pp.create_line_from_parameters(net, b_mv, b, length_km=2.0, r_ohm_per_km=0.2, x_ohm_per_km=0.1, c_nf_per_km=10, max_i_ka=0.6)
            sw = pp.create_switch(net, b_mv, ln, et="l", closed=True, type="CB", name=f"CB_{f}")
            self.feeder_bus[f], self.feeder_switch[f] = b, sw
            for lname, mw in fd["loads"].items():
                self.load_idx[lname] = (f, pp.create_load(net, b, p_mw=mw, q_mvar=mw * 0.25, name=lname))
        self.net = net
        pp.runpp(net)
        self.base_voltage = {f: float(net.res_bus.vm_pu[b]) for f, b in self.feeder_bus.items()}

    def power_state(self, open_feeders: frozenset):
        if open_feeders in self._power_cache:
            return self._power_cache[open_feeders]
        net = self.net
        for f, sw in self.feeder_switch.items():
            net.switch.at[sw, "closed"] = f not in open_feeders
        dead = set(ppt.unsupplied_buses(net))
        res = {f: (self.feeder_bus[f] not in dead) for f in self.feeder_bus}
        for f, sw in self.feeder_switch.items():
            net.switch.at[sw, "closed"] = True
        self._power_cache[open_feeders] = res
        return res

    # ------------------------------------------------------------------ water
    def _build_wn(self, events, horizon_h):
        W = self.W
        wn = wntr.network.WaterNetworkModel()
        o = wn.options
        o.time.duration = horizon_h * 3600
        o.time.hydraulic_timestep = STEP
        o.time.report_timestep = STEP
        o.time.pattern_timestep = STEP
        o.hydraulic.demand_model = "PDD"
        o.hydraulic.required_pressure = A("required_pressure_m") - 5.0  # 10 m for consumers
        o.hydraulic.minimum_pressure = 0.0
        o.hydraulic.pressure_exponent = 0.5
        nsteps = horizon_h * 3600 // STEP + 1
        hourly = W["demand_pattern"]
        wn.add_pattern("dem", [hourly[(i // 4) % 24] for i in range(nsteps)])
        wn.add_curve("pc", "HEAD", W["pump_curve"])
        wn.add_reservoir("R0", base_head=W["reservoir_head"])
        for p in ("PS1", "PS2"):
            wn.add_junction(f"N_{p}", elevation=5.0)
        # which feeder powers which pump -> power events become pump-off windows
        power_off = {"PS1": [], "PS2": []}
        local_duty = {}
        direct = {"PS1": [], "PS2": []}
        close_pipe = []  # (pipe, start_s, end_s)
        for e in events:
            s, d = e[2] * 3600, e[3] * 3600
            kind, tgt = e[0], e[1]
            if kind == "pump_off":
                direct[tgt].append((s, s + d))
            elif kind == "pump_duty":
                local_duty[tgt] = (s, s + d, A("ps2_local_duty"))
            elif kind == "valve_close":
                close_pipe.append((f"{tgt}", s, s + d))
            elif kind == "hospital_isolate":
                close_pipe.append((f"P_HC_{tgt}", s, s + d))
            elif kind == "breaker_open":
                for pump, f in self.P["pump_feeder"].items():
                    if f == tgt:
                        power_off[pump].append((s, s + d))
        for pump, tname, hub_node in (("PS1", "T1", "JD1"), ("PS2", "T2", "JD2")):
            tk = W["tanks"][tname]
            wn.add_tank(tname, elevation=tk["elev"], init_level=tk["init"], min_level=0.0, max_level=8.0, diameter=tk["d"])
            spd = np.ones(nsteps)
            # outage = PLC/power loss: the discharge valve is shut for the window (tank-level logic cannot override it)
            wins = sorted(direct[pump] + power_off[pump])
            merged = []
            for a, b in wins:
                if merged and a <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], b)
                else:
                    merged.append([a, b])
            for a, b in merged:
                close_pipe.append((f"P_{pump}_T", a, b))
            if pump in local_duty:
                a, b, duty = local_duty[pump]
                i0, i1 = int(a // STEP), int(np.ceil(b / STEP))
                for i in range(i0, min(i1, nsteps)):
                    if ((i - i0) % 4) >= int(round(duty * 4)):   # off part of the fixed schedule: discharge valve shut
                        close_pipe.append((f"P_{pump}_T", i * STEP, (i + 1) * STEP))
            wn.add_pattern(f"sp_{pump}", list(spd))
            wn.add_pump(pump, "R0", f"N_{pump}", "HEAD", "pc", speed=1.0, pattern=f"sp_{pump}")
            wn.add_pipe(f"P_{pump}_T", f"N_{pump}", tname, length=800, diameter=0.6, roughness=110)
            wn.add_junction(hub_node, elevation=8.0)
            wn.add_pipe(f"P_{tname}_{hub_node}", tname, hub_node, length=600, diameter=0.8, roughness=110)
            pump_obj, tank_obj = wn.get_link(pump), wn.get_node(tname)
            # PLC local level logic (hysteresis)
            wn.add_control(f"on_{pump}", Control._conditional_control(tank_obj, "level", np.less, W["pump_on_level"], ControlAction(pump_obj, "status", 1)))
            wn.add_control(f"off_{pump}", Control._conditional_control(tank_obj, "level", np.greater, W["pump_off_level"], ControlAction(pump_obj, "status", 0)))
        wn.add_junction("HC", elevation=12.0)
        pat = lambda: "dem"
        for zid, z in W["zones"].items():
            base = z["hh"] * A("persons_per_household") * A("water_lpcd") / 1000.0 / 86400.0
            wn.add_junction(zid, base_demand=base, demand_pattern="dem", elevation=z["elev"])
            wn.add_pipe(f"P_{z['hub']}_{zid}", z["hub"], zid, length=700, diameter=0.5, roughness=110)
        for hid, h in W["hospitals"].items():
            base = h["beds"] * A("hospital_litres_per_bed_day") / 1000.0 / 86400.0
            wn.add_junction(hid, base_demand=base, demand_pattern="dem", elevation=h["elev"])
            wn.add_pipe(f"P_{h['hub']}_{hid}" if h["hub"] != "HC" else f"P_HC_{hid}", h["hub"], hid, length=500, diameter=0.25, roughness=110)
        wn.add_pipe("V1", "JD1", "JD2", length=2500, diameter=0.25, roughness=110)  # cross-tie valve
        wn.add_pipe("V2", "JD2", "HC", length=900, diameter=0.35, roughness=110)  # hospital feeder valve
        wn.add_pipe("P_JD1_HC", "JD1", "HC", length=1500, diameter=0.2, roughness=110)  # redundant hospital feed
        merged_cp = {}
        for pname, s, e_ in sorted(close_pipe):
            lst = merged_cp.setdefault(pname, [])
            if lst and s <= lst[-1][1]:
                lst[-1][1] = max(lst[-1][1], e_)
            else:
                lst.append([s, e_])
        close_pipe = [(pn, a_, b_) for pn, lst in merged_cp.items() for a_, b_ in lst]
        for pname, s, e_ in close_pipe:
            link = wn.get_link(pname)
            wn.add_control(f"cl_{pname}_{int(s)}", Control._time_control(wn, int(s), "SIM_TIME", False, ControlAction(link, "status", 0)))
            wn.add_control(f"op_{pname}_{int(e_)}", Control._time_control(wn, int(e_), "SIM_TIME", False, ControlAction(link, "status", 1)))
        return wn

    def _simulate(self, key, want_series=False):
        events = [dict(kind=k, target=t, start_h=s, dur_h=d) for k, t, s, d in key]
        wn = self._build_wn(key, HORIZON_H)
        with self.lock:
            try:
                res = wntr.sim.EpanetSimulator(wn).run_sim()
            except Exception:
                # EPANET cannot always resolve a hydraulically disconnected network; WNTR's own PDD solver can.
                self.fallback_runs = getattr(self, "fallback_runs", 0) + 1
                wn = self._build_wn(key, HORIZON_H)
                res = wntr.sim.WNTRSimulator(wn).run_sim()
        self.sims_run += 1
        dem = res.node["demand"]
        head = res.node["head"]
        times = dem.index.values / 3600.0
        n = len(times)
        W = self.W
        patt = [W["demand_pattern"][(i // 4) % 24] for i in range(n)]
        dt_h = STEP / 3600.0
        pmin_h = A("hospital_min_pressure_m")
        hh_h = 0.0
        zone_ratio = {}
        for zid, z in W["zones"].items():
            base = z["hh"] * A("persons_per_household") * A("water_lpcd") / 1000.0 / 86400.0
            exp = np.array(patt) * base
            ratio = np.clip(dem[zid].values / np.maximum(exp, 1e-9), 0, 1)
            zone_ratio[zid] = ratio
            hh_h += float(z["hh"] * np.sum(1 - ratio) * dt_h)
        hosp = {}
        series = {}
        for hid, h in W["hospitals"].items():
            base = h["beds"] * A("hospital_litres_per_bed_day") / 1000.0 / 86400.0
            exp = np.array(patt) * base
            ratio = np.clip(dem[hid].values / np.maximum(exp, 1e-9), 0, 1)
            press = head[hid].values - h["elev"]
            ok = np.clip(press / pmin_h, 0, 1)
            s = np.minimum(ratio, ok)
            hosp[hid] = float(np.sum(1 - s) * dt_h)
            if want_series:
                series[f"p_{hid}"] = [round(float(x), 2) for x in press]
        hosp_water_h = float(sum(hosp.values()))
        # power side: union of open windows per feeder
        mwh = 0.0
        hosp_power_h = 0.0
        windows = {}
        for k, t, s, d in key:
            if k == "breaker_open":
                windows.setdefault(t, []).append((s, s + d))
        for f, ws in windows.items():
            ws.sort()
            merged = []
            for a, b in ws:
                if merged and a <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], b)
                else:
                    merged.append([a, b])
            for a, b in merged:
                dur = b - a
                for lname, mw in self.P["feeders"][f]["loads"].items():
                    if lname.startswith("H"):
                        hosp_power_h += max(0.0, dur - A("generator_autonomy_h"))
                    else:
                        mwh += mw * dur
        L = hh_h + A("w_hospital_hour") * (hosp_water_h + hosp_power_h) + A("w_mwh") * mwh
        out = dict(L=round(L, 3), hh_h=round(hh_h, 2), hosp_water_h=round(hosp_water_h, 3), hosp_power_h=round(hosp_power_h, 2), mwh=round(mwh, 3),
                   per_hospital={k: round(v, 3) for k, v in hosp.items()})
        if want_series:
            out["series"] = dict(t=[round(float(x), 2) for x in times], T1=[round(float(x - W["tanks"]["T1"]["elev"]), 3) for x in head["T1"].values],
                                 T2=[round(float(x - W["tanks"]["T2"]["elev"]), 3) for x in head["T2"].values], **series)
        return out

    # ------------------------------------------------------------------ public API
    def loss(self, events, want_series=False) -> dict:
        key = norm_events(events) if events and isinstance(events[0], dict) else tuple(events)
        ks = json.dumps(key)
        if not want_series and ks in self.cache:
            return self.cache[ks]
        r = self._simulate(key, want_series)
        if not want_series:
            self.cache[ks] = r
        return r

    def save(self):
        with self.lock:
            self.cache_file.write_text(json.dumps(self.cache), encoding="utf-8")

    def attack_events(self, action_ids, start_h, locked=()):
        """Actions an attacker takes at start_h; `locked` = breakers locked out by a wear attack."""
        ev = []
        rep = ASSUMPTIONS["repair_h"]
        for a_ in action_ids:
            act = self.actions[a_]
            dur = rep["breaker_lockout"] if (a_ in locked) else rep[act["repair"]]
            ev.append(dict(kind=act["kind"], target=act["target"], start_h=start_h, dur_h=dur))
        return ev

    def attack_loss(self, action_ids, start_h):
        if not action_ids:
            return self.baseline
        return self.loss(self.attack_events(sorted(action_ids), start_h))


if __name__ == "__main__":
    import time
    from .city import build_ward
    P = Physics(build_ward())
    print("baseline", P.baseline)
    t = time.time()
    for start in (3, 6, 18):
        for acts in (["PS1_OFF"], ["PS2_OFF"], ["PS1_OFF", "PS2_OFF"], ["V2_CLOSE"], ["CB_F1_OPEN"], ["CB_F3_OPEN"], ["H1_ISOLATE"], ["V2_CLOSE", "PS1_OFF"]):
            print(start, acts, P.attack_loss(acts, start))
    print("time", time.time() - t, "sims", P.sims_run)
    print(P.power_state(frozenset(["F1"])))
