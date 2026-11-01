"""Runtime: the always-on loop. One tick = one simulated minute.

live twin  : the city ATHENA is defending
none twin  : same attack, no response (counterfactual)
iso twin   : same attack, but the whole network is isolated when the incident is declared (counterfactual)
"""
from __future__ import annotations

import json
import math
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

import numpy as np

from .adversary import MODES, Adversary
from .assumptions import A, ASSUMPTIONS
from .blackbox import BlackBox, LogVault, TimeGuard
from .city import DATA, build_ward
from .healer import ISOLATION_H, Healer
from .physics import Physics
from .planner import Planner
from .threat import Defence, ThreatModel
from .twin import LiveTwin
from .training import build_watchdog
from .environment import Environment
from .rl import DECISION_MIN, PPO, RLCore, ZDState
from .zeroday import EXPLOITS, Library, fingerprint, products, random_zero_day

SBOM = {"SCADA_WEB": ["log4j-core 2.14.1", "tomcat 9.0.40"], "VPN_VENDOR": ["openssl 3.0.x", "busybox 1.35"], "HIST_01": ["php 7.4", "zabbix 5.4"],
        "SCADA_SRV": ["esxi 7.0U3", "openssl 1.1.1"], "FW_PERIM": ["fortios 7.0", "openssl 1.1.1"], "HMI_01": ["dopsoft 2.00.07"], "GW_LIGHT_01": ["linux 3.10", "busybox 1.19"],
        "GW_LIGHT_02": ["linux 3.10", "busybox 1.19"], "CCTV_01": ["linux 4.9", "dahua-sdk"], "WIFI_PUB_01": ["linux 3.10", "dnsmasq 2.80"]}


ESCALATE_MIN = 10   # simulated minutes a safe plan may wait for a human while service is at risk


class Runtime:
    def __init__(self, sync=False, n_samples=3000, seed=7, verbose=True):
        t0 = time.time()
        self.sync = sync
        self.seed = seed
        self.ward = build_ward()
        for k, v in SBOM.items():
            self.ward["assets"][k]["sbom"] = v
        if verbose: print("[boot] physics oracle ...", flush=True)
        self.phys = Physics(self.ward)
        self.T = ThreatModel(self.ward, self.phys, n_samples, seed)
        self.planner = Planner(self.ward, self.T, self.phys)
        self.healer = Healer(self.ward, self.T, self.phys)
        if verbose: print("[boot] training watchdog ...", flush=True)
        self.watchdog, self.traffic, _ = build_watchdog(self.ward, self.T, seed=0)
        self.bb, self.vault = BlackBox(), LogVault()
        self.tg = TimeGuard(["SCADA_SRV", "HIST_01", "PLC_PS1", "PLC_PS2", "RTU_F1", "RTU_F2", "RTU_F3", "JUMP_RDS"])
        self.lock = threading.RLock()
        self.ex_healer = ThreadPoolExecutor(1)
        self.ex_analytics = ThreadPoolExecutor(1)
        self.autonomy = "auto_low"
        self.autopilot = True
        self.stopped = False
        self.paused = False
        self.speed = 1.0
        self.running = False
        self.analytics = dict(version=0, computing=True)
        self.analytics_base = None
        self.health = dict(restarts=0, last_restart=None, escalations=0, feed_quarantined=0)
        self.exp_cache = None
        self.rlcore = RLCore(self.ward, self.T, self.phys)
        self.edge_index = {e["id"]: i for i, e in enumerate(self.ward["edges"])}
        self.ppo, self.ppo_meta, self.ppo_eval = None, None, None
        self.verbose = verbose
        ef = DATA / "ppo_eval.json"
        if ef.exists():
            self.ppo_eval = json.loads(ef.read_text(encoding="utf-8"))
        self.responder = ((self.ppo_eval or {}).get("default_responder", "ppo") if (DATA / "ppo_policy.pt").exists() else "search")
        self.reset(seed)
        self.bb.append("boot", dict(city=self.ward["meta"]["city"], assets=len(self.ward["assets"]), edges=len(self.ward["edges"])))
        if verbose: print(f"[boot] ready in {time.time()-t0:.1f}s", flush=True)

    # ------------------------------------------------------------------ lifecycle
    def reset(self, seed=None):
        with self.lock:
            seed = self.seed if seed is None else seed
            self.rng = np.random.default_rng(seed + 1)
            self.live = LiveTwin(self.ward, seed=1, name="live")
            self.none = LiveTwin(self.ward, seed=1, name="none")
            self.iso = LiveTwin(self.ward, seed=1, name="iso")
            self.flood_blocked, self.flood_until, self.flood_pending, self.flood_active, self.flood_only = {}, {}, [], False, False
            for _ in range(60):
                for tw in (self.live, self.none, self.iso):
                    tw.step()
            for tw in (self.live, self.none, self.iso):
                tw.lost = dict(hh_h=0.0, hosp_h=0.0, mwh=0.0)
            self.defence = Defence()
            self.decoys = {}
            # ATTACKER SIDE (three copies of the same attack, for the scoreboard) and ENVIRONMENT. The defence code below never reads self.adv*.
            self.adv = Adversary(self.ward, seed + 3)
            self.adv_none = Adversary(self.ward, seed + 3)
            self.adv_iso = Adversary(self.ward, seed + 3)
            self.env_live = Environment(self.ward, self.T, defence=lambda: self.defence, decoys=lambda: self.decoys, seed=seed)
            self.env_none = Environment(self.ward, self.T, seed=seed)          # same dice as the live world, so the three worlds differ only because of what the defence did
            self.env_iso = Environment(self.ward, self.T, refuse_all=lambda: self.iso_cut, seed=seed)
            self.last_net_ev = -9999
            self.iso_cut = False
            self.incidents, self.proposals, self.feed = [], [], deque(maxlen=300)
            self.hi, self.lo = 0, 0
            self.pending_verify = None
            self.next_launch = self.live.minute + int(self.rng.integers(20, 50))
            self.last_p = 0.0
            self.last_obs = {}
            self.ev_id = 0
            self.node_flags = {}
            self.watchdog.reset_state()
            self.decision_log = []
            self.zd_lib = Library()
            self.zd_lab = []
            self.shadow_mark = None
            self.timeline = deque(maxlen=400)
            self.new_events = []
            self.dirty = True
        self.note("system", "info", "Runtime reset: city restored, defences cleared.")

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.ex_analytics.submit(self._analytics_job)
        threading.Thread(target=self._load_ppo, daemon=True).start()   # importing torch takes ~7 s: do it in the background so the server is reachable sooner

    def _load_ppo(self):
        pf = DATA / "ppo_policy.pt"
        if not pf.exists():
            self.responder = "search"
            return
        try:
            ppo, meta = PPO.load(pf)
            with self.lock:
                self.ppo, self.ppo_meta = ppo, meta
        except Exception as e:
            self.responder = "search"
            if self.verbose:
                print("[boot] PPO policy not loaded:", e, flush=True)

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            t = time.time()
            try:
                if not self.paused:
                    with self.lock:
                        self.tick()
            except BaseException as e:  # health supervisor: log and keep running; the simulation loop must never die silently
                try:
                    self.health["restarts"] += 1
                    self.health["last_restart"] = f"{type(e).__name__}: {e}"
                    self.bb.append("module_restart", dict(error=str(e)))
                except Exception:
                    pass
                if isinstance(e, (KeyboardInterrupt, SystemExit)):
                    raise
            time.sleep(max(0.0, 0.25 / max(self.speed, 0.1) - (time.time() - t)))

    # ------------------------------------------------------------------ helpers
    def note(self, kind, sev, text, **extra):
        self.ev_id += 1
        ev = dict(id=self.ev_id, minute=self.live.minute, kind=kind, sev=sev, text=text, **extra)
        self.feed.append(ev)
        self.new_events.append(ev)
        if getattr(self, "event_sink", None):
            self.event_sink(ev)
        self.bb.append(kind, dict(text=text, **{k: v for k, v in extra.items() if isinstance(v, (str, int, float, list, dict, bool, type(None)))}), self.live.minute)
        self.vault.write(ev)
        return ev

    def hour(self):
        return self.live.hour()

    def clock(self):
        m = self.live.minute
        return f"Day {m // 1440 + 1} {int(m % 1440 // 60):02d}:{int(m % 60):02d}"

    # ------------------------------------------------------------------ attacks
    def launch_attack(self, mode="standard", entry=None, goal=None, stealth=None, actor="autopilot"):
        with self.lock:
            if mode not in MODES:
                raise ValueError("unknown mode")
            if entry is not None and entry not in self.ward["assets"]:
                raise ValueError("unknown entry")
            if goal is not None and goal not in self.adv.goals:
                raise ValueError("unknown goal")
            m = self.live.minute
            if mode == "group":      # a coordinated group: three attackers through different doors at different targets, plus a flood as cover
                made = []
                for i, sub in enumerate(("standard", "zero_day", "spoof", "ddos")):
                    made.append(self._launch_one(m, sub, entry if i == 0 else None, goal if i == 0 else None, None, actor))
                self.note("attack_launched", "warn", f"[{actor}] Coordinated group: {len(made)} attackers at once, including a flood", campaign=made[0]["id"], mode=mode, hidden=True)
                return made[0]
            if mode == "swarm":      # low and slow: several very quiet attackers at different doors at once. Each stays under the single-alarm line; together they add up.
                doors = [n for n, a_ in self.ward["assets"].items() if a_["entry_weight"] > 0 and n != entry]
                picks = ([entry] if entry else []) + [str(x) for x in self.rng.choice(doors, size=5 - (1 if entry else 0), replace=False)]
                made = [self._launch_one(m, "standard", d, goal if i == 0 else None, 0.8, actor, quiet=True) for i, d in enumerate(picks)]
                self.note("attack_launched", "warn", f"[{actor}] Swarm: {len(made)} very quiet attackers at once", campaign=made[0]["id"], mode=mode, hidden=True)
                return made[0]
            return self._launch_one(m, mode, entry, goal, stealth, actor)

    def _launch_one(self, m, mode, entry, goal, stealth, actor, quiet=False):
        c = self.adv.launch(m, mode=mode, entry=entry, goal=goal, stealth=stealth)
        c.quiet = quiet
        for a in (self.adv_none, self.adv_iso):
            a.launch(m, mode=mode, entry=c.entry, goal=c.goal, stealth=c.stealth, zd=c.zd).quiet = quiet
        if c.zd is not None:
            self._lab_register(c.zd, c, actor)
        self.note("attack_launched", "warn", f"[{actor}] {MODES[mode]} via {self.ward['assets'][c.entry]['name']} aiming at {self.ward['assets'][c.goal]['name']}", campaign=c.id, mode=mode, hidden=True)
        return c.public()

    def emergency_stop(self, actor="operator"):
        """Kill switch. Halts every running attack, turns the automatic attacker off and puts the defender into ask-first mode."""
        with self.lock:
            n = 0
            for a in (self.adv, self.adv_none, self.adv_iso):
                for c in a.campaigns:
                    if c.state not in ("done", "contained"):
                        c.state = "contained"
                        n += a is self.adv
            self.autopilot, self.autonomy, self.stopped = False, "suggest", True
            self.note("kill_switch", "warn", f"STOP pressed by {actor}: {n} running attack(s) halted, automatic attacks off, autonomy set to ask-first.")
            self.dirty = True
            return dict(stopped=True, halted=n)

    def resume(self, actor="operator"):
        with self.lock:
            self.autopilot, self.autonomy, self.stopped = True, "auto_low", False
            self.next_launch = self.live.minute + 30
            self.note("resume", "info", f"{actor} resumed the simulation: automatic attacks on, safe steps automatic.")
            return dict(stopped=False)

    def deploy_decoy(self, node, actor="operator"):
        with self.lock:
            a = self.ward["assets"].get(node)
            if not a or node == "INTERNET":
                raise ValueError("unknown device")
            if any(d["attached_to"] == node for d in self.decoys.values()):
                raise ValueError("a decoy is already next to this device")
            did = f"DCY{len(self.decoys)+1:02d}"
            self.decoys[did] = dict(id=did, attached_to=node, mimic="fake " + a["name"].split(" (")[0], placed=self.live.minute)
            self.note("decoy_placed", "ok", f"{actor} placed decoy {did} next to {a['name']}.", decoy=did, node=node)
            return self.decoys[did]

    def _heartbeat(self):
        """What the heartbeat shows. `raw` is the detector's alarm level. Once the attacker is cut off the alarm that is still ringing is the damage being
        repaired, not a live attack, so the level shown decays (with a clear 'healing' note and a repair countdown) instead of sitting at 90 %."""
        L, m, p = self.live, self.live.minute, float(self.last_p)
        left = max([0] + [int(u - m) for d in (L.forced_off, L.breaker_open, L.valve_closed) for u in d.values() if u > m])
        inc = next((i for i in reversed(self.incidents) if i["status"] in ("open", "contained")), None)
        shown, phase, note = p, ("alarm" if p > 0.6 else "calm"), ""
        if inc:
            cut = next((s for s in inc["stages"] if s["stage"] == "Cut made"), None)
            prop = next((q for q in self.proposals if q["incident"] == inc["id"] and q["status"] == "pending"), None)
            if cut and (m - self.last_net_ev) >= 5:
                shown = p * math.exp(-(m - cut["minute"]) / 6.0)
                phase = "healing"
                note = f"Attacker cut off. {'Crew restoring equipment, about ' + str(left) + ' min left.' if left else 'Checking that everything is back to normal.'}"
            elif prop:
                phase = "waiting"
                wait = max(0, ESCALATE_MIN - (m - prop["minute"]))
                note = "A safe plan is ready." + (f" It applies by itself in about {wait} min." if self.autonomy in ("auto_low", "auto_all") else " Waiting for your OK.")
            elif p > 0.6:
                note = "Alarm raised. ATHENA is working out the safest response."
        return dict(shown=round(float(shown), 3), raw=round(p, 3), phase=phase, note=note, repair_left=left)

    # ------------------------------------------------------------------ main tick
    def tick(self):
        L = self.live
        m = L.minute
        # autopilot adversary
        if self.autopilot and m >= self.next_launch and not self.adv.active():
            mode = str(self.rng.choice(["standard", "zero_day", "spoof", "wear", "insider"], p=[0.4, 0.15, 0.2, 0.1, 0.15]))
            self.launch_attack(mode)
            self.next_launch = m + int(self.rng.integers(120, 260))
        # adversaries
        fl, ph, evs = self.adv.tick(m, self.env_live)
        fl = self.env_live.deliver(fl)                     # traffic on a closed link never arrives
        for ev in evs:                                     # scoreboard only: did the flood still reach an open door this minute?
            if ev["type"] == "flood":
                camp = next((x for x in self.adv.campaigns if x.id == ev["campaign"]), None)
                if camp is not None and any(not self.env_live.blocked(self.env_live.edge[x]) for x in ev["edges"]):
                    camp.flood_open += 1
        fl_n, ph_n, _ = self.adv_none.tick(m, self.env_none)
        fl_i, ph_i, _ = (self.adv_iso.tick(m, self.env_iso) if not self.iso_cut else ([], [], []))
        for e in evs:
            if e["type"] in ("hop", "attack_blocked", "decoy_touch"):
                self.note("adversary_" + e["type"], "info", e.get("text") or f"hop {e['src']} -> {e['dst']}", hidden=True)
        for p in ph:
            self._physical(L, p, spoof=True)
            self.note("physical_action", "crit", f"Physical effect: {self.ward['actions'].get(p['action'], {}).get('label', p['action'])}", hidden=True)
        for p in ph_n:
            self._physical(self.none, p)
        for p in ph_i:
            self._physical(self.iso, p)
        tele = L.step()
        self.none.step(); self.iso.step()
        counts = self.traffic.normal()
        decoy_hits = self.traffic.add(counts, fl)
        obs = self.watchdog.observe(counts, tele, m, decoy_hits)
        self.last_obs = obs
        self.last_p = obs["p"]
        if obs["evidence"]:
            self.last_net_ev = m                       # the last minute the Watchdog saw odd network traffic (the only "is it still going on?" signal the defence has)
        self.watchdog.learn(counts, obs["p"], m)
        for src in self.tg.skew:
            pass
        self._flood_guard(counts, obs, m)
        # incidents
        self._incident_logic(obs, m)
        self._flood_note(m)
        self._scorekeeper(m)
        self._escalate(m)
        self._rl_tick(m)
        # verification of applied containment
        if self.pending_verify and m >= self.pending_verify["minute"]:
            self._verify(m)
        # 6-hour clock escalations
        for inc in self.incidents:
            if inc["status"] != "reported":
                left = inc["deadline"] - m
                for thr, name in ((120, "4h"), (60, "5h")):
                    if left <= thr and name not in inc["escalated"]:
                        inc["escalated"].append(name)
                        self.health["escalations"] += 1
                        self.note("clock_escalation", "warn", f"Incident {inc['id']}: {name} of the CERT-In 6-hour window used. Review & export the report.", incident=inc["id"])
        for inc in self.incidents:
            if inc.get("cost_due") and m >= inc["cost_due"]:
                inc["cost_due"] = None
                Ls, Ns, Is = self.live, self.none, self.iso
                inc["cost"] = dict(live=round(Ls.loss_composite()), none=round(Ns.loss_composite()), iso=round(Is.loss_composite()),
                                   live_hh=round(Ls.lost["hh_h"]), none_hh=round(Ns.lost["hh_h"]), iso_hh=round(Is.lost["hh_h"]))
                self.note("incident_cost", "ok", f"Incident {inc['id']} final service loss (10 h after resolution): ATHENA {inc['cost']['live']:,} | no response {inc['cost']['none']:,} | isolate-everything {inc['cost']['iso']:,} household-hour equivalents.", incident=inc["id"])
        if m % 30 == 0:
            self.bb.append("telemetry_digest", dict(p=round(self.last_p, 3), served=L.services()["served_frac"]), m)

    def _physical(self, tw, p, spoof=False):
        if p["kind"] == "wear":
            tw.breaker_cycle()
            return
        tw.act(p["kind"], p["target"], p["dur_min"])
        if spoof and p.get("mode") == "spoof":
            until = tw.minute + max(int(p.get("dur_min", 0)), 1)
            if p["kind"] == "pump_off":
                tw.spoof[f"{p['target']}_state"] = 1.0
                tw.spoof[f"{p['target']}_flow"] = lambda rep: 0.21
                tw.spoof_until[f"{p['target']}_state"] = tw.spoof_until[f"{p['target']}_flow"] = until
            elif p["kind"] == "breaker_open":
                tw.spoof[f"CB_{p['target']}"] = 1.0
                tw.spoof_until[f"CB_{p['target']}"] = until

    # ------------------------------------------------------------------ incident management
    def _flood_guard(self, counts, obs, m):
        """DDoS guard. A flood is a huge number of connections at a public door. The response is cheap and safe: drop that traffic at the edge (rate-limit the internet link).
        It never touches the control network, so it needs no hospital check. It is released after 30 quiet-looking minutes and re-applied at once if the flood is still there."""
        tr = self.traffic
        if not hasattr(self, "_inet_edges"):
            self._inet_edges = [(e["id"], tr.eidx[e["id"]]) for e in self.ward["edges"] if e["source"] == "INTERNET"]
            self.flood_blocked, self.flood_until, self.flood_pending = {}, {}, []
        flooded = [eid for eid, i in self._inet_edges if counts[i] > 12 * tr.lam[i] + 80 and eid not in self.defence.blocked_edges]
        auto = self.autonomy in ("auto_low", "auto_all") and not self.stopped
        if flooded and auto:
            for eid in flooded:
                self.defence.blocked_edges.add(eid); self.flood_blocked[eid] = m + 30
            self.flood_pending.append(dict(label=f"Drop flood traffic at {len(flooded)} public door{'s' if len(flooded) != 1 else ''} (rate-limit the internet link)", actor="athena:flood-guard", minute=m,
                                           safety="Safe: nothing behind these links runs water or power", target=dict(edge=flooded[0])))
            self.note("flood_guard", "warn", f"Flood of connections at {len(flooded)} public door(s): dropping it at the edge.", hidden=False)
        for eid, until in list(self.flood_blocked.items()):
            if until <= m:
                self.defence.blocked_edges.discard(eid); del self.flood_blocked[eid]    # probe: if the flood is still there it is blocked again within a minute
        self.flood_active = bool(flooded) or bool(self.flood_blocked)
        self.flood_only = bool(flooded) and not obs["violations"] and all(e["src"] == "INTERNET" for e in obs["evidence"])

    def _flood_note(self, m):
        inc = next((i for i in self.incidents if i["status"] in ("open", "contained")), None)
        if inc is not None and getattr(self, "flood_pending", None):
            inc["actions"].extend(self.flood_pending); self.flood_pending = []
            if not any(s["stage"] == "Cut made" for s in inc["stages"]):
                inc["stages"].append(dict(stage="Cut made", minute=m))

    def _incident_logic(self, obs, m):
        p = obs["p"]
        open_inc = next((i for i in self.incidents if i["status"] in ("open", "contained")), None)
        shown = self._heartbeat()["shown"]
        if p > 0.85:
            self.hi += 1
        else:
            self.hi = 0
        if shown > 0.85:
            self.lo = 0
        else:
            self.lo += 1
        if open_inc is None and self.hi >= 2:
            open_inc = self._new_incident(obs, m)
        if open_inc is not None:
            ev = set(open_inc["evidence_nodes"])
            ev |= set(obs["evidence_nodes"])
            open_inc["evidence_nodes"] = sorted(ev)
            for v in obs["violations"]:
                if v["text"] not in open_inc["physics"]:
                    open_inc["physics"].append(v["text"])
                    self.note("physics_alarm", "crit", v["text"], incident=open_inc["id"])
            open_inc["p_max"] = max(open_inc["p_max"], round(p, 3))
            self._zd_assess(open_inc, obs)
            # predicted route
            comp_est = sorted(ev)
            if comp_est:
                open_inc["next_hops"] = self.healer.next_hops(comp_est, self.defence)
            # re-plan when evidence grows
            if self.autonomy != "observe" and len(ev) > open_inc.get("planned_for", 0) and not open_inc.get("planning") and not self._uses_ppo(open_inc) and not getattr(self, "flood_only", False):
                self._request_decision(open_inc)
            # resolve
            quiet = (m - self.last_net_ev) >= 15 and self.lo >= 15 and not (self.live.active(self.live.forced_off) or self.live.active(self.live.breaker_open) or self.live.active(self.live.valve_closed))
            if quiet and open_inc["status"] != "resolved":
                open_inc["status"] = "contained" if open_inc["status"] == "open" else open_inc["status"]
                if self.lo >= 30:
                    self._resolve(open_inc, m)

    def _escalate(self, m):
        """A safety-checked plan must not wait forever: if nobody answers while service is at risk, autonomy applies it (humans can still freeze autonomy)."""
        if self.autonomy not in ("auto_low", "auto_all"):
            return
        harm = self.last_p > 0.85 or bool(self.live.active(self.live.forced_off) or self.live.active(self.live.breaker_open) or self.live.active(self.live.valve_closed))
        if not harm:
            return
        for prop in self.proposals:
            if prop["status"] != "pending" or m - prop["minute"] < ESCALATE_MIN:
                continue
            inc = next((i for i in self.incidents if i["id"] == prop["incident"]), None)
            if inc is None or inc["status"] not in ("open", "contained"):
                continue
            if not all((s.get("safety") or {}).get("ok", True) for s in prop["steps"]):
                continue
            self.note("escalation", "warn", f"Nobody answered {prop['id']} for {ESCALATE_MIN} min while service is at risk: autonomy applied the safety-checked plan.", proposal=prop["id"])
            self.approve(prop["id"], actor="autonomy:escalation", _locked=True)

    def _new_incident(self, obs, m):
        inc = dict(id=f"INC-{len(self.incidents)+1:03d}", t0=m, clock0=self.clock(), deadline=m + 360, status="open", escalated=[], evidence_nodes=[], physics=[],
                   p_max=round(obs["p"], 3), actions=[], next_hops=[], stages=[dict(stage="Detected", minute=m)], iso_cut_at=m, reported=False, planned_for=0,
                   cost=dict(), campaign=None, planning=False, detect_signals=dict(ae=obs["ae"], zmax=obs["zmax"], novelty=obs["novelty"], phys_z=obs["phys_z"]))
        self.incidents.append(inc)
        # iso counterfactual: cut everything now
        if not self.iso_cut:
            self.iso_cut = True
            for pump in ("PS1", "PS2"):
                self.iso.act("pump_duty", pump, int(ISOLATION_H * 60))
        self.note("incident_open", "crit", f"Incident {inc['id']} declared: attack probability {obs['p']:.0%}. CERT-In 6-hour clock started.", incident=inc["id"])
        return inc

    def _resolve(self, inc, m):
        inc["status"] = "resolved"
        inc["stages"].append(dict(stage="Recovered", minute=m))
        L, N, I = self.live, self.none, self.iso
        inc["cost"] = dict(live=round(L.loss_composite()), none=round(N.loss_composite()), iso=round(I.loss_composite()),
                           live_hh=round(L.lost["hh_h"]), none_hh=round(N.lost["hh_h"]), iso_hh=round(I.lost["hh_h"]))
        for pr in self.proposals:
            if pr["incident"] == inc["id"] and pr["status"] == "pending":
                pr["status"] = "expired"
        self.note("incident_resolved", "ok", f"Incident {inc['id']} resolved. The final service-loss comparison (ATHENA vs no response vs isolate-everything) follows once the counterfactual outages play out.", incident=inc["id"])
        inc["cost_due"] = m + 600
        if self.defence.quarantined or self.live.local_mode:
            released = sorted(self.defence.quarantined)
            self.defence.quarantined.clear()
            self.live.local_mode.clear()
            self.note("recovery", "ok", "Recovery: isolation lifted" + (f" for {', '.join(released)}" if released else "") + " after verification. Virtual patches and closed links stay as permanent hardening.", incident=inc["id"])
        self.iso_cut = False
        self.hi = 0
        self.dirty = True

    # ------------------------------------------------------------------ response
    def _request_decision(self, inc):
        inc["planning"] = True
        inc["planned_for"] = len(inc["evidence_nodes"])
        comp = ["INTERNET"] + list(inc["evidence_nodes"])
        done = []
        ctrl_action = {a["controller"]: aid for aid, a in self.ward["actions"].items()}
        for v in self.last_obs.get("violations", []):
            aid = ctrl_action.get(v.get("node"))
            if aid:
                a = self.ward["actions"][aid]
                if not any(d["action"] == aid for d in done):
                    done.append(dict(action=aid, kind=a["kind"], target=a["target"]))
        hour = self.hour()
        defence = self.defence.copy()
        job = lambda: self._decide_job(inc, comp, defence, hour, done)
        if self.sync:
            self._decide_job(inc, comp, defence, hour, done)
        else:
            self.ex_healer.submit(job)

    def _decide_job(self, inc, comp, defence, hour, done):
        try:
            dec = self.healer.decide(comp, defence, hour, done)
        except Exception as e:
            inc["planning"] = False
            self.note("healer_error", "warn", f"Healer error: {e}")
            return
        with self.lock:
            inc["planning"] = False
            self._propose(inc, dec, comp)

    def _propose(self, inc, dec, comp):
        inc["stages"].append(dict(stage="Predicted route", minute=self.live.minute))
        iso = dec["isolate_all"]
        pid = f"P{len(self.proposals)+1:03d}"
        steps = [dict(kind=s["kind"], label=s["label"], service=round(s["service"]), ops=round(s["ops"]), J=round(s["J"]), safety=s.get("safety"),
                      target=dict(node=s.get("node"), nodes=s.get("nodes"), edge=s.get("edge")), raw=s) for s in dec["steps"]]
        prop = dict(id=pid, incident=inc["id"], minute=self.live.minute, status="pending", steps=[{k: v for k, v in s.items() if k != "raw"} for s in steps],
                    observe_J=round(dec["observe"]["J"]), plan_J=round(dec["plan_J"]), isolate_all_J=round(iso["J"]), isolate_all_service=round(iso["service"]),
                    table=[dict(label=r["label"], J=round(r["J"]), remaining=round(r["remaining"]), service=round(r["service"]), ops=round(r["ops"])) for r in (dec["table"] or [])],
                    blocked=[dict(label=b["label"], note=b["safety"]["note"]) for b in dec["blocked"]], raw_steps=[s["raw"] for s in steps],
                    comp=comp, text=self._explain(inc, dec, comp))
        self.proposals.append(prop)
        self.decision_log.append(dict(blocked=len(dec["blocked"]), steps=len(dec["steps"]), blocked_labels=[b["label"] for b in dec["blocked"]]))
        self.note("proposal", "info", f"Healer proposes {len(steps)} step(s): " + "; ".join(s["label"] for s in steps) if steps else "Healer: no action improves on watching.", incident=inc["id"], proposal=pid)
        if not steps:
            prop["status"] = "none"
            return
        # autonomy
        auto = False
        if self.autonomy == "auto_all":
            auto = True
        elif self.autonomy == "auto_low":
            auto = all(s["service"] == 0 and s["ops"] <= 800 and s["kind"] in ("virtual_patch", "close_link", "rotate_creds", "decoy", "quarantine", "manual_restore") for s in steps)
        if auto:
            self.approve(pid, actor="autonomy:" + self.autonomy, _locked=True)
        else:
            self.note("approval_needed", "warn", f"Proposal {pid} needs human approval (autonomy = {self.autonomy}); final authority stays with the operator (CERT-In 10.1).", proposal=pid)

    @staticmethod
    def _explain(inc, dec, comp):
        names = ", ".join(comp[1:4]) if len(comp) > 1 else "the network edge"
        if not dec["steps"]:
            return "Watching only: none of the possible actions lowers expected harm."
        s0 = dec["steps"][0]
        return (f"The attacker is probably at {names}. Doing nothing leaves an expected {dec['observe']['J']:,.0f} household-hour-equivalents of harm. "
                f"The plan ({len(dec['steps'])} step(s)) cuts the expected total to {dec['plan_J']:,.0f}. First step: {s0['label']}. "
                f"Isolating the whole network would cost {dec['isolate_all']['J']:,.0f} and switch off every remote link, so it is only a comparison.")

    def approve(self, pid, actor="operator", _locked=False):
        def run():
            prop = next((p for p in self.proposals if p["id"] == pid), None)
            if not prop or prop["status"] not in ("pending",):
                return False
            inc = next((i for i in self.incidents if i["id"] == prop["incident"]), None)
            for raw in prop["raw_steps"]:
                self._apply_step(raw, inc, actor)
            prop["status"] = "applied"
            if inc:
                inc["stages"].append(dict(stage="Cut made", minute=self.live.minute))
            self.pending_verify = dict(minute=self.live.minute + 20, start=self.live.minute, inc=prop["incident"], pid=pid)
            self.dirty = True
            return True
        if _locked:
            return run()
        with self.lock:
            return run()

    def reject(self, pid, actor="operator"):
        with self.lock:
            prop = next((p for p in self.proposals if p["id"] == pid), None)
            if prop and prop["status"] == "pending":
                prop["status"] = "rejected"
                self.note("proposal_rejected", "info", f"{actor} rejected proposal {pid}.", proposal=pid)
                return True
        return False

    def _apply_step(self, raw, inc, actor):
        d, init = self.healer.apply(raw, self.defence, set())
        self.defence = d
        k = raw["kind"]
        if k == "decoy":
            did = f"DCY{len(self.decoys)+1:02d}"
            self.decoys[did] = dict(id=did, attached_to=raw["node"], mimic="fake pump-station PLC", placed=self.live.minute)
            if inc: inc["stages"].append(dict(stage="Decoy placed", minute=self.live.minute))
        for e in raw.get("events", []):
            self.live.act(e["kind"], e["target"], int(e["dur_h"] * 60))
        if k == "manual_restore":
            self.live.restore(raw["kind_phys"], raw["target"])
            for tag in ("V1_pos", "V2_pos", "CB_F1", "CB_F2", "CB_F3"):
                self.watchdog.authorise(tag, self.live.minute, 90)
            for tg in list(self.live.spoof):
                if raw["target"] in tg:
                    del self.live.spoof[tg]
        if inc is not None:
            inc["actions"].append(dict(minute=self.live.minute, kind=k, label=raw["label"], actor=actor, service=round(raw.get("service", 0)), safety=raw.get("safety", {}).get("note"),
                                       target=dict(node=raw.get("node"), nodes=raw.get("nodes"), edge=raw.get("edge"))))
        self.note("heal_action", "ok", f"{actor}: {raw['label']}", incident=inc["id"] if inc else None)

    def _verify(self, m):
        pv, self.pending_verify = self.pending_verify, None
        inc = next((i for i in self.incidents if i["id"] == pv["inc"]), None)
        progressed = self.last_net_ev > pv["start"] + 3          # odd traffic still showing up well after the response = it did not work
        if progressed and inc:
            self.note("verify_failed", "warn", f"Verification failed: odd traffic is still showing up after {pv['pid']}. Re-planning with new evidence.", incident=inc["id"])
            inc["planned_for"] = 0
        else:
            if inc:
                inc["stages"].append(dict(stage="Verified", minute=m))
            self.note("verify_ok", "ok", f"Verified: no more odd traffic after {pv['pid']}.", incident=pv["inc"])


    # ------------------------------------------------------------------ zero-day lab + RL responder
    def introduce_zero_day(self, product=None, exploit=None, mode="standard", entry=None, goal=None, stealth=None, actor="lab"):
        """Zero-day ingestion: the lab invents an exploit for a product no CVE/EPSS/signature covers and unleashes it."""
        with self.lock:
            g = products(self.ward)
            if product is not None and product not in g:
                raise ValueError("unknown product")
            if exploit is not None and exploit not in EXPLOITS:
                raise ValueError("unknown exploit class")
            if mode not in ("standard", "spoof", "wear", "insider"):
                raise ValueError("unknown mode")
            zd = random_zero_day(self.ward, self.rng, products_allowed=[product] if product else None, exploit=exploit, minute=self.live.minute)
            m = self.live.minute
            c = self.adv.launch(m, mode=mode, entry=entry, goal=goal, stealth=stealth, zd=zd)
            for a in (self.adv_none, self.adv_iso):
                a.launch(m, mode=mode, entry=c.entry, goal=c.goal, stealth=c.stealth, zd=zd)
            self._lab_register(zd, c, actor)
            return c.public()

    def _lab_register(self, zd, c, actor):
        self.zd_lab.append(dict(id=zd.id, product=zd.product, exploit=zd.exploit, exploit_text=EXPLOITS[zd.exploit], affected=zd.affected, campaign=c.id, introduced=self.clock(), minute=self.live.minute,
                                status="introduced", detected_minute=None, family=None, incident=None, actor=actor))
        self.note("zero_day_introduced", "warn", f"[{actor}] Zero-day {zd.id} introduced: {EXPLOITS[zd.exploit].lower()} - no CVE, EPSS score or signature exists. Product is hidden from the defender.", zd=zd.id, hidden=True)

    def _uses_ppo(self, inc):
        if self.ppo is None or self.responder == "search":
            return False
        if self.responder == "ppo":
            return True
        return bool(inc.get("zero_day", {}).get("suspected"))

    def _zd_assess(self, inc, obs):
        """Is this incident explained by known weaknesses? If not, treat it as a suspected zero-day and fingerprint it."""
        ev_edges = inc.setdefault("evidence_edges", [])
        for e in obs.get("evidence", []):
            if e["edge"] not in ev_edges:
                ev_edges.append(e["edge"])
        self.T.node_probs(self.defence)
        parts = getattr(self.T, "last_parts", {})
        def known_p(n):   # chance that a KNOWN exploit or weak credential alone would have let the attacker in
            return 1 - (1 - parts[n]["p_cve"]) * (1 - parts[n]["p_weak"])
        d = self.defence
        unexplained = [n for n in inc["evidence_nodes"] if n in parts and n != "INTERNET"
                       and (known_p(n) < 0.5 or d.cve_mult.get(n, 1.0) < 1.0 or d.weak_mult.get(n, 1.0) < 1.0)]   # a protected device that fell anyway is the classic zero-day sign
        susp = bool(unexplained) or (bool(obs.get("violations")) and not inc["evidence_nodes"])
        zd = inc.setdefault("zero_day", dict(suspected=False, unexplained=[], fingerprint=None))
        if susp and not zd["suspected"]:
            zd["suspected"] = True
            inc["stages"].append(dict(stage="Zero-day suspected", minute=self.live.minute))
            self.note("zero_day_suspected", "crit", f"Zero-day suspected for {inc['id']}: {', '.join(self.ward['assets'][n]['name'] for n in unexplained[:3]) or 'physical anomaly'} compromised with NO known weakness to explain it.", incident=inc["id"])
        zd["unexplained"] = unexplained
        idx = [self.edge_index[e] for e in ev_edges if e in self.edge_index]
        zd["fingerprint"] = fingerprint(self.ward, idx, [self.rlcore.eid[e]["technique"] for e in ev_edges if e in self.rlcore.eid], "low-and-slow" if obs.get("zmax", 0) < 8 else "noisy", len(inc["evidence_nodes"]))

    def _suspect_products(self, inc):
        """Which product family to analyse: the inventory product of every device the Watchdog could not explain with a known weakness. Nothing about the attacker is read."""
        node_prod = self.rlcore.node_prod
        return {n: node_prod[n] for n in inc.get("zero_day", {}).get("unexplained", []) if n in node_prod}

    def _zd_pipeline(self, inc, m):
        """Zero-day pipeline (automatic): keep the incident state, capture + analyse samples, deploy family rules."""
        core = self.rlcore
        zs = inc.get("zs")
        if zs is None:
            zs = inc["zs"] = ZDState()
        zs.observed = set(n for n in inc["evidence_nodes"] if n != "INTERNET")
        if zs.observed and zs.first_obs_step is None:
            zs.first_obs_step = zs.step
        flag = {"PLC_PS1": "pump1", "PLC_PS2": "pump2", "PLC_V1": "valve", "PLC_V2": "valve", "RTU_F1": "breaker", "RTU_F2": "breaker", "RTU_F3": "breaker", "BMS_KEM": "hospital"}
        for v in self.last_obs.get("violations", []):
            if v.get("node") in flag:
                zs.phys_obs[flag[v["node"]]] = 1
        lab_of = self._suspect_products(inc)
        done_p = core.finish_analysis(zs, self.defence, self.zd_lib, m)
        if done_p:
            n = len(core.prod[done_p])
            inc["stages"].append(dict(stage="Family rule deployed", minute=m))
            self.note("zero_day_rule", "ok", f"Sample analysed: family rule deployed to all {n} device(s) of '{done_p}'. The library now recognises this exploit family.", incident=inc["id"])
            self.dirty = True
        started = core.auto_analyse(zs, self.zd_lib, lab_of, m)
        if started:
            inc["stages"].append(dict(stage="Sample captured", minute=m))
            self.note("zero_day_sample", "warn", f"Exploit sample captured from the compromised device(s): analysing '{started}' (behavioural fingerprint, no signature).", incident=inc["id"])
        return zs, lab_of

    def _scorekeeper(self, m):
        """SCOREBOARD (read-only for the defence, which never calls this): keeps the zero-day lab table up to date by comparing what the lab introduced with what the
        defence has done. Nothing computed here feeds back into any defence decision."""
        for lab in self.zd_lab:
            if lab["status"] == "introduced":
                inc = next((i for i in self.incidents if i["t0"] >= lab["minute"] - 2 and i.get("zero_day", {}).get("suspected")), None)
                if inc is not None:
                    st = next((s["minute"] for s in inc["stages"] if s["stage"] == "Zero-day suspected"), m)
                    lab["status"], lab["detected_minute"], lab["incident"] = "suspected", st, inc["id"]
                    self.dirty = True
            if lab["status"] in ("introduced", "suspected") and lab["product"] in self.zd_lib.records and self.zd_lib.learned(lab["product"]):
                lab["status"], lab["family"] = "rule deployed", self.zd_lib.records[lab["product"]]["family"]
                self.dirty = True
            if lab["status"] != "contained":
                c = next((x for x in self.adv.campaigns if x.id == lab["campaign"]), None)
                if c is not None and c.state in ("contained", "done") and (lab["status"] != "introduced" or not c.acted):
                    lab["status"] = "contained"
                    self.dirty = True

    def _rl_tick(self, m):
        if self.autonomy == "observe" or m % DECISION_MIN != 0:
            return
        for inc in self.incidents:
            if inc["status"] == "open":
                try:
                    self._zd_pipeline(inc, m)
                    if self.ppo is not None and self._uses_ppo(inc):
                        self._ppo_step(inc, m)
                except Exception as e:
                    self.note("rl_error", "warn", f"RL responder error: {type(e).__name__}: {e}")

    def _ppo_step(self, inc, m):
        core = self.rlcore
        zs = inc["zs"]
        lab_of = self._suspect_products(inc)
        o = core.obs(zs, self.defence, self.live, self.zd_lib)
        mk = core.mask(zs, self.defence, self.live, self.zd_lib)
        a, _, _, probs = self.ppo.act(o, mk, deterministic=True)
        zs.step += 1
        top = [dict(label=core.label(int(i)), p=round(float(probs[i]), 3)) for i in np.argsort(-probs)[:3]]
        entry = dict(minute=m, clock=self.clock(), action=core.label(a), kind=core.actions[a][0], top=top, valid=int(mk.sum()), applied=False, note="")
        if a != 0:
            k = core.actions[a][0]
            low = (not core.events(a)) and core.ops(a) * 200 <= 800 and not (k == "quar" and core.actions[a][1] in ("SCADA_SRV", "PLC_PS1", "PLC_PS2", "PLC_V1", "PLC_V2", "RTU_F1", "RTU_F2", "RTU_F3", "BMS_KEM"))
            allowed = self.autonomy == "auto_all" or (self.autonomy == "auto_low" and (low or k == "restore"))
            if allowed:
                info = core.apply(a, zs, self.defence, self.live, self.zd_lib, lab_of, m)
                entry["applied"], entry["note"] = True, info.get("note", "")
                if k == "restore":
                    for tag in ("V1_pos", "V2_pos", "CB_F1", "CB_F2", "CB_F3"):
                        self.watchdog.authorise(tag, m, 90)
                    self.live.spoof.clear()
                if k in ("quar", "close", "vp", "creds") and not any(s["stage"] == "Cut made" for s in inc["stages"]):
                    inc["stages"].append(dict(stage="Cut made", minute=m))
                x = core.actions[a][1] if len(core.actions[a]) > 1 else None
                inc["actions"].append(dict(minute=m, kind=k, label=entry["action"], actor="ppo-responder", service=0, safety="Safety Check shield: action was masked unless safe",
                                           target=dict(node=x if k in ("quar", "vp", "creds") else None, nodes=None, edge=x if k == "close" else None)))
                self.note("heal_action", "ok", f"PPO responder: {entry['action']}", incident=inc["id"])
                self.dirty = True
            else:
                entry["note"] = f"recommended only (autonomy = {self.autonomy})"
        inc.setdefault("rl", []).append(entry)
        inc["rl"] = inc["rl"][-12:]

    # ------------------------------------------------------------------ operator tools
    def answer(self, uid, yes):
        with self.lock:
            ok = self.planner.answer(uid, bool(yes))
            if ok:
                self.note("answer", "info", f"Operator answered '{'yes' if yes else 'no'}' to {uid}; map updated, plan recomputed.", uid=uid)
                self.dirty = True
            return ok

    def apply_fix(self, fid, actor="operator"):
        with self.lock:
            f = self.planner.by_id.get(fid)
            if not f:
                raise ValueError("This fix is not in the plan.")
            if fid in self.defence.fixes:
                raise ValueError("Already done: this fix is already in place.")
            f.apply(self.defence)
            self.defence.fixes.append(fid)
            self.note("fix_applied", "ok", f"{actor} applied fix: {f.label}", fix=fid)
            self.dirty = True
            return True

    def whatif(self, fids):
        with self.lock:
            fx = [self.planner.by_id[f] for f in fids if f in self.planner.by_id]
            from .planner import apply_fixes
            d2 = apply_fixes(fx, self.defence)
            before, after = self.T.summary(self.defence), self.T.summary(d2)
            dt = sum(self.planner.best_slot(f)[0] for f in fx)
            return dict(before=before, after=after, fixes=[f.meta() for f in fx], downtime_loss=round(dt, 1), cost=sum(f.cost for f in fx))

    def timeguard_skew(self, source, seconds):
        with self.lock:
            self.tg.set_skew(source, seconds)
            self.note("time_skew", "warn", f"Clock of {source} skewed by {seconds}s; its events are flagged time-uncertain.", source=source)

    # ------------------------------------------------------------------ analytics (background)
    def _analytics_job(self):
        while self.running:
            if self.dirty:
                self.dirty = False
                try:
                    self.refresh_analytics()
                except Exception as e:
                    self.health["restarts"] += 1
                    self.health["last_restart"] = f"analytics: {type(e).__name__}: {e}"
                    self.bb.append("module_restart", dict(error=str(e), module="analytics"))
            time.sleep(0.5)

    def refresh_analytics(self, with_voi=True):
        defence = self.defence.copy()
        a = {}
        if self.analytics_base is None:
            self.analytics_base = self.T.summary(None)
        cur = self.T.summary(defence)
        a["summary"] = cur
        a["baseline"] = self.analytics_base
        e0, rr = self.T.raw_rrw(defence)
        bl = self.T.baselines()
        ids = [i for i in self.ward["assets"] if i != "INTERNET"]
        rank_cv = {n: r for r, n in enumerate(sorted(ids, key=lambda n: -bl["cvss_x_importance"][n]), 1)}
        rank_sar = {n: r for r, n in enumerate(sorted(ids, key=lambda n: -rr[n]["rrw"]), 1)}
        rows = []
        for n in ids:
            asset = self.ward["assets"][n]
            c = self.T.snap["cves"].get(asset["cve"] or "", {})
            rows.append(dict(id=n, name=asset["name"], layer=asset["layer"], cve=asset["cve"], cvss=c.get("cvss"), epss=c.get("epss"), kev=c.get("in_kev"),
                             raw=round(rr[n]["raw"]), rrw=round(rr[n]["rrw"]), rank_sar=rank_sar[n], rank_cvss=rank_cv[n], move=rank_cv[n] - rank_sar[n]))
        rows.sort(key=lambda r: r["rank_sar"])
        a["ranking"] = rows
        a["reversals"] = sum(1 for r in rows if abs(r["move"]) > 10)
        a["paths"] = self.T.top_paths(defence)
        def hist(d):
            L = self.T.evaluate(d)["L"]
            edges = np.linspace(0, 250000, 26)
            h, _ = np.histogram(L[L > 0], bins=edges)
            return dict(edges=[float(x) for x in edges], counts=[int(x) for x in h], zero_frac=float((L == 0).mean()), sar95=float(np.quantile(L, 0.95)), sar99=float(np.quantile(L, 0.99)), mean=float(L.mean()))
        a["hist_now"] = hist(defence)
        a["hist_base"] = self.analytics_hist_base if hasattr(self, "analytics_hist_base") else hist(None)
        self.analytics_hist_base = a["hist_base"]
        plan = self.planner.plan(defence, 12.0, now_hour=self.hour())
        sched = self.planner.schedule(plan)
        a["plan"] = dict(steps=plan["steps"], e_start=round(plan["e_start"]), e_end=round(plan["e_end"]), spent=plan["spent"], refused=plan["refused"][:5])
        a["schedule"] = sched
        a["after_plan"] = self.T.summary(plan["defence"])
        a["hist_after"] = hist(plan["defence"])
        a["catalog"] = [f.meta() for f in self.planner.catalog if f.id not in defence.fixes]
        a["unknowns_pending"] = len(self.planner.unknowns())
        a["version"] = self.analytics.get("version", 0) + 1
        a["computing"] = False
        a["voi"] = self.analytics.get("voi", []) if self.analytics.get("voi") else []
        a["voi_computing"] = with_voi
        a["updated_minute"] = self.live.minute
        self.analytics = a
        if with_voi:
            self.planner.n = 1000
            v, _ = self.planner.value_of_information(defence, 6.0)
            self.planner.n = 1500
            a["voi"] = v
            a["voi_computing"] = False
        self.phys.save()

    # ------------------------------------------------------------------ snapshots
    def static(self):
        w = self.ward
        return dict(meta=w["meta"], assets=w["assets"], edges=[{k: v for k, v in e.items() if k != "truth"} for e in w["edges"]], physical=w["physical"], actions=w["actions"],
                    water=w["water"], power=w["power"], assumptions=ASSUMPTIONS, threat_snapshot=dict(fetched=self.T.snap["fetched_utc"], kev=self.T.snap["kev_catalog_version"], cves=self.T.snap["cves"]),
                    modes=MODES)

    def snapshot(self, role="analyst"):
        with self.lock:
            L = self.live
            rep = L.last.get("reported", {})
            svc = L.services()
            events, self.new_events = self.new_events, []
            nodes = {}
            comp_known = set()
            for inc in self.incidents:
                if inc["status"] in ("open", "contained"):
                    comp_known |= set(inc["evidence_nodes"])
            for nid in self.ward["assets"]:
                st = "normal"
                if nid in self.defence.quarantined:
                    st = "quarantined"
                elif nid in comp_known:
                    st = "suspect"
                nodes[nid] = st
            snap = dict(
                t=L.minute, hour=round(L.hour(), 2), clock=self.clock(),
                tele={k: round(float(v), 3) for k, v in rep.items() if not k.startswith("P_")},
                press={h: round(L.press_h[h], 2) for h in L.press_h},
                levels=dict(L.level),
                pumps=dict(L.pump_on), forced={k: bool(v > L.minute) for k, v in L.forced_off.items()},
                services=svc,
                compare=dict(live=round(L.loss_composite()), none=round(self.none.loss_composite()), iso=round(self.iso.loss_composite()),
                             live_hh=round(L.lost["hh_h"]), none_hh=round(self.none.lost["hh_h"]), iso_hh=round(self.iso.lost["hh_h"]),
                             none_served=self.none.services()["served_frac"], iso_served=self.iso.services()["served_frac"],
                             none_cum=self.none.services()["cum"], iso_cum=self.iso.services()["cum"], none_levels=dict(self.none.level), iso_levels=dict(self.iso.level), none_hosp=self.none.services()["hospitals"], iso_hosp=self.iso.services()["hospitals"]),
                stopped=self.stopped, paused=self.paused,
                watch=dict(**self._heartbeat(), cusum=round(self.watchdog.cs, 2), cusum_line=round(getattr(self.watchdog, "cs_h", 0), 2), hits=self.hi, flood=bool(getattr(self, "flood_active", False)), p=round(self.last_p, 3), ae=self.last_obs.get("ae"), zmax=self.last_obs.get("zmax"), novelty=self.last_obs.get("novelty"), phys_z=self.last_obs.get("phys_z"),
                           violations=[dict(rule=v["rule"], text=v["text"], node=v["node"]) for v in self.last_obs.get("violations", [])][:4],
                           evidence=self.last_obs.get("evidence", [])[:3], drift_events=self.watchdog.drift_events),
                nodes=nodes,
                defence=dict(blocked=sorted(self.defence.blocked_edges), quarantined=sorted(self.defence.quarantined), fixes=list(self.defence.fixes),
                             decoys=list(self.decoys.values()), forced_local=[k for k, v in L.local_mode.items() if v > L.minute]),
                incidents=[self._inc_public(i) for i in self.incidents[-4:]],
                proposals=[{k: v for k, v in p.items() if k != "raw_steps"} for p in self.proposals[-4:]],
                events=events, autonomy=self.autonomy, autopilot=self.autopilot, speed=self.speed,
                health=dict(self.health), analytics_version=self.analytics.get("version", 0),
                brk_ops=rep.get("BRK_OPS_10M", 0), learned=self.watchdog.drift_events,
            )
            if role in ("analyst", "admin"):
                snap["adversary"] = [c.public() for c in self.adv.campaigns[-8:]]
            reveal = role in ("analyst", "admin")
            inc_open = next((i for i in reversed(self.incidents) if i["status"] in ("open", "contained", "resolved")), None)
            snap["zero_day"] = dict(
                lab=[(l if reveal else {k: v for k, v in l.items() if k not in ("product", "affected")}) for l in self.zd_lab[-6:]],
                library=self.zd_lib.public(), responder=self.responder, ppo_loaded=self.ppo is not None,
                rl=(inc_open.get("rl", []) if inc_open else []), suspected=bool(inc_open and inc_open.get("zero_day", {}).get("suspected")),
                fingerprint=(inc_open.get("zero_day", {}).get("fingerprint") if inc_open else None))
            return snap

    def _inc_public(self, i):
        left = max(0, i["deadline"] - self.live.minute)
        return dict(id=i["id"], status=i["status"], t0=i["t0"], clock0=i["clock0"], deadline=i["deadline"], left_min=left, reported=i["reported"], p_max=i["p_max"],
                    evidence_nodes=i["evidence_nodes"], physics=i["physics"][:4], actions=i["actions"], next_hops=i["next_hops"], stages=i["stages"], cost=i["cost"],
                    planning=i["planning"], signals=i["detect_signals"])

    # ------------------------------------------------------------------ reports & compliance
    def report(self, inc_id):
        with self.lock:
            inc = next((i for i in self.incidents if i["id"] == inc_id), None)
            if not inc:
                return None
            assets = self.ward["assets"]
            skewed = [s for s in self.tg.skew if self.tg.uncertain(s)]
            rep = dict(
                title=f"Cyber incident report {inc['id']}", prepared_for="CERT-In (incident@cert-in.org.in, 1800-11-4949 as listed in the Smart City Guidelines ch.12)",
                directions="CERT-In Directions of 28 April 2022: report within 6 hours of noticing the incident",
                point_of_contact=dict(name="Designated Point of Contact (configure)", role="Smart City cyber officer", phone="(configure)"),
                incident=dict(id=inc["id"], detected=inc["clock0"], deadline_minute=inc["deadline"], category="Attack on ICS / SCADA / OT systems (confirm against the Directions' Annexure I list)", severity="High (service affecting)" if inc["physics"] else "Medium", status=inc["status"]),
                what=dict(summary="Suspicious lateral movement and/or physical-process anomaly detected by the Watchdog.", physics_findings=inc["physics"], detection_signals=inc["detect_signals"]),
                where=dict(assets=[dict(id=n, name=assets[n]["name"], zone=assets[n]["zone"], purdue=assets[n]["purdue"], cve=assets[n]["cve"]) for n in inc["evidence_nodes"]]),
                how=dict(predicted_route=inc["next_hops"], attack_techniques="MITRE ATT&CK for ICS (see route edges)"),
                actions_taken=inc["actions"], ir_phases=dict(preparation="Playbooks + Black Box Log active", detection=inc["stages"][0] if inc["stages"] else None, containment=[a for a in inc["actions"]], eradication="Pending forensic validation", recovery=inc["stages"][-1], post_incident_review=inc["cost"] or "pending"),
                evidence=dict(black_box_head=self.bb.head[:32], log_integrity=self.bb.verify(), logs_retention_days=180, time_uncertain_sources=skewed),
                generated=self.clock())
            return rep

    def mark_reported(self, inc_id):
        with self.lock:
            inc = next((i for i in self.incidents if i["id"] == inc_id), None)
            if inc:
                inc["reported"] = True
                inc["status"] = "reported" if inc["status"] == "resolved" else inc["status"]
                self.note("incident_reported", "ok", f"Incident {inc_id} report exported to CERT-In package.", incident=inc_id)
                return True
        return False

    def compliance(self):
        with self.lock:
            a = self.ward["assets"]
            att = [x for x in a.values() if x["id"] != "INTERNET"]
            sbom_cov = sum(1 for x in att if x.get("sbom")) / len(att)
            iot_mis = [e for e in self.ward["edges"] if e["misconfig"]]
            return dict(
                clocks=[self._inc_public(i) for i in self.incidents[-5:]], vault=self.vault.status(), chain=self.bb.verify(), time=self.tg.status(),
                sbom_coverage=round(sbom_cov, 3), misconfigurations=[dict(edge=e["id"], text=e["misconfig"], src=e["source"], dst=e["target"], known=e["known"]) for e in iot_mis],
                audits=dict(internal_last="2026-06-12 (synthetic)", internal_next_due="2026-12-12 (every 6 months, ch.19)", third_party_last="2026-03-02 (synthetic)", third_party_next_due="2027-03-02 (yearly, ch.19)"),
                contact=dict(email="incident@cert-in.org.in", phone="1800-11-4949", source="Guidelines ch.12 / Useful Guidelines page"),
                threat_patterns=dict(region="Western India (Mumbai)", malware="Trojans (avalanche-andromeda, gamarue)", weakness="Remote connections allowed to unauthorised computers", source="Guidelines ch.2.3 (CERT-In analysis of 20 smart cities, 2024)"),
                standards=["CERT-In Smart City Guidelines 2025", "CERT-In Directions 28 Apr 2022", "MoHUA Advisories 22, 24, 25", "IEC 62443 zones & conduits", "NIST CSF 2.0", "MITRE ATT&CK for ICS"])
