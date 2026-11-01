"""ATTACKER SIDE. A stateful attacker that moves hop by hop through the *true* network (hidden links included), emits network traffic and finally
issues a physical command. It never touches anything outside the simulation.

Separation rule: this file knows nothing about the defender. It does not import or read the defence, the healer, the planner, the watchdog or any
fix that was applied. The only thing it talks to is the ENVIRONMENT (environment.py): it asks "may I try this link?" and gets back what happened
(ok / failed / refused / decoy), exactly as a real attacker would learn it. A cut link is not "seen" by the attacker; it simply stops answering."""
from __future__ import annotations

import heapq
import math

import numpy as np

from .assumptions import ASSUMPTIONS
from .zeroday import random_zero_day

MODES = {
    "standard": "Skilled attacker using known exploits",
    "zero_day": "Unknown exploit (no CVE signature)",
    "spoof": "Controller takeover with telemetry spoofing",
    "wear": "Breaker wear attack (rapid cycling)",
    "insider": "Insider already inside the network (stolen login)",
    "ddos": "DDoS flood on the public-facing services",
    "swarm": "Many small attacks at once, each too quiet to trip the alarm on its own",
    "blitz": "Fast and loud: crosses a link every minute or two, trying to finish before anyone reacts",
    "group": "Coordinated group: three attackers, different doors and targets, plus a flood",
}


class Campaign:
    _n = 0

    def __init__(self, entry, goal, mode, stealth, started):
        Campaign._n += 1
        self.id = f"C{Campaign._n:03d}"
        self.entry, self.goal, self.mode, self.stealth = entry, goal, mode, stealth
        self.started = started
        self.compromised = ["INTERNET"]
        self.hops = []          # (minute, edge_id, src, dst)
        self.state = "recon"    # recon -> moving -> acting -> done / contained
        self.timer = 3
        self.target_path = []
        self.attempts = {}
        self.hardened = set()
        self.dead = set()        # links this attacker found unresponsive
        self.refused = {}
        self.zd = None
        self.acted = False
        self.touched_decoy = None
        self.cycle_left = 0
        self.quiet = False       # low and slow: tiny traces, long pauses
        self.fast = mode == "blitz"   # fast and loud: very short pauses
        self.flood_minutes = 0   # DDoS: minutes the flood ran
        self.flood_open = 0      # DDoS: minutes it still reached at least one public door

    def public(self):
        return dict(id=self.id, entry=self.entry, goal=self.goal, mode=self.mode, state=self.state, flood_minutes=self.flood_minutes, flood_open=self.flood_open, compromised=list(self.compromised), zero_day=(self.zd.public() if self.zd else None),
                    hops=[dict(minute=h[0], edge=h[1], src=h[2], dst=h[3]) for h in self.hops], started=self.started)


class Adversary:
    def __init__(self, ward, seed=3):
        self.ward = ward
        self.rng = np.random.default_rng(seed)
        self.campaigns: list[Campaign] = []
        self.assets = ward["assets"]
        self.out = {}
        for i, e in enumerate(ward["edges"]):
            if e["truth"]:
                self.out.setdefault(e["source"], []).append(e)
        self.goals = {a["controller"]: aid for aid, a in ward["actions"].items()}

    # ------------------------------------------------------------------ planning (from the attacker's own picture of the network only)
    def _plan(self, c: Campaign, env):
        """Dijkstra from what the attacker holds to its goal; weights = -log(chance of success). The chances come from reconnaissance (a scan of the undefended
        network, delivered by the environment) and from links the attacker has itself found dead. It cannot see the defender's state."""
        pn, idx = env.recon()
        dist, prev, pq = {}, {}, []
        for n in c.compromised:
            dist[n] = 0.0
            heapq.heappush(pq, (0.0, n))
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist.get(u, 1e9):
                continue
            if u == c.goal:
                break
            for e in self.out.get(u, []):
                v = e["target"]
                if v in c.hardened or e["id"] in c.dead:
                    continue
                if u == "INTERNET" and v != c.entry:
                    continue
                pv = min(0.95, c.zd.p) if (c.zd is not None and v in c.zd.affected) else float(pn[idx[v]])
                nd = d - math.log(max(1e-3, e["p_access"] * pv))
                if nd < dist.get(v, 1e9):
                    dist[v], prev[v] = nd, e
                    heapq.heappush(pq, (nd, v))
        if c.goal not in dist:
            return None
        path, v = [], c.goal
        while v not in c.compromised:
            e = prev[v]
            path.append(e)
            v = e["source"]
        return list(reversed(path))

    # ------------------------------------------------------------------ API
    def launch(self, minute, mode="standard", entry=None, goal=None, stealth=None, weights=None, zd=None):
        entries = [n for n, a in self.assets.items() if a["entry_weight"] > 0]
        recent = getattr(self, "_recent_entries", [])
        if entry is None and mode == "insider":    # someone already inside: starts on an internal office / DMZ / control machine
            inside = [n for n, a in self.assets.items() if a["layer"] in ("it", "dmz", "control") and a["exposure"] != "internet"]
            entry = str(self.rng.choice(inside))
        elif entry is None:
            w = np.array([self.assets[n]["entry_weight"] for n in entries]) ** 0.5     # flatten: a popular door is likelier, not dominant
            w = w * np.array([0.35 if n in recent[-2:] else 1.0 for n in entries])      # and avoid repeating the last two entry points
            entry = str(self.rng.choice(entries, p=w / w.sum()))
        self._recent_entries = (recent + [entry])[-6:]
        if goal is None:
            goals = list(self.goals.keys())
            goal = str(self.rng.choice(goals, p=weights)) if weights is not None else str(self.rng.choice(goals))
        st = float(stealth) if stealth is not None else float(self.rng.uniform(2.0, 9.0))
        c = Campaign(entry, goal, mode, st, minute)
        if mode == "ddos":
            c.timer = int(self.rng.integers(45, 100))     # how long the flood lasts, in minutes
        if self.assets[entry]["exposure"] != "internet" and entry != "INTERNET":
            c.compromised.append(entry)      # an internal start (insider, or a device picked on the map): the attacker already holds it, so no internet hop is needed
        if zd is None and mode == "zero_day":
            zd = random_zero_day(self.ward, self.rng, minute=minute)
        c.zd = zd
        self.campaigns.append(c)
        return c

    def tick(self, minute, env):
        """Advance every live campaign by one minute. Returns (flows, physical, events). `env` is the environment this attacker acts in."""
        flows, phys, events = [], [], []
        for c in self.campaigns:
            if c.state in ("done", "contained"):
                continue
            if c.mode == "ddos":
                # a flood: a huge number of connections at every public door. It does not touch the control network, but it blinds and blocks the public services.
                c.timer -= 1
                if c.timer <= 0:
                    c.state = "done"
                    events.append(dict(type="ddos_end", campaign=c.id, minute=minute, text=f"{c.id}: the flood stopped"))
                    continue
                c.state = "flooding"
                doors = [e["id"] for e in self.out.get("INTERNET", [])]
                for eid in doors:
                    flows.append((eid, "read", int(self.rng.poisson(150 + 60 * c.stealth))))
                c.flood_minutes += 1
                events.append(dict(type="flood", campaign=c.id, minute=minute, edges=doors))
                continue
            c.timer -= 1
            # persistent chatter while moving
            if c.state == "moving" and c.target_path:
                e = c.target_path[0]
                flows.append((e["id"], "read", max(1, int(self.rng.poisson(c.stealth)))))
            if c.timer > 0:
                continue
            if c.state == "recon":
                c.state = "moving"
                c.timer = 1
                continue
            if c.state == "moving":
                path = self._plan(c, env)
                if path is None:
                    c.state, c.timer = "contained", 0
                    events.append(dict(type="attack_blocked", campaign=c.id, minute=minute, text=f"{c.id}: no usable route left to the target"))
                    continue
                c.target_path = path
                e = path[0]
                tgt = e["target"]
                c.attempts[tgt] = c.attempts.get(tgt, 0) + 1
                flows.append((e["id"], "read", int((1 + self.rng.poisson(c.stealth)) if c.quiet else (5 + self.rng.poisson(c.stealth * 2)))))
                r = env.attempt_hop(c, e, minute)          # the only way the attacker learns what happened
                flows.extend(r.get("flows", []))
                events.extend(r.get("events", []))
                out = r["outcome"]
                if out == "decoy":
                    c.touched_decoy = r.get("decoy")
                    if r.get("trapped"):
                        c.state = "contained"
                    c.timer = 6
                    continue
                if out == "refused":
                    c.refused[e["id"]] = c.refused.get(e["id"], 0) + 1
                    if c.refused[e["id"]] >= 2:
                        c.dead.add(e["id"])          # it has learned this link does not answer any more
                    c.timer = int(self.rng.integers(2, 5))
                    continue
                if out == "ok":
                    c.compromised.append(tgt)
                    c.hops.append((minute, e["id"], e["source"], tgt))
                    c.attempts[tgt] = 0
                    events.append(dict(type="hop", campaign=c.id, minute=minute, edge=e["id"], src=e["source"], dst=tgt, technique=e["technique"]))
                    if tgt == c.goal:
                        c.state, c.timer = "acting", 4
                    else:
                        c.timer = int(self.rng.integers(1, 3)) if c.fast else int(self.rng.integers(4, 11)) * (3 if c.quiet else 1)
                else:
                    if c.attempts[tgt] >= 3:
                        c.hardened.add(tgt)
                    c.timer = int(self.rng.integers(1, 3)) if c.fast else int(self.rng.integers(4, 9)) * (3 if c.quiet else 1)
                continue
            if c.state == "acting":
                aid = self.goals.get(c.goal)
                if aid is None:
                    c.state = "done"
                    continue
                if not env.attempt_command(c):
                    c.state = "contained"
                    events.append(dict(type="attack_blocked", campaign=c.id, minute=minute, text=f"{c.id}: the controller no longer answers"))
                    continue
                act = self.ward["actions"][aid]
                rep = ASSUMPTIONS["repair_h"]
                dur = int(rep[act["repair"]] * 60)
                if c.mode == "wear" and act["kind"] == "breaker_open":
                    dur = int(rep["breaker_lockout"] * 60)
                    c.cycle_left = 6
                phys.append(dict(campaign=c.id, action=aid, kind=act["kind"], target=act["target"], dur_min=dur, controller=c.goal, mode=c.mode))
                flows.append((c.hops[-1][1] if c.hops else "NONE", "write", 18))
                c.acted = True
                if c.cycle_left:
                    c.state, c.timer = "acting_wear", 1
                else:
                    c.state = "done"
                events.append(dict(type="physical_action", campaign=c.id, minute=minute, action=aid, text=act["label"]))
                continue
            if c.state == "acting_wear":
                phys.append(dict(campaign=c.id, action="WEAR_CYCLE", kind="wear", target=self.ward["actions"][self.goals[c.goal]]["target"], dur_min=0, controller=c.goal, mode="wear"))
                flows.append((c.hops[-1][1] if c.hops else "NONE", "write", 12))
                c.cycle_left -= 1
                c.timer = 1
                if c.cycle_left <= 0:
                    c.state = "done"
        return flows, phys, events

    def active(self):
        return [c for c in self.campaigns if c.state not in ("done", "contained")]
