"""Red-team adversary: a stateful attacker that moves hop by hop through the *true* network (hidden links included),
emits observable network flows, and finally performs a physical action. Used for the Autopilot adversary, the manual
attack console, and for training/validating the Watchdog. It never touches anything outside the simulation."""
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
    "insider": "Insider with vendor credentials",
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
        self.zd = None
        self.acted = False
        self.touched_decoy = None
        self.cycle_left = 0

    def public(self):
        return dict(id=self.id, entry=self.entry, goal=self.goal, mode=self.mode, state=self.state, compromised=list(self.compromised), zero_day=(self.zd.public() if self.zd else None),
                    hops=[dict(minute=h[0], edge=h[1], src=h[2], dst=h[3]) for h in self.hops], started=self.started)


class Adversary:
    def __init__(self, ward, threat, seed=3, defence_provider=None):
        self.ward, self.T = ward, threat
        self.rng = np.random.default_rng(seed)
        self.defence_provider = defence_provider or (lambda: None)
        self.campaigns: list[Campaign] = []
        self.assets = ward["assets"]
        self.out = {}
        for i, e in enumerate(ward["edges"]):
            if e["truth"]:
                self.out.setdefault(e["source"], []).append(e)
        self.goals = {a["controller"]: aid for aid, a in ward["actions"].items()}

    # ------------------------------------------------------------------ planning
    def _p(self, node, defence, c, pn=None):
        zd = c.zd
        if zd is not None and node in zd.affected:
            return min(0.95, zd.p * (defence.zd_mult.get(node, 1.0) if defence else 1.0))
        if pn is None:
            pn = self.T.node_probs(defence)
        return float(pn[self.T.idx[node]])

    def _edge_ok(self, e, defence):
        if defence is None:
            return True
        if e["id"] in defence.blocked_edges:
            return False
        return e["source"] not in defence.quarantined and e["target"] not in defence.quarantined

    def _plan(self, c: Campaign, defence, decoys):
        """Dijkstra from the compromised set to the goal controller; weights = -log(success probability)."""
        dist, prev = {}, {}
        pq = []
        pn = self.T.node_probs(defence)
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
                if v in c.hardened or not self._edge_ok(e, defence):
                    continue
                if u == "INTERNET" and v != c.entry:
                    continue
                pe = e["p_access"] * (defence.edge_mult.get(e["id"], 1.0) if defence else 1.0)
                p = max(1e-3, pe * self._p(v, defence, c, pn))
                nd = d - math.log(p)
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
        if entry is None:
            w = np.array([self.assets[n]["entry_weight"] for n in entries])
            entry = str(self.rng.choice(entries, p=w / w.sum()))
        if goal is None:
            goals = list(self.goals.keys())
            goal = str(self.rng.choice(goals, p=weights)) if weights is not None else str(self.rng.choice(goals))
        st = float(stealth) if stealth is not None else float(self.rng.uniform(2.0, 9.0))
        c = Campaign(entry, goal, mode, st, minute)
        if zd is None and mode == "zero_day":
            zd = random_zero_day(self.ward, self.rng, minute=minute)
        c.zd = zd
        self.campaigns.append(c)
        return c

    def tick(self, minute, defence=None, decoys=None):
        """Advance every live campaign by one minute. Returns (flows, physical, events)."""
        flows, phys, events = [], [], []
        for c in self.campaigns:
            if c.state in ("done", "contained"):
                continue
            c.timer -= 1
            # persistent chatter while moving (what the Watchdog can see)
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
                path = self._plan(c, defence, decoys)
                if path is None:
                    c.state, c.timer = "contained", 0
                    events.append(dict(type="attack_blocked", campaign=c.id, minute=minute, text=f"{c.id}: no usable route left to the target"))
                    continue
                c.target_path = path
                e = path[0]
                # lured by a decoy next to the attacker?
                if decoys:
                    near = [d for d in decoys.values() if d["attached_to"] in c.compromised]
                    if near and self.rng.random() < 0.6:
                        d = near[0]
                        flows.append((f"DECOY:{d['id']}", "read", 25))
                        c.touched_decoy = d["id"]
                        events.append(dict(type="decoy_touch", campaign=c.id, minute=minute, decoy=d["id"], text=f"Decoy {d['id']} touched by attacker from {d['attached_to']}"))
                        if self.rng.random() < 0.85:
                            c.state = "contained"
                            events.append(dict(type="attack_blocked", campaign=c.id, minute=minute, text=f"{c.id}: attacker trapped in decoy"))
                        c.timer = 6
                        continue
                tgt = e["target"]
                pe = e["p_access"] * (defence.edge_mult.get(e["id"], 1.0) if defence else 1.0)
                p = pe * self._p(tgt, defence, c)
                c.attempts[tgt] = c.attempts.get(tgt, 0) + 1
                flows.append((e["id"], "read", int(5 + self.rng.poisson(c.stealth * 2))))
                if self.rng.random() < p:
                    c.compromised.append(tgt)
                    c.hops.append((minute, e["id"], e["source"], tgt))
                    c.attempts[tgt] = 0
                    events.append(dict(type="hop", campaign=c.id, minute=minute, edge=e["id"], src=e["source"], dst=tgt, technique=e["technique"]))
                    if tgt == c.goal:
                        c.state, c.timer = "acting", 4
                    else:
                        c.timer = int(self.rng.integers(4, 11))
                else:
                    if c.attempts[tgt] >= 3:
                        c.hardened.add(tgt)
                    c.timer = int(self.rng.integers(4, 9))
                continue
            if c.state == "acting":
                aid = self.goals.get(c.goal)
                if aid is None:
                    c.state = "done"
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
