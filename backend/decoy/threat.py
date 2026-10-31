"""Threat Finder + Path Predictor + Risk Scorer.

Probabilistic attack graph over the cyber assets. A "possible world" fixes which edges are usable and which devices
fall to their exploit; the attacker enters at one internet-facing device and spreads along usable edges. The
compromised controllers translate to physical actions; the Impact Simulator turns those into service loss.
Common random numbers (CRN) make before/after comparisons exact: the same worlds are reused for every what-if.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field

import numpy as np

from .assumptions import A
from .city import DATA

N_BUCKETS = 8  # attack start hour = 3 * bucket
# Residual per-hop compromise even when the listed CVE is blocked: stolen credentials, unknown (zero-day) bugs, insiders.
# Scaled by attacker skill (UI dial: casual 0.4 ... process-aware APT 1.6). Assumption, see assumptions.py.
FLOOR = {"iot": 0.15, "it": 0.15, "dmz": 0.20, "control": 0.30, "field": 0.30, "internet": 0.0}
VP_EFFICACY = 0.85  # a virtual patch stops 85% of exploit attempts on that CVE


def load_snapshot():
    p = DATA / "threat_snapshot.json"
    return json.loads(p.read_text(encoding="utf-8"))


@dataclass
class Defence:
    blocked_edges: set = field(default_factory=set)
    cve_mult: dict = field(default_factory=dict)    # node -> multiplier on exploit probability (virtual patch 0.1, patched 0)
    weak_mult: dict = field(default_factory=dict)   # node -> multiplier on weak-config probability (MFA, rotate creds)
    edge_mult: dict = field(default_factory=dict)   # edge id -> multiplier on p_access (MFA on vendor link)
    zd_mult: dict = field(default_factory=dict)     # node -> multiplier on a ZERO-DAY exploit (behavioural rules / virtual patches)
    quarantined: set = field(default_factory=set)
    fixes: list = field(default_factory=list)       # human-readable applied fixes

    def copy(self):
        return copy.deepcopy(self)


class ThreatModel:
    def __init__(self, ward: dict, physics, n_samples: int = 3000, seed: int = 7):
        self.ward, self.phys = ward, physics
        self.snap = load_snapshot()
        self.ids = list(ward["assets"].keys())
        self.idx = {a: i for i, a in enumerate(self.ids)}
        self.V = len(self.ids)
        self.edges = ward["edges"]
        self.E = len(self.edges)
        self.src = np.array([self.idx[e["source"]] for e in self.edges])
        self.dst = np.array([self.idx[e["target"]] for e in self.edges])
        self.eid = {e["id"]: i for i, e in enumerate(self.edges)}
        self.inet = self.idx["INTERNET"]
        self.action_ids = list(ward["actions"].keys())
        self.ctrl_idx = np.array([self.idx[ward["actions"][a]["controller"]] for a in self.action_ids])
        self.S = n_samples
        rng = np.random.default_rng(seed)
        self.U_edge = rng.random((n_samples, self.E))
        self.U_node = rng.random((n_samples, self.V))
        self.U_entry = rng.random(n_samples)
        self.U_start = rng.integers(0, N_BUCKETS, n_samples)
        w = np.array([ward["assets"][i]["entry_weight"] for i in self.ids], dtype=float)
        self.entry_p = w / w.sum()
        self.entry_choice = np.searchsorted(np.cumsum(self.entry_p), self.U_entry)
        self.entry_choice = np.clip(self.entry_choice, 0, self.V - 1)
        self.last_eval = None
        self.skill = 1.0

    # ---------------------------------------------------------------- probabilities
    def p_exploit(self, cve):
        if not cve:
            return 0.0
        c = self.snap["cves"].get(cve)
        if not c:
            return 0.0
        ep = c["epss"] or 0.0
        return max(ep, 0.6) if c["in_kev"] else ep

    def node_probs(self, defence: Defence | None):
        d = defence or Defence()
        p = np.zeros(self.V)
        parts = {}
        for i, nid in enumerate(self.ids):
            a = self.ward["assets"][nid]
            if nid == "INTERNET":
                p[i] = 1.0
                continue
            pc = (1 - a["p_patched"]) * self.p_exploit(a["cve"]) * (a["cve_belief"] if not a["known_version"] else 1.0)
            pc *= d.cve_mult.get(nid, 1.0)
            pw = a["p_weak"] * d.weak_mult.get(nid, 1.0)
            floor = min(0.9, FLOOR[a["layer"]] * self.skill)
            p[i] = 1 - (1 - pc) * (1 - pw) * (1 - floor)
            parts[nid] = dict(p_cve=round(pc, 4), p_weak=round(pw, 4), p=round(float(p[i]), 4))
        for q in d.quarantined:
            p[self.idx[q]] = 0.0
        self.last_parts = parts
        return p

    def edge_probs(self, defence: Defence | None):
        d = defence or Defence()
        pe = np.zeros(self.E)
        for i, e in enumerate(self.edges):
            pa = e["p_access"] * (e["belief"] if not e["known"] else (1.0 if e["truth"] else 0.0))
            pa *= d.edge_mult.get(e["id"], 1.0)
            if e["id"] in d.blocked_edges or e["blocked"]:
                pa = 0.0
            if e["source"] in d.quarantined or e["target"] in d.quarantined:
                pa = 0.0
            pe[i] = pa
        return pe

    # ---------------------------------------------------------------- world evaluation
    def reach(self, defence=None, hacked=(), protected=(), init=None, track=False, n=None):
        S = n or self.S
        pn = self.node_probs(defence)
        pe = self.edge_probs(defence)
        for h in protected:
            pn[self.idx[h]] = 0.0
        comp = self.U_node[:S] < pn[None, :]
        up = self.U_edge[:S] < pe[None, :]
        # attacker picks one entry point
        inet_edges = np.where(self.src == self.inet)[0]
        for e in inet_edges:
            up[:, e] &= self.entry_choice[:S] == self.dst[e]
        reached = np.zeros((S, self.V), bool)
        parent = np.full((S, self.V), -1, int) if track else None
        if init:
            for h in init:
                reached[:, self.idx[h]] = True
        else:
            reached[:, self.inet] = True
        for h in hacked:
            reached[:, self.idx[h]] = True
            comp[:, self.idx[h]] = True
        for _ in range(12):
            changed = False
            for e in range(self.E):
                s_, d_ = self.src[e], self.dst[e]
                new = reached[:, s_] & up[:, e] & comp[:, d_] & ~reached[:, d_]
                if new.any():
                    reached[:, d_] |= new
                    if track:
                        parent[new, d_] = e
                    changed = True
            if not changed:
                break
        return reached, parent

    def masks(self, reached, S=None):
        m = np.zeros(reached.shape[0], int)
        for j, c in enumerate(self.ctrl_idx):
            m |= reached[:, c].astype(int) << j
        return m

    def losses(self, reached, start=None):
        S = reached.shape[0]
        m = self.masks(reached)
        b = self.U_start[:S] if start is None else np.full(S, int(start))
        key = m * N_BUCKETS + b
        uk, inv = np.unique(key, return_inverse=True)
        vals = np.zeros(len(uk))
        for j, k in enumerate(uk):
            mask, bk = divmod(int(k), N_BUCKETS)
            if mask == 0:
                continue
            acts = [self.action_ids[i] for i in range(len(self.action_ids)) if mask >> i & 1]
            vals[j] = self.phys.attack_loss(acts, 3 * bk)["L"]
        return vals[inv], m

    def evaluate(self, defence=None, hacked=(), protected=(), init=None, track=False, n=None, start=None):
        reached, parent = self.reach(defence, hacked, protected, init, track, n)
        L, m = self.losses(reached, start)
        return dict(L=L, reached=reached, mask=m, parent=parent)

    # ---------------------------------------------------------------- summaries
    @staticmethod
    def sar(L, q=0.95):
        return float(np.quantile(L, q))

    def summary(self, defence=None):
        ev = self.evaluate(defence)
        L = ev["L"]
        return dict(sar95=self.sar(L), sar99=self.sar(L, 0.99), mean=float(L.mean()), p_any=float((L > 0).mean()),
                    worst=float(L.max()), samples=len(L))

    def raw_rrw(self, defence=None, nodes=None):
        base = self.evaluate(defence)
        e0 = float(base["L"].mean())
        out = {}
        nodes = nodes or [i for i in self.ids if i != "INTERNET"]
        for n in nodes:
            hacked = self.evaluate(defence, hacked=[n])["L"].mean()
            prot = self.evaluate(defence, protected=[n])["L"].mean()
            out[n] = dict(raw=float(hacked - e0), rrw=float(e0 - prot))
        return e0, out

    def top_paths(self, defence=None, k=5):
        """Most damaging attack routes: aggregate sampled parent chains weighted by service loss."""
        ev = self.evaluate(defence, track=True)
        L, reached, parent = ev["L"], ev["reached"], ev["parent"]
        agg = {}
        for s in np.where(L > 0)[0]:
            # path to each compromised controller, take the one for the first compromised action
            for c in self.ctrl_idx:
                if reached[s, c]:
                    path, v = [], c
                    while v != self.inet and v >= 0:
                        e = parent[s, v]
                        if e < 0:
                            break
                        path.append(int(e))
                        v = self.src[e]
                    path = tuple(reversed(path))
                    agg[path] = agg.get(path, 0.0) + float(L[s]) / self.S
                    break
        top = sorted(agg.items(), key=lambda kv: -kv[1])[:k]
        out = []
        for path, w in top:
            nodes = [self.edges[path[0]]["source"]] + [self.edges[e]["target"] for e in path]
            out.append(dict(nodes=nodes, edges=[self.edges[e]["id"] for e in path], weight=round(w, 1),
                            techniques=[self.edges[e]["technique"] for e in path]))
        return out

    # ---------------------------------------------------------------- baselines (what everyone else does)
    def baselines(self):
        """Rankings used by existing tools; we compare against them."""
        out = {}
        importance = {"field": 10, "control": 8, "dmz": 6, "it": 4, "iot": 3, "internet": 0, "physical": 10}
        cv = {}
        for nid, a in self.ward["assets"].items():
            c = self.snap["cves"].get(a["cve"] or "", {})
            cv[nid] = dict(cvss=c.get("cvss") or 0.0, epss=c.get("epss") or 0.0)
        out["cvss_x_importance"] = {n: cv[n]["cvss"] * importance[self.ward["assets"][n]["layer"]] for n in cv}
        out["cvss"] = {n: cv[n]["cvss"] for n in cv}
        out["epss_x_importance"] = {n: cv[n]["epss"] * importance[self.ward["assets"][n]["layer"]] for n in cv}
        # choke-point count: number of known edges leading (transitively) to field controllers through the node
        import networkx as nx
        G = nx.DiGraph()
        for e in self.edges:
            if e["known"]:
                G.add_edge(e["source"], e["target"])
        cb = nx.betweenness_centrality(G)
        out["betweenness"] = {n: cb.get(n, 0.0) for n in cv}
        return out
