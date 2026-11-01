"""Stateful side of the What-if Lab: trains the risk model on the Monte-Carlo threat model, ranks assets, explains them,
runs the five defensive scenarios and compares mitigations. The simulation session never modifies the baseline."""
from __future__ import annotations

import copy
import hashlib
import json
import pickle
import threading
import time

import numpy as np

from .city import DATA
from .lab import (COST, FEATURES, FNAMES, GROUPS, BEST, MODEL_VERSION, RULES, Controls, LabDB, RiskModel, adjacency, asset_features, dependents, eff_weak,
                  graph_features, likelihood, model_from_ward, reachable, service_loss, simulate_compromise, vec, vulnerable_service)
from .threat import Defence, ThreatModel, VP_EFFICACY

NB = 8


def to_defence(c: Controls) -> Defence:
    """Translate lab controls into the Monte-Carlo threat model's defence (used only to LABEL training data)."""
    d = Defence()
    for a in c.vpatch:
        d.cve_mult[a] = 1 - VP_EFFICACY
    for a in c.patched:
        d.cve_mult[a] = 0.0
    for a in c.mfa | c.harden:
        d.weak_mult[a] = RULES["mfa_factor"]
    d.blocked_edges |= set(c.blocked_edges)
    d.quarantined |= set(c.isolated)
    return d


class LabService:
    def __init__(self, rt, db_path=None):
        self.rt = rt
        self.ward = copy.deepcopy(rt.ward)                    # private copy: live what-if jobs edit the shared ward temporarily and must not leak into the lab baseline
        self.T = ThreatModel(self.ward, rt.phys, n_samples=3000, seed=7)
        self.model = model_from_ward(self.ward, self.T.snap)
        self.db = LabDB(db_path or (DATA / "decoy_lab.db"))
        self.db.seed(self.model, rt.T.snap["cves"])
        self.risk = RiskModel()
        self.session = Controls()
        self.lock = threading.RLock()
        self._impact = {}
        self._cache = {}
        self.ref_impact = self.ref_risk = None
        self.state = dict(status="untrained", error=None)
        self.extra_hyp = []
        rt.event_sink = lambda ev: self._sink(ev)

    def _sink(self, ev):
        try:
            self.db.add_event(ev["minute"], ev["kind"], ev["sev"], ev["text"])
        except Exception:
            pass

    # ------------------------------------------------------------------ physics-backed impact
    def impact_fn(self, acts):
        k = tuple(sorted(acts))
        if k not in self._impact:
            P = self.rt.phys
            self._impact[k] = float(np.mean([P.attack_loss(list(k), 3 * b)["L"] for b in range(NB)]))
        return self._impact[k]

    # ------------------------------------------------------------------ training
    def build_training_set(self, n_variants=260, seed=11, n_worlds=1500):
        """Rows = (asset, control configuration). Label = share of 'attack worlds' in which the asset falls (Monte-Carlo threat model)."""
        rng = np.random.default_rng(seed)
        ids = [i for i in self.model["assets"] if i != "INTERNET"]
        T, X, y, g = self.T, [], [], []
        for v in range(n_variants):
            c, p = Controls(), (0.0 if v == 0 else float(rng.random()) * 0.4)
            for a in ids:
                r, A = rng.random(4), self.model["assets"][a]
                if r[0] < p and A["vulns"]:
                    c.vpatch.add(a)
                if r[1] < p * 0.5 and A["vulns"]:
                    c.patched.add(a)
                if r[2] < p and A["p_weak"] > 0:
                    (c.mfa if r[3] < 0.5 else c.harden).add(a)
            for e in self.model["edges"]:
                if rng.random() < p * 0.5:
                    c.blocked_edges.add(e["id"])
            reached, _ = T.reach(to_defence(c), n=n_worlds)
            prop, gf = reached.mean(0), graph_features(self.model, c)
            for a in ids:
                X.append(vec(asset_features(self.model, a, c, _g=gf)))
                y.append(float(prop[T.idx[a]]))
                g.append(v)
        return np.array(X), np.array(y), np.array(g)

    def _cache_key(self, n_variants, seed):
        h = hashlib.md5(json.dumps(self.model["assets"], sort_keys=True, default=str).encode("utf-8")).hexdigest()
        return f"{MODEL_VERSION}|{n_variants}|{seed}|{h}"

    def train(self, n_variants=260, seed=11):
        """Train the risk model, or load it from data/lab_model_cache.pkl when nothing it depends on has changed (so a restart is instant)."""
        with self.lock:
            self.state = dict(status="training", error=None)
        try:
            key = self._cache_key(n_variants, seed); path = DATA / "lab_model_cache.pkl"
            blob = None
            try:
                if path.exists():
                    with open(path, "rb") as fh:
                        b = pickle.load(fh)
                    if b.get("key") == key:
                        blob = b
            except Exception:
                blob = None
            if blob is not None:
                self.risk = blob["risk"]; meta = blob["meta"]
                with self.lock:
                    self._cache.clear(); self.ref_impact, self.ref_risk = blob["ref_impact"], blob["ref_risk"]
                    self.state = dict(status="ready", error=None, meta=meta, rules=RULES, features=[dict(name=n, source=s, direction=d) for n, s, d in FEATURES])
                return self.state
            X, y, g = self.build_training_set(n_variants, seed)
            meta = self.risk.fit(X, y, g, seed=seed)
            with self.lock:
                self._cache.clear()
                base = Controls()
                imp = {a: self.impact_raw(a, base) for a in self.model["assets"] if a != "INTERNET"}
                self.ref_impact = max(max(imp.values()), 1e-9)
                prior = self.priors(base)
                self.ref_risk = max(max(prior[a] * imp[a] / self.ref_impact for a in imp), 1e-9)
                self.state = dict(status="ready", error=None, meta=meta, rules=RULES, features=[dict(name=n, source=s, direction=d) for n, s, d in FEATURES])
                (DATA / "lab_model_meta.json").write_text(json.dumps(self.state["meta"]), encoding="utf-8")
            try:
                with open(path, "wb") as fh:
                    pickle.dump(dict(key=key, risk=self.risk, meta=meta, ref_impact=self.ref_impact, ref_risk=self.ref_risk), fh)
            except Exception:
                pass
        except Exception as e:   # surfaced by GET /model; never crashes the server
            with self.lock:
                self.state = dict(status="error", error=f"{type(e).__name__}: {e}")
            raise
        return self.state

    def train_async(self):
        threading.Thread(target=lambda: self._safe(self.train), daemon=True).start()

    def _safe(self, fn):
        try:
            fn()
        except Exception:
            pass

    def ready(self):
        return self.state.get("status") == "ready"

    def require_ready(self):
        if not self.ready():
            raise RuntimeError("risk model is not trained yet")

    # ------------------------------------------------------------------ risk
    def anomaly(self):
        """Observed anomaly per asset from the live Watchdog (0 when calm). Confirmed evidence only."""
        out = {}
        for inc in self.rt.incidents:
            if inc["status"] in ("open", "contained"):
                for n in inc["evidence_nodes"]:
                    out[n] = 1.0
        return out

    def priors(self, c, extra=()):
        gf = graph_features(self.model, c, extra)
        ids = [a for a in self.model["assets"] if a != "INTERNET"]
        X = np.array([vec(asset_features(self.model, a, c, extra, _g=gf)) for a in ids])
        return dict(zip(ids, self.risk.predict(X)))

    def impact_raw(self, aid, c, extra=()):
        """Operational impact of compromising `aid`: expected service loss (household-hour equivalents) over the fixed attack worlds, given that the
        attacker already holds it. Uses links AND service dependencies via the physics oracle; an isolated asset reaches nothing, so it scores ~0.
        Fixed random numbers make it reproducible."""
        k = (aid, json.dumps(c.to_json(), sort_keys=True))
        if k not in self._cache:
            loss = float(self.T.evaluate(to_defence(c), hacked=[aid], n=1500)["L"].mean())
            self._cache[k] = loss * (1 - RULES["backup_cut"] if c.backup_ir else 1.0)
        return self._cache[k]

    def ranking(self, c=None, anomaly=None, extra=()):
        self.require_ready()
        c = c or Controls()
        an = self.anomaly() if anomaly is None else anomaly
        pr = self.priors(c, extra)
        rows = []
        for a, p in pr.items():
            A = self.model["assets"][a]
            lk = likelihood(p, an.get(a, 0.0), a in c.monitoring)
            im = self.impact_raw(a, c, extra)
            nrm = im / self.ref_impact
            rows.append(dict(id=a, name=A["name"], category=A["category"], sector=A["sector"], cvss=round(A["cvss"], 1), exploit_epss=round(A["epss"], 3), kev=A["kev"],
                             propensity_prior=round(float(p), 4), likelihood=round(lk, 4), impact_raw=round(im, 1), impact=round(nrm, 4), risk=round(100 * lk * nrm / self.ref_risk, 2),
                             anomaly=an.get(a, 0.0)))
        rows.sort(key=lambda r: (-r["risk"], r["id"]))
        by_cvss = {r["id"]: i + 1 for i, r in enumerate(sorted(rows, key=lambda r: (-r["cvss"], r["id"])))}
        for i, r in enumerate(rows, 1):
            r["rank"], r["rank_by_cvss"] = i, by_cvss[r["id"]]
        return rows

    def explain(self, aid, c=None):
        self.require_ready()
        c = c or Controls()
        A = self.model["assets"][aid]
        gf = graph_features(self.model, c)
        f = asset_features(self.model, aid, c, _g=gf)
        base = float(self.risk.predict(vec(f))[0])
        parts = []
        for grp, names in GROUPS.items():
            g2 = dict(f)
            for n in names:
                g2[n] = BEST[n]
            parts.append(dict(group=grp, contribution=round(base - float(self.risk.predict(vec(g2))[0]), 4), inputs={n: round(f[n], 3) for n in names}))
        parts.sort(key=lambda x: -x["contribution"])
        sim = simulate_compromise(self.model, aid, c)
        loss = service_loss(self.model, sim["compromised"], self.impact_fn, c.backup_ir)
        row = next(r for r in self.ranking(c) if r["id"] == aid)
        why = f"Ranked #{row['rank']} of {len(self.model['assets']) - 1} by overall risk (#{row['rank_by_cvss']} by CVSS). "
        why += f"Likelihood {row['likelihood']:.2f} comes mostly from {parts[0]['group']}. "
        why += (f"If it is compromised the attacker can also reach {len(sim['compromised']) - 1} other asset(s) and stop {len(loss['services'])} service(s)." if len(sim["compromised"]) > 1 or loss["services"]
                else "If it is compromised nothing else can be reached from it, so its operational impact is low whatever its CVSS score.")
        return dict(asset=aid, name=A["name"], definitions=self.definitions(), features={n: round(f[n], 4) for n in FNAMES}, prior=round(base, 4), likelihood=row["likelihood"], impact=row["impact"],
                    risk=row["risk"], drivers=parts, reachable_from_asset=sim["compromised"][1:], services_lost=loss["services"], dependents=dependents(self.model, aid), explanation=why)

    def compare_assets(self, a, b, c=None):
        """Why is `a` ahead of (or behind) `b`? Side-by-side decomposition."""
        ea, eb = self.explain(a, c), self.explain(b, c)
        return dict(a=ea, b=eb, text=f"{ea['name']}: risk {ea['risk']} (likelihood {ea['likelihood']:.2f} x impact {ea['impact']:.2f}). {eb['name']}: risk {eb['risk']} (likelihood {eb['likelihood']:.2f} x impact {eb['impact']:.2f}).")

    @staticmethod
    def definitions():
        return dict(horizon="30 days (synthetic)", target="Share of simulated attack worlds in which the asset is compromised (Monte-Carlo threat model, 3,000 worlds)",
                    exploit_prediction="EPSS / CISA KEV for the asset's CVE: an input feature, not the model output",
                    compromise_likelihood="ML propensity (monotone gradient boosting) updated by observed anomaly (odds x (1 + 4a)) and monitoring (x 0.75). A synthetic risk propensity, NOT a real-world incident probability",
                    operational_impact="Deterministic: service loss (household-hour equivalents, water + power physics oracle) of everything an attacker holding the asset could reach, via links and service dependencies",
                    overall_risk="100 x likelihood x impact / (highest baseline likelihood x impact). Baseline top asset = 100",
                    ml_inputs=[n for n, _, _ in FEATURES], rule_inputs=["exposure", "hops", "in_degree", "exploit_signal", "weak_access", "unpatched", "segmented"], model_version=MODEL_VERSION)

    def ward_index(self, c=None, assumed=(), extra=(), blind=()):
        """Sum of likelihood x impact over all assets, scaled so the untouched baseline = 100. `assumed` assets are taken as compromised (likelihood 1)."""
        self.require_ready()
        c = c or Controls()
        an = self.anomaly()
        pr = self.priors(c, extra)
        tot = 0.0
        for a, p in pr.items():
            lk = 1.0 if a in assumed else likelihood(p, an.get(a, 0.0), a in c.monitoring and a not in blind)
            tot += lk * self.impact_raw(a, c, extra) / self.ref_impact
        return 100.0 * tot / self._base_total()

    def _base_total(self):
        if "bt" not in self._cache:
            pr = self.priors(Controls())
            an = self.anomaly()
            self._cache["bt"] = max(1e-9, sum(likelihood(p, 0.0, False) * self.impact_raw(a, Controls()) / self.ref_impact for a, p in pr.items()))
        return self._cache["bt"]

    # ------------------------------------------------------------------ mitigations
    def mitigation_catalogue(self):
        return [dict(id="mfa", label="Enable MFA on remote and weakly protected access", cost=COST["mfa"], effect="credentials alone stop working"),
                dict(id="restrict_remote_access", label="Restrict remote access (close all vendor links)", cost=COST["restrict_remote"], effect="no vendor path into OT"),
                dict(id="vendor_scope", label="Restrict vendor permissions to the jump host only", cost=COST["vendor_scope"], effect="vendor can no longer reach BMS / historian / engineering PC"),
                dict(id="segmentation", label="Improve segmentation (close the links an attack uses)", cost=COST["segment"], effect="removes the specific links on the path"),
                dict(id="vpatch", label="Patch / virtually patch vulnerable applications", cost=COST["vpatch"], effect="exploit signal x 0.15"),
                dict(id="disable_exposed", label="Disable unnecessary exposed services (close internet links)", cost=COST["disable_exposed"], effect="asset no longer reachable from the internet"),
                dict(id="monitoring", label="Improve anomaly monitoring", cost=COST["monitoring"], effect="likelihood x 0.75 (rule)"),
                dict(id="backup_ir", label="Test backups and incident-response readiness", cost=COST["backup_ir"], effect="impact x 0.6 (rule)")]

    def candidates(self, sim, c):
        """Concrete, simulation-driven control options for an observed/hypothetical compromise."""
        m, out = self.model, []
        comp = [a for a in sim["compromised"]]
        s0 = sim["start"]
        if s0 != "INTERNET" and m["assets"][s0]["p_weak"] > 0:
            out.append(("mfa", f"Enable MFA on {m['assets'][s0]['name']}", COST["mfa"], lambda x: x.mfa.add(s0)))
        for a in comp:
            A = m["assets"][a]
            if A["vulns"] and vulnerable_service(A, c):
                out.append(("vpatch", f"Virtually patch {A['name']} ({A['vulns'][0]})", COST["vpatch"], lambda x, a=a: x.vpatch.add(a)))
            if eff_weak(A, c) >= RULES["weak_min"]:
                out.append(("mfa", f"Enable MFA / change default credentials on {A['name']}", COST["mfa"], lambda x, a=a: x.mfa.add(a)))
        seen = set()
        for tgt, path in sim["paths"].items():
            for eid in path:
                if eid in seen:
                    continue
                seen.add(eid)
                e = next((q for q in m["edges"] + list(self.extra_hyp) if q["id"] == eid), None)
                if e and e["source"] != "INTERNET":
                    out.append(("segmentation", f"Close the {e['protocol'].upper()} link {m['assets'][e['source']]['name']} -> {m['assets'][e['target']]['name']}", COST["segment"], lambda x, eid=eid: x.blocked_edges.add(eid)))
                if e and e["source"] == "INTERNET":
                    out.append(("disable_exposed", f"Disable the internet-facing service on {m['assets'][e['target']]['name']}", COST["disable_exposed"], lambda x, eid=eid: x.blocked_edges.add(eid)))
        if any(e["kind"] == "vendor" and e["id"] in seen for e in m["edges"]):
            out.append(("restrict_remote_access", "Restrict remote access: close every vendor link", COST["restrict_remote"], lambda x: x.blocked_edges.update(e["id"] for e in m["edges"] if e["kind"] == "vendor")))
            out.append(("vendor_scope", "Restrict vendor permissions to the jump host only", COST["vendor_scope"], lambda x: setattr(x, "vendor_scoped", True)))
        out += self.cut_candidates(sim, c)
        out.append(("monitoring", "Add anomaly monitoring on every asset the attack touches", COST["monitoring"], lambda x: x.monitoring.update(comp)))
        out.append(("backup_ir", "Test backups and incident-response readiness", COST["backup_ir"], lambda x: setattr(x, "backup_ir", True)))
        return out

    def cut_candidates(self, sim, c, targets=None):
        """When paths are redundant no single link helps. A minimum cut finds the fewest links (or assets) that separate the attacker from every controller."""
        import networkx as nx
        from .lab import transition
        m = self.model
        ctrls = (set(targets) if targets else {s["controller"] for s in m["services"].values()}) & set(sim["compromised"])
        ctrls.discard(sim["start"])
        if not ctrls:
            return []
        G, comp = nx.DiGraph(), set(sim["compromised"])
        creds = {sim["start"]}
        for u, es in adjacency(m, c, self.extra_hyp).items():
            if u not in comp:
                continue
            for e in es:
                if e["target"] in comp and transition(m, e, c, creds)[0]:
                    G.add_edge(u, e["target"], capacity=1, eid=e["id"])
        for t in ctrls:
            G.add_edge(t, "__sink__", capacity=10 ** 6)
        if sim["start"] not in G or "__sink__" not in G or not nx.has_path(G, sim["start"], "__sink__"):
            return []
        out = []
        val, (S, Tt) = nx.minimum_cut(G, sim["start"], "__sink__")
        edges = sorted({G[u][v]["eid"] for u in S for v in G[u] if v in Tt and "eid" in G[u][v]})
        if edges and len(edges) <= 8:
            out.append(("segmentation", f"Segment: close the {len(edges)} link(s) that separate this attacker from every controller", COST["segment"] + 0.5 * (len(edges) - 1),
                        lambda x, edges=edges: x.blocked_edges.update(edges)))
        try:
            H = nx.DiGraph(G)
            H.remove_node("__sink__")
            for t in ctrls:
                H.add_edge(t, "__t__")
            cut = sorted(nx.minimum_node_cut(H, sim["start"], "__t__"))
        except Exception:
            cut = []
        cut = [n for n in cut if n not in ctrls or True]
        if cut and len(cut) <= 4:
            names = ", ".join(m["assets"][n]["name"] for n in cut)
            def fix(x, cut=cut):
                for n in cut:
                    A = m["assets"][n]
                    if A["vulns"]:
                        x.vpatch.add(n)
                    if A["p_weak"] > 0:
                        x.mfa.add(n)
            out.append(("vpatch", f"Harden the choke point(s): {names}", COST["vpatch"] * len(cut) + COST["mfa"] * len(cut) * 0.5, fix))
        return out

    def protect_target(self, target, c=None):
        """Inbound view: how could an attacker from the internet reach `target`, and which cuts stop it? (e.g. the hospital building system)"""
        c = c or Controls()
        sim = simulate_compromise(self.model, "INTERNET", c)
        if target not in sim["compromised"]:
            return dict(target=target, reachable=False, path=None, options=[])
        opts = []
        for kind, label, cost, fn in self.cut_candidates(sim, c, targets={target}):
            c2 = c.copy()
            fn(c2)
            s2 = simulate_compromise(self.model, "INTERNET", c2)
            opts.append(dict(control=kind, label=label, cost=cost, target_reachable_after=target in s2["compromised"], ward_risk_after=round(self.ward_index(c2), 2)))
        vend = [e["id"] for e in self.model["edges"] if e["kind"] == "vendor" and e.get("exists", True)]
        if any(e in sim["paths"][target] for e in vend):
            c2 = c.copy(); c2.blocked_edges.update(vend)
            s2 = simulate_compromise(self.model, "INTERNET", c2)
            opts.append(dict(control="restrict_remote_access", label="Restrict remote access: close every vendor link", cost=COST["restrict_remote"], target_reachable_after=target in s2["compromised"], ward_risk_after=round(self.ward_index(c2), 2)))
        return dict(target=target, reachable=True, path=sim["paths"][target], options=sorted(opts, key=lambda o: (o["target_reachable_after"], o["cost"])))

    def recommend(self, start, c=None, creds=(), extra=(), top=6, add=()):
        """Rank options by loss avoided per effort unit, re-running the deterministic simulation for each."""
        c = c or Controls()
        sim0 = simulate_compromise(self.model, start, c, creds, extra)
        base = service_loss(self.model, sim0["compromised"], self.impact_fn, c.backup_ir)["loss"]
        rows = []
        for kind, label, cost, fn in list(self.candidates(sim0, c)) + list(add):
            c2 = c.copy()
            fn(c2)
            s2 = simulate_compromise(self.model, start, c2, creds, extra)
            loss = service_loss(self.model, s2["compromised"], self.impact_fn, c2.backup_ir)["loss"]
            blank = Controls()
            fn(blank)
            rows.append(dict(control=kind, label=label, cost=cost, apply=blank.to_json(), reached_before=len(sim0["compromised"]) - 1, reached_after=len(s2["compromised"]) - 1,
                             loss_before=round(base, 1), loss_after=round(loss, 1), reduction=round(base - loss, 1), per_cost=round((base - loss) / cost, 2),
                             eliminates_all_paths=len(s2["compromised"]) == 1, still_reachable=s2["compromised"][1:]))
        rows.sort(key=lambda r: (-r["per_cost"], -r["reduction"], r["label"]))
        uniq, seen = [], set()
        for r in rows:
            if r["label"] not in seen:
                seen.add(r["label"]); uniq.append(r)
        return uniq[:top]

    def apply_recommendation_package(self, start, c, creds=(), extra=(), n=3):
        """Greedy package: add the best option, re-rank, repeat. Shows whether the combination closes every path."""
        c2, chosen = c.copy(), []
        for _ in range(n):
            rec = [r for r in self.recommend(start, c2, creds, extra, top=12) if r["reduction"] > 0]
            if not rec:
                break
            best = rec[0]
            for kind, label, cost, fn in self.candidates(simulate_compromise(self.model, start, c2, creds, extra), c2):
                if label == best["label"]:
                    fn(c2)
                    break
            chosen.append(best["label"])
        return c2, chosen

    # ------------------------------------------------------------------ what-if: simulate compromise
    def simulate(self, start, c=None, creds=(), extra=()):
        c = c or Controls()
        sim = simulate_compromise(self.model, start, c, creds, extra)
        loss = service_loss(self.model, sim["compromised"], self.impact_fn, c.backup_ir)
        out = dict(sim, services_lost=loss["services"], actions=loss["actions"], loss=round(loss["loss"], 1), controls=c.to_json(), model_version=MODEL_VERSION)
        out["classification"] = self.classify(sim)
        if self.ready():
            out["risk_before"] = round(self.ward_index(c, extra=extra), 2)
            out["risk_during"] = round(self.ward_index(c, assumed=sim["compromised"], extra=extra), 2)
            out["recommendations"] = self.recommend(start, c, creds, extra)
            c2, pack = self.apply_recommendation_package(start, c, creds, extra)
            out["package"] = dict(controls=pack, risk_after=round(self.ward_index(c2, extra=extra), 2), reached_after=simulate_compromise(self.model, start, c2, creds, extra)["compromised"][1:])
        return out

    def classify(self, sim):
        """Keep three kinds of statements apart: confirmed (observed live), plausible (simulated), predicted (ML)."""
        conf = sorted({n for inc in self.rt.incidents if inc["status"] in ("open", "contained") for n in inc["evidence_nodes"]})
        pred = []
        if self.ready():
            pred = [dict(id=r["id"], likelihood=r["likelihood"]) for r in self.ranking()[:5]]
        return dict(confirmed_incident_assets=conf, plausible_path_assets=sim["compromised"][1:], predicted_top_risk=pred,
                    note="Plausible = every step meets explicit preconditions in the simulation. Predicted = ML propensity. Confirmed = observed by the Watchdog in the live twin.")

    # ------------------------------------------------------------------ telemetry & optimisation
    def telemetry(self):
        L = self.rt.live
        rep = {k: round(float(v), 3) for k, v in L.last.get("reported", {}).items()}
        return dict(minute=L.minute, clock=self.rt.clock(), reported=rep, watchdog_p=round(self.rt.last_p, 3), anomaly_by_asset=self.anomaly(), services=L.services())

    def optimize(self, budget):
        d = self.rt.defence.copy()
        plan = self.rt.planner.plan(d, float(budget), now_hour=self.rt.hour())
        return dict(budget=budget, spent=plan["spent"], risk_before=round(plan["e_start"]), risk_after=round(plan["e_end"]),
                    steps=[dict(fix=s["fix"], gain=round(s["gain"]), downtime_loss=round(s["downtime_loss"])) for s in plan["steps"]], refused=[dict(label=r["fix"]["label"] if isinstance(r["fix"], dict) else r["fix"].label, reason=r["reason"]) for r in plan["refused"][:5]])

    def reset(self):
        with self.lock:
            self.session = Controls()
            self.extra_hyp = []
            self.db.clear_runs()
            self.db.seed(self.model, self.T.snap["cves"])
        return dict(ok=True, controls=self.session.to_json())
