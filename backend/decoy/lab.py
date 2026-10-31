"""What-if Lab: deterministic compromise simulation, a transparent risk engine, five defensive scenarios, mitigation comparison.

Everything here is SYNTHETIC and runs on an in-memory copy of the model. No payloads, no exploit code, no commands for equipment.

Vocabulary used everywhere (never mixed):
    exploit prediction   = EPSS / KEV  (real feeds, per CVE)               -> input feature
    compromise propensity = ML output  (synthetic risk propensity, 30-day horizon; NOT a real-world incident probability)
    operational impact   = deterministic: service loss of everything an attacker holding the asset could reach (physics oracle)
    overall risk         = propensity x impact, scaled so the highest baseline asset = 100
    plausible path       = a path whose every step satisfies explicit preconditions (simulation)
    predicted risk       = the ML propensity
    confirmed incident   = something the Watchdog really observed in the live twin (never produced by the lab)
"""
from __future__ import annotations

import copy
import json
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass, field

import numpy as np

MODEL_VERSION = "lab-1.1"

# ------------------------------------------------------------------ rules (deterministic, stated assumptions)
RULES = dict(
    epss_min=0.05,        # a vulnerable service counts as exploitable if it is in CISA KEV or EPSS >= this
    weak_min=0.20,        # access control counts as weak if the chance of default/shared/stolen credentials >= this
    mfa_factor=0.10,      # MFA / credential rotation keeps 10% of the weak-access chance
    vpatch_factor=0.15,   # a virtual patch keeps 15% of the exploit signal
    patched_at=0.5,       # p_patched >= this is treated as patched
    monitoring_cut=0.25,  # anomaly monitoring lowers likelihood by 25% (rule, not learned)
    backup_cut=0.40,      # tested backups + incident-response readiness lower impact by 40% (rule, not learned)
    anomaly_gain=4.0,     # observed anomaly a in [0,1] multiplies the odds by (1 + gain * a)
)

COST = dict(mfa=3, vpatch=1, patched=5, harden=2, segment=4, restrict_remote=2, vendor_scope=2, disable_exposed=2, monitoring=2, backup_ir=3)
SECTOR = {"Z-WATER": "water", "Z-POWER": "power", "Z-HOSPITAL": "healthcare", "Z-IOT": "smart city", "Z-OFFICE": "municipal IT", "Z-DMZ": "OT access", "Z-CONTROL": "OT control", "Z-WAN": "external"}
FUNCTION = {"internet": "Untrusted outside world", "iot": "Smart-city edge device", "it": "Office IT system", "dmz": "Buffer zone between IT and OT", "control": "Supervisory control", "field": "Controller that moves physical equipment"}

# service dependencies (operational, NOT network): provider -> consumer, kind. SYNTHETIC assumptions.
DEPENDENCIES = [
    ("SCADA_SRV", "HMI_01", "operates"), ("SCADA_SRV", "PLC_PS1", "operates"), ("SCADA_SRV", "PLC_PS2", "operates"), ("SCADA_SRV", "PLC_V1", "operates"),
    ("SCADA_SRV", "PLC_V2", "operates"), ("SCADA_SRV", "RTU_F1", "operates"), ("SCADA_SRV", "RTU_F2", "operates"), ("SCADA_SRV", "RTU_F3", "operates"),
    ("HMI_01", "SCADA_SRV", "operates"),                      # operators need the HMI to run SCADA: a deliberate dependency cycle
    ("HIST_01", "SCADA_SRV", "monitoring"), ("HIST_01", "HMI_01", "monitoring"), ("GW_METER_01", "HIST_01", "monitoring"),
    ("PLC_PS1", "PLC_V1", "operates"), ("PLC_PS2", "BMS_KEM", "operates"),
]
MONITORED_BY_HIST = ["SCADA_SRV", "HMI_01", "PLC_PS1", "PLC_PS2", "PLC_V1", "PLC_V2", "RTU_F1", "RTU_F2", "RTU_F3", "GW_METER_01"]


# ------------------------------------------------------------------ model
def model_from_ward(ward: dict, snap: dict) -> dict:
    """Plain-dict copy of the infrastructure that the pure functions below work on (so tests can build tiny fixtures)."""
    assets, ctrl_of = {}, {a["controller"]: aid for aid, a in ward["actions"].items()}
    for nid, a in ward["assets"].items():
        c = snap["cves"].get(a["cve"] or "", {})
        exp = "internet" if a["exposure"] == "internet" else ("isolated" if a["exposure"] == "isolated" else "internal")
        assets[nid] = dict(id=nid, name=a["name"], category=a["layer"], sector=SECTOR.get(a["zone"], "other"), description=FUNCTION.get(a["layer"], ""), function=FUNCTION.get(a["layer"], ""),
                           purdue=a["purdue"], firmware=a["firmware"], vulns=[a["cve"]] if a["cve"] else [], cvss=float(c.get("cvss") or 0.0), epss=float(c.get("epss") or 0.0),
                           kev=bool(c.get("in_kev")), exposure=exp, p_weak=float(a["p_weak"]), p_patched=float(a["p_patched"]), legacy=bool(a["legacy"]), known_version=bool(a["known_version"]),
                           cve_belief=float(a["cve_belief"]), entry_weight=float(a["entry_weight"]), anomaly=0.0, action=ctrl_of.get(nid), provenance=a["provenance"], tags=list(a["tags"]))
    edges = [dict(id=e["id"], source=e["source"], target=e["target"], kind="vendor" if e["type"] == "vendor" else "network", protocol=e["protocol"], p_access=float(e["p_access"]),
                  exists=bool(e["truth"]), documented=bool(e["known"]), note=e["misconfig"]) for e in ward["edges"]]
    services = {aid: dict(id=aid, name=a["label"], controller=a["controller"], kind=a["kind"], target=a["target"], weight=1.0) for aid, a in ward["actions"].items()}
    return dict(version=MODEL_VERSION, assets=assets, edges=edges, deps=[dict(provider=p, consumer=c, kind=k) for p, c, k in DEPENDENCIES if p in assets and c in assets], services=services,
                monitored=[a for a in MONITORED_BY_HIST if a in assets])


@dataclass
class Controls:
    mfa: set = field(default_factory=set)             # assets with MFA / credential rotation
    vpatch: set = field(default_factory=set)          # assets with a virtual patch
    patched: set = field(default_factory=set)         # assets fully patched
    harden: set = field(default_factory=set)          # default settings changed
    blocked_edges: set = field(default_factory=set)   # segmentation: links closed
    isolated: set = field(default_factory=set)        # assets cut off from the network
    monitoring: set = field(default_factory=set)      # assets under anomaly monitoring
    vendor_scoped: bool = False                       # vendor access limited to the jump host
    backup_ir: bool = False                           # tested backups + incident-response readiness

    def copy(self):
        return copy.deepcopy(self)

    def to_json(self):
        return {k: (sorted(v) if isinstance(v, set) else v) for k, v in self.__dict__.items()}

    @staticmethod
    def from_json(d):
        c = Controls()
        for k, v in (d or {}).items():
            if hasattr(c, k):
                setattr(c, k, set(v) if isinstance(getattr(c, k), set) else bool(v))
        return c


# ------------------------------------------------------------------ pure graph + precondition engine
def usable_edges(model, controls=None, extra=()):
    """Links that actually exist (not just documented) and are not closed. Connectivity only; says nothing about compromise."""
    c = controls or Controls()
    out = []
    for e in list(model["edges"]) + list(extra):
        if not e.get("exists", True) or e["id"] in c.blocked_edges or e["source"] in c.isolated or e["target"] in c.isolated:
            continue
        if c.vendor_scoped and e["kind"] == "vendor" and e["target"] != "JUMP_RDS":
            continue
        out.append(e)
    return sorted(out, key=lambda e: e["id"])


def adjacency(model, controls=None, extra=()):
    adj = {}
    for e in usable_edges(model, controls, extra):
        if e["source"] in model["assets"] and e["target"] in model["assets"]:
            adj.setdefault(e["source"], []).append(e)
    return adj


def reachable(model, src, controls=None, extra=()):
    """Network reachability only (BFS, cycle-safe). Returns {asset: hops}."""
    if src not in model["assets"]:
        raise KeyError(src)
    adj, dist, q = adjacency(model, controls, extra), {src: 0}, deque([src])
    while q:
        u = q.popleft()
        for e in adj.get(u, []):
            if e["target"] not in dist:
                dist[e["target"]] = dist[u] + 1
                q.append(e["target"])
    return dist


def eff_weak(a, c):
    return a["p_weak"] * (RULES["mfa_factor"] if (a["id"] in c.mfa or a["id"] in c.harden) else 1.0)


def patched(a, c):
    return a["id"] in c.patched or a["p_patched"] >= RULES["patched_at"]


def vulnerable_service(a, c):
    """Is there a vulnerable, reachable service an attacker could use? Needs a CVE, no patch, no virtual patch, and a real exploitation signal."""
    if not a["vulns"] or patched(a, c) or a["id"] in c.vpatch:
        return False
    if not a["known_version"] and a["cve_belief"] < 0.5:
        return False
    return bool(a["kev"] or a["epss"] >= RULES["epss_min"])


def exploit_signal(a, c):
    """0..1 deterministic exploit signal (the same recipe the Monte-Carlo threat model uses)."""
    if not a["vulns"] or patched(a, c):
        return 0.0
    s = max(a["epss"], 0.6) if a["kev"] else a["epss"]
    s *= (a["cve_belief"] if not a["known_version"] else 1.0)
    return s * (RULES["vpatch_factor"] if a["id"] in c.vpatch else 1.0)


def transition(model, e, c, creds):
    """Can the attacker step along link e? Returns (ok, reasons). A link alone never implies compromise."""
    src, dst = model["assets"][e["source"]], model["assets"][e["target"]]
    why = []
    if e["kind"] == "vendor" and e["source"] in creds and src["id"] not in c.mfa:
        why.append(f"valid vendor credential on {src['id']} (no MFA)")
    if vulnerable_service(dst, c):
        why.append(f"vulnerable service {dst['vulns'][0]}" + (" (in CISA KEV)" if dst["kev"] else f" (EPSS {dst['epss']:.2f})"))
    if eff_weak(dst, c) >= RULES["weak_min"]:
        why.append(f"weak access control on {dst['id']} (chance {eff_weak(dst, c):.2f})")
    if why:
        return True, why
    miss = []
    if e["kind"] == "vendor" and e["source"] in creds and src["id"] in c.mfa:
        miss.append("vendor credential is useless: MFA is required")
    if dst["vulns"] and (patched(dst, c) or dst["id"] in c.vpatch):
        miss.append(f"{dst['vulns'][0]} is patched / blocked")
    if not dst["vulns"]:
        miss.append("no vulnerable service")
    elif not (dst["kev"] or dst["epss"] >= RULES["epss_min"]):
        miss.append("vulnerability has no exploitation signal")
    miss.append("access control is strong")
    return False, miss


def simulate_compromise(model, start, controls=None, creds=(), extra=(), max_depth=12):
    """Deterministic what-if: treat `start` as compromised and spread only where every precondition holds. Same inputs -> same output."""
    if start not in model["assets"]:
        raise KeyError(start)
    c = controls or Controls()
    adj = adjacency(model, c, extra)
    creds = set(creds)
    order, depth, via, why, failed = [start], {start: 0}, {}, {}, []
    q = deque([start])
    while q:
        u = q.popleft()
        if depth[u] >= max_depth:
            continue
        for e in adj.get(u, []):
            v = e["target"]
            ok, reasons = transition(model, e, c, creds)
            if v in depth:
                continue
            if ok:
                depth[v], via[v], why[v] = depth[u] + 1, e["id"], reasons
                order.append(v)
                q.append(v)
                if e["kind"] == "vendor" and any("credential" in r for r in reasons):
                    creds.add(v)
            else:
                failed.append(dict(edge=e["id"], source=u, target=v, reasons=reasons))
    failed = [f for f in failed if f["target"] not in depth]
    byid = {e["id"]: e for e in model["edges"]}
    byid.update({e["id"]: e for e in extra})
    paths = {}
    for v in order:
        p, x = [], v
        while x != start:
            p.append(via[x]); x = byid[via[x]]["source"]
        paths[v] = list(reversed(p))
    return dict(start=start, compromised=order, depth=depth, paths=paths, why=why, failed=failed, status="plausible")


def dependents(model, asset, kinds=None):
    """Everything that (transitively) depends on `asset` for service. Cycle-safe."""
    out, q = [], deque([asset])
    seen = {asset}
    while q:
        u = q.popleft()
        for d in model["deps"]:
            if d["provider"] == u and d["consumer"] not in seen and (kinds is None or d["kind"] in kinds):
                seen.add(d["consumer"]); out.append(d["consumer"]); q.append(d["consumer"])
    return out


def service_loss(model, compromised, impact_fn=None, backup_ir=False):
    """Operational impact: which services stop when these assets are in attacker hands, and how much that costs."""
    comp = set(compromised)
    for a in list(comp):   # a controller also falls if the supervisory system it depends on falls
        comp.update(dependents(model, a, kinds=("operates",)))
    acts = sorted(aid for aid, s in model["services"].items() if s["controller"] in comp)
    loss = float(impact_fn(tuple(acts))) if (impact_fn and acts) else float(sum(model["services"][a]["weight"] for a in acts))
    if backup_ir:
        loss *= 1 - RULES["backup_cut"]
    return dict(actions=acts, services=[model["services"][a]["name"] for a in acts], loss=loss)


# ------------------------------------------------------------------ risk engine
FEATURES = [  # name, source, monotone direction (+1 more risk, -1 less risk)
    ("cvss", "NVD (data)", 1), ("epss", "FIRST EPSS (data)", 1), ("kev", "CISA KEV (data)", 1), ("exploit_signal", "rule: EPSS/KEV x patch x virtual patch", 1),
    ("exposure", "rule: internet 1.0 / internal 0.35 / isolated 0", 1), ("entry_weight", "scenario data: how often attackers start here", 1),
    ("weak_access", "data x control: weak credentials after MFA / hardening", 1), ("unpatched", "data x control: 1 - patched", 1), ("legacy", "inventory (data)", 1),
    ("hops", "rule: shortest hops from the internet over links that exist", -1), ("path_prob", "rule: chance of the best route from the internet (product of step chances)", 1), ("in_degree", "rule: links into the asset", 1),
    ("mfa_on", "control", -1), ("vpatch_on", "control", -1), ("segmented", "control: share of inbound links closed", -1),
]
FNAMES = [f[0] for f in FEATURES]
GROUPS = {"vulnerability": ["cvss", "epss", "kev", "exploit_signal"], "exposure": ["exposure", "entry_weight"], "access control": ["weak_access", "mfa_on"],
          "patch state": ["unpatched", "legacy", "vpatch_on"], "connectivity": ["hops", "in_degree", "segmented", "path_prob"]}
BEST = dict(path_prob=0.0, cvss=0.0, epss=0.0, kev=0.0, exploit_signal=0.0, exposure=0.0, entry_weight=0.0, weak_access=0.0, unpatched=0.0, legacy=0.0, hops=9.0, in_degree=0.0, mfa_on=0.0, vpatch_on=0.0, segmented=0.0)
EXPO = dict(internet=1.0, internal=0.35, isolated=0.0)


def step_chance(a, c):
    """Chance that an attacker who can reach this asset takes it: exploit signal or weak access (the same two causes the simulation checks)."""
    return 1.0 - (1.0 - exploit_signal(a, c)) * (1.0 - eff_weak(a, c))


def graph_features(model, controls=None, extra=()):
    """hops from the internet, usable in-degree, links that exist, and the best-route chance (max over routes of the product of step chances) for every asset."""
    import heapq
    c = controls or Controls()
    hops = reachable(model, "INTERNET", c, extra) if "INTERNET" in model["assets"] else {}
    all_in = {}
    for e in list(model["edges"]) + list(extra):
        if e.get("exists", True):
            all_in.setdefault(e["target"], []).append(e["id"])
    use = {}
    for e in usable_edges(model, c, extra):
        use[e["target"]] = use.get(e["target"], 0) + 1
    pp = {}
    if "INTERNET" in model["assets"]:
        adj = adjacency(model, c, extra)
        emax = max([a["entry_weight"] for a in model["assets"].values()] + [1e-9])
        best, q = {"INTERNET": 1.0}, [(-1.0, "INTERNET")]
        while q:
            negp, u = heapq.heappop(q)
            if -negp < best.get(u, 0.0):
                continue
            for e in adj.get(u, []):
                v = e["target"]
                w = (model["assets"][v]["entry_weight"] / emax) if u == "INTERNET" else step_chance(model["assets"][v], c)
                p = best[u] * min(1.0, w)
                if p > best.get(v, 0.0):
                    best[v] = p
                    heapq.heappush(q, (-p, v))
        pp = best
    return hops, use, all_in, pp


def asset_features(model, aid, controls=None, extra=(), _g=None):
    c = controls or Controls()
    a = model["assets"][aid]
    hops, use, all_in, pp = _g or graph_features(model, c, extra)
    inbound = len(all_in.get(aid, []))
    closed = inbound - use.get(aid, 0)
    exposure = EXPO[a["exposure"]]
    if aid != "INTERNET" and aid not in hops:
        exposure = min(exposure, 0.0 if a["exposure"] == "isolated" else exposure)   # a disconnected asset keeps its stated exposure but gets hops=9
    return dict(path_prob=float(pp.get(aid, 0.0)), cvss=a["cvss"] / 10.0, epss=a["epss"], kev=1.0 if a["kev"] else 0.0, exploit_signal=exploit_signal(a, c), exposure=exposure, entry_weight=a["entry_weight"],
                weak_access=eff_weak(a, c), unpatched=0.0 if patched(a, c) else (1 - a["p_patched"]), legacy=1.0 if a["legacy"] else 0.0, hops=float(min(hops.get(aid, 9), 9)),
                in_degree=float(use.get(aid, 0)), mfa_on=1.0 if (aid in c.mfa or aid in c.harden) else 0.0, vpatch_on=1.0 if aid in c.vpatch else 0.0,
                segmented=(closed / inbound) if inbound else 0.0)


def vec(f):
    return [f[n] for n in FNAMES]


class RiskModel:
    """Compromise-propensity model: gradient boosting with monotone constraints, so more exposure / weaker access can never lower the score."""

    def __init__(self):
        self.reg, self.meta = None, {}

    def fit(self, X, y, groups=None, seed=0):
        from scipy.stats import spearmanr
        from sklearn.ensemble import HistGradientBoostingRegressor
        X, y = np.asarray(X, float), np.asarray(y, float)
        if len(X) < 20:
            raise ValueError("not enough training rows")
        g = np.asarray(groups) if groups is not None else np.arange(len(X))
        ug = np.unique(g)
        rng = np.random.default_rng(seed)
        test_g = set(rng.choice(ug, size=max(1, len(ug) // 5), replace=False).tolist())   # hold out whole control configurations
        te = np.array([x in test_g for x in g])
        mono = [f[2] for f in FEATURES]
        mk = lambda: HistGradientBoostingRegressor(max_iter=500, learning_rate=0.04, max_depth=6, min_samples_leaf=8, monotonic_cst=mono, random_state=seed)
        m = mk().fit(X[~te], y[~te])
        pred = np.clip(m.predict(X[te]), 0, 1)
        rho = float(spearmanr(pred, y[te])[0]) if len(set(y[te])) > 1 else 0.0
        hits = []
        for gid in test_g:                      # does the model pick the same 5 most-likely-to-fall assets as the simulation, on a configuration it never saw?
            idx = np.where(g == gid)[0]
            if len(idx) >= 5:
                pg = np.clip(m.predict(X[idx]), 0, 1)
                hits.append(len(set(np.argsort(-pg)[:5]) & set(np.argsort(-y[idx])[:5])) / 5.0)
        self.meta = dict(version=MODEL_VERSION, top5_overlap_heldout=round(float(np.mean(hits)), 3) if hits else None, rows=int(len(X)), train_rows=int((~te).sum()), test_rows=int(te.sum()), mae_heldout=round(float(np.abs(pred - y[te]).mean()), 4),
                         spearman_heldout=round(rho, 3), mean_label=round(float(y.mean()), 4), seed=seed, trained_unix=int(time.time()))
        self.reg = mk().fit(X, y)   # final model sees every row
        return self.meta

    def predict(self, X):
        if self.reg is None:
            raise RuntimeError("model not trained")
        return np.clip(self.reg.predict(np.atleast_2d(np.asarray(X, float))), 0.0, 1.0)


def likelihood(prior, anomaly=0.0, monitored=False):
    """ML prior -> final likelihood: observed anomaly raises the odds (Bayes-style rule); monitoring lowers it (rule)."""
    p = min(max(float(prior), 1e-6), 1 - 1e-6)
    odds = p / (1 - p) * (1 + RULES["anomaly_gain"] * max(0.0, min(1.0, anomaly)))
    p = odds / (1 + odds)
    return p * (1 - RULES["monitoring_cut"]) if monitored else p


def feature_contributions(model, risk_model, aid, controls=None, extra=()):
    """Counterfactual explanation: how much of the asset's propensity disappears if one feature group is set to its safest value."""
    c = controls or Controls()
    f = asset_features(model, aid, c, extra)
    base = float(risk_model.predict(vec(f))[0])
    out = []
    for grp, names in GROUPS.items():
        g = dict(f)
        for n in names:
            g[n] = BEST[n]
        out.append(dict(group=grp, contribution=round(base - float(risk_model.predict(vec(g))[0]), 4), inputs={n: round(f[n], 3) for n in names}))
    return base, sorted(out, key=lambda x: (-x["contribution"], x["group"]))


def rank_assets(model, risk_model, controls=None, impact_fn=None, anomaly=None, extra=()):
    """Pure prioritisation: likelihood (ML prior + rules) x operational impact (closure of the asset through links and dependencies)."""
    c, an = controls or Controls(), anomaly or {}
    gf = graph_features(model, c, extra)
    ids = [a for a in model["assets"] if a != "INTERNET"]
    pri = risk_model.predict(np.array([vec(asset_features(model, a, c, extra, _g=gf)) for a in ids]))
    rows = []
    for a, p in zip(ids, pri):
        sim = simulate_compromise(model, a, c, extra=extra)
        imp = service_loss(model, sim["compromised"], impact_fn, c.backup_ir)["loss"]
        lk = likelihood(p, an.get(a, 0.0), a in c.monitoring)
        rows.append(dict(id=a, prior=float(p), likelihood=lk, impact=imp, risk=lk * imp, reach=len(sim["compromised"]) - 1))
    return sorted(rows, key=lambda r: (-r["risk"], r["id"]))


# ------------------------------------------------------------------ SQLite (baseline kept separate from simulation results)
BASELINE_TABLES = ("assets", "edges", "vulnerabilities", "dependencies", "events")
DELETE_SQL = {"assets": "DELETE FROM assets", "edges": "DELETE FROM edges", "vulnerabilities": "DELETE FROM vulnerabilities", "dependencies": "DELETE FROM dependencies", "events": "DELETE FROM events"}   # fixed statements, never built from input
SELECT_ALL_SQL = {"assets": "SELECT body FROM assets ORDER BY 1", "edges": "SELECT body FROM edges ORDER BY 1", "vulnerabilities": "SELECT body FROM vulnerabilities ORDER BY 1"}
SELECT_ONE_SQL = {"assets": "SELECT body FROM assets WHERE id=?", "edges": "SELECT body FROM edges WHERE id=?", "vulnerabilities": "SELECT body FROM vulnerabilities WHERE cve=?"}


class LabDB:
    def __init__(self, path):
        self.path = str(path)
        self.lock = threading.RLock()
        self.cx = sqlite3.connect(self.path, check_same_thread=False)
        self.cx.executescript("""
            CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS edges(id TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS vulnerabilities(cve TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS dependencies(provider TEXT, consumer TEXT, kind TEXT);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, minute INTEGER, kind TEXT, sev TEXT, text TEXT);
            CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, name TEXT, created INTEGER, body TEXT NOT NULL);
        """)

    def seed(self, model, cves):
        """Baseline tables are rewritten from the model at start-up; simulation runs live in `runs` and never touch them."""
        with self.lock, self.cx:
            for t in BASELINE_TABLES:
                self.cx.execute(DELETE_SQL[t])
            self.cx.executemany("INSERT INTO assets VALUES(?,?)", [(k, json.dumps(v)) for k, v in model["assets"].items()])
            self.cx.executemany("INSERT INTO edges VALUES(?,?)", [(e["id"], json.dumps(e)) for e in model["edges"]])
            self.cx.executemany("INSERT INTO vulnerabilities VALUES(?,?)", [(k, json.dumps(v)) for k, v in cves.items()])
            self.cx.executemany("INSERT INTO dependencies VALUES(?,?,?)", [(d["provider"], d["consumer"], d["kind"]) for d in model["deps"]])

    def rows(self, table):
        with self.lock:
            return [json.loads(r[0]) for r in self.cx.execute(SELECT_ALL_SQL[table])]

    def one(self, table, key, col="id"):
        with self.lock:
            r = self.cx.execute(SELECT_ONE_SQL[table], (key,)).fetchone()
        return json.loads(r[0]) if r else None

    def add_event(self, minute, kind, sev, text):
        with self.lock, self.cx:
            self.cx.execute("INSERT INTO events(minute,kind,sev,text) VALUES(?,?,?,?)", (int(minute), str(kind), str(sev), str(text)[:500]))

    def events(self, limit=100, kind=None):
        q, a = "SELECT minute,kind,sev,text FROM events", []
        if kind:
            q += " WHERE kind=?"; a.append(kind)
        q += " ORDER BY id DESC LIMIT ?"; a.append(int(limit))
        with self.lock:
            return [dict(minute=r[0], kind=r[1], sev=r[2], text=r[3]) for r in self.cx.execute(q, a)]

    def add_run(self, kind, name, body):
        with self.lock, self.cx:
            cur = self.cx.execute("INSERT INTO runs(kind,name,created,body) VALUES(?,?,?,?)", (kind, name, int(time.time()), json.dumps(body, default=float)))
            return cur.lastrowid

    def runs(self, limit=20):
        with self.lock:
            return [dict(id=r[0], kind=r[1], name=r[2], created=r[3]) for r in self.cx.execute("SELECT id,kind,name,created FROM runs ORDER BY id DESC LIMIT ?", (int(limit),))]

    def clear_runs(self):
        with self.lock, self.cx:
            self.cx.execute("DELETE FROM runs")
