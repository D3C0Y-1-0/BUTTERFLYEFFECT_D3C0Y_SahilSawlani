"""Reinforcement-learning responder for zero-day attacks.

RLCore  : observation, action space, action masking (incl. the Safety Check as a shield) and the action effects. Shared by the
          training environment and the live runtime, so what the policy learns is exactly what it later does.
ZDEnv   : episodes on the real adversary + live twin. One decision = 10 simulated minutes.
PPO     : clipped-objective actor-critic with GAE and invalid-action masking, written in PyTorch (no external RL library).
"""
from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from .adversary import Adversary
from .environment import Environment
from .assumptions import ASSUMPTIONS
from .city import DATA
from .healer import ISOLATION_H, OPS_COST, OPS_UNIT, Healer
from .threat import Defence, VP_EFFICACY
from .twin import LiveTwin
from .zeroday import VP_POST, VP_PRE, Library, products, random_zero_day, split_products

DECISION_MIN = 10
MAX_STEPS = 36
REWARD_SCALE = 20000.0


@dataclass
class ZDState:
    """What the defender knows and has done during one incident (shared by env and runtime)."""
    observed: set = field(default_factory=set)
    step: int = 0
    first_obs_step: int | None = None
    phys_obs: dict = field(default_factory=lambda: dict(pump1=0, pump2=0, valve=0, breaker=0, hospital=0))
    analysing: dict | None = None          # {"product":..., "done_step":...}
    analysis_failed: bool = False
    ops_total: float = 0.0
    actions: list = field(default_factory=list)


class RLCore:
    def __init__(self, ward, threat, physics):
        self.ward, self.T, self.P = ward, threat, physics
        self.healer = Healer(ward, threat, physics)
        self.nodes = [n for n in ward["assets"] if n != "INTERNET"]
        self.nidx = {n: i for i, n in enumerate(self.nodes)}
        self.edges = ward["edges"]
        self.prod = products(ward)
        self.node_prod = {n: p for p, ns in self.prod.items() for n in ns}
        a = [("wait", None)]
        a += [("vp", n) for n in self.nodes]
        a += [("quar", n) for n in self.nodes]
        a += [("close", e["id"]) for e in self.edges]
        a += [("creds", n) for n in self.nodes]
        a += [("restore", None), ("analyse", None)]
        self.actions = a
        self.A = len(a)
        self.eid = {e["id"]: e for e in self.edges}
        self._safe_cache = {}
        self.obs_dim = len(self.nodes) * 5 + 22

    # ------------------------------------------------------------------ labels
    def label(self, i):
        k, x = self.actions[i]
        nm = lambda n: self.ward["assets"][n]["name"]
        if k == "wait": return "Keep watching"
        if k == "vp": return f"Virtual patch in front of {nm(x)}"
        if k == "quar": return f"Isolate {nm(x)} from the network"
        if k == "close":
            e = self.eid[x]; return f"Close the {e['protocol'].upper()} link {nm(e['source'])} -> {nm(e['target'])}"
        if k == "creds": return f"Rotate credentials / add MFA for {nm(x)}"
        if k == "restore": return "Send a crew to restore equipment under local manual control"
        return "Analyse the exploit sample and deploy a family rule to every device of that product"

    def ops(self, i):
        k, x = self.actions[i]
        return {"wait": 0.0, "vp": 1.0, "quar": float(OPS_COST.get(x, 2)), "close": 1.5, "creds": 1.0, "restore": 3.0, "analyse": 2.0}[k]

    def events(self, i):
        k, x = self.actions[i]
        if k == "quar":
            return Healer._isolation_events({x}, set(), False)
        if k == "close":
            e = self.eid[x]; return Healer._isolation_events({e["source"]}, {e["target"]}, True)
        return []

    # ------------------------------------------------------------------ observation
    def obs(self, st: ZDState, defence: Defence, twin: LiveTwin, lib: Library):
        N = len(self.nodes)
        o = np.zeros(self.obs_dim, np.float32)
        for n in st.observed:
            if n in self.nidx:
                o[self.nidx[n]] = 1
        for n in defence.quarantined:
            o[N + self.nidx[n]] = 1
        for n in self.nodes:
            i = self.nidx[n]
            o[2 * N + i] = 1.0 if (defence.cve_mult.get(n, 1.0) < 0.5 or defence.zd_mult.get(n, 1.0) < 0.9) else 0.0
        blocked = defence.blocked_edges
        outc, tot = {}, {}
        for e in self.edges:
            tot[e["source"]] = tot.get(e["source"], 0) + 1
            if e["id"] in blocked:
                outc[e["source"]] = outc.get(e["source"], 0) + 1
        for n in self.nodes:
            o[3 * N + self.nidx[n]] = outc.get(n, 0) / max(1, tot.get(n, 1))
        # frontier: where would an attacker standing on the observed nodes go next
        C = set(st.observed)
        if C:
            pn = self.T.node_probs(defence); pe = self.T.edge_probs(defence)
            fr = np.zeros(N)
            for i, e in enumerate(self.edges):
                if e["source"] in C and e["target"] not in C and e["target"] in self.nidx:
                    fr[self.nidx[e["target"]]] = max(fr[self.nidx[e["target"]]], pe[i] * pn[self.T.idx[e["target"]]])
            if fr.max() > 0:
                fr /= fr.max()
            o[4 * N:5 * N] = fr
        g = 5 * N
        sv = twin.services()
        hr = twin.hour()
        learned_any = any(lib.learned(p) for p in lib.records)
        vals = [min(1.0, (st.step - (st.first_obs_step if st.first_obs_step is not None else st.step)) / MAX_STEPS) if st.first_obs_step is not None else 0.0,
                min(1.0, len(st.observed) / 10), *[float(v) for v in st.phys_obs.values()], sv["served_frac"], twin.level["T1"] / 8, twin.level["T2"] / 8,
                *[1.0 if sv["hospitals"][h]["ok"] else 0.0 for h in ("H1", "H2", "H3")], math.sin(2 * math.pi * hr / 24), math.cos(2 * math.pi * hr / 24),
                1.0 if learned_any else 0.0, 1.0 if st.analysing else 0.0, 1.0 if st.analysis_failed else 0.0, st.step / MAX_STEPS, min(1.0, len(defence.quarantined) / 10), 1.0 if st.observed else 0.0]
        o[g:g + len(vals)] = vals
        return o

    # ------------------------------------------------------------------ masking (+ Safety Check shield)
    def _active(self, st, twin):
        rep = ASSUMPTIONS["repair_h"]
        out = []
        m = twin.minute
        for pump, until in twin.forced_off.items():
            if until > m: out.append(dict(kind="pump_off", target=pump, dur_h=rep["plc"]))
        for v, until in twin.valve_closed.items():
            if until > m: out.append(dict(kind="valve_close", target=v, dur_h=rep["valve"]))
        for f, until in twin.breaker_open.items():
            if until > m: out.append(dict(kind="breaker_open", target=f, dur_h=rep["breaker"]))
        return out

    def safe(self, i, hour, active):
        ev = self.events(i)
        if not ev:
            return True
        key = (i, int(hour // 3), tuple(sorted((a["kind"], a["target"]) for a in active)))
        if key not in self._safe_cache:
            self._safe_cache[key] = self.healer.safety_check(dict(events=ev), hour, active)["ok"]
        return self._safe_cache[key]

    def mask(self, st: ZDState, defence: Defence, twin: LiveTwin, lib: Library, shield=True):
        m = np.zeros(self.A, bool)
        m[0] = True
        hour = twin.hour()
        active = self._active(st, twin) if shield else []
        any_phys = any(st.phys_obs.values())
        for i, (k, x) in enumerate(self.actions):
            if k == "wait":
                continue
            if k == "vp":
                m[i] = defence.zd_mult.get(x, 1.0) > 0.9 and defence.cve_mult.get(x, 1.0) > 0.9
            elif k == "quar":
                m[i] = x not in defence.quarantined
            elif k == "close":
                e = self.eid[x]; m[i] = e["id"] not in defence.blocked_edges and e["source"] != "INTERNET"
            elif k == "creds":
                m[i] = self.ward["assets"][x]["p_weak"] > 0.1 and defence.weak_mult.get(x, 1.0) > 0.5
            elif k == "restore":
                m[i] = any_phys
            elif k == "analyse":
                m[i] = bool(st.observed) and st.analysing is None and not st.analysis_failed
            if m[i] and shield and self.events(i) and not self.safe(i, hour, active):
                m[i] = False
        return m

    # ------------------------------------------------------------------ effects
    def apply(self, i, st: ZDState, defence: Defence, twin: LiveTwin, lib: Library, zd_product_of: dict | None = None, minute=0):
        """Apply action i. Returns a dict describing what happened (used by env and runtime)."""
        k, x = self.actions[i]
        info = dict(kind=k, label=self.label(i), ops=self.ops(i))
        st.ops_total += self.ops(i) * OPS_UNIT
        st.actions.append(dict(step=st.step, label=info["label"]))
        if k == "vp":
            defence.cve_mult[x] = defence.cve_mult.get(x, 1.0) * (1 - VP_EFFICACY)
            learned = lib.learned(self.node_prod[x])
            defence.zd_mult[x] = defence.zd_mult.get(x, 1.0) * (VP_POST if learned else VP_PRE)
        elif k == "quar":
            defence.quarantined.add(x)
        elif k == "close":
            defence.blocked_edges.add(x)
        elif k == "creds":
            defence.weak_mult[x] = defence.weak_mult.get(x, 1.0) * 0.1
        elif k == "restore":
            for a in self._active(st, twin):
                twin.restore(a["kind"], a["target"])
            if twin.h1_isolated_until > twin.minute:
                twin.restore("hospital_isolate", "H1")
            st.phys_obs = {kk: 0 for kk in st.phys_obs}
        elif k == "analyse":
            # the product is inferred from observed nodes that are unexplained by the CVE data; the sample reveals the family
            cands = [n for n in st.observed if n in self.node_prod]
            prods = [self.node_prod[n] for n in cands]
            target = None
            if zd_product_of:
                for n in cands:
                    if zd_product_of.get(n):
                        target = zd_product_of[n]; break
            if target is None:
                st.analysis_failed = True
                info["note"] = "Analysis found no exploit sample in the evidence."
            else:
                st.analysing = dict(product=target, done_step=st.step + 1)
                lib.add(target, minute, dict(observed=sorted(st.observed)), self.prod[target])
        for e in self.events(i):
            twin.act(e["kind"], e["target"], int(ISOLATION_H * 60))
        return info

    def auto_analyse(self, st: ZDState, lib: Library, zd_product_of, minute):
        """Zero-day pipeline step (automatic, not a learned action): as soon as evidence contains a device of a product that is not yet
        in the library, capture a sample, start the analysis (done next step) and register the family."""
        if st.analysing is not None or not zd_product_of:
            return None
        for n in sorted(st.observed):
            p = zd_product_of.get(n)
            if p and not lib.learned(p):
                st.analysing = dict(product=p, done_step=st.step + 1)
                st.ops_total += 2.0 * OPS_UNIT
                lib.add(p, minute, dict(observed=sorted(st.observed)), self.prod[p])
                return p
        return None

    def finish_analysis(self, st, defence, lib, minute):
        """Called every decision step: when the analysis is done, deploy the family rule fleet-wide."""
        if st.analysing and st.step >= st.analysing["done_step"]:
            p = st.analysing["product"]
            nodes = self.prod[p]
            for n in nodes:
                defence.zd_mult[n] = min(defence.zd_mult.get(n, 1.0), VP_POST)
            lib.learn(p, minute, len(nodes))
            st.analysing = None
            return p
        return None


# ====================================================================== environment
class ZDEnv:
    def __init__(self, core: RLCore, seed=0, train_products=None, lib_prob=0.3):
        self.core = core
        self.rng = np.random.default_rng(seed)
        self.train_products = train_products
        self.lib_prob = lib_prob
        self.twin = LiveTwin(core.ward, seed=seed)
        self.lib = Library()
        self.defence = Defence()

    def reset(self, product=None, entry=None, goal=None, mode=None, lib: Library | None = None, seed=None):
        c = self.core
        if seed is not None:
            self.rng = np.random.default_rng(seed)
        self.twin = LiveTwin(c.ward, seed=int(self.rng.integers(1e6)))
        self.twin.minute = int(self.rng.integers(0, 1440))
        for _ in range(60):
            self.twin.step()
        self.twin.lost = dict(hh_h=0.0, hosp_h=0.0, mwh=0.0)
        self.defence = Defence()
        self.st = ZDState()
        self.lib = lib if lib is not None else Library()
        key = product or str(self.rng.choice(self.train_products or sorted(c.prod)))
        self.zd = random_zero_day(c.ward, self.rng, products_allowed=[key], minute=self.twin.minute)
        if lib is None and self.rng.random() < self.lib_prob:      # a repeat encounter: the family rule already exists
            self.lib.add(key, 0, {}, c.prod[key]); self.lib.learn(key, 0, len(c.prod[key]))
        if self.lib.learned(key):
            for n in c.prod[key]:
                self.defence.zd_mult[n] = VP_POST
        self.adv = Adversary(c.ward, int(self.rng.integers(1e6)))
        self.env = Environment(c.ward, c.T, defence=lambda: self.defence, seed=int(self.rng.integers(1e6)))
        entries = [n for n, a in c.ward["assets"].items() if a["entry_weight"] > 0]
        goals = list(self.adv.goals)
        self.camp = self.adv.launch(self.twin.minute, mode=mode or str(self.rng.choice(["standard", "spoof", "wear", "insider"])), entry=entry or str(self.rng.choice(entries)),
                                    goal=goal or str(self.rng.choice(goals)), stealth=float(self.rng.uniform(2, 7)), zd=self.zd)
        self.exec_min = {}
        self.loss_prev = 0.0
        self.t = 0
        self.zd_product_of = {n: key for n in self.zd.affected}
        self.cost_log = dict(service=0.0, ops=0.0)
        self.peak_cut = 0
        return c.obs(self.st, self.defence, self.twin, self.lib)

    # --------------------------------------------------------------
    def _observe_phys(self, ph, minute):
        kind = ph["kind"]
        key = {"pump_off": "pump1" if ph["target"] == "PS1" else "pump2", "valve_close": "valve", "breaker_open": "breaker", "hospital_isolate": "hospital"}.get(kind)
        delay = {"pump_off": 30 if ph.get("mode") == "spoof" else 60, "valve_close": 1, "breaker_open": 1, "hospital_isolate": 5}.get(kind, 60)
        if key:
            self.exec_min[key] = (minute, delay)

    def _tick10(self):
        tw, c = self.twin, self.core
        for _ in range(DECISION_MIN):
            m = tw.minute
            fl, ph, evs = self.adv.tick(m, self.env)
            fl = self.env.deliver(fl)
            for e in evs:
                if e["type"] == "hop" and self.rng.random() < 0.55:
                    self.st.observed.add(e["dst"]); self.st.observed.discard("INTERNET")
                    if e["src"] != "INTERNET":
                        self.st.observed.add(e["src"])
            if fl and self.rng.random() < 0.05:
                eid = fl[0][0]
                if eid in c.eid:
                    self.st.observed.add(c.eid[eid]["target"])
            for p in ph:
                if p["kind"] == "wear":
                    tw.breaker_cycle(); continue
                tw.act(p["kind"], p["target"], p["dur_min"])
                self._observe_phys(p, m)
            tw.step()
        for key, (m0, delay) in list(self.exec_min.items()):
            if tw.minute - m0 >= delay:
                self.st.phys_obs[key] = 1
        if self.rng.random() < 0.03:
            self.st.observed.add(str(self.rng.choice(c.nodes)))
        if self.st.observed and self.st.first_obs_step is None:
            self.st.first_obs_step = self.st.step

    def step(self, a):
        c = self.core
        ops0 = self.st.ops_total
        info = c.apply(a, self.st, self.defence, self.twin, self.lib, self.zd_product_of, self.twin.minute)
        self._tick10()
        c.auto_analyse(self.st, self.lib, self.zd_product_of, self.twin.minute)
        self.st.step += 1
        self.t += 1
        learned_now = c.finish_analysis(self.st, self.defence, self.lib, self.twin.minute)
        self.peak_cut = max(self.peak_cut, len(self.defence.quarantined) + len(self.defence.blocked_edges))
        loss = self.twin.loss_composite()
        r = -(loss - self.loss_prev) / REWARD_SCALE - (self.st.ops_total - ops0) / REWARD_SCALE - 0.01 * len(self.defence.quarantined)
        if learned_now:
            r += 0.05   # shaping: a deployed family rule is institutional memory whose payoff arrives in LATER encounters
        self.cost_log["service"] += loss - self.loss_prev
        self.loss_prev = loss
        outage = bool(self.core._active(self.st, self.twin)) or self.twin.h1_isolated_until > self.twin.minute
        done = self.t >= MAX_STEPS or (self.camp.state in ("done", "contained") and self.t >= 3 and not outage)
        if done:
            r += self._terminal()
        return c.obs(self.st, self.defence, self.twin, self.lib), float(r), done, dict(info, loss=loss)

    def _terminal(self):
        """Fast-forward 10 h with recovery (isolation lifted) so unresolved outages are paid for."""
        tw = self.twin
        before = tw.loss_composite()
        contained = self.camp.state == "contained" or not self.camp.acted
        self.defence.quarantined.clear()
        tw.local_mode.clear()
        for _ in range(600):
            tw.step()
        rest = tw.loss_composite() - before
        self.cost_log["service"] += rest
        return -rest / REWARD_SCALE + (0.6 if contained and not self.camp.acted else 0.0)

    def result(self):
        tw = self.twin
        return dict(loss=tw.loss_composite(), service=self.cost_log["service"], ops=self.st.ops_total, total=tw.loss_composite() + self.st.ops_total,
                    contained=bool(self.camp.state == "contained" or not self.camp.acted), acted=bool(self.camp.acted), hosp_h=tw.lost["hosp_h"],
                    devices_cut=self.peak_cut, learned=bool(self.lib.learned(self.zd.product)), steps=self.t, product=self.zd.product, mode=self.camp.mode, actions=[a["label"] for a in self.st.actions])


# ====================================================================== PPO
def _torch():
    import torch
    return torch


class PPO:
    def __init__(self, obs_dim, n_act, seed=0, hidden=192, lr=3e-4):
        torch = _torch(); nn = torch.nn
        torch.manual_seed(seed)
        self.torch = torch
        self.net = nn.ModuleDict(dict(body=nn.Sequential(nn.Linear(obs_dim, hidden), nn.Tanh(), nn.Linear(hidden, hidden), nn.Tanh()), pi=nn.Linear(hidden, n_act), v=nn.Linear(hidden, 1)))
        nn.init.orthogonal_(self.net["pi"].weight, 0.01)
        self.opt = torch.optim.Adam(self.net.parameters(), lr=lr, eps=1e-5)
        self.obs_dim, self.n_act = obs_dim, n_act

    def forward(self, o, mask):
        torch = self.torch
        h = self.net["body"](o)
        logits = self.net["pi"](h).masked_fill(~mask, -1e9)
        return logits, self.net["v"](h).squeeze(-1)

    def act(self, obs, mask, deterministic=False):
        torch = self.torch
        with torch.no_grad():
            o = torch.as_tensor(obs, dtype=torch.float32).unsqueeze(0); m = torch.as_tensor(mask).unsqueeze(0)
            logits, v = self.forward(o, m)
            dist = torch.distributions.Categorical(logits=logits)
            a = logits.argmax(-1) if deterministic else dist.sample()
            return int(a.item()), float(dist.log_prob(a).item()), float(v.item()), dist.probs[0].numpy()

    def save(self, path, meta):
        self.torch.save(dict(state=self.net.state_dict(), meta=meta), path)

    @classmethod
    def load(cls, path):
        torch = _torch()
        d = torch.load(path, map_location="cpu", weights_only=True)   # tensors + plain metadata only: no pickled code is executed
        m = d["meta"]
        p = cls(m["obs_dim"], m["n_act"], hidden=m.get("hidden", 192))
        p.net.load_state_dict(d["state"]); p.net.eval()
        return p, m

    def update(self, buf, epochs=6, mb=256, clip=0.2, vf=0.5, ent=0.01):
        torch = self.torch
        o = torch.as_tensor(np.array(buf["obs"]), dtype=torch.float32); a = torch.as_tensor(buf["act"]); m = torch.as_tensor(np.array(buf["mask"]))
        lp0 = torch.as_tensor(buf["logp"], dtype=torch.float32); adv = torch.as_tensor(buf["adv"], dtype=torch.float32); ret = torch.as_tensor(buf["ret"], dtype=torch.float32)
        adv = (adv - adv.mean()) / (adv.std() + 1e-8)
        n = len(a); stats = []
        for _ in range(epochs):
            idx = torch.randperm(n)
            for s in range(0, n, mb):
                b = idx[s:s + mb]
                logits, v = self.forward(o[b], m[b])
                dist = torch.distributions.Categorical(logits=logits)
                lp = dist.log_prob(a[b]); ratio = (lp - lp0[b]).exp()
                pl = -torch.min(ratio * adv[b], ratio.clamp(1 - clip, 1 + clip) * adv[b]).mean()
                vl = ((v - ret[b]) ** 2).mean(); en = dist.entropy().mean()
                loss = pl + vf * vl - ent * en
                self.opt.zero_grad(); loss.backward(); torch.nn.utils.clip_grad_norm_(self.net.parameters(), 0.5); self.opt.step()
                stats.append((pl.item(), vl.item(), en.item()))
        return np.mean(stats, axis=0)


def train(core: RLCore, iters=80, steps=2048, seed=0, log=None, lr=3e-4, verbose=True, out=None):
    train_p, test_p = split_products(core.ward)
    env = ZDEnv(core, seed=seed, train_products=train_p)
    ppo = PPO(core.obs_dim, core.A, seed=seed, lr=lr)
    hist = []
    o = env.reset(); ep_r, ep_rs, ep_costs = 0.0, [], []
    t0 = time.time()
    for it in range(iters):
        buf = dict(obs=[], act=[], mask=[], logp=[], val=[], rew=[], done=[])
        for _ in range(steps):
            mk = core.mask(env.st, env.defence, env.twin, env.lib)
            a, lp, v, _ = ppo.act(o, mk)
            o2, r, d, info = env.step(a)
            for k_, x in zip(("obs", "act", "mask", "logp", "val", "rew", "done"), (o, a, mk, lp, v, r, d)):
                buf[k_].append(x)
            ep_r += r
            o = o2
            if d:
                ep_rs.append(ep_r); ep_costs.append(env.result()["total"]); ep_r = 0.0
                o = env.reset()
        # GAE
        torch = ppo.torch
        with torch.no_grad():
            mk = core.mask(env.st, env.defence, env.twin, env.lib)
            _, lastv = ppo.forward(torch.as_tensor(o, dtype=torch.float32).unsqueeze(0), torch.as_tensor(mk).unsqueeze(0))
            lastv = float(lastv.item())
        adv = np.zeros(steps); last = 0.0
        for t in reversed(range(steps)):
            nv = lastv if t == steps - 1 else buf["val"][t + 1]
            nd = 1.0 - float(buf["done"][t])
            delta = buf["rew"][t] + 0.99 * nv * nd - buf["val"][t]
            last = delta + 0.99 * 0.95 * nd * last
            adv[t] = last
        buf["adv"] = adv; buf["ret"] = adv + np.array(buf["val"])
        ent = max(0.006, 0.03 * (1 - it / iters))
        st = ppo.update(buf, ent=ent)
        rec = dict(iter=it, steps=(it + 1) * steps, mean_return=float(np.mean(ep_rs[-30:])) if ep_rs else 0.0, mean_total_cost=float(np.mean(ep_costs[-30:])) if ep_costs else 0.0,
                   entropy=float(st[2]), seconds=round(time.time() - t0))
        hist.append(rec)
        if verbose:
            print(rec, flush=True)
        if log:
            Path(log).write_text(json.dumps(hist), encoding="utf-8")
    meta = dict(obs_dim=core.obs_dim, n_act=core.A, hidden=192, train_products=train_p, test_products=test_p, nodes=core.nodes, iters=iters, steps=steps, seed=seed)
    ppo.save(out or (DATA / "ppo_policy.pt"), meta)
    return ppo, hist, meta


# ====================================================================== policies for evaluation
class PPOPolicy:
    def __init__(self, core: RLCore, path=None):
        self.core = core
        self.ppo, self.meta = PPO.load(path or DATA / "ppo_policy.pt")

    def choose(self, env_or_state, deterministic=True):
        raise NotImplementedError


def run_policy(core: RLCore, env: ZDEnv, name: str, ppo: PPO | None = None, search=None, deterministic=True):
    """Run one episode already reset in `env` with the named policy. Returns env.result()."""
    o = env.obs_now() if hasattr(env, "obs_now") else core.obs(env.st, env.defence, env.twin, env.lib)
    done = False
    iso_done = False
    last_obs_n = 0
    while not done:
        mk = core.mask(env.st, env.defence, env.twin, env.lib)
        a = 0
        if name == "none":
            a = 0
        elif name == "iso_all":
            if env.st.observed and not iso_done:
                iso_done = True
                for n in core.nodes:
                    env.defence.quarantined.add(n)
                env.st.ops_total += sum(OPS_COST.values()) * OPS_UNIT
                for p in ("PS1", "PS2"):
                    env.twin.act("pump_duty", p, int(ISOLATION_H * 60))
        elif name == "ppo":
            a, _, _, _ = ppo.act(o, mk, deterministic=deterministic)
        elif name == "search":
            if env.st.observed and len(env.st.observed) > last_obs_n:
                last_obs_n = len(env.st.observed)
                comp = ["INTERNET"] + sorted(env.st.observed)
                done_ph = []
                dec = search.decide(comp, env.defence, env.twin.hour(), done_ph, n=500)
                for step in dec["steps"]:
                    _apply_search_step(core, env, step)
        o, r, done, info = env.step(a)
    return env.result()


def _apply_search_step(core: RLCore, env: ZDEnv, step):
    k = step["kind"]
    d = env.defence
    env.st.ops_total += step["ops"]
    if k == "virtual_patch":
        n = step["node"]
        d.cve_mult[n] = d.cve_mult.get(n, 1.0) * (1 - VP_EFFICACY)
        d.zd_mult[n] = d.zd_mult.get(n, 1.0) * (VP_POST if env.lib.learned(core.node_prod[n]) else VP_PRE)
    elif k == "close_link":
        d.blocked_edges.add(step["edge"])
    elif k == "rotate_creds":
        d.weak_mult[step["node"]] = d.weak_mult.get(step["node"], 1.0) * 0.1
    elif k == "quarantine":
        for n in step["nodes"]:
            d.quarantined.add(n)
    for e in step.get("events", []):
        env.twin.act(e["kind"], e["target"], int(ISOLATION_H * 60))
