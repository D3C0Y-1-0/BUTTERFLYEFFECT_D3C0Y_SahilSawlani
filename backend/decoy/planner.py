"""Fix Planner + Ask-First (value of information).

Fix catalogue -> CELF lazy-greedy selection on *net* loss avoided per effort unit (net = loss avoided minus the service lost
by doing the fix itself) -> CP-SAT scheduling into weekly maintenance windows with service-safety conflicts.
Ask-First = expected value of perfect information about each unknown (hidden link / unknown firmware version).
"""
from __future__ import annotations

import heapq

import numpy as np
from ortools.sat.python import cp_model

from .assumptions import A
from .threat import Defence, VP_EFFICACY

CERTIN = {
    "virtual_patch": ["4.4 Network segmentation & isolation", "9.4 IoT/ICS vulnerability management"],
    "firmware_patch": ["9.4 Firmware and patch management", "18 Penetration testing & vulnerability management"],
    "close_link": ["4.4 Network segmentation (inter-zone traffic off by default)", "5 Network security"],
    "mfa_vendor": ["6.1 Multi-factor authentication", "17 Vendor access control policies"],
    "harden_iot": ["9.4 Change default factory settings", "6.5 Secure IoT & device authentication"],
}
CSF = {"virtual_patch": "Protect", "firmware_patch": "Protect", "close_link": "Protect", "mfa_vendor": "Protect", "harden_iot": "Protect"}
PLAIN = {
    "virtual_patch": "Block the known exploit in front of {n} (no reboot)",
    "firmware_patch": "Update the firmware on {n} (needs a restart)",
    "close_link": "Close the {p} link from {s} to {d}",
    "mfa_vendor": "Require a second factor (MFA) on the vendor VPN",
    "harden_iot": "Change default password / settings on {n}",
}


class Fix:
    def __init__(self, id, type, label, cost, apply, events_fn=None, target=None, hidden=False, edge=None):
        self.id, self.type, self.label, self.cost, self.apply, self.events_fn = id, type, label, cost, apply, events_fn
        self.target, self.hidden, self.edge = target, hidden, edge

    def events(self, start_h):
        return self.events_fn(start_h) if self.events_fn else []

    def meta(self):
        return dict(id=self.id, type=self.type, label=self.label, cost=self.cost, target=self.target, hidden_link=self.hidden,
                    certin=CERTIN[self.type], csf=CSF[self.type], iec62443="Zones & conduits (62443-3-2)" if self.type == "close_link" else None)


def fix_catalog(ward, threat) -> list[Fix]:
    assets, edges, acts = ward["assets"], ward["edges"], ward["actions"]
    cost = ASSUME_COST = __import__("decoy.assumptions", fromlist=["ASSUMPTIONS"]).ASSUMPTIONS["fix_cost"]
    out = []
    ctrl_action = {a["controller"]: aid for aid, a in acts.items()}
    for nid, a in assets.items():
        if nid == "INTERNET":
            continue
        if a["cve"]:
            if a["virtual_patchable"]:
                out.append(Fix(f"vp:{nid}", "virtual_patch", PLAIN["virtual_patch"].format(n=a["name"]), cost["virtual_patch"],
                               lambda d, n=nid: d.cve_mult.__setitem__(n, d.cve_mult.get(n, 1.0) * (1 - VP_EFFICACY)), target=nid))

            def fw_events(start_h, n=nid, a=a):
                if n in ctrl_action:
                    act = acts[ctrl_action[n]]
                    return [dict(kind=act["kind"], target=act["target"], start_h=start_h, dur_h=max(0.25, a["patch_downtime_min"] / 60.0))]
                return []
            out.append(Fix(f"fw:{nid}", "firmware_patch", PLAIN["firmware_patch"].format(n=a["name"]), cost["firmware_patch"],
                           lambda d, n=nid: d.cve_mult.__setitem__(n, 0.0), events_fn=fw_events, target=nid))
        if a["p_weak"] >= 0.15 and a["layer"] in ("iot",):
            out.append(Fix(f"hd:{nid}", "harden_iot", PLAIN["harden_iot"].format(n=a["name"]), cost["rotate_creds"],
                           lambda d, n=nid: d.weak_mult.__setitem__(n, d.weak_mult.get(n, 1.0) * 0.1), target=nid))
    out.append(Fix("mfa:VPN_VENDOR", "mfa_vendor", PLAIN["mfa_vendor"], cost["mfa_vendor"],
                   lambda d: ([d.weak_mult.__setitem__("VPN_VENDOR", d.weak_mult.get("VPN_VENDOR", 1.0) * A("mfa_factor"))] +
                              [d.edge_mult.__setitem__(e["id"], d.edge_mult.get(e["id"], 1.0) * 0.25) for e in edges if e["type"] == "vendor"]) and None,
                   target="VPN_VENDOR"))
    lvl = {"internet": 0, "iot": 1, "it": 1, "dmz": 2, "control": 3, "field": 4}
    for e in edges:
        sl, tl = assets[e["source"]]["layer"], assets[e["target"]]["layer"]
        if e["source"] == "INTERNET":
            continue
        crossing = lvl.get(tl, 0) - lvl.get(sl, 0) >= 1 and tl in ("control", "field", "dmz")
        if e["misconfig"] and ("Modbus TCP" in e["misconfig"] or "IEC 104" in e["misconfig"]):
            crossing = False  # intended SCADA<->PLC conduit; not closed by default
        if not (crossing or (not e["known"])):
            continue
        if e["source"] in ("SCADA_SRV", "ENG_WS", "HMI_01") and tl == "field":
            continue

        def ev(start_h, e=e):
            return []
        out.append(Fix(f"cl:{e['id']}", "close_link", PLAIN["close_link"].format(p=e["protocol"].upper(), s=assets[e["source"]]["name"], d=assets[e["target"]]["name"]),
                       cost["close_link"], lambda d, eid=e["id"]: d.blocked_edges.add(eid), events_fn=ev, target=e["id"], hidden=not e["known"], edge=e["id"]))
    return out


def apply_fixes(fixes: list[Fix], base: Defence | None = None) -> Defence:
    d = (base or Defence()).copy()
    for f in fixes:
        f.apply(d)
        d.fixes.append(f.id)
    return d


class Planner:
    def __init__(self, ward, threat, physics, n_plan=1500):
        self.ward, self.T, self.P, self.n = ward, threat, physics, n_plan
        self.catalog = fix_catalog(ward, threat)
        self.by_id = {f.id: f for f in self.catalog}

    def exp_loss(self, defence, n=None):
        ev = self.T.evaluate(defence, n=n or self.n)
        return float(ev["L"].mean())

    def downtime_cost(self, fix: Fix, hour: float):
        ev = fix.events(hour)
        if not ev:
            return 0.0
        return float(self.P.loss(ev)["L"])

    def dt_cached(self, fix: Fix, hour: float):
        c = self.__dict__.setdefault("_dt", {})
        k = (fix.id, hour)
        if k not in c:
            c[k] = self.downtime_cost(fix, hour)
        return c[k]

    def best_slot(self, fix: Fix, hours=(1.0, 2.0, 3.0, 4.0, 5.0, 14.0, 22.0)):
        return min(((self.dt_cached(fix, h), h) for h in hours))

    def severity(self, fix: Fix) -> float:
        """1 (ordinary) to 4 (listed as exploited in the wild and likely to be used): how urgent a fix is, from the real CVE feed."""
        a = self.ward["assets"].get(fix.target or "")
        c = self.T.snap["cves"].get((a or {}).get("cve") or "", {}) if a else {}
        return 1.0 + (1.0 if c.get("in_kev") else 0.0) + 2.0 * float(c.get("epss") or 0.0)

    # ---- CELF lazy greedy on net benefit per effort unit
    def plan(self, defence: Defence | None, budget: float = 12.0, now_hour: float | None = None, base_loss: float | None = None, catalog=None, dt_weight: float = 1.0):
        cat = [f for f in (catalog or self.catalog) if f.id not in (defence.fixes if defence else [])]
        cur = defence.copy() if defence else Defence()
        e_cur = self.exp_loss(cur) if base_loss is None else base_loss
        e_start = e_cur
        D = {f.id: self.best_slot(f)[0] for f in cat}
        heap = []
        for f in cat:
            d2 = cur.copy(); f.apply(d2)
            gain = e_cur - self.exp_loss(d2)
            heapq.heappush(heap, (-(gain - dt_weight * D[f.id]) / f.cost, f.id, gain))
        chosen, steps, spent = [], [], 0.0
        stamp = {f.id: 0 for f in cat}
        it = 0
        while heap and spent < budget:
            ratio, fid, gain_old = heapq.heappop(heap)
            f = self.by_id[fid]
            if spent + f.cost > budget:
                continue
            if stamp[fid] != it:   # stale -> recompute (lazy evaluation)
                d2 = cur.copy(); f.apply(d2)
                gain = e_cur - self.exp_loss(d2)
                stamp[fid] = it
                heapq.heappush(heap, (-(gain - dt_weight * D[fid]) / f.cost, fid, gain))
                continue
            gain = gain_old
            net = gain - dt_weight * D[fid]
            if net <= 0:
                break
            f.apply(cur); cur.fixes.append(fid)
            e_new = e_cur - gain
            chosen.append(f); spent += f.cost
            steps.append(dict(fix=f.meta(), gain=round(gain, 1), downtime_loss=round(D[fid], 1), net=round(net, 1), e_before=round(e_cur, 1), e_after=round(e_new, 1)))
            e_cur = e_new
            it += 1
        refused = []
        for f in cat:
            if f.type == "firmware_patch" and f.events(0):
                nowc = self.downtime_cost(f, now_hour if now_hour is not None else 18.0)
                best = self.best_slot(f)
                if nowc > 0:
                    refused.append(dict(fix=f.meta(), loss_if_now=round(nowc, 1), best_hour=best[1], loss_at_best=round(best[0], 1),
                                        reason=f"Doing this at {int(now_hour if now_hour is not None else 18):02d}:00 would cost {round(nowc):,} household-hour-equivalents of outage; schedule for {int(best[1]):02d}:00 or use a virtual patch."))
        return dict(chosen=chosen, steps=steps, e_start=e_start, e_end=e_cur, defence=cur, spent=spent, refused=refused, downtime=D)

    # ---- CP-SAT scheduling into weekly windows
    def schedule(self, plan, weeks=4, cap=8.0):
        chosen, steps = plan["chosen"], plan["steps"]
        if not chosen:
            return []
        m = cp_model.CpModel()
        x = {(i, w): m.NewBoolVar(f"x{i}_{w}") for i in range(len(chosen)) for w in range(weeks)}
        for i in range(len(chosen)):
            m.AddExactlyOne(x[i, w] for w in range(weeks))
        for w in range(weeks):
            m.Add(sum(int(round(chosen[i].cost * 10)) * x[i, w] for i in range(len(chosen))) <= int(cap * 10))
        # service safety: two fixes that stop equipment must not share a window if their combined outage is super-additive
        ev_idx = [i for i, f in enumerate(chosen) if f.events(3.0)]
        for a_ in range(len(ev_idx)):
            for b_ in range(a_ + 1, len(ev_idx)):
                i, j = ev_idx[a_], ev_idx[b_]
                both = self.P.loss(chosen[i].events(3.0) + chosen[j].events(3.0))["L"]
                single = self.P.loss(chosen[i].events(3.0))["L"] + self.P.loss(chosen[j].events(3.0))["L"]
                if both > 1.2 * single + 1.0:
                    for w in range(weeks):
                        m.Add(x[i, w] + x[j, w] <= 1)
        m.Minimize(sum(int(steps[i]["gain"] / 10) * w * x[i, w] for i in range(len(chosen)) for w in range(weeks)))
        s = cp_model.CpSolver(); s.parameters.max_time_in_seconds = 5
        st = s.Solve(m)
        DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        LOAD = [1.0, 1.0, 1.0, 1.0, 1.05, 0.8, 0.7]     # SYNTHETIC: water and power demand by weekday (weekends are lighter)
        HOURS = (1.0, 2.0, 3.0, 4.0, 5.0, 14.0, 22.0)
        DELAY = 0.012                                    # SYNTHETIC: share of a fix's benefit lost for each day it waits, scaled by severity
        used, out = set(), []
        order = sorted(range(len(chosen)), key=lambda i: -steps[i]["gain"])     # most valuable fix picks its slot first
        wk_of = {i: next((w for w in range(weeks) if st in (cp_model.OPTIMAL, cp_model.FEASIBLE) and s.Value(x[i, w])), i % weeks) for i in range(len(chosen))}
        for i in order:
            f = chosen[i]
            wk = wk_of[i]
            sev, gain = self.severity(f), steps[i]["gain"]
            has_out = bool(f.events(0))
            if not has_out:   # virtual patch, MFA, closing a link: no restart, so no need to wait for a quiet night. Most valuable first, in working hours
                rank = sum(1 for j in order if j != i and chosen[j].events(0) == [] and wk_of[j] == wk and order.index(j) < order.index(i))
                day_i, hour, dcost = min(rank, 4), 10.0, 0.0
                score_note = "no restart needed, so it is done in working hours, most valuable first"
            else:
                best = None
                for d in range(7):
                    for h in HOURS:
                        if (wk, d) in used:
                            continue
                        oc = self.dt_cached(f, h) * LOAD[d]
                        delay = gain * DELAY * sev * (wk * 7 + d)
                        sc = oc + delay
                        if best is None or sc < best[0]:
                            best = (sc, d, h, oc)
                if best is None:
                    best = (0.0, 0, HOURS[0], self.dt_cached(f, HOURS[0]))
                _, day_i, hour, dcost = best
                used.add((wk, day_i))
                score_note = f"lowest total of outage cost and waiting cost (severity {sev:.1f}, benefit {gain:,.0f})"
            first = (wk == 0 and not has_out and day_i == 0)
            when = "Now" if first else f"{DAYS[day_i][:3]} {int(hour):02d}:00" + (f" · wk {wk + 1}" if wk else "")
            out.append(dict(fix=f.meta(), week=wk + 1, day=DAYS[day_i], day_index=day_i, hour=hour, when=when, no_outage=not has_out,
                            downtime_min=int(f.events(0)[0]["dur_h"] * 60) if has_out else 0, downtime_loss=round(dcost, 1), gain=gain, severity=round(sev, 2),
                            reason=score_note))
        out.sort(key=lambda r: (r["week"], r["day_index"], r["hour"]))
        return out

    # ---- Ask-First
    def unknowns(self):
        U = []
        for e in self.ward["edges"]:
            if not e["known"]:
                U.append(dict(id=f"edge:{e['id']}", kind="link", edge=e["id"], belief=e["belief"], text=f"Can {self.ward['assets'][e['source']]['name']} reach {self.ward['assets'][e['target']]['name']} ({e['protocol'].upper()})?", detail=e["misconfig"]))
        for nid, a in self.ward["assets"].items():
            if not a["known_version"]:
                U.append(dict(id=f"ver:{nid}", kind="version", node=nid, belief=a["cve_belief"], text=f"Is {a['name']} running the vulnerable firmware ({a['cve']})?", detail="Firmware version missing from inventory"))
        return U

    def _with_answer(self, u, yes: bool):
        """Return a context manager-like pair (apply, undo) toggling the world to a known truth."""
        if u["kind"] == "link":
            e = next(x for x in self.ward["edges"] if x["id"] == u["edge"])
            old = (e["known"], e["truth"])
            def apply(): e["known"], e["truth"] = True, yes
            def undo(): e["known"], e["truth"] = old
        else:
            a = self.ward["assets"][u["node"]]
            old = (a["known_version"], a["cve_belief"])
            def apply(): a["known_version"], a["cve_belief"] = True, (1.0 if yes else 0.0)
            def undo(): a["known_version"], a["cve_belief"] = old
        return apply, undo

    def value_of_information(self, defence, budget=12.0, topk=12):
        """VoI(u) = E_answer[ loss(blind plan | truth) - loss(informed plan | truth) ]."""
        blind = self.plan(defence, budget)
        blind_fixes = blind["chosen"]
        res = []
        for u in self.unknowns():
            p = u["belief"]
            tot = 0.0
            detail = {}
            for yes, pr in ((True, p), (False, 1 - p)):
                apply, undo = self._with_answer(u, yes)
                apply()
                try:
                    e_blind = self.exp_loss(apply_fixes(blind_fixes, defence))
                    informed = self.plan(defence, budget)
                    e_inf = informed["e_end"]
                    detail["yes" if yes else "no"] = dict(p=round(pr, 2), blind=round(e_blind, 1), informed=round(e_inf, 1))
                    tot += pr * max(0.0, e_blind - e_inf)
                finally:
                    undo()
            res.append(dict(u, voi=round(tot, 1), answers=detail))
        res.sort(key=lambda r: -r["voi"])
        return res[:topk], blind

    def answer(self, uid, yes: bool):
        for u in self.unknowns():
            if u["id"] == uid:
                apply, _ = self._with_answer(u, yes)
                apply()
                return True
        return False
