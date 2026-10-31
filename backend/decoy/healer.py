"""Healer: smallest safe response.

Candidates come from the response ladder (observe < virtual patch < close one link < rotate credentials < decoy < quarantine a
node < crew-restores-manually). Each is scored in the twin with the same attack model:
    J = E[service loss still to come | action]  +  service lost by the action itself (oracle)  +  operational disruption
The best candidate must pass the Safety Check (hospital pressure / grid limits re-simulated by the oracle) before it runs.
"Isolate everything" is always evaluated as the comparison, never chosen.
"""
from __future__ import annotations

from .assumptions import A, ASSUMPTIONS
from .threat import VP_EFFICACY

ISOLATION_H = 18.0    # an isolation lasts until the system is verified clean (assumption)
OPS_UNIT = 200.0     # household-hour-equivalents per operational-disruption point (assumption)
OPS_COST = {"INTERNET": 0, "SCADA_SRV": 12, "HMI_01": 4, "ENG_WS": 3, "HIST_01": 3, "JUMP_RDS": 1, "VPN_VENDOR": 2, "SCADA_WEB": 1, "FW_PERIM": 6,
            "MAIL_01": 2, "BMS_KEM": 4, "PLC_PS1": 6, "PLC_PS2": 6, "PLC_V1": 5, "PLC_V2": 6, "RTU_F1": 6, "RTU_F2": 6, "RTU_F3": 6}
PLAIN = {
    "observe": "Keep watching (no change)",
    "virtual_patch": "Put a virtual patch in front of {n}",
    "close_link": "Close the {p} link {s} -> {d}",
    "rotate_creds": "Rotate credentials / add MFA for {n}",
    "decoy": "Redirect the attacker into a decoy next to {n}",
    "quarantine": "Isolate {n} from the network",
    "manual_restore": "Send a crew to restore {n} under local manual control",
    "isolate_all": "Isolate the whole network (comparison only)",
}


class Healer:
    def __init__(self, ward, threat, physics):
        self.ward, self.T, self.P = ward, threat, physics
        self.assets, self.edges = ward["assets"], ward["edges"]
        self.allow_decoy = True
        self.force_decoy = False   # experiment E13 only: always place a decoy first

    # ---------------------------------------------------------------- forecasting: where next?
    def next_hops(self, compromised, defence, k=4):
        C = set(compromised) - {"INTERNET"}
        pn = self.T.node_probs(defence)
        pe = self.T.edge_probs(defence)
        out = []
        for i, e in enumerate(self.edges):
            if e["source"] in C and e["target"] not in C:
                p = pe[i] * pn[self.T.idx[e["target"]]]
                if p > 0:
                    out.append(dict(edge=e["id"], src=e["source"], dst=e["target"], p=float(p), technique=e["technique"]))
        tot = sum(o["p"] for o in out) or 1.0
        for o in out:
            o["p"] = round(o["p"] / tot, 3)
        out.sort(key=lambda o: -o["p"])
        return out[:k]

    # ---------------------------------------------------------------- candidates
    @staticmethod
    def _fx(kind, **kw):
        return dict(kind=kind, **kw)

    def candidates(self, comp, defence, physical_done):
        C = set(comp) - {"INTERNET"}
        cands = [self._fx("observe", label=PLAIN["observe"], ops=0.0, events=[])]
        frontier_nodes, frontier_edges = set(), []
        for e in self.edges:
            if e["source"] in C and e["target"] not in C:
                frontier_nodes.add(e["target"])
                frontier_edges.append(e)
        for e in frontier_edges:
            if e["id"] in defence.blocked_edges:
                continue
            cands.append(self._fx("close_link", edge=e["id"], label=PLAIN["close_link"].format(p=e["protocol"].upper(), s=self.assets[e["source"]]["name"], d=self.assets[e["target"]]["name"]),
                                 ops=1.5, events=self._isolation_events({e["source"]}, {e["target"]}, link=True)))
        for n in frontier_nodes:
            a = self.assets[n]
            if a["cve"] and a["virtual_patchable"] and defence.cve_mult.get(n, 1.0) > 0.5:
                cands.append(self._fx("virtual_patch", node=n, label=PLAIN["virtual_patch"].format(n=a["name"]), ops=1.0, events=[]))
            if a["p_weak"] > 0.1 and defence.weak_mult.get(n, 1.0) > 0.5:
                cands.append(self._fx("rotate_creds", node=n, label=PLAIN["rotate_creds"].format(n=a["name"]), ops=1.0, events=[]))
        for n in C:
            a = self.assets[n]
            if self.allow_decoy:
                cands.append(self._fx("decoy", node=n, label=PLAIN["decoy"].format(n=a["name"]), ops=1.0, events=[]))
            if n not in defence.quarantined:
                cands.append(self._fx("quarantine", nodes=[n], label=PLAIN["quarantine"].format(n=a["name"]), ops=OPS_COST.get(n, 2),
                                      events=self._isolation_events({n}, set(), link=False)))
        cl = [n for n in C if self.assets[n]["layer"] in ("iot", "it", "dmz") and n not in defence.quarantined]
        if len(cl) >= 2:
            cands.append(self._fx("quarantine", nodes=sorted(cl), label="Isolate the compromised cluster: " + ", ".join(self.assets[n]["name"] for n in sorted(cl)),
                                  ops=sum(OPS_COST.get(n, 2) for n in cl), events=[]))
        for ph in physical_done:
            cands.append(self._fx("manual_restore", action=ph["action"], kind_phys=ph["kind"], target=ph["target"],
                                  label=PLAIN["manual_restore"].format(n=self.ward["actions"][ph["action"]]["label"].lower()), ops=3.0, events=[]))
        return cands

    @staticmethod
    def _isolation_events(nodes, targets, link):
        """Physical side effects of cutting nodes/links off from SCADA. Only PS2's level logic depends on SCADA (assumption)."""
        touched = set(nodes) | set(targets)
        if (not link and "SCADA_SRV" in nodes) or ("PLC_PS2" in touched and (not link or "SCADA_SRV" in nodes or "SCADA_SRV" in targets)):
            return [dict(kind="pump_duty", target="PS2", start_h=0.0, dur_h=ISOLATION_H)]
        return []

    # ---------------------------------------------------------------- scoring
    def apply(self, cand, defence, init):
        d = defence.copy()
        init = set(init)
        k = cand["kind"]
        if k == "close_link":
            d.blocked_edges.add(cand["edge"])
        elif k == "virtual_patch":
            d.cve_mult[cand["node"]] = d.cve_mult.get(cand["node"], 1.0) * (1 - VP_EFFICACY)
        elif k == "rotate_creds":
            d.weak_mult[cand["node"]] = d.weak_mult.get(cand["node"], 1.0) * 0.1
        elif k == "decoy":
            for e in self.edges:   # a decoy next to the attacker draws about half of its next moves away
                if e["source"] == cand["node"] and e["target"] not in init:
                    d.edge_mult[e["id"]] = d.edge_mult.get(e["id"], 1.0) * 0.5
        elif k == "quarantine":
            for n in cand["nodes"]:
                d.quarantined.add(n)
            init -= set(cand["nodes"])
        return d, init

    def score(self, cands, defence, comp, hour, n=900):
        b = int(round(hour / 3.0)) % 8
        rep = ASSUMPTIONS["repair_h"]
        rows = []
        for c in cands:
            d, init = self.apply(c, defence, comp if comp else {"INTERNET"})
            rem = float(self.T.evaluate(d, init=init, n=n, start=b)["L"].mean())
            if c["kind"] == "manual_restore":
                act = self.ward["actions"][c["action"]]
                full = self.P.loss([dict(kind=act["kind"], target=act["target"], start_h=hour, dur_h=rep[act["repair"]])])["L"]
                short = self.P.loss([dict(kind=act["kind"], target=act["target"], start_h=hour, dur_h=0.75)])["L"]
                ben = full - short
                rows.append(dict(c, remaining=rem - ben, service=0.0, ops=c["ops"] * OPS_UNIT, J=rem - ben + c["ops"] * OPS_UNIT, benefit_restore=round(ben, 1)))
                continue
            svc = 0.0
            if c["events"]:
                svc = float(self.P.loss([dict(e, start_h=hour) for e in c["events"]])["L"])
            rows.append(dict(c, remaining=rem, service=svc, ops=c["ops"] * OPS_UNIT, J=rem + svc + c["ops"] * OPS_UNIT))
        rows.sort(key=lambda r: r["J"])
        return rows

    def isolate_all_cost(self, hour):
        ev = [dict(kind="pump_duty", target="PS1", start_h=hour, dur_h=ISOLATION_H), dict(kind="pump_duty", target="PS2", start_h=hour, dur_h=ISOLATION_H)]
        svc = float(self.P.loss(ev)["L"])
        ops = sum(OPS_COST.values()) * OPS_UNIT
        return dict(kind="isolate_all", label=PLAIN["isolate_all"], service=svc, ops=ops, remaining=0.0, J=svc + ops)

    def safety_check(self, cand, hour, active=None):
        """Re-simulate the action's own physical effect TOGETHER with outages already in progress, then test hard constraints."""
        if not cand.get("events"):
            return dict(ok=True, note="No physical effect on water or power.", hosp_h=0.0, loss=0.0)
        act = [dict(a, start_h=hour) for a in (active or [])]
        base = self.P.loss(act)["hosp_water_h"] if act else 0.0
        r = self.P.loss(act + [dict(e, start_h=hour) for e in cand["events"]])
        added = r["hosp_water_h"] - base
        ok = added <= 0.01 and r["hosp_power_h"] <= (self.P.loss(act)["hosp_power_h"] if act else 0.0)
        note = ("Hospital pressure and grid limits stay inside safe limits, also with the outage already in progress." if ok
                else "BLOCKED: together with the outage already in progress this action would push a hospital below its minimum water pressure.")
        return dict(ok=ok, note=note, hosp_h=added, loss=r["L"])

    def decide(self, comp, defence, hour, physical_done, n=900, max_steps=4):
        """Greedy containment plan: keep adding the best safe action while it lowers the total expected cost."""
        cur_def, cur_comp, todo = defence.copy(), set(comp), list(physical_done)
        rep = ASSUMPTIONS["repair_h"]
        active = [dict(kind=ph["kind"], target=ph["target"], dur_h=rep[self.ward["actions"][ph["action"]]["repair"]]) for ph in physical_done]
        steps, first_table, extra, blocked = [], None, 0.0, []
        observe0 = None
        if self.force_decoy:
            for n in sorted(cur_comp - {"INTERNET"})[:2]:
                c = self._fx("decoy", node=n, label=PLAIN["decoy"].format(n=self.assets[n]["name"]), ops=1.0, events=[])
                row = self.score([c], cur_def, cur_comp, hour, n=600)[0]
                row["safety"] = dict(ok=True, note="No physical effect.")
                steps.append(row); extra += row["service"] + row["ops"]
                cur_def, _ = self.apply(row, cur_def, cur_comp)
        for _ in range(max_steps):
            cands = self.candidates(cur_comp, cur_def, todo)
            rows = self.score(cands, cur_def, cur_comp, hour, n)
            if first_table is None:
                first_table = rows[:8]
            observe = next(r for r in rows if r["kind"] == "observe")
            if observe0 is None:
                observe0 = observe
            pick = None
            for r in rows:
                if r["kind"] == "observe":
                    continue
                s_ = self.safety_check(r, hour, active)
                r["safety"] = s_
                if s_["ok"]:
                    pick = r
                    break
                blocked.append(r)
            if pick is None or pick["J"] >= observe["J"] * 0.97 - 1.0:
                break
            steps.append(pick)
            extra += pick["service"] + pick["ops"]
            cur_def, init = self.apply(pick, cur_def, cur_comp)
            cur_comp = set(init) if pick["kind"] == "quarantine" else cur_comp
            if pick["kind"] == "manual_restore":
                todo = [t for t in todo if t["action"] != pick["action"]]
        remaining = float(self.T.evaluate(cur_def, init=cur_comp, n=n, start=int(round(hour / 3.0)) % 8)["L"].mean()) if steps else observe0["remaining"]
        total = remaining + extra
        return dict(steps=steps, chosen=steps[0] if steps else None, observe=observe0, table=first_table, blocked=blocked[:3], isolate_all=self.isolate_all_cost(hour),
                    plan_J=total, plan_remaining=remaining, plan_extra=extra, defence=cur_def)
