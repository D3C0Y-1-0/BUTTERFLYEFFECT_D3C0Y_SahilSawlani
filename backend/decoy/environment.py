"""ENVIRONMENT: the network and the physical world, where the two sides meet. It is the only thing the attacker and the defender share, and neither can
look inside the other.

* The attacker asks it to try a link or issue a command and is told what happened (ok / failed / refused / decoy).
* The defender's actions (cut a link, quarantine a device, patch, shield, decoy) are stored here as plain facts about the network. The environment applies
  them when it resolves an attempt, the way a real firewall would drop a packet. It never tells the attacker "a defence exists".
* Everything the defender learns comes out of here as ordinary observations: traffic counts and telemetry. It never receives the attacker's identity,
  mode, route, goal or state.
"""
from __future__ import annotations

from .assumptions import A

import numpy as np


class Environment:
    def __init__(self, ward, threat, defence=None, decoys=None, refuse_all=None, seed=0):
        self.ward, self.T = ward, threat
        self._defence = defence or (lambda: None)
        self._decoys = decoys or (lambda: {})
        self._refuse_all = refuse_all or (lambda: False)
        self.rng = np.random.default_rng(seed + 9)
        self.edge = {e["id"]: e for e in ward["edges"]}

    # ---- what an attacker can learn by scanning (an undefended network): used only for its own planning
    def recon(self):
        return self.T.node_probs(None).copy(), self.T.idx

    # ---- does this link currently carry traffic?
    def blocked(self, e):
        if self._refuse_all():
            return True
        d = self._defence()
        return bool(d is not None and (e["id"] in d.blocked_edges or e["source"] in d.quarantined or e["target"] in d.quarantined))

    def attempt_hop(self, c, e, minute):
        """The attacker tries to cross link e. Returns {outcome, flows, events}; the attacker sees only the outcome."""
        if self.blocked(e):
            return dict(outcome="refused", flows=[], events=[])
        d = self._defence()
        decoys = self._decoys()
        if decoys:
            near = [x for x in decoys.values() if x["attached_to"] in c.compromised]
            if near and self.rng.random() < A("decoy_lure_p"):
                x = near[0]
                trapped = bool(self.rng.random() < A("decoy_trap_p"))
                ev = [dict(type="decoy_touch", campaign=c.id, minute=minute, decoy=x["id"], text=f"Decoy {x['id']} touched from {x['attached_to']}")]
                if trapped:
                    ev.append(dict(type="attack_blocked", campaign=c.id, minute=minute, text=f"{c.id}: trapped in a decoy"))
                return dict(outcome="decoy", decoy=x["id"], trapped=trapped, flows=[(f"DECOY:{x['id']}", "read", 25)], events=ev)
        tgt = e["target"]
        pe = e["p_access"] * (d.edge_mult.get(e["id"], 1.0) if d else 1.0)
        if c.zd is not None and tgt in c.zd.affected:
            pn = min(0.95, c.zd.p * (d.zd_mult.get(tgt, 1.0) if d else 1.0))
        else:
            pn = float(self.T.node_probs(d)[self.T.idx[tgt]])
        return dict(outcome="ok" if self.rng.random() < pe * pn else "failed", flows=[], events=[])

    def attempt_command(self, c):
        """The attacker, now on the last device, issues its physical command. Refused if that controller was cut off or its link is closed."""
        if self._refuse_all():
            return False
        d = self._defence()
        if d is None:
            return True
        if c.goal in d.quarantined:
            return False
        last = c.hops[-1][1] if c.hops else None
        return not (last and last in d.blocked_edges)

    def deliver(self, flows):
        """Traffic on a closed link never arrives: drop it before anything can observe it."""
        kept = []
        for f in flows:
            e = self.edge.get(f[0])
            if e is not None and self.blocked(e):
                continue
            kept.append(f)
        return kept
