"""Standing defence chosen BEFORE any attack, from the forecast: harden the few devices that sit on the most attack routes to the plant controllers.
Hardening = a virtual patch on the device's known weakness plus MFA / credential rotation on its remote access. Both are reversible and need no downtime, so they are safe to
run without waiting for an alarm. Chosen greedily: each pick is the device whose hardening lowers the chance that an attacker reaches any controller the most, given the picks so far.
Honest limit: the effect is measured against our own simulated attacker; real attackers adapt."""
from __future__ import annotations

import hashlib
import json

from .city import DATA
from .lab import RULES
from .threat import Defence, VP_EFFICACY

K_DEFAULT = 9


def _key(ward, k):
    blob = json.dumps(["v2", sorted((a, v["cve"], v["p_weak"], v["entry_weight"]) for a, v in ward["assets"].items()), sorted((e["id"], e["source"], e["target"], e["p_access"]) for e in ward["edges"]), k], default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _apply(d: Defence, ward, node):
    a = ward["assets"][node]
    if a["cve"] and a["virtual_patchable"]:
        d.cve_mult[node] = d.cve_mult.get(node, 1.0) * (1 - VP_EFFICACY)
    if a["p_weak"] > 0:
        d.weak_mult[node] = d.weak_mult.get(node, 1.0) * RULES["mfa_factor"]


def choose(ward, T, k=K_DEFAULT, n=700):
    f = DATA / "posture.json"
    key = _key(ward, k)
    try:
        c = json.loads(f.read_text())
        if c.get("key") == key:
            return c["nodes"]
    except (OSError, ValueError):
        pass
    cands = [x for x, a in ward["assets"].items() if x != "INTERNET" and ((a["cve"] and a["virtual_patchable"]) or a["p_weak"] > 0) and a["layer"] != "field"]
    d, picked = Defence(), []
    inside = [x for x, a in ward["assets"].items() if a["layer"] in ("it", "dmz", "control") and a["exposure"] != "internet"][:6]     # where an insider could start

    def score(dd):    # 60%: attacker from the internet; 40%: insider already inside. Both are chances of reaching ANY plant controller.
        ext = float(T.reach(dd, n=n)[0][:, T.ctrl_idx].any(1).mean())
        ins = float(sum(T.reach(dd, init=[h], n=n // 2)[0][:, T.ctrl_idx].any(1).mean() for h in inside) / max(1, len(inside)))
        return 0.6 * ext + 0.4 * ins
    cur = score(d)
    for _ in range(k):
        best, bs = None, cur
        for v in cands:
            if v in picked:
                continue
            t = d.copy()
            _apply(t, ward, v)
            s = score(t)
            if s < bs - 1e-4:
                best, bs = v, s
        if best is None:
            break
        _apply(d, ward, best)
        picked.append(best)
        cur = bs
    try:
        f.write_text(json.dumps(dict(key=key, nodes=picked, risk_after=round(cur, 4))))
    except OSError:
        pass
    return picked


def apply_to(defence: Defence, ward, nodes):
    for v in nodes:
        _apply(defence, ward, v)
        defence.fixes.append(f"standing: hardened {ward['assets'][v]['name']} in advance (forecast)")
