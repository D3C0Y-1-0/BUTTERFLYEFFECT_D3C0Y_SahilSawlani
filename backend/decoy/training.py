"""TRAINING HARNESS (not part of the defence). Generates labelled episodes (normal days, and days with a simulated attacker) to fit the Watchdog's fusion
and to calibrate its slow-build-up line. The defence code (watchdog.py) never imports the attacker; only this harness does, and what the Watchdog learns
here is ordinary labelled data, exactly what a real deployment would get from past incident records."""
from __future__ import annotations

import numpy as np

from .adversary import Adversary
from .environment import Environment
from .twin import LiveTwin
from .watchdog import CS_H_ADD, CS_H_MUL, CS_K_SD, Traffic, Watchdog


# (daily swing, burstiness k, peak hour): plain Poisson, a daily swing, burstier, both. Training on all of them is what lets the detector cope with traffic that is not textbook.
REGIMES = [(0.0, None, 14.0), (0.35, None, 14.0), (0.0, 3.0, 14.0), (0.6, 2.0, 11.0), (0.2, 6.0, 17.0), (0.0, None, 14.0)]


def build_watchdog(ward, threat, seed=0, episodes=48, verbose=False):
    """Train the fusion model on labelled simulated episodes (normal vs each attack mode)."""
    tr = Traffic(ward, seed=seed + 11)
    wd = Watchdog(ward, tr, seed=seed)
    rng = np.random.default_rng(seed + 5)
    X, y, calm = [], [], {}
    modes = ["standard", "zero_day", "spoof", "wear", "insider", "swarm"]
    for ep in range(episodes):
        tw = LiveTwin(ward, seed=seed + ep)
        for _ in range(90):
            tw.step()
        wd.reset_state()
        tr.set_regime(*REGIMES[ep % len(REGIMES)])
        adv = Adversary(ward, seed=seed + 100 + ep)
        env = Environment(ward, threat, seed=seed + 200 + ep)
        attack = ep % 3 != 0  # one third pure normal
        mode = modes[(ep // 3) % len(modes)] if attack else "none"
        if attack and mode == "swarm":      # several very quiet attackers at once, at different doors
            doors = [n for n, a_ in ward["assets"].items() if a_["entry_weight"] > 0]
            for d_ in rng.choice(doors, size=5, replace=False):
                c_ = adv.launch(tw.minute, mode="standard", entry=str(d_), stealth=0.8, goal=str(rng.choice([c for c in adv.goals])))
                c_.quiet = True
            camp = adv.campaigns[0]
        else:
            camp = adv.launch(tw.minute, mode=mode, stealth=float(rng.uniform(1.5, 8.0)), goal=str(rng.choice([c for c in adv.goals]))) if attack else None
        started_phys = False
        for k in range(260):
            minute = tw.minute
            flows, phys, evs = adv.tick(minute, env) if attack else ([], [], [])
            for ph in phys:
                if ph["kind"] == "wear":
                    tw.breaker_cycle()
                    continue
                tw.act(ph["kind"], ph["target"], ph["dur_min"])
                started_phys = True
                if mode == "spoof":
                    tag = {"pump_off": f"{ph['target']}_", }.get(ph["kind"])
                    if ph["kind"] == "pump_off":
                        p = ph["target"]
                        tw.spoof[f"{p}_state"] = 1.0
                        tw.spoof[f"{p}_flow"] = lambda rep: 0.21
                    elif ph["kind"] == "breaker_open":
                        tw.spoof[f"CB_{ph['target']}"] = 1.0
                if ph["kind"] in ("valve_close", "breaker_open", "hospital_isolate") and mode != "spoof":
                    pass
            tele = tw.step()
            counts = tr.normal(minute)
            decoy = tr.add(counts, flows)
            res = wd.observe(counts, tele, minute, decoy)
            label = 1 if (attack and (adv.active() or (started_phys and any(v > tw.minute for v in list(tw.forced_off.values()) + list(tw.breaker_open.values()) + list(tw.valve_closed.values()))))) else 0
            if k > 5:
                X.append(res["features"]); y.append(label)
                if not attack:
                    calm.setdefault(ep, []).append(res["features"])
    X, y = np.array(X), np.array(y)
    wd.fit_fusion(X, y)
    # CUSUM line: calibrated on the attack-free episodes only, with a safety margin, so a calm city does not cross it
    zs = [wd.fusion.decision_function(np.array(v))for v in calm.values()]
    allz = np.concatenate(zs); wd.cs_k = float(allz.mean() + CS_K_SD * allz.std()); mx = 0.0
    for z in zs:
        s_ = 0.0
        for v in z:
            s_ = max(0.0, 0.97 * s_ + float(v) - wd.cs_k); mx = max(mx, s_)
    wd.cs_h = mx * CS_H_MUL + CS_H_ADD
    tr.set_regime()
    wd.reset_state()
    return wd, tr, (X, y)
