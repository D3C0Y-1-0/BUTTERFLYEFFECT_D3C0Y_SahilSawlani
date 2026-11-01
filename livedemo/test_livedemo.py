"""No-network tests for the live-demo brain: synthetic packet windows go in, decisions come out. Run: python -m pytest livedemo -q"""
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from engine import Engine  # noqa: E402
from flowdetect import new_window  # noqa: E402

ME, GW, ATT = "192.168.43.20", "192.168.43.1", "192.168.43.77"


def calm(rng):
    w = new_window()
    for _ in range(rng.poisson(0.3)):
        w["flows"][(GW, 5353, "udp")] += 1; w["total"] += 1                       # a steady known flow
    if rng.random() < 0.08:                                                      # an occasional stray packet from a neighbour
        w["flows"][(f"192.168.43.{int(rng.integers(2, 200))}", 5353, "udp")] += 1; w["total"] += 1
    return w


def start(learn=90, seed=0):
    rng = np.random.default_rng(seed)
    e = Engine(local_ips=[ME], gateway=GW, dry_run=True, learn_windows=learn)
    t = 1000.0
    for _ in range(learn):
        e.process(calm(rng), t); t += 1
    return e, rng, t


def attack_window(rng, kind, pps, blocked, att=ATT):
    w = calm(rng)
    if kind == "syn":
        w["flows"][(att, 8080, "tcp")] += pps; w["syn"] += pps; w["total"] += pps
    elif kind == "http":
        w["flows"][(att, 8080, "tcp")] += pps; w["total"] += pps; w["data"] += pps; w["syn"] += max(1, pps // 10)
    elif kind == "scan":
        for p in rng.choice(np.arange(1, 5000), size=min(pps, 200), replace=False):
            w["flows"][(att, int(p), "tcp")] += 1
        w["syn"] += min(pps, 200); w["total"] += min(pps, 200)
    w["replies"][att] = 0 if blocked else int(pps * 0.9)
    return w


def run(e, rng, t, kind, secs=40, pps=120, att=ATT):
    for _ in range(secs):
        e.process(attack_window(rng, kind, pps, att in e.fw.rules, att), t); t += 1
    return t


def stages(e):
    return [x["stage"] for x in e.events]


def test_baseline_learned_and_calm_day_is_quiet():
    e, rng, t = start()
    assert "BASELINE_LEARNED" in stages(e)
    for _ in range(900):
        e.process(calm(rng), t); t += 1
    assert "DETECTED" not in stages(e)


def test_syn_flood_detected_predicted_rate_limited_then_blocked_and_verified():
    e, rng, t = start()
    run(e, rng, t, "syn")
    s = stages(e)
    for need in ("DETECTED", "PREDICTED", "ACTION", "ESCALATE", "VERIFIED"):
        assert need in s, (need, s)
    assert s.index("DETECTED") < s.index("PREDICTED") < s.index("ESCALATE") < s.index("VERIFIED")
    d = next(x for x in e.events if x["stage"] == "DETECTED")
    assert f"source={ATT}" in d["text"] and "SYN flood" in d["text"]
    assert d["t"] - 1000.0 - 90 <= 4                      # alarm within 4 seconds of the first attack window
    assert ATT in e.fw.rules and e.limiter.limits.get(ATT)
    assert next(x for x in e.events if x["stage"] == "VERIFIED")["text"].count("replies_sent_to_source=0") == 1


def test_request_burst_and_port_scan_are_classified_differently():
    e, rng, t = start(seed=1)
    run(e, rng, t, "http", secs=15)
    assert "request burst" in next(x for x in e.events if x["stage"] == "DETECTED")["text"]
    e2, rng2, t2 = start(seed=2)
    run(e2, rng2, t2, "scan", secs=15, pps=150)
    assert "port scan" in next(x for x in e2.events if x["stage"] == "DETECTED")["text"]


def test_rate_limit_alone_is_enough_when_the_source_backs_off():
    e, rng, t = start(seed=3)
    for _ in range(4):
        e.process(attack_window(rng, "http", 120, False), t); t += 1
    assert e.inc is not None
    for _ in range(14):                                    # the source slows right down once limited
        e.process(attack_window(rng, "http", 1, False), t); t += 1
    assert "VERIFIED" in stages(e) and ATT not in e.fw.rules and "ESCALATE" not in stages(e)


def test_never_blocks_a_public_address_this_laptop_or_the_gateway():
    for bad in ("8.8.8.8", ME, GW):
        e, rng, t = start(seed=4)
        run(e, rng, t, "syn", secs=25, att=bad)
        assert bad not in e.fw.rules, bad
        assert "SUGGEST" in stages(e), (bad, stages(e))


def test_traffic_from_a_blocked_source_is_not_judged_again():
    e, rng, t = start(seed=5)
    t = run(e, rng, t, "syn", secs=30)
    assert ATT in e.fw.rules
    assert stages(e).count("DETECTED") == 1
