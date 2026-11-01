"""Regression tests for the weaknesses found in the external review: forged traffic, log tamper-evidence, air-gap replay, unbounded growth, honest security page."""
import json
import time

import numpy as np
import pytest

from decoy.blackbox import BlackBox
from decoy.runtime import Runtime
from decoy.security import AirGap, RateLimiter


# ------------------------------------------------------------------ flaw 3: forged traffic must not be able to switch off the hospital by itself
@pytest.fixture(scope="module")
def rt():
    return Runtime(sync=True, n_samples=1500, verbose=False)


def test_forged_traffic_cannot_auto_cut_hospital_equipment(rt):
    rt.reset(31)
    rt.autonomy, rt.autopilot = "auto_all", False
    eid = next(e["id"] for e in rt.ward["edges"] if e["source"] == "VPN_VENDOR" and e["target"] == "BMS_KEM")
    m0 = rt.live.minute
    forged = lambda m, env: ([(eid, "read", 140)] if m0 + 30 <= m <= m0 + 120 else [], [], [])    # someone replays heavy traffic on that one link; no host is compromised
    rt.adv.tick = forged
    for _ in range(300):
        rt.tick()
    cut = {n for i in rt.incidents for a in i["actions"] for n in (a["target"].get("nodes") or []) + [a["target"].get("node")] if n}
    sens = rt._sensitive_nodes()
    assert rt.incidents, "the forged traffic should at least raise an alarm"
    assert any(p.get("held") for p in rt.proposals), "the cut must be held for a person"
    assert not (cut & sens), f"auto-cut hospital-adjacent: {cut & sens}"
    assert not (set(rt.defence.blocked_edges) & {eid}), "the hospital link was closed automatically"
    assert "BMS_KEM" not in rt.defence.quarantined


def test_automatic_steps_are_rate_limited(rt):
    rt.reset(32)
    m = rt.live.minute
    rt.auto_log.extend([m] * rt.AUTO_MAX)
    why = rt._auto_guard(dict(physics=[], evidence_nodes=["INTERNET", "A"]), [dict(kind="virtual_patch", service=0, target={})])
    assert why and "rate limit" in why


# ------------------------------------------------------------------ flaw 6: log tamper-evidence
def test_rehashed_chain_is_detected_without_the_key():
    bb = BlackBox(key=b"k" * 32)
    for i in range(40):
        bb.append("e", dict(i=i))
    r = bb.tamper_demo()
    assert r["before"]["ok"] and not r["after"]["ok"] and not r["rehashed"]["ok"]


def test_log_persists_and_tail_removal_is_caught(tmp_path):
    kw = dict(persist=True, key=b"s" * 32, anchor_path=tmp_path / "anchor.jsonl", log_dir=tmp_path / "log")
    a = BlackBox(**kw)
    for i in range(130):
        a.append("e", dict(i=i))
    b = BlackBox(**kw)                      # a restart continues the same chain
    assert b.count == 130 and b.head == a.head and b.verify(full=True)["ok"]
    b.append("e", dict(i=130))
    assert BlackBox(**kw).verify(full=True)["ok"]
    f = tmp_path / "log" / "log.jsonl"      # an intruder with disk access deletes the last 60 entries
    f.write_text("".join(f.read_text().splitlines(True)[:70]))
    c = BlackBox(**kw)
    assert not c.verify(full=True)["ok"]


def test_forged_entry_with_wrong_key_rejected(tmp_path):
    a = BlackBox(key=b"a" * 32)
    for i in range(5):
        a.append("e", dict(i=i))
    other = BlackBox(key=b"b" * 32)
    assert not other.verify_entries(list(a.entries), {})["ok"]


# ------------------------------------------------------------------ flaw 7: replay after restart
def test_airgap_counter_survives_restart(tmp_path):
    g = AirGap(key_dir=tmp_path)
    doc = g.export(dict(x=1))
    assert g.verify_import(doc)[0]
    g2 = AirGap(key_dir=tmp_path)           # restart
    ok, msg = g2.verify_import(doc)
    assert not ok and "replay" in msg
    assert g2.version == 1                  # the next export continues, it does not restart at 1


# ------------------------------------------------------------------ flaw 10: growth is bounded
def test_rate_limiter_table_is_capped_and_expires():
    rl = RateLimiter(rate=25, burst=80, max_clients=1000)
    for i in range(20000):
        rl.allow(f"10.0.{i // 250}.{i % 250}")
    assert len(rl.b) <= 1000 + 500       # swept every 500 calls
    assert rl.evicted > 0


def test_log_memory_window_is_capped_and_verify_is_incremental():
    bb = BlackBox(key=b"k" * 32)
    for i in range(12000):
        bb.append("e", dict(i=i))
    assert len(bb.entries) == 5000 and bb.count == 12000
    assert bb.verify()["ok"]
    bb.append("e", {})
    t0 = time.time()
    r = bb.verify()
    assert r["ok"] and r["checked"] == 1 and r["incremental"] and time.time() - t0 < 0.2


# ------------------------------------------------------------------ flaw 4: a coherent telemetry spoof needs an independent path to be seen early
def _first_physics_alarm(rt, use_independent, seed=41):
    rt.reset(seed)
    rt.autonomy, rt.autopilot = "suggest", False
    rt.watchdog.use_independent = use_independent
    rt.launch_attack("spoof_coherent", "SCADA_WEB", "PLC_PS1", 9, actor="test")
    t0 = rt.live.minute
    for _ in range(14 * 60):
        rt.tick()
        if any(i["physics"] for i in rt.incidents):
            return rt.live.minute - t0
    return None


def test_coherent_spoof_is_caught_early_only_with_the_independent_path(rt):
    with_path = _first_physics_alarm(rt, True)
    without = _first_physics_alarm(rt, False)
    rt.watchdog.use_independent = True
    assert with_path is not None and with_path <= 120
    assert without is None or without > 3 * with_path


def test_independent_path_adds_no_false_alarm_on_a_calm_day(rt):
    rt.reset(55)
    rt.autonomy, rt.autopilot = "auto_low", False
    for _ in range(12 * 60):
        rt.tick()
    assert not rt.incidents


# ------------------------------------------------------------------ decoys: a lone touch is an alarm, not permission to cut
def test_lone_decoy_touch_waits_for_a_person(rt):
    rt.reset(61)
    inc = dict(physics=[], evidence_nodes=["INTERNET", "FW_PERIM"], decoy_only=True)
    why = rt._auto_guard(inc, [dict(kind="quarantine", service=0, target=dict(nodes=["FW_PERIM"]))])
    assert why and "scanner" in why
    inc["decoy_only"] = False
    assert rt._auto_guard(inc, [dict(kind="quarantine", service=0, target=dict(nodes=["FW_PERIM"]))]) is None


def test_decoy_probabilities_live_with_the_other_assumptions():
    from decoy.assumptions import ASSUMPTIONS
    assert {"decoy_lure_p", "decoy_trap_p", "decoy_alarm_p"} <= set(ASSUMPTIONS)
