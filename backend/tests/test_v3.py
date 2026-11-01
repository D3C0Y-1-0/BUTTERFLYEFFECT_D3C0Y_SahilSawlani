"""v3 behaviour: varied attack entry points, factor-based scheduling, a real insider, emergency stop / resume, graceful heartbeat, clear fix errors, forecast, sites."""
import time

import pyotp
import pytest
from fastapi.testclient import TestClient

from decoy import api


@pytest.fixture(scope="module")
def client():
    with TestClient(api.app) as c:
        auth = api.state["auth"]
        hint = {a["user"]: a for a in auth.hint()}

        def tok(u):
            r = c.post("/api/auth/login", json=dict(username=u, password=hint[u]["password"], totp=pyotp.TOTP(auth.users[u]["totp"]).now()))
            assert r.status_code == 200, r.text
            return {"Authorization": "Bearer " + r.json()["token"]}

        c.adm, c.ope = tok("admin"), tok("operator")
        rt = api.state["rt"]
        rt.autopilot = False
        rt.reset()
        rt.refresh_analytics(with_voi=False)
        for _ in range(120):
            if api.state["lab"].ready():
                break
            time.sleep(0.5)
        yield c


def test_attack_paths_show_more_than_one_entry_point(client):
    paths = api.state["rt"].analytics["paths"]
    entries = {p["nodes"][1] for p in paths}
    assert len(entries) >= 4, entries


def test_random_attacks_do_not_all_enter_through_one_door():
    adv = api.state["rt"].adv
    seen = {}
    for _ in range(80):
        c = adv.launch(0, mode="standard")
        seen[c.entry] = seen.get(c.entry, 0) + 1
    assert len(seen) >= 6 and max(seen.values()) / 80 < 0.35, seen


def test_insider_starts_inside_without_an_internet_hop(client):
    c = api.state["rt"].adv.launch(0, mode="insider")
    a = api.state["rt"].ward["assets"][c.entry]
    assert a["exposure"] != "internet" and c.entry in c.compromised


def test_schedule_is_computed_not_a_fixed_weekend(client):
    sched = api.state["rt"].analytics["schedule"]
    assert sched and all("when" in r and "severity" in r and "reason" in r for r in sched)
    assert len({(r["day"], r["week"]) for r in sched}) > 1          # not one single slot for everything
    assert not all(r["day"] == "Sunday" for r in sched)
    # urgency: the most valuable no-restart fix is never scheduled after a much less valuable one in the same week
    first = [r for r in sched if r["week"] == 1 and r["no_outage"]]
    assert first == sorted(first, key=lambda r: (r["day_index"], -r["gain"]))


def test_restart_fixes_avoid_the_busiest_slots():
    from decoy.planner import Planner
    rt = api.state["rt"]
    fw = [f for f in rt.planner.catalog if f.type == "firmware_patch" and f.events(0)]
    assert fw, "catalogue should contain a restart fix"
    f = fw[0]
    best = rt.planner.best_slot(f)
    assert best[0] <= rt.planner.dt_cached(f, 14.0)           # the chosen hour is never worse than mid-afternoon


def test_emergency_stop_halts_attacks_and_resume_restores(client):
    r = client.post("/api/attack", json=dict(mode="standard"), headers=client.adm)
    assert r.status_code == 200
    s = client.post("/api/freeze", headers=client.ope).json()
    assert s["stopped"] and s["halted"] >= 1
    rt = api.state["rt"]
    assert rt.autopilot is False and rt.autonomy == "suggest" and not rt.adv.active()
    assert api.state["rt"].snapshot("admin")["stopped"] is True
    assert client.post("/api/resume", headers=client.ope).json()["stopped"] is False
    rt.autopilot = False


def test_fix_twice_gives_a_plain_409_not_a_404(client):
    rt = api.state["rt"]
    fid = rt.analytics["plan"]["steps"][0]["fix"]["id"]
    assert client.post("/api/fix", json=dict(id=fid), headers=client.ope).status_code == 200
    r = client.post("/api/fix", json=dict(id=fid), headers=client.ope)
    assert r.status_code == 409 and "Already done" in r.json()["detail"]
    assert client.post("/api/fix", json=dict(id="zz:nothing"), headers=client.ope).status_code == 409


def test_heartbeat_fades_once_the_attacker_is_cut_off():
    rt = api.state["rt"]
    rt.reset(); rt.autopilot = False
    rt.last_p = 0.9
    inc = dict(id="INC-T", status="open", stages=[dict(stage="Detected", minute=rt.live.minute - 40), dict(stage="Cut made", minute=rt.live.minute - 30)], evidence_nodes=[], t0=0)
    rt.incidents.append(inc)
    hb = rt._heartbeat()
    assert hb["raw"] == 0.9 and hb["shown"] < 0.1 and hb["phase"] == "healing" and "cut off" in hb["note"]
    rt.incidents.clear()


def test_decoy_can_be_placed_once_per_device(client):
    r = client.post("/api/decoy", json=dict(node="HIST_01"), headers=client.ope)
    assert r.status_code == 200 and r.json()["attached_to"] == "HIST_01"
    assert client.post("/api/decoy", json=dict(node="HIST_01"), headers=client.ope).status_code == 422
    assert client.post("/api/decoy", json=dict(node="NOPE"), headers=client.ope).status_code == 422


def test_forecast_lists_likely_targets_with_accuracy(client):
    r = client.get("/api/v2/forecast?top=5", headers=client.adm)
    assert r.status_code == 200, r.text
    j = r.json()
    assert len(j["items"]) == 5 and j["items"] == sorted(j["items"], key=lambda x: -x["likelihood"])
    assert -1 <= j["accuracy"]["spearman"] <= 1 and j["accuracy"]["top5_overlap"] is not None


def test_sites_are_part_of_the_ward_with_dependencies(client):
    ward = api.state["rt"].ward
    sites = [p for p in ward["physical"].values() if p["kind"] == "site"]
    assert len(sites) >= 10 and any(s["priority"] == "critical" and "BARC" in s["name"] for s in sites)
    assert all(d in ward["assets"] for s in sites for d in s["depends_on"])
    assert {s["sector"] for s in sites} >= {"nuclear", "it_hub", "factory", "hospital", "tourist"}


def test_impact_gives_people_hours_and_money_for_any_device(client):
    r = client.get("/api/v2/impact?node=PLC_PS1&start=6", headers=client.adm)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["people"] > 0 and j["hours"] > 0 and j["money_inr"] > 0 and j["assumption"]
    quiet = client.get("/api/v2/impact?node=CCTV_01&start=6", headers=client.adm).json()
    assert quiet["people"] <= j["people"]
    assert client.get("/api/v2/impact?node=NOPE_NODE", headers=client.adm).status_code == 404


def test_better_forecast_model_beats_the_old_numbers(client):
    meta = api.state["lab"].state["meta"]
    assert meta["spearman_heldout"] >= 0.88 and meta["top5_overlap_heldout"] >= 0.68 and meta["mae_heldout"] <= 0.017, meta


def test_roads_and_rail_are_served_for_the_map(client):
    g = client.get("/api/geo", headers=client.adm).json()
    kinds = {w["k"] for w in g["roads"]["ways"]}
    assert "rail" in kinds and "primary" in kinds and len(g["roads"]["ways"]) > 1000


def test_ddos_flood_is_dropped_at_the_edge_without_touching_control():
    rt = api.state["rt"]
    rt.reset(4000); rt.autonomy, rt.autopilot = "auto_all", False
    rt.launch_attack("ddos", None, None, None, actor="test")
    for _ in range(120):
        rt.tick()
    c = [x for x in rt.adv.campaigns if x.mode == "ddos"][0]
    assert c.flood_minutes > 30 and c.flood_open <= 0.15 * c.flood_minutes, (c.flood_open, c.flood_minutes)
    assert rt.live.loss_composite() == 0
    assert any(a["actor"] == "athena:flood-guard" for i in rt.incidents for a in i["actions"])


def test_coordinated_group_launches_several_attackers_and_service_survives():
    rt = api.state["rt"]
    rt.reset(4001); rt.autonomy, rt.autopilot = "auto_all", False
    rt.launch_attack("group", None, None, None, actor="test")
    assert len(rt.adv.campaigns) == 4
    for _ in range(200):
        rt.tick()
    assert rt.incidents and rt.live.loss_composite() <= rt.none.loss_composite()
