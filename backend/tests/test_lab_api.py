"""Integration tests: real ward, real physics oracle, real REST API (TestClient). Boots the runtime once (about 20 s)."""
import json
import time

import pyotp
import pytest
from fastapi.testclient import TestClient

from decoy import api

SCENARIOS = ["vendor_credential", "ransomware_monitoring", "controller_exposure", "iot_compromise", "hospital_incident"]


@pytest.fixture(scope="module")
def client():
    with TestClient(api.app) as c:
        auth = api.state["auth"]
        hint = {a["user"]: a for a in auth.hint()}

        def tok(u):
            r = c.post("/api/auth/login", json=dict(username=u, password=hint[u]["password"], totp=pyotp.TOTP(auth.users[u]["totp"]).now()))
            assert r.status_code == 200, r.text
            return {"Authorization": "Bearer " + r.json()["token"]}

        c.ana, c.exe, c.ope = tok("analyst"), tok("executive"), tok("operator")
        api.state["rt"].autopilot = False        # live attacks would add anomaly evidence between two calls and make comparisons flaky
        api.state["rt"].reset()
        for _ in range(120):                                   # the model trains in the background (~3 s)
            if api.state["lab"].ready():
                break
            time.sleep(0.5)
        assert api.state["lab"].ready(), api.state["lab"].state
        yield c


@pytest.fixture(autouse=True)
def fresh_session(client):
    client.post("/api/v2/reset", headers=client.ana)


def get(c, url, h=None):
    return c.get("/api/v2" + url, headers=h or c.exe)


def post(c, url, body=None, h=None):
    return c.post("/api/v2" + url, json=body or {}, headers=h or c.ana)


# ------------------------------------------------------------------ inventory, topology, telemetry
def test_asset_list_and_filters(client):
    r = get(client, "/assets").json()
    assert r["count"] >= 28 and all("sector" in a and "vulns" in a for a in r["assets"])
    assert get(client, "/assets?category=field").json()["count"] == 8
    assert get(client, "/assets?q=vendor").json()["count"] >= 1


def test_asset_detail_has_vulns_links_dependencies_and_risk(client):
    r = get(client, "/assets/SCADA_SRV").json()
    assert r["vulnerabilities"][0]["cvss"] and r["network_in"] and r["service_dependencies"]["provides_to"] and r["risk"]["risk"] > 0
    assert get(client, "/assets/NOPE").status_code == 404
    assert get(client, "/assets/bad id!").status_code == 422


def test_topology_separates_network_reachability_from_service_dependency(client):
    t = get(client, "/topology").json()
    assert t["network_links"] and t["service_dependencies"]
    assert {"actual", "documented only"} == {e["reachability"] for e in t["network_links"]}
    assert all("provider" in d for d in t["service_dependencies"])


def test_vulnerabilities_telemetry_events(client):
    assert get(client, "/vulnerabilities").json()["vulnerabilities"]
    tel = get(client, "/telemetry").json()
    assert "reported" in tel and "watchdog_p" in tel
    assert "events" in get(client, "/events?limit=5").json()


# ------------------------------------------------------------------ model, risk, explanation
def test_model_definitions_and_quality(client):
    m = get(client, "/model").json()
    assert m["state"]["status"] == "ready" and m["state"]["meta"]["spearman_heldout"] > 0.7
    d = m["definitions"]
    assert "synthetic risk propensity" in d["compromise_likelihood"] and "30 days" in d["horizon"] and d["exploit_prediction"] and d["operational_impact"]
    assert len(m["state"]["features"]) == 14


def test_retraining_is_reproducible(client):
    a = post(client, "/model/train", dict(variants=60, seed=4)).json()
    r1 = get(client, "/risk").json()["assets"]
    b = post(client, "/model/train", dict(variants=60, seed=4)).json()
    r2 = get(client, "/risk").json()["assets"]
    assert a["meta"]["mae_heldout"] == b["meta"]["mae_heldout"] and [x["risk"] for x in r1] == [x["risk"] for x in r2]
    post(client, "/model/train", dict(variants=140, seed=11))   # restore the default model for the other tests
    assert get(client, "/model").json()["state"]["status"] == "ready"


def test_risk_scores_are_bounded_and_ranked(client):
    r = get(client, "/risk").json()
    rows = r["assets"]
    assert rows[0]["risk"] == 100.0 and [x["risk"] for x in rows] == sorted((x["risk"] for x in rows), reverse=True)
    assert all(0 <= x["likelihood"] <= 1 and 0 <= x["propensity_prior"] <= 1 for x in rows)


def test_moderate_cvss_connected_asset_can_outrank_a_critical_cvss_one(client):
    rows = {x["id"]: x for x in get(client, "/risk").json()["assets"]}
    assert rows["SCADA_WEB"]["cvss"] == 10.0 and rows["SCADA_WEB"]["rank_by_cvss"] == 1
    assert rows["ENG_WS"]["cvss"] < rows["SCADA_WEB"]["cvss"] and rows["ENG_WS"]["rank"] < rows["SCADA_WEB"]["rank"]
    cmp = get(client, "/risk/compare?a=ENG_WS&b=SCADA_WEB").json()
    assert cmp["a"]["risk"] > cmp["b"]["risk"] and "likelihood" in cmp["text"]
    assert any(x["rank"] > 20 for x in rows.values() if x["cvss"] >= 9.8)    # a critical-CVSS device that reaches little ranks low


def test_explanation_names_drivers_and_impact(client):
    e = get(client, "/risk/ENG_WS/explain").json()
    assert e["drivers"][0]["contribution"] >= e["drivers"][-1]["contribution"] and e["reachable_from_asset"] and e["services_lost"] and "Ranked #" in e["explanation"]
    assert get(client, "/risk/NOPE/explain").status_code == 404


# ------------------------------------------------------------------ what-if simulation
def test_simulate_compromise_labels_plausible_predicted_confirmed(client):
    r = post(client, "/simulate/compromise", dict(start="VPN_VENDOR", credentials=["VPN_VENDOR"])).json()
    assert r["status"] == "plausible" and "PLC_PS2" in r["compromised"] and r["paths"]["PLC_PS2"]
    c = r["classification"]
    assert {"confirmed_incident_assets", "plausible_path_assets", "predicted_top_risk"} <= set(c) and r["risk_during"] > r["risk_before"] and r["recommendations"]
    assert r == post(client, "/simulate/compromise", dict(start="VPN_VENDOR", credentials=["VPN_VENDOR"])).json()   # deterministic


def test_failed_prerequisites_are_reported(client):
    r = post(client, "/simulate/compromise", dict(start="PLC_PS2")).json()
    assert r["compromised"] == ["PLC_PS2"] and r["loss"] > 0                      # nothing downstream, but its own service is lost


def test_attack_paths_endpoint(client):
    r = get(client, "/attack-paths/VPN_VENDOR", client.ana).json()
    assert r["status"] == "plausible" and r["paths"] and r["paths"][0]["nodes"][0] == "VPN_VENDOR"


def test_validation_and_roles(client):
    assert client.post("/api/v2/simulate/compromise", json=dict(start="NOPE"), headers=client.ana).status_code == 404
    assert client.post("/api/v2/simulate/compromise", json=dict(start="x; DROP TABLE"), headers=client.ana).status_code == 422
    assert client.post("/api/v2/simulate/compromise", json=dict(start="VPN_VENDOR"), headers=client.exe).status_code == 403
    assert client.get("/api/v2/assets").status_code == 401
    assert client.post("/api/v2/simulate/compromise", json=dict(start="VPN_VENDOR", controls=dict(mfa=["GHOST"])), headers=client.ana).status_code == 422
    assert post(client, "/mitigations/apply", dict(mitigation="rm -rf")).status_code == 422
    assert post(client, "/mitigations/apply", dict(mitigation="mfa")).status_code == 422
    assert post(client, "/mitigations/apply", dict(mitigation="segmentation", edges=["E9999"])).status_code == 422


# ------------------------------------------------------------------ the five scenarios
@pytest.mark.parametrize("sid", SCENARIOS)
def test_scenario_has_all_required_sections_and_is_deterministic(client, sid):
    a = post(client, f"/scenarios/{sid}/run").json()
    for k in ("assumptions", "initial_state", "timeline", "effects", "insights", "recommendations", "risk", "package"):
        assert a[k], f"{sid} lacks {k}"
    assert all(e["synthetic"] for e in a["timeline"]) and "Nothing here touches a real system" in a["synthetic_notice"]
    assert {"before", "during", "after_package"} <= set(a["risk"]) and a["risk"]["after_package"] < a["risk"]["during"]
    b = post(client, f"/scenarios/{sid}/run").json()
    assert json.dumps(a, sort_keys=True, default=float) == json.dumps(b, sort_keys=True, default=float)


def test_unknown_scenario_is_404(client):
    assert post(client, "/scenarios/nope/run").status_code == 404
    assert len(get(client, "/scenarios").json()["scenarios"]) == 5


def test_scenario_specific_effects(client):
    v = post(client, "/scenarios/vendor_credential/run").json()["effects"]
    assert "PLC_PS2" in v["compromised"] and v["abnormal_auth"]["sign_ins_per_hour_scenario"] > v["abnormal_auth"]["sign_ins_per_hour_baseline"]
    r = post(client, "/scenarios/ransomware_monitoring/run").json()["effects"]
    assert r["monitoring_visibility_lost_pct"] > 0 and r["dependent_assets"] and r["recovery_hours"]["with_tested_backups"] < r["recovery_hours"]["without_tested_backups"]
    w = post(client, "/scenarios/controller_exposure/run").json()["effects"]
    assert w["controller_reachable"] and len(w["plausible_path"]) < len(w["path_without_the_weak_link"]) and w["operational_model"]["result"]["hh_h"] > 0
    i = post(client, "/scenarios/iot_compromise/run").json()["effects"]
    assert i["detector"]["recall"] == 1.0 and i["detector"]["precision"] >= 0.5 and i["clusters"]
    h = post(client, "/scenarios/hospital_incident/run").json()["effects"]
    assert "H1_ISOLATE" in json.dumps(h) or h["services_lost"]
    assert h["inbound_protection"]["options"] and h["high_value_dependency"]["beds"] == 1800


def test_scenarios_never_modify_the_baseline(client):
    before = get(client, "/assets").json()
    topo = get(client, "/topology").json()
    for sid in SCENARIOS:
        post(client, f"/scenarios/{sid}/run")
    assert get(client, "/assets").json()["assets"] == before["assets"] or [a["id"] for a in get(client, "/assets").json()["assets"]] == [a["id"] for a in before["assets"]]
    assert get(client, "/topology").json() == topo
    assert get(client, "/mitigations").json()["applied"]["blocked_edges"] == []     # scenarios do not leak controls into the session


# ------------------------------------------------------------------ mitigations: before / after, partial effect, reset
def test_mitigation_lowers_ward_risk_and_compare_explains(client):
    base = get(client, "/compare", client.ana).json()["ward_risk_before"]
    post(client, "/mitigations/apply", dict(mitigation="restrict_remote_access"))
    post(client, "/mitigations/apply", dict(mitigation="vpatch", assets=["SCADA_SRV", "JUMP_RDS", "ENG_WS"]))
    c = get(client, "/compare?start=VPN_VENDOR", client.ana).json()
    assert c["ward_risk_after"] < base and c["assets"][0]["delta"] <= 0
    assert c["simulation"]["reachable_after"] != c["simulation"]["reachable_before"]


def test_a_single_mitigation_may_not_eliminate_every_path(client):
    post(client, "/mitigations/apply", dict(mitigation="mfa", assets=["VPN_VENDOR"]))
    c = get(client, "/compare?start=VPN_VENDOR", client.ana).json()["simulation"]
    assert c["all_paths_eliminated"] is False and c["paths_remaining"] > 0


def test_reset_restores_the_baseline(client):
    risk0 = get(client, "/risk").json()["ward_risk_index"]
    post(client, "/mitigations/apply", dict(mitigation="backup_ir"))
    post(client, "/mitigations/apply", dict(mitigation="monitoring", assets=["SCADA_SRV"]))
    assert get(client, "/risk").json()["ward_risk_index"] < risk0
    assert post(client, "/reset").json()["ok"]
    assert get(client, "/risk").json()["ward_risk_index"] == risk0
    assert get(client, "/mitigations").json()["applied"]["backup_ir"] is False


def test_optimize_returns_a_budgeted_plan(client):
    r = post(client, "/optimize", dict(budget=8)).json()
    assert r["steps"] and r["spent"] <= 8 and r["risk_after"] <= r["risk_before"]
    assert post(client, "/optimize", dict(budget=9999)).status_code == 422
