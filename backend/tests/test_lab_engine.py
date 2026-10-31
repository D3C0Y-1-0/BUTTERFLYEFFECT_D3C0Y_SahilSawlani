"""Unit tests for the What-if Lab engine on tiny, fully deterministic fixtures (no physics, no network, no randomness)."""
import numpy as np
import pytest

from decoy.lab import (Controls, FNAMES, RULES, RiskModel, asset_features, dependents, feature_contributions, graph_features, likelihood, rank_assets, reachable,
                       service_loss, simulate_compromise, transition, usable_edges, vec)


def A(id, category="it", exposure="internal", cvss=0.0, epss=0.0, kev=False, vulns=None, p_weak=0.0, p_patched=0.0, entry=0.0, **kw):
    d = dict(id=id, name=id, category=category, sector="test", description="", function="", purdue=3, firmware="1", vulns=vulns if vulns is not None else ([f"CVE-T-{id}"] if cvss else []), cvss=cvss, epss=epss, kev=kev,
             exposure=exposure, p_weak=p_weak, p_patched=p_patched, legacy=False, known_version=True, cve_belief=1.0, entry_weight=entry, anomaly=0.0, action=None, provenance="SYNTHETIC", tags=[])
    d.update(kw)
    return d


def E(id, s, t, kind="network", exists=True, p=1.0):
    return dict(id=id, source=s, target=t, kind=kind, protocol="tcp", p_access=p, exists=exists, documented=True, note=None)


def M(assets, edges, deps=(), services=None):
    return dict(version="t", assets={a["id"]: a for a in assets}, edges=list(edges), deps=[dict(provider=p, consumer=c, kind=k) for p, c, k in deps],
                services=services or {}, monitored=[])


SVC = lambda ctrl, w=100.0: {"S_" + ctrl: dict(id="S_" + ctrl, name="service of " + ctrl, controller=ctrl, kind="x", target="t", weight=w)}


def chain():
    """INTERNET -> WEB(vulnerable) -> APP(weak access) -> PLC(vulnerable, drives a service);  ISO is disconnected and critical-looking."""
    a = [A("INTERNET", "internet", "internet"), A("WEB", "dmz", "internet", cvss=9.0, epss=0.5, kev=True, entry=1.0), A("APP", "control", p_weak=0.5),
         A("PLC", "field", cvss=7.0, epss=0.2, vulns=["CVE-T-PLC"]), A("ISO", "it", "isolated", cvss=10.0, epss=0.97, kev=True)]
    e = [E("e1", "INTERNET", "WEB"), E("e2", "WEB", "APP"), E("e3", "APP", "PLC")]
    return M(a, e, services=SVC("PLC"))


# ------------------------------------------------------------------ graph construction and reachability
def test_reachability_follows_links_only():
    m = chain()
    assert reachable(m, "INTERNET") == {"INTERNET": 0, "WEB": 1, "APP": 2, "PLC": 3}
    assert "ISO" not in reachable(m, "INTERNET")                       # disconnected asset


def test_reachability_terminates_on_cycles_and_unknown_asset_raises():
    m = chain()
    m["edges"] += [E("e4", "PLC", "APP"), E("e5", "APP", "WEB")]      # cycles
    assert reachable(m, "WEB") == {"WEB": 0, "APP": 1, "PLC": 2}
    with pytest.raises(KeyError):
        reachable(m, "NOPE")


def test_documented_but_absent_links_do_not_count():
    m = chain()
    m["edges"].append(E("ghost", "WEB", "ISO", exists=False))
    assert "ISO" not in reachable(m, "WEB")
    assert "ghost" not in {e["id"] for e in usable_edges(m)}


def test_closed_links_and_isolated_assets_break_reachability():
    m = chain()
    assert "PLC" not in reachable(m, "WEB", Controls(blocked_edges={"e3"}))
    assert "APP" not in reachable(m, "WEB", Controls(isolated={"APP"}))


# ------------------------------------------------------------------ attack preconditions
def test_a_connection_alone_is_not_a_compromise():
    m = chain()
    m["assets"]["APP"]["p_weak"] = 0.0                                  # strong access control, no CVE
    sim = simulate_compromise(m, "WEB")
    assert sim["compromised"] == ["WEB"]
    assert sim["failed"] and "no vulnerable service" in sim["failed"][0]["reasons"]


def test_each_precondition_alone_is_enough_and_is_reported():
    m = chain()
    sim = simulate_compromise(m, "WEB")
    assert sim["compromised"] == ["WEB", "APP", "PLC"]
    assert "weak access control" in sim["why"]["APP"][0] and "vulnerable service" in sim["why"]["PLC"][0]


def test_patching_or_virtual_patching_blocks_the_vulnerability_precondition():
    m = chain()
    assert "PLC" not in simulate_compromise(m, "WEB", Controls(vpatch={"PLC"}))["compromised"]
    assert "PLC" not in simulate_compromise(m, "WEB", Controls(patched={"PLC"}))["compromised"]


def test_low_exploitation_signal_means_not_exploitable():
    m = chain()
    m["assets"]["PLC"].update(epss=0.001, kev=False)
    assert "PLC" not in simulate_compromise(m, "WEB")["compromised"]


def test_vendor_credentials_need_no_mfa():
    a = [A("INTERNET", "internet", "internet"), A("VPN", "dmz", "internet", p_weak=0.3), A("BMS", "field")]
    m = M(a, [E("v1", "VPN", "BMS", kind="vendor")], services=SVC("BMS"))
    assert simulate_compromise(m, "VPN", creds={"VPN"})["compromised"] == ["VPN", "BMS"]
    no = simulate_compromise(m, "VPN", Controls(mfa={"VPN"}), creds={"VPN"})
    assert no["compromised"] == ["VPN"] and "MFA" in no["failed"][0]["reasons"][0]
    assert simulate_compromise(m, "VPN")["compromised"] == ["VPN"]     # no credential, no vulnerability, no weak target: nothing happens


def test_simulation_is_deterministic():
    m = chain()
    assert simulate_compromise(m, "WEB") == simulate_compromise(m, "WEB")


def test_missing_vulnerability_data_is_safe():
    m = chain()
    m["assets"]["PLC"].update(vulns=[], cvss=0.0, epss=0.0, kev=False)
    ok, why = transition(m, m["edges"][2], Controls(), set())
    assert ok is False and "no vulnerable service" in why
    f = asset_features(m, "PLC")
    assert f["cvss"] == 0.0 and f["exploit_signal"] == 0.0 and len(vec(f)) == len(FNAMES)


def test_unknown_firmware_with_low_belief_is_not_assumed_vulnerable():
    m = chain()
    m["assets"]["PLC"].update(known_version=False, cve_belief=0.3)
    assert "PLC" not in simulate_compromise(m, "WEB")["compromised"]


# ------------------------------------------------------------------ service dependencies
def test_dependency_analysis_handles_cycles():
    m = M([A("X"), A("Y"), A("Z"), A("W")], [], deps=[("X", "Y", "operates"), ("Y", "Z", "operates"), ("Z", "X", "operates")])
    assert sorted(dependents(m, "X")) == ["Y", "Z"]
    assert dependents(m, "W") == []


def test_service_loss_counts_controllers_that_depend_on_a_compromised_supervisor():
    m = M([A("SUP"), A("C1", "field"), A("C2", "field")], [], deps=[("SUP", "C1", "operates"), ("SUP", "C2", "monitoring")], services={**SVC("C1", 10), **SVC("C2", 5)})
    assert service_loss(m, ["SUP"])["loss"] == 10                      # C1 operates under SUP; C2 only monitored by it
    assert service_loss(m, ["C2"])["loss"] == 5
    assert service_loss(m, ["SUP"], backup_ir=True)["loss"] == pytest.approx(10 * (1 - RULES["backup_cut"]))


# ------------------------------------------------------------------ prioritisation
def synthetic_training(m, n=60, seed=0):
    """Label = a transparent closed-form propensity, so the pipeline test needs no simulator."""
    rng = np.random.default_rng(seed)
    X, y, g = [], [], []
    for v in range(n):
        c = Controls()
        for a in m["assets"]:
            if rng.random() < 0.3: c.vpatch.add(a)
            if rng.random() < 0.3: c.mfa.add(a)
        gf = graph_features(m, c)
        for a in m["assets"]:
            if a == "INTERNET": continue
            f = asset_features(m, a, c, _g=gf)
            X.append(vec(f)); g.append(v)
            y.append(min(1.0, 0.05 + 0.5 * f["exploit_signal"] + 0.4 * f["weak_access"] + 0.2 * f["exposure"] - 0.02 * f["hops"]))
    return np.array(X), np.clip(np.array(y), 0, 1), np.array(g)


@pytest.fixture(scope="module")
def trained():
    m = chain()
    rm = RiskModel()
    X, y, g = synthetic_training(m)
    rm.fit(X, y, g, seed=3)
    return m, rm


def test_isolated_critical_cvss_ranks_below_moderate_but_connected(trained):
    m, rm = trained
    m["assets"]["APP"].update(cvss=5.0, epss=0.06, vulns=["CVE-T-APP"])   # moderate severity, in the middle of the chain
    rows = rank_assets(m, rm, impact_fn=None)
    by = {r["id"]: r for r in rows}
    assert m["assets"]["ISO"]["cvss"] > m["assets"]["APP"]["cvss"]          # ISO looks far worse on CVSS
    assert by["ISO"]["impact"] == 0 and by["ISO"]["reach"] == 0              # but it reaches nothing
    assert by["APP"]["risk"] > by["ISO"]["risk"]
    assert [r["id"] for r in rows].index("APP") < [r["id"] for r in rows].index("ISO")


def test_ranking_is_deterministic(trained):
    m, rm = trained
    assert rank_assets(m, rm) == rank_assets(m, rm)


def test_isolated_asset_has_hops_nine_and_zero_inbound():
    f = asset_features(chain(), "ISO")
    assert f["hops"] == 9.0 and f["in_degree"] == 0.0


# ------------------------------------------------------------------ mitigation effect (explainable direction)
def test_mfa_and_virtual_patch_lower_the_modelled_propensity(trained):
    m, rm = trained
    p0 = rm.predict(vec(asset_features(m, "APP")))[0]
    p1 = rm.predict(vec(asset_features(m, "APP", Controls(mfa={"APP"}))))[0]
    assert p1 < p0
    q0 = rm.predict(vec(asset_features(m, "PLC")))[0]
    q1 = rm.predict(vec(asset_features(m, "PLC", Controls(vpatch={"PLC"}))))[0]
    assert q1 < q0


def test_reducing_exposure_does_not_raise_risk(trained):
    m, rm = trained
    before = rm.predict(vec(asset_features(m, "WEB")))[0]
    m2 = chain(); m2["assets"]["WEB"]["exposure"] = "internal"
    assert rm.predict(vec(asset_features(m2, "WEB")))[0] <= before


def test_monotone_constraints_hold_for_every_feature(trained):
    m, rm = trained
    f = asset_features(m, "APP")
    from decoy.lab import FEATURES
    for i, (name, _, d) in enumerate(FEATURES):
        lo, hi = dict(f), dict(f)
        lo[name], hi[name] = 0.0, (9.0 if name == "hops" else 1.0)
        pl, ph = rm.predict(vec(lo))[0], rm.predict(vec(hi))[0]
        assert (ph - pl) * d >= -1e-9, f"{name} breaks its monotone direction"


def test_explanations_name_the_driver(trained):
    m, rm = trained
    base, parts = feature_contributions(m, rm, "WEB")
    assert base > 0 and parts[0]["contribution"] >= parts[-1]["contribution"]
    assert {p["group"] for p in parts} >= {"vulnerability", "exposure", "connectivity"}


def test_monitoring_and_anomaly_rules():
    assert likelihood(0.1, 0.0, True) < likelihood(0.1, 0.0, False)
    assert likelihood(0.1, 1.0) > likelihood(0.1, 0.0)
    assert 0 < likelihood(0.0) < 1e-3 and likelihood(1.0) < 1.0


# ------------------------------------------------------------------ mitigation that does not remove every path
def test_one_mitigation_can_leave_other_paths_open():
    a = [A("INTERNET", "internet", "internet"), A("WEB", "dmz", "internet", cvss=9.0, epss=0.5, kev=True), A("VPN", "dmz", "internet", cvss=8.0, epss=0.4),
         A("PLC", "field", cvss=7.0, epss=0.3)]
    m = M(a, [E("w", "WEB", "PLC"), E("v", "VPN", "PLC"), E("i1", "INTERNET", "WEB"), E("i2", "INTERNET", "VPN")], services=SVC("PLC"))
    assert "PLC" in simulate_compromise(m, "INTERNET")["compromised"]
    after_one = simulate_compromise(m, "INTERNET", Controls(blocked_edges={"w"}))
    assert "PLC" in after_one["compromised"]                                  # the second route still works
    assert "PLC" not in simulate_compromise(m, "INTERNET", Controls(blocked_edges={"w", "v"}))["compromised"]
    assert "PLC" not in simulate_compromise(m, "INTERNET", Controls(vpatch={"PLC"}))["compromised"]


# ------------------------------------------------------------------ ML pipeline integrity
def test_training_is_reproducible_and_reports_held_out_quality():
    m = chain()
    X, y, g = synthetic_training(m)
    a, b = RiskModel(), RiskModel()
    ma, mb = a.fit(X, y, g, seed=5), b.fit(X, y, g, seed=5)
    assert np.allclose(a.predict(X[:20]), b.predict(X[:20]))
    assert {k: ma[k] for k in ("mae_heldout", "spearman_heldout", "train_rows", "test_rows")} == {k: mb[k] for k in ("mae_heldout", "spearman_heldout", "train_rows", "test_rows")}
    assert ma["test_rows"] > 0 and ma["train_rows"] + ma["test_rows"] == len(X)   # whole control configurations held out
    assert ma["spearman_heldout"] > 0.5


def test_model_refuses_to_predict_before_training_and_to_train_on_tiny_data():
    with pytest.raises(RuntimeError):
        RiskModel().predict([0] * len(FNAMES))
    with pytest.raises(ValueError):
        RiskModel().fit(np.zeros((5, len(FNAMES))), np.zeros(5))


def test_predictions_are_probabilities(trained):
    m, rm = trained
    X, _, _ = synthetic_training(m, n=10, seed=9)
    p = rm.predict(X)
    assert ((p >= 0) & (p <= 1)).all()
