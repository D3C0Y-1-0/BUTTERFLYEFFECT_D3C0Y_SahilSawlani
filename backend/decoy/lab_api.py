"""REST API of the What-if Lab (mounted at /api/v2). The backend is the only place where simulation and risk are computed.
Same guards as the rest of the app: signed token, role check, strict pydantic validation. Simulations run on copies; the baseline is never modified."""
from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

from .lab import Controls, RULES, simulate_compromise
from .lab_scenarios import SCENARIO_LIST, run_scenario

ID = r"^[A-Za-z0-9_:\-\.]{1,64}$"
_FORECAST: dict = {}
IDS = Field(default_factory=list, max_length=60)


class Sim(BaseModel):
    start: str = Field(pattern=ID)
    controls: dict | None = None
    use_session: bool = True
    credentials: list[str] = Field(default_factory=list, max_length=10)


class Apply(BaseModel):
    mitigation: Literal["mfa", "vpatch", "patched", "harden", "segmentation", "disable_exposed", "restrict_remote_access", "vendor_scope", "monitoring", "backup_ir", "isolate"] | None = None
    controls: dict | None = None            # alternative to `mitigation`: the exact controls a recommendation carries
    assets: list[str] = IDS
    edges: list[str] = IDS


class Budget(BaseModel):
    budget: float = Field(default=12.0, ge=1, le=40)


class Train(BaseModel):
    variants: int = Field(default=260, ge=40, le=400)
    seed: int = Field(default=11, ge=0, le=10_000)


def make_router(state, user_for) -> APIRouter:
    r = APIRouter()

    def lab():
        return state["lab"]

    def asset_or_404(a):
        if a not in lab().model["assets"]:
            raise HTTPException(404, "unknown asset")
        return lab().model["assets"][a]

    def need_model():
        if not lab().ready():
            raise HTTPException(409, "The risk model is still training or failed to train. See GET /api/v2/model.")

    def controls_from(body: Sim):
        L = lab()
        c = L.session.copy() if body.use_session else Controls()
        if body.controls:
            extra = Controls.from_json(body.controls)
            for k, v in extra.__dict__.items():
                cur = getattr(c, k)
                setattr(c, k, (cur | v) if isinstance(cur, set) else (cur or v))
        for a in c.mfa | c.vpatch | c.patched | c.harden | c.monitoring | c.isolated:
            if a not in L.model["assets"]:
                raise HTTPException(422, f"unknown asset in controls: {a}")
        ids = {e["id"] for e in L.model["edges"]}
        bad = [e for e in c.blocked_edges if e not in ids]
        if bad:
            raise HTTPException(422, f"unknown link in controls: {bad[0]}")
        return c

    # ---------------------------------------------------------------- inventory & topology
    @r.get("/assets")
    def assets(category: str | None = Query(None, max_length=20), sector: str | None = Query(None, max_length=30), q: str | None = Query(None, max_length=40), u=Depends(user_for("read"))):
        rows = lab().db.rows("assets")
        risk = {x["id"]: x for x in lab().ranking(lab().session)} if lab().ready() else {}
        out = []
        for a in rows:
            if category and a["category"] != category or sector and a["sector"] != sector or q and q.lower() not in (a["name"] + a["id"]).lower():
                continue
            out.append(dict(a, risk=risk.get(a["id"])))
        return dict(count=len(out), assets=out)

    @r.get("/assets/{aid}")
    def asset(aid: str = Path(pattern=ID), u=Depends(user_for("read"))):
        asset_or_404(aid)
        L = lab()
        a = L.db.one("assets", aid)
        edges = L.db.rows("edges")
        vul = [L.db.one("vulnerabilities", v, "cve") for v in a["vulns"]]
        ev = [e for e in L.db.events(300) if aid in e["text"]][:15]
        return dict(asset=a, vulnerabilities=vul, network_in=[e for e in edges if e["target"] == aid and e["exists"]], network_out=[e for e in edges if e["source"] == aid and e["exists"]],
                    documented_but_absent=[e for e in edges if aid in (e["source"], e["target"]) and not e["exists"]],
                    service_dependencies=dict(provides_to=[d for d in L.model["deps"] if d["provider"] == aid], depends_on=[d for d in L.model["deps"] if d["consumer"] == aid]),
                    risk=next((x for x in L.ranking(L.session) if x["id"] == aid), None) if L.ready() else None, event_history=ev)

    @r.get("/topology")
    def topology(u=Depends(user_for("read"))):
        L = lab()
        return dict(nodes=[dict(id=a["id"], name=a["name"], category=a["category"], sector=a["sector"], exposure=a["exposure"]) for a in L.db.rows("assets")],
                    network_links=[dict(e, reachability="actual" if e["exists"] else "documented only") for e in L.db.rows("edges")],
                    service_dependencies=[dict(provider=d["provider"], consumer=d["consumer"], kind=d["kind"]) for d in L.model["deps"]],
                    note="Network reachability and operational/service dependency are different relations. A link alone never implies compromise.")

    @r.get("/vulnerabilities")
    def vulnerabilities(u=Depends(user_for("read"))):
        L = lab()
        cves = {c["cve"] if "cve" in c else k: c for k, c in ((k, v) for k, v in L.rt.T.snap["cves"].items())}
        by = {}
        for a in L.model["assets"].values():
            for v in a["vulns"]:
                by.setdefault(v, []).append(a["id"])
        return dict(vulnerabilities=[dict(cve=k, cvss=v.get("cvss"), epss=v.get("epss"), in_kev=v.get("in_kev"), assets=by.get(k, [])) for k, v in sorted(cves.items())], source="NVD / FIRST EPSS / CISA KEV snapshots")

    @r.get("/telemetry")
    def telemetry(u=Depends(user_for("read"))):
        return lab().telemetry()

    @r.get("/events")
    def events(limit: int = Query(50, ge=1, le=500), kind: str | None = Query(None, max_length=40, pattern=r"^[a-z_]+$"), u=Depends(user_for("read"))):
        return dict(events=lab().db.events(limit, kind), runs=lab().db.runs(10))

    # ---------------------------------------------------------------- model & risk
    @r.get("/model")
    def model(u=Depends(user_for("read"))):
        L = lab()
        return dict(state=L.state, definitions=L.definitions(), rules=RULES)

    @r.post("/model/train")
    def train(b: Train, u=Depends(user_for("whatif"))):
        try:
            return lab().train(b.variants, b.seed)
        except Exception as e:
            raise HTTPException(500, f"training failed: {type(e).__name__}")

    @r.get("/forecast")
    def forecast(top: int = Query(default=6, ge=1, le=12), u=Depends(user_for("risk"))):
        """Prediction: which devices are most likely to be attacked next, why, and the best next step for each."""
        need_model()
        L = lab()
        key = (top, json.dumps(L.session.to_json(), sort_keys=True), tuple(sorted(L.anomaly())))   # same controls and same evidence = same answer: reopening the page costs nothing
        hit = _FORECAST.get(key)
        if hit is not None:
            return hit
        rows = sorted(L.ranking(L.session), key=lambda x: -x["likelihood"])[:top]
        out = []
        for x in rows:
            why = L.explain(x["id"], L.session)
            rec = [q for q in L.recommend(x["id"], L.session, top=3) if q["reduction"] > 0][:2]
            out.append(dict(id=x["id"], name=x["name"], likelihood=x["likelihood"], risk=x["risk"], impact=x["impact"], main_reason=why["drivers"][0]["group"],
                            reaches=len(why["reachable_from_asset"]), services_lost=why["services_lost"], steps=[dict(label=q["label"], cost=q["cost"], reduction=q["reduction"], apply=q["apply"]) for q in rec]))
        meta = L.state["meta"]
        res = dict(items=out, accuracy=dict(spearman=meta["spearman_heldout"], mae=meta["mae_heldout"], top5_overlap=meta.get("top5_overlap_heldout"), test_rows=meta["test_rows"],
                                             note="Measured on control configurations the model never saw during training. Labels come from the simulated attack worlds, so this is accuracy against the simulator, not against real incidents."))
        _FORECAST.clear(); _FORECAST[key] = res
        return res

    @r.get("/impact")
    def impact(node: str = Query(pattern=ID), start: float = Query(default=6.0, ge=0, le=23), u=Depends(user_for("risk"))):
        """What would happen to people if this one device were taken over: people without service, how long, and the money lost. Nothing is changed."""
        from .assumptions import A, ASSUMPTIONS
        from .lab import service_loss
        L = lab(); rt = state["rt"]
        if node not in L.model["assets"] and node not in rt.ward["physical"]:
            raise HTTPException(404, "unknown device")
        if node in L.model["assets"] and node != "INTERNET":
            sim = simulate_compromise(L.model, node, L.session)
            acts = service_loss(L.model, sim["compromised"])["actions"]
            reach = len(sim["compromised"]) - 1
        else:
            acts = [a for a, v in rt.ward["actions"].items() if v["target"] == node or "CB_" + v["target"] == node]
            reach = 0
        acts = [a for a in acts if a in rt.ward["actions"]]
        if not acts:
            return dict(node=node, actions=[], reach=reach, people=0, hours=0.0, money_inr=0.0, homes=0, hospitals_hit=0, lines=[], assumption="No water or power service can be switched off from here.")
        ev = rt.phys.attack_events(sorted(acts), start)
        res = rt.phys.loss(ev); hours = max(e["dur_h"] for e in ev)
        homes = res["hh_h"] / max(hours, 1e-6)
        inr = A("inr_per_household_hour") if "inr_per_household_hour" in ASSUMPTIONS else 70.0
        hosp_h = res["hosp_water_h"] + res["hosp_power_h"]
        return dict(node=node, actions=acts, labels=[rt.ward["actions"][a]["label"] for a in acts], reach=reach, start=start, hours=round(hours, 1), homes=int(round(homes)), people=int(round(homes * A("persons_per_household") + res["mwh"] * 700 / max(hours, 1e-6) * A("persons_per_household"))),
                    hospitals_hit=int(sum(1 for v in res["per_hospital"].values() if v > 0.05)) + (1 if res["hosp_power_h"] > 0 else 0), money_inr=round(res["L"] * inr, 0), loss_units=res["L"],
                    assumption=f"People = homes without water or power (average over the outage) x {A('persons_per_household')} per home. Money counts Rs {inr:.0f} per home-hour and a hospital-hour as {A('w_hospital_hour'):.0f} home-hours (SYNTHETIC rates).")

    @r.get("/risk")
    def risk(session: bool = True, u=Depends(user_for("risk"))):
        need_model()
        L = lab()
        rows = L.ranking(L.session if session else Controls())
        return dict(model_version=L.state["meta"]["version"], definitions=L.definitions(), ward_risk_index=round(L.ward_index(L.session if session else Controls()), 2), assets=rows)

    @r.get("/risk/compare")
    def risk_compare(a: str = Query(pattern=ID), b: str = Query(pattern=ID), u=Depends(user_for("risk"))):
        need_model(); asset_or_404(a); asset_or_404(b)
        return lab().compare_assets(a, b, lab().session)

    @r.get("/risk/{aid}/explain")
    def explain(aid: str = Path(pattern=ID), u=Depends(user_for("risk"))):
        need_model(); asset_or_404(aid)
        return lab().explain(aid, lab().session)

    # ---------------------------------------------------------------- what-if
    @r.post("/simulate/compromise")
    def simulate(b: Sim, u=Depends(user_for("whatif"))):
        need_model(); asset_or_404(b.start)
        for c in b.credentials:
            asset_or_404(c)
        return lab().simulate(b.start, controls_from(b), set(b.credentials))

    @r.get("/attack-paths/{aid}")
    def attack_paths(aid: str = Path(pattern=ID), u=Depends(user_for("whatif"))):
        asset_or_404(aid)
        L = lab()
        sim = simulate_compromise(L.model, aid, L.session)
        names = {a["id"]: a["name"] for a in L.model["assets"].values()}
        paths = [dict(to=v, nodes=[aid] + [next(e["target"] for e in L.model["edges"] if e["id"] == eid) for eid in p], edges=p, why=sim["why"][v]) for v, p in sim["paths"].items() if v != aid]
        return dict(start=aid, status="plausible", paths=paths, failed_prerequisites=sim["failed"][:20], names=names)

    @r.get("/scenarios")
    def scenarios(u=Depends(user_for("read"))):
        return dict(scenarios=SCENARIO_LIST)

    @r.post("/scenarios/{sid}/run")
    def scenario(sid: str = Path(pattern=ID), u=Depends(user_for("whatif"))):
        need_model()
        try:
            return run_scenario(lab(), sid)
        except KeyError:
            raise HTTPException(404, "unknown scenario")

    # ---------------------------------------------------------------- mitigations
    @r.get("/mitigations")
    def mitigations(u=Depends(user_for("read"))):
        return dict(catalogue=lab().mitigation_catalogue(), applied=lab().session.to_json())

    @r.post("/mitigations/apply")
    def apply(b: Apply, u=Depends(user_for("whatif"))):
        L = lab()
        for a in b.assets:
            asset_or_404(a)
        ids = {e["id"] for e in L.model["edges"]}
        for e in b.edges:
            if e not in ids:
                raise HTTPException(422, f"unknown link: {e}")
        c, m = L.session, b.mitigation
        if b.controls is not None:
            extra = Controls.from_json(b.controls)
            if any(x not in L.model["assets"] for x in extra.mfa | extra.vpatch | extra.patched | extra.harden | extra.monitoring | extra.isolated):
                raise HTTPException(422, "unknown asset in controls")
            if any(x not in ids for x in extra.blocked_edges):
                raise HTTPException(422, "unknown link in controls")
            for k, v in extra.__dict__.items():
                cur = getattr(c, k)
                setattr(c, k, (cur | v) if isinstance(cur, set) else (cur or v))
            return dict(applied=c.to_json(), note="Simulation only: the live twin and the baseline are untouched.")
        if m is None:
            raise HTTPException(422, "give a mitigation or controls")
        if m in ("mfa", "vpatch", "patched", "harden", "monitoring", "isolate", "disable_exposed") and not b.assets:
            raise HTTPException(422, "this mitigation needs at least one asset")
        if m == "segmentation" and not b.edges:
            raise HTTPException(422, "segmentation needs at least one link")
        if m == "mfa": c.mfa.update(b.assets)
        elif m == "vpatch": c.vpatch.update(b.assets)
        elif m == "patched": c.patched.update(b.assets)
        elif m == "harden": c.harden.update(b.assets)
        elif m == "monitoring": c.monitoring.update(b.assets)
        elif m == "isolate": c.isolated.update(b.assets)
        elif m == "segmentation": c.blocked_edges.update(b.edges)
        elif m == "disable_exposed": c.blocked_edges.update(e["id"] for e in L.model["edges"] if e["source"] == "INTERNET" and e["target"] in b.assets)
        elif m == "restrict_remote_access": c.blocked_edges.update(e["id"] for e in L.model["edges"] if e["kind"] == "vendor")
        elif m == "vendor_scope": c.vendor_scoped = True
        elif m == "backup_ir": c.backup_ir = True
        return dict(applied=c.to_json(), note="Simulation only: the live twin and the baseline are untouched.")

    @r.get("/compare")
    def compare(start: str | None = Query(None, pattern=ID), u=Depends(user_for("whatif"))):
        """Before/after risk: baseline (no controls) vs the simulated mitigations applied in this session."""
        need_model()
        L = lab()
        base, now = Controls(), L.session
        rb = {x["id"]: x for x in L.ranking(base)}
        out = dict(ward_risk_before=round(L.ward_index(base), 2), ward_risk_after=round(L.ward_index(now), 2), controls=now.to_json())
        after = {x["id"]: x for x in L.ranking(now)}
        out["assets"] = sorted([dict(id=a, name=rb[a]["name"], risk_before=rb[a]["risk"], risk_after=after[a]["risk"], delta=round(after[a]["risk"] - rb[a]["risk"], 2),
                                     likelihood_before=rb[a]["likelihood"], likelihood_after=after[a]["likelihood"]) for a in rb], key=lambda x: x["delta"])
        if start:
            asset_or_404(start)
            s0, s1 = simulate_compromise(L.model, start, base), simulate_compromise(L.model, start, now)
            out["simulation"] = dict(start=start, reachable_before=s0["compromised"][1:], reachable_after=s1["compromised"][1:], paths_remaining=len(s1["compromised"]) - 1,
                                     all_paths_eliminated=len(s1["compromised"]) == 1)
        return out

    @r.post("/reset")
    def reset(u=Depends(user_for("whatif"))):
        return lab().reset()

    @r.post("/optimize")
    def optimize(b: Budget, u=Depends(user_for("whatif"))):
        return lab().optimize(b.budget)

    return r
