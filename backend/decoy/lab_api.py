"""REST API of the What-if Lab (mounted at /api/v2). The backend is the only place where simulation and risk are computed.
Same guards as the rest of the app: signed token, role check, strict pydantic validation. Simulations run on copies; the baseline is never modified."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

from .lab import Controls, RULES, simulate_compromise
from .lab_scenarios import SCENARIO_LIST, run_scenario

ID = r"^[A-Za-z0-9_:\-\.]{1,64}$"
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
    variants: int = Field(default=140, ge=40, le=400)
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
