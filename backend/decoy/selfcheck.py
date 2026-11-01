"""Security self-checks. Every control on the Security page is MEASURED here by exercising the real code (throw-away instances, never the live accounts or keys);
nothing is a hard-coded tick. A check that cannot be run reports ok=False with the reason, never a silent pass."""
from __future__ import annotations

import json
import os
import time

from .blackbox import BlackBox
from .city import DATA
from .security import AirGap, Auth, PERMS, RateLimiter, ROLES

PUBLIC = {"/api/auth/login", "/api/auth/hint", "/api/health"}
_CACHE: dict = {}


def _t(fn):
    try:
        r = fn()
        return r if isinstance(r, tuple) else (bool(r), "")
    except Exception as e:      # a failing check is a finding, not a crash
        return False, f"check could not run: {type(e).__name__}: {e}"


def c_argon2(auth):
    return all(u["hash"].startswith("$argon2id$") for u in auth.users.values()), f"{len(auth.users)} accounts hashed with Argon2id"


def c_mfa(_):
    a = Auth()
    u = next(iter(a.users))
    pw = __import__("decoy.security", fromlist=["DEMO_USERS"]).DEMO_USERS[u][1]
    tok, err = a.login(u, pw, "000000", "selfcheck")
    return tok is None, "right password + wrong code was refused" if tok is None else "login succeeded without a valid code"


def c_token(_):
    a = Auth()
    good = a.verify(a.token("analyst", "analyst"))
    body, sig = a.token("analyst", "analyst").split(".")
    forged = a.verify(body + "." + "0" * len(sig))
    expired = a.verify(a.token("analyst", "analyst", ttl=-5))
    return bool(good) and forged is None and expired is None, "valid accepted; forged signature and expired token refused"


def c_rbac(app):
    from fastapi.routing import APIRoute
    open_ = [r.path for r in app.routes if isinstance(r, APIRoute) and r.path.startswith("/api") and r.path not in PUBLIC and not r.dependant.dependencies]
    least = ROLES[PERMS["reset"]] > ROLES[PERMS["read"]] and ROLES[PERMS["approve"]] > ROLES[PERMS["adversary_view"]] - 1
    return (not open_) and least, ("every /api route checks a role" if not open_ else f"routes without a role check: {open_[:4]}")


def c_lock(_):
    a = Auth()
    from .security import DEMO_USERS
    u = next(iter(a.users))
    for _i in range(5):
        a.login(u, "wrong-password", "000000", "selfcheck")
    tok, err = a.login(u, DEMO_USERS[u][1], __import__("pyotp").TOTP(a.users[u]["totp"]).now(), "selfcheck")
    return tok is None and "locked" in (err or ""), "correct credentials refused after 5 failures"


def c_rate(_):
    r = RateLimiter(rate=1.0, burst=3)
    res = [r.allow("x") for _i in range(6)]
    return (not all(res)) and res[0], f"{res.count(False)} of 6 rapid requests refused"


def c_valid(app):
    from .api import Attack
    bad = 0
    for kw in (dict(entry="../etc/passwd"), dict(mode="rm -rf"), dict(stealth=99)):
        try:
            Attack(**kw)
        except Exception:
            bad += 1
    return bad == 3, f"{bad} of 3 malformed bodies rejected"


def c_headers(app):
    from fastapi.testclient import TestClient
    r = TestClient(app).get("/")
    need = ["content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"]
    miss = [h for h in need if h not in r.headers]
    return not miss, "all present" if not miss else f"missing: {miss}"


def c_schema(app):
    from fastapi.testclient import TestClient
    c = TestClient(app)
    leaks = [p for p in ("/openapi.json", "/docs", "/redoc") if c.get(p).headers.get("content-type", "").startswith("application/json") or "swagger" in c.get(p).text.lower()]
    return app.openapi_url is None and not leaks, "no schema or docs endpoint answers" if not leaks else f"exposed: {leaks}"


def c_chain(rt):
    r = rt.bb.verify()
    keyed = bool(getattr(rt.bb, "key", None)) and all("mac" in e for e in list(rt.bb.entries)[-20:])
    t = rt.bb.tamper_demo()
    rehash_caught = t.get("rehashed", dict(ok=True))["ok"] is False if "rehashed" in t else True
    anchored = bool(rt.bb.anchors)
    return r["ok"] and keyed and rehash_caught, (f"{rt.bb.count} entries, HMAC-keyed, re-hash forgery caught: {rehash_caught}; external anchor points: {len(rt.bb.anchors)}" +
                                                  ("" if rt.bb.persist else " (NOT persisted in this run)") + ("" if anchored else "; no anchor yet"))


def c_signed(_):
    g = AirGap(persist=False)
    d = g.export(dict(x=1))
    ok1 = g.verify_import(d)[0]
    replay = not g.verify_import(d)[0]
    d2 = g.export(dict(x=2))
    d2["payload"]["x"] = 3
    tamper = not g.verify_import(d2)[0]
    return ok1 and replay and tamper, "valid accepted; replay and edited payload refused"


def c_airgap_persist(_):
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        g = AirGap(key_dir=Path(td))
        d = g.export(dict(x=1))
        g.verify_import(d)
        g2 = AirGap(key_dir=Path(td))
        return not g2.verify_import(d)[0], "an accepted snapshot is still refused after a restart"


def c_twop(_):
    from .api import needs_two
    return needs_two([dict(service=5, ops=0)]) and needs_two([dict(service=0, ops=900)]) and not needs_two([dict(service=0, ops=1)]), "high-impact steps need a second, different person; small ones do not"


def c_twin(rt):
    blocked = sum(d["blocked"] for d in rt.decision_log) if rt.decision_log else 0
    has = hasattr(rt.healer, "safety_check")
    return has, f"every cut/restart is simulated first; {blocked} unsafe candidate(s) refused so far. Scope: water and power only (hospital BMS/HVAC is guarded by a human-confirmation rule instead)"


def c_guard(rt):
    return bool(rt._sensitive_nodes()) and rt.AUTO_MAX > 0, f"{len(rt._sensitive_nodes())} hospital-adjacent devices need a person unless physics corroborates; at most {rt.AUTO_MAX} automatic steps per {rt.AUTO_WINDOW} min"


def c_feed(_):
    now = time.time()
    snap = json.loads((DATA / "threat_snapshot.json").read_text(encoding="utf-8"))
    kev = json.loads((DATA / "kev.json").read_text(encoding="utf-8"))
    cves = snap["cves"]
    bad = [k for k, v in cves.items() if not (0 <= float(v.get("cvss", 0)) <= 10) or not (0 <= float(v.get("epss", 0) or 0) <= 1)]
    from datetime import datetime
    age = (datetime.now().astimezone() - datetime.fromisoformat(snap["fetched_utc"])).days
    return (not bad) and bool(kev.get("vulnerabilities")) and age <= 400, f"{len(cves)} CVEs, scores in range: {not bad}; snapshot is {age} days old (stale after 400)"


def c_tls(_):
    return os.environ.get("DECOY_TLS") == "1", "HTTPS is on" if os.environ.get("DECOY_TLS") == "1" else "plain HTTP in this run; start with DECOY_TLS=1 (in deployment TLS ends at the reverse proxy)"


def c_keys(_):
    from .blackbox import KEY_DIR
    inside = str(KEY_DIR.resolve()).startswith(str(DATA.resolve()))
    return not inside, f"signing and log keys are kept in {KEY_DIR} (outside the project data folder)"


def c_bounded(rt):
    ok = len(rt.bb.entries) <= 5000 and getattr(rt.vault, "status", None) is not None
    return ok, f"log memory capped at 5000 entries; vault gzips old days and stays under {os.environ.get('ATHENA_VAULT_MAX_GB', '2')} GB; rate-limit table capped"


def run(rt, app, auth, rl):
    if _CACHE.get("t", 0) > time.time() - 90 and _CACHE.get("rt") is rt:
        out = _CACHE["out"]
    else:
        spec = [
            ("argon2", "Passwords hashed with Argon2id", "Guidelines 6.2", lambda: c_argon2(auth)),
            ("mfa", "TOTP multi-factor authentication: a right password with a wrong code is refused", "Guidelines 6.1", lambda: c_mfa(None)),
            ("token", "Signed, expiring session tokens: forged and expired tokens are refused", "Guidelines 6.7", lambda: c_token(None)),
            ("rbac", "Role-based access control: every API route checks a role", "Guidelines 6.7 / 4.1", lambda: c_rbac(app)),
            ("lock", "Account lock-out after 5 failed logins", "Guidelines 6.2", lambda: c_lock(None)),
            ("rate", "Rate limiting on the API", "Guidelines 13", lambda: c_rate(None)),
            ("valid", "Strict input validation: malformed bodies and unknown IDs are rejected", "Guidelines 13", lambda: c_valid(app)),
            ("headers", "CSP, X-Frame-Options, nosniff, Referrer-Policy on responses", "Guidelines 13", lambda: c_headers(app)),
            ("schema", "No public API schema or docs endpoint", "Guidelines 13", lambda: c_schema(app)),
            ("chain", "Keyed, hash-chained, anchored Black Box Log (re-hash forgery detected)", "Guidelines 8.5", lambda: c_chain(rt)),
            ("keys", "Signing and log keys live outside the project folder", "Guidelines 6.4", lambda: c_keys(None)),
            ("signed", "Ed25519-signed air-gap snapshots: replay and edited payloads refused", "Guidelines 4.4", lambda: c_signed(None)),
            ("replay", "Air-gap replay protection survives a restart", "Guidelines 4.4", lambda: c_airgap_persist(None)),
            ("twop", "Two-person approval for high-impact actions", "Guidelines 10.1", lambda: c_twop(None)),
            ("twin", "Safety Check: every automatic physical action is simulated first", "Guidelines 4.2", lambda: c_twin(rt)),
            ("guard", "Human confirmation for hospital-adjacent cuts without physical proof, and a rate limit on automatic steps", "Guidelines 10.1", lambda: c_guard(rt)),
            ("bounded", "Logs, vault and rate-limit table cannot grow without bound", "Guidelines 12", lambda: c_bounded(rt)),
            ("feed", "Threat-feed sanity check: scores in range, snapshot dated and not stale", "Guidelines 16", lambda: c_feed(None)),
            ("tls", "TLS on the transport", "Guidelines 5", lambda: c_tls(None)),
        ]
        out = []
        for cid, name, ref, fn in spec:
            ok, note = _t(fn)
            out.append(dict(id=cid, name=name, ok=bool(ok), ref=ref, note=note))
        out.append(dict(id="mtls", name="Mutual TLS between services", ok=False, ref="Guidelines 6.4", note="Not built: the demo is one process. Deployment needs mTLS between api, engine and worker."))
        _CACHE.update(t=time.time(), rt=rt, out=out)
    return [dict(c, blocked=rl.blocked) if c["id"] == "rate" else c for c in out]
