"""Automated security tests for ATHENA itself (experiment E14). Writes data/security_tests.json.

Run: python backend/security_tests.py
"""
import json
import subprocess
import sys
import time
from pathlib import Path

import pyotp

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fastapi.testclient import TestClient  # noqa: E402

from decoy import api  # noqa: E402
from decoy.blackbox import BlackBox  # noqa: E402

results = []


def check(name, cond, detail=""):
    results.append(dict(name=name, passed=bool(cond), detail=str(detail)[:160]))
    print(("PASS " if cond else "FAIL ") + name, detail if not cond else "")


with TestClient(api.app) as c:
    auth = api.state["auth"]
    hint = {a["user"]: a for a in auth.hint()}

    def login(u):
        a = hint[u]
        r = c.post("/api/auth/login", json=dict(username=u, password=a["password"], totp=pyotp.TOTP(auth.users[u]["totp"]).now()))
        return r.json().get("token") if r.status_code == 200 else None

    H = lambda t: {"Authorization": "Bearer " + t}
    adm, ope, ana, exe = login("admin"), login("operator"), login("analyst"), login("executive")
    check("all four demo accounts can log in with password + TOTP", all([adm, ope, ana, exe]))

    # --- authentication
    check("no token -> 401", c.get("/api/static").status_code == 401)
    check("garbage token -> 401", c.get("/api/static", headers=H("abc.def")).status_code == 401)
    body, sig = adm.split(".")
    check("tampered token signature -> 401", c.get("/api/static", headers=H(body + "." + "0" * len(sig))).status_code == 401)
    check("expired token -> 401", c.get("/api/static", headers=H(auth.token("admin", "admin", ttl=-5))).status_code == 401)
    check("role claim cannot be forged (body edited, signature kept)", c.get("/api/static", headers=H(__import__("base64").urlsafe_b64encode(json.dumps(dict(sub="x", role="admin", exp=9999999999)).encode()).decode() + "." + sig)).status_code == 401)
    r = c.post("/api/auth/login", json=dict(username="admin", password="wrong-password", totp="123456"))
    check("wrong password -> 401", r.status_code == 401)
    r = c.post("/api/auth/login", json=dict(username="admin", password=hint["admin"]["password"], totp="000000"))
    check("correct password but wrong MFA code -> 401", r.status_code == 401)
    for _ in range(6):
        r = c.post("/api/auth/login", json=dict(username="analyst", password="nope-nope", totp="111111"))
    check("lock-out after repeated failures", r.status_code == 401 and "locked" in r.json().get("detail", ""), r.text)
    check("input validation on login (bad username chars) -> 422", c.post("/api/auth/login", json=dict(username="admin' OR 1=1--", password="x", totp="123456")).status_code == 422)

    # --- authorisation (RBAC / BFLA)
    check("executive cannot launch attacks (403)", c.post("/api/attack", headers=H(exe), json=dict(mode="standard")).status_code == 403)
    check("analyst cannot approve proposals (403)", c.post("/api/proposal/P001/approve", headers=H(ana)).status_code == 403)
    check("operator cannot reset or tamper (403)", c.post("/api/reset", headers=H(ope)).status_code == 403 and c.get("/api/blackbox/tamper", headers=H(ope)).status_code == 403)
    check("only admin may enable full autonomy (403 for operator)", c.post("/api/autonomy", headers=H(ope), json=dict(mode="auto_all")).status_code == 403)
    check("executive can read risk (200)", c.get("/api/risk", headers=H(exe)).status_code == 200)

    # --- input validation
    check("unknown attack mode -> 422", c.post("/api/attack", headers=H(adm), json=dict(mode="rm -rf")).status_code == 422)
    check("injection-style entry id -> 422", c.post("/api/attack", headers=H(adm), json=dict(mode="standard", entry="VPN_VENDOR; DROP TABLE")).status_code == 422)
    check("unknown asset id -> 422", c.post("/api/attack", headers=H(adm), json=dict(mode="standard", entry="NOPE")).status_code == 422)
    check("out-of-range stealth -> 422", c.post("/api/attack", headers=H(adm), json=dict(mode="standard", stealth=999)).status_code == 422)
    check("executive cannot introduce zero-days (403)", c.post("/api/zeroday", headers=H(exe), json=dict(mode="standard")).status_code == 403)
    check("zero-day product name is validated (injection -> 422)", c.post("/api/zeroday", headers=H(adm), json=dict(product="x'; DROP TABLE users;--")).status_code == 422)
    check("unknown zero-day product rejected (422)", c.post("/api/zeroday", headers=H(adm), json=dict(product="Nonexistent Vendor Box")).status_code == 422)
    check("unknown exploit class rejected (422)", c.post("/api/zeroday", headers=H(adm), json=dict(exploit="rootkit")).status_code == 422)
    check("responder mode is validated (422)", c.post("/api/responder", headers=H(adm), json=dict(mode="skynet")).status_code == 422)
    check("analyst cannot change the responder (403)", c.post("/api/responder", headers=H(ana), json=dict(mode="search")).status_code == 403)
    check("what-if rejects unsafe characters", c.get("/api/whatif?fix=../../etc/passwd", headers=H(adm)).status_code == 422)
    check("timeline rejects unknown action", c.get("/api/timeline?actions=NOPE", headers=H(adm)).status_code == 422)

    # --- surface hygiene
    check("no public API docs / schema", all(("swagger" not in c.get(p).text.lower() and "openapi" not in c.get(p).text.lower()) for p in ("/docs", "/redoc", "/openapi.json")))
    r = c.get("/api/static", headers=H(adm))
    check("security headers present (CSP, X-Frame-Options, nosniff, no-store)", all(k in r.headers for k in ("content-security-policy", "x-frame-options", "x-content-type-options")) and r.headers.get("cache-control") == "no-store")
    r = c.get("/api/static", headers={**H(adm), "Origin": "https://evil.example"})
    check("CORS does not allow a foreign origin", r.headers.get("access-control-allow-origin") in (None, ""))
    r = c.get("/..%2f..%2fbackend%2fdecoy%2fapi.py")
    check("path traversal does not leak source files", "FastAPI" not in r.text)

    # --- rate limit
    got = [c.get("/api/me", headers=H(exe)).status_code for _ in range(220)]
    check("rate limiting returns 429 under a request flood", 429 in got)
    time.sleep(3)

    # --- integrity
    bb = BlackBox()
    for i in range(12):
        bb.append("t", dict(i=i))
    before = bb.verify()
    t = bb.tamper_demo()
    check("hash chain intact, and a tampered copy is detected", before["ok"] and t["before"]["ok"] and not t["after"]["ok"])
    ex = c.get("/api/airgap/export", headers=H(adm)).json()
    r1 = c.post("/api/airgap/import", headers=H(adm), json=ex).json()
    r2 = c.post("/api/airgap/import", headers=H(adm), json=ex).json()
    check("signed air-gap import accepted once", r1["ok"])
    check("replayed air-gap snapshot rejected (version counter)", not r2["ok"], r2)
    ex2 = c.get("/api/airgap/export", headers=H(adm)).json()
    ex2["payload"]["assets"][0]["cve"] = "TAMPERED"
    check("tampered air-gap snapshot rejected", not c.post("/api/airgap/import", headers=H(adm), json=ex2).json()["ok"])
    ex3 = c.get("/api/airgap/export", headers=H(adm)).json()
    ex3["public_key"] = "A" * 43 + "="
    check("snapshot signed by an unknown key rejected", not c.post("/api/airgap/import", headers=H(adm), json=ex3).json()["ok"])

    # --- websocket: token in the first message, caps, shared frames
    from starlette.websockets import WebSocketDisconnect as _WSD
    with c.websocket_connect("/ws") as w:
        w.send_text(json.dumps(dict(token=exe)))
        check("websocket streams after a first-message token", "services" in json.loads(w.receive_text()))
    try:
        with c.websocket_connect("/ws?token=" + exe) as w:
            w.send_text("{}")
            w.receive_text()
        check("a token in the URL no longer works", False)
    except _WSD:
        check("a token in the URL no longer works", True)
    socks = []
    refused = 0
    try:
        for _i in range(api.WS_PER_USER + 1):
            cm = c.websocket_connect("/ws"); w = cm.__enter__(); socks.append(cm); w.send_text(json.dumps(dict(token=ope)))
            try:
                w.receive_text()
            except _WSD:
                refused += 1
    finally:
        for cm in socks:
            try:
                cm.__exit__(None, None, None)
            except Exception:
                pass
    check("per-user websocket cap refuses the extra connection", refused == 1, refused)

    # --- the security page is measured, not asserted
    sec = c.get("/api/security", headers=H(exe)).json()["controls"]
    bad = [x["id"] for x in sec if not x["ok"] and x["id"] not in ("tls", "mtls")]
    check("every measured control on the Security page passes its own check", not bad, bad)
    check("the Security page honestly reports what is not built (mTLS)", any(x["id"] == "mtls" and not x["ok"] for x in sec))

passed = sum(r["passed"] for r in results)
summary = f"{passed}/{len(results)} automated security tests passed"

# --- static analysis and dependency audit (best effort)
extra = {}
try:
    out = subprocess.run([sys.executable, "-m", "bandit", "-r", str(ROOT / "backend" / "decoy"), "-q", "-f", "json"], capture_output=True, text=True, timeout=300)
    j = json.loads(out.stdout or "{}")
    sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for it in j.get("results", []):
        sev[it["issue_severity"]] += 1
    extra["bandit"] = dict(sev, issues=[dict(test=i["test_id"], sev=i["issue_severity"], file=Path(i["filename"]).name, line=i["line_number"], text=i["issue_text"][:90]) for i in j.get("results", [])][:12])
except Exception as e:
    extra["bandit"] = dict(error=str(e)[:100])
try:
    out = subprocess.run([sys.executable, "-m", "pip_audit", "-f", "json", "--progress-spinner", "off"], capture_output=True, text=True, timeout=300)
    j = json.loads(out.stdout or "{}")
    vulns = [d for d in j.get("dependencies", []) if d.get("vulns")]
    extra["pip_audit"] = dict(packages_with_known_vulns=len(vulns), names=[d["name"] for d in vulns][:10])
except Exception as e:
    extra["pip_audit"] = dict(error=str(e)[:100])
if "bandit" in extra and "HIGH" in extra["bandit"]:
    summary += f" · bandit: {extra['bandit']['HIGH']} high / {extra['bandit']['MEDIUM']} medium / {extra['bandit']['LOW']} low"
if "pip_audit" in extra and "packages_with_known_vulns" in extra["pip_audit"]:
    summary += f" · pip-audit: {extra['pip_audit']['packages_with_known_vulns']} packages with known CVEs"
(ROOT / "data" / "security_tests.json").write_text(json.dumps(dict(results=results, summary=summary, extra=extra, generated=time.strftime("%Y-%m-%d %H:%M:%S")), indent=1), encoding="utf-8")
print(summary)
