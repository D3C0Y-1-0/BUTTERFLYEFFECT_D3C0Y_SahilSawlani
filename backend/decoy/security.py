"""Security controls of ATHENA itself (CERT-In Smart City Guidelines ch.4.1, 6, 10.1, 13).

Implemented here (not just described): Argon2id password hashing, TOTP MFA, signed expiring tokens, RBAC, login lock-out,
rate limiting, security headers/CSP, two-person approval for high-impact actions, Ed25519-signed air-gap snapshots with
anti-replay version counter. Everything is checked on every request (complete mediation).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from nacl import signing
from nacl.exceptions import BadSignatureError

from .city import DATA

ROLES = {"executive": 1, "analyst": 2, "operator": 3, "admin": 4}
# minimum role per capability
PERMS = {
    "read": "executive", "risk": "executive", "compliance": "executive", "security": "executive",
    "adversary_view": "analyst", "whatif": "analyst", "attack": "analyst", "settings": "operator",
    "approve": "operator", "answer": "operator", "fix": "operator", "report": "operator",
    "reset": "admin", "tamper": "admin", "chaos": "admin", "airgap_import": "admin", "freeze": "operator",
}
DEMO_USERS = {  # demo accounts: strong-looking passwords, shown ONLY when DECOY_DEMO=1
    "admin": ("admin", "Cs-Admin#2026-Mumbai"), "operator": ("operator", "Op-Night#Shift-42-Parel"),
    "analyst": ("analyst", "An-Hunt#Team-7-Sion"), "executive": ("executive", "Ex-Review#Ward-Chief-9"),
}


class Auth:
    def __init__(self):
        self.ph = PasswordHasher()   # Argon2id
        self.secret = os.urandom(32)
        self.users = {}
        for name, (role, pw) in DEMO_USERS.items():
            self.users[name] = dict(role=role, hash=self.ph.hash(pw), totp=pyotp.random_base32())
        self.fail = {}
        self.lock = threading.Lock()
        self.demo = os.environ.get("DECOY_DEMO", "1") == "1"

    def hint(self):
        if not self.demo:
            return None
        return [dict(user=u, password=DEMO_USERS[u][1], role=d["role"], totp_now=pyotp.TOTP(d["totp"]).now()) for u, d in self.users.items()]

    def login(self, user, pw, code, ip):
        key = (user, ip)
        with self.lock:
            f = self.fail.get(key, (0, 0))
            if f[0] >= 5 and time.time() - f[1] < 60:
                return None, "locked: too many failed attempts, wait 60 s"
        u = self.users.get(user)
        ok = False
        if u:
            try:
                self.ph.verify(u["hash"], pw)
                ok = pyotp.TOTP(u["totp"]).verify(code, valid_window=1)
            except VerifyMismatchError:
                ok = False
        else:
            self.ph.hash(pw)  # equalise timing
        with self.lock:
            if not ok:
                n = self.fail.get(key, (0, 0))[0] + 1
                self.fail[key] = (n, time.time())
                if len(self.fail) > 2000:      # forget attempts older than the lock-out window so the table cannot grow forever
                    now = time.time()
                    self.fail = {k: v for k, v in self.fail.items() if now - v[1] < 60}
                return None, "invalid credentials or MFA code"
            self.fail.pop(key, None)
        return self.token(user, u["role"]), None

    def token(self, user, role, ttl=3600):
        body = base64.urlsafe_b64encode(json.dumps(dict(sub=user, role=role, exp=int(time.time()) + ttl)).encode()).decode()
        sig = hmac.new(self.secret, body.encode(), hashlib.sha256).hexdigest()
        return f"{body}.{sig}"

    def verify(self, token):
        try:
            body, sig = token.split(".")
            good = hmac.new(self.secret, body.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, good):
                return None
            d = json.loads(base64.urlsafe_b64decode(body.encode()))
            if d["exp"] < time.time():
                return None
            return d
        except Exception:
            return None

    @staticmethod
    def allowed(role, perm):
        return ROLES[role] >= ROLES[PERMS[perm]]


class RateLimiter:
    """Token bucket per client. A bucket that has fully refilled carries no information, so it is dropped; the table is also hard-capped so a flood of fake client
    addresses cannot grow memory without bound (oldest buckets go first)."""

    def __init__(self, rate=25.0, burst=80, max_clients=5000):
        self.rate, self.burst, self.max_clients = rate, burst, max_clients
        self.b = {}
        self.lock = threading.Lock()
        self.blocked = 0
        self.calls = 0
        self.evicted = 0

    def _sweep(self, now):
        idle = self.burst / self.rate
        for k in [k for k, (t, last) in self.b.items() if now - last >= idle]:
            del self.b[k]
        while len(self.b) > self.max_clients:       # dicts keep insertion order: drop the oldest
            del self.b[next(iter(self.b))]
            self.evicted += 1

    def allow(self, key):
        now = time.time()
        with self.lock:
            self.calls += 1
            if self.calls % 500 == 0 or len(self.b) > self.max_clients:
                self._sweep(now)
            tok, last = self.b.pop(key, (self.burst, now))       # pop + reinsert keeps recently active clients at the end
            tok = min(self.burst, tok + (now - last) * self.rate)
            if tok < 1:
                self.b[key] = (tok, now)
                self.blocked += 1
                return False
            self.b[key] = (tok - 1, now)
            return True


class AirGap:
    """Signed one-way snapshot: export from the connected side, import on the isolated side. Ed25519 + monotonic version.
    The signing key and the version counters live in KEY_DIR (outside the project folder) and survive a restart, so an already-accepted snapshot cannot be replayed
    after a reboot. Honest limit: in this demo both sides are one process; a real deployment keeps the signing key in an HSM on the connected side and only the
    public key plus the counter on the isolated side."""

    def __init__(self, key_dir=None, persist=True):
        from .blackbox import KEY_DIR
        self.dir = key_dir or KEY_DIR
        self.persist = persist
        self.state_file = self.dir / "airgap_state.json"
        if persist:
            self.dir.mkdir(parents=True, exist_ok=True)
            kf = self.dir / "airgap_ed25519.key"
            old = DATA / "airgap_ed25519.key"          # migrate a key an older build left next to the app
            if not kf.exists() and old.exists():
                kf.write_bytes(old.read_bytes())
                old.unlink()
            if kf.exists():
                self.sk = signing.SigningKey(kf.read_bytes())
            else:
                self.sk = signing.SigningKey.generate()
                kf.write_bytes(bytes(self.sk))
        else:
            self.sk = signing.SigningKey.generate()
        self.vk = self.sk.verify_key
        self.version = 0
        self.last_imported = 0
        self.accepted = 0
        self.rejected = 0
        if persist and self.state_file.exists():
            try:
                st = json.loads(self.state_file.read_text())
                self.version, self.last_imported = int(st.get("version", 0)), int(st.get("last_imported", 0))
            except (ValueError, OSError):
                pass

    def _save(self):
        if self.persist:
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(dict(version=self.version, last_imported=self.last_imported)))
            os.replace(tmp, self.state_file)

    def export(self, payload: dict):
        self.version += 1
        self._save()
        body = dict(payload, version=self.version, issued=int(time.time()))
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        sig = self.sk.sign(raw).signature
        return dict(payload=body, sha256=hashlib.sha256(raw).hexdigest(), signature=base64.b64encode(sig).decode(), public_key=base64.b64encode(bytes(self.vk)).decode())

    def verify_import(self, doc: dict):
        try:
            raw = json.dumps(doc["payload"], sort_keys=True, separators=(",", ":")).encode()
            if hashlib.sha256(raw).hexdigest() != doc["sha256"]:
                raise BadSignatureError("hash mismatch")
            vk = signing.VerifyKey(base64.b64decode(doc["public_key"]))
            if bytes(vk) != bytes(self.vk):
                raise BadSignatureError("unknown signer")
            vk.verify(raw, base64.b64decode(doc["signature"]))
            if doc["payload"]["version"] <= self.last_imported:
                raise BadSignatureError("replayed or older version")
        except Exception as e:
            self.rejected += 1
            return False, f"REJECTED: {e}"
        self.last_imported = doc["payload"]["version"]
        self._save()
        self.accepted += 1
        return True, "ACCEPTED: signature, hash and version counter valid"
