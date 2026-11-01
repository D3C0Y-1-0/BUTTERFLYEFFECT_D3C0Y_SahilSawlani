"""The two responses, both reversible. Stage 1 protects the service (a per-source rate limit inside the demo service). Stage 2 cuts the source (Windows Firewall inbound block rule).
Safety: only private-network addresses can be blocked, never this laptop, the gateway or anything on the safe list; at most 3 rules; every rule expires."""
import ctypes
import ipaddress
import subprocess
import threading
import time


class RateLimiter:
    """Token bucket per source, shared with the demo service. No entry means no limit."""

    def __init__(self):
        self.limits, self.tokens, self.lock = {}, {}, threading.Lock()
        self.served, self.dropped = {}, {}

    def set(self, ip, rate):
        with self.lock:
            self.limits[ip] = rate

    def clear(self, ip=None):
        with self.lock:
            if ip is None:
                self.limits.clear()
            else:
                self.limits.pop(ip, None)

    def allow(self, ip):
        with self.lock:
            r = self.limits.get(ip)
            now = time.time()
            if r is None:
                self.served[ip] = self.served.get(ip, 0) + 1
                return True
            tok, last = self.tokens.get(ip, (r, now))
            tok = min(r, tok + (now - last) * r)
            if tok >= 1:
                self.tokens[ip] = (tok - 1, now)
                self.served[ip] = self.served.get(ip, 0) + 1
                return True
            self.tokens[ip] = (tok, now)
            self.dropped[ip] = self.dropped.get(ip, 0) + 1
            return False


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class Firewall:
    def __init__(self, safe=(), dry_run=False, max_rules=3):
        self.safe, self.dry, self.max, self.rules = set(safe), dry_run, max_rules, {}

    def can_block(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False, "not an address"
        if not a.is_private or a.is_loopback:
            return False, "not a private-network address; a person must decide"
        if ip in self.safe:
            return False, "on the safe list (this laptop or the gateway)"
        if len(self.rules) >= self.max:
            return False, f"already {self.max} rules active"
        return True, ""

    def _run(self, args):
        if self.dry:
            return True, "dry run"
        r = subprocess.run(args, capture_output=True, text=True, shell=False)
        return r.returncode == 0, (r.stdout + r.stderr).strip()[:200]

    def block(self, ip, hold_s=600):
        ok, why = self.can_block(ip)
        if not ok:
            return False, why
        name = f"ATHENA-BLOCK-{ip}"
        good, out = self._run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in", "action=block", f"remoteip={ip}", "enable=yes"])
        if good:
            self.rules[ip] = dict(name=name, since=time.time(), expires=time.time() + hold_s)
        return good, out

    def unblock(self, ip):
        name = f"ATHENA-BLOCK-{ip}"
        good, out = self._run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
        self.rules.pop(ip, None)
        return good, out

    def expired(self):
        return [ip for ip, r in list(self.rules.items()) if r["expires"] < time.time()]
