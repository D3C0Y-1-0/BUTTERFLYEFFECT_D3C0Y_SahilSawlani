"""Black Box Log (hash-chained, tamper-evident), Log Vault (180-day rolling retention, India-local file store), Time Guard."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .city import DATA

RETENTION_DAYS = 180   # CERT-In Directions 28 Apr 2022 / Guidelines ch. 12 and 8.5
VAULT_DIR = DATA / "vault"
VAULT_MAX_BYTES = int(float(os.environ.get("ATHENA_VAULT_MAX_GB", "2")) * 1e9)   # size budget on top of the 180-day rule


KEY_DIR = Path(os.environ.get("ATHENA_KEY_DIR", str(Path.home() / ".athena")))      # secrets live OUTSIDE the project/data folder (separate trust domain; in production an HSM or another host)
ANCHOR_PATH = Path(os.environ.get("ATHENA_ANCHOR_PATH", str(KEY_DIR / "log_anchor.jsonl")))   # in production: a write-once / off-box target (WORM bucket, remote syslog)
LOG_DIR = DATA / "blackbox"
MEM_WINDOW = 5000        # entries kept in memory; the full history is on disk
ANCHOR_EVERY = 50        # entries between anchors


def _h(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()


def load_key(name: str) -> bytes:
    """A 32-byte secret kept in KEY_DIR, created on first use (owner-only permissions where the OS supports it)."""
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    f = KEY_DIR / name
    if f.exists():
        return f.read_bytes()
    k = os.urandom(32)
    f.write_bytes(k)
    try:
        os.chmod(f, 0o600)
    except OSError:
        pass
    return k


class BlackBox:
    """Every state change is appended with the hash of the previous entry AND an HMAC of that hash under a key the log file does not contain.
    Editing an entry and re-hashing the chain no longer works without the key; deleting the tail or replacing the whole log is caught by the external anchor.
    Memory is capped (a window of recent entries); the full history is written to disk when persist=True. Honest limit: an attacker with root on this machine AND
    the key directory can forge entries; the anchor target must be a separate write-once store for that case."""

    def __init__(self, persist: bool = False, key: bytes | None = None, anchor_path: Path | None = None, log_dir: Path | None = None):
        self.entries: deque = deque(maxlen=MEM_WINDOW)
        self.lock = threading.Lock()
        self.persist = persist
        self.key = key if key is not None else (load_key("log_hmac.key") if persist else os.urandom(32))
        self.anchor_path = anchor_path or ANCHOR_PATH
        self.log_dir = log_dir or LOG_DIR
        self.count = 0
        self.head = "0" * 64
        self.anchors: dict[int, str] = {}
        self._fh = None
        self._verified = dict(upto=-1, head="0" * 64, ok=True)     # incremental verification checkpoint
        if persist:
            self._load()

    # ------------------------------------------------------------ storage
    def _mac(self, h: str) -> str:
        return hmac.new(self.key, h.encode(), hashlib.sha256).hexdigest()

    def _load(self):
        self.log_dir.mkdir(parents=True, exist_ok=True)
        f = self.log_dir / "log.jsonl"
        if f.exists():
            with open(f, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    self.entries.append(e)
                    self.count = e["i"] + 1
                    self.head = e["hash"]
        if self.anchor_path.exists():
            for line in self.anchor_path.read_text(encoding="utf-8").splitlines():
                try:
                    a = json.loads(line)
                    self.anchors[a["i"]] = a["hash"]
                except (ValueError, KeyError):
                    continue
        self._fh = open(f, "a", encoding="utf-8")

    def _anchor(self, e):
        self.anchors[e["i"]] = e["hash"]
        if self.persist:
            try:
                self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.anchor_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(dict(i=e["i"], hash=e["hash"])) + "\n")
            except OSError:
                pass

    def append(self, kind: str, data: dict, sim_minute: int | None = None, actor: str = "system"):
        with self.lock:
            body = dict(i=self.count, ts=datetime.now(timezone.utc).isoformat(timespec="seconds"), sim_minute=sim_minute, kind=kind, actor=actor, data=data)
            h = _h(self.head, body)
            e = dict(body, prev=self.head, hash=h, mac=self._mac(h))
            self.entries.append(e)
            self.head = h
            self.count += 1
            if self._fh is not None:
                self._fh.write(json.dumps(e, separators=(",", ":")) + "\n")
                self._fh.flush()
            if e["i"] % ANCHOR_EVERY == 0:
                self._anchor(e)
        return e

    # ------------------------------------------------------------ verification
    def verify_entries(self, entries, anchors=None):
        """Chain linkage + HMAC for every entry; entries must agree with any anchor recorded for their index; the log must not be shorter than the last anchor."""
        anchors = self.anchors if anchors is None else anchors
        prev = None
        for e in entries:
            body = {k: e[k] for k in ("i", "ts", "sim_minute", "kind", "actor", "data")}
            if (prev is not None and e["prev"] != prev) or e["hash"] != _h(e["prev"], body) or not hmac.compare_digest(e.get("mac", ""), self._mac(e["hash"])):
                return dict(ok=False, broken_at=e["i"], checked=len(entries), reason="entry edited, re-ordered or forged")
            if e["i"] in anchors and anchors[e["i"]] != e["hash"]:
                return dict(ok=False, broken_at=e["i"], checked=len(entries), reason="does not match the external anchor")
            prev = e["hash"]
        if entries and anchors and max(anchors) > entries[-1]["i"]:
            return dict(ok=False, broken_at=entries[-1]["i"], checked=len(entries), reason="log is shorter than the external anchor (tail removed)")
        return dict(ok=True, broken_at=None, checked=len(entries), head=(prev or self.head)[:16])

    def verify(self, full: bool = False):
        """Only entries added since the last good check are re-hashed (unless full=True); the lock is held just long enough to copy them."""
        with self.lock:
            cp = self._verified
            window = list(self.entries)
            anchors = dict(self.anchors)
        if full or cp["upto"] < 0 or not window or window[0]["i"] > cp["upto"] + 1:
            todo = window
        else:
            todo = [e for e in window if e["i"] > cp["upto"]]
            if todo and todo[0]["prev"] != cp["head"]:
                todo = window
        if not todo:
            return dict(ok=cp["ok"], broken_at=None, checked=0, head=cp["head"][:16], incremental=True)
        r = self.verify_entries(todo, anchors)
        if r["ok"]:
            self._verified = dict(upto=todo[-1]["i"], head=todo[-1]["hash"], ok=True)
        r["incremental"] = (not full) and todo is not window
        return r

    def tamper_demo(self):
        """Two attacks on a COPY of the log (the live log is untouched): (1) edit an entry only, (2) edit an entry and re-hash the whole chain without the key."""
        with self.lock:
            copy = json.loads(json.dumps(list(self.entries)[-300:]))
        if len(copy) < 3:
            return dict(before=dict(ok=True), after=dict(ok=True), note="not enough entries")
        before = self.verify_entries(copy, {})
        k = len(copy) // 2
        copy[k]["data"] = dict(copy[k]["data"], tampered=True)
        after = self.verify_entries(copy, {})
        prev = copy[0]["prev"]
        for e in copy:      # the cleverer forger: recompute every hash so the chain links again; they do not have the HMAC key
            body = {kk: e[kk] for kk in ("i", "ts", "sim_minute", "kind", "actor", "data")}
            e["prev"] = prev
            e["hash"] = _h(prev, body)
            prev = e["hash"]
        rehashed = self.verify_entries(copy, {})
        return dict(before=before, after=after, rehashed=rehashed, edited_entry=copy[k]["i"])

    def tail(self, n=40):
        with self.lock:
            return list(self.entries)[-n:]


class LogVault:
    """Raw events kept 180 days on India-local disk, then deleted. Daily JSONL files."""

    def __init__(self):
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.written = 0
        self.prune()

    def write(self, rec: dict):
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        if day != getattr(self, "day", day):
            self.prune()          # a new day began: compress yesterday, enforce retention and the size budget
        self.day = day
        with self.lock, open(VAULT_DIR / f"{day}.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
            self.written += 1

    def prune(self):
        """Delete days past retention, gzip every day before today (about 10x smaller), and keep the whole vault under a size budget by dropping the oldest days first."""
        import gzip
        import shutil
        cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        removed = 0
        for f in list(VAULT_DIR.glob("*.jsonl")) + list(VAULT_DIR.glob("*.jsonl.gz")):
            stem = f.name.split(".")[0]
            try:
                d = datetime.strptime(stem, "%Y%m%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if d < cutoff:
                f.unlink()
                removed += 1
            elif f.suffix == ".jsonl" and stem != today:
                with open(f, "rb") as src, gzip.open(str(f) + ".gz", "wb") as dst:
                    shutil.copyfileobj(src, dst)
                f.unlink()
        files = sorted(VAULT_DIR.glob("*.jsonl*"))
        total = sum(x.stat().st_size for x in files)
        while total > VAULT_MAX_BYTES and len(files) > 1:
            total -= files[0].stat().st_size
            files.pop(0).unlink()
            removed += 1
        return removed

    def status(self):
        files = sorted(VAULT_DIR.glob("*.jsonl*"))
        days = 0
        if files:
            first = datetime.strptime(files[0].name.split(".")[0], "%Y%m%d").replace(tzinfo=timezone.utc)
            days = (datetime.now(timezone.utc) - first).days + 1
        size = sum(f.stat().st_size for f in files)
        return dict(retention_days=RETENTION_DAYS, days_held=days, files=len(files), bytes=size, jurisdiction="India (local disk)", written=self.written)


class TimeGuard:
    """Compares every source clock with the reference (NIC/NPL NTP in production) and flags drift."""

    def __init__(self, sources):
        self.skew = {s: 0.0 for s in sources}
        self.threshold = 5.0

    def set_skew(self, source, seconds):
        if source in self.skew:
            self.skew[source] = float(seconds)

    def status(self):
        bad = {s: v for s, v in self.skew.items() if abs(v) > self.threshold}
        return dict(reference="NIC / NPL NTP (simulated reference)", threshold_s=self.threshold, drifting=bad, ok=not bad,
                    sources={s: round(v, 1) for s, v in self.skew.items()})

    def uncertain(self, source):
        return abs(self.skew.get(source, 0.0)) > self.threshold
