"""Black Box Log (hash-chained, tamper-evident), Log Vault (180-day rolling retention, India-local file store), Time Guard."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .city import DATA

RETENTION_DAYS = 180   # CERT-In Directions 28 Apr 2022 / Guidelines ch. 12 and 8.5
VAULT_DIR = DATA / "vault"


def _h(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()


class BlackBox:
    """Every state change is appended with the hash of the previous entry. Editing any entry breaks the chain."""

    def __init__(self):
        self.entries: list[dict] = []
        self.lock = threading.Lock()
        self.head = "0" * 64

    def append(self, kind: str, data: dict, sim_minute: int | None = None, actor: str = "system"):
        with self.lock:
            body = dict(i=len(self.entries), ts=datetime.now(timezone.utc).isoformat(timespec="seconds"), sim_minute=sim_minute, kind=kind, actor=actor, data=data)
            h = _h(self.head, body)
            e = dict(body, prev=self.head, hash=h)
            self.entries.append(e)
            self.head = h
        return e

    @staticmethod
    def verify_entries(entries):
        prev = "0" * 64
        for e in entries:
            body = {k: e[k] for k in ("i", "ts", "sim_minute", "kind", "actor", "data")}
            if e["prev"] != prev or e["hash"] != _h(prev, body):
                return dict(ok=False, broken_at=e["i"], checked=len(entries))
            prev = e["hash"]
        return dict(ok=True, broken_at=None, checked=len(entries), head=prev[:16])

    def verify(self):
        with self.lock:
            return self.verify_entries(list(self.entries))

    def tamper_demo(self):
        """Edit one entry in a COPY and show that verification fails (the live log is untouched)."""
        with self.lock:
            copy = json.loads(json.dumps(self.entries))
        if len(copy) < 3:
            return dict(before=dict(ok=True), after=dict(ok=True), note="not enough entries")
        before = self.verify_entries(copy)
        k = len(copy) // 2
        copy[k]["data"] = dict(copy[k]["data"], tampered=True)
        after = self.verify_entries(copy)
        return dict(before=before, after=after, edited_entry=k)

    def tail(self, n=40):
        with self.lock:
            return list(self.entries[-n:])


class LogVault:
    """Raw events kept 180 days on India-local disk, then deleted. Daily JSONL files."""

    def __init__(self):
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.written = 0
        self.prune()

    def write(self, rec: dict):
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        with self.lock, open(VAULT_DIR / f"{day}.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
            self.written += 1

    def prune(self):
        cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
        removed = 0
        for f in VAULT_DIR.glob("*.jsonl"):
            try:
                d = datetime.strptime(f.stem, "%Y%m%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if d < cutoff:
                f.unlink()
                removed += 1
        return removed

    def status(self):
        files = sorted(VAULT_DIR.glob("*.jsonl"))
        days = 0
        if files:
            first = datetime.strptime(files[0].stem, "%Y%m%d").replace(tzinfo=timezone.utc)
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
