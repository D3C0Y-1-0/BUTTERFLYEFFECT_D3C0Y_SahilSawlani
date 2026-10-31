"""Zero-day ingestion and library.

A zero-day is an exploit for a *product* that no CVE record, EPSS score or signature covers. The lab introduces them
(random or chosen), the defender never sees the product list. Handling = detect behaviour -> extract a fingerprint ->
analyse the sample -> deploy a behavioural rule fleet-wide for every device of that product (the "family rule").
Until the rule exists, a classic virtual patch only partly helps (no signature to match).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

EXPLOITS = {
    "rce": "Remote code execution in the device firmware",
    "auth_bypass": "Authentication bypass on the management service",
    "protocol_abuse": "Malformed industrial-protocol request that hands over control",
}
P_ZD = 0.85          # chance the exploit works on a device of the affected product
VP_PRE = 0.70        # virtual patch before the family rule is known: only 30% of attempts stopped (no signature)
VP_POST = 0.15       # after the family rule: 85% stopped


def product_key(asset) -> str:
    return f"{asset['vendor']} {asset['model']}"


def products(ward) -> dict[str, list[str]]:
    g: dict[str, list[str]] = {}
    for nid, a in ward["assets"].items():
        if nid == "INTERNET":
            continue
        g.setdefault(product_key(a), []).append(nid)
    return g


@dataclass
class ZeroDay:
    id: str
    product: str
    affected: list
    exploit: str = "rce"
    p: float = P_ZD
    minute: int = 0
    held_out: bool = False

    def public(self):
        return dict(id=self.id, product=self.product, affected=self.affected, exploit=self.exploit, exploit_text=EXPLOITS[self.exploit], minute=self.minute)


_n = 0


def random_zero_day(ward, rng, products_allowed=None, exploit=None, minute=0) -> ZeroDay:
    global _n
    g = products(ward)
    keys = [k for k in g if (products_allowed is None or k in products_allowed)]
    key = str(rng.choice(keys))
    _n += 1
    return ZeroDay(id=f"ZD-{_n:04d}", product=key, affected=list(g[key]), exploit=exploit or str(rng.choice(list(EXPLOITS))), minute=minute)


def split_products(ward, seed=11, test_frac=0.3):
    """Fixed train / held-out split of products so evaluation uses zero-days the policy never trained on."""
    keys = sorted(products(ward))
    rng = np.random.default_rng(seed)
    rng.shuffle(keys)
    k = max(3, int(len(keys) * test_frac))
    return sorted(keys[k:]), sorted(keys[:k])


@dataclass
class Library:
    """What the defender has learned about zero-day families."""
    records: dict = field(default_factory=dict)     # product -> record

    def seen(self, product):
        return product in self.records

    def learned(self, product):
        r = self.records.get(product)
        return bool(r and r.get("learned_minute") is not None)

    def add(self, product, minute, fingerprint, nodes):
        self.records.setdefault(product, dict(family=f"FAM-{len(self.records)+1:03d}", first_seen=minute, learned_minute=None, fingerprint=fingerprint, nodes=nodes, blocked_devices=0))
        return self.records[product]

    def learn(self, product, minute, blocked):
        r = self.records.get(product)
        if r:
            r["learned_minute"], r["blocked_devices"] = minute, blocked

    def public(self):
        return [dict(product=k, **v) for k, v in self.records.items()]


def fingerprint(ward, evidence_edges, techniques, stealth_class, hops):
    """Behavioural fingerprint of an unknown exploit: which protocols/techniques/zones it used, not a byte signature."""
    protos = sorted({ward["edges"][i]["protocol"] for i in evidence_edges}) if evidence_edges else []
    return dict(protocols=protos, techniques=sorted(set(techniques)), stealth=stealth_class, hops=hops)
