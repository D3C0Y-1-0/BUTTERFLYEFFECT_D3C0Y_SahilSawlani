"""The defender's brain on laptop B. It sees ONLY what arrives at this laptop's network card (packet counts), learns what is normal, notices an anomaly, works out who and what,
chooses a response, applies it and checks that it worked, using the same method as the ATHENA Watchdog. It has no channel to the attacker and no knowledge of what the attacker runs.

Stages, each written as a real packet (see markers.py) so Wireshark shows them in order:
  BASELINE_LEARNED -> DETECTED -> PREDICTED -> ACTION rate_limit -> (still arriving?) ESCALATE -> ACTION block -> VERIFIED
"""
from __future__ import annotations

import time
from collections import deque

import numpy as np

from flowdetect import FlowDetector, new_window
from markers import emit
from responder import Firewall, RateLimiter

RL_RATE = 2.0          # requests per second a limited source may still get
RL_WAIT = 8            # seconds the rate limit gets to work before the source is cut
VERIFY_AFTER = 5       # seconds after a block before it is checked


class Engine:
    def __init__(self, local_ips=(), gateway=None, dry_run=False, learn_windows=90, hold_s=600, on_evidence=None):
        self.det = FlowDetector(learn_windows=learn_windows)
        self.limiter = RateLimiter()
        self.fw = Firewall(safe=set(local_ips) | ({gateway} if gateway else set()), dry_run=dry_run)
        self.hold_s, self.on_evidence = hold_s, on_evidence
        self.stage = "learning"
        self.events: deque = deque(maxlen=200)
        self.series: deque = deque(maxlen=240)
        self.inc: dict | None = None
        self.progress = 0.0

    # ------------------------------------------------------------ helpers
    def say(self, now, stage, **kw):
        text = emit(stage, **kw)
        self.events.append(dict(t=now, iso=time.strftime("%H:%M:%S", time.localtime(now)), stage=stage, text=text))

    @staticmethod
    def _pps(w, ip):
        return sum(c for k, c in w["flows"].items() if k[0] == ip)

    def reset(self, now=None):
        now = now or time.time()
        for ip in list(self.fw.rules):
            self.fw.unblock(ip)
        self.limiter.clear()
        self.inc = None
        self.stage = "watching" if self.det.ready else "learning"
        self.say(now, "RESET", note="rules removed, watching again")

    def undo(self, ip, now=None):
        now = now or time.time()
        self.fw.unblock(ip)
        self.limiter.clear(ip)
        self.say(now, "UNDO", source=ip, note="block removed by operator")

    # ------------------------------------------------------------ one window per second
    def process(self, w, now=None):
        now = now or time.time()
        for ip in self.fw.expired():
            self.fw.unblock(ip)
            self.say(now, "RELEASE", source=ip, note="block expired")
        blocked = set(self.fw.rules)
        raw_total = w["total"]
        if blocked:       # traffic from a source the firewall already drops is no longer a threat to this laptop; it is counted, not judged
            for k in [k for k in w["flows"] if k[0] in blocked]:
                n = w["flows"].pop(k)
                w["total"] -= n
        if not self.det.ready:
            self.progress = self.det.learn(w)
            self.stage = "learning"
            self._record(now, w, raw_total, None)
            if self.det.ready:
                self.stage = "watching"
                self.say(now, "BASELINE_LEARNED", windows=len(self.det.base), known_flows=self.det.calib["known_flows"], normal_max_p=self.det.calib["normal_max_p"])
            return
        busy = self.inc is not None
        r = self.det.observe(w, learn_ok=not busy)
        self._record(now, w, raw_total, r)
        if not busy:
            if r["alarm"]:
                self._detect(w, r, now)
        else:
            self._follow(w, r, now)

    def _record(self, now, w, raw_total, r):
        att = self.inc["attacker"] if self.inc else None
        self.series.append(dict(t=now, total=raw_total, syn=w["syn"], p=(r or {}).get("p", 0.0), cs=((r or {}).get("cusum", 0.0) / max((r or {}).get("cusum_line", 1.0), 1e-9)),
                                att=(self._pps(w, att) if att else 0), replies=(w["replies"].get(att, 0) if att else 0)))

    # ------------------------------------------------------------ detect -> predict -> respond
    def _detect(self, w, r, now):
        recent = [x for x in list(self.series)[-3:]]
        by_src = {}
        for k, c, z in r["top"]:
            by_src[k[0]] = by_src.get(k[0], 0) + max(z, 0)
        if not by_src:
            return
        att = max(by_src, key=by_src.get)
        keys = [k for k in w["flows"] if k[0] == att]
        ports = {k[1] for k in keys}
        pps = self._pps(w, att)
        if len(ports) >= 15:
            kind, port = "port scan", None
        else:
            port = max(keys, key=lambda k: w["flows"][k])[1] if keys else None
            kind = "request burst" if w.get("data", 0) >= 0.10 * max(pps, 1) else "connection flood (SYN flood)"
        self.inc = dict(attacker=att, kind=kind, port=port, t0=now, peak=pps, stage="rate_limit", stage_t=now, since_quiet=0)
        self.stage = "detected"
        self.say(now, "DETECTED", source=att, kind=kind, port=port or "many", p=round(r["p"], 2), pkts_per_s=int(pps), novelty=r["novelty"], zmax=round(r["zmax"], 1), cusum=round(r["cusum"], 1))
        nxt = f"keeps hitting port {port}" if port else "moves on to the ports it finds open"
        self.say(now, "PREDICTED", source=att, next_step=nxt, plan="rate-limit first, cut the source if it continues")
        self.limiter.set(att, RL_RATE)
        self.stage = "rate_limit"
        self.say(now, "ACTION", step="rate_limit", source=att, limit_per_s=RL_RATE, note="protects the service, traffic still arrives")

    def _follow(self, w, r, now):
        inc = self.inc
        att = inc["attacker"]
        pps = self._pps(w, att)
        inc["peak"] = max(inc["peak"], pps)
        inc["since_quiet"] = inc["since_quiet"] + 1 if pps < 2 and att not in self.fw.rules else 0
        if inc["since_quiet"] >= 10 and inc["stage"] != "verified":
            self.say(now, "ATTACK_ENDED", source=att, note="traffic from the source stopped on its own")
            self.limiter.clear(att)
            self.inc, self.stage = None, "watching"
            return
        if inc["stage"] == "rate_limit" and now - inc["stage_t"] >= RL_WAIT:
            recent = [s["att"] for s in list(self.series)[-4:]]
            if np.mean(recent) >= 0.5 * inc["peak"] or np.mean(recent) >= 10:      # still arriving: half the peak, or simply far above anything normal here
                self.say(now, "ESCALATE", source=att, reason=f"still {int(np.mean(recent))} pkts/s after the rate limit (peak {int(inc['peak'])})")
                ok, out = self.fw.block(att, self.hold_s)
                if ok:
                    inc["stage"], inc["stage_t"] = "block", now
                    self.stage = "blocked"
                    self.say(now, "ACTION", step="block", source=att, rule=f"ATHENA-BLOCK-{att}", note="Windows Firewall inbound block")
                else:
                    inc["stage"] = "suggest"
                    self.stage = "needs_person"
                    self.say(now, "SUGGEST", source=att, reason=out, note="not applied automatically")
                    self._evidence(now)
            else:
                inc["stage"], inc["stage_t"] = "verified", now
                self.stage = "verified"
                self.say(now, "VERIFIED", source=att, note="the rate limit was enough: traffic from the source fell", pkts_per_s=int(np.mean(recent)))
                self._evidence(now)
        elif inc["stage"] == "block" and now - inc["stage_t"] >= VERIFY_AFTER:
            win = list(self.series)[-4:]
            rep = sum(s["replies"] for s in win)
            arriving = int(np.mean([s["att"] for s in win]))
            if rep == 0:
                inc["stage"] = "verified"
                self.stage = "verified"
                self.say(now, "VERIFIED", source=att, replies_sent_to_source=0, still_arriving_pkts_per_s=arriving, note="attack packets still arrive but this laptop no longer answers them")
                self._evidence(now)
            elif now - inc["stage_t"] >= 3 * VERIFY_AFTER:
                inc["stage"] = "failed"
                self.stage = "needs_person"
                self.say(now, "VERIFY_FAILED", source=att, replies_sent_to_source=rep, note="the block did not stop replies; a person must look")

    def _evidence(self, now):
        if self.on_evidence:
            try:
                path = self.on_evidence(now)
                if path:
                    self.say(now, "EVIDENCE", file=path)
            except Exception:
                pass

    # ------------------------------------------------------------ for the page
    def state(self):
        return dict(stage=self.stage, progress=self.progress, ready=self.det.ready, calib=getattr(self.det, "calib", None), incident=self.inc,
                    rules=[dict(ip=ip, since=time.strftime("%H:%M:%S", time.localtime(r["since"]))) for ip, r in self.fw.rules.items()], limits=dict(self.limiter.limits),
                    served=dict(self.limiter.served), dropped=dict(self.limiter.dropped), series=list(self.series)[-120:], events=list(self.events)[-60:])
