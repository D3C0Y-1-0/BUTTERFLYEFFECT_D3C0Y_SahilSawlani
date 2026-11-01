"""Packet capture on laptop B (Npcap through scapy: the same packets Wireshark shows). Turns packets into one window of counts per second for the detector."""
from __future__ import annotations

import subprocess
import threading
import time
from collections import deque

from flowdetect import new_window


def listening_ports() -> set:
    """Ports this laptop is listening on (TCP) or bound to (UDP), from netstat, refreshed by the caller."""
    ports = set()
    try:
        out = subprocess.run(["netstat", "-an"], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ports
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 4 and ((p[0] == "TCP" and p[-1] == "LISTENING") or (p[0] == "UDP")):
            try:
                ports.add(int(p[1].rsplit(":", 1)[1]))
            except (ValueError, IndexError):
                pass
    return ports


class Capture:
    def __init__(self, local_ips, iface=None, ring=30000):
        self.local, self.iface = set(local_ips), iface
        self.cur, self.lock = new_window(), threading.Lock()
        self.ring: deque = deque(maxlen=ring)
        self.listen, self._lt = set(), 0.0
        self.sniffer = None

    def start(self):
        from scapy.all import AsyncSniffer
        self.sniffer = AsyncSniffer(iface=self.iface, store=False, prn=self._cb, filter="ip")
        self.sniffer.start()

    def stop(self):
        if self.sniffer:
            self.sniffer.stop()

    def _cb(self, pkt):
        from scapy.layers.inet import IP, TCP, UDP
        if IP not in pkt:
            return
        now = time.time()
        if now - self._lt > 10:
            self.listen, self._lt = listening_ports(), now
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        self.ring.append(pkt)
        proto = "tcp" if TCP in pkt else "udp" if UDP in pkt else None
        if proto is None:
            return
        l4 = pkt[TCP] if proto == "tcp" else pkt[UDP]
        sport, dport = int(l4.sport), int(l4.dport)
        if src.startswith("127.") and dst.startswith("127."):
            return                                           # loopback to loopback (this laptop talking to itself, e.g. the status page) is never an outside attacker
        if 47474 in (sport, dport) or dport == 8765:
            return                                           # ATHENA's own decision packets are never traffic to judge
        syn = proto == "tcp" and bool(int(l4.flags) & 0x02) and not int(l4.flags) & 0x10
        with self.lock:
            w = self.cur
            if src in self.local and (dst not in self.local or sport in self.listen):
                if dst != src:
                    w["replies"][dst] += 1                       # this laptop is talking to dst
                return
            if dst in self.local and (syn or dport in self.listen):
                w["flows"][(src, dport, proto)] += 1             # unsolicited: a connection attempt, or anything sent to a port this laptop listens on
                w["total"] += 1
                if syn:
                    w["syn"] += 1
                if proto == "tcp" and len(l4.payload) > 0:
                    w["data"] += 1                                  # carries real content (a request), not just the handshake

    def take(self):
        with self.lock:
            w, self.cur = self.cur, new_window()
        return w

    def save_ring(self, path, seconds=90):
        from scapy.all import wrpcap
        cutoff = time.time() - seconds
        pk = [p for p in list(self.ring) if float(p.time) >= cutoff]
        wrpcap(path, pk)
        return len(pk)
