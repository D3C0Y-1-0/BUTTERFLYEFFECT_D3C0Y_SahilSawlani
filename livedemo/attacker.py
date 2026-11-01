"""LAPTOP A. A small, capped, harmless attack on a laptop you own, for a demonstration.
  python attacker.py --target 192.168.43.20 --mode syn  --i-own-both
  python attacker.py --target 192.168.43.20 --mode http --i-own-both
Limits: private addresses only, at most 300 attempts per second, at most 60 seconds. It has no way to talk to ATHENA; it only behaves like a very eager client."""
import argparse
import ipaddress
import json
import socket
import sys
import time

ap = argparse.ArgumentParser()
ap.add_argument("--target", required=True)
ap.add_argument("--mode", choices=["syn", "http"], required=True)
ap.add_argument("--port", type=int, default=8080)
ap.add_argument("--rate", type=int, default=120, help="attempts per second (max 300)")
ap.add_argument("--seconds", type=int, default=30, help="duration (max 60)")
ap.add_argument("--i-own-both", action="store_true", help="confirm you own both laptops and everyone on the network agrees")
a = ap.parse_args()
if not a.i_own_both:
    sys.exit("Refusing: add --i-own-both to confirm you own both machines.")
ip = ipaddress.ip_address(a.target)
if not ip.is_private or ip.is_loopback:
    sys.exit("Refusing: target must be a private-network address (your own LAN).")
rate, secs = max(1, min(a.rate, 300)), max(1, min(a.seconds, 60))
log = open("attacker_log.jsonl", "a", encoding="utf-8")


def stamp(event, **kw):
    rec = dict(t=time.time(), iso=time.strftime("%H:%M:%S"), event=event, **kw)
    log.write(json.dumps(rec) + "\n")
    log.flush()
    print(rec["iso"], event, kw if kw else "")


stamp("attack_start", mode=a.mode, target=a.target, port=a.port, rate=rate, seconds=secs)
sent = ok = 0
t_end = time.time() + secs
nxt = time.time()
while time.time() < t_end:
    nxt += 1.0 / rate
    try:
        s = socket.socket()
        s.settimeout(0.4)
        s.connect((a.target, a.port))
        if a.mode == "http":
            s.sendall(b"GET / HTTP/1.0\r\nHost: demo\r\n\r\n")
            try:
                s.recv(256)
            except OSError:
                pass
        ok += 1
        s.close()
    except OSError:
        pass
    sent += 1
    if sent % rate == 0:
        stamp("progress", sent=sent, answered=ok)
    d = nxt - time.time()
    if d > 0:
        time.sleep(d)
stamp("attack_end", sent=sent, answered=ok)
