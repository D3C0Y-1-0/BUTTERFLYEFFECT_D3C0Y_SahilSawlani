"""LAPTOP B. Run as administrator:   python server.py            (then open http://127.0.0.1:8765)
Options: --iface "Wi-Fi"  --learn 90 (seconds of normal traffic to learn)  --dry-run (decide but do not touch the firewall)  --gateway 192.168.43.1
Starts: the packet sensor, the protected demo service on port 8080, the detector/response engine, and a minimal status page."""
import argparse
import os
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import uvicorn  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse  # noqa: E402

from capture import Capture  # noqa: E402
from engine import Engine  # noqa: E402
from responder import is_admin  # noqa: E402
from target_service import make  # noqa: E402

HERE = Path(__file__).resolve().parent
ap = argparse.ArgumentParser()
ap.add_argument("--iface", default=None)
ap.add_argument("--learn", type=int, default=90)
ap.add_argument("--dry-run", action="store_true")
ap.add_argument("--gateway", default=None)
ap.add_argument("--port", type=int, default=8765)
args = ap.parse_args()


def local_ips():
    ips = {"127.0.0.1"}
    try:
        from scapy.all import conf, get_if_addr
        ips.add(get_if_addr(args.iface or conf.iface))
    except Exception:
        pass
    try:
        ips |= set(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    return {i for i in ips if i and i != "0.0.0.0"}


LOCAL = local_ips()
cap = Capture(LOCAL, iface=args.iface)
(HERE / "evidence").mkdir(exist_ok=True)


def evidence(now):
    path = HERE / "evidence" / f"incident-{time.strftime('%Y%m%d-%H%M%S', time.localtime(now))}.pcap"
    n = cap.save_ring(str(path))
    return f"{path.name} ({n} packets)"


eng = Engine(local_ips=LOCAL, gateway=args.gateway, dry_run=args.dry_run, learn_windows=args.learn, on_evidence=evidence)
make(eng.limiter, 8080)
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def loop():
    cap.start()
    nxt = time.time() + 1
    while True:
        time.sleep(max(0, nxt - time.time()))
        nxt += 1
        eng.process(cap.take(), time.time())


@app.get("/")
def index():
    return FileResponse(HERE / "static" / "index.html")


@app.get("/api/state")
def state():
    s = eng.state()
    att = (s["incident"] or {}).get("attacker")
    s.update(local_ips=sorted(LOCAL), iface=args.iface or "default", admin=is_admin(), dry_run=args.dry_run,
             wireshark_filter=(f"ip.addr == {att} || udp.port == 47474" if att else "udp.port == 47474 || tcp.port == 8080"), now=time.time())
    return JSONResponse(s)


@app.post("/api/undo/{ip}")
def undo(ip: str):
    eng.undo(ip)
    return dict(ok=True)


@app.post("/api/reset")
def reset():
    eng.reset()
    return dict(ok=True)


if __name__ == "__main__":
    if not is_admin() and not args.dry_run:
        print("WARNING: not running as administrator. Packet capture and firewall rules will fail. Right-click the terminal, Run as administrator.")
    print(f"ATHENA live demo on {sorted(LOCAL)}. Learning normal traffic for {args.learn}s. Page: http://127.0.0.1:{args.port}")
    threading.Thread(target=loop, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
