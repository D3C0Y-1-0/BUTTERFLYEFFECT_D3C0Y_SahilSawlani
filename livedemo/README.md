# ATHENA live demo: laptop A attacks, laptop B notices and responds, Wireshark is the proof

Two laptops on the same phone hotspot or home Wi-Fi. Laptop B has **no link to A**: it only listens to its own network card. Nothing about the attack is hard-coded: B learns what is normal for itself, then judges what arrives with the same method as ATHENA (per-flow z-score, novelty, autoencoder, logistic fusion, CUSUM, two windows above 85% before an incident).

## Setup
**Laptop B (defender)** — Windows, Npcap and Wireshark installed, terminal **Run as administrator**:
```powershell
pip install -r requirements.txt          # needs scapy, fastapi, uvicorn, scikit-learn, numpy
python livedemo\server.py --gateway <your hotspot gateway ip>      # add --iface "Wi-Fi" if the default adapter is wrong
```
Open http://127.0.0.1:8765. Use the laptop normally until the page says **WATCHING** (about 90 seconds; `--learn 30` for a short rehearsal). Find B's address with `ipconfig`.

**Wireshark on B:** capture on **Wi-Fi and Npcap Loopback Adapter** together (select both). Copy `athena.lua` to the Personal Lua Plugins folder (Help > About Wireshark > Folders) so decisions appear as protocol **ATHENA**. Display filter: `ip.addr == <A's ip> || udp.port == 47474` (the page shows it and copies on click). Add a time column "Seconds since beginning of capture".

**Laptop A (attacker)** — only Python needed:
```powershell
python attacker.py --target <B's ip> --mode http --i-own-both      # request burst on B's demo service
python attacker.py --target <B's ip> --mode syn  --i-own-both      # connection flood
```
Capped: private addresses only, at most 300 attempts per second and 60 seconds. A writes `attacker_log.jsonl` so you can show its own timeline next to B's.

## What the judges see, in order, in Wireshark
1. `A -> B` TCP packets to port 8080 start (the attack).
2. **ATHENA DETECTED** (source, kind, packets per second, confidence), about 1 second later.
3. **ATHENA PREDICTED** (what it expects next and its plan).
4. **ATHENA ACTION step=rate_limit**: the service starts refusing the source.
5. If the packets keep arriving after 8 seconds: **ESCALATE**, then **ACTION step=block** (Windows Firewall rule `ATHENA-BLOCK-<ip>`).
6. **VERIFIED replies_sent_to_source=0 still_arriving_pkts_per_s=N**: A's packets are still visible in Wireshark (Npcap sees them before the firewall) but B's replies to A disappear. That gap is the proof the block works.
Also saved automatically: `livedemo/evidence/incident-*.pcap` (the last 90 seconds, attack and decisions together). Undo/Reset buttons remove any rule.

## Honest notes
- Decision packets are sent to B's own loopback (UDP 47474) and never to A. They are ATHENA's own record, written by the same program that decided, so the independent proof is the attack packets and the vanishing replies; the evidence file keeps both on one clock.
- Safety: only private-network addresses can be blocked, never B itself or the gateway; at most 3 rules; rules expire after 10 minutes. Without administrator rights capture and blocking fail (the page warns).
- The fusion needs examples of "attack" windows. None exist for B, so they are made by injecting synthetic floods and scans into B's own recorded normal windows; the real attack from A is never seen in training.
- Tested here without a second laptop: 6 synthetic-window tests (`python -m pytest livedemo`) and a real-packet run through Npcap loopback (detection about 0.5 s after the first attack packet, rate limit, escalation, refusal to block because the attacker was this same machine). **Not yet tested: a real block between two laptops.**
- Weak spots: a very slow probe stays below the line; B's own heavy services listening on many ports raise the baseline; learning on a laptop that is already under attack teaches it the attack.
