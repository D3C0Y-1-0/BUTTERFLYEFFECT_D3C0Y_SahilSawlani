# Proving it to the judges with Wireshark (first-timer guide)

## The idea in one picture
```
 Laptop A (you, attacker)                         Laptop B (friend, defender)
 Wireshark A: sees attack GO OUT,                 Wireshark B: sees attack COME IN,
 sees B's replies come back,                      sees ATHENA's decisions (protocol ATHENA),
 sees the replies STOP after the block            sees B stop answering after the block
 python attacker.py ----------------------------> server.py (ATHENA) + demo service :8080
```
**Which Wireshark proves what**
| Question | Where to look |
|---|---|
| Did the attack really happen? | A (leaving) and B (arriving) |
| Did B notice and decide, with no help from A? | B: ATHENA lines, and A has no way to receive them |
| Did the block really work? | A: after the block, B's replies disappear and A's connection attempts are retransmitted with no answer. B: packets still arrive, but B sends nothing back |
A's capture is the independent proof: it is on your machine, and B cannot alter it.

## 1. Before the day (do this twice as a rehearsal)
Both laptops on the same phone hotspot (or one Wi-Fi that allows device-to-device traffic).
1. **Laptop B:** install Wireshark with **Npcap** (tick "Install Npcap" and keep "loopback support"). Install Python 3.11, then `pip install scapy fastapi uvicorn scikit-learn numpy`. Copy the `livedemo` folder.
2. **Laptop A:** install Wireshark and Python. Copy `livedemo/attacker.py` only.
3. Find the addresses: open a terminal and type `ipconfig`. Note the **IPv4 Address** of the Wi-Fi adapter on each laptop (for example A = 192.168.43.10, B = 192.168.43.20) and the **Default Gateway** on B.
4. **Check they can talk:** on A run `ping 192.168.43.20`. If it times out, the network blocks device-to-device traffic (common on college Wi-Fi). Use a phone hotspot.
5. **Windows Firewall on B** may block the ping. That is fine: the attack targets port 8080, which ATHENA's demo service opens (allow it if Windows asks).

## 2. Start ATHENA on laptop B
Right-click Start > **Terminal (Admin)** (needed to capture and to add the firewall rule):
```powershell
cd livedemo
python server.py --gateway 192.168.43.1
```
Open http://127.0.0.1:8765 in a browser. The banner says LEARNING with a progress bar. **Use the laptop normally** (browse a page, play a video) until it says **WATCHING** (about 90 s; for a quick rehearsal add `--learn 30`). Do not attack during learning: it would learn the attack as normal.

## 3. Wireshark on laptop B (the main screen)
**Install the ATHENA decoder (once):** copy `athena.lua` to `%APPDATA%\Wireshark\plugins\` (create the folder if it does not exist), then restart Wireshark. Decision packets will show protocol **ATHENA** with readable text.

**Start a capture on both adapters:**
1. Open Wireshark. The start page lists interfaces with little live graphs.
2. Hold **Ctrl** and click **Wi-Fi** *and* **Adapter for loopback traffic capture (Npcap Loopback Adapter)** so both are highlighted.
3. Click the blue **shark fin** (Start capturing). Packets scroll by.

**Set it up so judges can read it (once):**
- **Display filter** (green bar at the top; press Enter): `ip.addr == 192.168.43.10 || udp.port == 47474`  (A's address, plus the ATHENA decisions). The page on B shows this filter and copies it when clicked.
- **Time column:** *Edit > Preferences > Appearance > Columns*, or simply *View > Time Display Format > Seconds Since Beginning of Capture*. Now every packet has a time in seconds.
- **Colour the decisions:** right-click an ATHENA packet > *Colorize Conversation* or *View > Coloring Rules > +*: name `ATHENA`, filter `udp.port == 47474`, background orange. Attack packets: name `attack`, filter `tcp.port == 8080`, background red.
- **Hide the noise:** if too many packets scroll, narrow to `(ip.addr == 192.168.43.10 && tcp.port == 8080) || udp.port == 47474`.

## 4. Wireshark on laptop A (the independent witness)
1. Open Wireshark, select **Wi-Fi** only, start the capture.
2. Display filter: `ip.addr == 192.168.43.20 && tcp.port == 8080` (B's address).
3. Add the same time column.
Useful extra filters on A:
| Filter | What it shows |
|---|---|
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | every connection attempt A sends |
| `tcp.flags.syn == 1 && tcp.flags.ack == 1` | B's answers (SYN-ACK). These stop after the block |
| `tcp.analysis.retransmission` | A repeating a SYN because nobody answered. Appears after the block |
| `tcp.flags.reset == 1` | resets, if B's service refuses |

## 5. Run the attack (on laptop A)
Start both Wireshark captures first, then:
```powershell
python attacker.py --target 192.168.43.20 --mode http --i-own-both
```
(`--mode syn` is the connection flood. Default 120 attempts per second for 30 s; capped at 300/s and 60 s.) The terminal prints a timestamped log and saves `attacker_log.jsonl`.

## 6. What you should see, with times (judges follow this list)
On **laptop B**, filter `ip.addr == A || udp.port == 47474`:
| Time | In Wireshark | Meaning |
|---|---|---|
| 0 s | A to B, TCP port 8080, a burst of packets (hundreds per second) | the attack starts |
| about +1 s | **ATHENA DETECTED** source=A kind=request burst pkts_per_s=... p=1.0 | B noticed, using only its own traffic |
| same moment | **ATHENA PREDICTED** next_step=keeps hitting port 8080 | its forecast and plan |
| same moment | **ATHENA ACTION** step=rate_limit | first response: protect the service |
| about +9 s | **ATHENA ESCALATE** still N pkts/s after the rate limit | the limit was not enough |
| right after | **ATHENA ACTION** step=block rule=ATHENA-BLOCK-A | firewall rule added |
| about +14 s | **ATHENA VERIFIED** replies_sent_to_source=0 still_arriving_pkts_per_s=N | A's packets still arrive, B no longer answers |
On **laptop A**: `SYN` packets leave steadily; replies (`SYN, ACK`) come back until the block, then stop and `[TCP Retransmission]` lines appear. Same moment on both screens.

## 7. Two graphs that make it obvious
**I/O Graph** (*Statistics > I/O Graphs*): add graph 1 with display filter `ip.src == 192.168.43.10 && tcp.port == 8080` (attack in), graph 2 `ip.src == 192.168.43.20 && tcp.srcport == 8080` (B's replies out). Style *Line*. Judges see attack steady, replies dropping to zero at the block.
**Conversations** (*Statistics > Conversations > TCP*): packet counts per direction. After the block, A to B keeps growing and B to A freezes.

## 8. Save the proof
- **File > Save As** on both laptops: `A-capture.pcapng`, `B-capture.pcapng`. Open them later and the story is intact.
- B's page also saved `livedemo\evidence\incident-*.pcap` automatically (attack plus decisions on one clock).
- Show `attacker_log.jsonl` (A's own timeline) next to B's event table.

## 9. What to say, honestly
- "Laptop B has no connection to A. It only listens to its own network card."
- "It learned what normal is for this laptop in the last 90 seconds. Nothing about this attack was programmed in."
- "The ATHENA lines are B's record of its own decisions. The proof they are real is the packets around them: A's capture shows the attack leaving and B's replies stopping exactly when the block happened."
- If asked about limits: the detector is trained on synthetic floods injected into this laptop's own normal traffic, the attack here is deliberately mild and capped, and a very slow probe could stay below the line.

## 10. If something goes wrong
| Problem | Fix |
|---|---|
| Page says "not administrator" | Reopen the terminal as Administrator |
| No packets in Wireshark | Pick the right adapter (the one with the live graph); on B also add the loopback adapter |
| A cannot reach B | Phone hotspot; check `ping`; allow the app through Windows Firewall |
| ATHENA never detects | Wait for WATCHING; use `--rate 150`; check the page shows packets per second rising |
| Detects the wrong thing at start | You attacked during LEARNING; press Reset and wait again |
| Blocked yourself by mistake | Click **Undo** on the page, or run `netsh advfirewall firewall delete rule name=all` for the ATHENA rule name |
| Live demo fails on stage | Open the saved `.pcapng` files and walk through them. Say plainly that they are recordings from your rehearsal |

## 11. Wireshark in five minutes (first time)
- **Interface list:** the first screen. A moving line means traffic. Double-click to start.
- **Packet list (top):** one row per packet: time, source, destination, protocol, info. Click one to inspect it.
- **Details (middle) and bytes (bottom):** the layers of the selected packet and its raw data. For an ATHENA packet, open the *ATHENA decision* line to read the text.
- **Display filter (green bar):** hides rows without losing packets. Turns red if the syntax is wrong, green if valid. Examples: `ip.addr == 1.2.3.4`, `tcp.port == 8080`, `udp.port == 47474`. Combine with `&&` (and) and `||` (or).
- **Capture filter** (before starting, in the interface list): throws packets away, so avoid it for the demo.
- **Follow a conversation:** right-click a packet > *Follow > TCP Stream* shows the actual HTTP request A sent.
- **Stop** with the red square. **Restart** to clear. Always save before closing.
- **Packets look huge in number?** Normal: 120 requests per second is about 600 packets per second.
