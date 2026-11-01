# ATHENA live demo: the exact steps that worked

**You (laptop B)** are attacked and run ATHENA and Wireshark. **Your friend (laptop A)** runs one attack script. Your laptop is never told about the attack: it learns what is normal, then notices, decides and responds on its own. Wireshark is the proof.

Your address (B_IP) in our rehearsal: `10.120.135.52`. If you use another network, run `ipconfig` and read **IPv4 Address** under Wi-Fi.

---
## One-time setup
**Laptop B (you):** Wireshark with Npcap (keep "loopback support" ticked), Python 3.11, then in PowerShell:
```powershell
pip install scapy==2.6.1 fastapi uvicorn scikit-learn numpy
```
Optional but nicer: copy `livedemo\athena.lua` to `%APPDATA%\Wireshark\plugins\` (create the folder if missing) and restart Wireshark, so ATHENA's rows show as protocol **ATHENA**.

**Laptop A (friend):** Python 3.11 and the file `livedemo\attacker.py`. Nothing else.

**Network:** both laptops on the same Wi-Fi or phone hotspot. Check from A: `ping 10.120.135.52`. If it times out, use a phone hotspot.

---
## Run the demo (every time)

### Step 1. Start ATHENA on laptop B
Right-click Start > **Terminal (Admin)**, then:
```powershell
cd C:\Users\Shreyas\Desktop\Projects\Decoy
python livedemo\server.py
```
Open **http://127.0.0.1:8765** in a browser. It says **LEARNING** with a progress bar. Use the laptop normally for about 90 seconds until it says **WATCHING**.
- The top-right of the page must **not** say "dry run". (Dry run means it will not touch the firewall.)
- Error "only one usage of each socket address ... 8765"? An older copy is still running. In an Admin PowerShell run:
  ```powershell
  Get-NetTCPConnection -LocalPort 8765 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
  ```
  then repeat Step 1.

### Step 2. Start Wireshark on laptop B
1. Open Wireshark. On the first screen click **Wi-Fi**, hold **Ctrl** and click **Adapter for loopback traffic capture**. Both are highlighted.
2. Click the blue **shark fin** (top left) to start capturing.
3. Click the filter bar ("Apply a display filter") and paste, then press Enter:
   ```
   (tcp.port == 8080 || udp.port == 47474) && !icmp
   ```
4. *View > Time Display Format > Seconds Since Beginning of Capture*.
The list stays nearly empty. You may see one row **ATHENA baseline_learned**: that is ATHENA announcing it finished learning.

### Step 3. Your friend attacks (laptop A)
Only after the page says WATCHING and Wireshark is capturing. In a normal terminal where `attacker.py` is saved:
```powershell
python attacker.py --target 10.120.135.52 --mode http --i-own-both
```
(It runs 30 seconds at 120 requests per second, harmless and capped.)

### Step 4. What you see
| When | Where | What |
|---|---|---|
| 0 s | Wireshark | many rows from your friend's IP to port **8080** (the attack arriving) |
| about 1 s | Wireshark | **ATHENA DETECTED** source=friend's IP kind=request burst ... |
| same moment | Wireshark | **ATHENA PREDICTED**, then **ATHENA ACTION step=rate_limit** |
| about 8 s | Wireshark | **ATHENA ESCALATE**, then **ATHENA ACTION step=block** |
| about 13 s | Wireshark | **ATHENA VERIFIED replies_sent_to_source=0** |
| throughout | browser page | WATCHING, then DETECTED, then BLOCKED, then VERIFIED, with a live chart and event log |
Click any ATHENA row and read the full text in the bottom pane (or expand "ATHENA decision" if `athena.lua` is installed).

**Why the attack rows continue after the block:** Wireshark sees packets before the firewall drops them. The interception is that **your replies to them stop**.

### Step 5. Show the interception as a graph (optional, strong)
*Statistics > I/O Graphs*, click **+** twice:
- Graph 1: name `attack in`, filter `ip.src == FRIEND_IP && tcp.dstport == 8080`, style **Line**, red.
- Graph 2: name `our replies`, filter `ip.src == 10.120.135.52 && ip.dst == FRIEND_IP`, style **Line**, blue.
The red line stays up; the blue line drops to zero at the block. (FRIEND_IP is in the DETECTED row.)

### Step 6. Save the proof
Stop capture (red square), *File > Save As* `B-capture.pcapng`. ATHENA also saves `livedemo\evidence\incident-*.pcap` and the attacker's own timeline is in `attacker_log.jsonl` on laptop A.

---
## To run it again
1. **Reset ATHENA:** on the page click **Reset / remove all rules**. This removes the firewall block and rate limit, and it goes back to WATCHING. (If you closed it, redo Step 1 and wait for WATCHING again.)
2. **Clean Wireshark:** press the **blue shark fin / restart capture** button (or *Capture > Restart*) so the old packets are gone. Keep the same filter.
3. **Attack again:** your friend repeats Step 3.
If the block is still on, look at *Active responses* on the page and click **Undo**. By hand, in an Admin PowerShell: `netsh advfirewall firewall delete rule name="ATHENA-BLOCK-FRIEND_IP"`. Blocks also expire by themselves after 10 minutes.

## Quick fixes
| Problem | Fix |
|---|---|
| No attack rows in Wireshark | `ping 10.120.135.52` from A; try a phone hotspot; check Wi-Fi is selected |
| Attack rows appear but ATHENA is silent | the page must say WATCHING and must not say "dry run" or "not administrator" |
| Wrongly detects at the very start | the attack started during LEARNING: press Reset, wait for WATCHING, attack again |
| "unreachable" ICMP rows | harmless; the filter above hides them |
| Stuck after a block | click **Undo** on the page, then **Reset** |

## What to tell the judges
- "This laptop has no link to the attacker. It only listens to its own network card and learned what normal looks like in the last 90 seconds. Nothing about this attack was programmed in."
- "The ATHENA rows are this laptop's own record of its decisions. The independent proof is the packets around them: the attack arriving, then our replies stopping at the block."
- Limits: the attack is deliberately mild and capped; ATHENA's attack examples were synthetic floods injected into this laptop's own normal traffic, not the real attack; a very slow probe could stay below the alarm line.
