import { C } from "../palette";

export type Status = { key: "calm" | "watch" | "attack" | "healing" | "recovered"; label: string; word: string; tone: "safe" | "watch" | "crit"; color: string; line: string };

/** One plain answer to "what is going on right now?" used by the top bar, the Defend page and the map. */
export function statusOf(snap: any): Status {
  const incs: any[] = snap?.incidents || []; const p: number = snap?.watch?.p ?? 0;
  const open = [...incs].reverse().find((i) => i.status === "open" || i.status === "contained");
  if (open) {
    const cut = open.stages.some((s: any) => s.stage === "Cut made");
    if (cut) return { key: "healing", label: "Healing", word: "Healing", tone: "watch", color: C.apricot, line: "The attacker is cut off. Service is being restored." };
    return p >= 0.6 ? { key: "attack", label: "Under attack", word: "ALARM", tone: "crit", color: C.terra, line: "DECOY detected an attack and is choosing the safest response." }
      : { key: "attack", label: "Investigating", word: "Incident open", tone: "watch", color: C.apricot, line: "An incident is open. DECOY is checking what happened." };
  }
  const rec = [...incs].reverse().find((i) => i.status === "resolved" && snap.t - (i.stages[i.stages.length - 1]?.minute ?? 0) < 90);
  if (rec) return { key: "recovered", label: "Recovered", word: "Recovered", tone: "safe", color: C.aquaD, line: "Attack stopped. Service is back to normal." };
  if (p > 0.6) return { key: "watch", label: "Suspicious", word: "Suspicious", tone: "watch", color: C.apricot, line: "Something looks odd. DECOY is watching closely." };
  return { key: "calm", label: "All calm", word: "Calm", tone: "safe", color: C.aquaD, line: "No attack. DECOY is learning what normal looks like." };
}

export const RANK: Record<string, number> = { executive: 1, analyst: 2, operator: 3, admin: 4 };
export const can = (role: string | null, min: string) => !!role && RANK[role] >= RANK[min];
/** Short, friendly device names for lists ("Pump-station PS1 controller (Sion)" -> "Pump 1 controller"). */
export const brief = (n: string) => n.replace(/ \(.*\)/, "").replace("Pump-station PS", "Pump ").replace("Vendor remote-access VPN", "Vendor VPN").replace("SCADA read-only web portal", "SCADA web portal").replace(" read-only", "").replace("Engineering workstation", "Engineering PC");
export const nameOf = (st: any, id: string) => brief(st.assets[id]?.name || st.physical[id]?.name || id);
export const plainFix = (s: string) => s.replace(/^Block the known exploit in front of /, "Shield ").replace(/^Update the firmware on /, "Update ").replace(/^Close the /, "Close ").replace(/^Put a virtual patch in front of /, "Shield ").replace(/ \(no reboot\)/, "").replace("Pump-station PS", "Pump ");
