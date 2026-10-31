import { C } from "../palette";

export type Status = { key: "calm" | "watch" | "attack" | "healing" | "recovered"; label: string; word: string; tone: "safe" | "watch" | "crit"; color: string; line: string };

/** One plain answer to "what is going on right now?" used by the top bar, the Defend page and the map. */
export function statusOf(snap: any): Status {
  const incs: any[] = snap?.incidents || []; const p: number = snap?.watch?.p ?? 0;
  const open = [...incs].reverse().find((i) => i.status === "open" || i.status === "contained");
  if (open) {
    const cut = open.stages.some((s: any) => s.stage === "Cut made");
    if (cut) return { key: "healing", label: "Healing", word: "Healing", tone: "watch", color: C.apricot, line: "The attacker is cut off. Service is being restored." };
    return p >= 0.6 ? { key: "attack", label: "Under attack", word: "ALARM", tone: "crit", color: C.terra, line: "ATHENA detected an attack and is choosing the safest response." }
      : { key: "attack", label: "Investigating", word: "Incident open", tone: "watch", color: C.apricot, line: "An incident is open. ATHENA is checking what happened." };
  }
  const run = (snap?.adversary || []).slice().reverse().find((c: any) => c.state !== "done" && c.state !== "contained");   // an attack is under way but nothing has been noticed yet
  if (run) { const n = Math.max(0, run.compromised.length - 1); return { key: "attack", label: "Attack running", word: "Attack running", tone: "crit", color: C.terra, line: `A simulated attacker is moving through the network (${n} device${n === 1 ? "" : "s"} taken so far). ATHENA has not raised an alarm yet; it reacts when odd traffic or a broken physics rule shows up.` }; }
  const rec = [...incs].reverse().find((i) => i.status === "resolved" && snap.t - (i.stages[i.stages.length - 1]?.minute ?? 0) < 90);
  if (rec) return { key: "recovered", label: "Recovered", word: "Recovered", tone: "safe", color: C.aquaD, line: "Attack stopped. Service is back to normal." };
  if (p > 0.6) return { key: "watch", label: "Suspicious", word: "Suspicious", tone: "watch", color: C.apricot, line: "Something looks odd. ATHENA is watching closely." };
  return { key: "calm", label: "All calm", word: "Calm", tone: "safe", color: C.aquaD, line: "No attack. ATHENA is learning what normal looks like." };
}

export const RANK: Record<string, number> = { executive: 1, analyst: 2, operator: 3, admin: 4 };
export const can = (role: string | null, min: string) => !!role && RANK[role] >= RANK[min];
/** Short, friendly device names for lists ("Pump-station PS1 controller (Sion)" -> "Pump 1 controller"). */
export const brief = (n: string) => n.replace(/ \(.*\)/, "").replace("Pump-station PS", "Pump ").replace("Vendor remote-access VPN", "Vendor VPN").replace("SCADA read-only web portal", "SCADA web portal").replace(" read-only", "").replace("Engineering workstation", "Engineering PC");
export const nameOf = (st: any, id: string) => brief(st.assets[id]?.name || st.physical[id]?.name || id);
/** Every remedial move (fix, healing step, recommendation) in plain words: a short title and one line on what it does. */
export function plainMove(raw: string): { title: string; why: string } {
  const clean = (x: string) => brief(x.replace(/ \(CVE[^)]*\)/g, "").replace(/ \(no reboot\)/, "").replace(/ \(needs a restart\)/, "").trim());
  let m: RegExpMatchArray | null;
  if (/^Keep watching/.test(raw)) return { title: "Keep watching", why: "Nothing needs to be cut yet." };
  if ((m = raw.match(/^(?:Put a virtual patch in front of|Virtual patch in front of|Virtually patch|Block the known exploit in front of|Shield) (.+)$/))) return { title: `Block the known weakness in ${clean(m[1])}`, why: "Stops the attack now. No restart needed." };
  if ((m = raw.match(/^Update the firmware on (.+)$/))) return { title: `Update the software on ${clean(m[1])}`, why: "Fixes the weakness for good. Needs a short restart." };
  if ((m = raw.match(/^Close the \S+ link (?:from )?(.+?) (?:->|→| to )\s*(.+)$/))) return { title: `Cut the connection between ${clean(m[1])} and ${clean(m[2])}`, why: "Removes one road the attacker could use." };
  if (/second factor \(MFA\) on the vendor VPN/.test(raw)) return { title: "Add a second login step for vendors", why: "A stolen password alone no longer lets anyone in." };
  if ((m = raw.match(/^(?:Enable MFA \/ change default credentials on|Enable MFA on|Rotate credentials \/ add MFA for) (.+)$/))) return { title: `Add a second login step on ${clean(m[1])}`, why: "A stolen password alone no longer lets anyone in." };
  if ((m = raw.match(/^Change default password \/ settings on (.+)$/))) return { title: `Change the default password on ${clean(m[1])}`, why: "Factory passwords are the first thing attackers try." };
  if ((m = raw.match(/^Isolate the compromised cluster: (.+)$/))) return { title: `Disconnect the infected devices: ${m[1].split(", ").map(clean).join(", ")}`, why: "They can no longer talk to anything else." };
  if (/^Isolate the IoT segment/.test(raw)) return { title: "Wall off the smart-city devices", why: "They can no longer reach offices, the historian or control systems." };
  if ((m = raw.match(/^Isolate (.+) from the network$/))) return { title: `Disconnect ${clean(m[1])} from the network`, why: "It cannot reach or infect anything else. Easy to undo." };
  if ((m = raw.match(/^Redirect the attacker into a decoy next to (.+)$/))) return { title: `Set a trap next to ${clean(m[1])}`, why: "A fake device lures the attacker away from the real ones." };
  if ((m = raw.match(/^Send a crew to restore (.+?)(?: under local manual control)?$/))) {
    const a = m[1].replace(/ \(.*\)/, "").trim();
    const what = a === "equipment" ? "the equipment" : a.replace(/^stop pump ps(\d)/i, "pump $1").replace(/^close (cross-tie|hospital-feeder) valve (v\d)/i, "valve $2").replace(/^open breaker on feeder (f\d)/i, "breaker $1").replace(/^cut (.+) water supply/i, "the $1 water supply");
    return { title: `Send a crew to put ${what.replace(/\b(kem)\b/i, "KEM")} back by hand`, why: "Brings water or power back while the system is cleaned." };
  }
  if (/^Analyse the exploit sample/.test(raw)) return { title: "Study the new attack and block it everywhere", why: "One rule then protects every device of that product." };
  if ((m = raw.match(/^Segment: close the (\d+) link/))) return { title: `Cut ${m[1]} connection${m[1] === "1" ? "" : "s"} that lead to the pumps and valves`, why: "The fewest cuts that shut every route to the equipment." };
  if ((m = raw.match(/^Harden the choke point\(s\): (.+)$/))) return { title: `Protect the key stepping stones: ${m[1].split(", ").map(clean).join(", ")}`, why: "Every route to the equipment has to pass through these." };
  if (/^Restrict remote access/.test(raw)) return { title: "Switch off all vendor remote access", why: "No outside company can log in until it is safe." };
  if (/^Restrict vendor permissions/.test(raw)) return { title: "Let vendors reach only the jump host", why: "They can no longer touch the hospital system, historian or engineering PC." };
  if (/^Test backups/.test(raw)) return { title: "Test your backups and response plan", why: "A tested plan makes any outage much shorter." };
  if (/^Add anomaly monitoring/.test(raw)) return { title: "Watch those devices more closely", why: "Odd behaviour is spotted sooner." };
  if ((m = raw.match(/^Disable the internet-facing service on (.+)$/))) return { title: `Switch off public access to ${clean(m[1])}`, why: "Nobody on the internet can reach it any more." };
  return { title: clean(raw), why: "" };
}
