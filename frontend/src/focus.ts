import { getState, setState, toast } from "./store";
import { dijkstra, routeTo } from "./routes";

/** What the map highlights. Every button in the side panel that refers to a path, link or device sets one of these. Pressing it again clears it. */
export type Focus = { key: string; kind: "attack" | "predicted" | "defence"; route?: { nodes: string[]; edges: string[] }; segs?: string[][]; edges?: string[]; marks?: string[]; blast?: Record<string, number>; hit?: string[] };

const set = (f: Focus | null) => setState({ focus: f && getState().focus?.key === f.key ? null : f });
export const clearFocus = () => setState({ focus: null });
const uniq = <T,>(a: T[]) => [...new Set(a)];

/** An ordered route (numbered on the map). */
export function showRoute(nodes: string[], edges: string[], kind: Focus["kind"] = "attack") { set({ key: "r:" + nodes.join(">"), kind, route: { nodes, edges }, edges }); }

/** A set of links (not numbered). */
export function showEdges(st: any, ids: string[], kind: Focus["kind"] = "defence") {
  const es = ids.map((id) => st.edges.find((e: any) => e.id === id)).filter(Boolean);
  if (!es.length) return;
  set({ key: "e:" + ids.join(","), kind, segs: es.map((e: any) => [e.source, e.target]), edges: ids, marks: uniq(es.flatMap((e: any) => [e.source, e.target])) });
}

/** Devices only (no links), for example every device of a product family. */
export function showNodes(ids: string[], kind: Focus["kind"] = "defence") { if (ids.length) set({ key: "n:" + ids.join(","), kind, marks: ids }); }

/** The most likely way in from the internet to a device; falls back to marking the device. */
export function showNodeRoute(st: any, id: string, kind: Focus["kind"] = "attack") {
  const r = st.assets[id] && id !== "INTERNET" ? routeTo(st, id) : null;
  if (r) showRoute(r.nodes, r.edges, kind); else showNodes([id], kind);
}

/** Blast radius: if this device is taken over, which other devices (and Mumbai sites) can the attacker reach, and how likely each step is. */
export function blastOf(st: any, id: string) {
  const { dist, prev } = dijkstra(st, id);
  const reach = Object.keys(dist).filter((n) => n !== id && n !== "INTERNET" && Math.exp(-dist[n]) >= 0.03).sort((a, b) => dist[a] - dist[b]).slice(0, 16);
  const blast: Record<string, number> = {}; const edges = new Set<string>(); const segs: string[][] = [];
  for (const n of reach) { blast[n] = Math.exp(-dist[n]); let v = n; while (v !== id && prev[v]) { const e = prev[v]; if (!edges.has(e.id)) { edges.add(e.id); segs.push([e.source, e.target]); } v = e.source; } }
  const reached = new Set([id, ...reach]); const sites: string[] = [];
  for (const ph of Object.values<any>(st.physical)) {
    if (ph.kind !== "site") continue; const dep = (ph.depends_on || []).filter((d: string) => reached.has(d) && Math.exp(-(dist[d] ?? 0)) >= 0.3); if (!dep.length) continue;
    const via = dep.sort((a: string, b: string) => (dist[a] ?? 0) - (dist[b] ?? 0))[0]; sites.push(ph.id); segs.push([via, ph.id]); blast[ph.id] = Math.exp(-(dist[via] ?? 0)) * 0.8;
  }
  return { blast, segs, edges: [...edges], marks: [id, ...reach, ...sites], sites, devices: reach };
}
export function showBlast(st: any, id: string) {
  const b = blastOf(st, id); if (!b.devices.length && !b.sites.length) { setState({ focus: null }); return; }
  setState({ focus: { key: "b:" + id, kind: "attack", segs: b.segs, edges: b.edges, marks: b.marks, blast: b.blast, hit: b.sites } });
}

/** Select a device (opens its card) and show its blast radius (default) or the way in. */
export function pickNode(st: any, id: string | null) {
  const pk = getState().pick;
  if (pk && id) {   // choosing an attack entry point or target by clicking the map
    const a = st.assets[id]; const isCtrl = Object.values<any>(st.actions).some((x: any) => x.controller === id);
    if (!a || id === "INTERNET" || (pk === "goal" && !isCtrl)) { toast("warn", pk === "goal" ? "Pick a controller (a pump, valve or breaker controller)" : "Pick a device"); return; }
    const entry = pk === "entry" ? id : getState().atkEntry, goal = pk === "goal" ? id : getState().atkGoal;
    setState({ [pk === "entry" ? "atkEntry" : "atkGoal"]: id, pick: null, selected: null, focus: { key: "pick:" + entry + ">" + goal, kind: "predicted", marks: [entry, goal].filter(Boolean) } } as any);
    toast("ok", (pk === "entry" ? "Entry point: " : "Target: ") + (a.name || id).replace(/ \(.*\)/, ""));
    return;
  }
  if (!id) { setState({ selected: null, focus: null }); return; }
  const ph = st.physical[id]; setState({ selected: id, focus: null });
  if (ph?.kind === "site") { const dep: string[] = ph.depends_on || []; setState({ focus: { key: "s:" + id, kind: "attack", segs: dep.map((d) => [d, id]), marks: [id, ...dep], blast: Object.fromEntries(dep.map((d) => [d, 0.6])) } }); return; }   // a site: the devices it relies on
  if (getState().blast && !ph) showBlast(st, id); else showNodeRoute(st, id);
}

/** A fix from the plan: shield / update / harden a device -> the route that fix cuts; close a link -> that link; MFA on the vendor VPN -> every vendor link. */
function fixFocus(st: any, id: string): Focus | null {
  const [kind, target] = id.split(":");
  if (kind === "cl") { const e = st.edges.find((x: any) => x.id === target); return e ? { key: "e:" + target, kind: "defence", segs: [[e.source, e.target]], edges: [target], marks: [e.source, e.target] } : null; }
  if (kind === "mfa") { const es = st.edges.filter((x: any) => x.type === "vendor"); return { key: "mfa", kind: "defence", segs: es.map((e: any) => [e.source, e.target]), edges: es.map((e: any) => e.id), marks: uniq(es.flatMap((e: any) => [e.source, e.target])) }; }
  const r = routeTo(st, target);
  return r ? { key: "r:" + r.nodes.join(">"), kind: "attack", route: { nodes: r.nodes, edges: r.edges }, edges: r.edges } : { key: "n:" + target, kind: "defence", marks: [target] };
}
export function showFix(st: any, id: string) { set(fixFocus(st, id)); }

/** Several fixes at once (the preview): all their routes and links together. */
export function showFixes(st: any, ids: string[]) {
  const fs = ids.map((i) => fixFocus(st, i)).filter(Boolean) as Focus[];
  if (!fs.length) { clearFocus(); return; }
  if (fs.length === 1) { setState({ focus: fs[0] }); return; }
  const segs = fs.flatMap((f) => f.segs || (f.route ? f.route.nodes.slice(0, -1).map((a, i) => [a, f.route!.nodes[i + 1]]) : []));
  setState({ focus: { key: "f:" + ids.join(","), kind: "defence", segs, edges: uniq(fs.flatMap((f) => f.edges || [])), marks: uniq(fs.flatMap((f) => [...(f.marks || []), ...(f.route?.nodes || [])])) } });
}

/** What a healing step acts on (the Healer or the PPO responder). A device -> the route into it; a link -> that link. */
export function showTarget(st: any, t: any, fallback: string[] = []) {
  if (t?.edge) { showEdges(st, [t.edge], "defence"); return; }
  const nodes: string[] = t?.nodes?.length ? t.nodes : t?.node ? [t.node] : fallback;
  if (nodes.length === 1) showNodeRoute(st, nodes[0]); else if (nodes.length) showNodes(nodes, "defence");
}
export function showTargets(st: any, ts: any[], fallback: string[] = []) {
  const edges = uniq(ts.map((t) => t?.edge).filter(Boolean) as string[]); const nodes = uniq(ts.flatMap((t) => (t?.nodes?.length ? t.nodes : t?.node ? [t.node] : [])));
  const es = edges.map((id) => st.edges.find((e: any) => e.id === id)).filter(Boolean);
  const segs = es.map((e: any) => [e.source, e.target]);
  const marks = uniq([...nodes.length ? nodes : fallback, ...es.flatMap((e: any) => [e.source, e.target])]);
  if (!segs.length && !marks.length) return;
  setState({ focus: { key: "t:" + edges.join(",") + "|" + nodes.join(","), kind: "defence", segs, edges, marks } });
}

/** A recommendation from the What-if lab: the links it closes, or the devices it protects. */
export function showControls(st: any, c: any) {
  if (c?.blocked_edges?.length) { showEdges(st, c.blocked_edges, "defence"); return; }
  const nodes: string[] = uniq([...(c?.mfa || []), ...(c?.vpatch || []), ...(c?.patched || []), ...(c?.harden || []), ...(c?.monitoring || []), ...(c?.isolated || [])]);
  if (nodes.length === 1) showNodeRoute(st, nodes[0]); else showNodes(nodes, "defence");
}
