/** Client-side route finding over the documented links (same weights as the "assume breach" tool): -log(chance each step works). */
export function dijkstra(st: any, start: string) {
  const cv = st.threat_snapshot.cves; const A = st.assets; const FLOOR: any = { iot: 0.15, it: 0.15, dmz: 0.2, control: 0.3, field: 0.3 };
  const pn = (id: string) => { const a = A[id]; const c = cv[a.cve || ""]; const ex = c ? (c.in_kev ? Math.max(c.epss, 0.6) : c.epss) : 0; const pc = (1 - a.p_patched) * ex * (a.known_version ? 1 : a.cve_belief); return 1 - (1 - pc) * (1 - a.p_weak) * (1 - (FLOOR[a.layer] || 0)); };
  const dist: any = { [start]: 0 }, prev: any = {}, q = [start];
  while (q.length) {
    q.sort((a, b) => dist[a] - dist[b]); const u = q.shift()!;
    for (const e of st.edges) { if (e.source !== u) continue; const p = Math.max(1e-3, e.p_access * (e.known ? 1 : e.belief) * pn(e.target)); const nd = dist[u] - Math.log(p); if (nd < (dist[e.target] ?? 1e9)) { dist[e.target] = nd; prev[e.target] = e; q.push(e.target); } }
  }
  return { dist, prev };
}

export function routeBetween(st: any, start: string, goal: string) {
  if (start === goal) return null; const { dist, prev } = dijkstra(st, start); if (dist[goal] === undefined) return null;
  const nodes = [goal], edges: string[] = []; let v = goal;
  while (v !== start) { const e = prev[v]; edges.unshift(e.id); v = e.source; nodes.unshift(v); }
  return { nodes, edges, p: Math.exp(-dist[goal]) };
}

/** Most likely way in from the internet to a device. */
export const routeTo = (st: any, node: string) => routeBetween(st, "INTERNET", node);

/** From a hacked device, the quickest route to a pump, valve or breaker. */
export function assumeBreach(st: any, start: string) {
  const { dist, prev } = dijkstra(st, start); const targets = Object.values<any>(st.assets).filter((a) => a.layer === "field").map((a) => a.id);
  const goal = targets.filter((t) => dist[t] !== undefined).sort((a, b) => dist[a] - dist[b])[0]; if (!goal) return null;
  const nodes = [goal], edges: string[] = []; let v = goal; while (v !== start) { const e = prev[v]; edges.unshift(e.id); v = e.source; nodes.unshift(v); }
  const weakest = edges.map((id) => st.edges.find((e: any) => e.id === id)).filter((e: any) => !e.known || e.misconfig).sort((a: any, b: any) => a.p_access - b.p_access)[0];
  return { nodes, edges, hops: edges.length, p: Math.exp(-dist[goal]), cut: weakest ? "cl:" + weakest.id : null };
}
