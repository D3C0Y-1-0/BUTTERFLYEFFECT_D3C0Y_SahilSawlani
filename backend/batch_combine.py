"""Merge the chunk files into experiment E17 (batches of 10 up to 8000 attacks)."""
import json
import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from decoy.city import DATA  # noqa: E402

SIZES = (10, 50, 100, 500, 1000, 3000, 8000)   # batch size = number of attacks; the attack types rotate evenly, so every batch holds an almost equal share of each
S = []
for i in range(16):
    p = DATA / f"_chunk_{i}.json"
    if p.exists():
        S += json.loads(p.read_text(encoding="utf-8"))
print("attacks available:", len(S))


def wilson_low(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n
    return round(100 * (p + z * z / (2 * n) - z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / (1 + z * z / n), 1)


rows = []
for n in SIZES:
    if n > len(S):
        continue
    B = S[:n]; M = lambda key: float(np.mean([x[key] for x in B]))
    hurt = [x for x in B if x["executed_none"] or x["mode"] == "ddos"]; moved = [x for x in B if x["hops"] >= 1 or x["mode"] == "ddos"]
    dm = [x["detect_min"] for x in hurt if x["detect_min"] is not None]
    hd = sum(x["detected"] for x in hurt); idt = sum(x["detected"] for x in moved)
    secs = float(sum(x["sec"] for x in B))
    rows.append(dict(batch=n, seconds=round(secs, 1), per_attack_s=round(secs / n, 2), harmful=len(hurt),
                     harmful_detected_pct=round(100 * hd / len(hurt), 1) if hurt else None, harmful_detected_low95=wilson_low(hd, len(hurt)),
                     intruders=len(moved), intruders_detected_pct=round(100 * idt / len(moved), 1) if moved else None, intruders_detected_low95=wilson_low(idt, len(moved)),
                     failed_at_door=sum(1 for x in B if x["hops"] == 0), median_detect_minutes=float(np.median(dm)) if dm else None, p90_detect_minutes=float(np.percentile(dm, 90)) if dm else None,
                     p99_detect_minutes=float(np.percentile(dm, 99)) if dm else None, slowest_detect_minutes=float(max(dm)) if dm else None,
                     stopped_before_damage_pct=round(100 * (1 - sum(1 for x in hurt if x["executed_live"] and x["mode"] != "ddos") / max(1, sum(1 for x in hurt if x["mode"] != "ddos"))), 1), stopped_before_damage_low95=wilson_low(sum(1 for x in hurt if x["mode"] != "ddos") - sum(1 for x in hurt if x["executed_live"] and x["mode"] != "ddos"), sum(1 for x in hurt if x["mode"] != "ddos")), reached_equipment=sum(1 for x in hurt if x["executed_live"] and x["mode"] != "ddos"), harmful_physical=sum(1 for x in hurt if x["mode"] != "ddos"),
                     loss_decoy=round(M("live")), loss_none=round(M("none")), loss_iso=round(M("iso")), loss_cut_pct=round(100 * (1 - M("live") / max(1.0, M("none"))), 1),
                     worst_single_loss=round(max(x["live"] for x in B)), attacks_with_any_loss=sum(1 for x in B if x["live"] > 0),
                     reached_physical_pct=round(100 * M("executed_live"), 1), devices_cut=round(M("devices_cut_decoy"), 1), contained_pct=round(100 * float(np.mean([x["contained"] for x in B])), 1)))
types = {}
Bm = S[:max(n for n in SIZES if n <= len(S))] if S else []
for t in sorted({x["mode"] for x in Bm}):
    T = [x for x in Bm if x["mode"] == t]; hu = [x for x in T if x["executed_none"] or t == "ddos"]; dd = [x["detect_min"] for x in hu if x["detect_min"] is not None]
    types[t] = dict(attacks=len(T), harmful=len(hu), harmful_detected_pct=round(100 * float(np.mean([x["detected"] for x in hu])), 1) if hu else None, median_detect_minutes=float(np.median(dd)) if dd else None,
                    p99_detect_minutes=float(np.percentile(dd, 99)) if dd else None, loss_athena=round(float(np.mean([x["live"] for x in T]))), loss_none=round(float(np.mean([x["none"] for x in T]))),
                    loss_cut_pct=round(100 * (1 - float(np.mean([x["live"] for x in T])) / max(1.0, float(np.mean([x["none"] for x in T])))), 1), reached_equipment=sum(x["executed_live"] for x in T))
fa = json.loads((DATA / "_chunk_99.json").read_text(encoding="utf-8")) if (DATA / "_chunk_99.json").exists() else dict(false_alarm_runs=None, calm_runs=0)
E = json.loads((DATA / "experiments.json").read_text(encoding="utf-8"))
ok = all(r["loss_decoy"] < r["loss_none"] for r in rows) and fa["false_alarm_runs"] == 0 and all((r["harmful_detected_pct"] or 100) >= 90 for r in rows)
E["E17"] = dict(claim="Performance holds as the batch of attacks grows", target="loss below no response at every size; harmful attacks detected >= 90%; no false alarms in calm runs",
                result=dict(rows=rows, by_type=types, false_alarm_runs=fa["false_alarm_runs"], calm_runs=fa["calm_runs"], calm_hours=fa["calm_runs"] * 12,
                            note="Each batch is the first N attacks of one balanced run: attack types (standard, zero-day, spoof, wear, insider, DDoS flood, many small attacks, fast and loud) and the 8 pieces of equipment are rotated evenly, entries are random (seeds the detector was never calibrated on), so bigger batches include the smaller ones. Run time is single-core time added up over the attacks. 'Harmful' = would have cut service with no response; 'failed at the door' = nothing got in. This is the same simulator that generates the attacks, so it shows consistency inside the simulation, not real-world accuracy."),
                met=bool(ok))
(DATA / "experiments.json").write_text(json.dumps(E, indent=1, default=float), encoding="utf-8")
for r in rows:
    print(r["batch"], r["harmful"], r["harmful_detected_pct"], r["harmful_detected_low95"], r["intruders_detected_pct"], r["median_detect_minutes"], r["p99_detect_minutes"], r["loss_cut_pct"], r["worst_single_loss"], r["attacks_with_any_loss"], r["per_attack_s"])
print(fa)
