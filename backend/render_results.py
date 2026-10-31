"""Render data/experiments.json (+ security tests) into the results table inside PLAN.md (between the RESULTS markers)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
E = json.loads((ROOT / "data" / "experiments.json").read_text(encoding="utf-8"))
S = json.loads((ROOT / "data" / "security_tests.json").read_text(encoding="utf-8")) if (ROOT / "data" / "security_tests.json").exists() else None


def k(n):
    return f"{n/1000:.1f}k" if abs(n) >= 1000 else f"{n:.0f}"


def head(key, r):
    if key == "E1":
        o = r["ours (3000 worlds)"]; return f"Spearman {o['spearman']} / top-10 overlap {o['top10_overlap']}/10 vs CVSS×importance {r['cvss_x_importance']['spearman']}, EPSS×importance {r['epss_x_importance']['spearman']}, betweenness {r['betweenness']['spearman']}"
    if key == "E2": return f"{r['devices_moved_over_10']} devices move >10 places (e.g. " + "; ".join(f"{x['device']}: #{x['cvss_rank']}→#{x['sar_rank']}" for x in r["examples"][:3]) + ")"
    if key == "E3": return f"greedy {k(r['greedy'])} = exhaustive {k(r['exhaustive_best'])}; random {k(r['random_mean'])}, CVSS-first {k(r['cvss_first'])}, no fixes {k(r['baseline_loss'])}"
    if key == "E4": return f"total harm incl. patch outages: downtime-aware {k(r['with_downtime_term']['total'])} vs ignoring downtime {k(r['ignoring_downtime']['total'])}"
    if key == "E5": return "; ".join(f"{kk}: VoI {k(v['value_of_information'])} / uncertain-first {k(v['most_uncertain_first'])} / random {k(v['random_mean'])}" for kk, v in r.items() if "value_of_information" in v and kk != "k=0")
    if key == "E6": return f"coverage {r['coverage']} (target 0.90), Spearman {r['spearman']}, {r['speedup']}× faster than the exact simulation, worst-10% escalated {int(r['worst10_escalated']*100)}%"
    if key == "E7": return (f"{r['frac_epss_ge_0_1']*100:.0f}% of {r['n_kev_cves_with_history']} later-KEV CVEs had EPSS ≥ 0.1 thirty days before listing (median percentile {r['median_percentile']})" if "frac_epss_ge_0_1" in r else r.get("note", ""))
    if key == "E8": return "worst top-10 overlap " + str(min(v["top10_overlap"] for v in r.values())) + "/10 over " + str(len(r)) + " perturbations"
    if key == "E9": return (f"mean service loss: ATHENA {k(r['mean_loss_decoy'])} vs no response {k(r['mean_loss_no_response'])} vs isolate-everything {k(r['mean_loss_isolate_all'])}; devices cut {r['mean_devices_disconnected_decoy']} vs {r['devices_disconnected_isolate_all']}; physical effect reached {r['attack_reached_physical_effect_pct_decoy']}% vs {r['attack_reached_physical_effect_pct_none']}%; detected {r['detected_pct']}% (median {r['median_detect_minutes']} min)")
    if key == "E10":
        m = [v["fused (network + physics)"]["median_delay_min"] for v in r["detection"].values() if v["fused (network + physics)"]["median_delay_min"] is not None]
        return f"fused median detection delay {min(m):.0f}–{max(m):.0f} min on held-out attack types; false-alarm minutes over 3 normal days: {r['false_alarm_minutes_over_3_normal_days']['fused (network + physics)']}"
    if key == "E11": return "; ".join(f"{x['nodes']:,} nodes: {x['seconds']} s" for x in r["runs"]) + " per 500 attack worlds"
    if key == "E12": return f"{r['candidate_actions_blocked_in_scenarios']} candidate actions blocked in scenarios; {r['scenarios_where_response_made_hospital_worse']} scenario(s) where the response left hospitals worse off; isolate-everything blocked at {r['isolate_everything_blocked_hour_count']}/24 start hours"
    if key == "E13":
        f = r["forced_decoys"]; return f"hops with policy-chosen decoys {r['mean_attacker_hops_with_decoys']} vs without {r['mean_attacker_hops_without_decoys']} (policy picks a decoy in {r['decoy_chosen_by_policy_pct']}% of runs); forced decoys: {f['mean_attacker_hops']} hops, physical effect {f['physical_effect_pct']}%"
    if key == "E15":
        p = r["policies"]; return "; ".join(f"{n} {v['mean_total']:.0f} (contained {v['contained']*100:.0f}%, devices cut {v['devices_cut']:.1f})" for n, v in p.items()) + f" on {r['episodes']} zero-days for held-out products"
    if key == "E16": return f"first encounter {r['first_encounter']:.0f} vs repeat {r['repeat_encounter']:.0f}; family rule learned in {r['learned_in_first_pct']:.0f}% of first encounters"
    return ""


rows = ["| ID | Claim | Target met? | Headline numbers |", "|---|---|---|---|"]
for key in sorted([x for x in E if x != "_meta"], key=lambda s: int(s[1:])):
    v = E[key]
    if "result" not in v:
        continue
    met = {True: "✔ yes", False: "✘ **missed**", None: "n/a"}[v.get("met")]
    rows.append(f"| {key} | {v['claim']} | {met} | {head(key, v['result'])} |")
if S:
    rows.append(f"| E14 | Platform security | {'✔ yes' if all(r['passed'] for r in S['results']) else '✘ missed'} | {S['summary']} |")
table = "\n".join(rows)
p = ROOT / "PLAN.md"
s = p.read_text(encoding="utf-8")
a, b = "<!-- RESULTS:START -->", "<!-- RESULTS:END -->"
i, j = s.index(a) + len(a), s.index(b)
p.write_text(s[:i] + "\n" + table + "\n" + s[j:], encoding="utf-8")
print(table)
