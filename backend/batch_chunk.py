"""One slice of the big batch-scaling run (experiment E17). Usage: python batch_chunk.py <chunk index> [attacks per chunk]
Chunk 99 runs attack-free days instead (false alarms). Results go to data/_chunk_<i>.json; batch_combine.py merges them."""
import json
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("OMP_NUM_THREADS", "1")
sys.path.insert(0, str(Path(__file__).resolve().parent))
import numpy as np  # noqa: E402
import experiments as X  # noqa: E402
from decoy.city import DATA  # noqa: E402
from decoy.runtime import Runtime  # noqa: E402

TAG = os.environ.get("CHUNK_TAG", ""); VAR = os.environ.get("ATHENA_VARIANT", "operator")   # operator (default) | noguard | alone (guard, nobody answers)
idx = int(sys.argv[1]); per = int(sys.argv[2]) if len(sys.argv) > 2 else 500
rt = Runtime(sync=True, n_samples=2000, verbose=False)
import copy  # noqa: E402
BASE_WATCHDOG = copy.deepcopy(rt.watchdog)   # every attack meets the detector exactly as it was trained: nothing it learns from one run may leak into the next
out = []
if idx == 99:
    rt.autonomy, rt.autopilot = "auto_all", False
    fa = 0; runs = 60
    for k in range(runs):
        rt.watchdog = copy.deepcopy(BASE_WATCHDOG); rt.reset(130000 + k)
        for _ in range(12 * 60):
            rt.tick()
        fa += 1 if rt.incidents else 0
    (DATA / f"_chunk_{TAG}99.json").write_text(json.dumps(dict(false_alarm_runs=fa, calm_runs=runs)), encoding="utf-8")
else:
    # balanced design: attack number g gets attack type TYPES[g % 8] and target GOALS[(g // 8) % 8], so every batch (and every prefix of a batch) holds an even mix of all 8 types and all 8 pieces of equipment.
    TYPES = ["standard", "zero_day", "spoof", "wear", "insider", "ddos", "swarm", "blitz"]
    if os.environ.get("ATHENA_ONLY"):
        TYPES = [os.environ["ATHENA_ONLY"]] * 8      # targeted study of one attack type
    GOALS = list(rt.adv.goals.keys())
    entries = [kk for kk, a in rt.ward["assets"].items() if a["entry_weight"] > 0]
    if VAR == "noguard":
        rt._auto_guard = lambda *a, **k: None
    if VAR == "operator":
        rt.sim_operator = dict(min_delay=5, max_delay=20, availability=0.9)
    rt.healer.allow_decoy = True; rt.healer.force_decoy = False; rt.autonomy, rt.autopilot = "auto_all", False
    for k in range(per):
        g = idx * per + k; mode = TYPES[g % 8]; goal = GOALS[(g // 8) % len(GOALS)]
        rng = np.random.default_rng(200000 + g); entry = str(rng.choice(entries)) if mode not in ("insider", "swarm") else None
        t = time.time()
        rt.watchdog = copy.deepcopy(BASE_WATCHDOG); rt.reset(200000 + g); rt.rng = np.random.default_rng(200000 + g)
        rt.launch_attack(mode, entry, goal if mode not in ("ddos", "swarm") else None, float(rng.uniform(2, 7)), actor="experiment"); m0 = rt.live.minute
        for _ in range(22 * 60):
            rt.tick()
        inc = rt.incidents[0] if rt.incidents else None
        out.append(dict(mode=mode, detected=bool(inc), detect_min=(inc["t0"] - m0) if inc else None, hops=max([len(c.hops) for c in rt.adv.campaigns] or [0]),
                        live=rt.live.loss_composite(), none=rt.none.loss_composite(), iso=rt.iso.loss_composite(), executed_live=any(c.acted for c in rt.adv.campaigns),
                        executed_none=any(c.acted for c in rt.adv_none.campaigns), devices_cut_decoy=len(rt.defence.quarantined) + len(rt.defence.blocked_edges),
                        contained=any(c.state == "contained" for c in rt.adv.campaigns), sec=time.time() - t))
    (DATA / f"_chunk_{TAG}{idx}.json").write_text(json.dumps(out, default=float), encoding="utf-8")
print("chunk", idx, "done")
