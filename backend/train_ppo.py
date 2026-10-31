"""Train the PPO zero-day responder. Usage: python backend/train_ppo.py [iters] [steps_per_iter] [seed]

With a seed, writes data/ppo_policy_s<seed>.pt and data/ppo_train_s<seed>.json (several seeds can train in parallel; eval_ppo.py
selects the best on a validation set). Without a seed, writes data/ppo_policy.pt and data/ppo_train.json.
Training zero-days come from a fixed set of products; a disjoint set is held out for evaluation (E15).
"""
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("OMP_NUM_THREADS", "1")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from decoy.city import DATA, build_ward  # noqa: E402
from decoy.physics import Physics  # noqa: E402
from decoy.rl import RLCore, train  # noqa: E402
from decoy.threat import ThreatModel  # noqa: E402

if __name__ == "__main__":
    import torch
    torch.set_num_threads(1)
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    steps = int(sys.argv[2]) if len(sys.argv) > 2 else 2048
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else None
    W = build_ward(); P = Physics(W); T = ThreatModel(W, P, 1500, 7)
    core = RLCore(W, T, P)
    print("actions", core.A, "obs dim", core.obs_dim, "seed", seed, flush=True)
    t = time.time()
    sfx = f"_s{seed}" if seed is not None else ""
    train(core, iters=iters, steps=steps, seed=seed or 0, log=DATA / f"ppo_train{sfx}.json", out=DATA / f"ppo_policy{sfx}.pt")
    print("trained in", round(time.time() - t), "s", flush=True)
