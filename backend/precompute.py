"""Fill the exact loss table: every subset of attacker actions x 8 start hours. Run once; result is cached to data/."""
import sys, time, itertools
sys.path.insert(0, '.')
from decoy.city import build_ward
from decoy.physics import Physics

W = build_ward(); P = Physics(W)
ids = list(W['actions'].keys())
t = time.time(); n = 0
for mask in range(1, 2 ** len(ids)):
    acts = [ids[i] for i in range(len(ids)) if mask >> i & 1]
    for b in range(8):
        P.attack_loss(acts, 3 * b); n += 1
    if mask % 16 == 0:
        P.save(); print(mask, time.time() - t, flush=True)
P.save()
print('done', n, 'entries', len(P.cache), 'sims', P.sims_run, 'fallbacks', getattr(P, 'fallback_runs', 0), time.time() - t)
