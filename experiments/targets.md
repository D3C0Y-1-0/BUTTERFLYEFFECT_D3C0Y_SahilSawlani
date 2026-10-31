# Success targets (written BEFORE running any experiment)

All results are produced inside the simulation (Mumbai ward model). Misses are reported, not hidden.

| ID | Claim | Target |
|----|-------|--------|
| E1 | Our device ranking matches the brute-force ground truth | Spearman >= 0.90 and top-10 overlap >= 7/10, and better than every baseline (CVSS x importance, EPSS x importance, betweenness) |
| E2 | Real harm overturns severity | At least 3 devices move more than 10 places versus CVSS x importance |
| E3 | Greedy plan is near-best | Within 10% of the exhaustive optimum on a 12-fix reduced catalogue; better than random and CVSS-first |
| E4 | Counting a fix's own downtime changes the outcome | Total loss (residual + maintenance outage) lower than the same planner ignoring downtime |
| E5 | Asking the highest-value question first finds a better plan | After 1, 3 and 5 answers, VoI order <= random order and <= most-uncertain-first (lower residual loss) |
| E6 | The Fast Guesser is trustworthy and fast | Conformal coverage >= 0.85 (target 0.90), Spearman >= 0.90, >= 100x faster than the exact simulation |
| E7 | The threat layer anticipates exploitation | Majority of later-KEV CVEs already had EPSS >= 0.1 thirty days before listing (reference: FIRST reports 63% coverage at that cut-off) |
| E8 | Ranking is stable under +-20% assumption changes | Top-10 overlap >= 6/10 under every perturbation |
| E9 | Healing is surgical | Lower mean service loss than both "no response" and "isolate everything"; disrupts far fewer devices than isolate-everything |
| E10 | Zero-day / unseen attacks are caught | Fused detector detects held-out attack types with median delay < 30 min and <= 1 false-alarm minute per simulated day |
| E11 | The method scales | Near-linear growth in time; 10^4-node graph evaluated in < 60 s per 500 attack worlds |
| E12 | The Safety Check works | Blocks every candidate action that would push a hospital below minimum pressure; zero unsafe actions applied |
| E13 | Decoys help | Fewer attacker hops reach a controller with decoys than without |
| E14 | Platform security | All automated security tests pass (auth bypass, role escalation, rate limit, tamper, replay, input fuzz) |

## Added before running the zero-day work (31 Oct 2026)

| ID | Claim | Target |
|----|-------|--------|
| E15 | A PPO-trained responder handles **held-out zero-day products** (never seen in training) better than the search Healer and no response | Lower mean total cost (service loss + disruption penalty) than both; contains a larger share of campaigns than the search Healer; disconnects fewer devices than isolate-everything |
| E16 | The zero-day library speeds up the second encounter | Mean cost of a repeat zero-day (same product, new entry point) is lower than the first encounter |
