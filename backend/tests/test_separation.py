"""The attacker and the defender must never interact. They share only the environment (the network and the physical world).
These tests read the source code, so they fail the moment someone wires one side to the other."""
import ast
from pathlib import Path

D = Path(__file__).resolve().parents[1] / "decoy"
DEFENCE_FILES = ["watchdog.py", "healer.py", "planner.py"]
DEFENCE_METHODS = ["_incident_logic", "_new_incident", "_flood_guard", "_flood_note", "_escalate", "_request_decision", "_decide_job", "_propose", "_apply_step", "_verify",
                   "_heartbeat", "_zd_assess", "_zd_pipeline", "_suspect_products", "_rl_tick", "_uses_ppo", "approve", "_auto_guard", "_sensitive_nodes", "_step_hold", "_guard_steps", "_operator_tick"]
ATTACKER_ONLY = {"adv", "adv_none", "adv_iso", "campaigns", "Adversary", "env_live", "env_none", "env_iso", "Campaign"}
DEFENCE_WORDS = {"Defence", "defence", "healer", "watchdog", "planner", "quarantined", "blocked_edges", "Healer", "Watchdog", "Planner", "zd_mult", "cve_mult"}


def tree(name):
    return ast.parse((D / name).read_text(encoding="utf-8"))


def imported(t):
    out = set()
    for n in ast.walk(t):
        if isinstance(n, ast.ImportFrom):
            out.add((n.module or "").split(".")[-1]); out.update(a.name for a in n.names)
        elif isinstance(n, ast.Import):
            out.update(a.name.split(".")[-1] for a in n.names)
    return out


def test_attacker_file_knows_nothing_about_the_defender():
    t = tree("adversary.py")
    bad_imports = imported(t) & {"healer", "planner", "watchdog", "threat", "runtime", "rl", "Defence", "Healer", "Watchdog", "Planner", "ThreatModel", "environment", "Environment"}
    assert not bad_imports, bad_imports
    names = {n.id for n in ast.walk(t) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(t) if isinstance(n, ast.Attribute)}
    assert not (names & DEFENCE_WORDS), names & DEFENCE_WORDS


def test_defence_files_never_import_the_attacker_or_the_environment():
    for f in DEFENCE_FILES:
        assert not (imported(tree(f)) & {"adversary", "Adversary", "Campaign", "environment", "Environment", "training"}), f


def test_defence_methods_in_runtime_never_read_the_attacker():
    cls = next(n for n in tree("runtime.py").body if isinstance(n, ast.ClassDef) and n.name == "Runtime")
    fns = {f.name: f for f in cls.body if isinstance(f, ast.FunctionDef)}
    for name in DEFENCE_METHODS:
        assert name in fns, f"{name} missing: update the list if it was renamed"
        used = {n.attr for n in ast.walk(fns[name]) if isinstance(n, ast.Attribute)} | {n.id for n in ast.walk(fns[name]) if isinstance(n, ast.Name)}
        assert not (used & ATTACKER_ONLY), (name, used & ATTACKER_ONLY)


def test_the_environment_never_hands_the_defender_attacker_facts():
    t = tree("environment.py")
    # it must not import either side's decision-making
    assert not (imported(t) & {"healer", "planner", "watchdog", "Healer", "Planner", "Watchdog", "adversary", "Adversary"})
