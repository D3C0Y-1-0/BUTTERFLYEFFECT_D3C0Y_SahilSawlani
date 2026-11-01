"""SOC / ticketing export. A city SOC does not watch a new dashboard; it reads its SIEM and its ticket queue. ATHENA therefore writes every incident in the two formats those
systems accept: ArcSight CEF lines (syslog, Splunk, QRadar, Sentinel all ingest CEF) and a plain JSON ticket (ServiceNow / Jira / email)."""
from __future__ import annotations

SEV = {"open": 9, "contained": 6, "resolved": 3, "reported": 2}


def _esc(v) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\|").replace("=", "\=").replace("\n", " ")


def to_cef(inc: dict, assets: dict) -> str:
    names = ", ".join(assets[n]["name"] for n in inc["evidence_nodes"] if n in assets)
    ext = f"cs1Label=devices cs1={_esc(names)} cn1Label=probability cn1={inc['p_max']} cn2Label=actions cn2={len(inc['actions'])} cs2Label=clock0 cs2={_esc(inc['clock0'])} cs3Label=status cs3={inc['status']}"
    return f"CEF:0|ATHENA|CyberRiskTwin|1.0|{_esc(inc['id'])}|ATHENA incident {_esc(inc['id'])}|{SEV.get(inc['status'], 5)}|{ext}"


def to_ticket(inc: dict, assets: dict) -> dict:
    return dict(
        id=inc["id"], title=f"ATHENA incident {inc['id']}: suspected intrusion on {len(inc['evidence_nodes'])} device(s)", status=inc["status"], priority="P1" if inc["status"] == "open" else "P3",
        opened=inc["clock0"], cert_in_report_due_minutes_after_open=360, devices=[dict(id=n, name=assets[n]["name"], zone=assets[n]["zone"]) for n in inc["evidence_nodes"] if n in assets],
        actions_taken=[dict(minute=a["minute"], by=a["actor"], what=a["label"]) for a in inc["actions"]], stages=[s["stage"] for s in inc["stages"]],
        runbook="Confirm with the plant operator before any further cut of hospital-adjacent equipment; keep the Black Box Log export for the CERT-In report.")
