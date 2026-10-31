"""Map Builder: the Mumbai (Parel-Sion-Matunga) ward model.

REAL      : hospital / substation / water-tower locations (OpenStreetMap), CVE + EPSS + KEV data (snapshots).
SYNTHETIC : device inventory, IPs, links, credentials, pump/tank sizes, zone households (see assumptions.py).
"""
from __future__ import annotations

import json
import math
from pathlib import Path

from .assumptions import A

DATA = Path(__file__).resolve().parent.parent.parent / "data"
ORIGIN = (19.0150, 72.8450)  # lat, lon of scene centre


def to_xz(lat: float, lon: float) -> tuple[float, float]:
    """Metres east / south of ORIGIN (three.js x, z)."""
    x = (lon - ORIGIN[1]) * 111320.0 * math.cos(math.radians(ORIGIN[0]))
    z = -(lat - ORIGIN[0]) * 110540.0
    return round(x, 1), round(z, 1)


def _osm():
    p = DATA / "osm_features.json"
    return json.loads(p.read_text(encoding="utf-8"))["features"] if p.exists() else []


def _find(feats, needle=None, tag=None, near=None):
    best, bd = None, 1e9
    for f in feats:
        n = (f.get("name") or "")
        if needle and needle.lower() not in n.lower():
            continue
        if tag and not all(f["tags"].get(k) == v for k, v in tag.items()):
            continue
        if near:
            d = (f["lat"] - near[0]) ** 2 + (f["lon"] - near[1]) ** 2
            if d < bd:
                best, bd = f, d
        else:
            return f
    return best


# ------------------------------------------------------------------ cyber assets
# (id, name, layer, purdue, zone62443, vendor/model, firmware, cve, exposure, extras)
def _assets(geo):
    H = geo
    def a(id, name, layer, purdue, zone, vendor, model, fw, cve, exposure, pos, **x):
        d = dict(id=id, name=name, layer=layer, purdue=purdue, zone=zone, vendor=vendor, model=model, firmware=fw, cve=cve,
                 exposure=exposure, geo=pos, provenance="SYNTHETIC", protocols=[], encrypted=False, controls=None,
                 patch_downtime_min=0, maintenance_window="Sun 02:00-05:00", legacy=False, p_weak=0.0, p_patched=0.0,
                 virtual_patchable=True, known_version=True, cve_belief=1.0, entry_weight=0.0, tags=[], hospital_dependent=False)
        d.update(x)
        return d

    pt_it = H["dc"]
    ot = H["ctrl"]
    L = [
        a("INTERNET", "Public Internet", "internet", 5, "Z-WAN", "-", "-", "-", None, "internet", H["dc"], provenance="REAL"),
        # --- smart-city / IoT edge (Annexure II device classes)
        a("EVC_01", "EV charging station (Dadar)", "iot", 4, "Z-IOT", "Generic", "OCPP 1.6 charger", "fw 2.3", None, "internet", H["evc"], p_weak=A("p_default_creds_iot"), protocols=["https", "ocpp"], entry_weight=0.10, tags=["Annexure II #16"], virtual_patchable=False),
        a("WIFI_PUB_01", "Public Wi-Fi controller (Parel)", "iot", 4, "Z-IOT", "TP-Link", "TL-WR841N class AP", "fw 3.16", "CVE-2023-50224", "internet", H["wifi"], p_weak=0.25, entry_weight=0.10, tags=["CERT-In 2.3 finding"], p_patched=0.2),
        a("GW_LIGHT_01", "Street-light gateway 01 (Sion)", "iot", 4, "Z-IOT", "TP-Link", "TL-WR841N class gateway", "fw 3.16", "CVE-2023-50224", "internet", H["light1"], p_weak=A("p_default_creds_iot"), protocols=["mqtt"], entry_weight=0.06, tags=["Annexure II #6"], p_patched=0.1),
        a("GW_LIGHT_02", "Street-light gateway 02 (Matunga)", "iot", 4, "Z-IOT", "TP-Link", "TL-WR841N class gateway", "fw 3.16", "CVE-2023-50224", "internet", H["light2"], p_weak=A("p_default_creds_iot"), protocols=["mqtt"], entry_weight=0.04, tags=["Annexure II #6"], p_patched=0.1),
        a("CCTV_01", "CCTV camera (Sion Hospital gate)", "iot", 4, "Z-IOT", "Hikvision", "DS-2CD web server", "v5.4", "CVE-2021-36260", "internet", H["cctv1"], p_weak=0.2, entry_weight=0.05, tags=["Annexure II #9"], p_patched=0.15),
        a("CCTV_02", "CCTV camera (Parel junction)", "iot", 4, "Z-IOT", "D-Link", "DCS-2530L", "v1.05", "CVE-2020-25078", "internet", H["cctv2"], p_weak=0.2, entry_weight=0.05, tags=["Annexure II #9"], p_patched=0.15),
        a("GW_METER_01", "Smart-meter data gateway", "iot", 4, "Z-IOT", "Zyxel", "DSL CPE", "fw 5.17", "CVE-2024-40891", "internet", H["meter"], p_weak=0.15, entry_weight=0.04, tags=["Annexure II #7"], p_patched=0.2),
        # --- municipal office IT (Purdue 4)
        a("MAIL_01", "Municipal e-mail server", "it", 4, "Z-OFFICE", "Generic", "Mail gateway", "-", None, "internet", pt_it, p_weak=0.35, entry_weight=0.10, tags=["phishing entry"], virtual_patchable=False),
        a("OFFICE_PC_01", "Ward-office PC 01", "it", 4, "Z-OFFICE", "Microsoft", "Windows 7 (legacy)", "SP1", "CVE-2017-0144", "internal", pt_it, legacy=True, p_patched=A("p_patched_it"), p_weak=0.05, protocols=["smb"], tags=["8.1 legacy"]),
        a("OFFICE_PC_02", "Ward-office PC 02 (remote-access enabled)", "it", 4, "Z-OFFICE", "Microsoft", "Windows Server 2008 RDS", "SP2", "CVE-2019-0708", "internal", pt_it, legacy=True, p_patched=A("p_patched_it"), p_weak=0.1, protocols=["rdp"], tags=["CERT-In 2.3: remote connections"]),
        a("OFFICE_PC_03", "Video-management client PC", "it", 4, "Z-OFFICE", "Microsoft", "Windows 10", "22H2", None, "internal", pt_it, p_weak=0.08, protocols=["rtsp"]),
        a("FW_PERIM", "Perimeter firewall", "dmz", 4, "Z-DMZ", "Fortinet", "FortiGate / FortiOS", "7.0.x", "CVE-2024-55591", "internet", pt_it, p_patched=A("p_patched_it"), entry_weight=0.08),
        # --- DMZ (Purdue 3.5)
        a("VPN_VENDOR", "Vendor remote-access VPN", "dmz", 4, "Z-DMZ", "Ivanti", "Connect Secure", "22.7R2", "CVE-2025-0282", "internet", pt_it, p_weak=0.30, p_patched=A("p_patched_it"), entry_weight=0.20, tags=["17 vendor access", "shared password"]),
        a("JUMP_RDS", "Jump host (RDS)", "dmz", 3, "Z-DMZ", "Microsoft", "Windows Server 2008 R2", "SP1", "CVE-2019-0708", "internal", ot, legacy=True, p_patched=A("p_patched_it"), protocols=["rdp"], tags=["8.1 legacy"]),
        a("SCADA_WEB", "SCADA read-only web portal", "dmz", 3, "Z-DMZ", "Apache", "Java portal (Log4j2)", "2.14", "CVE-2021-44228", "internet", ot, p_patched=A("p_patched_it"), entry_weight=0.12, protocols=["https"]),
        a("HIST_01", "Historian / network monitor", "dmz", 3, "Z-DMZ", "Zabbix", "Frontend", "5.4", "CVE-2022-23131", "internal", ot, p_patched=A("p_patched_ot"), protocols=["snmp", "https"], tags=["CERT-In 2.3: SNMP"]),
        # --- control layer (Purdue 3 / 2)
        a("SCADA_SRV", "SCADA server (virtualised)", "control", 3, "Z-CONTROL", "VMware", "ESXi host", "7.0 U3", "CVE-2025-22224", "internal", ot, p_patched=A("p_patched_ot"), protocols=["modbus_tcp", "iec104"], encrypted=False),
        a("HMI_01", "Operator HMI / programming station", "control", 2, "Z-CONTROL", "Delta Electronics", "DOPSoft 2", "2.00.07", "CVE-2021-38406", "internal", ot, p_patched=A("p_patched_ot"), protocols=["https"]),
        a("ENG_WS", "Engineering workstation", "control", 3, "Z-CONTROL", "Microsoft", "Windows 7 (legacy)", "SP1", "CVE-2017-0144", "internal", ot, legacy=True, p_patched=A("p_patched_ot"), protocols=["smb", "s7", "ethernet_ip"], tags=["8.1 legacy"]),
        # --- field controllers (Purdue 1/2) - each owns one physical action
        a("PLC_PS1", "Pump-station PS1 controller (Sion)", "field", 1, "Z-WATER", "Rockwell", "Logix controller", "v20", "CVE-2021-22681", "internal", H["ps1"], controls="PS1_OFF", patch_downtime_min=30, p_patched=A("p_patched_ot"), protocols=["modbus_tcp", "ethernet_ip"], hospital_dependent=True),
        a("PLC_PS2", "Pump-station PS2 controller (Parel)", "field", 1, "Z-WATER", "Rockwell", "Logix controller", "unknown", "CVE-2021-22681", "internal", H["ps2"], controls="PS2_OFF", patch_downtime_min=30, p_patched=A("p_patched_ot"), protocols=["modbus_tcp", "ethernet_ip"], known_version=False, cve_belief=0.5, hospital_dependent=True),
        a("PLC_V1", "Cross-tie valve controller V1", "field", 1, "Z-WATER", "Rockwell", "Logix controller", "v20", "CVE-2021-22681", "internal", H["v1"], controls="V1_CLOSE", patch_downtime_min=20, p_patched=A("p_patched_ot"), protocols=["modbus_tcp"]),
        a("PLC_V2", "Hospital-feeder valve controller V2", "field", 1, "Z-WATER", "Siemens", "SIMATIC CP 1543-1", "v2.0", "CVE-2016-8562", "internal", H["v2"], controls="V2_CLOSE", patch_downtime_min=20, p_patched=A("p_patched_ot"), protocols=["s7", "modbus_tcp"], hospital_dependent=True),
        a("RTU_F1", "Feeder-F1 breaker RTU (Sion substation)", "field", 1, "Z-POWER", "Siemens", "SIMATIC CP 1543-1", "v2.0", "CVE-2016-8562", "internal", H["ss_a"], controls="CB_F1_OPEN", patch_downtime_min=45, p_patched=A("p_patched_ot"), protocols=["iec104", "iec61850"]),
        a("RTU_F2", "Feeder-F2 breaker RTU (Sewri substation)", "field", 1, "Z-POWER", "Siemens", "SIMATIC CP 1543-1", "unknown", "CVE-2016-8562", "internal", H["ss_b"], controls="CB_F2_OPEN", patch_downtime_min=45, p_patched=A("p_patched_ot"), protocols=["iec104", "iec61850"], known_version=False, cve_belief=0.5),
        a("RTU_F3", "Feeder-F3 breaker RTU (Parel substation)", "field", 1, "Z-POWER", "Siemens", "SIMATIC CP 1543-1", "v2.0", "CVE-2016-8562", "internal", H["ss_c"], controls="CB_F3_OPEN", patch_downtime_min=45, p_patched=A("p_patched_ot"), protocols=["iec104", "iec61850"], hospital_dependent=True),
        a("BMS_KEM", "KEM hospital building-management system", "field", 2, "Z-HOSPITAL", "Schneider Electric", "U.motion Builder", "1.3", "CVE-2018-7841", "internal", H["kem"], controls="H1_ISOLATE", patch_downtime_min=15, p_patched=A("p_patched_ot"), protocols=["bacnet", "http"], hospital_dependent=True, tags=["Annexure I BACnet"]),
    ]
    return {x["id"]: x for x in L}


# edge: (src, dst, type, protocol, p_access, known, p_exists_belief, truth_exists, misconfig, technique, conduit)
def _edges():
    E = []
    def e(s, d, t, proto, pa, known=True, belief=1.0, truth=True, mis=None, tech="T0866", conduit=None):
        E.append(dict(source=s, target=d, type=t, protocol=proto, p_access=pa, known=known, belief=belief if not known else 1.0,
                      truth=truth, misconfig=mis, technique=tech, conduit=conduit or f"{s}->{d}", blocked=False))
    # internet exposure
    for t, pa, tech in [("VPN_VENDOR", 1.0, "T0883"), ("SCADA_WEB", 1.0, "T0883"), ("FW_PERIM", 1.0, "T0883"), ("EVC_01", 1.0, "T0883"),
                        ("WIFI_PUB_01", 1.0, "T0883"), ("GW_LIGHT_01", 1.0, "T0883"), ("GW_LIGHT_02", 1.0, "T0883"), ("CCTV_01", 1.0, "T0883"),
                        ("CCTV_02", 1.0, "T0883"), ("GW_METER_01", 1.0, "T0883"), ("MAIL_01", 1.0, "T0865")]:
        e("INTERNET", t, "reach", "ip", pa, tech=tech)
    # office / DMZ
    e("MAIL_01", "OFFICE_PC_01", "reach", "smtp", 0.9, tech="T0865")
    e("MAIL_01", "OFFICE_PC_03", "reach", "smtp", 0.9, tech="T0865")
    e("FW_PERIM", "OFFICE_PC_01", "reach", "smb", 0.8)
    e("FW_PERIM", "OFFICE_PC_03", "reach", "smb", 0.8)
    e("FW_PERIM", "JUMP_RDS", "reach", "rdp", 0.5, conduit="CNDT-DMZ-JUMP")
    e("OFFICE_PC_01", "JUMP_RDS", "reach", "rdp", 0.9, tech="T0886", conduit="CNDT-OFFICE-JUMP")
    e("OFFICE_PC_01", "OFFICE_PC_02", "reach", "smb", 0.9)
    e("OFFICE_PC_02", "JUMP_RDS", "reach", "rdp", 0.9, tech="T0886", conduit="CNDT-OFFICE-JUMP")
    e("OFFICE_PC_03", "OFFICE_PC_01", "reach", "smb", 0.8)
    e("CCTV_01", "OFFICE_PC_03", "reach", "rtsp", 0.9)
    e("CCTV_02", "OFFICE_PC_03", "reach", "rtsp", 0.9)
    e("GW_METER_01", "HIST_01", "reach", "snmp", 0.9, mis="SNMP community string (CERT-In 2.3)", conduit="CNDT-AMI-HIST")
    e("GW_LIGHT_01", "GW_LIGHT_02", "reach", "mqtt", 0.8)
    e("EVC_01", "WIFI_PUB_01", "reach", "wifi", 0.7)
    # vendor access
    e("VPN_VENDOR", "JUMP_RDS", "vendor", "rdp", 0.95, tech="T0859", conduit="CNDT-VENDOR")
    e("VPN_VENDOR", "BMS_KEM", "vendor", "http", 0.8, tech="T0859", conduit="CNDT-VENDOR-BMS")
    e("VPN_VENDOR", "HIST_01", "vendor", "https", 0.8, tech="T0859", conduit="CNDT-VENDOR")
    # DMZ -> control
    e("JUMP_RDS", "SCADA_SRV", "reach", "rdp", 0.9, tech="T0886", conduit="CNDT-JUMP-SCADA")
    e("JUMP_RDS", "ENG_WS", "reach", "rdp", 0.8, tech="T0886", conduit="CNDT-JUMP-ENG")
    e("SCADA_WEB", "SCADA_SRV", "reach", "https", 0.7, conduit="CNDT-WEB-SCADA")
    e("HIST_01", "SCADA_SRV", "reach", "https", 0.7, conduit="CNDT-HIST-SCADA")
    e("SCADA_SRV", "HMI_01", "reach", "https", 1.0)
    e("HMI_01", "SCADA_SRV", "reach", "https", 1.0)
    e("SCADA_SRV", "ENG_WS", "reach", "smb", 0.6, tech="T0886")
    e("ENG_WS", "SCADA_SRV", "reach", "smb", 0.6, tech="T0886")
    # control -> field
    for p in ["PLC_PS1", "PLC_PS2", "PLC_V1", "PLC_V2"]:
        e("SCADA_SRV", p, "reach", "modbus_tcp", 0.95, tech="T0855", conduit=f"CNDT-SCADA-{p}", mis="Modbus TCP without TLS (Annexure I #1)")
        e("ENG_WS", p, "reach", "ethernet_ip", 0.9, tech="T0843", conduit=f"CNDT-ENG-{p}")
        e("HMI_01", p, "reach", "modbus_tcp", 0.9, tech="T0855", conduit=f"CNDT-HMI-{p}")
    for r in ["RTU_F1", "RTU_F2", "RTU_F3"]:
        e("SCADA_SRV", r, "reach", "iec104", 0.95, tech="T0855", conduit=f"CNDT-SCADA-{r}", mis="IEC 104 without TLS (Annexure I #6)")
        e("ENG_WS", r, "reach", "iec61850", 0.9, tech="T0843", conduit=f"CNDT-ENG-{r}")
    # --- hidden / uncertain links (the CERT-In style misconfigurations)
    e("GW_LIGHT_01", "PLC_PS1", "reach", "modbus_tcp", 0.9, known=False, belief=0.40, truth=True, mis="Open Modbus link left from commissioning", tech="T0855", conduit="CNDT-LIGHT-PS1")
    e("WIFI_PUB_01", "OFFICE_PC_02", "reach", "rdp", 0.9, known=False, belief=0.50, truth=True, mis="Remote connection allowed to unauthorised computer (CERT-In 2.3)", tech="T0886", conduit="CNDT-WIFI-OFFICE")
    e("HIST_01", "ENG_WS", "trusts", "smb", 0.9, known=False, belief=0.50, truth=True, mis="Historian can write to engineering workstation share", tech="T0886", conduit="CNDT-HIST-ENG")
    e("VPN_VENDOR", "ENG_WS", "vendor", "rdp", 0.9, known=False, belief=0.60, truth=True, mis="Shared vendor password reaches engineering workstation", tech="T0859", conduit="CNDT-VENDOR-ENG")
    e("OFFICE_PC_03", "JUMP_RDS", "reach", "rdp", 0.9, known=False, belief=0.40, truth=False, mis="Possible RDP rule", tech="T0886", conduit="CNDT-OFFICE-JUMP2")
    e("CCTV_02", "SCADA_SRV", "reach", "https", 0.9, known=False, belief=0.30, truth=False, mis="Camera VLAN trunk to control zone?", tech="T0866", conduit="CNDT-CCTV-SCADA")
    e("BMS_KEM", "PLC_V2", "reach", "bacnet", 0.8, known=False, belief=0.30, truth=False, mis="Hospital BMS to valve PLC?", tech="T0855", conduit="CNDT-BMS-V2")
    e("RTU_F2", "RTU_F3", "reach", "iec104", 0.8, known=False, belief=0.30, truth=False, mis="Peer link between RTUs?", tech="T0855", conduit="CNDT-RTU-PEER")
    return E


# ------------------------------------------------------------------ physical models
WATER = dict(
    pump_curve=[(0.0, 36.0), (0.15, 30.0), (0.25, 20.0)],  # m3/s, m
    reservoir_head=12.0,
    pump_on_level=4.0, pump_off_level=7.0,
    tanks={"T1": dict(elev=30.0, d=22.0, init=6.0, name="Sion service reservoir"), "T2": dict(elev=30.0, d=24.0, init=6.0, name="Parel service reservoir")},
    zones={  # households (SYNTHETIC); elevation
        "Z1": dict(name="Sion", hh=8000, elev=8.0, hub="JD1"),
        "Z2": dict(name="Matunga", hh=10000, elev=7.0, hub="JD1"),
        "Z3": dict(name="Parel", hh=9000, elev=8.0, hub="JD2"),
        "Z4": dict(name="Lalbaug", hh=7000, elev=7.0, hub="JD2"),
        "Z5": dict(name="Dadar East", hh=6000, elev=8.0, hub="JD2"),
    },
    hospitals={  # beds (public figures, order of magnitude)
        "H1": dict(name="KEM Hospital", beds=1800, elev=17.0, hub="HC"),
        "H2": dict(name="Tata Memorial Hospital", beds=700, elev=17.0, hub="HC"),
        "H3": dict(name="Sion (LTMG) Hospital", beds=1400, elev=17.0, hub="JD1"),
    },
    demand_pattern=[0.45, 0.35, 0.3, 0.3, 0.45, 0.9, 1.6, 1.5, 1.2, 1.0, 0.9, 0.9, 1.0, 0.95, 0.9, 0.9, 1.0, 1.2, 1.6, 1.5, 1.2, 0.9, 0.7, 0.55],
)

POWER = dict(
    feeders={"F1": dict(loads={"PS1": 0.35, "STREETLIGHT": 0.15, "EVC": 0.25, "H3": 1.2, "RES_A": 1.8}),
             "F2": dict(loads={"PS2": 0.40, "COMMERCIAL": 1.5, "RES_B": 2.0}),
             "F3": dict(loads={"H1": 1.6, "H2": 0.6, "RES_C": 1.2})},
    pump_feeder={"PS1": "F1", "PS2": "F2"},
    hospital_feeder={"H1": "F3", "H2": "F3", "H3": "F1"},
)

# Attacker physical actions, owned by exactly one controller
ACTIONS = {
    "PS1_OFF": dict(kind="pump_off", target="PS1", controller="PLC_PS1", repair="plc", label="Stop pump PS1 (Sion)"),
    "PS2_OFF": dict(kind="pump_off", target="PS2", controller="PLC_PS2", repair="plc", label="Stop pump PS2 (Parel)"),
    "V1_CLOSE": dict(kind="valve_close", target="V1", controller="PLC_V1", repair="valve", label="Close cross-tie valve V1"),
    "V2_CLOSE": dict(kind="valve_close", target="V2", controller="PLC_V2", repair="valve", label="Close hospital-feeder valve V2"),
    "CB_F1_OPEN": dict(kind="breaker_open", target="F1", controller="RTU_F1", repair="breaker", label="Open breaker on feeder F1"),
    "CB_F2_OPEN": dict(kind="breaker_open", target="F2", controller="RTU_F2", repair="breaker", label="Open breaker on feeder F2"),
    "CB_F3_OPEN": dict(kind="breaker_open", target="F3", controller="RTU_F3", repair="breaker", label="Open breaker on feeder F3"),
    "H1_ISOLATE": dict(kind="hospital_isolate", target="H1", controller="BMS_KEM", repair="bms", label="Cut KEM hospital water supply"),
}


def build_ward() -> dict:
    feats = _osm()
    def hosp(needle, fallback, tag_near=None):
        f = _find(feats, needle=needle, tag={"amenity": "hospital"})
        return (f["lat"], f["lon"], "OSM") if f else (*fallback, "approx")
    kem = hosp("K.E.M", (19.0021, 72.8419)) if _find(feats, "K.E.M") else (19.0021, 72.8419, "approx")
    tmh = hosp("Tata Memorial", (19.0050, 72.8431))
    sion = hosp("Sion Hospital", (19.0369, 72.8582))
    subs = [f for f in feats if f["tags"].get("power") == "substation"]
    towers = [f for f in feats if f["tags"].get("man_made") in ("water_tower", "water_works")]
    def near(lst, p):
        return min(lst, key=lambda f: (f["lat"] - p[0]) ** 2 + (f["lon"] - p[1]) ** 2) if lst else None
    ss_a = near(subs, (19.0363, 72.8551)); ss_b = near(subs, (19.0047, 72.8609)); ss_c = near(subs, (18.9925, 72.8407))
    t1 = near(towers, (19.0400, 72.8570)); t2 = near(towers, (19.0000, 72.8390))
    P = lambda f, fb: ((f["lat"], f["lon"], "OSM") if f else (*fb, "approx"))
    geo = {
        "kem": kem, "tmh": tmh, "sion": sion,
        "ss_a": P(ss_a, (19.0363, 72.8551)), "ss_b": P(ss_b, (19.0047, 72.8609)), "ss_c": P(ss_c, (18.9925, 72.8407)),
        "t1": P(t1, (19.0405, 72.8590)), "t2": P(t2, (19.0000, 72.8390)),
        "ps1": (19.0375, 72.8560, "synthetic"), "ps2": (18.9990, 72.8430, "synthetic"),
        "v1": (19.0215, 72.8500, "synthetic"), "v2": (19.0030, 72.8420, "synthetic"),
        "dc": (19.0178, 72.8478, "synthetic"), "ctrl": (19.0140, 72.8440, "synthetic"),
        "evc": (19.0190, 72.8420, "synthetic"), "wifi": (19.0080, 72.8350, "synthetic"),
        "light1": (19.0330, 72.8500, "synthetic"), "light2": (19.0270, 72.8470, "synthetic"),
        "cctv1": (19.0360, 72.8575, "synthetic"), "cctv2": (19.0100, 72.8400, "synthetic"), "meter": (19.0160, 72.8530, "synthetic"),
    }
    assets = _assets(geo)
    for a_ in assets.values():
        a_["xz"] = to_xz(a_["geo"][0], a_["geo"][1])
        a_["geo"] = {"lat": a_["geo"][0], "lon": a_["geo"][1], "source": a_["geo"][2]}
    edges = _edges()
    for i, e_ in enumerate(edges):
        e_["id"] = f"E{i:03d}"

    # physical + service nodes (non-attackable but drawn and used for dependency edges)
    def phys(id, name, kind, p, extra=None):
        d = dict(id=id, name=name, kind=kind, geo={"lat": p[0], "lon": p[1], "source": p[2]}, xz=to_xz(p[0], p[1]))
        d.update(extra or {})
        return d
    physical = {
        "PS1": phys("PS1", "Pump station PS1 (Sion)", "pump", geo["ps1"]),
        "PS2": phys("PS2", "Pump station PS2 (Parel)", "pump", geo["ps2"]),
        "T1": phys("T1", WATER["tanks"]["T1"]["name"], "tank", geo["t1"], WATER["tanks"]["T1"]),
        "T2": phys("T2", WATER["tanks"]["T2"]["name"], "tank", geo["t2"], WATER["tanks"]["T2"]),
        "V1": phys("V1", "Cross-tie valve V1", "valve", geo["v1"]),
        "V2": phys("V2", "Hospital-feeder valve V2", "valve", geo["v2"]),
        "CB_F1": phys("CB_F1", "Breaker feeder F1", "breaker", geo["ss_a"]),
        "CB_F2": phys("CB_F2", "Breaker feeder F2", "breaker", geo["ss_b"]),
        "CB_F3": phys("CB_F3", "Breaker feeder F3", "breaker", geo["ss_c"]),
        "H1": phys("H1", WATER["hospitals"]["H1"]["name"], "hospital", geo["kem"], WATER["hospitals"]["H1"]),
        "H2": phys("H2", WATER["hospitals"]["H2"]["name"], "hospital", geo["tmh"], WATER["hospitals"]["H2"]),
        "H3": phys("H3", WATER["hospitals"]["H3"]["name"], "hospital", geo["sion"], WATER["hospitals"]["H3"]),
    }
    zc = {"Z1": (19.0340, 72.8550), "Z2": (19.0270, 72.8490), "Z3": (19.0010, 72.8410), "Z4": (19.0010, 72.8350), "Z5": (19.0180, 72.8465)}
    for zid, z in WATER["zones"].items():
        physical[zid] = phys(zid, f"{z['name']} homes", "zone", (*zc[zid], "synthetic"), z)
    return dict(assets=assets, edges=edges, physical=physical, water=WATER, power=POWER, actions=ACTIONS,
                meta=dict(city="Mumbai", ward="Parel-Sion-Matunga (F/South + F/North + G/North)", origin=ORIGIN,
                          note="Hospital, substation and water-tower locations REAL (OSM). Device inventory, links, pump/tank sizes SYNTHETIC."))


if __name__ == "__main__":
    w = build_ward()
    print(len(w["assets"]), "assets", len(w["edges"]), "edges")
    for k in ("kem", "tmh"):
        pass
    print({k: v["geo"] for k, v in w["physical"].items() if v["kind"] == "hospital"})
