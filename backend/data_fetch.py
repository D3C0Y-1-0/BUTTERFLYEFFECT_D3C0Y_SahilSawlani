"""Fetch REAL public data used by ATHENA and store dated snapshots in ../data.

Sources (all public, no keys):
  - CISA KEV   : known exploited vulnerabilities (already downloaded as data/kev.json)
  - NVD 2.0    : CVSS base score, description, CPE for each CVE we use
  - FIRST EPSS : 30-day exploitation probability
  - OSM        : Mumbai (Parel-Sion) hospitals, substations, buildings via Overpass

Run:  python backend/data_fetch.py [threat|osm|all]
"""
from __future__ import annotations

import json
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
UA = {"User-Agent": "decoy-hackathon/1.0 (research prototype)"}

# Real CVEs, all present in the CISA KEV snapshot. Each maps to a device class in the Mumbai ward model.
CVE_CATALOG = {
    "CVE-2025-0282": "Ivanti Connect Secure (vendor remote-access VPN gateway)",
    "CVE-2024-55591": "Fortinet FortiOS (perimeter firewall)",
    "CVE-2017-0144": "Microsoft SMBv1 (legacy Windows workstation)",
    "CVE-2019-0708": "Microsoft Remote Desktop Services (remote access)",
    "CVE-2025-22224": "VMware ESXi (SCADA virtualisation host)",
    "CVE-2022-23131": "Zabbix Frontend (network/historian monitoring)",
    "CVE-2021-22681": "Rockwell Logix controllers (pump-station PLC)",
    "CVE-2016-8562": "Siemens SIMATIC CP 1543-1 (substation comms processor)",
    "CVE-2021-38406": "Delta Electronics DOPSoft 2 (HMI engineering software)",
    "CVE-2018-7841": "Schneider Electric U.motion Builder (building automation)",
    "CVE-2021-36260": "Hikvision camera web server (CCTV)",
    "CVE-2020-25078": "D-Link DCS-2530L (CCTV camera)",
    "CVE-2023-50224": "TP-Link TL-WR841N (street-light / IoT cellular gateway)",
    "CVE-2024-40891": "Zyxel DSL CPE (smart-meter gateway)",
    "CVE-2021-44228": "Apache Log4j2 (Java SCADA web portal)",
}


def get_json(url: str, tries: int = 4):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:  # network hiccup / NVD rate limit
            last = e
            time.sleep(8 * (i + 1))
    raise RuntimeError(f"failed {url}: {last}")


def fetch_threat() -> None:
    kev = json.loads((DATA / "kev.json").read_text(encoding="utf-8"))
    kev_by_id = {v["cveID"]: v for v in kev["vulnerabilities"]}
    ids = list(CVE_CATALOG)

    epss_raw = get_json("https://api.first.org/data/v1/epss?cve=" + ",".join(ids))
    epss = {r["cve"]: {"epss": float(r["epss"]), "percentile": float(r["percentile"]), "date": r["date"]} for r in epss_raw["data"]}

    out = {}
    for cve in ids:
        nvd = get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve)
        item = nvd["vulnerabilities"][0]["cve"]
        desc = next((d["value"] for d in item["descriptions"] if d["lang"] == "en"), "")
        cvss, vector = None, None
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            if key in item.get("metrics", {}):
                m = item["metrics"][key][0]["cvssData"]
                cvss, vector = m["baseScore"], m.get("vectorString")
                break
        k = kev_by_id.get(cve)
        out[cve] = {
            "device_class": CVE_CATALOG[cve],
            "cvss": cvss,
            "cvss_vector": vector,
            "description": desc[:400],
            "epss": epss.get(cve, {}).get("epss"),
            "epss_percentile": epss.get(cve, {}).get("percentile"),
            "epss_date": epss.get(cve, {}).get("date"),
            "in_kev": k is not None,
            "kev_date_added": k["dateAdded"] if k else None,
            "kev_ransomware": (k or {}).get("knownRansomwareCampaignUse"),
            "kev_name": k["vulnerabilityName"] if k else None,
            "provenance": "REAL",
        }
        print(cve, out[cve]["cvss"], out[cve]["epss"], out[cve]["in_kev"])
        time.sleep(6.5)  # NVD public rate limit: 5 requests / 30 s

    snap = {
        "fetched_utc": datetime.now(timezone.utc).isoformat(),
        "kev_catalog_version": kev["catalogVersion"],
        "sources": ["CISA KEV", "NVD API 2.0", "FIRST EPSS"],
        "cves": out,
    }
    (DATA / "threat_snapshot.json").write_text(json.dumps(snap, indent=1), encoding="utf-8")
    print("wrote threat_snapshot.json")


def fetch_osm() -> None:
    # Parel - Sion - Matunga - Wadala strip of Mumbai (F/South + F/North + G/North wards)
    s, w, n, e = 18.985, 72.828, 19.045, 72.868
    q = f"""[out:json][timeout:90];
(
  node["amenity"="hospital"]({s},{w},{n},{e});
  way["amenity"="hospital"]({s},{w},{n},{e});
  node["power"="substation"]({s},{w},{n},{e});
  way["power"="substation"]({s},{w},{n},{e});
  node["man_made"="water_tower"]({s},{w},{n},{e});
  way["man_made"="water_tower"]({s},{w},{n},{e});
  node["man_made"="pumping_station"]({s},{w},{n},{e});
  way["man_made"="pumping_station"]({s},{w},{n},{e});
  node["man_made"="water_works"]({s},{w},{n},{e});
  way["man_made"="water_works"]({s},{w},{n},{e});
  node["railway"="station"]({s},{w},{n},{e});
);
out center tags;"""
    data = None
    for ep in ("https://overpass-api.de/api/interpreter", "https://overpass.kumi.systems/api/interpreter"):
        try:
            req = urllib.request.Request(ep, data=urllib.parse.urlencode({"data": q}).encode(), headers=UA)
            with urllib.request.urlopen(req, timeout=120) as r:
                data = json.loads(r.read().decode("utf-8"))
            break
        except Exception as ex:
            print("overpass failed", ep, ex)
    if data is None:
        raise SystemExit("OSM fetch failed")
    feats = []
    for el in data["elements"]:
        lat = el.get("lat") or el.get("center", {}).get("lat")
        lon = el.get("lon") or el.get("center", {}).get("lon")
        if lat is None:
            continue
        t = el.get("tags", {})
        feats.append({"osm_id": el["id"], "type": el["type"], "lat": lat, "lon": lon, "name": t.get("name"), "tags": {k: v for k, v in t.items() if k in ("amenity", "power", "man_made", "railway", "operator", "healthcare", "beds")}})
    (DATA / "osm_features.json").write_text(json.dumps({"fetched_utc": datetime.now(timezone.utc).isoformat(), "bbox": [s, w, n, e], "source": "OpenStreetMap via Overpass", "features": feats}, indent=1), encoding="utf-8")
    print("osm features", len(feats), [f["name"] for f in feats if f["name"]][:40])

    # Buildings (compact): centroid + bbox size + levels
    bq = f"""[out:json][timeout:120];
way["building"]({18.990},{72.832},{19.020},{72.862});
out geom tags;"""
    bd = None
    for ep in ("https://overpass-api.de/api/interpreter", "https://overpass.kumi.systems/api/interpreter"):
        try:
            req = urllib.request.Request(ep, data=urllib.parse.urlencode({"data": bq}).encode(), headers=UA)
            with urllib.request.urlopen(req, timeout=180) as r:
                bd = json.loads(r.read().decode("utf-8"))
            break
        except Exception as ex:
            print("overpass buildings failed", ep, ex)
    if bd is None:
        print("buildings skipped")
        return
    blds = []
    for el in bd["elements"]:
        g = el.get("geometry")
        if not g or len(g) < 4:
            continue
        pts = [(p["lon"], p["lat"]) for p in g[:-1]]
        t = el.get("tags", {})
        lv = t.get("building:levels")
        try:
            lv = float(lv) if lv else None
        except ValueError:
            lv = None
        h = t.get("height")
        try:
            h = float(str(h).replace("m", "").strip()) if h else None
        except ValueError:
            h = None
        blds.append({"p": [[round(x, 6), round(y, 6)] for x, y in pts[:12]], "lv": lv, "h": h})
    (DATA / "osm_buildings.json").write_text(json.dumps({"fetched_utc": datetime.now(timezone.utc).isoformat(), "source": "OpenStreetMap via Overpass", "buildings": blds}, separators=(",", ":")), encoding="utf-8")
    print("buildings", len(blds))


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what in ("threat", "all"):
        fetch_threat()
    if what in ("osm", "all"):
        fetch_osm()
