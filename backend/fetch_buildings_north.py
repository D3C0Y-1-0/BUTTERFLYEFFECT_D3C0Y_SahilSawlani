"""Second Overpass query: buildings in the northern strip (Matunga-Sion) merged into data/osm_buildings.json."""
import json, urllib.parse, urllib.request, sys
from pathlib import Path
DATA = Path(__file__).resolve().parent.parent / "data"
q = '[out:json][timeout:120];way["building"](19.020,72.834,19.043,72.866);out geom tags;'
d = None
for ep in ("https://overpass-api.de/api/interpreter", "https://overpass.kumi.systems/api/interpreter"):
    try:
        req = urllib.request.Request(ep, data=urllib.parse.urlencode({"data": q}).encode(), headers={"User-Agent": "decoy-hackathon"})
        d = json.loads(urllib.request.urlopen(req, timeout=180).read()); break
    except Exception as e:
        print("fail", ep, e)
if not d: sys.exit(1)
cur = json.loads((DATA / "osm_buildings.json").read_text(encoding="utf-8"))
new = []
for el in d["elements"]:
    g = el.get("geometry")
    if not g or len(g) < 4: continue
    t = el.get("tags", {})
    def num(v):
        try: return float(str(v).replace("m", "").strip()) if v else None
        except ValueError: return None
    new.append({"p": [[round(p["lon"], 6), round(p["lat"], 6)] for p in g[:-1][:12]], "lv": num(t.get("building:levels")), "h": num(t.get("height"))})
cur["buildings"] += new
(DATA / "osm_buildings.json").write_text(json.dumps(cur, separators=(",", ":")), encoding="utf-8")
print("added", len(new), "total", len(cur["buildings"]))
