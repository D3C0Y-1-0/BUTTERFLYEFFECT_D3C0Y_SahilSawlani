import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import { mergeGeometries } from "three/examples/jsm/utils/BufferGeometryUtils.js";
import { N } from "../palette";

const S = 0.1; // scene units per metre
const STACK_Y: Record<string, number> = { internet: 120, iot: 88, it: 88, dmz: 64, control: 42, field: 20 };
const STACK_LABEL: [string, number][] = [["Internet", 120], ["Smart-city edge + office IT", 88], ["DMZ (vendor VPN, jump host)", 64], ["SCADA / control", 42], ["PLCs and RTUs", 20], ["Physical city", 0]];
const RAMP = [new THREE.Color(N.aquaM), new THREE.Color(N.apricot), new THREE.Color(N.terra), new THREE.Color(N.terraD)];
const riskColor = (t: number) => { const x = Math.min(0.999, Math.max(0, t)) * 3, i = Math.floor(x); return RAMP[i].clone().lerp(RAMP[i + 1], x - i); };
const hash = (s: string) => { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0) / 4294967295; };
const short = (n: string) => n.replace(/ \(.*\)/, "").slice(0, 26);

const labelCache = new Map<string, THREE.CanvasTexture>();
function label(text: string, size = 24, color = "#3A2216", bg = "rgba(255,247,238,.95)", border = "rgba(212,103,67,.45)") {
  const key = [text, size, color, bg].join("|"); let tex = labelCache.get(key); let w = 0, h = 0;
  const c = document.createElement("canvas"); const g = c.getContext("2d")!; g.font = `700 ${size}px Sora, system-ui, sans-serif`;
  w = Math.ceil(g.measureText(text).width) + 26; h = size + 18; c.width = w; c.height = h; g.font = `700 ${size}px Sora, system-ui, sans-serif`;
  g.fillStyle = bg; g.strokeStyle = border; g.lineWidth = 2; g.beginPath(); g.roundRect(1, 1, w - 2, h - 2, 10); g.fill(); g.stroke();
  g.fillStyle = color; g.textBaseline = "middle"; g.fillText(text, 13, h / 2 + 1);
  if (!tex) { tex = new THREE.CanvasTexture(c); tex.minFilter = THREE.LinearFilter; labelCache.set(key, tex); }
  const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false, depthTest: false }));
  sp.scale.set(w / 12, h / 12, 1); sp.renderOrder = 20; return sp;
}
function disc(text: string, fill: string, size = 56) {
  const c = document.createElement("canvas"); c.width = c.height = size; const g = c.getContext("2d")!;
  g.fillStyle = "#fff"; g.beginPath(); g.arc(size / 2, size / 2, size / 2 - 1, 0, 7); g.fill();
  g.fillStyle = fill; g.beginPath(); g.arc(size / 2, size / 2, size / 2 - 6, 0, 7); g.fill();
  g.fillStyle = "#fff"; g.font = `800 ${size * 0.55}px Sora, system-ui, sans-serif`; g.textAlign = "center"; g.textBaseline = "middle"; g.fillText(text, size / 2, size / 2 + 2);
  const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: new THREE.CanvasTexture(c), transparent: true, depthTest: false, depthWrite: false })); sp.renderOrder = 30; sp.scale.set(8, 8, 1); return sp;
}

type NodeObj = { id: string; asset: any; mesh: THREE.Object3D; city: THREE.Vector3; stack: THREE.Vector3; cur: THREE.Vector3; ring: THREE.Mesh; mat: THREE.MeshStandardMaterial };

export class CityScene {
  el: HTMLElement; onPick: (id: string | null) => void; onHover: (id: string | null) => void = () => {}; onQuality: (q: number) => void = () => {};
  renderer: THREE.WebGLRenderer; scene = new THREE.Scene(); camera: THREE.PerspectiveCamera; controls: OrbitControls;
  st: any; geo: any; snap: any = null; ana: any = null; ui: any = { mode: "city", layers: {}, selected: null, xray: false, pathNodes: [], pathEdges: [], pathKind: "none" };
  nodes = new Map<string, NodeObj>(); phys = new Map<string, any>(); cyberEdges: any[] = [];
  root = new THREE.Group(); slabGroup = new THREE.Group(); riskMesh!: THREE.Mesh; pipePts!: THREE.Points; pipes: any[] = []; particles: any[] = [];
  buildingMesh: THREE.Mesh | null = null; tiers: { sp: THREE.Sprite; tier: number }[] = [];
  clock = new THREE.Clock(); raf = 0; raycaster = new THREE.Raycaster(); pointer = new THREE.Vector2(); hoverId: string | null = null; pickables: THREE.Object3D[] = [];
  camGoal: { pos: THREE.Vector3; look: THREE.Vector3 } | null = null; modeT = 0; modeTarget = 0; fpsAvg = 60; quality = 2; decoyObjs = new Map<string, THREE.Mesh>();
  disposed = false; ro: ResizeObserver; frame = 0; needHover = false; keys = new Set<string>(); edgesDirty = true;
  // path (attack route) drawing
  pathGroup = new THREE.Group(); pathKey = ""; pathIds: string[] = []; pathCurves: THREE.QuadraticBezierCurve3[] = []; pathTubes: THREE.Mesh[] = []; pathMarks: { sp: THREE.Sprite; id: string; lab: THREE.Sprite | null }[] = [];
  comet!: THREE.Points; cometT = 0; cometColor = N.terra;
  // healing effects
  ripples: any[] = []; fx!: { pts: THREE.Points; pos: Float32Array; col: Float32Array; vel: Float32Array; life: Float32Array; base: THREE.Color[]; n: number; i: number };
  shields = new Map<string, { m: THREE.Group; t: number; dying: boolean }>(); crosses = new Map<string, THREE.Sprite>(); prev: { q: Set<string>; b: Set<string>; s: Set<string>; ok: boolean } | null = null; crossTex: THREE.Texture | null = null;

  constructor(el: HTMLElement, onPick: (id: string | null) => void) {
    this.el = el; this.onPick = onPick;
    this.renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: "high-performance" });
    this.renderer.setPixelRatio(Math.min(1.5, window.devicePixelRatio));
    el.appendChild(this.renderer.domElement);
    this.camera = new THREE.PerspectiveCamera(48, 1, 1, 4000); this.camera.position.set(60, 300, 470);
    this.controls = new OrbitControls(this.camera, this.renderer.domElement);
    Object.assign(this.controls, { enableDamping: true, dampingFactor: 0.08, maxPolarAngle: Math.PI * 0.49, minDistance: 18, maxDistance: 1100, zoomToCursor: true, screenSpacePanning: false, rotateSpeed: 0.8, zoomSpeed: 1.1, panSpeed: 1.2 });
    this.controls.target.set(90, 0, 0);
    this.controls.addEventListener("start", () => { this.camGoal = null; });
    this.scene.background = this.sky(); this.scene.fog = new THREE.FogExp2(N.cream, 0.00035);
    this.scene.add(new THREE.HemisphereLight(0xffffff, 0xf3cfae, 1.55));
    const d = new THREE.DirectionalLight(0xffefd9, 1.25); d.position.set(-180, 280, 140); this.scene.add(d);
    this.scene.add(this.root); this.root.add(this.slabGroup, this.pathGroup);
    this.initFx();
    this.ro = new ResizeObserver(() => this.resize()); this.ro.observe(el); this.resize();
    const dom = this.renderer.domElement; let down = [0, 0];
    dom.addEventListener("pointermove", (e) => { const r = dom.getBoundingClientRect(); this.pointer.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1); this.needHover = true; });
    dom.addEventListener("pointerleave", () => { this.hoverId = null; this.onHover(null); });
    dom.addEventListener("pointerdown", (e) => { down = [e.clientX, e.clientY]; });
    dom.addEventListener("pointerup", (e) => {   // pick exactly where the finger lifted, not where the last hover was
      if (Math.hypot(e.clientX - down[0], e.clientY - down[1]) > 5 || e.button !== 0) return;
      const r = dom.getBoundingClientRect(); this.pointer.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
      this.onPick(this.pickAt());
    });
    window.addEventListener("keydown", this.onKey); window.addEventListener("keyup", this.onKeyUp);
    this.loop();
  }

  // ------------------------------------------------------------------ keyboard / pad movement (forward, back, sideways, up, down)
  onKey = (e: KeyboardEvent) => {
    const t = e.target as HTMLElement; if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (t && ["INPUT", "SELECT", "TEXTAREA", "BUTTON"].includes(t.tagName)) return;
    if (t && t.closest && t.closest(".side")) return;
    const k = e.key.toLowerCase(); if (["w", "a", "s", "d", "q", "e", "arrowup", "arrowdown", "arrowleft", "arrowright"].includes(k)) { this.keys.add(k); this.camGoal = null; e.preventDefault(); }
  };
  onKeyUp = (e: KeyboardEvent) => { this.keys.delete(e.key.toLowerCase()); };
  nudge(right: number, fwd: number, up = 0) {
    const f = new THREE.Vector3(); this.camera.getWorldDirection(f); f.y = 0; if (f.lengthSq() < 1e-6) f.set(0, 0, -1); f.normalize();
    const r = new THREE.Vector3().crossVectors(f, new THREE.Vector3(0, 1, 0)).normalize();
    const step = Math.max(14, this.camera.position.distanceTo(this.controls.target) * 0.22);
    const dlt = f.multiplyScalar(fwd * step).add(r.multiplyScalar(right * step)).add(new THREE.Vector3(0, up * step, 0));
    this.camera.position.add(dlt); this.controls.target.add(dlt); this.camGoal = null;
  }
  zoom(factor: number) { const v = this.camera.position.clone().sub(this.controls.target); const len = Math.min(1100, Math.max(18, v.length() * factor)); this.camera.position.copy(this.controls.target).add(v.setLength(len)); this.camGoal = null; }
  turn(rad: number) { const v = this.camera.position.clone().sub(this.controls.target); v.applyAxisAngle(new THREE.Vector3(0, 1, 0), rad); this.camera.position.copy(this.controls.target).add(v); this.camGoal = null; }

  sky() {
    const c = document.createElement("canvas"); c.width = 4; c.height = 512; const g = c.getContext("2d")!;
    const gr = g.createLinearGradient(0, 0, 0, 512); gr.addColorStop(0, "#FFF4E8"); gr.addColorStop(0.6, "#FFEAD3"); gr.addColorStop(1, "#FBCFA0");
    g.fillStyle = gr; g.fillRect(0, 0, 4, 512); const t = new THREE.CanvasTexture(c); t.colorSpace = THREE.SRGBColorSpace; return t;
  }

  resize() {
    const w = this.el.clientWidth, h = this.el.clientHeight; if (!w || !h) return;
    this.renderer.setSize(w, h); this.camera.aspect = w / h; this.camera.updateProjectionMatrix();
  }

  // ------------------------------------------------------------------ build
  setStatic(st: any, geo: any) {
    this.st = st; this.geo = geo;
    this.buildGround(); this.buildBuildings(); this.buildPhysical(); this.buildCyber(); this.buildStackSlabs(); this.buildRisk(); this.buildComet();
  }
  p(xz: number[], y = 0) { return new THREE.Vector3(xz[0] * S, y, xz[1] * S); }
  hit(o: THREE.Object3D, r: number, id: string) { const m = new THREE.Mesh(new THREE.SphereGeometry(r, 8, 6), new THREE.MeshBasicMaterial({ visible: false })); m.userData.id = id; o.add(m); }
  addLabel(sp: THREE.Sprite, tier: number) { this.root.add(sp); this.tiers.push({ sp, tier }); }

  buildGround() {
    const g = new THREE.Mesh(new THREE.PlaneGeometry(1800, 1800), new THREE.MeshStandardMaterial({ color: N.cream, roughness: 1, metalness: 0 }));
    g.rotation.x = -Math.PI / 2; g.position.set(100, -0.2, 0); this.root.add(g);
    const grid = new THREE.GridHelper(700, 28, 0xF0C9A3, 0xF6D8BA); grid.position.set(100, 0.05, 0); (grid.material as any).transparent = true; (grid.material as any).opacity = 0.5; (grid.material as any).fog = true; this.root.add(grid);
  }

  buildBuildings() {
    const b = this.geo?.buildings?.buildings || []; const o = this.st.meta.origin; const cosl = Math.cos((o[0] * Math.PI) / 180);
    const geos: THREE.BufferGeometry[] = []; const cLow = new THREE.Color(0xB5E1E6), cHigh = new THREE.Color(0x5FB3BE);
    for (const bd of b) {
      const pts = bd.p.map((q: number[]) => new THREE.Vector2((q[0] - o[1]) * 111320 * cosl * S, (q[1] - o[0]) * 110540 * S)); if (pts.length < 3) continue;
      const hm = bd.h || (bd.lv ? bd.lv * 3.2 : 6 + hash(JSON.stringify(bd.p[0])) * 16); let ge: THREE.ExtrudeGeometry;
      try { ge = new THREE.ExtrudeGeometry(new THREE.Shape(pts), { depth: hm * S * 1.2, bevelEnabled: false }); } catch { continue; }
      ge.rotateX(-Math.PI / 2);
      const col = cLow.clone().lerp(cHigh, Math.min(1, hm / 40)); const n = ge.attributes.position.count; const arr = new Float32Array(n * 3);
      for (let i = 0; i < n; i++) { arr[i * 3] = col.r; arr[i * 3 + 1] = col.g; arr[i * 3 + 2] = col.b; }
      ge.setAttribute("color", new THREE.BufferAttribute(arr, 3)); ge.deleteAttribute("uv"); geos.push(ge);
    }
    if (!geos.length) return;
    this.buildingMesh = new THREE.Mesh(mergeGeometries(geos, false)!, new THREE.MeshStandardMaterial({ vertexColors: true, transparent: true, opacity: 0.85, roughness: 0.85, metalness: 0 }));
    this.root.add(this.buildingMesh); geos.forEach((g) => g.dispose());
  }

  buildPhysical() {
    const P = this.st.physical; const g = new THREE.Group(); this.root.add(g);
    const add = (id: string, obj: THREE.Object3D, data: any, hitR = 7) => { obj.userData.id = id; g.add(obj); this.hit(obj, hitR, id); this.pickables.push(obj); this.phys.set(id, { obj, data, ...(obj.userData.parts || {}) }); };
    for (const [id, z] of Object.entries<any>(P).filter(([, v]) => v.kind === "zone")) {
      const r = Math.sqrt(z.hh) * 0.20; const m = new THREE.MeshStandardMaterial({ color: N.aquaM, transparent: true, opacity: 0.4, roughness: 1 });
      const dsc = new THREE.Mesh(new THREE.CylinderGeometry(r, r, 0.35, 48), m); dsc.position.copy(this.p(z.xz, 0.2)); dsc.userData.parts = { mat: m, r };
      const ring = new THREE.Mesh(new THREE.TorusGeometry(r, 0.18, 8, 64), new THREE.MeshBasicMaterial({ color: N.aquaD, transparent: true, opacity: 0.8 })); ring.rotation.x = Math.PI / 2; ring.position.y = 0.2; dsc.add(ring);
      add(id, dsc, z, Math.max(8, r * 0.6)); const l = label(`${z.name} · ${(z.hh / 1000).toFixed(0)}k homes`, 20, "#2F7A84"); l.position.copy(dsc.position).add(new THREE.Vector3(0, 6, 0)); this.addLabel(l, 1);
    }
    for (const id of ["T1", "T2"]) {
      const t = P[id]; const rad = (t.d / 2) * S * 2.2; const H = 16; const grp = new THREE.Group(); grp.position.copy(this.p(t.xz, 0));
      const glass = new THREE.Mesh(new THREE.CylinderGeometry(rad, rad, H, 40, 1, true), new THREE.MeshStandardMaterial({ color: 0xffffff, transparent: true, opacity: 0.35, roughness: 0.2, side: THREE.DoubleSide })); glass.position.y = H / 2;
      const liqMat = new THREE.MeshStandardMaterial({ color: N.aquaM, transparent: true, opacity: 0.9, roughness: 0.3 }); const liq = new THREE.Mesh(new THREE.CylinderGeometry(rad * 0.96, rad * 0.96, H, 40), liqMat); liq.position.y = H / 2;
      const cap = new THREE.Mesh(new THREE.TorusGeometry(rad, 0.25, 8, 48), new THREE.MeshBasicMaterial({ color: N.ink })); cap.rotation.x = Math.PI / 2; cap.position.y = H;
      const minLine = new THREE.Mesh(new THREE.TorusGeometry(rad * 1.02, 0.14, 8, 48), new THREE.MeshBasicMaterial({ color: N.terra })); minLine.rotation.x = Math.PI / 2; minLine.position.y = (2.2 / 8) * H;
      grp.add(glass, liq, cap, minLine); grp.userData.parts = { liq, liqMat, H }; add(id, grp, t, rad + 3);
      const l = label(t.name, 22); l.position.copy(grp.position).add(new THREE.Vector3(0, H + 5, 0)); this.addLabel(l, 0);
    }
    for (const id of ["PS1", "PS2"]) {
      const m = new THREE.MeshStandardMaterial({ color: N.aquaD, roughness: 0.45 }); const g2 = new THREE.Group();
      const body = new THREE.Mesh(new THREE.CylinderGeometry(2.2, 2.6, 4, 24), m); body.position.y = 2;
      const rotor = new THREE.Mesh(new THREE.TorusGeometry(3.2, 0.45, 8, 24), new THREE.MeshStandardMaterial({ color: N.apricot })); rotor.rotation.x = Math.PI / 2; rotor.position.y = 4.8;
      g2.add(body, rotor); g2.position.copy(this.p(P[id].xz, 0)); g2.userData.parts = { mat: m, rotor }; add(id, g2, P[id], 6);
      const l = label("Pump " + id.slice(2), 20); l.position.copy(g2.position).add(new THREE.Vector3(0, 11, 0)); this.addLabel(l, 2);
    }
    for (const id of ["V1", "V2"]) {
      const m = new THREE.MeshStandardMaterial({ color: N.aquaD, roughness: 0.4 }); const v = new THREE.Mesh(new THREE.OctahedronGeometry(3.4), m); v.position.copy(this.p(P[id].xz, 3)); v.userData.parts = { mat: m }; add(id, v, P[id], 6);
    }
    for (const id of ["CB_F1", "CB_F2", "CB_F3"]) {
      const m = new THREE.MeshStandardMaterial({ color: N.apricot, roughness: 0.5 }); const grp = new THREE.Group();
      const b = new THREE.Mesh(new THREE.BoxGeometry(5, 4, 5), m); b.position.y = 2; const mt = new THREE.MeshBasicMaterial({ color: N.ink });
      const pylon = new THREE.Mesh(new THREE.CylinderGeometry(0.25, 0.25, 14, 6), mt); pylon.position.y = 9; const arm = new THREE.Mesh(new THREE.BoxGeometry(7, 0.35, 0.35), mt); arm.position.y = 14;
      grp.add(b, pylon, arm); grp.position.copy(this.p(P[id].xz, 0)); grp.userData.parts = { mat: m }; add(id, grp, P[id], 7);
      const l = label("Breaker " + id.slice(4), 20); l.position.copy(grp.position).add(new THREE.Vector3(0, 19, 0)); this.addLabel(l, 2);
    }
    for (const id of ["H1", "H2", "H3"]) {
      const m = new THREE.MeshStandardMaterial({ color: N.aquaD, roughness: 0.5 }); const grp = new THREE.Group();
      const c1 = new THREE.Mesh(new THREE.BoxGeometry(7, 2.2, 2.2), m), c2 = new THREE.Mesh(new THREE.BoxGeometry(2.2, 7, 2.2), m); c1.position.y = c2.position.y = 7.5;
      const base = new THREE.Mesh(new THREE.BoxGeometry(9, 5, 9), new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.6 })); base.position.y = 2.5;
      const shaft = new THREE.Mesh(new THREE.CylinderGeometry(2.6, 2.6, 30, 24, 1, true), new THREE.MeshBasicMaterial({ color: N.aquaM, transparent: true, opacity: 0.22, side: THREE.DoubleSide, depthWrite: false })); shaft.position.y = 19;
      grp.add(base, c1, c2, shaft); grp.position.copy(this.p(P[id].xz, 0)); grp.userData.parts = { mat: m, shaft }; add(id, grp, P[id], 9);
      const l = label(P[id].name, 21, "#1D5C64"); l.position.copy(grp.position).add(new THREE.Vector3(0, 23, 0)); this.addLabel(l, 0);
    }
    this.buildNetworks();
  }

  buildNetworks() {
    const pos = (id: string) => this.phys.get(id)!.obj.position.clone(); const mid = (a: THREE.Vector3, b: THREE.Vector3) => a.clone().add(b).multiplyScalar(0.5);
    const hub1 = mid(pos("Z1"), pos("Z2")).lerp(pos("T1"), 0.35), hub2 = mid(mid(pos("Z3"), pos("Z4")), pos("Z5")).lerp(pos("T2"), 0.3), hc = mid(pos("H1"), pos("H2"));
    const src1 = pos("PS1").add(new THREE.Vector3(-30, 0, -22)), src2 = pos("PS2").add(new THREE.Vector3(-34, 0, 18));
    const W = (id: string, a: THREE.Vector3, b: THREE.Vector3, tag: string, y = 0.9, w = 1) => this.pipes.push({ id, a: a.clone().setY(Math.max(a.y, 0) + y), b: b.clone().setY(Math.max(b.y, 0) + y), tag, kind: "water", w });
    W("mains1", src1, pos("PS1"), "PS1"); W("p1", pos("PS1"), pos("T1"), "PS1"); W("t1", pos("T1"), hub1, "T1"); W("z1", hub1, pos("Z1"), "Z1"); W("z2", hub1, pos("Z2"), "Z2"); W("h3", hub1, pos("H3"), "H3");
    W("mains2", src2, pos("PS2"), "PS2"); W("p2", pos("PS2"), pos("T2"), "PS2"); W("t2", pos("T2"), hub2, "T2"); W("z3", hub2, pos("Z3"), "Z3"); W("z4", hub2, pos("Z4"), "Z4"); W("z5", hub2, pos("Z5"), "Z5");
    W("v1a", hub1, pos("V1"), "V1", 0.9, 0.5); W("v1b", pos("V1"), hub2, "V1", 0.9, 0.5); W("v2a", hub2, pos("V2"), "V2"); W("v2b", pos("V2"), hc, "V2"); W("h1", hc, pos("H1"), "H1"); W("h2", hc, pos("H2"), "H2"); W("hc1", hub1, hc, "HC1", 1.4, 0.35);
    const Pw = (id: string, a: string, b: string, feeder: string) => this.pipes.push({ id, a: pos(a).setY(15), b: pos(b).setY(4), tag: feeder, kind: "power", w: 1 });
    Pw("pw1", "CB_F1", "PS1", "F1"); Pw("pw2", "CB_F1", "H3", "F1"); Pw("pw3", "CB_F2", "PS2", "F2"); Pw("pw4", "CB_F3", "H1", "F3"); Pw("pw5", "CB_F3", "H2", "F3");
    const NP = 20; const total = this.pipes.length * NP; const positions = new Float32Array(total * 3), colors = new Float32Array(total * 3);
    this.pipes.forEach((p, i) => {
      const m = mid(p.a, p.b).add(new THREE.Vector3(0, p.kind === "power" ? 4 : 1.2, 0)); p.curve = new THREE.QuadraticBezierCurve3(p.a, m, p.b);
      const col = p.kind === "water" ? N.aquaM : N.apricot;
      const tube = new THREE.Mesh(new THREE.TubeGeometry(p.curve, 20, p.kind === "water" ? 0.5 * p.w : 0.2, 6, false), new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.8 }));
      p.tube = tube; this.root.add(tube); p.base = i * NP; p.factor = 1;
      for (let k = 0; k < NP; k++) this.particles.push({ pipe: p, t: k / NP, spd: 0.18 + hash(p.id + k) * 0.08, slot: p.base + k });
    });
    const geo = new THREE.BufferGeometry(); geo.setAttribute("position", new THREE.BufferAttribute(positions, 3)); geo.setAttribute("color", new THREE.BufferAttribute(colors, 3));
    this.pipePts = new THREE.Points(geo, new THREE.PointsMaterial({ size: 1.9, vertexColors: true, transparent: true, opacity: 1, depthWrite: false, sizeAttenuation: true })); this.pipePts.frustumCulled = false; this.root.add(this.pipePts);
  }

  buildCyber() {
    const A = this.st.assets; const groups = new Map<string, string[]>();
    for (const [id, a] of Object.entries<any>(A)) { const k = `${Math.round(a.xz[0] / 40)}_${Math.round(a.xz[1] / 40)}`; (groups.get(k) || groups.set(k, []).get(k)!).push(id); }
    const geoOf = (kind: string) => kind === "internet" ? new THREE.IcosahedronGeometry(7, 1) : kind === "iot" ? new THREE.CylinderGeometry(2.6, 2.6, 3, 6) : kind === "it" ? new THREE.BoxGeometry(4, 4, 4) : kind === "dmz" ? new THREE.ConeGeometry(3, 5, 4) : kind === "control" ? new THREE.BoxGeometry(5.4, 3.6, 5.4) : new THREE.OctahedronGeometry(3.4);
    for (const [, ids] of groups) ids.forEach((id, i) => {
      const a = A[id]; const mat = new THREE.MeshStandardMaterial({ color: N.aquaD, roughness: 0.4, metalness: 0.1 });
      const mesh = new THREE.Mesh(geoOf(a.layer), mat); mesh.userData.id = id;
      const ang = (i / ids.length) * Math.PI * 2, rad = ids.length > 1 ? 6 + ids.length * 0.8 : 0;
      let base = this.p(a.xz, 0); if (id === "INTERNET") base = new THREE.Vector3(-30, 0, -250);
      const city = base.clone().add(new THREE.Vector3(Math.cos(ang) * rad, 0, Math.sin(ang) * rad)); city.y = id === "INTERNET" ? 110 : a.layer === "field" ? 9 : a.layer === "control" ? 13 : a.layer === "dmz" ? 17 : 21;
      const stack = city.clone(); stack.y = STACK_Y[a.layer] ?? 40; if (id === "INTERNET") stack.set(-30, 120, -240);
      const ring = new THREE.Mesh(new THREE.TorusGeometry(5.6, 0.34, 8, 40), new THREE.MeshBasicMaterial({ color: N.terra, transparent: true, opacity: 0 })); ring.rotation.x = Math.PI / 2; mesh.add(ring);
      this.hit(mesh, 6.5, id); mesh.position.copy(city); this.root.add(mesh); this.pickables.push(mesh);
      this.nodes.set(id, { id, asset: a, mesh, city, stack, cur: city.clone(), ring, mat });
    });
    for (const e of this.st.edges) {
      const a = this.nodes.get(e.source), b = this.nodes.get(e.target); if (!a || !b) continue;
      const mat = e.known ? new THREE.LineBasicMaterial({ color: 0xB08B72, transparent: true, opacity: 0.45 }) : new THREE.LineDashedMaterial({ color: N.apricot, dashSize: 1.6, gapSize: 1.2, transparent: true, opacity: 0.85 });
      const geom = new THREE.BufferGeometry(); geom.setAttribute("position", new THREE.BufferAttribute(new Float32Array(15 * 3), 3));
      const line = new THREE.Line(geom, mat); line.frustumCulled = false; this.root.add(line); this.cyberEdges.push({ e, a, b, line, mat, dashed: !e.known });
    }
    for (const act of Object.values<any>(this.st.actions)) {
      const n = this.nodes.get(act.controller); const tgt = act.target; const ph = this.phys.get(tgt) || this.phys.get("CB_" + tgt); if (!n || !ph) continue;
      const geom = new THREE.BufferGeometry(); geom.setAttribute("position", new THREE.BufferAttribute(new Float32Array(2 * 3), 3));
      const line = new THREE.Line(geom, new THREE.LineDashedMaterial({ color: N.terraD, dashSize: 0.8, gapSize: 0.8, transparent: true, opacity: 0.55 })); line.frustumCulled = false;
      this.root.add(line); this.cyberEdges.push({ ctrl: true, a: n, ph, line });
    }
  }

  buildStackSlabs() {
    for (const [txt, y] of STACK_LABEL) {
      const w = 300, d = 540;
      const plane = new THREE.Mesh(new THREE.PlaneGeometry(w, d), new THREE.MeshBasicMaterial({ color: y === 0 ? N.aqua : N.apricot, transparent: true, opacity: 0, side: THREE.DoubleSide, depthWrite: false }));
      plane.rotation.x = -Math.PI / 2; plane.position.set(110, y + 0.3, 0);
      const edge = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.PlaneGeometry(w, d)), new THREE.LineBasicMaterial({ color: N.terraD, transparent: true, opacity: 0 })); edge.rotation.x = -Math.PI / 2; edge.position.copy(plane.position);
      const l = label(txt, 24); l.position.set(-30, y + 3, 262); l.material.opacity = 0; this.slabGroup.add(plane, edge, l);
    }
  }

  buildRisk() {
    const NN = 80; const geo = new THREE.PlaneGeometry(430, 600, NN, NN); geo.rotateX(-Math.PI / 2);
    geo.setAttribute("color", new THREE.BufferAttribute(new Float32Array((NN + 1) * (NN + 1) * 3), 3));
    this.riskMesh = new THREE.Mesh(geo, new THREE.MeshBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.0, depthWrite: false }));
    this.riskMesh.position.set(100, 0.5, 5); this.riskMesh.visible = false; this.root.add(this.riskMesh);
  }

  updateRisk() {
    if (!this.ana?.ranking || !this.riskMesh) return;
    const geo = this.riskMesh.geometry as THREE.PlaneGeometry; const pos = geo.attributes.position as THREE.BufferAttribute; const col = geo.attributes.color as THREE.BufferAttribute;
    const srcs: { x: number; z: number; w: number }[] = []; const mx = Math.max(1, ...this.ana.ranking.map((r: any) => r.rrw)); const ground = new THREE.Color(0xFBE3CB);
    for (const r of this.ana.ranking) { const n = this.nodes.get(r.id); if (n && r.rrw > 0) srcs.push({ x: n.city.x - this.riskMesh.position.x, z: n.city.z - this.riskMesh.position.z, w: r.rrw / mx }); }
    for (let i = 0; i < pos.count; i++) {
      const x = pos.getX(i), z = pos.getZ(i); let h = 0; for (const s of srcs) h += s.w * Math.exp(-((x - s.x) ** 2 + (z - s.z) ** 2) / 1500);
      h = Math.min(1, h); pos.setY(i, h * 28); const c = riskColor(h).lerp(ground, 1 - Math.min(1, h * 1.6)); col.setXYZ(i, c.r, c.g, c.b);
    }
    pos.needsUpdate = true; col.needsUpdate = true; geo.computeVertexNormals();
  }

  buildComet() {
    const n = 40; const g = new THREE.BufferGeometry(); g.setAttribute("position", new THREE.BufferAttribute(new Float32Array(n * 3), 3)); g.setAttribute("color", new THREE.BufferAttribute(new Float32Array(n * 3), 3));
    this.comet = new THREE.Points(g, new THREE.PointsMaterial({ size: 5, vertexColors: true, transparent: true, depthTest: false, depthWrite: false })); this.comet.frustumCulled = false; this.comet.visible = false; this.comet.renderOrder = 31; this.root.add(this.comet);
  }

  // ------------------------------------------------------------------ healing effects
  initFx() {
    const n = 140; const pos = new Float32Array(n * 3).fill(-9999), col = new Float32Array(n * 3), vel = new Float32Array(n * 3), life = new Float32Array(n);
    const g = new THREE.BufferGeometry(); g.setAttribute("position", new THREE.BufferAttribute(pos, 3)); g.setAttribute("color", new THREE.BufferAttribute(col, 3));
    const pts = new THREE.Points(g, new THREE.PointsMaterial({ size: 3.4, vertexColors: true, transparent: true, depthTest: false, depthWrite: false, sizeAttenuation: true })); pts.frustumCulled = false; pts.renderOrder = 32; this.root.add(pts);
    this.fx = { pts, pos, col, vel, life, base: Array.from({ length: n }, () => new THREE.Color()), n, i: 0 };
  }
  emit(at: THREE.Vector3, color: number, count = 30) {
    const f = this.fx;
    for (let k = 0; k < count; k++) {
      const i = f.i++ % f.n, a = Math.random() * Math.PI * 2, s = 6 + Math.random() * 14;
      f.pos.set([at.x, at.y + 1, at.z], i * 3); f.vel.set([Math.cos(a) * s * 0.5, 8 + Math.random() * 16, Math.sin(a) * s * 0.5], i * 3); f.life[i] = 1; f.base[i].set(color);
    }
  }
  updateFx(dt: number) {
    const f = this.fx; const bg = new THREE.Color(N.cream);
    for (let i = 0; i < f.n; i++) {
      if (f.life[i] <= 0) continue; f.life[i] -= dt * 0.7; const l = Math.max(0, f.life[i]);
      f.pos[i * 3] += f.vel[i * 3] * dt; f.pos[i * 3 + 1] += f.vel[i * 3 + 1] * dt; f.pos[i * 3 + 2] += f.vel[i * 3 + 2] * dt; f.vel[i * 3 + 1] -= 10 * dt;
      const c = f.base[i].clone().lerp(bg, 1 - l); f.col[i * 3] = c.r; f.col[i * 3 + 1] = c.g; f.col[i * 3 + 2] = c.b;
      if (l <= 0) f.pos[i * 3 + 1] = -9999;
    }
    (f.pts.geometry.attributes.position as THREE.BufferAttribute).needsUpdate = true; (f.pts.geometry.attributes.color as THREE.BufferAttribute).needsUpdate = true;
  }
  ripple(at: THREE.Vector3, color: number = N.terra, big = 1) {
    const m = new THREE.Mesh(new THREE.RingGeometry(0.82, 1, 56), new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.9, side: THREE.DoubleSide, depthTest: false, depthWrite: false }));
    m.rotation.x = -Math.PI / 2; m.position.copy(at).setY(0.6); m.renderOrder = 28; this.root.add(m); this.ripples.push({ m, t: 0, big, kind: "ring" });
  }
  beam(at: THREE.Vector3, color: number = N.aquaM) {
    const m = new THREE.Mesh(new THREE.CylinderGeometry(1.2, 1.2, 46, 16, 1, true), new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.55, depthWrite: false, depthTest: false, side: THREE.DoubleSide }));
    m.position.copy(at).setY(23); m.renderOrder = 27; this.root.add(m); this.ripples.push({ m, t: 0, big: 1, kind: "beam" });
  }
  heal(at: THREE.Vector3, strong = true) { this.ripple(at, N.aquaM, strong ? 1.3 : 0.8); if (strong) { this.beam(at); this.emit(at, N.aquaD, 34); } else this.emit(at, N.aquaM, 14); }
  updateRipples(dt: number) {
    for (const r of this.ripples) {
      r.t += dt; const dur = r.kind === "beam" ? 1.4 : 2.0, k = r.t / dur;
      if (r.kind === "ring") { r.m.scale.setScalar((2 + k * 38) * r.big); (r.m.material as any).opacity = 0.9 * (1 - k); } else { r.m.scale.set(1 + k * 3, 1, 1 + k * 3); (r.m.material as any).opacity = 0.55 * (1 - k); }
    }
    this.ripples = this.ripples.filter((r) => { if (r.t > (r.kind === "beam" ? 1.4 : 2.0)) { this.root.remove(r.m); r.m.geometry.dispose(); r.m.material.dispose(); return false; } return true; });
  }
  atNode(id: string) { return (this.nodes.get(id)?.cur || this.phys.get(id)?.obj.position)?.clone(); }

  /** Compare with the previous frame of the world and play the right animation: attacker lands = terracotta ring, defence works = aqua shield + beam. */
  diffEffects(s: any) {
    const q = new Set<string>(s.defence?.quarantined || []), b = new Set<string>(s.defence?.blocked || []), sus = new Set<string>(Object.entries<string>(s.nodes || {}).filter(([, v]) => v === "suspect").map(([k]) => k));
    const p = this.prev;
    if (p) {
      for (const id of q) if (!p.q.has(id)) { const at = this.atNode(id); if (at) this.heal(at); }
      for (const id of b) if (!p.b.has(id)) { const ce = this.cyberEdges.find((c) => c.e?.id === id); if (ce) this.heal(ce.a.cur.clone().add(ce.b.cur).multiplyScalar(0.5), false); }
      for (const id of sus) if (!p.s.has(id)) { const at = this.atNode(id); if (at) { this.ripple(at, N.terra, 1.1); this.emit(at, N.terra, 10); } }
      for (const id of p.s) if (!sus.has(id) && !q.has(id)) { const at = this.atNode(id); if (at) this.heal(at, false); }
      const ok = Object.values<any>(s.services?.hospitals || {}).every((h: any) => h.ok);
      if (ok && !p.ok) for (const h of ["H1", "H2", "H3"]) { const at = this.phys.get(h)?.obj.position; if (at) this.heal(at.clone(), true); }
      this.prev = { q, b, s: sus, ok };
    } else this.prev = { q, b, s: sus, ok: Object.values<any>(s.services?.hospitals || {}).every((h: any) => h.ok) };
    for (const ev of s.events || []) if (ev.kind === "incident_resolved" || ev.kind === "recovery") for (const h of ["H1", "H3"]) { const at = this.phys.get(h)?.obj.position; if (at) this.heal(at.clone(), false); }
    // shields around isolated devices
    for (const id of q) if (!this.shields.has(id)) {
      const n = this.nodes.get(id); if (!n) continue; const grp = new THREE.Group();
      grp.add(new THREE.Mesh(new THREE.SphereGeometry(7.5, 20, 14), new THREE.MeshBasicMaterial({ color: N.aquaM, transparent: true, opacity: 0.28, depthWrite: false })));
      const ring = new THREE.Mesh(new THREE.TorusGeometry(7.5, 0.22, 6, 40), new THREE.MeshBasicMaterial({ color: N.aquaD })); ring.rotation.x = Math.PI / 2; grp.add(ring);
      grp.scale.setScalar(0.1); this.root.add(grp); this.shields.set(id, { m: grp, t: 0, dying: false });
    }
    for (const [id, sh] of this.shields) if (!q.has(id)) sh.dying = true;
  }

  // ------------------------------------------------------------------ external state
  setSnapshot(s: any) { this.snap = s; this.diffEffects(s); }
  setAnalytics(a: any) { this.ana = a; if (a?.ranking) this.updateRisk(); }
  setUI(u: any) {
    const modeChanged = u.mode !== this.ui.mode; this.ui = u;
    if (modeChanged) { this.modeTarget = u.mode === "stack" ? 1 : 0; this.flyTo(u.mode === "stack" ? "stack" : "overview"); this.edgesDirty = true; }
    if (this.riskMesh) { this.riskMesh.visible = !!u.layers.risk; (this.riskMesh.material as any).opacity = u.layers.risk ? 0.8 : 0; }
    this.buildPath();
  }

  /** The attack route: thick, high-contrast, numbered, drawn on top of everything else. */
  buildPath() {
    const ids: string[] = this.ui.pathNodes || []; const key = ids.join(">") + "|" + this.ui.pathKind;
    if (key === this.pathKey) return; this.pathKey = key; this.clearPath();
    this.pathIds = ids; if (ids.length < 2) { this.comet.visible = false; return; }
    const col = this.ui.pathKind === "predicted" ? N.apricot : N.terra; this.cometColor = col;
    this.pathTubes = []; this.pathMarks = [];
    for (let i = 0; i < ids.length - 1; i++) {
      const halo = new THREE.Mesh(new THREE.BufferGeometry(), new THREE.MeshBasicMaterial({ color: N.ink, transparent: true, opacity: 0.28, depthTest: false, depthWrite: false })); halo.renderOrder = 24;
      const tube = new THREE.Mesh(new THREE.BufferGeometry(), new THREE.MeshBasicMaterial({ color: col, depthTest: false, depthWrite: false })); tube.renderOrder = 25; tube.userData.halo = halo;
      this.pathGroup.add(halo, tube); this.pathTubes.push(tube);
    }
    ids.forEach((id, i) => {
      const last = i === ids.length - 1; const sp = disc(last ? "!" : String(i + 1), last ? "#3A2216" : "#D46743");
      const nm = short(this.st.assets[id]?.name || this.st.physical[id]?.name || id); const lab = label(nm, 20, "#3A2216", "rgba(255,247,238,.97)", "rgba(58,34,22,.7)");
      sp.scale.set(10, 10, 1); lab.scale.multiplyScalar(1.35); this.pathGroup.add(sp, lab); this.pathMarks.push({ sp, id, lab });
    });
    this.comet.visible = true; this.rebuildPath();
  }
  clearPath() { for (const o of [...this.pathGroup.children]) { this.pathGroup.remove(o); (o as any).geometry?.dispose?.(); (o as any).material?.dispose?.(); } this.pathTubes = []; this.pathMarks = []; }
  rebuildPath() {
    const pts = this.pathIds.map((id) => (this.nodes.get(id)?.cur || this.phys.get(id)?.obj.position)?.clone()).filter(Boolean) as THREE.Vector3[]; if (pts.length < 2) return;
    this.pathCurves = pts.slice(0, -1).map((p, i) => this.curve(p, pts[i + 1]));
    this.pathTubes.forEach((t, i) => { if (!this.pathCurves[i]) return; t.geometry.dispose(); t.geometry = new THREE.TubeGeometry(this.pathCurves[i], 28, 1.15, 8, false); const h = t.userData.halo as THREE.Mesh; h.geometry.dispose(); h.geometry = new THREE.TubeGeometry(this.pathCurves[i], 28, 2.3, 8, false); });
    this.pathMarks.forEach((m, i) => { const p = pts[i]; if (!p) return; m.sp.position.copy(p).add(new THREE.Vector3(0, 6.5, 0)); if (m.lab) m.lab.position.copy(p).add(new THREE.Vector3(0, 13.5, 0)); });
  }

  flyTo(name: string, id?: string) {
    const V = (x: number, y: number, z: number) => new THREE.Vector3(x, y, z);
    const presets: Record<string, [THREE.Vector3, THREE.Vector3]> = { overview: [V(60, 300, 470), V(95, 0, -10)], stack: [V(-170, 130, 230), V(105, 55, 0)], ward: [V(20, 70, 110), V(5, 0, 40)], hospital: [V(-50, 45, 140), V(-25, 5, 125)], water: [V(70, 110, 120), V(40, 0, 30)], path: [V(60, 150, 140), V(60, 20, -50)], sion: [V(220, 90, -150), V(140, 0, -230)] };
    if (name === "node" && id) { const o = this.nodes.get(id)?.mesh.position || this.phys.get(id)?.obj.position; if (o) this.camGoal = { pos: o.clone().add(V(40, 45, 60)), look: o.clone() }; return; }
    const p = presets[name]; if (p) this.camGoal = { pos: p[0], look: p[1] };
  }

  // ------------------------------------------------------------------ frame loop
  loop = () => {
    if (this.disposed) return; this.raf = requestAnimationFrame(this.loop);
    if (document.hidden) return;
    const dt = Math.min(0.1, this.clock.getDelta()), time = this.clock.elapsedTime; this.frame++;
    this.fpsAvg = this.fpsAvg * 0.95 + (1 / Math.max(dt, 0.001)) * 0.05; if (this.frame % 90 === 0) this.adaptQuality();
    if (this.camGoal) { this.camera.position.lerp(this.camGoal.pos, 0.07); this.controls.target.lerp(this.camGoal.look, 0.09); if (this.camera.position.distanceTo(this.camGoal.pos) < 1.5) this.camGoal = null; }
    if (this.keys.size) { const sp = Math.max(60, this.camera.position.distanceTo(this.controls.target) * 1.0) * dt; const k = this.keys; this.nudgeRaw((k.has("d") || k.has("arrowright") ? 1 : 0) - (k.has("a") || k.has("arrowleft") ? 1 : 0), (k.has("w") || k.has("arrowup") ? 1 : 0) - (k.has("s") || k.has("arrowdown") ? 1 : 0), (k.has("e") ? 1 : 0) - (k.has("q") ? 1 : 0), sp); }
    this.controls.update();
    const moving = Math.abs(this.modeTarget - this.modeT) > 0.002; this.modeT += (this.modeTarget - this.modeT) * Math.min(1, dt * 3.5); const mt = this.modeT;
    if (moving) { this.edgesDirty = true; for (const n of this.nodes.values()) n.cur.lerpVectors(n.city, n.stack, mt), n.mesh.position.copy(n.cur); this.slabGroup.children.forEach((c: any) => { const m = c.material; if (m) m.opacity = c.type === "Sprite" ? mt : c.type === "LineSegments" ? 0.6 * mt : 0.12 * mt; }); }
    for (const n of this.nodes.values()) n.mesh.rotation.y += dt * 0.4;
    const pathOn = this.pathIds.length >= 2; const bt = pathOn ? 0.42 : 0.9 - 0.5 * mt; if (this.buildingMesh) { const m = this.buildingMesh.material as THREE.MeshStandardMaterial; m.opacity += (bt - m.opacity) * 0.12; }
    if (moving && pathOn) this.rebuildPath();
    this.applyState(time, dt); this.updateEdges(); this.updateParticles(dt); this.updateComet(dt); this.updateRipples(dt); this.updateFx(dt); this.updateShields(dt, time); this.updateLabels();
    if (this.needHover && this.frame % 3 === 0) { this.needHover = false; const id = this.pickAt(); if (id !== this.hoverId) { this.hoverId = id; this.renderer.domElement.style.cursor = id ? "pointer" : "grab"; this.onHover(id); } }
    this.renderer.render(this.scene, this.camera);
  };
  nudgeRaw(right: number, fwd: number, up: number, sp: number) {
    if (!right && !fwd && !up) return; const f = new THREE.Vector3(); this.camera.getWorldDirection(f); f.y = 0; f.normalize(); const r = new THREE.Vector3().crossVectors(f, new THREE.Vector3(0, 1, 0)).normalize();
    const d = f.multiplyScalar(fwd * sp).add(r.multiplyScalar(right * sp)).add(new THREE.Vector3(0, up * sp, 0)); this.camera.position.add(d); this.controls.target.add(d);
  }

  adaptQuality() {
    const f = this.fpsAvg; let q = this.quality;
    if (f < 28 && q > 0) q--; else if (f > 54 && q < 2 && this.clock.elapsedTime > 10) q++;
    if (q !== this.quality) { this.quality = q; this.renderer.setPixelRatio(q === 2 ? Math.min(1.5, devicePixelRatio) : q === 1 ? 1 : 0.75); this.resize(); this.onQuality(q); }
  }

  updateLabels() {
    if (this.frame % 6) return; const d = this.camera.position.distanceTo(this.controls.target);
    for (const t of this.tiers) t.sp.visible = t.tier === 0 ? d < 800 : t.tier === 1 ? d < 430 : d < 230;
  }

  updateShields(dt: number, time: number) {
    for (const [id, sh] of this.shields) {
      const n = this.nodes.get(id); if (!n) continue; sh.m.position.copy(n.cur);
      sh.t += dt * (sh.dying ? -2 : 3); const k = Math.max(0, Math.min(1, sh.t)); const e = 1 - Math.pow(1 - k, 3); sh.m.scale.setScalar(Math.max(0.01, e * (1 + Math.sin(time * 3) * 0.04)));
      if (sh.dying && sh.t <= 0) { this.root.remove(sh.m); sh.m.traverse((o: any) => { o.geometry?.dispose?.(); o.material?.dispose?.(); }); this.shields.delete(id); }
    }
  }

  applyState(time: number, dt: number) {
    const s = this.snap; if (!s) return; const ui = this.ui;
    const rrw: Record<string, number> = {}; let mx = 1; if (this.ana?.ranking) for (const r of this.ana.ranking) { rrw[r.id] = r.rrw; mx = Math.max(mx, r.rrw); }
    const sel = ui.selected; const adv = new Set<string>((s.adversary || []).flatMap((c: any) => c.compromised)); const hot = ui.hotNodes ? new Set<string>(ui.hotNodes) : null;
    const pathSet = new Set<string>(this.pathIds); const pathOn = pathSet.size > 1; const seeAdv = ["analyst", "admin", "operator"].includes(ui.role);
    for (const n of this.nodes.values()) {
      const st = s.nodes?.[n.id] || "normal"; const r = (rrw[n.id] || 0) / mx; let col = new THREE.Color(n.id === "INTERNET" ? N.ink : N.aquaD), em = 0;
      if (ui.layers.risk) col = riskColor(Math.pow(r, 0.6));
      if (pathOn && pathSet.has(n.id)) { col = new THREE.Color(N.terra); em = 0.25; }
      if (st === "suspect") { col = new THREE.Color(N.apricot); em = 0.3 + Math.sin(time * 6) * 0.2; }
      if (st === "quarantined") { col = new THREE.Color(N.sand); }
      if (seeAdv && adv.has(n.id) && n.id !== "INTERNET") { col = new THREE.Color(N.terra); em = 0.45 + Math.sin(time * 8) * 0.25; }
      n.mat.color.lerp(col, 0.25); n.mat.emissive.lerp(col, 0.25); n.mat.emissiveIntensity = em;
      const dim = pathOn ? (pathSet.has(n.id) ? 1 : 0.22) : sel && sel !== n.id && !(hot && hot.has(n.id)) ? 0.4 : 1; n.mat.opacity += (dim - n.mat.opacity) * 0.2; n.mat.transparent = n.mat.opacity < 0.99;
      const sc = (n.id === sel ? 1.5 : n.id === this.hoverId ? 1.25 : 1) * (1 + (r > 0.6 ? 0.2 : 0)); n.mesh.scale.lerp(new THREE.Vector3(sc, sc, sc), 0.2);
      const rm = n.ring.material as THREE.MeshBasicMaterial; rm.opacity = st === "quarantined" ? 0.9 : st === "suspect" ? 0.6 + 0.3 * Math.sin(time * 6) : n.id === sel ? 0.95 : 0; rm.color.set(st === "quarantined" ? N.aquaD : n.id === sel ? N.ink : N.terra);
    }
    const lv = s.levels || {}, served = s.services?.zones || {}, hosp = s.services?.hospitals || {}, forced = s.forced || {}, feeders = s.services?.feeders || {};
    for (const t of ["T1", "T2"]) { const p = this.phys.get(t); if (!p || !p.liq) continue; const f = Math.max(0.02, (lv[t] ?? 6) / 8); p.liq.scale.y += (f - p.liq.scale.y) * 0.15; p.liq.position.y = (p.H * p.liq.scale.y) / 2; p.liqMat.color.set(lv[t] < 2.5 ? N.terra : lv[t] < 4 ? N.apricot : N.aquaM); }
    for (const pm of ["PS1", "PS2"]) { const p = this.phys.get(pm); if (!p) continue; const on = s.pumps?.[pm] && !forced[pm]; p.rotor.rotation.z += on ? dt * 6 : 0; p.mat.color.set(forced[pm] ? N.terra : on ? N.aquaD : N.apricot); }
    for (const v of ["V1", "V2"]) { const p = this.phys.get(v); if (!p) continue; const open = (s.tele?.[v + "_pos"] ?? 1) > 0.5; p.mat.color.set(open ? N.aquaD : N.terra); p.obj.rotation.y += dt * (open ? 0.8 : 0); }
    for (const f of ["F1", "F2", "F3"]) { const p = this.phys.get("CB_" + f); if (!p) continue; const ok = feeders[f] !== false; p.mat.color.set(ok ? N.apricot : N.terra); p.mat.emissive.set(ok ? 0x000000 : N.terra); p.mat.emissiveIntensity = ok ? 0 : 0.5 + Math.sin(time * 9) * 0.3; }
    for (const h of ["H1", "H2", "H3"]) { const p = this.phys.get(h); if (!p) continue; const ok = hosp[h]?.ok !== false; p.mat.color.set(ok ? N.aquaD : N.terra); (p.shaft.material as any).color.set(ok ? N.aquaM : N.terra); (p.shaft.material as any).opacity = ok ? 0.2 : 0.35 + 0.15 * Math.sin(time * 6); }
    for (const [id, p] of this.phys) { if (!p.r) continue; const sv = served[id] ?? 1; p.mat.color.copy(riskColor((1 - sv) * 1.3)); p.mat.opacity = 0.4 + (1 - sv) * 0.4; }
    for (const p of this.pipes) {
      let f = 1;
      if (p.kind === "water") { const tag = p.tag; if (tag === "PS1" || tag === "PS2") f = s.pumps?.[tag] && !forced[tag] ? 1 : 0; else if (tag === "T1" || tag === "T2") f = (lv[tag] ?? 6) > 0.2 ? 0.8 : 0; else if (tag === "V1" || tag === "V2") f = (s.tele?.[tag + "_pos"] ?? 1) > 0.5 ? 0.5 : 0; else if (tag === "HC1") f = 0.25; else f = served[tag] ?? hosp[tag]?.served ?? 1; }
      else f = feeders[p.tag] === false ? 0 : 1;
      p.factor += (f - p.factor) * 0.15; const m = p.tube.material as THREE.MeshBasicMaterial; m.opacity = (pathOn ? 0.15 : 0.35) + 0.5 * p.factor * (pathOn ? 0.5 : 1); m.color.set(p.factor < 0.05 ? N.sand : p.kind === "water" ? N.aquaM : N.apricot);
    }
    const decoys = s.defence?.decoys || [];
    for (const d of decoys) {
      if (!this.decoyObjs.has(d.id)) { const m = new THREE.Mesh(new THREE.OctahedronGeometry(2.6), new THREE.MeshBasicMaterial({ color: N.apricot, transparent: true, opacity: 0.6, wireframe: true })); this.root.add(m); this.decoyObjs.set(d.id, m); }
      const m = this.decoyObjs.get(d.id)!; const at = this.nodes.get(d.attached_to); if (at) m.position.copy(at.cur).add(new THREE.Vector3(7, 3 + Math.sin(time * 2) * 0.6, 5)); m.visible = !!ui.xray; m.rotation.y += dt;
    }
  }

  curve(a: THREE.Vector3, b: THREE.Vector3) { const m = a.clone().add(b).multiplyScalar(0.5); m.y += 4 + a.distanceTo(b) * 0.18; return new THREE.QuadraticBezierCurve3(a, m, b); }

  updateEdges() {
    const s = this.snap; const blocked = new Set<string>(s?.defence?.blocked || []); const path = new Set<string>(this.ui.pathEdges || []); const pathOn = this.pathIds.length >= 2;
    const sel = this.ui.selected; const showEdges = this.ui.layers.links !== false; const dirty = this.edgesDirty; this.edgesDirty = false;
    for (const ce of this.cyberEdges) {
      const pa = ce.line.geometry.attributes.position as THREE.BufferAttribute;
      if (ce.ctrl) { if (dirty || !ce.init) { const b = ce.ph.obj.position; pa.setXYZ(0, ce.a.cur.x, ce.a.cur.y, ce.a.cur.z); pa.setXYZ(1, b.x, b.y + 4, b.z); pa.needsUpdate = true; ce.line.computeLineDistances(); ce.init = true; } ce.line.visible = showEdges && !pathOn; continue; }
      if (dirty || !ce.init) { const pts = this.curve(ce.a.cur, ce.b.cur).getPoints(14); pts.forEach((v, i) => pa.setXYZ(i, v.x, v.y, v.z)); pa.needsUpdate = true; if (ce.dashed) ce.line.computeLineDistances(); ce.init = true; }
      const e = ce.e; const isBlocked = blocked.has(e.id); const onPath = path.has(e.id); const touches = sel && (e.source === sel || e.target === sel);
      ce.line.visible = (showEdges && !pathOn) || touches || isBlocked; const m = ce.line.material; const base = e.known ? 0.45 : 0.85;
      m.opacity = touches ? 1 : isBlocked ? 0.6 : sel ? 0.1 : base; m.color.set(isBlocked ? N.sand : touches ? N.terra : e.known ? 0xB08B72 : N.apricot);
      this.blockMark(e.id, isBlocked, ce);
    }
  }
  blockMark(id: string, on: boolean, ce: any) {
    let sp = this.crosses.get(id);
    if (on && !sp) { sp = disc("✕", "#A94A2B", 48); sp.scale.set(5, 5, 1); this.root.add(sp); this.crosses.set(id, sp); }
    if (sp) { sp.visible = on; if (on) sp.position.copy(ce.a.cur).add(ce.b.cur).multiplyScalar(0.5).add(new THREE.Vector3(0, 4 + ce.a.cur.distanceTo(ce.b.cur) * 0.09, 0)); }
  }

  updateParticles(dt: number) {
    if (!this.pipePts) return; const pos = this.pipePts.geometry.attributes.position as THREE.BufferAttribute; const col = this.pipePts.geometry.attributes.color as THREE.BufferAttribute;
    const q = this.quality === 0 ? 3 : 1; let i = 0;
    for (const pt of this.particles) {
      const p = pt.pipe; if (i % q === 0) pt.t = (pt.t + dt * pt.spd * p.factor * (p.kind === "power" ? 1.8 : 1)) % 1; i++;
      const v = p.curve.getPoint(pt.t); pos.setXYZ(pt.slot, v.x, v.y, v.z); const a = p.factor > 0.05 ? 1 : 0.1; const c = p.kind === "water" ? [0.18, 0.48, 0.52] : [0.66, 0.29, 0.17]; col.setXYZ(pt.slot, c[0] + (1 - a) * 0.3, c[1] + (1 - a) * 0.3, c[2] + (1 - a) * 0.3);
    }
    pos.needsUpdate = true; col.needsUpdate = true;
  }

  updateComet(dt: number) {
    if (this.pathIds.length < 2 || !this.pathCurves.length) return; this.cometT = (this.cometT + dt * 0.2) % 1;
    const n = 40; const pos = this.comet.geometry.attributes.position as THREE.BufferAttribute; const col = this.comet.geometry.attributes.color as THREE.BufferAttribute; const c0 = new THREE.Color(N.ink), c1 = new THREE.Color(this.cometColor);
    for (let k = 0; k < n; k++) {
      const tt = (this.cometT - k * 0.007 + 1) % 1; const f = tt * this.pathCurves.length; const ci = Math.min(this.pathCurves.length - 1, Math.floor(f)); const v = this.pathCurves[ci].getPoint(f - ci); pos.setXYZ(k, v.x, v.y + 0.4, v.z);
      const c = c0.clone().lerp(c1, k / n); col.setXYZ(k, c.r, c.g, c.b);
    }
    pos.needsUpdate = true; col.needsUpdate = true;
  }

  /** Pixel position of a device inside the canvas (used by the control tests). */
  screenPos(id: string) {
    const o = this.nodes.get(id)?.mesh.position || this.phys.get(id)?.obj.position; if (!o) return null;
    const v = o.clone().project(this.camera); const r = this.renderer.domElement.getBoundingClientRect();
    return { x: r.left + ((v.x + 1) / 2) * r.width, y: r.top + ((1 - v.y) / 2) * r.height, behind: v.z > 1 };
  }

  pickAt(): string | null {
    this.raycaster.setFromCamera(this.pointer, this.camera); const hits = this.raycaster.intersectObjects(this.pickables, true);
    for (const h of hits) { let o: THREE.Object3D | null = h.object; while (o && !o.userData.id) o = o.parent; if (o) return o.userData.id; }
    return null;
  }

  dispose() {
    this.disposed = true; cancelAnimationFrame(this.raf); this.ro.disconnect(); window.removeEventListener("keydown", this.onKey); window.removeEventListener("keyup", this.onKeyUp);
    this.controls.dispose(); this.renderer.dispose(); this.el.removeChild(this.renderer.domElement);
  }
}
