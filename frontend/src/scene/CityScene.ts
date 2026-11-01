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

/** One colour per layer so the stack reads at a glance (legend in the map). */
export const LAYER_COL: Record<string, number> = { internet: 0x2B2B3A, iot: 0x1FA2A6, it: 0x7B61FF, dmz: 0xF2A52B, control: 0x2E6BE6, field: 0xD46743 };
export const SECTOR_COL: Record<string, number> = { nuclear: 0xC2185B, it_hub: 0x7B61FF, factory: 0x6D4C41, hospital: 0x2F7A84, tourist: 0xF08A24, transport: 0x3949AB };
const HOT = 0xE11D48;   // the attacker's colour: crimson stands out on green land, cream roads and aqua buildings

/** Pictograms drawn on a canvas: a white glyph on a coloured disc, so each device type is recognisable without reading. */
const GLYPH: Record<string, (g: CanvasRenderingContext2D) => void> = {
  globe: (g) => { g.beginPath(); g.arc(32, 32, 14, 0, 7); g.moveTo(18, 32); g.lineTo(46, 32); g.moveTo(32, 18); g.bezierCurveTo(24, 26, 24, 38, 32, 46); g.moveTo(32, 18); g.bezierCurveTo(40, 26, 40, 38, 32, 46); g.stroke(); },
  wall: (g) => { g.strokeRect(17, 20, 30, 24); g.beginPath(); g.moveTo(17, 28); g.lineTo(47, 28); g.moveTo(17, 36); g.lineTo(47, 36); g.moveTo(27, 20); g.lineTo(27, 28); g.moveTo(37, 28); g.lineTo(37, 36); g.moveTo(27, 36); g.lineTo(27, 44); g.stroke(); },
  key: (g) => { g.beginPath(); g.arc(25, 32, 8, 0, 7); g.moveTo(33, 32); g.lineTo(48, 32); g.moveTo(42, 32); g.lineTo(42, 38); g.moveTo(47, 32); g.lineTo(47, 37); g.stroke(); },
  mail: (g) => { g.strokeRect(16, 21, 32, 22); g.beginPath(); g.moveTo(16, 22); g.lineTo(32, 35); g.lineTo(48, 22); g.stroke(); },
  monitor: (g) => { g.strokeRect(16, 19, 32, 21); g.beginPath(); g.moveTo(26, 46); g.lineTo(38, 46); g.moveTo(32, 40); g.lineTo(32, 46); g.stroke(); },
  server: (g) => { for (let i = 0; i < 3; i++) { g.strokeRect(17, 17 + i * 10, 30, 8); g.beginPath(); g.arc(24, 21 + i * 10, 1.2, 0, 7); g.fill(); } },
  db: (g) => { g.beginPath(); g.ellipse(32, 21, 13, 5, 0, 0, 7); g.moveTo(19, 21); g.lineTo(19, 43); g.ellipse(32, 43, 13, 5, 0, Math.PI, 0, true); g.lineTo(45, 21); g.moveTo(19, 32); g.ellipse(32, 32, 13, 5, 0, Math.PI, 0, true); g.stroke(); },
  panel: (g) => { g.strokeRect(16, 18, 32, 26); g.beginPath(); g.arc(25, 31, 5, Math.PI, 0); g.moveTo(25, 31); g.lineTo(28, 27); g.moveTo(36, 25); g.lineTo(43, 25); g.moveTo(36, 31); g.lineTo(43, 31); g.moveTo(36, 37); g.lineTo(43, 37); g.stroke(); },
  chip: (g) => { g.strokeRect(21, 21, 22, 22); for (let i = 0; i < 3; i++) { const o = 26 + i * 6; g.beginPath(); g.moveTo(o, 21); g.lineTo(o, 16); g.moveTo(o, 43); g.lineTo(o, 48); g.moveTo(21, o); g.lineTo(16, o); g.moveTo(43, o); g.lineTo(48, o); g.stroke(); } },
  bolt: (g) => { g.beginPath(); g.moveTo(35, 14); g.lineTo(22, 34); g.lineTo(31, 34); g.lineTo(28, 50); g.lineTo(43, 28); g.lineTo(33, 28); g.closePath(); g.stroke(); },
  cross: (g) => { g.beginPath(); g.moveTo(27, 16); g.lineTo(37, 16); g.lineTo(37, 27); g.lineTo(48, 27); g.lineTo(48, 37); g.lineTo(37, 37); g.lineTo(37, 48); g.lineTo(27, 48); g.lineTo(27, 37); g.lineTo(16, 37); g.lineTo(16, 27); g.lineTo(27, 27); g.closePath(); g.stroke(); },
  camera: (g) => { g.strokeRect(15, 24, 24, 16); g.beginPath(); g.moveTo(39, 29); g.lineTo(49, 23); g.lineTo(49, 41); g.lineTo(39, 35); g.stroke(); },
  wifi: (g) => { for (let i = 1; i <= 3; i++) { g.beginPath(); g.arc(32, 42, i * 8, Math.PI * 1.25, Math.PI * 1.75); g.stroke(); } g.beginPath(); g.arc(32, 42, 1.8, 0, 7); g.fill(); },
  plug: (g) => { g.beginPath(); g.moveTo(26, 14); g.lineTo(26, 24); g.moveTo(38, 14); g.lineTo(38, 24); g.stroke(); g.strokeRect(21, 24, 22, 10); g.beginPath(); g.moveTo(32, 34); g.lineTo(32, 48); g.stroke(); },
  lamp: (g) => { g.beginPath(); g.arc(32, 28, 10, 0, 7); g.moveTo(27, 40); g.lineTo(37, 40); g.moveTo(28, 45); g.lineTo(36, 45); g.stroke(); },
  gauge: (g) => { g.beginPath(); g.arc(32, 36, 15, Math.PI, 0); g.lineTo(17, 36); g.moveTo(32, 36); g.lineTo(40, 26); g.stroke(); },
  atom: (g) => { for (let i = 0; i < 3; i++) { g.beginPath(); g.ellipse(32, 32, 16, 6, (i * Math.PI) / 3, 0, 7); g.stroke(); } g.beginPath(); g.arc(32, 32, 2.5, 0, 7); g.fill(); },
  building: (g) => { g.strokeRect(20, 16, 24, 32); for (let r = 0; r < 4; r++) for (let c = 0; c < 2; c++) g.strokeRect(25 + c * 8, 21 + r * 7, 4, 4); },
  factory: (g) => { g.beginPath(); g.moveTo(15, 46); g.lineTo(15, 30); g.lineTo(26, 36); g.lineTo(26, 30); g.lineTo(37, 36); g.lineTo(37, 18); g.lineTo(46, 18); g.lineTo(46, 46); g.closePath(); g.stroke(); },
  palm: (g) => { g.beginPath(); g.moveTo(32, 48); g.lineTo(32, 30); g.moveTo(32, 30); g.quadraticCurveTo(22, 22, 16, 28); g.moveTo(32, 30); g.quadraticCurveTo(42, 22, 48, 28); g.moveTo(32, 30); g.quadraticCurveTo(30, 18, 24, 16); g.moveTo(32, 30); g.quadraticCurveTo(34, 18, 40, 16); g.stroke(); },
  train: (g) => { g.strokeRect(21, 16, 22, 26); g.strokeRect(25, 21, 14, 8); g.beginPath(); g.moveTo(24, 48); g.lineTo(28, 42); g.moveTo(40, 48); g.lineTo(36, 42); g.stroke(); },
};
const ICON_OF = (id: string, layer: string): string => ({ INTERNET: "globe", FW_PERIM: "wall", VPN_VENDOR: "key", MAIL_01: "mail", JUMP_RDS: "server", SCADA_WEB: "globe", HIST_01: "db", SCADA_SRV: "server", HMI_01: "panel", ENG_WS: "monitor", BMS_KEM: "cross", WIFI_PUB_01: "wifi", EVC_01: "plug", GW_METER_01: "gauge", CCTV_01: "camera", CCTV_02: "camera" } as Record<string, string>)[id]
  || (id.startsWith("OFFICE_PC") ? "monitor" : id.startsWith("GW_LIGHT") ? "lamp" : id.startsWith("RTU") ? "bolt" : id.startsWith("PLC") ? "chip" : layer === "field" ? "chip" : "server");
const SITE_ICON: Record<string, string> = { nuclear: "atom", it_hub: "building", factory: "factory", hospital: "cross", tourist: "palm", transport: "train" };
const iconTex = new Map<string, THREE.CanvasTexture>();
function iconSprite(glyph: string, fill: string, size = 9, ring = "#fff") {
  const key = glyph + fill + ring; let tex = iconTex.get(key);
  if (!tex) {
    const c = document.createElement("canvas"); c.width = c.height = 64; const g = c.getContext("2d")!;
    g.fillStyle = ring; g.beginPath(); g.arc(32, 32, 31, 0, 7); g.fill(); g.fillStyle = fill; g.beginPath(); g.arc(32, 32, 27, 0, 7); g.fill();
    g.strokeStyle = "#fff"; g.fillStyle = "#fff"; g.lineWidth = 3.4; g.lineCap = "round"; g.lineJoin = "round"; (GLYPH[glyph] || GLYPH.server)(g);
    tex = new THREE.CanvasTexture(c); tex.colorSpace = THREE.SRGBColorSpace; iconTex.set(key, tex);
  }
  const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false, depthWrite: false })); (sp.material as any).toneMapped = false; sp.scale.set(size, size, 1); sp.renderOrder = 12; return sp;
}

const labelCache = new Map<string, THREE.CanvasTexture>();
function label(text: string, size = 24, color = "#3A2216", bg = "rgba(255,247,238,.95)", border = "rgba(212,103,67,.45)") {
  const key = [text, size, color, bg].join("|"); let tex = labelCache.get(key); let w = 0, h = 0;
  const c = document.createElement("canvas"); const g = c.getContext("2d")!; g.font = `700 ${size}px Sora, system-ui, sans-serif`;
  w = Math.ceil(g.measureText(text).width) + 26; h = size + 18; c.width = w; c.height = h; g.font = `700 ${size}px Sora, system-ui, sans-serif`;
  g.fillStyle = bg; g.strokeStyle = border; g.lineWidth = 2; g.beginPath(); g.roundRect(1, 1, w - 2, h - 2, 10); g.fill(); g.stroke();
  g.fillStyle = color; g.textBaseline = "middle"; g.fillText(text, 13, h / 2 + 1);
  if (!tex) { tex = new THREE.CanvasTexture(c); tex.minFilter = THREE.LinearFilter; labelCache.set(key, tex); }
  const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false, depthTest: false }));
  (sp.material as any).toneMapped = false; sp.scale.set(w / 12, h / 12, 1); sp.renderOrder = 20; return sp;
}
function disc(text: string, fill: string, size = 56) {
  const c = document.createElement("canvas"); c.width = c.height = size; const g = c.getContext("2d")!;
  g.fillStyle = "#fff"; g.beginPath(); g.arc(size / 2, size / 2, size / 2 - 1, 0, 7); g.fill();
  g.fillStyle = fill; g.beginPath(); g.arc(size / 2, size / 2, size / 2 - 6, 0, 7); g.fill();
  g.fillStyle = "#fff"; g.font = `800 ${size * 0.55}px Sora, system-ui, sans-serif`; g.textAlign = "center"; g.textBaseline = "middle"; g.fillText(text, size / 2, size / 2 + 2);
  const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: new THREE.CanvasTexture(c), transparent: true, depthTest: false, depthWrite: false })); (sp.material as any).toneMapped = false; sp.renderOrder = 30; sp.scale.set(8, 8, 1); return sp;
}

type NodeObj = { id: string; asset: any; mesh: THREE.Object3D; city: THREE.Vector3; stack: THREE.Vector3; cur: THREE.Vector3; ring: THREE.Mesh; mat: THREE.MeshStandardMaterial; icon: THREE.Sprite };

export class CityScene {
  el: HTMLElement; onPick: (id: string | null) => void; onLocked: () => void = () => {}; onHover: (id: string | null) => void = () => {}; onQuality: (q: number) => void = () => {}; onUserMove: () => void = () => {}; badges = new Map<string, { sp: THREE.Sprite; kind: string }>(); discs = new Map<string, THREE.Mesh>();
  renderer: THREE.WebGLRenderer; scene = new THREE.Scene(); camera: THREE.PerspectiveCamera; controls: OrbitControls;
  st: any; geo: any; snap: any = null; ana: any = null; ui: any = { mode: "city", layers: {}, selected: null, xray: false, pathNodes: [], pathEdges: [], pathKind: "none" };
  nodes = new Map<string, NodeObj>(); phys = new Map<string, any>(); cyberEdges: any[] = [];
  root = new THREE.Group(); slabGroup = new THREE.Group(); riskMesh!: THREE.Mesh; pipePts!: THREE.Points; pipes: any[] = []; particles: any[] = [];
  buildingMesh: THREE.Mesh | null = null; tiers: { sp: THREE.Sprite; tier: number }[] = []; sun!: THREE.DirectionalLight;
  clock = new THREE.Clock(); raf = 0; raycaster = new THREE.Raycaster(); pointer = new THREE.Vector2(); hoverId: string | null = null; pickables: THREE.Object3D[] = [];
  camGoal: { pos: THREE.Vector3; look: THREE.Vector3 } | null = null; modeT = 0; modeTarget = 0; fpsAvg = 60; quality = 2; decoyObjs = new Map<string, THREE.Mesh>();
  hidden = false; disposed = false; ro: ResizeObserver; frame = 0; needHover = false; keys = new Set<string>(); edgesDirty = true;
  // path (attack route) drawing
  lockTiles: THREE.Mesh[] = []; pathSegs: string[][] = []; pathGroup = new THREE.Group(); pathKey = ""; pathIds: string[] = []; pathCurves: THREE.QuadraticBezierCurve3[] = []; pathTubes: THREE.Mesh[] = []; pathMarks: { sp: THREE.Sprite; id: string; lab: THREE.Sprite | null }[] = [];
  blastMesh: THREE.Group | null = null; comet!: THREE.Points; cometT = 0; cometColor = N.terra;
  // healing effects
  ripples: any[] = []; fx!: { pts: THREE.Points; pos: Float32Array; col: Float32Array; vel: Float32Array; life: Float32Array; base: THREE.Color[]; n: number; i: number };
  shields = new Map<string, { m: THREE.Group; t: number; dying: boolean }>(); crosses = new Map<string, THREE.Sprite>(); prev: { q: Set<string>; b: Set<string>; s: Set<string>; ok: boolean } | null = null; crossTex: THREE.Texture | null = null;

  constructor(el: HTMLElement, onPick: (id: string | null) => void) {
    this.el = el; this.onPick = onPick;
    this.renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: "high-performance" });
    this.renderer.setPixelRatio(Math.min(1.75, window.devicePixelRatio));
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping; this.renderer.toneMappingExposure = 1.12;   // Unity-style film tone mapping: rich colours, no chalky white
    this.renderer.shadowMap.enabled = true; this.renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    el.appendChild(this.renderer.domElement);
    this.camera = new THREE.PerspectiveCamera(48, 1, 1, 4000); this.camera.position.set(60, 300, 470);
    this.controls = new OrbitControls(this.camera, this.renderer.domElement);
    Object.assign(this.controls, { enableDamping: true, dampingFactor: 0.08, maxPolarAngle: Math.PI * 0.49, minDistance: 18, maxDistance: 1700, zoomToCursor: true, screenSpacePanning: false, rotateSpeed: 0.8, zoomSpeed: 1.1, panSpeed: 1.2 });
    this.controls.target.set(90, 0, 0);
    this.controls.mouseButtons = { LEFT: THREE.MOUSE.PAN, MIDDLE: THREE.MOUSE.DOLLY, RIGHT: THREE.MOUSE.ROTATE };   // hold + drag = move the map, right-hold + drag = turn it, wheel = zoom
    this.controls.touches = { ONE: THREE.TOUCH.PAN, TWO: THREE.TOUCH.DOLLY_ROTATE };
    this.controls.addEventListener("start", () => { this.camGoal = null; this.onUserMove(); });
    this.scene.background = this.sky(); this.scene.fog = new THREE.FogExp2(0xD9E6F2, 0.00024);
    this.scene.add(new THREE.HemisphereLight(0xBFD9F0, 0xC9A98C, 0.9));   // cool sky bounce over warm ground-bounce, like Unity's ambient
    const d = new THREE.DirectionalLight(0xfff1d6, 2.1); d.position.set(-240, 320, 170); this.scene.add(d, d.target); this.sun = d;   // warm low afternoon sun
    d.castShadow = true; d.shadow.mapSize.set(2048, 2048);
    const sc = d.shadow.camera; sc.left = -900; sc.right = 900; sc.top = 900; sc.bottom = -900; sc.near = 20; sc.far = 2600; sc.updateProjectionMatrix();
    d.shadow.bias = -0.00015; d.shadow.normalBias = 1.4;
    const fill = new THREE.DirectionalLight(0xA9C9E8, 0.6); fill.position.set(240, 200, -180); this.scene.add(fill);   // blue fill so shadowed faces stay readable
    this.scene.environment = this.pmrem();   // sky reflections for the glass towers and water
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
      const id = this.pickAt(); if (id) { this.onPick(id); return; }
      this.raycaster.setFromCamera(this.pointer, this.camera);
      if (this.raycaster.intersectObjects(this.lockTiles, false).length) this.onLocked(); else this.onPick(null);
    });
    window.addEventListener("keydown", this.onKey); window.addEventListener("keyup", this.onKeyUp);
    this.loop();
  }

  // ------------------------------------------------------------------ keyboard / pad movement (forward, back, sideways, up, down)
  onKey = (e: KeyboardEvent) => {
    const t = e.target as HTMLElement; if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (t && ["INPUT", "SELECT", "TEXTAREA", "BUTTON"].includes(t.tagName)) return;
    if (t && t.closest && t.closest(".side")) return;
    const k = e.key.toLowerCase(); if (["w", "a", "s", "d", "q", "e", "arrowup", "arrowdown", "arrowleft", "arrowright"].includes(k)) { this.keys.add(k); this.camGoal = null; this.onUserMove(); e.preventDefault(); }
  };
  onKeyUp = (e: KeyboardEvent) => { this.keys.delete(e.key.toLowerCase()); };
  nudge(right: number, fwd: number, up = 0) {
    const f = new THREE.Vector3(); this.camera.getWorldDirection(f); f.y = 0; if (f.lengthSq() < 1e-6) f.set(0, 0, -1); f.normalize();
    const r = new THREE.Vector3().crossVectors(f, new THREE.Vector3(0, 1, 0)).normalize();
    const step = Math.max(14, this.camera.position.distanceTo(this.controls.target) * 0.22);
    const dlt = f.multiplyScalar(fwd * step).add(r.multiplyScalar(right * step)).add(new THREE.Vector3(0, up * step, 0));
    this.camera.position.add(dlt); this.controls.target.add(dlt); this.camGoal = null;
  }
  zoom(factor: number) { const v = this.camera.position.clone().sub(this.controls.target); const len = Math.min(1700, Math.max(18, v.length() * factor)); this.camera.position.copy(this.controls.target).add(v.setLength(len)); this.camGoal = null; }
  turn(rad: number) { const v = this.camera.position.clone().sub(this.controls.target); v.applyAxisAngle(new THREE.Vector3(0, 1, 0), rad); this.camera.position.copy(this.controls.target).add(v); this.camGoal = null; }

  sky() {
    const c = document.createElement("canvas"); c.width = 4; c.height = 512; const g = c.getContext("2d")!;
    const gr = g.createLinearGradient(0, 0, 0, 512); gr.addColorStop(0, "#7FB8E8"); gr.addColorStop(0.55, "#C7E0F2"); gr.addColorStop(1, "#F2EFE6");
    g.fillStyle = gr; g.fillRect(0, 0, 4, 512); const t = new THREE.CanvasTexture(c); t.colorSpace = THREE.SRGBColorSpace; return t;
  }

  /** A soft sky/ground reflection preset: the cheap stand-in for Unity's ambient cubemap. */
  pmrem() {
    const c = document.createElement("canvas"); c.width = 64; c.height = 32; const g = c.getContext("2d")!;
    const gr = g.createLinearGradient(0, 0, 0, 32); gr.addColorStop(0, "#9CC7EE"); gr.addColorStop(0.5, "#D7E8F4"); gr.addColorStop(1, "#B29A7F");
    g.fillStyle = gr; g.fillRect(0, 0, 64, 32);
    const t = new THREE.CanvasTexture(c); t.mapping = THREE.EquirectangularReflectionMapping; t.colorSpace = THREE.SRGBColorSpace;
    const p = new THREE.PMREMGenerator(this.renderer); const env = p.fromEquirectangular(t).texture; p.dispose(); t.dispose(); return env;
  }

  /** Quality tiers also drive the sun shadow: off at q0, small map at q1, full at q2. */
  applyQuality() {
    const s = this.sun; if (!s) return;
    const sizes = [512, 1024, 2048];
    s.castShadow = this.quality > 0;
    const sz = sizes[Math.max(1, this.quality)];
    if (s.shadow.mapSize.x !== sz) { s.shadow.mapSize.set(sz, sz); if (s.shadow.map) { s.shadow.map.dispose(); s.shadow.map = null; } }
    this.scene.traverse((o: any) => { const ms = Array.isArray(o.material) ? o.material : o.material ? [o.material] : []; ms.forEach((m: any) => (m.needsUpdate = true)); });
  }

  /** Park trees with real shadows along the roads that leave the ward: the detail that sells the game look. */
  buildTrees(sites: THREE.Vector3[], spurs: number[][][]) {
    const greens = [0x5E9450, 0x6FA35C, 0x87B36A, 0x4E8A46].map((c) => new THREE.Color(c));
    const worldDev = Object.values<any>(this.st?.physical || {}).map((d: any) => this.p(d.xz, 0));
    const pts: { x: number; z: number; s: number }[] = [];
    const clear = (x: number, z: number, r: number) => !sites.some((s) => Math.hypot(s.x - x, s.z - z) < r) && !worldDev.some((s) => Math.hypot(s.x - x, s.z - z) < r);
    for (const l of spurs) for (let i = 0; i + 1 < l.length; i++) {
      const [ax, az] = l[i], [bx, bz] = l[i + 1]; const L = Math.hypot(bx - ax, bz - az); const n = Math.max(1, Math.floor(L / 24));
      for (let k = 1; k < n; k++) { const t = k / n; const x = ax + (bx - ax) * t + (hash(`tx${i},${k}`) - 0.5) * 9, z = az + (bz - az) * t + (hash(`tz${i},${k}`) - 0.5) * 9;
        if (Math.abs(x - this.coastX(z)) < 14 || !clear(x, z, 20) || pts.length >= 260) continue;
        if (hash(`tp${i},${k}`) < 0.55) pts.push({ x, z, s: 0.8 + hash(`ts${i},${k}`) * 0.6 }); }
    }
    for (let i = 0; i < 400 && pts.length < 340; i++) {   // clusters on the locked land east of the ward
      const x = 40 + hash(`qx${i}`) * 620 - 30, z = -520 + hash(`qz${i}`) * 1040;
      if (x < this.coastX(z) + 16 || !clear(x, z, 24) || hash(`qp${i}`) < 0.72) continue;
      pts.push({ x, z, s: 0.8 + hash(`qs${i}`) * 0.7 });
    }
    if (!pts.length) return;
    const n = pts.length; const m = new THREE.Matrix4(), q = new THREE.Quaternion();
    const trunk = new THREE.InstancedMesh(new THREE.CylinderGeometry(0.24, 0.38, 2.6, 6), new THREE.MeshStandardMaterial({ color: 0x8A6A4F, roughness: 1 }), n);
    const canopy = new THREE.InstancedMesh(new THREE.IcosahedronGeometry(1.55, 0), new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.9 }), n);
    pts.forEach((p2, i) => {
      m.compose(new THREE.Vector3(p2.x, 1.3 * p2.s, p2.z), q, new THREE.Vector3(p2.s, p2.s, p2.s)); trunk.setMatrixAt(i, m);
      m.compose(new THREE.Vector3(p2.x, 3.2 * p2.s + 0.8, p2.z), q, new THREE.Vector3(p2.s * 1.05, p2.s * 0.95, p2.s * 1.05)); canopy.setMatrixAt(i, m);
      canopy.setColorAt(i, greens[Math.floor(hash(`tc${i}`) * greens.length)]);
    });
    trunk.castShadow = canopy.castShadow = true; trunk.receiveShadow = canopy.receiveShadow = true; trunk.frustumCulled = canopy.frustumCulled = false;
    this.root.add(trunk, canopy);
  }

  resize() {
    const w = this.el.clientWidth, h = this.el.clientHeight; if (!w || !h) return;
    this.renderer.setSize(w, h); this.camera.aspect = w / h; this.camera.updateProjectionMatrix();
  }

  // ------------------------------------------------------------------ build
  setStatic(st: any, geo: any) {
    this.st = st; this.geo = geo;
    this.buildGround(); this.buildBuildings(); this.buildPhysical(); this.buildCyber(); this.buildStackSlabs(); this.buildRisk(); this.buildComet(); this.buildSites();
  }
  p(xz: number[], y = 0) { return new THREE.Vector3(xz[0] * S, y, xz[1] * S); }
  hit(o: THREE.Object3D, r: number, id: string) { const m = new THREE.Mesh(new THREE.SphereGeometry(r, 8, 6), new THREE.MeshBasicMaterial({ visible: false })); m.userData.id = id; o.add(m); }
  addLabel(sp: THREE.Sprite, tier: number) { this.root.add(sp); this.tiers.push({ sp, tier }); }

  /** The west coast: the sea lies to the west, land to the east. Returns the x of the shoreline at a given z. */
  coastX(z: number) { return -222 + 16 * Math.sin(z / 58) + 9 * Math.sin(z / 21 + 1) - Math.max(0, Math.abs(z) - 330) * 0.12; }

  buildGround() {
    const sea = new THREE.Mesh(new THREE.PlaneGeometry(6000, 6000), new THREE.MeshStandardMaterial({ color: 0x4EA3D6, roughness: 0.32, metalness: 0.06, envMapIntensity: 0.9 })); sea.rotation.x = -Math.PI / 2; sea.position.set(100, -0.6, 0); sea.receiveShadow = true; this.root.add(sea);
    const pts: THREE.Vector2[] = []; for (let z = -1100; z <= 1100; z += 14) pts.push(new THREE.Vector2(this.coastX(z), -z));
    const shape = new THREE.Shape([...pts, new THREE.Vector2(1500, -1100), new THREE.Vector2(1500, 1100)].map((v, i, arr) => i === arr.length - 1 ? v : v));
    const land = new THREE.Mesh(new THREE.ShapeGeometry(shape), new THREE.MeshStandardMaterial({ color: 0xE7DCC2, roughness: 0.95, metalness: 0 })); land.rotation.x = -Math.PI / 2; land.position.y = -0.2; land.receiveShadow = true; this.root.add(land);
    const beach = new THREE.Mesh(new THREE.BufferGeometry(), new THREE.MeshBasicMaterial({ color: 0xFFFFFF, transparent: true, opacity: 0.85, toneMapped: false }));   // a pale surf line along the shore
    beach.geometry = this.ribbon(pts.map((p) => [p.x, -p.y]), 2.2); beach.position.y = -0.1; this.root.add(beach);
    const o = this.st.meta.origin; const cosl = Math.cos((o[0] * Math.PI) / 180); const bb = this.geo?.roads?.bbox || [18.985, 72.828, 19.045, 72.868];
    const x0 = (bb[1] - o[1]) * 111320 * cosl * S, x1 = (bb[3] - o[1]) * 111320 * cosl * S, z0 = -(bb[2] - o[0]) * 110540 * S, z1 = -(bb[0] - o[0]) * 110540 * S;
    const ward = new THREE.Mesh(new THREE.PlaneGeometry(x1 - x0 + 30, z1 - z0 + 30), new THREE.MeshStandardMaterial({ color: 0xF7F3EA, roughness: 1 })); ward.rotation.x = -Math.PI / 2; ward.position.set((x0 + x1) / 2, -0.12, (z0 + z1) / 2); ward.receiveShadow = true; this.root.add(ward);
    this.wardBox = [x0 - 15, x1 + 15, z0 - 15, z1 + 15];
    this.buildRoads(); this.buildSurround();
  }

  wardBox = [-190, 255, -345, 345];

  /** A flat ribbon along a polyline (x, z pairs), w scene units wide. */
  ribbon(line: number[][], w: number) { return this.ribbons([line], () => w); }
  ribbons(lines: number[][][], widthOf: (i: number) => number) {
    let nseg = 0; for (const l of lines) nseg += Math.max(0, l.length - 1);
    const pos = new Float32Array(nseg * 18); let k = 0;
    lines.forEach((l, li) => {
      const h = widthOf(li) / 2;
      for (let i = 0; i + 1 < l.length; i++) {
        const [ax, az] = l[i], [bx, bz] = l[i + 1]; const dx = bx - ax, dz = bz - az, len = Math.hypot(dx, dz) || 1, nx = (-dz / len) * h, nz = (dx / len) * h;
        const v = [ax + nx, az + nz, ax - nx, az - nz, bx + nx, bz + nz, bx + nx, bz + nz, ax - nx, az - nz, bx - nx, bz - nz];
        for (let j = 0; j < 6; j++) { pos[k++] = v[j * 2]; pos[k++] = 0; pos[k++] = v[j * 2 + 1]; }
      }
    });
    const g = new THREE.BufferGeometry(); g.setAttribute("position", new THREE.BufferAttribute(pos, 3)); return g;
  }

  /** Real roads and railways (OpenStreetMap) drawn like an aerial map: pale road with a soft edge, rail as a dark line with a light core. */
  buildRoads() {
    const ways: any[] = this.geo?.roads?.ways || []; if (!ways.length) return; const o = this.st.meta.origin; const cosl = Math.cos((o[0] * Math.PI) / 180);
    const W: Record<string, number> = { motorway: 2.8, trunk: 2.5, primary: 2.1, secondary: 1.6, tertiary: 1.2, residential: 0.75, unclassified: 0.75 };
    const proj = (p: number[]) => [(p[0] - o[1]) * 111320 * cosl * S, -(p[1] - o[0]) * 110540 * S];
    const road = ways.filter((w) => w.k !== "rail").map((w) => ({ k: w.k, l: w.p.map(proj) })); const rail = ways.filter((w) => w.k === "rail").map((w) => w.l || w.p.map(proj));
    const mat = (c: number, off: number) => new THREE.MeshBasicMaterial({ color: c, polygonOffset: true, polygonOffsetFactor: -off, polygonOffsetUnits: -off, side: THREE.DoubleSide });
    const add = (lines: number[][][], widthOf: (i: number) => number, c: number, off: number, y: number) => { const m = new THREE.Mesh(this.ribbons(lines, widthOf), mat(c, off)); m.position.y = y; m.frustumCulled = false; this.root.add(m); };
    const lines = road.map((r) => r.l); const wd = (i: number) => W[road[i].k] ?? 0.7;
    add(lines, (i) => wd(i) + 0.45, 0xC9BFA9, 1, 0.02); add(lines, wd, 0xFFFFFF, 2, 0.04);
    add(rail, () => 1.5, 0x5C6068, 3, 0.06); add(rail, () => 0.55, 0xE9ECEF, 4, 0.08);
    this.railLines = rail;
  }
  railLines: number[][][] = [];

  /** The land around the ward: low pale blocks on a loose grid, thinning with distance, with main roads out to every Mumbai site. */
  buildSurround() {
    const bx = this.wardBox; const sites = Object.values<any>(this.st.physical).filter((p) => p.kind === "site").map((p) => this.p(p.xz, 0));
    const cell = 13; const cells: THREE.Matrix4[] = []; const cols: THREE.Color[] = []; const m = new THREE.Matrix4(); const pal = [0xE6A07C, 0xE9B27A, 0xF0C98A, 0xEBB4A4, 0xE2A0A4, 0xF3E2B8, 0xA9D3BC, 0x8FC1E3, 0x6FA6D6, 0xD9BC9C];
    for (let x = -240; x < 1000; x += cell) for (let z = -900; z < 900; z += cell) {
      const px = x + (hash(`x${x},${z}`) - 0.5) * 6, pz = z + (hash(`z${x},${z}`) - 0.5) * 6; if (px < this.coastX(pz) + 10) continue;
      if (px > bx[0] && px < bx[1] && pz > bx[2] && pz < bx[3]) continue; if (sites.some((s) => Math.hypot(s.x - px, s.z - pz) < 26)) continue;
      const d = Math.hypot(px - 30, pz); if (hash(`p${x},${z}`) > Math.exp(-d / 520) * 0.95) continue;
      const h = 0.9 + hash(`h${x},${z}`) * 3.2 * (d < 500 ? 1.3 : 0.8); m.compose(new THREE.Vector3(px, h / 2, pz), new THREE.Quaternion().setFromAxisAngle(new THREE.Vector3(0, 1, 0), (hash(`r${x},${z}`) - 0.5) * 0.5), new THREE.Vector3(3.2 + hash(`w${x},${z}`) * 3.2, h, 3.2 + hash(`d${x},${z}`) * 3.2));
      cells.push(m.clone()); cols.push(new THREE.Color(pal[Math.floor(hash(`c${x},${z}`) * pal.length)]));
    }
    if (cells.length) { const im = new THREE.InstancedMesh(new THREE.BoxGeometry(1, 1, 1), new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.88, envMapIntensity: 0.35 }), cells.length); cells.forEach((c, i) => { im.setMatrixAt(i, c); im.setColorAt(i, cols[i]); }); im.frustumCulled = false; im.castShadow = true; im.receiveShadow = true; this.root.add(im); }
    const hub = new THREE.Vector3(30, 0, 0); const lines = sites.map((s) => { const mid = hub.clone().lerp(s, 0.5); mid.x += (s.z - hub.z) * 0.06; mid.z -= (s.x - hub.x) * 0.06; return [[hub.x, hub.z], [mid.x, mid.z], [s.x, s.z]]; });
    const mk = (w: number, c: number, off: number, y: number) => { const g = this.ribbons(lines, () => w); const mm = new THREE.Mesh(g, new THREE.MeshBasicMaterial({ color: c, polygonOffset: true, polygonOffsetFactor: -off, polygonOffsetUnits: -off, side: THREE.DoubleSide })); mm.position.y = y; mm.frustumCulled = false; this.root.add(mm); };
    mk(3.4, 0xC9BFA9, 1, 0.02); mk(2.6, 0xFFFFFF, 2, 0.04);
    this.buildTrees(sites, lines);
  }

  /** Mumbai sites outside the simulated ward (BARC, IT hubs, factories, hospitals, tourist spots): placed on the locked land at their true bearing, not to scale. */
  buildSites() {
    const P = this.st.physical; const g = new THREE.Group(); this.root.add(g);
    for (const [id, s] of Object.entries<any>(P).filter(([, v]) => v.kind === "site")) {
      const col = SECTOR_COL[s.sector] ?? 0x555555; const grp = new THREE.Group(); grp.position.copy(this.p([Math.max(s.xz[0], (this.coastX(s.xz[1] * S) + 28) / S), s.xz[1]], 0)); const big = s.priority === "critical" ? 1.5 : s.priority === "high" ? 1.15 : 0.95;
      const mat = new THREE.MeshStandardMaterial({ color: col, roughness: 0.5, emissive: col, emissiveIntensity: 0.1 });
      const base = new THREE.Mesh(new THREE.CylinderGeometry(9 * big, 10 * big, 2, 6), mat); base.position.y = 0.8;
      const stem = new THREE.Mesh(new THREE.CylinderGeometry(0.6, 0.6, 18 * big, 6), new THREE.MeshBasicMaterial({ color: col })); stem.position.y = 10 * big;
      const ring = new THREE.Mesh(new THREE.TorusGeometry(12 * big, 0.5, 8, 48), new THREE.MeshBasicMaterial({ color: HOT, transparent: true, opacity: 0 })); ring.rotation.x = Math.PI / 2; ring.position.y = 1.1;
      const icon = iconSprite(SITE_ICON[s.sector] || "building", "#" + col.toString(16).padStart(6, "0"), 22 * big); icon.position.y = 22 * big;
      grp.add(base, stem, ring, icon); grp.traverse((mm: any) => { if (mm.isMesh && mm.material && !mm.material.transparent && mm.material.visible !== false) mm.castShadow = true; }); grp.userData.parts = { mat, ring, icon, site: s }; g.add(grp); grp.userData.id = id; this.hit(grp, 16 * big, id); this.pickables.push(grp); this.phys.set(id, { obj: grp, data: s, mat, ring, icon, site: s });
      const l = label(s.name.replace(/ \(.*\)/, "") + (s.priority === "critical" ? "  ·  TOP PRIORITY" : ""), 21, s.priority === "critical" ? "#fff" : "#3A2216", s.priority === "critical" ? "#C2185B" : "rgba(255,247,238,.96)", "#" + col.toString(16).padStart(6, "0")); l.scale.multiplyScalar(1.7); l.position.copy(grp.position).add(new THREE.Vector3(0, 40 * big, 0)); this.addLabel(l, 0);
    }
  }

  buildBuildings() {
    const b = this.geo?.buildings?.buildings || []; const o = this.st.meta.origin; const cosl = Math.cos((o[0] * Math.PI) / 180);
    const geos: THREE.BufferGeometry[] = [];
    // Game-style palette: warm plaster walls with occasional blue glass, saturated roofs (finite light-bounce look).
    // Mumbai-style palette: low blocks are painted plaster (terracotta, ochre, peach, rose, mint, sky, cream); tall blocks are glass in blue, teal or steel; a few are grey concrete.
    const WALL = ["#E08A63", "#D9734F", "#E9A86A", "#F0C27B", "#F2B8A0", "#E5949A", "#C97B84", "#F4E3B8", "#9FCFB5", "#7FBFA8", "#8EC3E6", "#F1D9C4", "#D6A57A", "#B9C9A0", "#C7B6E0"].map((c) => new THREE.Color(c));
    const GLASS = ["#5E9BD6", "#4F8FC9", "#6FB1DC", "#3F9FB8", "#7FA6CC", "#5B7FB0"].map((c) => new THREE.Color(c));
    const CONC = ["#B8B2A7", "#A9A49C", "#C8C0B2"].map((c) => new THREE.Color(c));
    const ROOF = ["#B5563C", "#8D9BA8", "#C76D4F", "#A97C50", "#6E8498", "#4E6E8C", "#9A4B38"].map((c) => new THREE.Color(c));
    const put = (arr: Float32Array, i: number, c: THREE.Color, k: number) => { const w = 0.02; arr[i * 3] = c.r * k * (1 - w) + w; arr[i * 3 + 1] = c.g * k * (1 - w) + w; arr[i * 3 + 2] = c.b * k * (1 - w) + w; };  // only a hint of wash: keep the game colour
    for (const bd of b) {
      const pts = bd.p.map((q: number[]) => new THREE.Vector2((q[0] - o[1]) * 111320 * cosl * S, (q[1] - o[0]) * 110540 * S)); if (pts.length < 3) continue;
      const key = JSON.stringify(bd.p[0]); const hm = bd.h || (bd.lv ? bd.lv * 3.2 : 6 + hash(key) * 16); let ge: THREE.ExtrudeGeometry;
      try { ge = new THREE.ExtrudeGeometry(new THREE.Shape(pts), { depth: hm * S * 1.2 * 1.9, bevelEnabled: false }); } catch { continue; }   // heights exaggerated 1.9x for the game look
      ge.rotateX(-Math.PI / 2);
      const tall = Math.min(1, hm / 40); const cool = hash(key + "g") < (tall > 0.45 ? 0.85 : 0.1); const grey = !cool && hash(key + "k") < 0.12;   // tall blocks go glass
      const wall = cool ? GLASS[Math.floor(hash(key + "b") * GLASS.length)] : grey ? CONC[Math.floor(hash(key + "q") * CONC.length)] : WALL[Math.floor(hash(key + "w") * WALL.length)];
      const roof = ROOF[Math.floor(hash(key + "r") * ROOF.length)]; const shade = 0.92 + hash(key + "s") * 0.16 - tall * 0.04;
      const n = ge.attributes.position.count; const nor = ge.attributes.normal; const arr = new Float32Array(n * 3);
      for (let i = 0; i < n; i++) put(arr, i, nor.getY(i) > 0.7 ? roof : wall, nor.getY(i) > 0.7 ? 0.82 : shade);
      ge.setAttribute("color", new THREE.BufferAttribute(arr, 3)); ge.deleteAttribute("uv"); geos.push(ge);
      if (hm >= 18) {   // rooftop plant room on tall blocks so they read as buildings, not extruded paper
        let mx = 1e9, Mx = -1e9, my = 1e9, My = -1e9; for (const q of pts) { mx = Math.min(mx, q.x); Mx = Math.max(Mx, q.x); my = Math.min(my, q.y); My = Math.max(My, q.y); }
        const w = Math.min(3.2, (Mx - mx) * 0.3), dd = Math.min(3.2, (My - my) * 0.3);
        if (w > 0.6 && dd > 0.6) { const box = new THREE.BoxGeometry(w, 1.3, dd).translate((mx + Mx) / 2, hm * S * 1.2 * 1.9 + 0.65, -(my + My) / 2);
          const bn = box.attributes.position.count; const barr = new Float32Array(bn * 3); const dark = roof.clone().multiplyScalar(0.8);
          for (let i = 0; i < bn; i++) put(barr, i, dark, 1); box.setAttribute("color", new THREE.BufferAttribute(barr, 3)); box.deleteAttribute("uv"); const boxgi = box.toNonIndexed(); box.dispose(); geos.push(boxgi); }
      }
    }
    if (!geos.length) return;
    this.buildingMesh = new THREE.Mesh(mergeGeometries(geos, false)!, new THREE.MeshStandardMaterial({ vertexColors: true, transparent: true, opacity: 1, roughness: 0.72, metalness: 0.06, envMapIntensity: 0.45 }));
    this.buildingMesh.castShadow = true; this.buildingMesh.receiveShadow = true;
    this.root.add(this.buildingMesh); geos.forEach((g) => g.dispose());
  }

  buildPhysical() {
    const P = this.st.physical; const g = new THREE.Group(); this.root.add(g);
    const add = (id: string, obj: THREE.Object3D, data: any, hitR = 7) => { obj.userData.id = id; g.add(obj); obj.traverse((mm: any) => { if (mm.isMesh && mm.material && !mm.material.transparent && mm.material.visible !== false) mm.castShadow = true; }); this.hit(obj, hitR, id); this.pickables.push(obj); this.phys.set(id, { obj, data, ...(obj.userData.parts || {}) }); };
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
      const tube = new THREE.Mesh(new THREE.TubeGeometry(p.curve, 20, p.kind === "water" ? 0.5 * p.w : 0.2, 6, false), new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.8, toneMapped: false }));
      p.tube = tube; this.root.add(tube); p.base = i * NP; p.factor = 1;
      for (let k = 0; k < NP; k++) this.particles.push({ pipe: p, t: k / NP, spd: 0.18 + hash(p.id + k) * 0.08, slot: p.base + k });
    });
    const geo = new THREE.BufferGeometry(); geo.setAttribute("position", new THREE.BufferAttribute(positions, 3)); geo.setAttribute("color", new THREE.BufferAttribute(colors, 3));
    this.pipePts = new THREE.Points(geo, new THREE.PointsMaterial({ size: 1.9, vertexColors: true, transparent: true, opacity: 1, depthWrite: false, sizeAttenuation: true, toneMapped: false })); this.pipePts.frustumCulled = false; this.root.add(this.pipePts);
  }

  buildCyber() {
    const A = this.st.assets; const groups = new Map<string, string[]>();
    for (const [id, a] of Object.entries<any>(A)) { const k = `${Math.round(a.xz[0] / 40)}_${Math.round(a.xz[1] / 40)}`; (groups.get(k) || groups.set(k, []).get(k)!).push(id); }
    for (const [, ids] of groups) ids.forEach((id, i) => {
      const a = A[id]; const lc = LAYER_COL[a.layer] ?? N.aquaD; const mat = new THREE.MeshStandardMaterial({ color: lc, roughness: 0.4, metalness: 0.1 });
      const mesh = new THREE.Mesh(a.layer === "internet" ? new THREE.IcosahedronGeometry(7, 1) : new THREE.CylinderGeometry(4.6, 5.2, 1.5, 24), mat); mesh.userData.id = id;
      const icon = iconSprite(ICON_OF(id, a.layer), "#" + lc.toString(16).padStart(6, "0"), id === "INTERNET" ? 13 : 9.5); icon.position.y = id === "INTERNET" ? 0 : 6.5; icon.userData.id = id; mesh.add(icon);
      const ang = (i / ids.length) * Math.PI * 2, rad = ids.length > 1 ? 6 + ids.length * 0.8 : 0;
      let base = this.p(a.xz, 0); if (id === "INTERNET") base = new THREE.Vector3(-30, 0, -250);
      const city = base.clone().add(new THREE.Vector3(Math.cos(ang) * rad, 0, Math.sin(ang) * rad)); city.y = id === "INTERNET" ? 110 : a.layer === "field" ? 9 : a.layer === "control" ? 13 : a.layer === "dmz" ? 17 : 21;
      const stack = city.clone(); stack.y = STACK_Y[a.layer] ?? 40; if (id === "INTERNET") stack.set(-30, 120, -240);
      const ring = new THREE.Mesh(new THREE.TorusGeometry(5.6, 0.34, 8, 40), new THREE.MeshBasicMaterial({ color: N.terra, transparent: true, opacity: 0 })); ring.rotation.x = Math.PI / 2; mesh.add(ring);
      this.hit(mesh, 6.5, id); mesh.position.copy(city); this.root.add(mesh); this.pickables.push(mesh);
      this.nodes.set(id, { id, asset: a, mesh, city, stack, cur: city.clone(), ring, mat, icon });
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
    this.riskMesh = new THREE.Mesh(geo, new THREE.MeshBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.0, depthWrite: false, toneMapped: false }));
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
    this.comet = new THREE.Points(g, new THREE.PointsMaterial({ size: 5, vertexColors: true, transparent: true, depthTest: false, depthWrite: false, toneMapped: false })); this.comet.frustumCulled = false; this.comet.visible = false; this.comet.renderOrder = 31; this.root.add(this.comet);
  }

  // ------------------------------------------------------------------ healing effects
  initFx() {
    const n = 140; const pos = new Float32Array(n * 3).fill(-9999), col = new Float32Array(n * 3), vel = new Float32Array(n * 3), life = new Float32Array(n);
    const g = new THREE.BufferGeometry(); g.setAttribute("position", new THREE.BufferAttribute(pos, 3)); g.setAttribute("color", new THREE.BufferAttribute(col, 3));
    const pts = new THREE.Points(g, new THREE.PointsMaterial({ size: 3.4, vertexColors: true, transparent: true, depthTest: false, depthWrite: false, sizeAttenuation: true, toneMapped: false })); pts.frustumCulled = false; pts.renderOrder = 32; this.root.add(pts);
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
    const m = new THREE.Mesh(new THREE.RingGeometry(0.82, 1, 56), new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.9, side: THREE.DoubleSide, depthTest: false, depthWrite: false, toneMapped: false }));
    m.rotation.x = -Math.PI / 2; m.position.copy(at).setY(0.6); m.renderOrder = 28; this.root.add(m); this.ripples.push({ m, t: 0, big, kind: "ring" });
  }
  beam(at: THREE.Vector3, color: number = N.aquaM) {
    const m = new THREE.Mesh(new THREE.CylinderGeometry(1.2, 1.2, 46, 16, 1, true), new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.55, depthWrite: false, depthTest: false, side: THREE.DoubleSide, toneMapped: false }));
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
      grp.add(new THREE.Mesh(new THREE.SphereGeometry(7.5, 20, 14), new THREE.MeshBasicMaterial({ color: N.aquaM, transparent: true, opacity: 0.28, depthWrite: false, toneMapped: false })));
      const ring = new THREE.Mesh(new THREE.TorusGeometry(7.5, 0.22, 6, 40), new THREE.MeshBasicMaterial({ color: N.aquaD, toneMapped: false })); ring.rotation.x = Math.PI / 2; grp.add(ring);
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

  /** The highlighted route or set of links: thick, high-contrast, drawn on top of everything else. A route is numbered; a set of links is not. */
  buildPath() {
    const ids: string[] = this.ui.pathNodes || []; const given: string[][] | undefined = this.ui.pathSegs;
    const segs: string[][] = given?.length ? given : ids.slice(0, -1).map((a, i) => [a, ids[i + 1]]);
    const nodes = [...new Set([...segs.flat(), ...ids, ...(this.ui.pathMarks || [])])]; const numbered = !given?.length && ids.length >= 2 && this.ui.pathNumbered !== false;
    const key = JSON.stringify([segs, nodes, this.ui.pathKind, numbered]);
    if (key === this.pathKey) return; this.pathKey = key; this.clearPath();
    this.pathIds = nodes; this.pathSegs = segs; if (!nodes.length) { this.comet.visible = false; this.pathCurves = []; return; }
    const kind = this.ui.pathKind; const col = kind === "predicted" ? 0xF28C1B : kind === "defence" ? N.aquaD : HOT; const hex = kind === "predicted" ? "#F28C1B" : kind === "defence" ? "#2F7A84" : "#E11D48"; this.cometColor = col;
    this.pathTubes = []; this.pathMarks = [];
    for (let i = 0; i < segs.length; i++) {
      const halo = new THREE.Mesh(new THREE.BufferGeometry(), new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.6, depthTest: false, depthWrite: false, toneMapped: false })); halo.renderOrder = 24;
      const tube = new THREE.Mesh(new THREE.BufferGeometry(), new THREE.MeshBasicMaterial({ color: col, depthTest: false, depthWrite: false, toneMapped: false })); tube.renderOrder = 25; tube.userData.halo = halo;
      this.pathGroup.add(halo, tube); this.pathTubes.push(tube);
    }
    nodes.forEach((id) => {
      const idx = ids.indexOf(id); const last = numbered && idx === ids.length - 1 && kind !== "defence";
      const sp = disc(numbered ? (last ? "!" : String(idx + 1)) : kind === "defence" ? "✓" : "", last ? "#3A2216" : hex);
      const nm = short(this.st.assets[id]?.name || this.st.physical[id]?.name || id); const lab = label(nm, 20, "#3A2216", "rgba(255,247,238,.97)", "rgba(58,34,22,.7)");
      sp.scale.set(11, 11, 1); lab.scale.multiplyScalar(1.35); this.pathGroup.add(sp, lab); this.pathMarks.push({ sp, id, lab });
    });
    this.comet.visible = segs.length > 0; this.rebuildPath();
  }
  clearPath() { for (const o of [...this.pathGroup.children]) { this.pathGroup.remove(o); (o as any).geometry?.dispose?.(); (o as any).material?.dispose?.(); } this.pathTubes = []; this.pathMarks = []; this.pathCurves = []; }
  posOf(id: string) { const n = this.nodes.get(id); if (n) return n.cur.clone(); const p = this.phys.get(id)?.obj.position; return p ? p.clone().add(new THREE.Vector3(0, 3, 0)) : null; }
  rebuildPath() {
    this.pathCurves = [];
    this.pathSegs.forEach(([a, b], i) => {
      const pa = this.posOf(a), pb = this.posOf(b), t = this.pathTubes[i]; if (!pa || !pb || !t) return;
      const cv = this.curve(pa, pb); this.pathCurves.push(cv);
      t.geometry.dispose(); t.geometry = new THREE.TubeGeometry(cv, 28, 2.2, 8, false); const h = t.userData.halo as THREE.Mesh; h.geometry.dispose(); h.geometry = new THREE.TubeGeometry(cv, 28, 3.2, 8, false);
    });
    this.pathMarks.forEach((m) => { const p = this.posOf(m.id); if (!p) return; m.sp.position.copy(p).add(new THREE.Vector3(0, 6.5, 0)); if (m.lab) m.lab.position.copy(p).add(new THREE.Vector3(0, 13.5, 0)); });
  }

  /** Move the camera so every listed device is in view (used when a side-panel choice highlights a path). */
  frameNodes(ids: string[], close = false) {
    const pts = ids.map((i) => this.posOf(i)).filter(Boolean) as THREE.Vector3[]; if (!pts.length) return;
    const box = new THREE.Box3().setFromPoints(pts); const c = box.getCenter(new THREE.Vector3()); const size = Math.max(box.max.x - box.min.x, box.max.z - box.min.z, close ? 34 : 120);
    const k = close ? 0.62 : 0.85;   // close = zoom right in on the equipment
    this.camGoal = { pos: new THREE.Vector3(c.x + size * 0.3, Math.min(1100, size * k + (close ? 26 : 55)), c.z + size * (close ? 0.75 : 0.95)), look: new THREE.Vector3(c.x, 0, c.z) };
  }

  flyTo(name: string, id?: string) {
    const V = (x: number, y: number, z: number) => new THREE.Vector3(x, y, z);
    const presets: Record<string, [THREE.Vector3, THREE.Vector3]> = { overview: [V(60, 300, 470), V(95, 0, -10)], stack: [V(-170, 130, 230), V(105, 55, 0)], ward: [V(20, 70, 110), V(5, 0, 40)], hospital: [V(-50, 45, 140), V(-25, 5, 125)], water: [V(70, 110, 120), V(40, 0, 30)], path: [V(60, 150, 140), V(60, 20, -50)], sion: [V(220, 90, -150), V(140, 0, -230)] };
    if (name === "node" && id) { const o = this.nodes.get(id)?.mesh.position || this.phys.get(id)?.obj.position; if (o) this.camGoal = { pos: o.clone().add(V(40, 45, 60)), look: o.clone() }; return; }
    if (name === "hospital") { this.frameNodes(["H1", "H2", "H3"], true); return; }
    if (name === "water") { this.frameNodes(["PS1", "PS2", "T1", "T2", "V1", "V2"], true); return; }
    if (name === "power") { this.frameNodes(["CB_F1", "CB_F2", "CB_F3", "PS1", "PS2"], true); return; }
    if (name === "mumbai") { const ids = Object.keys(this.st.physical).filter((k) => this.st.physical[k].kind === "site"); this.frameNodes([...ids, "H1", "T1"]); return; }
    const p = presets[name]; if (p) this.camGoal = { pos: p[0], look: p[1] };
  }

  // ------------------------------------------------------------------ frame loop
  loop = () => {
    if (this.disposed) return; this.raf = requestAnimationFrame(this.loop);
    if (document.hidden || this.hidden) return;
    const dt = Math.min(0.1, this.clock.getDelta()), time = this.clock.elapsedTime; this.frame++;
    this.fpsAvg = this.fpsAvg * 0.95 + (1 / Math.max(dt, 0.001)) * 0.05; if (this.frame % 90 === 0) this.adaptQuality();
    if (this.camGoal) { this.camera.position.lerp(this.camGoal.pos, 0.07); this.controls.target.lerp(this.camGoal.look, 0.09); if (this.camera.position.distanceTo(this.camGoal.pos) < 1.5) this.camGoal = null; }
    if (this.keys.size) { const sp = Math.max(60, this.camera.position.distanceTo(this.controls.target) * 1.0) * dt; const k = this.keys; this.nudgeRaw((k.has("d") || k.has("arrowright") ? 1 : 0) - (k.has("a") || k.has("arrowleft") ? 1 : 0), (k.has("w") || k.has("arrowup") ? 1 : 0) - (k.has("s") || k.has("arrowdown") ? 1 : 0), (k.has("e") ? 1 : 0) - (k.has("q") ? 1 : 0), sp); }
    this.controls.update();
    const moving = Math.abs(this.modeTarget - this.modeT) > 0.002; this.modeT += (this.modeTarget - this.modeT) * Math.min(1, dt * 3.5); const mt = this.modeT;
    if (moving) { this.edgesDirty = true; for (const n of this.nodes.values()) n.cur.lerpVectors(n.city, n.stack, mt), n.mesh.position.copy(n.cur); this.slabGroup.children.forEach((c: any) => { const m = c.material; if (m) m.opacity = c.type === "Sprite" ? mt : c.type === "LineSegments" ? 0.6 * mt : 0.12 * mt; }); }
    for (const n of this.nodes.values()) n.mesh.rotation.y += dt * 0.4;
    const pathOn = this.pathIds.length >= 1; const bt = pathOn ? 0.55 : 0.97 - 0.57 * mt; if (this.buildingMesh) { const m = this.buildingMesh.material as THREE.MeshStandardMaterial; m.opacity += (bt - m.opacity) * 0.12; }
    if (moving && pathOn) this.rebuildPath();
    this.applyState(time, dt); this.updateEdges(); this.updateParticles(dt); this.updateComet(dt); this.updateRipples(dt); this.updateFx(dt); this.updateShields(dt, time); this.updateLabels(); this.blastRings(time);
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
    if (q !== this.quality) { this.quality = q; this.renderer.setPixelRatio(q === 2 ? Math.min(1.75, devicePixelRatio) : q === 1 ? 1 : 0.75); this.resize(); this.applyQuality(); this.onQuality(q); }
  }

  updateLabels() {
    if (this.frame % 6) return; const d = this.camera.position.distanceTo(this.controls.target);
    for (const t of this.tiers) t.sp.visible = t.tier === 0 ? d < 1500 : t.tier === 1 ? d < 700 : d < 260;
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
    const sel = ui.selected; const affectedNow = (s.incidents || []).some((i: any) => i.status === "open" || i.status === "contained") || (s.adversary || []).some((c: any) => c.state !== "done" && c.state !== "contained");   // once the incident is resolved the map goes back to normal
    const adv = new Set<string>(affectedNow ? (s.adversary || []).flatMap((c: any) => c.compromised) : []); const hot = ui.hotNodes ? new Set<string>(ui.hotNodes) : null;
    const pathSet = new Set<string>(this.pathIds); const pathOn = pathSet.size >= 1; const seeAdv = ["analyst", "admin", "operator"].includes(ui.role);
    for (const n of this.nodes.values()) {
      const st = s.nodes?.[n.id] || "normal"; const r = (rrw[n.id] || 0) / mx; const lcol = LAYER_COL[n.asset.layer] ?? N.aquaD; let col = new THREE.Color(lcol), em = 0;
      if (ui.layers.risk) col = riskColor(Math.pow(r, 0.6));
      if (pathOn && pathSet.has(n.id)) { col = new THREE.Color(ui.pathKind === "defence" ? N.aquaD : HOT); em = 0.3; }
      if (st === "suspect") { col = new THREE.Color(N.apricot); em = 0.3 + Math.sin(time * 6) * 0.2; }
      if (st === "quarantined") { col = new THREE.Color(N.sand); }
      if (seeAdv && adv.has(n.id) && n.id !== "INTERNET" && st !== "quarantined") { col = new THREE.Color(HOT); em = 0.45 + Math.sin(time * 8) * 0.25; }
      const bp = ui.blast ? ui.blast[n.id] : undefined; if (bp !== undefined && n.id !== ui.selected) { col = new THREE.Color(HOT).lerp(new THREE.Color(N.apricot), 1 - Math.min(1, bp * 1.6)); em = 0.35 + Math.sin(time * 5) * 0.15; }
      n.mat.color.lerp(col, 0.25); n.mat.emissive.lerp(col, 0.25); n.mat.emissiveIntensity = em;
      const dim = pathOn ? (pathSet.has(n.id) ? 1 : 0.22) : sel && sel !== n.id && !(hot && hot.has(n.id)) ? 0.4 : 1; n.mat.opacity += (dim - n.mat.opacity) * 0.2; n.mat.transparent = n.mat.opacity < 0.99; (n.icon.material as THREE.SpriteMaterial).opacity = Math.max(0.35, n.mat.opacity);
      const sc = (n.id === sel ? 1.5 : n.id === this.hoverId ? 1.25 : 1) * (1 + (r > 0.6 ? 0.2 : 0)); n.mesh.scale.lerp(new THREE.Vector3(sc, sc, sc), 0.2);
      const rm = n.ring.material as THREE.MeshBasicMaterial; rm.opacity = st === "quarantined" ? 0.9 : st === "suspect" ? 0.6 + 0.3 * Math.sin(time * 6) : seeAdv && adv.has(n.id) && n.id !== "INTERNET" ? 0.95 : n.id === sel ? 0.95 : 0; rm.color.set(st === "quarantined" ? N.aquaD : n.id === sel ? N.ink : HOT);
    }
    // status badges: a big, unmistakable marker above every device that is taken over, suspected or cut off
    for (const n of this.nodes.values()) {
      if (n.id === "INTERNET") continue; const stt = s.nodes?.[n.id] || "normal";
      const kind = stt === "quarantined" ? "cut" : seeAdv && adv.has(n.id) ? "taken" : stt === "suspect" ? "suspect" : "";
      let b = this.badges.get(n.id);
      if (kind && (!b || b.kind !== kind)) {
        if (b) { this.root.remove(b.sp); b.sp.material.dispose(); }
        const sp = disc(kind === "taken" ? "!" : kind === "suspect" ? "?" : "✓", kind === "taken" ? "#E11D48" : kind === "suspect" ? "#F28C1B" : "#2F7A84", 64); sp.scale.set(8.5, 8.5, 1); this.root.add(sp); b = { sp, kind }; this.badges.set(n.id, b);
      }
      if (b) { b.sp.visible = !!kind; if (kind) { b.sp.position.set(n.cur.x, n.cur.y + 13 + (kind === "taken" ? Math.sin(time * 6) * 0.9 : 0), n.cur.z); const k2 = kind === "taken" ? 1 + 0.12 * Math.sin(time * 6) : 1; b.sp.scale.set(8.5 * k2, 8.5 * k2, 1); } }
    }
    if (seeAdv) {   // affected area: a soft red disc on the ground under every device the attacker holds
      for (const id of adv) { if (id === "INTERNET" || s.nodes?.[id] === "quarantined") continue; const n = this.nodes.get(id); if (!n) continue; let d = this.discs.get(id);
        if (!d) { d = new THREE.Mesh(new THREE.CircleGeometry(18, 40), new THREE.MeshBasicMaterial({ color: HOT, transparent: true, opacity: 0.16, depthWrite: false, toneMapped: false, polygonOffset: true, polygonOffsetFactor: -6, polygonOffsetUnits: -6 })); d.rotation.x = -Math.PI / 2; d.renderOrder = 4; this.root.add(d); this.discs.set(id, d); }
        d.position.set(n.cur.x, 0.5, n.cur.z); d.visible = true; (d.material as THREE.MeshBasicMaterial).opacity = 0.12 + 0.07 * Math.sin(time * 4); }
      for (const [id, d] of this.discs) if (!adv.has(id) || s.nodes?.[id] === "quarantined") d.visible = false;
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
    for (const [id, p] of this.phys) {   // Mumbai sites: a red pulsing ring when a device they rely on is compromised or suspect
      if (!p.site) continue; const dep: string[] = p.site.depends_on || []; const hit = dep.some((d) => adv.has(d) || (s.nodes?.[d] && s.nodes[d] !== "normal")); const bl = ui.blast && dep.some((d) => ui.blast[d] !== undefined);
      const rm = p.ring.material as THREE.MeshBasicMaterial; rm.opacity = hit || bl || ui.selected === id ? 0.7 + 0.25 * Math.sin(time * 5) : 0; rm.color.set(ui.selected === id && !hit && !bl ? N.ink : HOT); p.mat.emissiveIntensity = hit || bl ? 0.5 : 0.1;
      const k2 = id === ui.selected ? 1.3 : id === this.hoverId ? 1.15 : 1; p.obj.scale.lerp(new THREE.Vector3(k2, k2, k2), 0.2);
    }
    const decoys = s.defence?.decoys || [];
    for (const d of decoys) {
      if (!this.decoyObjs.has(d.id)) { const m = new THREE.Mesh(new THREE.OctahedronGeometry(2.6), new THREE.MeshBasicMaterial({ color: N.apricot, transparent: true, opacity: 0.6, wireframe: true })); this.root.add(m); this.decoyObjs.set(d.id, m); }
      const m = this.decoyObjs.get(d.id)!; const at = this.nodes.get(d.attached_to); if (at) m.position.copy(at.cur).add(new THREE.Vector3(7, 3 + Math.sin(time * 2) * 0.6, 5)); m.visible = !!ui.xray; m.rotation.y += dt;
    }
  }

  blastRings(time: number) {
    const c = this.ui.blast && this.ui.selected ? this.posOf(this.ui.selected) : null;
    if (!c) { if (this.blastMesh) this.blastMesh.visible = false; return; }
    if (!this.blastMesh) {
      this.blastMesh = new THREE.Group();
      for (let i = 0; i < 3; i++) { const r = new THREE.Mesh(new THREE.RingGeometry(0.9, 1, 64), new THREE.MeshBasicMaterial({ color: HOT, transparent: true, opacity: 0.5, side: THREE.DoubleSide, depthWrite: false, depthTest: false, toneMapped: false })); r.rotation.x = -Math.PI / 2; r.renderOrder = 22; this.blastMesh.add(r); }
      this.root.add(this.blastMesh);
    }
    const near = Object.keys(this.ui.blast).filter((id) => this.st.assets[id]).map((id) => { const q = this.posOf(id); return q ? q.distanceTo(c) : 0; });   // devices only: far Mumbai sites must not stretch the rings
    const reach = Math.min(46, Math.max(22, ...near));
    this.blastMesh.visible = true; this.blastMesh.position.set(c.x, 0.7, c.z);
    this.blastMesh.children.forEach((r: any, i) => { const k = ((time * 0.35 + i / 3) % 1); r.scale.setScalar(6 + k * reach * 1.05); r.material.opacity = 0.55 * (1 - k); });
  }

  curve(a: THREE.Vector3, b: THREE.Vector3) { const m = a.clone().add(b).multiplyScalar(0.5); m.y += 4 + a.distanceTo(b) * 0.18; return new THREE.QuadraticBezierCurve3(a, m, b); }

  updateEdges() {
    const s = this.snap; const blocked = new Set<string>(s?.defence?.blocked || []); const path = new Set<string>(this.ui.pathEdges || []); const pathOn = this.pathIds.length >= 1;
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
    if (!this.pathCurves.length) return; this.cometT = (this.cometT + dt * 0.2) % 1;
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
