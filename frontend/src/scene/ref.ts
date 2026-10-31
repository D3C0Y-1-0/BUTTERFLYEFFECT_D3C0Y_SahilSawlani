import type { CityScene } from "./CityScene";

/** The one live 3D scene (set by the map component, used by the control pad, the tour and the pages). */
export const scene: { current: CityScene | null } = { current: null };
if (typeof window !== "undefined") (window as any).__decoyScene = scene;   // read-only handle for automated UI tests
