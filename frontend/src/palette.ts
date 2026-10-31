/** One palette for the whole product (the four supplied colours + tints/shades of them).
 *  cream  #FFEAD3  calm background, paper
 *  aqua   #BFE7EA  safe / water / healing
 *  apricot #E89B5B watch / power / attention
 *  terra  #D46743  attacker / danger
 *  Text uses a dark shade of terracotta (ink) so contrast stays high on cream. */
export const C = {
  cream: "#FFEAD3", aqua: "#BFE7EA", apricot: "#E89B5B", terra: "#D46743",
  ink: "#3A2216", ink2: "#6B4A36", dim: "#85624C",
  paper: "#FFF7EE", line: "#F0D2B4",
  aquaD: "#2F7A84", aquaM: "#6FC3CB", terraD: "#A94A2B", sand: "#A38C7B",
};

const hex = (s: string) => parseInt(s.slice(1), 16);
export const N = {
  cream: hex(C.cream), aqua: hex(C.aqua), apricot: hex(C.apricot), terra: hex(C.terra), ink: hex(C.ink), paper: hex(C.paper),
  aquaD: hex(C.aquaD), aquaM: hex(C.aquaM), terraD: hex(C.terraD), sand: hex(C.sand),
};

const STOPS = [C.aquaM, C.apricot, C.terra, C.terraD];
const rgb = (h: string) => [1, 3, 5].map((j) => parseInt(h.slice(j, j + 2), 16));
/** 0 = safe (aqua) ... 1 = critical (deep terracotta) */
export const riskColor = (t: number) => {
  t = Math.max(0, Math.min(0.999, t)); const x = t * 3, i = Math.floor(x), f = x - i;
  const a = rgb(STOPS[i]), b = rgb(STOPS[i + 1]);
  return `rgb(${a.map((v, j) => Math.round(v + (b[j] - v) * f)).join(",")})`;
};
