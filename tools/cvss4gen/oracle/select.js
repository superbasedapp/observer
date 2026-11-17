// select.js chooses which vectors go into the oracle fixtures. It runs FIRST's
// calculator JS (the vendored files) only to GROUP vectors by MacroVector so
// the sample covers every one; the expected scores in the fixtures never come
// from here, they come from the independent go-cvss runner (main.go).
//
//   node select.js <upstream dir> <out dir>
//
// Writes <out dir>/base-vectors.txt (a stratified sample of the 104,976 base
// vectors) and <out dir>/full-vectors.txt (random full vectors, threat and
// environmental metrics included, covering every one of the 270 MacroVectors
// at least PER_MACRO times). Deterministic: a fixed seed, no clock.
"use strict";
const fs = require("fs");
const vm = require("vm");

const [upstream, outDir] = process.argv.slice(2);
const PER_MACRO_BASE = 20; // base vectors per reachable MacroVector
const PER_SCORE = 2; // base vectors per distinct score value
const PER_MACRO_FULL = 2; // full vectors per MacroVector
const SEED = 0x4c565353;

const code = ["cvss_lookup.js", "max_composed.js", "max_severity.js", "cvss_score.js"]
  .map((f) => fs.readFileSync(upstream + "/" + f, "utf8")).join("\n");
const ctx = vm.createContext({});
vm.runInContext(code + "\n" + fs.readFileSync(upstream + "/cvss_config.js", "utf8"), ctx);
const macroVector = vm.runInContext("macroVector", ctx);
const cvssScore = vm.runInContext("cvss_score", ctx);

// metric -> option values (without X), and the config's defaults
const options = {};
const defaults = {};
for (const group of Object.values(ctx.cvssConfig)) {
  for (const sub of Object.values(group.metric_groups)) {
    for (const m of Object.values(sub)) {
      options[m.short] = Object.values(m.options).map((o) => o.value).filter((v) => v && v !== "X");
      defaults[m.short] = m.selected;
    }
  }
}
const BASE = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"];
// The specification's vector order: base, threat, environmental, supplemental.
const SPEC_ORDER = BASE.concat(["E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA", "S", "AU", "R", "V", "RE", "U"]);

function vectorOf(sel) {
  let v = "CVSS:4.0";
  for (const k of SPEC_ORDER) {
    if (BASE.includes(k) || sel[k] !== "X") v += "/" + k + ":" + sel[k];
  }
  return v;
}
function macroOf(sel) {
  return macroVector(sel);
}
function scoreOf(sel) {
  return cvssScore(sel, ctx.cvssLookup_global, ctx.maxSeverity, macroVector(sel));
}

// ---- base sample --------------------------------------------------------
const all = [];
(function walk(i, sel) {
  if (i === BASE.length) { all.push(Object.assign({}, sel)); return; }
  for (const v of options[BASE[i]]) { sel[BASE[i]] = v; walk(i + 1, sel); }
})(0, Object.assign({}, defaults));

const chosen = new Set();
const byMacro = new Map();
const byScore = new Map();
const zeros = [];
for (const sel of all) {
  const vec = vectorOf(sel);
  const mv = macroOf(sel);
  const sc = scoreOf(sel);
  if (!byMacro.has(mv)) byMacro.set(mv, []);
  byMacro.get(mv).push(vec);
  if (!byScore.has(sc)) byScore.set(sc, []);
  byScore.get(sc).push(vec);
  if (sc === 0) zeros.push(vec);
}
function spread(list, n) {
  if (list.length <= n) return list.slice();
  const out = [];
  for (let i = 0; i < n; i++) out.push(list[Math.floor((i * (list.length - 1)) / (n - 1))]);
  return out;
}
for (const list of byMacro.values()) for (const v of spread(list, PER_MACRO_BASE)) chosen.add(v);
for (const list of byScore.values()) for (const v of spread(list, PER_SCORE)) chosen.add(v);
for (const v of spread(zeros, 8)) chosen.add(v);
const baseVectors = Array.from(chosen).sort();
fs.writeFileSync(outDir + "/base-vectors.txt", baseVectors.join("\n") + "\n");

// ---- full-vector sample --------------------------------------------------
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(SEED);
const pick = (xs) => xs[Math.floor(rnd() * xs.length)];
const found = new Map(); // macro -> Set(vector)
const seenVec = new Set();
const MACROS = 270;
let draws = 0;
while (draws < 3000000) {
  draws++;
  const sel = {};
  for (const k of SPEC_ORDER) {
    // half the optional metrics stay not-defined, so base-only-like vectors
    // and fully specified ones both occur
    sel[k] = BASE.includes(k) ? pick(options[k]) : (rnd() < 0.5 ? "X" : pick(options[k]));
  }
  const mv = macroOf(sel);
  const vec = vectorOf(sel);
  if (seenVec.has(vec)) continue;
  let set = found.get(mv);
  if (!set) { set = new Set(); found.set(mv, set); }
  if (set.size >= PER_MACRO_FULL) continue;
  set.add(vec);
  seenVec.add(vec);
  let done = found.size === MACROS;
  if (done) for (const s of found.values()) if (s.size < PER_MACRO_FULL) { done = false; break; }
  if (done) break;
}
if (found.size !== MACROS) throw new Error("full sample covers " + found.size + " MacroVectors, want " + MACROS);
const fullVectors = [];
for (const s of found.values()) for (const v of s) fullVectors.push(v);
fullVectors.sort();
fs.writeFileSync(outDir + "/full-vectors.txt", fullVectors.join("\n") + "\n");
console.error("base sample " + baseVectors.length + " of " + all.length + "; full sample " + fullVectors.length + " covering " + found.size + " MacroVectors after " + draws + " draws");
