// firstjs.js runs FIRST's own calculator code (the vendored JavaScript files)
// over vectors. It is a CROSS-CHECK of the Go port, not the oracle: it is the
// same code the tables came from. The oracle is the independent go-cvss run
// (main.go) and the published CVE scores.
//
//   node firstjs.js <upstream dir> all-base          every base vector
//   node firstjs.js <upstream dir> stdin < vectors   one vector per line
//
// Prints "vector<TAB>score<TAB>macro vector" per vector.
"use strict";
const fs = require("fs");
const vm = require("vm");

const [dir, mode] = process.argv.slice(2);
const code = ["cvss_lookup.js", "max_composed.js", "max_severity.js", "cvss_score.js"]
  .map((f) => fs.readFileSync(dir + "/" + f, "utf8")).join("\n");
const ctx = vm.createContext({ console });
vm.runInContext(code + "\n" + fs.readFileSync(dir + "/cvss_config.js", "utf8"), ctx);
const macroVector = vm.runInContext("macroVector", ctx);
const cvssScore = vm.runInContext("cvss_score", ctx);

// every metric starts at the configuration's "selected" value, as in the app
const defaults = {};
for (const group of Object.values(ctx.cvssConfig)) {
  for (const sub of Object.values(group.metric_groups)) {
    for (const m of Object.values(sub)) defaults[m.short] = m.selected;
  }
}

function scoreVector(v) {
  const sel = Object.assign({}, defaults);
  for (const part of v.split("/").slice(1)) {
    const [k, val] = part.split(":");
    sel[k] = val;
  }
  const mv = macroVector(sel);
  return [cvssScore(sel, ctx.cvssLookup_global, ctx.maxSeverity, mv), mv];
}

const lines = [];
if (mode === "all-base") {
  const base = [["AV", "NALP"], ["AC", "LH"], ["AT", "NP"], ["PR", "NLH"], ["UI", "NPA"], ["VC", "HLN"],
    ["VI", "HLN"], ["VA", "HLN"], ["SC", "HLN"], ["SI", "HLN"], ["SA", "HLN"]];
  const walk = (i, cur) => {
    if (i === base.length) { lines.push(cur); return; }
    for (const ch of base[i][1]) walk(i + 1, cur + "/" + base[i][0] + ":" + ch);
  };
  walk(0, "CVSS:4.0");
} else {
  for (const l of fs.readFileSync(0, "utf8").split("\n")) if (l.trim()) lines.push(l.trim().split("\t")[0]);
}
const out = [];
for (const v of lines) {
  const [s, mv] = scoreVector(v);
  out.push(v + "\t" + s.toFixed(1) + "\t" + mv);
}
process.stdout.write(out.join("\n") + "\n");
