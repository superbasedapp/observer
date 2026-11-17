// mkfixtures.js turns the outputs of the oracle steps (README.md) into the
// committed fixture files of internal/secassess/cvss4/testdata:
//
//   node mkfixtures.js <work dir> <testdata dir> <cvelistV5 commit> <cvelistV5 commit date>
//
// <work dir> holds: base-gocvss.tsv and full-gocvss.tsv (main.go over select.js's
// vectors), allbase-gocvss.tsv (main.go all-base), allbase-first.tsv (firstjs.js
// all-base), cve-rows.tsv (extract-cve.js), cve-first.tsv and cve-gocvss.tsv
// (the distinct CVE vectors scored by firstjs.js and by main.go).
"use strict";
const fs = require("fs");
const crypto = require("crypto");

const [work, out, cveCommit, cveDate] = process.argv.slice(2);
const rd = (f) => fs.readFileSync(work + "/" + f, "utf8").trim().split("\n");
const header = (lines) => lines.map((l) => "# " + l).join("\n") + "\n";
fs.mkdirSync(out, { recursive: true });

// 1 and 2: go-cvss's scores for the stratified samples
fs.writeFileSync(out + "/oracle_gocvss_base.tsv", header([
  "Expected scores from github.com/pandatix/go-cvss v0.6.4 (MIT), an implementation independent of the generated tables.",
  "A stratified sample of the 104,976 base vectors: up to 20 per reachable MacroVector, 2 per distinct score, 8 zero-impact.",
  "Produced by tools/cvss4gen/oracle (select.js then main.go); see README.md in this directory.",
  "Columns: vector, go-cvss score.",
]) + rd("base-gocvss.tsv").join("\n") + "\n");
fs.writeFileSync(out + "/oracle_gocvss_full.tsv", header([
  "Expected scores from github.com/pandatix/go-cvss v0.6.4 (MIT).",
  "Full vectors with threat, environmental and supplemental metrics: 2 per MacroVector, covering all 270.",
  "They exercise the table rows a base-only vector never reaches (EQ4 = 0, EQ5 = 1 and 2, EQ6 = 0 beside modified metrics).",
  "Columns: vector, go-cvss score.",
]) + rd("full-gocvss.tsv").join("\n") + "\n");

// 3: every base vector on which go-cvss and FIRST's calculator differ
const g = rd("allbase-gocvss.tsv").map((l) => l.split("\t"));
const f = rd("allbase-first.tsv").map((l) => l.split("\t"));
if (g.length !== 104976 || f.length !== 104976) throw new Error("the whole base space is 104,976 vectors");
const div = [];
for (let i = 0; i < g.length; i++) {
  if (g[i][0] !== f[i][0]) throw new Error("order differs at " + i);
  if (g[i][1] !== f[i][1]) div.push([g[i][0], f[i][1], g[i][1]].join("\t"));
}
fs.writeFileSync(out + "/oracle_base_divergence.tsv", header([
  "Every base vector, of all 104,976, whose score differs between FIRST's calculator (the generated scorer) and go-cvss v0.6.4.",
  "All " + div.length + " are one case: the unrounded score is exactly 4.95, which float64 holds as 4.9499999999999993.",
  "FIRST's calculator rounds that to 4.9 (Math.round); go-cvss and exact decimal arithmetic give 5.0. Same band (medium) either way.",
  "Columns: vector, FIRST calculator score, go-cvss score.",
]) + div.join("\n") + "\n");

// 4: digest of go-cvss's output over the whole base space
const sha = crypto.createHash("sha256").update(fs.readFileSync(work + "/allbase-gocvss.tsv")).digest("hex");
fs.writeFileSync(out + "/oracle_gocvss_space.txt", header([
  "sha256 of go-cvss v0.6.4's output over every base vector, one line per vector, \"vector<TAB>score<LF>\",",
  "in the canonical nested order (AV outermost; each metric's values in the order of the generated baseMetricDefs).",
  "The test regenerates the same lines from the scorer, replaces the scores listed in oracle_base_divergence.tsv by",
  "go-cvss's, and requires this digest and the count: the whole base space agrees with go-cvss except those rows.",
]) + sha + " " + g.length + "\n");

// 5: real CVE records, one row per distinct (vector, published score, severity)
const rows = rd("cve-rows.tsv").map((l) => l.split("\t"));
const groups = new Map();
for (const [id, kind, who, vec, score, sev] of rows) {
  const key = vec + "\t" + Number(score).toFixed(1) + "\t" + sev;
  if (!groups.has(key)) groups.set(key, { ids: [], who: [] });
  const grp = groups.get(key);
  if (!grp.ids.includes(id)) grp.ids.push(id);
  const w = who + (kind === "adp" ? "(adp)" : "");
  if (!grp.who.includes(w)) grp.who.push(w);
}
const cve = [];
for (const [key, v] of Array.from(groups.entries()).sort()) {
  cve.push(key + "\t" + v.ids.slice(0, 3).join(",") + (v.ids.length > 3 ? ",+" + (v.ids.length - 3) : "") + "\t" + v.who.slice(0, 3).join(","));
}
fs.writeFileSync(out + "/oracle_cve.tsv", header([
  "Published CVSS 4.0 base metrics of real CVE records, from CVEProject/cvelistV5 at commit " + cveCommit + " (" + cveDate + ").",
  "Only entries whose vector has exactly the eleven base metrics. One row per distinct (vector, published score, severity).",
  "CVE(R) is a registered trademark of The MITRE Corporation; used under the CVE Terms of Use, https://www.cve.org/Legal/TermsOfUse",
  "Columns: vector, published base score, published severity, CVE ids (first three, +N more), publishing CNAs.",
]) + cve.join("\n") + "\n");

// 6: the published rows our scorer disagrees with
const first = Object.fromEntries(rd("cve-first.tsv").map((l) => l.split("\t").slice(0, 2)));
const goc = Object.fromEntries(rd("cve-gocvss.tsv").map((l) => l.split("\t").slice(0, 2)));
const seen = new Set();
const disputed = [];
for (const [id, kind, who, vec, score] of rows) {
  const pub = Number(score).toFixed(1);
  if (pub === first[vec] || seen.has(vec + pub)) continue;
  seen.add(vec + pub);
  disputed.push([vec, pub, first[vec], goc[vec], id, who].join("\t"));
}
disputed.sort();
fs.writeFileSync(out + "/oracle_cve_disputed.tsv", header([
  "The published rows of oracle_cve.tsv whose score differs from FIRST's calculator (the generated scorer).",
  "Three vectors are errors of the publishing CNA (AMD twice, Docker once): both calculators agree with each other and not with the record.",
  "One (CVE-2026-46749) is the 4.95 rounding tie of oracle_base_divergence.tsv: the CNA published 5.0, FIRST's calculator gives 4.9.",
  "Columns: vector, published score, FIRST calculator score, go-cvss score, CVE id, publishing CNA.",
]) + disputed.join("\n") + "\n");
console.log("divergences " + div.length + "; space digest " + sha + "; cve rows " + cve.length + " of " + rows.length + " entries; disputed " + disputed.length);
