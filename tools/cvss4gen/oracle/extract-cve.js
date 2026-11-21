// extract-cve.js reads CVE records (cvelistV5 JSON files in one directory) and
// prints one line for every CVSS 4.0 metric whose vector carries exactly the
// eleven base metrics (a threat or environmental part is skipped):
//
//   node extract-cve.js <records dir> > cve-rows.tsv
//
// Columns: CVE id, container (cna|adp), publishing organisation, vector,
// published base score, published severity (lower case). A summary of what was
// read and skipped goes to stderr.
"use strict";
const fs = require("fs");
const path = require("path");

const dir = process.argv[2];
const baseRe = /^CVSS:4\.0\/AV:[NALP]\/AC:[LH]\/AT:[NP]\/PR:[NLH]\/UI:[NPA]\/VC:[HLN]\/VI:[HLN]\/VA:[HLN]\/SC:[HLN]\/SI:[HLN]\/SA:[HLN]$/;
const rows = [];
let files = 0, unreadable = 0, v4 = 0, nonBase = 0;
for (const f of fs.readdirSync(dir).sort()) {
  let j;
  try { j = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")); } catch (e) { unreadable++; continue; }
  files++;
  const id = j.cveMetadata && j.cveMetadata.cveId;
  const containers = [];
  if (j.containers && j.containers.cna) containers.push(["cna", j.containers.cna]);
  for (const adp of (j.containers && j.containers.adp) || []) containers.push(["adp", adp]);
  for (const [kind, c] of containers) {
    for (const m of c.metrics || []) {
      const x = m.cvssV4_0;
      if (!x) continue;
      v4++;
      if (!baseRe.test(x.vectorString || "")) { nonBase++; continue; }
      const pm = c.providerMetadata || {};
      rows.push([id, kind, pm.shortName || pm.orgId, x.vectorString, x.baseScore, String(x.baseSeverity).toLowerCase()]);
    }
  }
}
console.error("records=" + files + " unreadable=" + unreadable + " cvss4 entries=" + v4 + " skipped (not base-only)=" + nonBase + " kept=" + rows.length);
for (const r of rows) console.log(r.join("\t"));
