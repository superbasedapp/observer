// T-546: the operator copy rule (no em or en dashes) extended to SOURCE,
// comments included, across every app and shared/. The trees still carry
// a few thousand legacy dashes in comments, so a full ban is not cheap; this
// is a RATCHET: each root's count may only go down. A change that adds a
// dash anywhere under these roots fails here. A change that removes some
// lowers the ceiling to the new count in the same commit (never raise it).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repo = fileURLToPath(new URL("../../../", import.meta.url));

// [root, ceiling]: the count of U+2014 / U+2013 in .ts / .tsx / .css files.
const CEILINGS: Array<[string, number]> = [
  ["web/src", 1505],
  ["web2/src", 895],
  ["shared", 404],
  ["webcloud/src", 79],
];

const DASH = /[\u2013\u2014]/g;

function walk(dir: string, out: string[]): void {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "dist") continue;
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx|css)$/.test(name)) out.push(p);
  }
}

for (const [root, ceiling] of CEILINGS) {
  test(`dash ratchet: ${root} has at most ${ceiling} em / en dashes`, () => {
    const files: string[] = [];
    walk(path.join(repo, root), files);
    let n = 0;
    const per: Array<[string, number]> = [];
    for (const f of files) {
      const c = (readFileSync(f, "utf8").match(DASH) ?? []).length;
      n += c;
      if (c) per.push([path.relative(repo, f), c]);
    }
    assert.ok(
      n <= ceiling,
      `${root}: ${n} em / en dashes, ceiling ${ceiling}. Use ASCII punctuation (a colon, a comma, " - ") ` +
        `in new copy and comments. Top files: ${per.sort((a, b) => b[1] - a[1]).slice(0, 5).map(([f, c]) => `${f} ${c}`).join(", ")}`,
    );
  });
}

test("dash ratchet: the TopBar comment named by T-546 is ASCII", () => {
  const s = readFileSync(path.join(repo, "web/src/components/TopBar.tsx"), "utf8");
  assert.doesNotMatch(s, /Extra link tools \u2014/);
});
