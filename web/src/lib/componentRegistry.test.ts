import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// The route-registry lint rule (modular packaging plan 5.1 rev N5, lane
// MP-DASH): lib/components.gen.ts is the ONLY module that imports a routed
// page. A per-distro build regenerates it without the pages of absent
// components; any other import of such a page would pull its chunk back into
// the bundle and silently defeat the build. The repository has no ESLint, so
// the rule is this test (the same shape as noBareDollar.test.ts): it reads
// the sources as text and fails with the offending file and line.

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REGISTRY = join(SRC, "lib", "components.gen.ts");

function registryModules(): string[] {
  const src = readFileSync(REGISTRY, "utf8");
  return [...src.matchAll(/import\("@\/pages\/([A-Za-z0-9_/]+)"\)/g)].map((m) => m[1]);
}

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(name) && !/\.test\.ts$/.test(name)) out.push(p);
  }
  return out;
}

test("the registry lists every routed page", () => {
  const mods = registryModules();
  assert.ok(mods.length >= 20, `only ${mods.length} pages in the registry`);
  for (const m of ["Overview", "Settings", "Components", "Terminals"]) {
    assert.ok(mods.includes(m), `${m} missing from components.gen.ts`);
  }
});

test("no module but components.gen.ts imports a registry page", () => {
  const mods = new Set(registryModules());
  const offenders: string[] = [];
  for (const file of walk(SRC)) {
    if (file === REGISTRY) continue;
    const lines = readFileSync(file, "utf8").split("\n");
    lines.forEach((line, i) => {
      for (const m of line.matchAll(/(?:from\s+|import\()\s*["']([^"']+)["']/g)) {
        const spec = m[1];
        let page: string | null = null;
        if (spec.startsWith("@/pages/")) page = spec.slice("@/pages/".length);
        else if (spec.startsWith(".")) {
          const abs = resolve(dirname(file), spec);
          const rel = relative(join(SRC, "pages"), abs);
          if (!rel.startsWith("..")) page = rel.replace(/\\/g, "/").replace(/\.(tsx|ts)$/, "");
        }
        // A page's own subtree (pages/security/* for pages/Security) is part
        // of that page's chunk graph already, so it may import the page.
        const ownSubtree = page != null && relative(join(SRC, "pages", page.toLowerCase()), file).split(/[\/]/)[0] !== "..";
        if (page && mods.has(page) && !ownSubtree) offenders.push(`${relative(SRC, file)}:${i + 1} imports ${spec}`);
      }
    });
  }
  assert.deepEqual(offenders, [], "import a routed page only through lib/components.gen.ts (PAGE_ROUTES)");
});

// A component-owned FEATURE module (LaunchTerminal, owned by terminals) is
// reached through its registry constant (LAUNCH_TERMINAL), never by a value
// import from an always-present module: main.tsx's dock importing it directly
// is what kept three xterm chunks in the minimal bundle (lane MP-REL2). Type
// imports are erased and stay allowed; so does the owner's own page subtree
// (Terminals and its workspace grid, and Remote, which no distro compiles
// without terminals).
test("feature modules are imported only through components.gen.ts", () => {
  const registry = readFileSync(REGISTRY, "utf8");
  const features = [...registry.matchAll(/typeof import\("@\/([A-Za-z0-9_/]+)"\)/g)].map((m) => m[1]);
  assert.ok(features.includes("components/LaunchTerminal"), "LAUNCH_TERMINAL missing from components.gen.ts");
  const owners = new Set(["pages/Terminals.tsx", "pages/Remote.tsx"]);
  const offenders: string[] = [];
  for (const file of walk(SRC)) {
    const r = relative(SRC, file).replace(/\\/g, "/");
    // A test file is never bundled, so its import pulls no chunk in.
    if (file === REGISTRY || owners.has(r) || r.startsWith("components/workspace/") || /\.test\.tsx?$/.test(r)) continue;
    const src = readFileSync(file, "utf8");
    for (const m of src.matchAll(/import\s+(type\s+)?([^;]*?)\s+from\s+["']([^"']+)["']/g)) {
      if (m[1]) continue;
      const spec = m[3].replace(/^@\//, "");
      const abs = m[3].startsWith(".") ? relative(SRC, resolve(dirname(file), m[3])).replace(/\\/g, "/") : spec;
      const target = abs.replace(/\.(tsx|ts)$/, "");
      if (!features.includes(target) || target === r.replace(/\.(tsx|ts)$/, "")) continue;
      // `import { type A, type B } from` is erased too.
      const names = m[2].replace(/[{}]/g, "").split(",").map((x) => x.trim()).filter(Boolean);
      if (names.every((n) => n.startsWith("type "))) continue;
      offenders.push(`${r} imports ${m[3]}`);
    }
  }
  assert.deepEqual(offenders, [], "render a feature module through its lib/components.gen.ts constant");
});
