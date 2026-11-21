// test-components.mjs runs webcloud's component tests (every
// src/components/**/*.test.tsx and src/staff/**/*.test.tsx) under node's own test runner. It is the
// webcloud twin of web2/scripts/test-components.mjs (plan 07 M6.5 added the
// first webcloud render tests, for the Teams pages). Node strips TypeScript
// types but does not transform JSX, so each test file is bundled first with
// esbuild (the copy vite itself depends on) into node_modules/.cache, where
// node resolves react and the other packages from the workspace's
// node_modules: one React instance, the same one the app uses. The alias is
// vite.config.ts's (@shared); stylesheets load as empty modules. Component
// tests render with react-dom/server, so they need no DOM.

import { build } from "esbuild";
import { existsSync, readdirSync, rmSync, statSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const webcloud = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
// The portal's components and the staff console's (src/staff, lane
// w17/staff-console). Output files are flattened by name, so a test file
// name must be unique across both trees.
const srcs = [path.join(webcloud, "src", "components"), path.join(webcloud, "src", "staff")];
const out = path.join(webcloud, "node_modules", ".cache", "component-tests");

// Every component test under src/components, at any depth.
const walk = (d) =>
  readdirSync(d, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith(".test.tsx") ? [path.join(d, e.name)] : [],
  );
const entries = srcs.flatMap(walk);
if (entries.length === 0) {
  console.log("no component tests");
  process.exit(0);
}

// vite's resolution order.
const exts = [".mjs", ".js", ".mts", ".ts", ".jsx", ".tsx", ".json"];

// exactCase resolves relative imports with exact-case file checks (see the
// web2 twin for why esbuild's case-folding resolver needs it).
const exactCase = {
  name: "exact-case",
  setup(b) {
    b.onResolve({ filter: /^\.\.?\// }, (args) => {
      const base = path.resolve(args.resolveDir, args.path);
      const isFile = (p) => existsSync(p) && statSync(p).isFile();
      if (isFile(base)) return { path: base };
      for (const e of exts) if (isFile(base + e)) return { path: base + e };
      for (const e of exts) if (isFile(path.join(base, "index" + e))) return { path: path.join(base, "index" + e) };
      return undefined;
    });
  },
};

rmSync(out, { recursive: true, force: true });
await build({
  entryPoints: entries,
  outdir: out,
  entryNames: "[name]",
  outExtension: { ".js": ".mjs" },
  bundle: true,
  splitting: true,
  format: "esm",
  platform: "node",
  target: "node22",
  jsx: "automatic",
  packages: "external",
  alias: { "@shared": path.join(webcloud, "..", "shared") },
  resolveExtensions: exts,
  plugins: [exactCase],
  loader: { ".css": "empty", ".svg": "empty", ".png": "empty", ".woff2": "empty" },
  define: { "import.meta.env.DEV": "false" },
  logLevel: "warning",
});

const files = readdirSync(out)
  .filter((f) => f.endsWith(".test.mjs"))
  .map((f) => path.join(out, f));
const res = spawnSync(process.execPath, ["--test", ...files], { stdio: "inherit" });
process.exit(res.status ?? 1);
