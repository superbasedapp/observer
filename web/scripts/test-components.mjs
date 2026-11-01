// test-components.mjs runs the component tests (src/components/*.test.tsx
// and src/components/security/*.test.tsx)
// under node's own test runner (lane sbx-p2b: the dialog's web tests). Node
// strips TypeScript types but does not transform JSX, so each test file is
// bundled first with esbuild (the copy vite itself depends on) into
// node_modules/.cache, where node resolves react and the other packages from
// the workspace's node_modules: one React instance, the same one the app
// uses. The aliases are vite.config.ts's (@ and @shared); stylesheets load
// as empty modules. Component tests render with react-dom/server, so they
// need no DOM.

import { build } from "esbuild";
import { existsSync, readdirSync, rmSync, statSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = path.join(web, "src", "components");
const out = path.join(web, "node_modules", ".cache", "component-tests");

// The component directories holding tests (one level, no recursion).
const testDirs = [src, path.join(src, "security")];
const entries = testDirs.flatMap((d) =>
  readdirSync(d)
    .filter((f) => f.endsWith(".test.tsx"))
    .map((f) => path.join(d, f)),
);
if (entries.length === 0) {
  console.log("no component tests");
  process.exit(0);
}

// vite's resolution order.
const exts = [".mjs", ".js", ".mts", ".ts", ".jsx", ".tsx", ".json"];

// exactCase resolves relative imports with exact-case file checks.
// esbuild's resolver folds case in its directory cache, so a directory
// holding both GaugeStat.tsx and gaugeStat.ts (shared/components/
// sessiondetail) resolves "./gaugeStat" to the wrong file; vite does not.
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
  // Flat output: every test lands in out/ whatever its directory.
  entryNames: "[name]",
  outExtension: { ".js": ".mjs" },
  bundle: true,
  splitting: true,
  format: "esm",
  platform: "node",
  target: "node22",
  jsx: "automatic",
  packages: "external",
  alias: { "@": path.join(web, "src"), "@shared": path.join(web, "..", "shared") },
  resolveExtensions: exts,
  plugins: [exactCase],
  loader: { ".css": "empty", ".svg": "empty", ".png": "empty", ".woff2": "empty" },
  logLevel: "warning",
});

const files = readdirSync(out)
  .filter((f) => f.endsWith(".test.mjs"))
  .map((f) => path.join(out, f));
const res = spawnSync(process.execPath, ["--test", ...files], { stdio: "inherit" });
process.exit(res.status ?? 1);
