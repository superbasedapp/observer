// test-components.mjs: the ONE component-test runner of the three apps
// (web, web2, webcloud). Each app's scripts/test-components.mjs calls
// runComponentTests with its own test roots and aliases; `npm test` in the
// app runs it.
//
// It runs every *.test.tsx under the app's test roots (at any depth) under
// node's own test runner. Node strips TypeScript types but does not
// transform JSX, so each test file is bundled first with esbuild (the copy
// vite itself depends on, passed in by the app because it resolves from the
// app's node_modules) into the app's node_modules/.cache, where node resolves
// react and the other packages from the workspace's node_modules: one React
// instance, the same one the app uses. The aliases are the app's
// vite.config.ts ones; stylesheets and binary assets load as empty modules,
// .toml as text. `import.meta.env.DEV` is false, as in a production build.
// Component tests render with react-dom/server, so they need no DOM.

import { existsSync, readdirSync, rmSync, statSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

// vite's resolution order.
const exts = [".mjs", ".js", ".mts", ".ts", ".jsx", ".tsx", ".json"];

// exactCase resolves relative imports with exact-case file checks.
// esbuild's resolver folds case in its directory cache, so a directory
// holding two modules that differ only by case (shared/components/
// sessiondetail once held GaugeStat.tsx and gaugeStat.ts) resolves to the
// wrong file. On a case-insensitive file system Vite does too, so such
// pairs are now refused by tests/invariant/web_case_collision_test.go.
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

// walk lists every component test under a directory, at any depth.
const walk = (d) =>
  readdirSync(d, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith(".test.tsx") ? [path.join(d, e.name)] : [],
  );

/**
 * runComponentTests bundles and runs an app's component tests, then exits
 * the process with the test run's status.
 *
 * @param {object} opts
 * @param {Function} opts.build esbuild's build, imported by the app's script.
 * @param {string} opts.appDir the app's root directory.
 * @param {string[]} opts.testRoots directories walked for *.test.tsx. The
 *   output is flat, so a test file name must be unique across them.
 * @param {Record<string, string>} opts.alias the app's import aliases
 *   (vite.config.ts resolve.alias).
 */
export async function runComponentTests({ build, appDir, testRoots, alias }) {
  const out = path.join(appDir, "node_modules", ".cache", "component-tests");
  const entries = testRoots.flatMap(walk);
  if (entries.length === 0) {
    console.log("no component tests");
    process.exit(0);
  }

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
    alias,
    resolveExtensions: exts,
    plugins: [exactCase],
    loader: { ".css": "empty", ".svg": "empty", ".png": "empty", ".woff2": "empty", ".toml": "text" },
    define: { "import.meta.env.DEV": "false" },
    logLevel: "warning",
  });

  const files = readdirSync(out)
    .filter((f) => f.endsWith(".test.mjs"))
    .map((f) => path.join(out, f));
  const res = spawnSync(process.execPath, ["--test", ...files], { stdio: "inherit" });
  process.exit(res.status ?? 1);
}
