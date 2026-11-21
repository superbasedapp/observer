// The documented install from a checkout works on a fresh copy: an app runs
// `npm install /path/to/sdk/typescript` with no build in the SDK folder and
// nothing installed next to it, then imports the package (ESM and CommonJS)
// and instruments a framework the app installed. npm skips a linked folder's
// devDependencies, so scripts/prepare.mjs must fetch the build tools itself,
// and instrument() must find a peer from the app as well as from the SDK's
// own folder (live finding L-15).
//
// Opt-in (it downloads packages): SUPERBASED_INSTALL_TEST=1 npm run test:install
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const sdk = join(dirname(fileURLToPath(import.meta.url)), "..");
const skip = process.env.SUPERBASED_INSTALL_TEST !== "1" && "set SUPERBASED_INSTALL_TEST=1 (downloads packages)";

test("npm install <checkout>/sdk/typescript works on a fresh copy", { skip, timeout: 600_000 }, () => {
  const tmp = mkdtempSync(join(tmpdir(), "sbo-sdk-install-"));
  try {
    // A fresh checkout: the files git would hold (no node_modules, no dist).
    const copy = join(tmp, "sdk", "typescript");
    const tracked = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { cwd: sdk, encoding: "utf8" }).split("\0").filter(Boolean);
    for (const f of tracked) cpSync(join(sdk, f), join(copy, f));
    assert.ok(!existsSync(join(copy, "dist")) && !existsSync(join(copy, "node_modules")));

    const app = join(tmp, "app");
    cpSync(join(sdk, "LICENSE"), join(app, "LICENSE")); // mkdir -p
    writeFileSync(join(app, "package.json"), JSON.stringify({ name: "app", version: "1.0.0", private: true, type: "module" }));
    // No compiler or types from outside the app (a global NODE_PATH would hide the defect).
    const env = { ...process.env };
    delete env.NODE_PATH;
    for (const k of Object.keys(env)) if (k.startsWith("npm_")) delete env[k];
    execFileSync("npm", ["install", "--no-audit", "--no-fund", copy], { cwd: app, env, stdio: "inherit" });
    // A framework and its instrumentation, installed in the app (not next to the linked SDK).
    const lock = JSON.parse(readFileSync(join(sdk, "package-lock.json"), "utf8")).packages;
    const pin = (p) => `${p}@${lock[`node_modules/${p}`].version}`;
    execFileSync("npm", ["install", "--no-audit", "--no-fund", pin("openai"), pin("@arizeai/openinference-instrumentation-openai")], { cwd: app, env, stdio: "inherit" });

    writeFileSync(
      join(app, "check.mjs"),
      [
        'import { createRequire } from "node:module";',
        'import * as esm from "@superbased/sdk";',
        'const cjs = createRequire(import.meta.url)("@superbased/sdk");',
        'if (typeof esm.init !== "function" || typeof cjs.init !== "function") throw new Error("no init export");',
        'esm.init({ serviceName: "install-check", destination: "local", discover: false });',
        'const st = esm.instrument(["openai"], { modules: { openai: await import("openai") } });',
        'if (st.openai !== "instrumented") throw new Error("instrument: " + JSON.stringify(st));',
        'await esm.shutdown(500);',
        'console.log("ok");',
      ].join("\n"),
    );
    const out = execFileSync(process.execPath, ["check.mjs"], { cwd: app, env, encoding: "utf8" });
    assert.match(out, /^ok$/m);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
