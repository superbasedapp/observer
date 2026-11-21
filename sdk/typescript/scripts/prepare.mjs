// The package's `prepare` script: build dist/ wherever npm runs it.
//
// `npm install /path/to/sdk/typescript` from an app runs this in the SDK
// folder, but npm does not install a linked folder's devDependencies, so a
// fresh checkout has no TypeScript compiler and no runtime dependencies next
// to the sources. When they are missing this script fetches only what the
// build needs, at the versions package-lock.json pins:
//
// - the runtime dependencies, with `npm ci --omit=dev` (the OpenTelemetry
//   packages the sources import);
// - the compiler and the Node types, into node_modules/.superbased-build
//   (not the whole development tree: the test frameworks are hundreds of MB).
//
// Then it runs scripts/build.mjs. In a development checkout where
// `npm install` already ran here, nothing is fetched. No lifecycle script
// of a fetched package runs (--ignore-scripts), and package.json and
// package-lock.json are never written.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const BUILD_TOOLS_DIR = join(root, "node_modules", ".superbased-build");
const BUILD_TOOLS = ["typescript", "@types/node"];

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));

const has = (dir, name) => existsSync(join(dir, "node_modules", name, "package.json"));
const runtimeMissing = () => Object.keys(pkg.dependencies ?? {}).filter((d) => !has(root, d));
const toolsMissing = () => BUILD_TOOLS.filter((t) => !has(root, t) && !has(BUILD_TOOLS_DIR, t));

/** Run npm (the one running this script when known, so Windows and version managers work). */
function npm(args, cwd) {
  const cli = process.env.npm_execpath;
  const [cmd, argv] = cli && cli.endsWith(".js") ? [process.execPath, [cli, ...args]] : [process.platform === "win32" ? "npm.cmd" : "npm", args];
  execFileSync(cmd, argv, { cwd, stdio: "inherit", shell: process.platform === "win32" && !cli });
}

const quiet = ["--ignore-scripts", "--no-audit", "--no-fund", "--loglevel=error"];
if (runtimeMissing().length) {
  console.log("@superbased/sdk: installing its runtime dependencies to build it (npm ci --omit=dev)");
  npm(["ci", "--omit=dev", ...quiet], root);
}
const missing = toolsMissing();
if (missing.length) {
  const specs = missing.map((t) => `${t}@${lock.packages?.[`node_modules/${t}`]?.version ?? pkg.devDependencies[t]}`);
  console.log(`@superbased/sdk: fetching its build tools (${specs.join(", ")}) into node_modules/.superbased-build`);
  mkdirSync(BUILD_TOOLS_DIR, { recursive: true });
  const marker = join(BUILD_TOOLS_DIR, "package.json");
  if (!existsSync(marker)) writeFileSync(marker, JSON.stringify({ name: "superbased-sdk-build-tools", private: true }) + "\n");
  npm(["install", "--no-save", "--no-package-lock", ...quiet, ...specs], BUILD_TOOLS_DIR);
}
const left = [...runtimeMissing(), ...toolsMissing()];
if (left.length) {
  console.error(`@superbased/sdk: cannot build: still missing ${left.join(", ")}. Run \`npm install\` in ${root} and try again.`);
  process.exit(1);
}
execFileSync(process.execPath, [join(root, "scripts", "build.mjs")], { cwd: root, stdio: "inherit" });
