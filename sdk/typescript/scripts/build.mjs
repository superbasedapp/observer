// Dual build: ESM to dist/esm, CommonJS to dist/cjs (with a package.json that
// marks the directory CommonJS, since the package itself is "type": "module").
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
// The compiler and the Node types: this package's own node_modules (a
// development checkout), else the build tools scripts/prepare.mjs fetched
// for an app installing this folder (npm skips a linked folder's
// devDependencies). Never one found further up the tree or on NODE_PATH:
// its version and its types are not the ones the lockfile pins.
const tools = join(root, "node_modules", ".superbased-build");
const own = existsSync(join(root, "node_modules", "typescript", "package.json"));
const tsc = createRequire(join(own ? root : tools, "package.json")).resolve("typescript/bin/tsc");
const typeRoots = existsSync(join(root, "node_modules", "@types", "node")) ? [] : ["--typeRoots", join(tools, "node_modules", "@types")];
rmSync(join(root, "dist"), { recursive: true, force: true });
for (const cfg of ["tsconfig.json", "tsconfig.cjs.json"]) {
  execFileSync(process.execPath, [tsc, "-p", join(root, cfg), ...typeRoots], { stdio: "inherit", cwd: root });
}
mkdirSync(join(root, "dist", "cjs"), { recursive: true });
writeFileSync(join(root, "dist", "cjs", "package.json"), JSON.stringify({ type: "commonjs" }) + "\n");

// req.js: a require that resolves from the package, per format (src/req.ts is the stand-in).
writeFileSync(
  join(root, "dist", "esm", "req.js"),
  'import { createRequire } from "node:module";\nexport const req = createRequire(import.meta.url);\n',
);
writeFileSync(
  join(root, "dist", "cjs", "req.js"),
  '"use strict";\nObject.defineProperty(exports, "__esModule", { value: true });\nexports.req = require;\n',
);
