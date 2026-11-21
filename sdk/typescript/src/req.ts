/**
 * Loading optional peer dependencies from both builds.
 *
 * This source is only the type-checked stand-in: `scripts/build.mjs` writes
 * the real `dist/esm/req.js` (`createRequire(import.meta.url)`) and
 * `dist/cjs/req.js` (the module's own `require`), because `import.meta`
 * cannot be compiled to CommonJS.
 */

import { createRequire } from "node:module";

declare const __filename: string | undefined;

/** A `require` that resolves from this package's location. */
export const req: NodeJS.Require = createRequire(typeof __filename === "string" ? __filename : `${process.cwd()}/`);
