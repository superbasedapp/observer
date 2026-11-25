// test-components.mjs runs the node dashboard's component tests (every
// *.test.tsx under src/components and src/pages/security, at any depth)
// through the one runner the three apps share,
// shared/scripts/test-components.mjs, which says how. esbuild is imported
// here because it resolves from this app's node_modules. The aliases are
// vite.config.ts's (@ and @shared).

import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runComponentTests } from "../../shared/scripts/test-components.mjs";

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

await runComponentTests({
  build,
  appDir: web,
  testRoots: [path.join(web, "src", "components"), path.join(web, "src", "pages", "security")],
  alias: { "@": path.join(web, "src"), "@shared": path.join(web, "..", "shared") },
});
