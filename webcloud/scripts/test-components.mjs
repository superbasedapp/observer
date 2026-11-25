// test-components.mjs runs the portal's component tests (every *.test.tsx
// under src/components and src/staff, the staff console's tree, at any
// depth) through the one runner the three apps share,
// shared/scripts/test-components.mjs, which says how. esbuild is imported
// here because it resolves from this app's node_modules. The alias is
// vite.config.ts's (@shared).

import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runComponentTests } from "../../shared/scripts/test-components.mjs";

const webcloud = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

await runComponentTests({
  build,
  appDir: webcloud,
  testRoots: [path.join(webcloud, "src", "components"), path.join(webcloud, "src", "staff")],
  alias: { "@shared": path.join(webcloud, "..", "shared") },
});
