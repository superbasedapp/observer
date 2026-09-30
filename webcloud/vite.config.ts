import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import fs from "node:fs";
import path from "node:path";

// keepSourcemapsOutOfEmbed: webcloud/dist IS the go:embed dir (webcloud/
// embed.go `//go:embed all:dist`, committed, served under /portal/ and
// diffed by scripts/verify-webcloud-dist.sh), unlike web/ and web2/ whose
// maps scripts/sync-web-embed.sh drops on the way into their embed dirs. So
// the hidden maps are written to Vite's cache dir (node_modules/.vite, never
// committed) instead of dist: dist stays byte-identical to a map-less build,
// nothing embeds or serves a map, and the maps still exist for local
// debugging.
function keepSourcemapsOutOfEmbed(): Plugin {
  let mapsDir = "";
  return {
    name: "keep-sourcemaps-out-of-embed",
    apply: "build",
    configResolved(config) {
      mapsDir = path.join(config.cacheDir, "sourcemaps");
    },
    generateBundle(_options, bundle) {
      for (const [fileName, out] of Object.entries(bundle)) {
        if (out.type !== "asset" || !fileName.endsWith(".map")) continue;
        const dest = path.join(mapsDir, fileName);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, out.source);
        delete bundle[fileName];
      }
    },
  };
}

// The app.superbased.app cloud portal SPA is served under the /portal/ path
// prefix by cmd/observer-cloud, so all asset URLs must be prefixed with it.
export default defineConfig({
  base: "/portal/",
  plugins: [react(), keepSourcemapsOutOfEmbed()],
  resolve: {
    alias: {
      // The shared design system (components/charts/tokens) lives outside this
      // app's root; @shared resolves to it. See docs/app-design-system.md.
      "@shared": path.resolve(__dirname, "../shared"),
    },
    // dedupe pins ONE instance of each shared dep so a hooks-bearing shared
    // component never gets a second React ("invalid hook call").
    dedupe: [
      "react",
      "react-dom",
      "react-router-dom",
      "recharts",
      "clsx",
      "@floating-ui/react",
      "framer-motion",
      "lucide-react",
    ],
  },
  server: {
    // shared/ is outside the Vite root; allow the dev server to read it.
    fs: { allow: [".", "../shared"] },
  },
  build: {
    outDir: "dist",
    // "hidden": maps are generated but the bundles carry no
    // `//# sourceMappingURL` comment (and see keepSourcemapsOutOfEmbed).
    sourcemap: "hidden",
  },
});
