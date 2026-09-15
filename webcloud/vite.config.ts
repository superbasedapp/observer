import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// The app.superbased.app cloud portal SPA is served under the /portal/ path
// prefix by cmd/observer-cloud, so all asset URLs must be prefixed with it.
export default defineConfig({
  base: "/portal/",
  plugins: [react()],
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
    ],
  },
  server: {
    // shared/ is outside the Vite root; allow the dev server to read it.
    fs: { allow: [".", "../shared"] },
  },
  build: {
    outDir: "dist",
  },
});
