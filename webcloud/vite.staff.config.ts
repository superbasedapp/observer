import { mergeConfig, type UserConfig } from "vite";
import tailwindcss from "tailwindcss";
import autoprefixer from "autoprefixer";
import base from "./vite.config";

// The staff console's build (managed-SaaS M6.8; lane w17/staff-console). A
// separate build of its own entry (staff.html -> src/staff/main.tsx) into its
// own embed dir, dist-staff/ (webcloud/embed.go: `//go:embed all:dist-staff`,
// committed, diffed by scripts/verify-webcloud-dist.sh like dist/). It is
// served ONLY by the staff process (webcloud.StaffHandler behind
// api.Options.StaffSPA) under /staff/ on the staff host, so its asset URLs
// carry /staff/ and its bundle holds none of the portal's pages. Everything
// else (the @shared alias, dedupe, map handling) is the portal config's.
export default mergeConfig(base as UserConfig, {
  base: "/staff/",
  // Its own Tailwind content (tailwind.staff.config.ts), so the two builds'
  // stylesheets never pull in each other's classes.
  css: { postcss: { plugins: [tailwindcss({ config: "./tailwind.staff.config.ts" }), autoprefixer()] } },
  // The portal's public/ (favicons) is copied as-is; the staff page names
  // /staff/favicon.svg, which that copy provides.
  build: {
    outDir: "dist-staff",
    emptyOutDir: true,
    rollupOptions: { input: "staff.html" },
  },
  server: { port: 5175 },
});
