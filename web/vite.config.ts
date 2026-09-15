import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import type { ClientRequest, IncomingMessage } from "node:http";

const devApiTarget = process.env.VITE_API_PROXY || "http://localhost:8820";

// Origins the dev server itself serves on. Requests carrying any OTHER
// Origin (a hostile cross-site request routed through :5174) are proxied
// with their original Origin intact so the daemon's CSRF check rejects them.
const devOwnOrigins = new Set([
  "http://localhost:5174",
  "http://127.0.0.1:5174",
]);

function rewriteDevOrigin(proxyReq: ClientRequest, req: IncomingMessage) {
  const origin = req.headers.origin;
  if (origin && devOwnOrigins.has(origin)) {
    proxyReq.setHeader("origin", devApiTarget);
  }
}

export default defineConfig({
  // Phase 8 cutover: dashboard now mounts at root. Phase 1–7 ran
  // the app under /v2/ as a coexistence path while the legacy
  // static SPA stayed at /. Both are now served from /.
  base: "/",
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
      "@shared": path.resolve(__dirname, "../shared"),
    },
    // shared/ imports these; dedupe pins ONE instance so a hooks-bearing
    // shared component never gets a second React (the "invalid hook call"
    // trap) when its dep resolves from the root workspace node_modules.
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
    port: 5174,
    // shared/ lives outside the Vite root; allow the dev server to read it.
    fs: { allow: [".", "../shared"] },
    proxy: {
      // Dev API target. Defaults to the standard daemon on :8820;
      // override (e.g. for the mobile-view demo instance on :8092)
      // with VITE_API_PROXY. Runtime output is unaffected — this is
      // dev-server-only.
      //
      // The Origin rewrite exists because the daemon's terminal-launch
      // surface is same-origin enforced end to end (browserGuard CSRF on
      // the POST, coder/websocket Accept on the upgrade): a browser at
      // :5174 sends Origin http://localhost:5174, which the daemon at
      // the proxy target would reject. We rewrite Origin to the target —
      // but ONLY when the incoming Origin is the dev server's own, so a
      // hostile page's cross-origin request proxied through :5174 keeps
      // its hostile Origin and the daemon's CSRF check still rejects it
      // (codex review 2026-07-23, finding 2). Dev-only; the shipped
      // bundle is same-origin and never sees this path.
      "/api": {
        target: devApiTarget,
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on("proxyReq", rewriteDevOrigin);
        },
      },
      // Terminal websocket (/ws/launch/<token>, opened by LaunchTerminal).
      // ws:true upgrades the proxied connection so the embedded xterm — and
      // live STT/dictation iteration through it — works against the daemon
      // from the Vite dev server. Same VITE_API_PROXY override; dev-only.
      "/ws": {
        target: devApiTarget,
        ws: true,
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on("proxyReq", rewriteDevOrigin);
          proxy.on("proxyReqWs", rewriteDevOrigin);
        },
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
    rollupOptions: {
      output: {
        // Peel large vendor libs out of the entry bundle so the
        // 500 KB warning goes away and the browser can cache them
        // independently of app code. Recharts is the heaviest at
        // ~150 KB; TanStack Table ~50 KB; React Router ~30 KB.
        // d3-* deps that Recharts pulls in (d3-shape, d3-scale,
        // victory-vendor) land in the recharts chunk via prefix.
        manualChunks(id) {
          if (id.includes("node_modules/recharts/")) return "vendor-recharts";
          if (id.includes("node_modules/d3-")) return "vendor-recharts";
          if (id.includes("node_modules/victory-vendor/")) return "vendor-recharts";
          if (id.includes("node_modules/@tanstack/react-table"))
            return "vendor-table";
          if (id.includes("node_modules/react-router"))
            return "vendor-router";
          if (id.includes("node_modules/framer-motion"))
            return "vendor-framer";
          if (id.includes("node_modules/motion-")) return "vendor-framer";
          // @floating-ui/* powers the Tooltip primitive — positioning,
          // flip/shift/offset, arrow placement. Pinning to its own
          // chunk keeps Rollup from sweeping it into vendor-recharts
          // (which would force eager preload of ~110 KB just to
          // render a hover bubble). Same gotcha as clsx — see the
          // [[feedback_vite_manualchunks_clsx]] memory entry.
          if (id.includes("node_modules/@floating-ui/"))
            return "vendor-floating-ui";
          // @xterm/* powers the embedded web terminal (Continue-in… →
          // "Launch here"). It is dynamic-imported from LaunchTerminal so
          // this chunk stays lazy — nobody who never opens a terminal pays
          // for it. Pinning keeps Rollup from folding it into an eager
          // vendor bundle (same lesson as clsx/@floating-ui).
          if (id.includes("node_modules/@xterm/")) return "vendor-xterm";
          // react-grid-layout + react-resizable power the Terminal
          // Workspace dock grid. Lazy-imported from the workspace route;
          // pinning keeps Rollup from folding them into an eager vendor
          // bundle (same lesson as clsx/@floating-ui/@xterm).
          if (
            id.includes("node_modules/react-grid-layout/") ||
            id.includes("node_modules/react-resizable/") ||
            id.includes("node_modules/react-draggable/")
          )
            return "vendor-grid";
          if (
            id.includes("node_modules/react/") ||
            id.includes("node_modules/react-dom/") ||
            id.includes("node_modules/scheduler/") ||
            // clsx is tiny but used everywhere; pinning it to the
            // react chunk keeps Rollup from sweeping it into
            // vendor-recharts (which would force eager preload).
            id.includes("node_modules/clsx/")
          )
            return "vendor-react";
          return undefined;
        },
      },
    },
  },
});
