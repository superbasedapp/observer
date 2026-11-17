import type { Config } from "tailwindcss";
import preset from "../shared/styles/tailwind-preset";

// The staff console's Tailwind config (vite.staff.config.ts): the same
// shared preset as the portal (docs/app-design-system.md), scanning only what
// the staff build renders: its own pages, the two portal components it reuses
// (the brand lockup and the theme toggle) and the shared design system.
export default {
  presets: [preset],
  content: [
    "./staff.html",
    "./src/staff/**/*.{ts,tsx}",
    "./src/components/BrandMark.tsx",
    "./src/components/ThemeToggle.tsx",
    "../shared/**/*.{ts,tsx}",
  ],
  plugins: [],
} satisfies Config;
