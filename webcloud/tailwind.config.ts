import type { Config } from "tailwindcss";
import preset from "../shared/styles/tailwind-preset";

// Cloud portal Tailwind config. The design-system theme (numbered token scale
// + tool colors + radii/shadows/fonts) comes from the SHARED preset so the
// portal renders the same components as the local dashboard with no drift.
// `content` MUST include ../shared or Tailwind purges the utility classes the
// shared components emit. See docs/app-design-system.md.
export default {
  presets: [preset],
  // src/staff is the staff console's own build (tailwind.staff.config.ts):
  // its classes must not enter the portal's stylesheet, or every portal
  // chunk's hash changes with each staff screen.
  content: [
    "./index.html",
    "./src/**/*.{ts,tsx}",
    "!./src/staff/**",
    "../shared/**/*.{ts,tsx}",
  ],
  plugins: [],
} satisfies Config;
