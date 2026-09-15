import type { Config } from "tailwindcss";
import preset from "../shared/styles/tailwind-preset";

// The theme (token -> utility mapping) lives in the shared design-system
// preset so web/, web2/ and webcloud/ never drift. Token VALUES are the CSS
// custom properties in shared/styles/tokens.css, imported by src/index.css.
// `content` MUST include ../shared so Tailwind does not purge the utility
// classes emitted by the shared components.
export default {
  presets: [preset],
  content: [
    "./index.html",
    "./src/**/*.{ts,tsx}",
    "../shared/**/*.{ts,tsx}",
  ],
  plugins: [],
} satisfies Config;
