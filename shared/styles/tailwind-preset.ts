import type { Config } from "tailwindcss";

// tokenColor maps a CSS custom property onto a Tailwind color that honours
// the opacity modifier. A bare `var(--x)` color silently DROPS every
// `bg-accent/15`, `border-warn/40`, `bg-bg-3/60` ... class (Tailwind cannot
// split a var() into channels), which left ~880 such classes across web/,
// web2/ and webcloud/ compiling to nothing (2026-09-27 UI review). color-mix
// with <alpha-value> keeps the token as the single source of truth and makes
// every modifier work; with no modifier it resolves to the token itself.
export function tokenColor(cssVar: string): string {
  return `color-mix(in srgb, var(${cssVar}) calc(<alpha-value> * 100%), transparent)`;
}

// Shared design-system Tailwind theme. The single source of truth for how
// utility classes map to the design tokens (CSS custom properties defined in
// ./tokens.css). Every application surface (web/, web2/, webcloud/) imports
// this as a Tailwind `preset` so the token->class mapping never drifts.
// Dark/light theme switching flips the CSS variables; no `dark:` variants are
// needed. Var VALUES live in ./tokens.css, imported by each app's entry CSS.
const preset: Partial<Config> = {
  theme: {
    extend: {
      colors: {
        bg: {
          0: tokenColor("--bg-0"),
          1: tokenColor("--bg-1"),
          2: tokenColor("--bg-2"),
          3: tokenColor("--bg-3"),
          4: tokenColor("--bg-4"),
          5: tokenColor("--bg-5"),
        },
        line: {
          1: tokenColor("--line-1"),
          2: tokenColor("--line-2"),
          3: tokenColor("--line-3"),
        },
        fg: {
          0: tokenColor("--fg-0"),
          1: tokenColor("--fg-1"),
          2: tokenColor("--fg-2"),
          3: tokenColor("--fg-3"),
          4: tokenColor("--fg-4"),
        },
        accent: {
          DEFAULT: tokenColor("--accent"),
          strong: tokenColor("--accent-strong"),
          soft: tokenColor("--accent-soft"),
          ring: tokenColor("--accent-ring"),
          on: tokenColor("--on-accent"),
        },
        success: { DEFAULT: tokenColor("--success"), soft: tokenColor("--success-soft") },
        // `ok` was used by the terminal status pills (text-ok / bg-ok/20) but
        // never defined, so they rendered unstyled. Alias of success.
        ok: tokenColor("--success"),
        warn: { DEFAULT: tokenColor("--warn"), soft: tokenColor("--warn-soft") },
        danger: { DEFAULT: tokenColor("--danger"), soft: tokenColor("--danger-soft"), on: tokenColor("--on-danger") },
        info: { DEFAULT: tokenColor("--info"), soft: tokenColor("--info-soft") },
        // The current SuperBased mark's Blueprint (bg-brand-blueprint etc.).
        brand: {
          blueprint: tokenColor("--brand-blueprint"),
          "blueprint-ink": tokenColor("--brand-blueprint-ink"),
          "blueprint-soft": tokenColor("--brand-blueprint-soft"),
        },
        tok: {
          net: tokenColor("--tok-net"),
          read: tokenColor("--tok-read"),
          write: tokenColor("--tok-write"),
          out: tokenColor("--tok-out"),
        },
        tool: {
          "claude-code": tokenColor("--tool-claude-code"),
          codex: tokenColor("--tool-codex"),
          cursor: tokenColor("--tool-cursor"),
          cline: tokenColor("--tool-cline"),
          copilot: tokenColor("--tool-copilot"),
          cowork: tokenColor("--tool-cowork"),
          antigravity: tokenColor("--tool-antigravity"),
          opencode: tokenColor("--tool-opencode"),
          openclaw: tokenColor("--tool-openclaw"),
          pi: tokenColor("--tool-pi"),
          gemini: tokenColor("--tool-gemini"),
          other: tokenColor("--tool-other"),
        },
        // Loading placeholder base, hover/press overlays and terminal
        // surfaces - theme-aware (and terminal-scope-aware) via tokens.css.
        skel: tokenColor("--skel-base"),
        overlay: {
          1: tokenColor("--overlay-1"),
          2: tokenColor("--overlay-2"),
        },
        term: {
          bg: tokenColor("--term-bg"),
          chrome: tokenColor("--term-chrome"),
          banner: tokenColor("--term-banner"),
          pop: tokenColor("--term-pop"),
        },
      },
      // A bare `border` (no color class) used Tailwind's default #e5e7eb - a
      // light-gray line even in the dark theme. Default it to the token.
      // (Plain var, not tokenColor: preflight reads this value verbatim.)
      borderColor: {
        DEFAULT: "var(--line-2)",
      },
      gridTemplateColumns: {
        // 24-col grid — for the HourHeatmap.
        24: "repeat(24, minmax(0, 1fr))",
      },
      // Named type scale over the --fs-* tokens (additive: Tailwind's own
      // text-xs / text-sm / ... keep their meaning).
      fontSize: {
        micro: ["var(--fs-micro)", { lineHeight: "1.4" }],
        caption: ["var(--fs-caption)", { lineHeight: "1.45" }],
        small: ["var(--fs-small)", { lineHeight: "1.5" }],
        body: ["var(--fs-body)", { lineHeight: "1.5" }],
        lead: ["var(--fs-lead)", { lineHeight: "1.45" }],
        title: ["var(--fs-title)", { lineHeight: "1.25" }],
        h1: ["var(--fs-h1)", { lineHeight: "1.2" }],
        "display-sm": ["var(--fs-display-sm)", { lineHeight: "1.1" }],
        display: ["var(--fs-display)", { lineHeight: "1.05" }],
      },
      // Density spacing over the --density-* tokens (tokens.css "Density";
      // comfortable = the pre-density values, compact = the data-density
      // override). Additive keys, so every numeric spacing class keeps its
      // meaning: py-row / py-head (table rows / headers), px-cell /
      // px-cell-num (table cells, numeric cells), p-card (Card), px-stat-x /
      // py-stat-y (StatCard).
      spacing: {
        row: "var(--density-row-y)",
        head: "var(--density-head-y)",
        cell: "var(--density-cell-x)",
        "cell-num": "var(--density-cell-x-num)",
        card: "var(--density-card-pad)",
        "stat-x": "var(--density-stat-x)",
        "stat-y": "var(--density-stat-y)",
      },
      minHeight: {
        stat: "var(--density-stat-min-h)",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ['"JetBrains Mono"', '"SF Mono"', "Menlo", "Consolas", "monospace"],
      },
      borderRadius: {
        1: "var(--r-1)",
        2: "var(--r-2)",
        3: "var(--r-3)",
        4: "var(--r-4)",
        pill: "var(--r-pill)",
      },
      boxShadow: {
        1: "var(--shadow-1)",
        2: "var(--shadow-2)",
        3: "var(--shadow-3)",
        drawer: "var(--shadow-drawer)",
      },
      // Motion vocabulary (tokens.css "Motion"; keyframes in motion.css).
      // Durations read the tokens, so prefers-reduced-motion collapses them.
      transitionTimingFunction: {
        smooth: "var(--ease)",
        out: "var(--ease-out)",
        "in-out": "var(--ease-in-out)",
        spring: "var(--ease-spring)",
      },
      transitionDuration: {
        instant: "var(--dur-instant)",
        fast: "var(--dur-fast)",
        base: "var(--dur)",
        slow: "var(--dur-slow)",
        slower: "var(--dur-slower)",
      },
      animation: {
        "fade-in": "sb-fade-in var(--dur) var(--ease-out) backwards",
        "fade-up": "sb-fade-up var(--dur-slow) var(--ease-out) backwards",
        "scale-in": "sb-scale-in var(--dur) var(--ease-out) backwards",
        "slide-in-right": "sb-slide-in-right var(--dur-slow) var(--ease-out) backwards",
      },
    },
  },
};

export default preset;
