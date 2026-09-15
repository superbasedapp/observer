// Inline icon library — kept hand-rolled instead of pulling lucide so
// the critical-path bundle stays small and themes via currentColor.
//
// Two groups:
//   * Nav icons (eye / list / lightning / dollar / chart / wrench /
//     droplet / magnifier / sparkles / gear) — one per top-level tab.
//   * Provider glyphs (anthropic / openai / google / github / agnostic)
//     — abstract marks rendered inside ToolBadge to signal lineage.

import type { ReactElement } from "react";

type IconProps = { size?: number; className?: string };

function svg(d: string, size: number, className?: string): ReactElement {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <path
        d={d}
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// ----- nav icons -----------------------------------------------------

export function EyeIcon({ size = 14, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <path
        d="M1.5 8s2.4-4.5 6.5-4.5S14.5 8 14.5 8s-2.4 4.5-6.5 4.5S1.5 8 1.5 8Z"
        stroke="currentColor"
        strokeWidth="1.4"
      />
      <circle cx="8" cy="8" r="2" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  );
}

export function ListIcon({ size = 14, className }: IconProps) {
  return svg(
    "M3 4h10M3 8h10M3 12h10M1.5 4v0M1.5 8v0M1.5 12v0",
    size,
    className,
  );
}

export function LightningIcon({ size = 14, className }: IconProps) {
  return svg("M9 1.5 3.5 9h4L7 14.5 12.5 7h-4L9 1.5Z", size, className);
}

export function DollarIcon({ size = 14, className }: IconProps) {
  return svg(
    "M8 1.5v13M11.5 4.5H6.5a2 2 0 0 0 0 4h3a2 2 0 0 1 0 4H4",
    size,
    className,
  );
}

export function BarChartIcon({ size = 14, className }: IconProps) {
  return svg(
    "M3 13V8M7 13V4M11 13v-7M14.5 13.5H1.5",
    size,
    className,
  );
}

export function WrenchIcon({ size = 14, className }: IconProps) {
  return svg(
    "M10.5 1.5a3.5 3.5 0 0 0-3.4 4.4L1.5 11.5l3 3 5.6-5.6a3.5 3.5 0 1 0 .4-7.4Z",
    size,
    className,
  );
}

export function DropletIcon({ size = 14, className }: IconProps) {
  return svg(
    "M8 1.5C6 4 3.5 6.5 3.5 9.5a4.5 4.5 0 0 0 9 0C12.5 6.5 10 4 8 1.5Z",
    size,
    className,
  );
}

export function SearchIcon({ size = 14, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <circle cx="7" cy="7" r="4.5" stroke="currentColor" strokeWidth="1.4" />
      <path
        d="m10.5 10.5 3 3"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function SparklesIcon({ size = 14, className }: IconProps) {
  return svg(
    "M5 2v3M3.5 3.5h3M11 7v3M9.5 8.5h3M8 11v3M6.5 12.5h3M3 11v2M2 12h2",
    size,
    className,
  );
}

export function GearIcon({ size = 14, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <circle cx="8" cy="8" r="2" stroke="currentColor" strokeWidth="1.4" />
      <path
        d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function ShieldIcon({ size = 14, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <path
        d="M8 1.5l5 2v4c0 3.2-2.1 5.6-5 7-2.9-1.4-5-3.8-5-7v-4l5-2Z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M5.8 8l1.6 1.6L10.4 6.4"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// ----- additional KPI tile icons ------------------------------------

export function LayersIcon({ size = 14, className }: IconProps) {
  return svg(
    "M8 1.5l6 3-6 3-6-3 6-3ZM2 7.5l6 3 6-3M2 10.5l6 3 6-3",
    size,
    className,
  );
}

export function BoltIcon({ size = 14, className }: IconProps) {
  return svg("M9 1.5L3 9h4l-1 5.5L13 7h-4l1-5.5Z", size, className);
}

export function DatabaseIcon({ size = 14, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <ellipse cx="8" cy="3.5" rx="5.5" ry="2" stroke="currentColor" strokeWidth="1.4" />
      <path
        d="M2.5 3.5v9c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2v-9M2.5 8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2"
        stroke="currentColor"
        strokeWidth="1.4"
      />
    </svg>
  );
}

export function AlertIcon({ size = 14, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <path
        d="M8 1.5l7 12.5H1L8 1.5Z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path d="M8 6.5v3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      <circle cx="8" cy="11.5" r="0.8" fill="currentColor" />
    </svg>
  );
}

export function ClockIcon({ size = 14, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.4" />
      <path
        d="M8 4.5V8l2.5 1.5"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function CalendarIcon({ size = 14, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <rect
        x="2"
        y="3.5"
        width="12"
        height="10"
        rx="1.5"
        stroke="currentColor"
        strokeWidth="1.4"
      />
      <path d="M2 6.5h12M5 1.5v3M11 1.5v3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}

export function CompassIcon({ size = 14, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.4" />
      <path d="M10.5 5.5L9 9l-3.5 1.5L7 7l3.5-1.5Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
    </svg>
  );
}

export function PercentIcon({ size = 14, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <path d="M3 13L13 3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      <circle cx="4.5" cy="4.5" r="1.8" stroke="currentColor" strokeWidth="1.4" />
      <circle cx="11.5" cy="11.5" r="1.8" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  );
}

export function FlameIcon({ size = 14, className }: IconProps) {
  return svg(
    "M8 1.5c1 2.5 4 4 4 7.5a4 4 0 0 1-8 0c0-1.5 1-2.5 1-3.5C5 7 5 9 6 9c0-2 1-4 2-7.5Z",
    size,
    className,
  );
}

export function CoinsIcon({ size = 14, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <ellipse cx="6" cy="5" rx="4" ry="2" stroke="currentColor" strokeWidth="1.4" />
      <path d="M2 5v3c0 1.1 1.8 2 4 2s4-.9 4-2V5" stroke="currentColor" strokeWidth="1.4" />
      <ellipse cx="10" cy="10" rx="4" ry="2" stroke="currentColor" strokeWidth="1.4" />
      <path d="M6 10v3c0 1.1 1.8 2 4 2s4-.9 4-2v-3" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  );
}

export function CompressIcon({ size = 14, className }: IconProps) {
  return svg(
    "M5 5L1 1M1 5h4V1M11 5L15 1M15 5h-4V1M5 11L1 15M1 11h4v4M11 11L15 15M15 11h-4v4",
    size,
    className,
  );
}

// ----- provider glyphs ----------------------------------------------

// Anthropic — abstract spiral / asterisk approximation.
export function AnthropicGlyph({ size = 12, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <path
        d="M5.5 3 3 13h2l.7-2.8h4.6L11 13h2L10.5 3h-5Zm.5 5.5L8 4.6l2 3.9H6Z"
        fill="currentColor"
      />
    </svg>
  );
}

// OpenAI — abstract 6-petal flower.
export function OpenAIGlyph({ size = 12, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <path
        d="M8 1.5 6 3v3l-3-1.5L1.5 7.5 4 9 1.5 10.5 3 13l3-1.5v3l2 1.5 2-1.5v-3l3 1.5 1.5-2.5L12 9l2.5-1.5L13 5l-3 1.5v-3L8 1.5Z"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinejoin="round"
        fill="none"
      />
    </svg>
  );
}

// Google — abstract 4-color G stub (rendered monochrome via currentColor).
export function GoogleGlyph({ size = 12, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <path
        d="M8 1.5a6.5 6.5 0 1 0 6.4 7.5H8V6.5h6"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

// GitHub — Octocat silhouette stub.
export function GitHubGlyph({ size = 12, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      className={className}
      aria-hidden
    >
      <path d="M8 1.5a6.5 6.5 0 0 0-2.05 12.67c.33.06.45-.14.45-.32v-1.1c-1.84.4-2.22-.89-2.22-.89-.3-.77-.74-.98-.74-.98-.6-.41.05-.4.05-.4.67.05 1.02.69 1.02.69.59 1.02 1.55.73 1.93.56.06-.43.23-.73.42-.9-1.47-.16-3.01-.74-3.01-3.28 0-.72.26-1.31.69-1.78-.07-.17-.3-.85.06-1.77 0 0 .56-.18 1.84.68a6.4 6.4 0 0 1 3.34 0c1.28-.86 1.84-.68 1.84-.68.36.92.13 1.6.06 1.77.43.47.69 1.06.69 1.78 0 2.55-1.54 3.11-3.01 3.27.24.21.45.61.45 1.23v1.83c0 .18.12.39.45.32A6.5 6.5 0 0 0 8 1.5Z" />
    </svg>
  );
}

// Agnostic — abstract cube.
export function AgnosticGlyph({ size = 12, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <path
        d="M8 1.5 2 4.5v7L8 14.5 14 11.5v-7L8 1.5ZM2 4.5 8 7.5l6-3M8 7.5v7"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export type ProviderId =
  | "anthropic"
  | "openai"
  | "google"
  | "github"
  | "agnostic";

export function ProviderGlyph({
  provider,
  size = 12,
  className,
}: {
  provider: ProviderId;
  size?: number;
  className?: string;
}) {
  switch (provider) {
    case "anthropic":
      return <AnthropicGlyph size={size} className={className} />;
    case "openai":
      return <OpenAIGlyph size={size} className={className} />;
    case "google":
      return <GoogleGlyph size={size} className={className} />;
    case "github":
      return <GitHubGlyph size={size} className={className} />;
    case "agnostic":
    default:
      return <AgnosticGlyph size={size} className={className} />;
  }
}

// ToolGlyph — per-tool distinctive glyph mark. Ports the abstract
// per-tool shapes from design/provider-icons.jsx so Claude Code,
// Cowork, Cline, Pi, OpenClaw etc. don't all share the same letter-A
// silhouette. Each path is drawn inside the 24×24 design viewBox at
// stroke 1.8 — caller scales via `size` and tints via currentColor.
export function ToolGlyph({
  tool,
  size = 12,
  className,
}: {
  tool: string;
  size?: number;
  className?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      stroke="currentColor"
      fill="none"
      className={className}
      aria-hidden
    >
      {toolGlyphPath(tool)}
    </svg>
  );
}

function toolGlyphPath(tool: string) {
  switch (tool) {
    case "claude-code":
      // Nested arcs framing a center dot — suggests reasoning.
      return (
        <>
          <path
            d="M9 5 C5 8, 5 16, 9 19"
            strokeWidth="1.8"
            strokeLinecap="round"
          />
          <path
            d="M15 5 C19 8, 19 16, 15 19"
            strokeWidth="1.8"
            strokeLinecap="round"
          />
          <circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none" />
        </>
      );
    case "codex":
      // Terminal prompt "> _".
      return (
        <>
          <path
            d="M5 9 L8 12 L5 15"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <line
            x1="11"
            y1="16"
            x2="19"
            y2="16"
            strokeWidth="1.8"
            strokeLinecap="round"
          />
        </>
      );
    case "cursor":
      // Cursor arrow.
      return (
        <path
          d="M6 4 L6 18 L10 14 L13 20 L15 19 L12 13 L18 13 Z"
          fill="currentColor"
          stroke="none"
        />
      );
    case "cline":
      // Chevron + bar (cli).
      return (
        <>
          <path
            d="M5 8 L9 12 L5 16"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <line
            x1="12"
            y1="16"
            x2="19"
            y2="16"
            strokeWidth="1.8"
            strokeLinecap="round"
          />
          <line
            x1="14"
            y1="8"
            x2="19"
            y2="8"
            strokeWidth="1.8"
            strokeLinecap="round"
            opacity="0.5"
          />
        </>
      );
    case "copilot":
      // Orbit — two dots inside an arc (pair-programming).
      return (
        <>
          <circle cx="12" cy="12" r="6" strokeWidth="1.6" />
          <circle cx="8.5" cy="9.5" r="1.6" fill="currentColor" stroke="none" />
          <circle
            cx="15.5"
            cy="14.5"
            r="1.6"
            fill="currentColor"
            stroke="none"
          />
        </>
      );
    case "cowork":
      // Two linked circles.
      return (
        <>
          <circle cx="9" cy="12" r="4" strokeWidth="1.8" />
          <circle cx="15" cy="12" r="4" strokeWidth="1.8" />
        </>
      );
    case "antigravity":
      // Upward triangle floating above a baseline.
      return (
        <>
          <path d="M12 5 L18 14 L6 14 Z" fill="currentColor" stroke="none" />
          <line
            x1="5"
            y1="18"
            x2="19"
            y2="18"
            strokeWidth="1.6"
            strokeLinecap="round"
            opacity="0.5"
          />
        </>
      );
    case "opencode":
      // Open square brackets.
      return (
        <>
          <path
            d="M9 6 L5 6 L5 18 L9 18"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M15 6 L19 6 L19 18 L15 18"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </>
      );
    case "openclaw":
      // Three diagonal strokes (claw marks).
      return (
        <>
          <path
            d="M7 6 L14 18"
            strokeWidth="1.8"
            strokeLinecap="round"
          />
          <path
            d="M11 5 L17 16"
            strokeWidth="1.8"
            strokeLinecap="round"
          />
          <path
            d="M15 4 L19 13"
            strokeWidth="1.8"
            strokeLinecap="round"
            opacity="0.65"
          />
        </>
      );
    case "pi":
      // Greek letter pi.
      return (
        <>
          <line
            x1="6"
            y1="9"
            x2="18"
            y2="9"
            strokeWidth="1.8"
            strokeLinecap="round"
          />
          <line
            x1="9"
            y1="9"
            x2="9"
            y2="18"
            strokeWidth="1.8"
            strokeLinecap="round"
          />
          <path
            d="M15 9 L15 16 Q15 18, 17 18"
            strokeWidth="1.8"
            strokeLinecap="round"
          />
        </>
      );
    case "gemini":
    case "gemini-cli":
      // Four-point sparkle.
      return (
        <path
          d="M12 5 L13.5 10.5 L19 12 L13.5 13.5 L12 19 L10.5 13.5 L5 12 L10.5 10.5 Z"
          fill="currentColor"
          stroke="none"
        />
      );
    default:
      // Generic dot.
      return (
        <circle cx="12" cy="12" r="3.5" fill="currentColor" stroke="none" />
      );
  }
}

// ----- capture-surface icons -----------------------------------------
//
// One per value of the closed capture-surface vocabulary (node migration
// 107 / models.SurfaceCLI..SurfaceWeb), rendered by SurfaceBadge. Same
// hand-rolled, currentColor-themed treatment as the nav icons above.

/** TerminalIcon — a shell prompt caret + line. Surface "cli". */
export function TerminalIcon({ size = 12, className }: IconProps) {
  return svg("M3.5 5.5 6 8l-2.5 2.5M8 11h4.5", size, className);
}

/** WindowIcon — an editor window with a title bar. Surface "ide". */
export function WindowIcon({ size = 12, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <rect
        x="2"
        y="3"
        width="12"
        height="10"
        rx="1.5"
        stroke="currentColor"
        strokeWidth="1.4"
      />
      <path d="M2 6h12" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  );
}

/** MonitorIcon — a screen on a stand. Surface "desktop". */
export function MonitorIcon({ size = 12, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <rect
        x="2"
        y="3"
        width="12"
        height="8"
        rx="1.5"
        stroke="currentColor"
        strokeWidth="1.4"
      />
      <path
        d="M6 13.5h4M8 11v2.5"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** BracketsIcon — angle brackets: a programmatic embedding. Surface "sdk". */
export function BracketsIcon({ size = 12, className }: IconProps) {
  return svg("M5.5 4.5 2.5 8l3 3.5M10.5 4.5 13.5 8l-3 3.5", size, className);
}

/** GlobeIcon — a meridian globe. Surface "web". */
export function GlobeIcon({ size = 12, className }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      className={className}
      aria-hidden
    >
      <circle cx="8" cy="8" r="5.5" stroke="currentColor" strokeWidth="1.4" />
      <path
        d="M2.5 8h11M8 2.5c1.6 1.6 2.4 3.4 2.4 5.5S9.6 12.4 8 13.5C6.4 12.4 5.6 10.1 5.6 8S6.4 4.1 8 2.5Z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
    </svg>
  );
}
