import { Pill } from "./Pill";
import { GlyphBadge } from "./GlyphBadge";
import { vocabIcon } from "../lib/vocabIcons";

// SurfaceBadge renders the capture-surface attribution a session carries
// (node migration 107: sessions.surface / sessions.surface_host) as one small
// pill: "how was this agent driven?" — a terminal, an editor, a desktop app, a
// programmatic embedding, or a browser.
//
// HONESTY RULE (the reason this component exists rather than a `?? "cli"`
// default at each call site): the columns are OMITTED whenever no adapter
// stamped one, and absence means UNKNOWN, never "cli". An unknown or
// unrecognised kind renders NOTHING — no pill, no placeholder, no guess. The
// same rule governs the org drawer, where an old node ships no surface at all.
//
// The KIND is a closed vocabulary (models.SurfaceCLI..SurfaceWeb) and drives
// the icon + label. The HOST token is free-form by design — adapters mint
// their own ("vscode", "cursor", "jetbrains-idea", "claude-desktop",
// "antigravity-cli", "freebuff-desktop", ...) — so it is rendered VERBATIM
// beside the kind rather than mapped through a table that would go stale as
// adapters land. A host with no kind still renders (the columns are
// independent: SetSessionSurface fills each one separately).

/** The closed capture-surface vocabulary. */
export type SurfaceKind = "cli" | "ide" | "desktop" | "sdk" | "web" | "mobile";

type SurfaceMeta = {
  label: string;
  /** Long-form gloss shown on hover/focus. The glyph comes from
   * VOCAB_ICONS.captureSurface (shared/lib/vocabIcons), the one icon table. */
  gloss: string;
};

// SURFACE_META is the one table this component dispatches on — a data row per
// vocabulary value, never an if/else ladder (CLAUDE.md #5).
const SURFACE_META: Record<SurfaceKind, SurfaceMeta> = {
  cli: {
    label: "cli",
    gloss: "Captured from a terminal run of the tool's CLI.",
  },
  ide: {
    label: "ide",
    gloss:
      "Captured from an editor extension, plugin, or IDE fork driving the agent.",
  },
  desktop: {
    label: "desktop",
    gloss: "Captured from a standalone desktop app.",
  },
  sdk: {
    label: "sdk",
    gloss: "Captured from a programmatic embedding (agent SDK / API harness).",
  },
  web: {
    label: "web",
    gloss: "Captured from a browser / web-app surface.",
  },
  mobile: {
    label: "mobile",
    gloss: "Driven from a phone or tablet app (the Claude mobile app starting a cloud session).",
  },
};

/** isSurfaceKind narrows an arbitrary string to the closed vocabulary. */
export function isSurfaceKind(v: string | null | undefined): v is SurfaceKind {
  return v === "cli" || v === "ide" || v === "desktop" || v === "sdk" || v === "web" || v === "mobile";
}

export type SurfaceBadgeProps = {
  /** sessions.surface — one of the closed vocabulary values, or absent. */
  surface?: string | null;
  /** sessions.surface_host — the free-form host token, or absent. */
  host?: string | null;
  className?: string;
  /**
   * compact drops the kind WORD when a host is present: the glyph already
   * names the kind and the tooltip spells both out, so a narrow table cell
   * spends its width on the host ("claude-desktop") instead of truncating
   * "cli · cla..." (T-803). Without a host the kind word still shows.
   */
  compact?: boolean;
  /**
   * glyph draws the kind's glyph alone (no pill, no words); the tooltip and
   * the accessible name carry the kind and host. For a dense table cell that
   * shows the client beside another badge.
   */
  glyph?: boolean;
};

export function SurfaceBadge({ surface, host, className, compact, glyph }: SurfaceBadgeProps) {
  const kind = isSurfaceKind(surface) ? surface : null;
  const hostToken = (host ?? "").trim();
  // Nothing grounded => render nothing. Never a fabricated "cli".
  if (!kind && !hostToken) return null;

  const meta = kind ? SURFACE_META[kind] : null;
  const title = [
    "Capture surface:",
    meta ? meta.gloss : "host reported, kind unknown.",
    hostToken ? `Host: ${hostToken}.` : "",
  ]
    .filter(Boolean)
    .join(" ");

  if (glyph) {
    // Name first (what a table header would have said), then the gloss.
    const name = [meta ? meta.label : "", hostToken].filter(Boolean).join(" · ");
    return (
      <GlyphBadge
        className={className}
        icon={vocabIcon("captureSurface", kind)}
        label={`Client: ${name}. ${meta ? meta.gloss : "Host reported, kind unknown."}`}
      />
    );
  }

  return (
    <Pill className={className} title={title} icon={kind ? vocabIcon("captureSurface", kind) : undefined}>
      {meta && !(compact && hostToken) ? meta.label : null}
      {hostToken ? (
        <span className="text-fg-3">
          {meta && !compact ? "· " : ""}
          {hostToken}
        </span>
      ) : null}
    </Pill>
  );
}
