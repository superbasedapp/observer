import type { ReactElement } from "react";
import { Pill } from "./Pill";
import {
  BracketsIcon,
  GlobeIcon,
  MonitorIcon,
  TerminalIcon,
  WindowIcon,
} from "../lib/icons";

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
export type SurfaceKind = "cli" | "ide" | "desktop" | "sdk" | "web";

type SurfaceMeta = {
  label: string;
  icon: (props: { size?: number; className?: string }) => ReactElement;
  /** Long-form gloss shown on hover/focus. */
  gloss: string;
};

// SURFACE_META is the one table this component dispatches on — a data row per
// vocabulary value, never an if/else ladder (CLAUDE.md #5).
const SURFACE_META: Record<SurfaceKind, SurfaceMeta> = {
  cli: {
    label: "cli",
    icon: TerminalIcon,
    gloss: "Captured from a terminal run of the tool's CLI.",
  },
  ide: {
    label: "ide",
    icon: WindowIcon,
    gloss:
      "Captured from an editor extension, plugin, or IDE fork driving the agent.",
  },
  desktop: {
    label: "desktop",
    icon: MonitorIcon,
    gloss: "Captured from a standalone desktop app.",
  },
  sdk: {
    label: "sdk",
    icon: BracketsIcon,
    gloss: "Captured from a programmatic embedding (agent SDK / API harness).",
  },
  web: {
    label: "web",
    icon: GlobeIcon,
    gloss: "Captured from a browser / web-app surface.",
  },
};

/** isSurfaceKind narrows an arbitrary string to the closed vocabulary. */
export function isSurfaceKind(v: string | null | undefined): v is SurfaceKind {
  return v === "cli" || v === "ide" || v === "desktop" || v === "sdk" || v === "web";
}

export type SurfaceBadgeProps = {
  /** sessions.surface — one of the closed vocabulary values, or absent. */
  surface?: string | null;
  /** sessions.surface_host — the free-form host token, or absent. */
  host?: string | null;
  className?: string;
};

export function SurfaceBadge({ surface, host, className }: SurfaceBadgeProps) {
  const kind = isSurfaceKind(surface) ? surface : null;
  const hostToken = (host ?? "").trim();
  // Nothing grounded => render nothing. Never a fabricated "cli".
  if (!kind && !hostToken) return null;

  const meta = kind ? SURFACE_META[kind] : null;
  const Icon = meta?.icon;
  const title = [
    "Capture surface",
    meta ? `— ${meta.gloss}` : "— host reported, kind unknown.",
    hostToken ? `Host: ${hostToken}.` : "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <Pill className={className} title={title}>
      {Icon ? <Icon size={11} className="shrink-0 opacity-80" /> : null}
      {meta ? meta.label : null}
      {hostToken ? (
        <span className="text-fg-3">
          {meta ? "· " : ""}
          {hostToken}
        </span>
      ) : null}
    </Pill>
  );
}
