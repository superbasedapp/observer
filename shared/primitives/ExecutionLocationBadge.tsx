import { Pill } from "./Pill";
import { GlyphBadge } from "./GlyphBadge";
import { vocabIcon } from "../lib/vocabIcons";
import type { Tone } from "../lib/tone";

// ExecutionLocationBadge renders WHERE a session's agent ran (cloud-agents
// arc, decision CA-D1: node migration 240 / server migration 300,
// sessions.execution_location) as one small pill: on the developer's own
// machine, in the vendor's cloud sandbox, or on compute the customer runs for
// the vendor (a self-hosted worker or runner).
//
// It is a dimension of its own, NOT a capture surface: SurfaceBadge answers
// "how was the agent driven" (cli, ide, desktop, sdk, web) and one Claude Code
// cloud session can be driven from the web, the desktop app or the CLI. The
// two badges sit side by side.
//
// HONESTY RULE (the SurfaceBadge rule): the column is NULL whenever no capture
// path stamped a location, and absence means UNKNOWN, never "local". An
// unknown or unrecognised value renders NOTHING here. The "unknown" filter
// option below is how a viewer finds those sessions on purpose.

/** The closed execution-location vocabulary (models.Execution*). */
export type ExecutionLocation = "local" | "vendor_cloud" | "customer_worker";

type ExecutionMeta = {
  /** Short pill text. */
  label: string;
  /** Long-form gloss shown on hover/focus. */
  gloss: string;
  /** Pill tone: local stays calm, anything off this machine is called out. */
  tone: Tone;
};

// EXECUTION_META is the one table this component dispatches on: a data row
// per vocabulary value, never an if/else ladder (CLAUDE.md #5). The glyph
// comes from VOCAB_ICONS.executionLocation (shared/lib/vocabIcons).
const EXECUTION_META: Record<ExecutionLocation, ExecutionMeta> = {
  local: {
    label: "local",
    gloss: "The agent ran on the developer's own machine.",
    tone: "neutral",
  },
  vendor_cloud: {
    label: "cloud",
    gloss: "The agent ran in the vendor's cloud sandbox, not on this machine.",
    tone: "info",
  },
  customer_worker: {
    label: "worker",
    gloss: "The agent ran on compute your organization operates for the vendor (a self-hosted worker or runner).",
    tone: "accent",
  },
};

/** The ordered vocabulary, for pickers and tests. */
export const EXECUTION_LOCATIONS: readonly ExecutionLocation[] = ["local", "vendor_cloud", "customer_worker"];

/** isExecutionLocation narrows an arbitrary string to the closed vocabulary. */
export function isExecutionLocation(v: string | null | undefined): v is ExecutionLocation {
  return v === "local" || v === "vendor_cloud" || v === "customer_worker";
}

/** executionLocationLabel is the short label for a location, "unknown" for anything else. */
export function executionLocationLabel(v: string | null | undefined): string {
  return isExecutionLocation(v) ? EXECUTION_META[v].label : "unknown";
}

/**
 * The value a "Where it ran" filter sends: one vocabulary value, "unknown"
 * (sessions nothing stamped), or "" for no filter.
 */
export type ExecutionFilterValue = ExecutionLocation | "unknown" | "";

/**
 * EXECUTION_FILTER_OPTIONS backs every "Where it ran" picker (node Sessions,
 * org Sessions and Projects), walked as data so both dashboards offer the same
 * choices with the same words. The query parameter is `execution_location`.
 */
export const EXECUTION_FILTER_OPTIONS: ReadonlyArray<{ value: ExecutionFilterValue; label: string }> = [
  { value: "", label: "Ran: anywhere" },
  { value: "local", label: "local - this machine" },
  { value: "vendor_cloud", label: "cloud - vendor sandbox" },
  { value: "customer_worker", label: "worker - your compute" },
  { value: "unknown", label: "unknown - not recorded" },
];

/** isExecutionFilterValue narrows a URL or picker value to a filter value. */
export function isExecutionFilterValue(v: string | null | undefined): v is ExecutionFilterValue {
  return v === "" || v === "unknown" || isExecutionLocation(v);
}

export type ExecutionLocationBadgeProps = {
  /** sessions.execution_location: one vocabulary value, or absent. */
  location?: string | null;
  /**
   * sessions.vendor_session_ref: the vendor's second native session id, used
   * to join rails. Shown only in the tooltip; it is an opaque id, never content.
   */
  vendorRef?: string | null;
  /**
   * hideLocal renders nothing for "local". A table whose rows are almost all
   * local spends its width on the exceptions; the detail panel keeps it.
   */
  hideLocal?: boolean;
  /**
   * glyph draws the location's glyph alone, in its tone (no pill, no
   * words); the tooltip and the accessible name carry the words.
   */
  glyph?: boolean;
  className?: string;
};

export function ExecutionLocationBadge({ location, vendorRef, hideLocal, glyph, className }: ExecutionLocationBadgeProps) {
  // Nothing grounded means render nothing. Never a fabricated "local".
  if (!isExecutionLocation(location)) return null;
  if (hideLocal && location === "local") return null;
  const meta = EXECUTION_META[location];
  const ref = (vendorRef ?? "").trim();
  const title = ["Where it ran:", meta.gloss, ref ? `Vendor session: ${ref}.` : ""].filter(Boolean).join(" ");
  if (glyph) {
    return (
      <GlyphBadge
        className={className}
        icon={vocabIcon("executionLocation", location)}
        tone={meta.tone}
        label={`Ran: ${meta.label}. ${title}`}
      />
    );
  }
  return (
    <Pill
      className={className}
      title={title}
      icon={vocabIcon("executionLocation", location)}
      variant={meta.tone}
    >
      {meta.label}
    </Pill>
  );
}
