import { Link } from "react-router-dom";
import { useApi } from "@/lib/useApi";
import { HelpInd } from "@/components/HelpInd";
import { Pill } from "@/components/primitives";

// PromptGuardLine — Session Detail Overview's small prompt-submit
// intervention indicator (PHASE-3b-DASHBOARD task item 3). Renders
// NOTHING when the session has no user_prompt guard events (the common
// case — most sessions never trip R-172/R-190), so it never adds noise
// to a clean session's Overview tab. When it has events, shows a count
// + the most recent outcome and links to the Security page's Prompt
// guard card for the full picture (per-session filtering there is a
// manual step today — the card has no session deep-link yet, so this
// links to the section, not a pre-filtered view).
//
// Reuses GET /api/guard/prompt/events (Security page's own data
// source) with session_id + a wide `since` window, since a session can
// be arbitrarily old — never any matched value or prompt text, same
// privacy invariant as the Security page card.

type PromptGuardEventsResponse = {
  events:
    | {
        id: number;
        ts: string;
        outcome?: string;
        rule_id: string;
        detectors?: string[] | null;
      }[]
    | null;
  count: number;
};

const OUTCOME_VARIANT: Record<string, "neutral" | "warn" | "danger" | "info" | "accent"> = {
  blocked: "danger",
  confirmed: "info",
  warned: "warn",
  redacted: "accent",
  allowed: "neutral",
};

function outcomeVariant(outcome: string): "neutral" | "warn" | "danger" | "info" | "accent" {
  if (outcome.startsWith("degraded:")) return "warn";
  return OUTCOME_VARIANT[outcome] ?? "neutral";
}

export function PromptGuardLine({ sessionId }: { sessionId: string }) {
  const events = useApi<PromptGuardEventsResponse>(
    "/api/guard/prompt/events",
    // ~2 years — a session can be old; this is a cheap indexed-by-id
    // scan over guard_events (low-volume by design), not a hot path.
    { session_id: sessionId, since: "17520h", limit: 50 },
    [sessionId],
  );

  const rows = events.data?.events ?? [];
  if (events.loading || rows.length === 0) return null;

  const last = rows[0]; // LoadRecentGuardEvents orders most-recent-first
  const lastOutcome = last.outcome || "unknown";

  return (
    <div className="mt-5 flex flex-wrap items-center gap-2 rounded-3 border bg-bg-2 px-4 py-3 text-[11.5px]">
      <span className="flex items-center gap-1.5 font-semibold uppercase tracking-[0.06em] text-fg-3">
        Prompt guard
        <HelpInd id="card.session_prompt_guard" />
      </span>
      <span className="text-fg-2">
        {rows.length} prompt-submit event{rows.length === 1 ? "" : "s"} in this session
      </span>
      <span className="text-fg-3">· last:</span>
      <Pill variant={outcomeVariant(lastOutcome)}>{lastOutcome}</Pill>
      <Link
        to="/security"
        className="ml-auto text-[11px] text-accent underline decoration-dotted underline-offset-[3px] hover:decoration-accent"
      >
        View in Security →
      </Link>
    </div>
  );
}
