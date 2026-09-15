import { useState } from "react";
import { useApi } from "@/lib/useApi";
import {
  parseAnnouncement,
  useReleaseAnnouncement,
  type ReleaseAnnouncement,
} from "@/lib/version";

// AnnouncementBanner — the single banner surface for every announcement
// rail (docs/plans/dashboard-announcements-banner-plan-2026-07-31.md §1).
// A slim strip under the TopBar, ONE announcement at a time (highest
// severity, then newest), ALWAYS dismissible, never a modal, never
// blocking. Dismissals persist in localStorage under `sb_announce_ack`,
// copying the BudgetBanner `sb_budget_ack` pattern.
//
// Two rails feed it today, neither of which adds a network behaviour:
//   - R1 release-embedded, via GET /api/announcements — a local
//     endpoint reading data compiled into the daemon binary.
//   - R2 the update-check piggyback, read out of the response the
//     operator's own "Check for updates" click already fetched
//     (web/src/lib/version.ts). Nothing is fetched on this component's
//     behalf, ever.
// The org rail (R3) lands on the same endpoint later; this component
// needs no change for it.
//
// Content is rendered as PLAIN TEXT. No field is ever interpreted as
// HTML or markdown, and the optional link is a single https anchor —
// the plan (§6) records "rich bodies" as a deliberate non-goal.
const ACK_KEY = "sb_announce_ack";

type AnnouncementsResponse = {
  announcements?: ReleaseAnnouncement[] | null;
};

function acks(): Record<string, true> {
  try {
    return JSON.parse(localStorage.getItem(ACK_KEY) ?? "{}") as Record<
      string,
      true
    >;
  } catch {
    return {};
  }
}

const SEVERITY_RANK: Record<ReleaseAnnouncement["severity"], number> = {
  critical: 3,
  notice: 2,
  info: 1,
};

// mergeAnnouncements mirrors announce.Merge (Go) exactly so the one
// announcement shown here is the head of the same ordering the backend
// computes: validate + drop expired, dedupe by id (first wins), then
// severity descending, newest (later expiry) first, id last.
//
// Re-validating the endpoint's rows client-side is not paranoia about
// our own daemon — it is what keeps the ordering and the expiry cutoff
// correct in a tab that has been open across an expiry instant, and it
// applies the same https-only rule to every rail.
export function mergeAnnouncements(
  ...sources: (ReleaseAnnouncement[] | ReleaseAnnouncement | null | undefined)[]
): ReleaseAnnouncement[] {
  const now = Date.now();
  const seen = new Set<string>();
  const out: ReleaseAnnouncement[] = [];
  for (const src of sources) {
    if (!src) continue;
    for (const raw of Array.isArray(src) ? src : [src]) {
      const a = parseAnnouncement(raw, now);
      if (!a || seen.has(a.id)) continue;
      seen.add(a.id);
      out.push(a);
    }
  }
  return out.sort((x, y) => {
    const rank = SEVERITY_RANK[y.severity] - SEVERITY_RANK[x.severity];
    if (rank !== 0) return rank;
    const exp = Date.parse(y.expires_at) - Date.parse(x.expires_at);
    if (exp !== 0) return exp;
    return x.id < y.id ? -1 : x.id > y.id ? 1 : 0;
  });
}

// severityClasses is the styling ladder, mirroring BudgetBanner's:
// critical → danger (reserved for security advisories), notice →
// accent, info → neutral.
function severityClasses(severity: ReleaseAnnouncement["severity"]): {
  strip: string;
  label: string;
  text: string;
} {
  switch (severity) {
    case "critical":
      return {
        strip: "border-danger/30 bg-danger-soft",
        label: "font-semibold text-danger",
        text: "Advisory",
      };
    case "notice":
      return {
        strip: "border-accent/30 bg-accent-soft",
        label: "font-semibold text-accent",
        text: "Notice",
      };
    default:
      return {
        strip: "border-line-2 bg-bg-2",
        label: "font-semibold text-fg-1",
        text: "Note",
      };
  }
}

export function AnnouncementBanner() {
  // No refreshMs: announcements change at release/fleet-policy speed,
  // not request speed, and the endpoint is a pure in-memory fold. One
  // fetch per mount is the right cost.
  const api = useApi<AnnouncementsResponse>("/api/announcements");
  const fromUpdateCheck = useReleaseAnnouncement();
  const [, bump] = useState(0);

  const merged = mergeAnnouncements(api.data?.announcements, fromUpdateCheck);
  const acked = acks();
  const showing = merged.find((a) => !acked[a.id]);
  if (!showing) return null;

  const style = severityClasses(showing.severity);
  const dismiss = () => {
    const next = acks();
    next[showing.id] = true;
    try {
      localStorage.setItem(ACK_KEY, JSON.stringify(next));
    } catch {
      // Storage unavailable — the banner stays; nothing breaks.
    }
    bump((n) => n + 1);
  };

  return (
    <div
      className={`flex items-center gap-2 border-b px-4 py-1.5 text-[11.5px] text-fg-2 ${style.strip}`}
      role="status"
    >
      <span className={style.label}>{style.text}</span>
      <span className="min-w-0 truncate">
        <span className="font-medium text-fg-1">{showing.title}</span>
        {showing.body ? ` - ${showing.body}` : ""}
      </span>
      <div className="flex-1" />
      {showing.url && (
        <a
          href={showing.url}
          target="_blank"
          rel="noopener noreferrer"
          className="shrink-0 text-[11px] font-medium text-accent hover:text-accent-strong"
        >
          Details →
        </a>
      )}
      <button
        type="button"
        onClick={dismiss}
        aria-label="Dismiss announcement"
        title="Dismiss"
        className="shrink-0 rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-fg-2 hover:bg-bg-3"
      >
        ×
      </button>
    </div>
  );
}
