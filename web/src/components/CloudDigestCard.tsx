import { useState } from "react";
import { Button, Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { cloudFmtWhen } from "@/lib/cloud";
import { fmtDateRange } from "@/lib/format";
import type {
  CloudDigestEntry,
  CloudDigestsResponse,
  CloudStatusWithDigestPlan,
} from "@/lib/cloud";

// CLOUD_PORTAL_BILLING_URL is where the locked card's upsell link points —
// the same portal billing page CloudIntelligenceSection's "Manage plan" link
// uses, so the two surfaces never disagree about where to send someone.
const CLOUD_PORTAL_BILLING_URL = "https://cloud.superbased.app/portal/billing";

// CLOUD_DIGEST_LIMIT bounds how many periods this card fetches — one latest
// plus a small "previous" tail, never the whole history.
const CLOUD_DIGEST_LIMIT = 6;

// CloudDigestCard renders one project's weekly digest (value-upgrade plan
// §W5): the latest period in full, older ones collapsed. Three honest
// states:
//
//   (a) a digest exists — the latest rendered in full, with a "previous"
//       disclosure for the rest;
//   (b) the plan is KNOWN and does not include weekly digests — a quiet
//       upsell card ("locked");
//   (c) the plan is unknown, OR it includes digests but none has arrived
//       yet — a muted one-line placeholder.
//
// Rule (b) never fires off an unknown plan: a `null` plan is always state
// (c), never a fabricated "locked" card.
export function CloudDigestCard({ projectRoot }: { projectRoot: string }) {
  const status = useApi<CloudStatusWithDigestPlan>(
    "/api/cloud/status",
    undefined,
    [],
  );
  const digests = useApi<CloudDigestsResponse>(
    projectRoot ? "/api/cloud/digests" : null,
    projectRoot ? { project: projectRoot, limit: CLOUD_DIGEST_LIMIT } : undefined,
    [projectRoot],
  );

  // No flash while either read is still in flight — the same discipline
  // CloudRow follows for its own first paint.
  if (!status.data || !digests.data) return null;

  const entries = digests.data.digests;
  if (entries.length > 0) {
    return <CloudDigestEntries entries={entries} />;
  }

  const plan = status.data.plan;
  if (plan && plan.digest_weekly === false) {
    return <CloudDigestLockedCard />;
  }

  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3">
      <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        Weekly project digest
      </div>
      <p className="text-[11.5px] leading-snug text-fg-3">
        Your first weekly digest appears here after a week of enriched
        sessions.
      </p>
    </section>
  );
}

function CloudDigestLockedCard() {
  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3">
      <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        Weekly project digest
      </div>
      <p className="text-[11.5px] leading-relaxed text-fg-3">
        Themes, cost and token trend, recurring error classes, unfinished
        threads and a suggested next session for this project, every week.
      </p>
      <Button
        href={CLOUD_PORTAL_BILLING_URL}
        target="_blank"
        rel="noreferrer"
        variant="primary"
        size="sm"
        className="mt-2"
      >
        Part of Plus - USD 15/month, 7-day trial
      </Button>
    </section>
  );
}

function CloudDigestEntries({ entries }: { entries: CloudDigestEntry[] }) {
  const [showPrevious, setShowPrevious] = useState(false);
  const [latest, ...previous] = entries;

  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Weekly project digest
        </span>
        <Pill variant="accent">AI</Pill>
      </div>
      <CloudDigestBody entry={latest} />
      {previous.length > 0 && (
        <div className="mt-3 border-t border-line-2 pt-2">
          <button
            type="button"
            onClick={() => setShowPrevious((v) => !v)}
            className="text-[10.5px] font-medium text-fg-3 hover:text-fg-1"
          >
            {showPrevious
              ? "Hide previous digests"
              : `Show ${previous.length} previous digest${previous.length === 1 ? "" : "s"}`}
          </button>
          {showPrevious && (
            <div className="mt-2 space-y-3">
              {previous.map((e) => (
                <div key={e.id} className="border-t border-line-2 pt-2">
                  <CloudDigestBody entry={e} />
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function CloudDigestBody({ entry }: { entry: CloudDigestEntry }) {
  const r = entry.result;
  return (
    <div>
      <div className="text-[12px] font-semibold leading-snug text-fg-1">
        {r.headline}
      </div>
      <div className="mt-0.5 text-[10.5px] text-fg-4">
        {fmtDateRange(r.period_start, r.period_end)} - {r.confidence} confidence -
        received {cloudFmtWhen(entry.received_at)}
      </div>

      {r.themes.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {r.themes.map((t) => (
            <Pill key={t} variant="neutral">
              {t}
            </Pill>
          ))}
        </div>
      )}

      {r.cost_trend && (
        <p className="mt-2 text-[11px] leading-snug text-fg-2">{r.cost_trend}</p>
      )}

      {r.recurring_error_classes.length > 0 && (
        <div className="mt-2">
          <div className="text-[10px] font-semibold uppercase tracking-[0.05em] text-fg-4">
            Recurring error classes
          </div>
          <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[11px] leading-snug text-fg-2">
            {r.recurring_error_classes.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </div>
      )}

      {r.unfinished_threads.length > 0 && (
        <div className="mt-2">
          <div className="text-[10px] font-semibold uppercase tracking-[0.05em] text-fg-4">
            Unfinished threads
          </div>
          <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[11px] leading-snug text-fg-2">
            {r.unfinished_threads.map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
        </div>
      )}

      {r.suggested_next_session && (
        <p className="mt-2 text-[11px] leading-snug text-fg-2">
          <span className="font-semibold text-fg-1">Suggested next session: </span>
          {r.suggested_next_session}
        </p>
      )}

      {/* Limitations are what the digest could NOT observe - an honesty
          qualifier, never a to-do list. The digest's own "what to do next" is
          "Unfinished threads" + "Suggested next session" above, so this line
          is explicitly labelled so the two are never read as the same thing. */}
      {r.limitations.length > 0 && (
        <p className="mt-2 text-[10px] leading-snug text-fg-4">
          <span className="font-semibold">Limitations: </span>
          {r.limitations.join(" - ")}
        </p>
      )}
    </div>
  );
}
