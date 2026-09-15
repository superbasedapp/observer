import { Link } from "react-router-dom";
import type { CloudStatusWithDigestPlan } from "@/lib/cloud";
import { fmtDateTime, fmtInt } from "@/lib/format";

// Shared explanation of session selection. Reading it never changes consent.
export function CloudEnrichmentSummary({ data }: { data: CloudStatusWithDigestPlan }) {
  const automatic = !!data.policy && data.policy.level !== "off" && data.policy.background;
  const plan = data.plan;
  const signedIn = data.sign_in?.signed_in;

  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3" aria-label="Session enrichment settings">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-[12px] font-semibold text-fg-1">
          Session enrichment · {automatic ? "Automatic" : "Choose sessions yourself"}
        </h3>
        <Link to="/settings?section=cloud" className="text-[11px] font-medium text-accent hover:text-accent-strong">
          Enrichment settings
        </Link>
      </div>
      <p className="mt-1 text-[11.5px] leading-relaxed text-fg-3">
        {automatic
          ? "Personal sessions are selected automatically, longest-waiting first. You can also choose a session yourself."
          : "Automatic session enrichment is off. Choose Enrich session beside a session to review and enrich just that session. This also works for older sessions."}
        {!signedIn && " Sign in to submit an enrichment; previewing stays local."}
      </p>
      {plan?.daily_cap != null && plan?.monthly_cap != null && (
        <p className="mt-1 text-[11px] text-fg-3">
          {plan.label}: up to {fmtInt(plan.daily_cap)} enrichments per day and {fmtInt(plan.monthly_cap)} per month, shared by automatic and manual requests. Windows reset in UTC. These are plan limits; remaining usage is checked when you submit.
        </p>
      )}
      <details className="mt-2 text-[11px] leading-relaxed text-fg-3">
        <summary className="w-fit cursor-pointer font-medium text-fg-2">Which sessions, and when?</summary>
        <ul className="mt-1.5 list-disc space-y-1 pl-4">
          <li>Automatic selection requires at least 3 recorded actions and a quiet period after the latest action. Organization-owned sessions are excluded.</li>
          <li>Only sessions started after Cloud Intelligence was enabled are selected automatically{data.policy?.since ? ` (${fmtDateTime(data.policy.since)})` : ""}. Older sessions can be chosen manually.</li>
          <li>By default, the node checks every 5 minutes after 10 minutes of inactivity, selecting up to 25 candidates per check. Enriched sessions and requests already in progress are skipped.</li>
          <li>Uploads and result pulls run on a separate sync schedule, every 15 minutes by default. The node must be running. Timing can be changed in Settings.</li>
          <li>Selection does not guarantee a quota slot or an immediate result. A queued request may wait for capacity or need review. Open its enrichment panel to check progress or retry.</li>
        </ul>
      </details>
    </section>
  );
}
