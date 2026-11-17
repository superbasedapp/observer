import { Link } from "react-router-dom";
import type { OrgSessionsBanner } from "@/lib/orgIntel";

// OrgSessionsBannerView is the Sessions-list banner for org-plane sessions
// (ruling Q6): the org enrichment state and the org's terms, decided by the
// pure orgIntelSessionsBanner. It sits where the personal
// CloudEnrichmentSummary sits and uses the same frame; reading it never
// changes consent.
export function OrgSessionsBannerView({ banner }: { banner: OrgSessionsBanner }) {
  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3" aria-label="Team AI summaries">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-[12px] font-semibold text-fg-1">{banner.title}</h3>
        <Link to={banner.link} className="text-[11px] font-medium text-accent hover:text-accent-strong">
          Team AI summaries settings
        </Link>
      </div>
      <p className="mt-1 text-[11.5px] leading-relaxed text-fg-3">{banner.text}</p>
      {banner.terms && <p className="mt-1 break-words text-[11px] text-fg-3">{banner.terms}</p>}
    </section>
  );
}
