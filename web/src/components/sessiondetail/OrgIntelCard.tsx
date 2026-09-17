import { IntelResultCard, type IntelResultLike } from "@shared/components/sessiondetail";
import { sessionOrgIntelPath } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { OrgIntelResponse } from "@/lib/types";

// OrgIntelCard — the org-served Cloud Intelligence row on the session Overview
// tab (org-served-cloud-intelligence plan §3.5, W8b). It reads
// /api/session/<id>/org-intel (node-local org_intel_cache: the org's own
// derived result pulled back for this session) and renders it through the
// SHARED IntelResultCard, so the node and org drawers show the same card.
//
// Honesty + quietness rules it follows:
//   - it is a QUIET add-on: while loading it renders nothing (no flash), and a
//     node whose org has not enabled enrichment (the common case) has no
//     cached result, so the card does not appear at all rather than showing an
//     empty "no enrichment" box on every session;
//   - the node cache carries no provider / model / tokens / cost, so none are
//     shown — the shared card omits what is absent rather than zeroing it;
//   - the timestamp is the node's own PULL time, labelled "fetched", not the
//     org's production time.
export function OrgIntelCard({ sessionId }: { sessionId: string }) {
  const intel = useApi<OrgIntelResponse>(
    sessionOrgIntelPath(sessionId),
    undefined,
    [sessionId],
  );
  const d = intel.data;
  // No flash while loading, and nothing at all when this session has no cached
  // org result — the majority case on a node whose org has not enabled it.
  if (!d || !d.enriched || !d.result) return null;

  const r = d.result;
  const result: IntelResultLike = {
    title: r.title,
    description: r.description,
    confidence: r.confidence,
    taxonomyTags: r.taxonomy_tags,
    suggestedTags: r.suggested_tags,
    limitations: r.limitations,
    // The five narrative lists go straight into the SHARED card, which already
    // owns the one narrative renderer - the node drawer does not get a second
    // copy of it. Each is undefined when the org sent none, and the card omits
    // an absent list rather than printing an empty heading.
    workDone: r.work_done,
    plansImplemented: r.plans_implemented,
    issuesFound: r.issues_found,
    failures: r.failures,
    nextSteps: r.next_steps,
    schemaVersion: r.schema_version,
    generatedAt: r.fetched_at,
  };

  return (
    <IntelResultCard
      result={result}
      // Never reached (we only mount when result is present), but the prop is
      // required; kept honest in case the mount condition ever loosens.
      emptyMessage="No enrichment for this session."
      generatedAtLabel="fetched"
    />
  );
}
