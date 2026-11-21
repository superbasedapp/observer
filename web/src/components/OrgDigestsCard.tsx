import { useState } from "react";
import { NeedsSettingLink } from "@/components/NeedsSettingNotice";
import { placeLink } from "@/lib/settingsPlaces";
import type { LucideIcon } from "lucide-react";
import { Button, ChartShell, Pill } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import { apiReason } from "@/lib/api";
import {
  ORG_DIGESTS_PATH,
  groupOrgDigests,
  orgDigestNotice,
  weekLabel,
  type OrgDigest,
  type OrgDigestsResponse,
} from "@/lib/orgDigests";

// OrgDigestsCard is the developer's read-only view of the weekly org project
// digests (T-490, D-328 item 3): the digests of the projects this member
// works in, as the org server built them on its own provider. The server
// scopes the list by the member's own sessions, audits the read and never
// serves a digest a purge or consent withdrawal invalidated (D-241). Nothing
// here can change a digest; the org admin runs them.
export function OrgDigestsCard({ icon }: { icon?: LucideIcon }) {
  // Not polled: each read is an audited request to the org.
  const res = useApi<OrgDigestsResponse>(ORG_DIGESTS_PATH, undefined, []);
  const data = res.data;
  const notice = data ? orgDigestNotice(data) : null;
  const projects = data && !notice ? groupOrgDigests(data.digests) : [];

  return (
    <ChartShell
      title="Organization project digests"
      icon={icon}
      sub="The weekly digest your organization builds for each project you work in, read-only. It sums up the week's sessions of everyone on the project, without names, cost or tokens."
      right={
        <Button size="sm" variant="ghost" onClick={() => res.reload()} disabled={res.loading}>
          Refresh
        </Button>
      }
    >
      <ChartState loading={res.loading && !data} error={null} denied={false} empty={false} height={120}>
        {res.error && !data ? (
          <p className="text-[12px] text-fg-2">The digests are not available here: {apiReason(res.error)}.</p>
        ) : notice ? (
          <p className={`text-[12px] leading-relaxed ${notice.tone === "warn" ? "text-warn" : "text-fg-2"}`}>
            {notice.text}
            {notice.place && (
              <>
                {" "}
                <NeedsSettingLink link={placeLink(notice.place)} />
              </>
            )}
          </p>
        ) : (
          <div className="space-y-3">
            {projects.map((p) => (
              <ProjectDigest key={p.projectId} label={p.label} latest={p.latest} previous={p.previous} />
            ))}
          </div>
        )}
      </ChartState>
    </ChartShell>
  );
}

function ProjectDigest({ label, latest, previous }: { label: string; latest: OrgDigest; previous: OrgDigest[] }) {
  const [open, setOpen] = useState(false);
  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="text-[12px] font-semibold text-fg-1">{label}</span>
        <Pill variant="accent">AI</Pill>
      </div>
      <DigestBody d={latest} />
      {previous.length > 0 && (
        <div className="mt-3 border-t border-line-2 pt-2">
          <button type="button" onClick={() => setOpen((v) => !v)} className="text-[10.5px] font-medium text-fg-3 hover:text-fg-1">
            {open ? "Hide earlier weeks" : `Show ${previous.length} earlier week${previous.length === 1 ? "" : "s"}`}
          </button>
          {open && (
            <div className="mt-2 space-y-3">
              {previous.map((d) => (
                <div key={d.week_start} className="border-t border-line-2 pt-2">
                  <DigestBody d={d} />
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function DigestBody({ d }: { d: OrgDigest }) {
  return (
    <div className="space-y-1.5 text-[11.5px] leading-snug text-fg-2">
      <div className="text-[10.5px] text-fg-3">
        {weekLabel(d)} · {d.session_count} session{d.session_count === 1 ? "" : "s"}
      </div>
      <div className="text-[12px] font-semibold text-fg-1">{d.headline}</div>
      <List title="Themes" items={d.themes} />
      <List title="Recurring errors" items={d.recurring_error_classes} />
      <List title="Unfinished threads" items={d.unfinished_threads} />
      {d.suggested_next_session && (
        <p>
          <span className="font-medium text-fg-1">Suggested next session: </span>
          {d.suggested_next_session}
        </p>
      )}
    </div>
  );
}

function List({ title, items }: { title: string; items?: string[] }) {
  if (!items || items.length === 0) return null;
  return (
    <div>
      <span className="font-medium text-fg-1">{title}: </span>
      {items.join("; ")}
    </div>
  );
}
