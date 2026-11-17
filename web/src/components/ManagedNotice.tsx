import { governedOrgLabel, type Governance } from "@/lib/governance";
import { navSource, settingsSource } from "@/lib/visibility";

/**
 * ManagedNotice renders instead of a page or a Settings section that is
 * hidden on this machine (the resolved visibility: the org's directives plus
 * the managed-node defaults). A direct-URL visit to a hidden page, or a
 * `/settings?section=` link to a hidden section, must say so - never blank
 * out, 404 or silently open another section (CG-20).
 *
 * Pass `navId` for a page or `settingsId` for a Settings section.
 */
export function ManagedNotice({
  gov,
  navId,
  settingsId,
}: {
  gov: Governance | null | undefined;
  navId?: string;
  settingsId?: string;
}) {
  const notice = gov?.notice;
  const section = settingsId != null;
  const byDefault = section
    ? settingsSource(gov, settingsId) === "default"
    : navSource(gov, navId ?? "") === "default";
  const what = section ? "This settings section" : "This page";
  return (
    <div
      className="flex h-full items-center justify-center p-12"
      data-testid={section ? "managed-settings-notice" : "managed-notice"}
    >
      <div className="max-w-md text-center">
        <h2 className="text-[15px] font-semibold text-fg-1">Managed by your organization</h2>
        <p className="mt-2 text-[12.5px] text-fg-3">
          {what} is managed by {governedOrgLabel(gov)} and is not available on this machine.
          {byDefault &&
            " It is hidden by default on organization-managed machines; your administrator can make it available."}
        </p>
        {(notice?.contact || notice?.policy_url) && (
          <p className="mt-3 text-[11.5px] text-fg-3">
            {notice?.contact && (
              <a href={`mailto:${notice.contact}`} className="text-accent hover:underline">
                {notice.contact}
              </a>
            )}
            {notice?.contact && notice?.policy_url && " · "}
            {notice?.policy_url && (
              <a href={notice.policy_url} target="_blank" rel="noreferrer" className="text-accent hover:underline">
                {notice.policy_url}
              </a>
            )}
          </p>
        )}
      </div>
    </div>
  );
}
