import { Link } from "react-router-dom";
import { ExternalLink } from "lucide-react";
import { Button, ReadOnlyBanner } from "@/components/primitives";
import { governedOrgLabel, type Governance } from "@/lib/governance";
import { managedNext, type ManagedLevel, type NextLink } from "@/lib/managedNext";
import { navSource, settingsSource } from "@/lib/visibility";

/**
 * ManagedNotice renders instead of a page or a Settings section that is
 * hidden on this machine (the resolved visibility: the org's directives plus
 * the managed-node defaults). A direct-URL visit to a hidden page, or a
 * `/settings?section=` link to a hidden section, must say so - never blank
 * out, 404 or silently open another section (CG-20).
 *
 * It is never a dead end (operator ruling 2, 2026-11-24): lib/managedNext.ts
 * decides the sentence and the next steps. On a machine its owner manages
 * from a personal organization of one it says the owner controls it and links
 * to their online dashboard's Settings > Developer dashboards and the same
 * page there; on a team member's machine it names the administrator and
 * offers a request, a message, the contact and the page on the organization's
 * dashboard where every member may open it.
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
  const section = settingsId != null;
  const next = managedNext({
    level: "hidden",
    kind: section ? "section" : "page",
    navId,
    online: gov?.online,
    orgLabel: governedOrgLabel(gov),
    byDefault: section ? settingsSource(gov, settingsId) === "default" : navSource(gov, navId ?? "") === "default",
    contact: gov?.notice?.contact,
    policyUrl: gov?.notice?.policy_url,
  });
  return (
    <div
      className="flex h-full items-center justify-center p-12"
      data-testid={section ? "managed-settings-notice" : "managed-notice"}
    >
      <div className="max-w-md text-center">
        <h2 className="text-[15px] font-semibold text-fg-1">{next.title}</h2>
        <p className="mt-2 text-[12.5px] text-fg-3" data-testid="managed-notice-text">
          {next.body}
        </p>
        <NextSteps links={next.links} className="mt-3 justify-center" />
      </div>
    </div>
  );
}

/**
 * ManagedReadOnlyBar sits above a page this machine's organization locked
 * read-only: the page renders, and its writes are refused by the daemon (409
 * governance_read_only). Saying so up front beats a button that fails, and
 * the bar carries the same next steps as the hidden-page notice.
 */
export function ManagedReadOnlyBar({ gov, navId }: { gov: Governance | null | undefined; navId?: string }) {
  const next = managedNext({
    level: "read_only" satisfies ManagedLevel,
    kind: "page",
    navId,
    online: gov?.online,
    orgLabel: governedOrgLabel(gov),
    byDefault: navSource(gov, navId ?? "") === "default",
    contact: gov?.notice?.contact,
    policyUrl: gov?.notice?.policy_url,
  });
  return (
    <div
      role="status"
      data-testid="managed-read-only"
      className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-line-1 bg-bg-1 px-4 py-2 text-[11.5px] text-fg-3 sm:px-6"
    >
      <span className="min-w-0 flex-1 basis-[18rem]" data-testid="managed-read-only-text">
        {next.body}
      </span>
      <NextSteps links={next.links} />
    </div>
  );
}

/**
 * ManagedSettingsReadOnly is the banner above a Settings section this
 * machine's organization locked read-only, with the same next steps as a
 * read-only page (the section has no online page equivalent).
 */
export function ManagedSettingsReadOnly({
  gov,
  settingsId,
  className,
}: {
  gov: Governance | null | undefined;
  settingsId: string;
  className?: string;
}) {
  const next = managedNext({
    level: "read_only",
    kind: "section",
    online: gov?.online,
    orgLabel: governedOrgLabel(gov),
    byDefault: settingsSource(gov, settingsId) === "default",
    contact: gov?.notice?.contact,
    policyUrl: gov?.notice?.policy_url,
  });
  return (
    <ReadOnlyBanner className={className}>
      <span data-testid="managed-settings-read-only">{next.body}</span>
      <NextSteps links={next.links} className="mt-1.5" />
    </ReadOnlyBanner>
  );
}

/** NextSteps renders the notice's links: in-app ones as router links, the
 *  online dashboard, a mail address and a policy page in a new tab. */
function NextSteps({ links, className }: { links: NextLink[]; className?: string }) {
  if (links.length === 0) return null;
  return (
    <div className={`flex flex-wrap items-center gap-2 ${className ?? ""}`} data-testid="managed-next-steps">
      {links.map((l) =>
        l.external ? (
          <Button
            key={l.key}
            size="sm"
            variant="secondary"
            iconLeft={ExternalLink}
            href={l.href}
            target={l.href.startsWith("mailto:") ? undefined : "_blank"}
            data-testid={`managed-next-${l.key}`}
          >
            {l.label}
          </Button>
        ) : (
          <Link
            key={l.key}
            to={l.href}
            className="text-[11.5px] font-medium text-accent hover:text-accent-strong"
            data-testid={`managed-next-${l.key}`}
          >
            {l.label}
          </Link>
        ),
      )}
    </div>
  );
}
