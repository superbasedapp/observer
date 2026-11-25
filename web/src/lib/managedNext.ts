// managedNext: what a hidden or read-only page (or Settings section) says, and
// the next steps it offers (operator ruling 2, 2026-11-24: a hidden or
// read-only page is never a dead end). The one owner of that wording and of
// which links appear; components/ManagedNotice.tsx renders it.
//
// Two audiences, decided by the daemon's `online.kind` (never a host name):
//
//   - personal: the organization is the developer's own, so they are its
//     administrator. The notice says the owner controls it and links to their
//     online dashboard's Settings > Developer dashboards and, where one
//     exists, the same page there.
//   - team: the notice names who manages it (the organization's contact when
//     it published one) and offers the in-app ways to ask (a page-access
//     request, a message to the admins), the contact and policy links, and
//     the page on the organization's dashboard when every member may open it.
//
// Every link is either in-app (a floor page: always shown) or an address the
// daemon built from the enrolment (lib/visibility.ts onlineHref re-checks it).
// The link table is walked top-down (CLAUDE.md #5); one test case per row.
//
// Pure: no React, no fetch, so managedNext.test.ts runs under `node --test`.

import { pageRequestLink } from "./requestEntry.ts";
import { onlineHref, onlinePageFor, type GovernanceOnline } from "./visibility.ts";

export type ManagedLevel = "hidden" | "read_only";

export type ManagedNextInput = {
  level: ManagedLevel;
  /** A page (nav id) or a Settings section. */
  kind: "page" | "section";
  /** The page's nav id (for its online equivalent and an access request). */
  navId?: string;
  online?: GovernanceOnline | null;
  /** The organization's display name (governedOrgLabel), never an id. */
  orgLabel: string;
  /** The level comes from the managed-machine default, not an org choice. */
  byDefault: boolean;
  /** The organization's published contact and policy page (notice). */
  contact?: string;
  policyUrl?: string;
};

export type NextLink = {
  key: string;
  href: string;
  label: string;
  /** Opens outside the dashboard (a new tab). */
  external: boolean;
};

export type ManagedNext = {
  title: string;
  body: string;
  links: NextLink[];
};

/** Whether the organization is the developer's own. */
function isOwner(input: ManagedNextInput): boolean {
  return input.online?.kind === "personal";
}

function what(input: ManagedNextInput): string {
  return input.kind === "section" ? "This settings section" : "This page";
}

/** The place the levels are chosen, in words (the label, and where it is). */
function placeWords(input: ManagedNextInput): string {
  const label = input.online?.visibility.label || "Settings > Developer dashboards";
  return isOwner(input) ? `${label} on your personal dashboard` : label;
}

/** Who can change it on a team machine: the published contact, else the admins. */
function adminPhrase(input: ManagedNextInput): string {
  if (input.contact) return `Your administrator (${input.contact})`;
  return input.orgLabel === "your organization" ? "Your organization's administrators" : `The administrators of ${input.orgLabel}`;
}

type LinkRule = {
  key: string;
  when: (input: ManagedNextInput) => boolean;
  link: (input: ManagedNextInput) => NextLink;
};

/**
 * LINK_RULES: the next steps, in the order they render. A rule whose `when`
 * holds adds its link.
 */
export const LINK_RULES: readonly LinkRule[] = [
  {
    // The same page on the online dashboard, where the person can open it.
    key: "online-page",
    when: (i) => i.kind === "page" && onlinePageFor(i.online, i.navId) != null,
    link: (i) => {
      const page = onlinePageFor(i.online, i.navId)!;
      return { key: "online-page", href: page.href, label: `Open ${page.label} online`, external: true };
    },
  },
  {
    // The owner changes the level themselves, on their personal dashboard.
    key: "developer-dashboards",
    when: (i) => isOwner(i) && onlineHref(i.online?.visibility.href) != null,
    link: (i) => ({
      key: "developer-dashboards",
      href: onlineHref(i.online?.visibility.href)!,
      label: `Open ${i.online?.visibility.label || "Settings > Developer dashboards"}`,
      external: true,
    }),
  },
  {
    // The owner's dashboard address is unknown here: Settings > Account shows
    // where this machine is connected and opens that dashboard.
    key: "account",
    when: (i) => isOwner(i) && onlineHref(i.online?.visibility.href) == null,
    link: () => ({ key: "account", href: "/settings?section=enrolment", label: "Open Settings > Account", external: false }),
  },
  {
    // A team member asks for a hidden page (T-435): shown read-only until the
    // grant ends.
    key: "request",
    when: (i) => !isOwner(i) && i.level === "hidden" && i.kind === "page" && !!i.navId,
    link: (i) => ({ key: "request", href: pageRequestLink(i.navId), label: "Request access", external: false }),
  },
  {
    // A team member writes to the admins (D-695).
    key: "message",
    when: (i) => !isOwner(i),
    link: () => ({ key: "message", href: "/messages", label: "Message your administrator", external: false }),
  },
  {
    key: "contact",
    when: (i) => !isOwner(i) && !!i.contact,
    link: (i) => ({ key: "contact", href: `mailto:${i.contact}`, label: `Email ${i.contact}`, external: true }),
  },
  {
    key: "policy",
    when: (i) => onlineHref(i.policyUrl) != null,
    link: (i) => ({ key: "policy", href: onlineHref(i.policyUrl)!, label: "Read the policy", external: true }),
  },
];

/** managedNext is the notice for one hidden or read-only page or section. */
export function managedNext(input: ManagedNextInput): ManagedNext {
  const links = LINK_RULES.filter((r) => r.when(input)).map((r) => r.link(input));
  const subject = what(input);
  const lower = subject.charAt(0).toLowerCase() + subject.slice(1);
  if (isOwner(input)) {
    const where = placeWords(input);
    return input.level === "hidden"
      ? {
          title: "Hidden on this machine",
          body: `${subject} is hidden on this machine by a setting on your personal dashboard. You are its owner, so you can show it again in ${where}.`,
          links,
        }
      : {
          title: "Read-only on this machine",
          body: `${subject} is read-only on this machine by a setting on your personal dashboard. You are its owner, so you can turn editing back on in ${where}.`,
          links,
        };
  }
  if (input.level === "hidden") {
    const def = input.byDefault ? " It is hidden by default on organization-managed machines." : "";
    return {
      title: "Managed by your organization",
      body: `${subject} is managed by ${input.orgLabel} and is not available on this machine.${def} ${adminPhrase(input)} can make it available.`,
      links,
    };
  }
  return {
    title: "Read-only on this machine",
    body: `${input.orgLabel.charAt(0).toUpperCase()}${input.orgLabel.slice(1)} manages ${lower}. You can see everything here, but changes are turned off. ${adminPhrase(input)} can turn editing on.`,
    links,
  };
}
