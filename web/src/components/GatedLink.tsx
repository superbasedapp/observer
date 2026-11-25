import type { ReactNode } from "react";
import { Link, type LinkProps } from "react-router-dom";
import { useHrefGate, useOnlineEquivalent } from "@/lib/governance";

/** MANAGED_LINK_TEXT: what a link to a place this machine does not show
 *  reads instead (CG-21). */
export const MANAGED_LINK_TEXT = "Managed by your organization";

/**
 * GatedLink is a router Link to a page, Settings section or page tab that an
 * organization may hide on a managed machine (CG-20/CG-21). Where the target
 * is shown it is an ordinary Link. Where the target is hidden it goes to the
 * page's equivalent on the online dashboard instead, in a new tab, when there
 * is one the person may open (operator ruling 2, 2026-11-24:
 * lib/visibility.ts onlinePageFor); otherwise it renders `managed` (by
 * default the note "Managed by your organization") instead of a link that
 * would land on a notice. While the posture is still unknown it renders the
 * label as plain text, making no claim either way. `managed={null}` (an
 * action with no place in the sentence around it) renders nothing in both of
 * those cases.
 */
export function GatedLink({
  to,
  managed,
  className,
  children,
  ...rest
}: Omit<LinkProps, "to"> & { to: string; managed?: ReactNode }) {
  const gate = useHrefGate()(to);
  const online = useOnlineEquivalent()(to);
  if (gate === "shown") {
    return (
      <Link to={to} className={className} {...rest}>
        {children}
      </Link>
    );
  }
  if (gate === "managed" && online) {
    return (
      <a
        href={online.href}
        target="_blank"
        rel="noreferrer"
        className={className}
        title={`Hidden on this machine: opens ${online.label} on the online dashboard`}
        data-testid="managed-link-online"
      >
        {children}
      </a>
    );
  }
  if (managed === null) return null;
  if (gate === "unresolved") return <span className="text-fg-3">{children}</span>;
  return (
    <span className="text-fg-3" data-testid="managed-link">
      {managed ?? MANAGED_LINK_TEXT}
    </span>
  );
}
