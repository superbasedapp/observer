import type { ReactNode } from "react";
import { Link, type LinkProps } from "react-router-dom";
import { useHrefGate } from "@/lib/governance";

/** MANAGED_LINK_TEXT: what a link to a place this machine does not show
 *  reads instead (CG-21). */
export const MANAGED_LINK_TEXT = "Managed by your organization";

/**
 * GatedLink is a router Link to a page, Settings section or page tab that an
 * organization may hide on a managed machine (CG-20/CG-21). Where the target
 * is shown it is an ordinary Link. Where the target is hidden it renders
 * `managed` (by default the note "Managed by your organization") instead of a
 * link that would land on a notice. While the posture is still unknown it
 * renders the label as plain text, making no claim either way.
 * `managed={null}` (an action with no place in the sentence around it)
 * renders nothing in both of those cases.
 */
export function GatedLink({
  to,
  managed,
  className,
  children,
  ...rest
}: Omit<LinkProps, "to"> & { to: string; managed?: ReactNode }) {
  const gate = useHrefGate()(to);
  if (gate === "shown") {
    return (
      <Link to={to} className={className} {...rest}>
        {children}
      </Link>
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
