import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import { Tooltip, idLinkClass } from "@/components/primitives";

// NodeLink renders a node-dashboard destination (a project's Projects-page
// detail, a session's drawer, a commit in the project drawer) as a link, or
// as plain text when there is no destination: never a dead link. variant
// "id" is the shared id-link look (mono, dotted underline); "text" is a
// name in prose accent. shared/lib/entityLinks.ts maps the ORG dashboard's
// routes (/projects/:id), which the node dashboard does not have, so the
// node's hrefs come from lib/codeSecurity.ts instead.
export function NodeLink({
  to,
  children,
  variant = "id",
  title,
  className,
}: {
  to: string | null;
  children: ReactNode;
  variant?: "id" | "text";
  title?: ReactNode;
  className?: string;
}) {
  const look =
    variant === "id"
      ? idLinkClass(className)
      : clsx("text-accent transition-colors hover:text-accent-strong hover:underline", className);
  const body = to ? (
    <Link to={to} className={look} onClick={(e) => e.stopPropagation()}>
      {children}
    </Link>
  ) : (
    <span className={clsx(variant === "id" && "font-mono text-[11px]", "text-fg-2", className)}>{children}</span>
  );
  return title ? <Tooltip content={title}>{body}</Tooltip> : body;
}
