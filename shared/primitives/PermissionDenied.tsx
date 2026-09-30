import clsx from "clsx";
import { Link } from "react-router-dom";
import { Eye, Lock } from "lucide-react";
import { Icon } from "./Icon";
import { EmptyIllustration } from "./EmptyIllustration";

// PermissionDenied: RBAC denial is a distinct state, not an error. A 403
// used to render exactly like a network failure; this names the missing
// permission key and points at where access is granted. `accessTo` is the
// app's own route for that (the org dashboard passes its People & Access
// page); shared code never assumes a route.
export function PermissionDenied({
  permission,
  title = "You don't have access to this",
  body,
  accessTo,
  accessLabel = "People & Access",
  variant = "page",
  className,
}: {
  /** The missing permission key, e.g. "read:content". */
  permission?: string | null;
  title?: string;
  body?: React.ReactNode;
  accessTo?: string;
  accessLabel?: string;
  variant?: "page" | "inline";
  className?: string;
}) {
  const page = variant === "page";
  return (
    <div
      className={clsx(
        "sb-scale-in mx-auto flex max-w-md flex-col items-center gap-2 text-center",
        page ? "py-10" : "py-5",
        className,
      )}
    >
      <EmptyIllustration kind="locked" size={page ? 160 : 110} />
      <h3 className="text-[14px] font-semibold text-fg-0">{title}</h3>
      <p className="text-[12.5px] leading-relaxed text-fg-3">
        {body ??
          (permission ? (
            <>
              This needs the <code className="font-mono text-fg-2">{permission}</code> permission. An
              admin can grant it.
            </>
          ) : (
            "Your role does not include this. An admin can grant it."
          ))}
      </p>
      {accessTo && (
        <Link
          to={accessTo}
          className="mt-1 text-[12px] font-medium text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent"
        >
          {accessLabel}
        </Link>
      )}
    </div>
  );
}

// ReadOnlyBanner: the one "you can look but not change" strip, replacing the
// inconsistent read-only treatments. Names what write access needs.
export function ReadOnlyBanner({
  requires,
  children,
  accessTo,
  accessLabel = "People & Access",
  className,
}: {
  /** The permission key that would allow edits, e.g. "write:pricing". */
  requires?: string | null;
  /** Overrides the default sentence. */
  children?: React.ReactNode;
  accessTo?: string;
  accessLabel?: string;
  className?: string;
}) {
  return (
    <div
      role="note"
      className={clsx(
        "flex flex-wrap items-center gap-2 rounded-2 border border-line-2 bg-bg-3 px-3 py-2 text-[12px] text-fg-2",
        className,
      )}
    >
      <span className="inline-flex items-center gap-1 font-medium text-fg-1">
        <Icon icon={Lock} size="xs" className="text-fg-3" />
        <Icon icon={Eye} size="xs" className="text-fg-3" />
        Read-only
      </span>
      <span className="min-w-0 flex-1">
        {children ??
          (requires ? (
            <>
              Editing needs <code className="font-mono text-fg-1">{requires}</code>.
            </>
          ) : (
            "You can view this but not change it."
          ))}
      </span>
      {accessTo && (
        <Link to={accessTo} className="text-[12px] font-medium text-accent hover:underline">
          {accessLabel}
        </Link>
      )}
    </div>
  );
}
