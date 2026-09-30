import clsx from "clsx";
import type { ReactNode } from "react";
import { HOST_MARKS, IDP_MARKS } from "../lib/brandMarks";
import { hostIdFor, idpIdFor } from "../lib/brandMarkIds";

// HostMark / IdpMark — the serving-host and identity-provider logos from the
// generated brand-mark tables, painted in currentColor on a 24px grid. Pass
// either a closed id or the raw API string; an unresolvable value renders
// NOTHING (unknown means unknown - never a guessed vendor). Brand marks are
// not UI icons: they never go through <Icon>.

function Mark({ children, size, className, label }: { children: ReactNode; size: number; className?: string; label?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      fillRule="evenodd"
      className={clsx("shrink-0", className)}
      aria-hidden={label ? undefined : true}
      aria-label={label}
      role={label ? "img" : undefined}
    >
      {children}
    </svg>
  );
}

export function HostMark({
  host,
  size = 14,
  className,
  label,
}: {
  /** A HostId or any provider / upstream string (resolved by hostIdFor). */
  host: string | null | undefined;
  size?: number;
  className?: string;
  label?: string;
}) {
  const id = hostIdFor(host);
  if (!id) return null;
  return (
    <Mark size={size} className={className} label={label}>
      {HOST_MARKS[id]}
    </Mark>
  );
}

export function IdpMark({
  idp,
  size = 16,
  className,
  label,
}: {
  /** An IdpId or any rail / preset string (resolved by idpIdFor). */
  idp: string | null | undefined;
  size?: number;
  className?: string;
  label?: string;
}) {
  const id = idpIdFor(idp);
  if (!id) return null;
  return (
    <Mark size={size} className={className} label={label}>
      {IDP_MARKS[id]}
    </Mark>
  );
}
