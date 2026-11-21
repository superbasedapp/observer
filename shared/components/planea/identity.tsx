import { TooltipSpan } from "../../primitives/Tooltip";
import type { EndUserState, PlaneATraceIdentity } from "./types";

// The hosted app's identity cells (promoted from web2/src/pages/obs/identity.tsx,
// B5-0; web2 keeps a re-export shim). The identity type is declared in
// ./types (structurally equal to web2 lib/api.ts ObsTraceIdentity, which
// ObsTraceListRow and ObsSessionRow extend).
export type { EndUserState };
export type ObsTraceIdentity = PlaneATraceIdentity;

// identityOf reads the optional identity fields off any trace/session row.
export function identityOf(row: object): ObsTraceIdentity {
  return row as ObsTraceIdentity;
}

// endUserLabel: the raw end user, else a short hash label, else null (no end
// user reported, e.g. a row from a node that predates the identity contract).
export function endUserLabel(id: ObsTraceIdentity): string | null {
  if (id.end_user) return id.end_user;
  if (id.end_user_hash) return `end user ${id.end_user_hash.slice(0, 12)}`;
  return null;
}

// emptyEndUser explains an empty end user by its server-side state.
const emptyEndUser: Record<EndUserState, { text: string; why: string } | null> = {
  present: null,
  none: null,
  not_shared: {
    text: "not shared",
    why: "The source withheld the end user: a metadata-only node, or the gateway below the full capture level. Nothing about the end user reached the org.",
  },
  unknown: {
    text: "not shared or none",
    why: "Either the trace named no end user or its source withheld it; this row does not say which.",
  },
};

// EndUserCell renders the app's end user; a hash-only value is muted and
// explains why the raw value is absent; an empty one says whether it was
// not shared or simply absent.
export function EndUserCell({ row }: { row: object }) {
  const id = identityOf(row);
  const label = endUserLabel(id);
  if (!label) {
    const empty = id.end_user_state ? emptyEndUser[id.end_user_state] : null;
    if (empty) {
      return (
        <TooltipSpan className="text-[11px] italic text-fg-4" content={empty.why}>
          {empty.text}
        </TooltipSpan>
      );
    }
    return <span className="text-[12px] text-fg-4">-</span>;
  }
  if (!id.end_user) {
    return (
      <TooltipSpan
        className="inline-block max-w-[110px] truncate align-bottom font-mono text-[11px] text-fg-3"
        content="Pseudonymous end-user id: you need the read:content permission to see the raw end user."
      >
        {label}
      </TooltipSpan>
    );
  }
  return (
    <span className="inline-block max-w-[110px] truncate align-bottom text-[12px] text-fg-2" title={label}>
      {label}
    </span>
  );
}

// ServiceCell renders the app's service with its environment and release.
export function ServiceCell({ row }: { row: object }) {
  const id = identityOf(row);
  if (!id.service && !id.environment && !id.release) return <span className="text-[12px] text-fg-4">-</span>;
  const detail = [id.environment, id.release].filter(Boolean).join(" · ");
  const title = [id.service && `service ${id.service}`, id.environment && `environment ${id.environment}`, id.release && `release ${id.release}`]
    .filter(Boolean)
    .join(", ");
  return (
    <span className="inline-flex max-w-[170px] items-baseline gap-1.5 truncate align-bottom" title={title}>
      <span className="truncate text-[12px] text-fg-1">{id.service || "(no service)"}</span>
      {detail && <span className="truncate text-[11px] text-fg-3">{detail}</span>}
    </span>
  );
}
