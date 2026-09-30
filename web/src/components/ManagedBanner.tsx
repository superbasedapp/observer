import { Link } from "react-router-dom";
import {
  governedOrgLabel,
  isManaged,
  type Governance,
} from "@/lib/governance";

// ManagedBanner — the T8 developer-transparency floor for Enterprise-Managed
// Tenancy. When this machine enrolled managed, a persistent, NON-dismissable
// strip says so and names the org, so the developer always knows the machine
// is under comprehensive org control and where to see exactly what is shared
// and enforced (the Privacy page, an unhideable section). It is state
// disclosure, not a notification: there is deliberately no dismiss control,
// and managed policy can never hide it (it lives in the always-mounted shell,
// not a governed nav section).
//
// Renders nothing on an individual / BYO node — the default — so an
// unmanaged machine's shell is byte-for-byte unchanged.
export function ManagedBanner({ gov }: { gov: Governance | null }) {
  if (!isManaged(gov)) return null;
  return (
    <div className="flex items-center gap-2 border-b border-warn/40 bg-warn-soft px-4 py-1.5 text-[11.5px] text-fg-2">
      <span className="shrink-0 font-semibold text-warn">Managed</span>
      <span className="min-w-0 truncate">
        This machine is managed by {governedOrgLabel(gov)}. Your organization
        can extract activity and enforce policy here.
      </span>
      <div className="flex-1" />
      <Link
        to="/privacy"
        className="shrink-0 rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-fg-2 hover:bg-bg-3"
      >
        What is shared
      </Link>
    </div>
  );
}
