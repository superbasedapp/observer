import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { securityNoticeLine, type SecurityOrgNotice as Notice } from "@/lib/securityOrgNotice";

// SecurityOrgNotice is the affected-worker notice (security plan 7.12, lane
// SEC-E3): while an organization security floor is in force on this machine
// or code security findings are shared with the organization, a slim strip
// under the TopBar says what is shared, the purpose the organization stated
// and, under ruling P-089, what the organization's views can see under its
// current settings (information, not a privacy promise); the line "Not for
// evaluating individual employees' performance" appears only when the
// organization chose to show it. It reads GET /api/security/org-notice (never hidden by the
// org's page governance) once on mount and renders nothing while inactive.
// "Details" folds the list open; there is no dismiss, because the notice is
// the organization's information duty, not a passing message.
export function SecurityOrgNotice() {
  const q = useApi<Notice>("/api/security/org-notice", undefined, []);
  const [open, setOpen] = useState(false);
  const n = q.data;
  if (!n || !n.active) return null;
  return (
    <div role="note" data-testid="security-org-notice" className="border-b border-line-2 bg-bg-2 px-4 py-1.5 text-[11.5px] text-fg-2">
      <div className="flex items-center gap-2">
        <span className="font-semibold text-fg-1">Shared with your organization</span>
        <span className="min-w-0 truncate">{securityNoticeLine(n)}</span>
        <div className="flex-1" />
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          className="shrink-0 rounded-2 border border-line-2 bg-bg-1 px-2 py-0.5 text-fg-2 hover:bg-bg-3"
        >
          {open ? "Hide details" : "Details"}
        </button>
      </div>
      {open && (
        <ul className="mt-1 list-disc pl-5">
          {n.shared.map((line) => (
            <li key={line}>{line}</li>
          ))}
          {(n.org_sees ?? []).map((line) => (
            <li key={line}>{line}</li>
          ))}
          {n.not_for && <li>{n.not_for}.</li>}
        </ul>
      )}
    </div>
  );
}
