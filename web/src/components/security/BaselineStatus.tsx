// BaselineStatus.tsx: the project's baseline line on the Code security
// page's Baselines tab, with the "approved by the org" label the CLI and
// the API already show (lane LEFT2-SEC item R-023). Pure: it renders what
// lib/codeSecurityExceptions.ts says and fetches nothing.

import { baselineOrgLabel, baselineStatusLine, type BaselineView } from "@/lib/codeSecurityExceptions";

/** BaselineStatus is the baseline line and, when the org approved the same
 *  reference, its label. */
export function BaselineStatus({ current }: { current: BaselineView["current"] }) {
  const org = baselineOrgLabel(current);
  return (
    <>
      <p className="m-0 text-fg-2" data-testid="baseline-status">
        {baselineStatusLine(current)}
      </p>
      {org && (
        <p className="m-0 text-fg-3" data-testid="baseline-org-label">
          {org}
        </p>
      )}
    </>
  );
}
