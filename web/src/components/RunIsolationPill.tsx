// RunIsolationPill is the run pill on a terminal's header (sandbox plan v2
// section 9): what the run was actually launched in, from its recorded
// evidence. A key-on run that Observer's syscall filter could not reach
// (seccomp not_applicable, audit N2-A9 / FU4-A2) is shown in the warning
// tone with the reason in its title, so a dashboard launch says so, the way
// the CLI launch line does.

import type { LaunchIsolation } from "@/lib/types";
import { runPillLabel, seccompNotFiltered } from "@/lib/sandboxIsolation";

/** SECCOMP_NOT_FILTERED_TITLE is the pill title's sentence for not_applicable. */
export const SECCOMP_NOT_FILTERED_TITLE =
  "The syscall filter (seccomp) is on, but Observer's filter does not run on this backend and no engine filter is grounded: this run is not filtered by Observer.";

export function RunIsolationPill({ isolation, truncate }: { isolation?: LaunchIsolation; truncate?: boolean }) {
  const label = runPillLabel(isolation);
  if (!label) return null;
  const warn = seccompNotFiltered(isolation);
  const title = `Sandboxed: ${label}` + (warn ? `. ${SECCOMP_NOT_FILTERED_TITLE}` : "");
  return (
    <span
      className={
        "rounded-pill border px-1.5 py-px text-[10px] " +
        (warn ? "border-warn/40 text-warn" : "text-fg-2") +
        (truncate ? " min-w-0 truncate" : "")
      }
      title={title}
      data-seccomp={isolation?.seccomp || undefined}
    >
      {label}
    </span>
  );
}
