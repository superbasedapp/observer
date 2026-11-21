import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { Button, Card, Pill } from "@/components/primitives";
import { HelpInd, TitleWithHelp } from "@/components/HelpInd";
import { useApi } from "@/lib/useApi";
import { apiReason } from "@/lib/api";
import { fmtRelative } from "@/lib/format";
import { toolMeta } from "@/lib/tools";
import {
  FIX_ATTEMPTS_PATH,
  fixAttemptBreakdown,
  fixAttemptStatus,
  fixAttemptSummary,
  fixAttemptsPolling,
  type FixAttempt,
  type FixAttemptsResponse,
} from "@/lib/securityFix";

// FixAttemptsPanel is the Findings tab's list of recent "Fix with an agent"
// launches (plan docs/plans/fix-findings-with-agent-plan-2026-11-13.md
// section 6): the agent, the project, when, and the CURRENT state of the
// findings each attempt was given, read live from the findings themselves.
// A rescan decides: "Rescan project" starts the page's own scan job for
// that one project. The attempt never changes a finding.
//
// Compact (one line) while there are none; hidden when the route is not
// installed (Code security compiled out, or a daemon without the route).
// Refreshes every 30 s while any attempt still has an open finding.

const POLL_MS = 30_000;
// Rule ids shown per attempt before "+N more".
const RULES_SHOWN = 6;

function AttemptRow({ a, onRescan, scanning }: { a: FixAttempt; onRescan?: (hash: string) => void; scanning?: boolean }) {
  const shown = a.findings.slice(0, RULES_SHOWN);
  const more = a.findings.length - shown.length;
  return (
    <li className="flex flex-wrap items-start justify-between gap-2 border-b border-line-1 py-2 last:border-b-0" data-testid="code-security-fix-attempt">
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium text-fg-1">{toolMeta(a.tool).label}</span>
          <span className="text-fg-2">{a.project_name || "Unknown project"}</span>
          <span className="text-fg-3">{fmtRelative(a.created_at)}</span>
          <Pill variant={a.cleared ? "success" : "warn"} case="none">{fixAttemptSummary(a)}</Pill>
          {!a.seeded && <span className="text-[11px] text-fg-3">task pasted by hand</span>}
        </div>
        {a.findings.length > 0 && (
          <>
            <div className="text-[11.5px] text-fg-3">{fixAttemptBreakdown(a.findings)}</div>
            <div className="flex flex-wrap gap-1">
              {shown.map((f) => {
                const s = fixAttemptStatus(f.status);
                return (
                  <Pill key={f.id} variant={s.tone} case="none" title={`${f.rule_id}: ${s.label}`}>
                    <span className="font-mono">{f.rule_id}</span>
                  </Pill>
                );
              })}
              {more > 0 && <span className="text-[11px] text-fg-3">{`+${more} more`}</span>}
            </div>
          </>
        )}
      </div>
      {onRescan && (
        <Button
          size="sm"
          variant="secondary"
          iconLeft={RefreshCw}
          disabled={scanning || !a.project_root_hash}
          title={scanning ? "A scan is running" : undefined}
          onClick={() => onRescan(a.project_root_hash)}
        >
          Rescan project
        </Button>
      )}
    </li>
  );
}

export function FixAttemptsPanel({ onRescan, scanning }: { onRescan?: (hash: string) => void; scanning?: boolean }) {
  const [polling, setPolling] = useState(false);
  const read = useApi<FixAttemptsResponse>(FIX_ATTEMPTS_PATH, undefined, [], { refreshMs: polling ? POLL_MS : 0 });
  useEffect(() => setPolling(fixAttemptsPolling(read.data)), [read.data]);

  // Not installed (or a daemon without the route): nothing to show.
  if (read.notInstalled || read.status === 404) return null;
  if (read.loading && !read.data) return null;
  if (read.error && !read.data) {
    return (
      <p className="m-0 text-[11.5px] text-fg-3" data-testid="code-security-fix-attempts">
        {`Fix attempts could not be read: ${apiReason(read.error)}`}
      </p>
    );
  }
  const attempts = read.data?.attempts ?? [];
  if (attempts.length === 0) {
    return (
      <p className="m-0 flex items-center text-[11.5px] text-fg-3" data-testid="code-security-fix-attempts">
        No fix attempts yet. Use Fix with an agent on a finding, a group or the filtered list.
        <HelpInd id="card.code_security_fix_attempts" />
      </p>
    );
  }
  return (
    <Card
      title={<TitleWithHelp text="Fix attempts" helpId="card.code_security_fix_attempts" />}
      sub="Agents started on findings, and whether those findings cleared on the latest scan."
      stale={read.isStale}
    >
      <ul className="m-0 list-none p-0 text-[12.5px]" data-testid="code-security-fix-attempts">
        {attempts.map((a) => (
          <AttemptRow key={a.id} a={a} onRescan={onRescan} scanning={scanning} />
        ))}
      </ul>
    </Card>
  );
}
