import { useState } from "react";
import { Button, Pill, Select, SlideOver } from "@/components/primitives";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { ChartState } from "@/components/ChartState";
import { ExplainButton } from "@/components/security/ExplainButton";
import { useApi } from "@/lib/useApi";
import { useHrefGate } from "@/lib/governance";
import { fmtRelative } from "@/lib/format";
import {
  commitHref,
  findingWhereDetail,
  heldApproveHref,
  projectHref,
  reasonWords,
  SECURITY_VERDICTS_HREF,
  sessionHref,
  type SecurityFinding,
  type SecurityFindingDetail,
} from "@/lib/codeSecurity";
import {
  exceptionGrantBody,
  exceptionStateLabel,
  pickerLabel,
  securityPost,
  type ExceptionsResponse,
} from "@/lib/codeSecurityExceptions";
import { toneOf } from "../../../../shared/lib/tone";
import { pushToast } from "@/components/Toast";
import { NodeLink } from "./NodeLink";
import { DependencyRows, DependencySections, DependencySignalRows } from "./DependencyDetail";
import { SEVERITY_TONE } from "./ProjectsCard";
import { FixButton } from "./FixButton";

// FindingDrawer is one finding's detail (GET /api/security/findings/{id}),
// opened from a Findings row and addressed by `?finding=<id>`: what fired
// and where, the project, scanner, session and commits it links to, the
// files it is sighted in, its lifecycle and its exceptions, with Except and
// Explain as the drawer's actions. Never secret evidence: the redacted
// excerpt stays with Explain. A dependency finding additionally shows the
// package, the lockfile lines and the advisory detail read from the local
// OSV database at view time, and its reachability tier and exploit labels
// (KEV, EPSS with FIRST's citation) beside the package (DependencyDetail).
// An open finding that holds commits links to where such a commit or push is
// approved, its verdict on Security > Verdicts (the drawer itself has no
// approve; dashboard CLI parity plan B-CS7).

/** ExceptForm is the "Except" form: pickers only, nothing typed. */
function ExceptForm({
  finding,
  pickers,
  onDone,
  onCancel,
}: {
  finding: SecurityFinding;
  pickers: ExceptionsResponse;
  onDone: () => void;
  onCancel: () => void;
}) {
  const [reason, setReason] = useState(pickers.reasons[0]?.id ?? "");
  const [expiry, setExpiry] = useState(pickers.expiries[0]?.id ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  async function save() {
    const body = exceptionGrantBody(finding.id, reason, expiry, pickers);
    if (!body) return;
    setBusy(true);
    setErr(null);
    try {
      await securityPost("/api/security/exceptions", pickers.confirm_token, body);
      pushToast("Finding excepted", "success");
      onDone();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="grid gap-2 rounded-2 border border-line-2 bg-bg-2 p-3" data-testid={`code-security-except-${finding.id}`}>
      <p className="m-0 text-small text-fg-3">
        Excepts this one finding in this project. The rule keeps firing everywhere else, and the finding comes back when
        the exception ends.
      </p>
      <Select
        label="Reason"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        options={pickers.reasons.map((r) => ({ value: r.id, label: r.label }))}
      />
      <Select
        label="Until"
        value={expiry}
        onChange={(e) => setExpiry(e.target.value)}
        options={pickers.expiries.map((x) => ({ value: x.id, label: x.label }))}
      />
      <div className="flex gap-2">
        <Button size="sm" variant="primary" disabled={busy} loading={busy} onClick={() => void save()}>
          Except this finding
        </Button>
        <Button size="sm" variant="ghost" disabled={busy} onClick={onCancel}>
          Cancel
        </Button>
      </div>
      {err && <p className="m-0 text-danger">{err}</p>}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-1.5">
      <h3 className="m-0 text-[11px] font-medium uppercase tracking-wide text-fg-3">{title}</h3>
      {children}
    </section>
  );
}

export function FindingDrawer({
  id,
  onClose,
  pickers,
  explainSelected,
  onChanged,
  onFix,
}: {
  id: string | null;
  onClose: () => void;
  pickers: ExceptionsResponse | null;
  explainSelected: readonly string[] | null | undefined;
  onChanged: () => void;
  /** "Fix with an agent" for an open finding (absent: no button). */
  onFix?: (id: string) => void;
}) {
  const detail = useApi<SecurityFindingDetail>(id ? `/api/security/findings/${encodeURIComponent(id)}` : null, undefined, [id]);
  const [excepting, setExcepting] = useState(false);
  const d = detail.data;
  const f = d?.finding;
  const pid = d?.project?.id;
  // Security (where a held commit is approved) is hidden by default on a
  // managed machine, while an org may expose this page (CG-21): say so rather
  // than link to the managed notice.
  const hrefGate = useHrefGate();
  return (
    <SlideOver
      open={id != null}
      onClose={() => {
        setExcepting(false);
        onClose();
      }}
      width={640}
      title={f ? <span className="font-mono">{f.rule_id}</span> : "Finding"}
      subtitle={f?.message}
      bodyClassName="p-5"
      footer={
        f && (pickers || (onFix && f.status === "open")) ? (
          <div className="flex flex-wrap items-center gap-2">
            {onFix && f.status === "open" && <FixButton onClick={() => onFix(f.id)} testId="code-security-fix-drawer" />}
            {pickers && f.status === "open" && !excepting && (
              <Button size="sm" variant="secondary" onClick={() => setExcepting(true)}>
                Except...
              </Button>
            )}
            {pickers && <ExplainButton findingId={f.id} token={pickers.confirm_token} selected={explainSelected} />}
          </div>
        ) : undefined
      }
    >
      <ChartState
        kind="table"
        loading={detail.loading && !d}
        error={detail.error}
        denied={detail.denied}
        onRetry={detail.reload}
        empty={false}
        emptyHint=""
      >
        {f && d ? (
          <div className="space-y-5 text-[12.5px]" data-testid="code-security-finding-drawer">
            <div className="flex flex-wrap gap-1.5">
              <Pill variant={toneOf(SEVERITY_TONE, f.severity)}>{f.severity}</Pill>
              <Pill variant="neutral">{reasonWords(f.category)}</Pill>
              <Pill variant={f.status === "open" ? "warn" : "neutral"}>{reasonWords(f.status)}</Pill>
              <Pill variant="neutral">{`confidence ${f.confidence}`}</Pill>
              <Pill variant="neutral">{`baseline: ${reasonWords(f.baseline)}`}</Pill>
            </div>
            {excepting && pickers && (
              <ExceptForm
                finding={f}
                pickers={pickers}
                onCancel={() => setExcepting(false)}
                onDone={() => {
                  setExcepting(false);
                  detail.reload();
                  onChanged();
                }}
              />
            )}
            <DefinitionList>
              <DefinitionRow
                label="Project"
                value={
                  d.project ? (
                    <NodeLink to={projectHref(d.project.id)} variant="text" title={d.project.root_path}>
                      {d.project.name}
                    </NodeLink>
                  ) : (
                    "Unknown project"
                  )
                }
              />
              {d.dependency && <DependencyRows dep={d.dependency} />}
              <DependencySignalRows finding={f} />
              <DefinitionRow label="Where" value={<span className="break-all font-mono">{findingWhereDetail(d)}</span>} />
              <DefinitionRow
                label="Scanner"
                value={`${f.driver || "unknown"}${d.driver_version ? ` ${d.driver_version}` : ""}${d.rule_pack ? ` (${d.rule_pack})` : ""}`}
              />
              <DefinitionRow label="Found by" value={reasonWords(f.scope) || "unknown"} />
              <DefinitionRow
                label="Session"
                value={
                  f.session_id ? (
                    <NodeLink to={sessionHref(f.session_id)} title={f.session_id}>
                      {f.session_id.slice(0, 12)}
                    </NodeLink>
                  ) : (
                    "none attributed"
                  )
                }
              />
              {(f.tool || d.model) && (
                <DefinitionRow label="Agent" value={[f.tool, d.model].filter(Boolean).join(" / ")} />
              )}
              <DefinitionRow label="First seen" value={fmtRelative(f.first_seen)} />
              <DefinitionRow label="Last seen" value={fmtRelative(f.last_seen)} />
              {d.closed_at && <DefinitionRow label="Closed" value={fmtRelative(d.closed_at)} />}
            </DefinitionList>
            {d.fix_hint && (
              <Section title="How to fix">
                <p className="m-0 text-fg-1">{d.fix_hint}</p>
              </Section>
            )}
            <DependencySections detail={d} />
            {d.sightings.length > 0 && (
              <Section title={`Sighted in ${d.sightings.length} file(s)`}>
                <ul className="m-0 list-none space-y-0.5 p-0 font-mono text-[11.5px] text-fg-2">
                  {d.sightings.map((p) => (
                    <li key={p}>{p}</li>
                  ))}
                </ul>
              </Section>
            )}
            {d.commits.length > 0 && (
              <Section title={`Held by ${d.commits.length} commit(s)`}>
                <ul className="m-0 list-none space-y-1 p-0">
                  {d.commits.map((c) => (
                    <li key={c.sha} className="flex flex-wrap items-center gap-2">
                      <NodeLink to={commitHref(pid, c.sha)} title={c.sha}>
                        {c.sha.slice(0, 7)}
                      </NodeLink>
                      <span className="text-fg-3">{fmtRelative(c.last_seen)}</span>
                      {(c.remotes ?? []).length > 0 && <Pill variant="danger">{`reached ${c.remotes?.join(", ")}`}</Pill>}
                    </li>
                  ))}
                </ul>
                {heldApproveHref(f, d.commits) && (
                  <p className="m-0 text-fg-3" data-testid="finding-approve-pointer">
                    {"A commit or push this finding holds is approved from its verdict, not here. "}
                    {hrefGate(SECURITY_VERDICTS_HREF) === "managed" ? (
                      "Approving it is managed by your organization."
                    ) : (
                      <NodeLink to={heldApproveHref(f, d.commits)} variant="text">
                        Approve in Security
                      </NodeLink>
                    )}
                  </p>
                )}
              </Section>
            )}
            {d.exceptions.length > 0 && (
              <Section title="Exceptions">
                <ul className="m-0 list-none space-y-1 p-0 text-fg-2">
                  {d.exceptions.map((e) => (
                    <li key={e.id}>
                      {pickerLabel(pickers?.reasons ?? [], e.reason)}, until {e.expires_at.slice(0, 10)}: {exceptionStateLabel(e)}
                    </li>
                  ))}
                </ul>
              </Section>
            )}
            {d.events.length > 0 && (
              <Section title="History">
                <ol className="m-0 list-none space-y-1 p-0">
                  {d.events.map((e, i) => (
                    <li key={`${e.at}-${i}`} className="flex gap-3">
                      <span className="w-28 shrink-0 text-fg-3">{fmtRelative(e.at)}</span>
                      <span className="text-fg-1">{reasonWords(e.kind)}</span>
                      {e.detail && <span className="min-w-0 truncate text-fg-3">{reasonWords(e.detail)}</span>}
                    </li>
                  ))}
                </ol>
              </Section>
            )}
          </div>
        ) : null}
      </ChartState>
    </SlideOver>
  );
}
