import { useState } from "react";
import { Building2, RefreshCw, ScrollText, ShieldCheck } from "lucide-react";
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  InlineLoading,
  Pill,
  Table,
  TruncatedPath,
} from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { ORG_STATE_LABEL, ORG_STATE_TONE, formatValue, orgNotice, type OrgNotice, type OrgPolicyView } from "@/lib/agentConfig";
import { applyOrg, asCallError } from "./api";

// OrgTab: the organization's AI tool policy as this managed machine holds
// it (adapter config P6/P7), and what Observer did with each setting on
// each file. The server decides everything; this tab shows it. Short of a
// policy in force, it says which state the machine is in (orgNotice): not
// enrolled, enrolled but not managed (naming the org), managed with the
// grant not in force, or managed with no policy yet. Enforced
// settings are also marked "set by your organization" on the By tool tab,
// where the editor refuses them.

const ACCESS_LABEL: Record<string, string> = {
  read_only: "Read-only, except what your organization grants",
  editable: "You may edit everything your organization does not enforce",
};

const ON_DRIFT_LABEL: Record<string, string> = {
  reassert: "A changed value is put back and reported",
  report: "A changed value is reported, and left as you set it",
};

const SECRETS_LABEL: Record<string, string> = {
  warn: "Warn before saving a plaintext secret",
  refuse: "Refuse to save a plaintext secret",
  allow: "Allow plaintext secrets",
};

export function OrgTab({ confirmToken }: { confirmToken: string }) {
  const org = useApi<OrgPolicyView>("/api/agent-config/org");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ tone: "ok" | "err"; text: string } | null>(null);

  if (org.error && !org.data) return <ErrorState error={org.error} onRetry={org.reload} />;
  if (!org.data) return <InlineLoading label="Reading your organization's policy" />;
  const v = org.data;

  const notice = orgNotice(v);
  if (notice) return <OrgStatusNotice notice={notice} />;

  async function apply() {
    setBusy(true);
    setNote(null);
    try {
      const r = await applyOrg(confirmToken);
      setNote({
        tone: "ok",
        text: r.writes === 0 ? "Every setting already holds your organization's value." : `Applied: ${r.writes} file write${r.writes === 1 ? "" : "s"}.`,
      });
      org.reload();
    } catch (e) {
      setNote({ tone: "err", text: asCallError(e).message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card
        title="Your organization's AI tool policy"
        icon={Building2}
        sub={`Version ${v.version}${v.policies.length > 0 ? ` from ${v.policies.join(", ")}` : ""}. Observer applies it when it changes and checks it every minute.`}
        stale={org.isStale}
      >
        <dl className="grid gap-x-4 gap-y-2 text-[12px] sm:grid-cols-[max-content_1fr]">
          <dt className="text-fg-3">Your editing</dt>
          <dd className="text-fg-1">{ACCESS_LABEL[v.developer_access ?? ""] ?? v.developer_access}</dd>
          {v.grants.length > 0 && (
            <>
              <dt className="text-fg-3">Granted to you</dt>
              <dd className="flex min-w-0 flex-wrap gap-1">
                {v.grants.map((g) => (
                  <code key={g} className="break-all rounded-1 bg-bg-3 px-1 font-mono text-[11px] text-fg-2">
                    {g}
                  </code>
                ))}
              </dd>
            </>
          )}
          <dt className="text-fg-3">When a value changes</dt>
          <dd className="text-fg-1">{ON_DRIFT_LABEL[v.on_drift ?? ""] ?? v.on_drift}</dd>
          <dt className="text-fg-3">Plaintext secrets</dt>
          <dd className="text-fg-1">{SECRETS_LABEL[v.secrets_posture ?? ""] ?? v.secrets_posture}</dd>
          <dt className="text-fg-3">What your organization sees</dt>
          <dd className="text-fg-1">
            Every AI tool setting on this machine with its value, and every instructions, skills, agents, commands and rules
            file with its text, secrets scrubbed (when this machine shares full content).
          </dd>
        </dl>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Button variant="secondary" size="sm" iconLeft={RefreshCw} loading={busy} disabled={busy} onClick={apply}>
            Apply now
          </Button>
          {note && (
            <span role="status" className={note.tone === "ok" ? "text-[11.5px] text-success" : "text-[11.5px] text-danger"}>
              {note.text}
            </span>
          )}
        </div>
      </Card>

      {(v.instructions ?? []).length > 0 && (
        <Card
          title="Instructions your organization adds"
          icon={ScrollText}
          sub="Added as a marked block to each AI tool's own instruction file. Your text around the block is yours; the block itself is locked and put back if edited."
        >
          <ul className="space-y-2" aria-label="Organization instructions">
            {(v.instructions ?? []).map((ins) => (
              <li key={ins.project ?? ""} className="rounded-2 border border-line-1 p-2 text-[11.5px]">
                <div className="flex flex-wrap items-center gap-1.5">
                  <Pill case="none">{ins.project ? "one project" : "every project"}</Pill>
                  {ins.project && ins.placement === "shared" && (
                    <Pill variant="warn" case="none">
                      shared file, commits with the repo
                    </Pill>
                  )}
                  <span className="text-fg-4">{ins.policy}</span>
                </div>
                <p className="mt-1 line-clamp-4 whitespace-pre-wrap break-words text-fg-2">{ins.text}</p>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card
        title="Settings your organization sets"
        icon={ShieldCheck}
        sub={
          v.drifted > 0
            ? `${v.drifted} setting${v.drifted === 1 ? " no longer holds" : "s no longer hold"} your organization's value.`
            : "Enforced settings are locked in the editor. Defaults are a starting value."
        }
      >
        {v.rows.length === 0 ? (
          <p className="text-[11.5px] text-fg-3">Nothing has been applied yet. Use Apply now, or wait a minute.</p>
        ) : (
          <Table
            minWidth={720}
            head={
              <tr>
                <th className="px-2 py-1.5 text-left">Setting</th>
                <th className="px-2 py-1.5 text-left">Kind</th>
                <th className="px-2 py-1.5 text-left">State</th>
                <th className="px-2 py-1.5 text-left">File</th>
              </tr>
            }
          >
            {v.rows.map((r) => (
              <tr key={`${r.setting}|${r.file_id}|${r.project_root ?? ""}`} className="border-t border-line-1 align-top">
                <td className="max-w-[260px] px-2 py-1.5">
                  <code className="break-all font-mono text-[11.5px] text-fg-1">{r.setting}</code>
                  <div className="text-[10.5px] text-fg-4">{r.policy}</div>
                </td>
                <td className="whitespace-nowrap px-2 py-1.5">
                  <Pill variant={r.mode === "enforced" ? "info" : "neutral"} case="none">
                    {r.mode === "enforced" ? "enforced" : "default"}
                  </Pill>
                </td>
                <td className="px-2 py-1.5">
                  <Pill variant={ORG_STATE_TONE[r.state] ?? "neutral"} case="none" title={r.reason}>
                    {ORG_STATE_LABEL[r.state] ?? r.state}
                  </Pill>
                  {r.observed_secret && !r.observed_value ? (
                    <div className="mt-0.5 text-[10.5px] text-fg-4">Found a value that looks like a secret (hidden)</div>
                  ) : r.observed_value && r.drift ? (
                    <div className="mt-0.5 break-all text-[10.5px] text-fg-3">
                      Found <code className="font-mono">{formatValue(safeParse(r.observed_value))}</code>
                      {r.observed_secret && " (secrets hidden)"}
                    </div>
                  ) : null}
                  {r.drift_count > 0 && (
                    <div className="text-[10.5px] text-fg-4">
                      {r.drift_count} change{r.drift_count === 1 ? "" : "s"} in the last hour
                    </div>
                  )}
                </td>
                <td className="max-w-[300px] px-2 py-1.5 text-[11px]">
                  <span className="text-fg-2">{r.file_id}</span>
                  {r.project_root && <TruncatedPath value={r.project_root} className="font-mono text-[10.5px] text-fg-4" />}
                  {r.scope === "project_shared" && (
                    <div className="text-[10.5px] text-warn">shared project file, the change can be committed with the repo</div>
                  )}
                  {r.personal && <div className="text-[10.5px] text-fg-4">personal file; on a managed machine your organization sees its values (secrets scrubbed)</div>}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}

// OrgStatusNotice renders the tab's state when no policy is in force.
export function OrgStatusNotice({ notice }: { notice: OrgNotice }) {
  return <EmptyState title={notice.title} body={notice.body} to={notice.to} toLabel={notice.toLabel} />;
}

function safeParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}
