// SandboxHostedStatus.tsx is the live half of the Hosted sandboxes panel
// (lane SBX-P7): per provider, whether a credential is in reach (where it
// comes from, never its value), the consent screen for a picked project and
// the agreement it records, the day's box-minutes with a dated estimate, and
// the leftover boxes of earlier runs with a delete that calls the provider
// only on the user's confirm. It reads GET /api/terminal/sandbox/hosted
// (which calls no provider) and writes through the two Local routes with the
// confirm token. Connecting a credential stays a CLI step
// (`observer sandbox hosted connect <provider>`), so no secret is ever typed
// into or returned by the dashboard.

import { useState } from "react";
import { ComboChip, ConfirmButton, ErrorState, InlineLoading } from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import { dollarsShown, fmtUSD } from "@/lib/format";
import { useApi } from "@/lib/useApi";
import { useProjectRootOptions } from "@/lib/usePickerSources";

type ConsentLine = { label: string; value: string };
type Exclusion = { path: string; reason: string };
type EndpointDoc = { call: string; method: string; path: string; doc: string; unverified?: string };

type HostedProvider = {
  id: string;
  name: string;
  credential: string;
  credential_env: string[];
  consent?: { at: string };
  screen?: { lines: ConsentLine[]; excluded: Exclusion[] | null; uploaded?: string[] | null; uploaded_more?: number };
  screen_error?: string;
  consent_verdict?: string;
  unverified: string[] | null;
  endpoint_docs: EndpointDoc[] | null;
};

type Leftover = {
  run_id: string;
  provider: string;
  region: string;
  vendor_id?: string;
  state: string;
  age_seconds: number;
  expires_in_seconds: number;
  action: string;
  adoptable: boolean;
};

type DayTotal = { provider: string; day: string; minutes: number; estimate: { usd: number; price: { date: string } } };

export type HostedStatusResponse = {
  confirm_token: string;
  providers: HostedProvider[] | null;
  leftovers: Leftover[] | null;
  spend: DayTotal[] | null;
};

const CREDENTIAL_LABEL: Record<string, string> = {
  keystore: "connected (stored in this machine's keychain)",
  env: "from the environment at use time",
};

function minutesText(seconds: number): string {
  const m = Math.round(seconds / 60);
  return m >= 60 ? `${Math.floor(m / 60)} h ${m % 60} min` : `${m} min`;
}

export function SandboxHostedStatus({ selected }: { selected: string[] }) {
  const [workspace, setWorkspace] = useState("");
  const status = useApi<HostedStatusResponse>("/api/terminal/sandbox/hosted", workspace ? { workspace } : undefined, [workspace]);
  const roots = useProjectRootOptions(true);
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState<string | null>(null);

  async function post(path: string, body: unknown, key: string) {
    if (!status.data?.confirm_token) return;
    setBusy(key);
    setErr(null);
    try {
      await fetchJSON(path, undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Observer-Confirm": status.data.confirm_token },
        body: JSON.stringify(body),
      });
      status.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy("");
    }
  }

  if (status.loading && !status.data) return <InlineLoading label="Reading hosted sandbox status" />;
  if (status.error && !status.data) return <ErrorState title="Hosted sandbox status is not available" error={status.error} />;
  return (
    <SandboxHostedStatusView
      data={status.data}
      selected={selected}
      workspace={workspace}
      onWorkspace={setWorkspace}
      rootOptions={roots.options}
      busy={busy}
      err={err}
      post={(path, body, key) => void post(path, body, key)}
    />
  );
}

/** SandboxHostedStatusViewProps is what the status view renders from: the
 * fetched answer and the controls' state, so a render test needs no fetch. */
export type SandboxHostedStatusViewProps = {
  data: HostedStatusResponse | null | undefined;
  selected: string[];
  workspace: string;
  onWorkspace: (v: string) => void;
  rootOptions: { id: string; label: string }[];
  busy: string;
  err: string | null;
  post: (path: string, body: unknown, key: string) => void;
  /** today is the UTC day the spend line counts (tests pin it). */
  today?: string;
};

/** SandboxHostedStatusView renders one answer of GET /api/terminal/sandbox/hosted. */
export function SandboxHostedStatusView({ data, selected, workspace, onWorkspace, rootOptions, busy, err, post, today: todayProp }: SandboxHostedStatusViewProps) {
  const setWorkspace = onWorkspace;
  const providers = (data?.providers ?? []).filter((p) => selected.includes(p.id));
  const leftovers = data?.leftovers ?? [];
  const today = todayProp ?? new Date().toISOString().slice(0, 10);
  const spend = (data?.spend ?? []).filter((s) => s.day === today);

  return (
    <div className="space-y-3">
      <div className="space-y-1">
        <span id="sandbox-hosted-workspace" className="block font-medium text-fg-1">Project to review</span>
        <ComboChip
          label="Project to review"
          labelledBy="sandbox-hosted-workspace"
          hideTriggerLabel
          fullWidth
          value={workspace}
          onChange={(v) => setWorkspace(v)}
          options={[{ value: "", label: <span>Pick a project</span>, searchable: "" }, ...rootOptions.map((o) => ({ value: o.id, label: <span className="font-mono">{o.label}</span>, searchable: o.label }))]}
          buttonValueRender={() => <span className="font-mono">{workspace || "Pick a project"}</span>}
        />
        <span className="block text-[11px] text-fg-3">
          The consent screen below lists exactly what would leave this machine for that project. Nothing is uploaded until a launch.
        </span>
      </div>
      {err && <p className="text-[11px] text-bad">{err}</p>}
      {providers.map((p) => {
        const used = spend.find((s) => s.provider === p.id);
        const agreed = p.consent_verdict === "ok";
        return (
          <div key={p.id} className="space-y-2 rounded-2 border border-line-2 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-medium text-fg-1">{p.name}</span>
              <span className="text-[11px] text-fg-3">
                Credential: {CREDENTIAL_LABEL[p.credential] ?? `none (run observer sandbox hosted connect ${p.id}, or set ${p.credential_env.join(", ")})`}
              </span>
            </div>
            {used && (
              <span className="block text-[11px] text-fg-3">
                Today: {used.minutes} box-minutes
                {dollarsShown() && <> (about {fmtUSD(used.estimate.usd, true)} at the list price of {used.estimate.price.date})</>}
              </span>
            )}
            {p.screen_error && <p className="text-[11px] text-warn">{p.screen_error}</p>}
            {p.screen && (
              <div className="space-y-1">
                <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-[11px]">
                  {p.screen.lines.map((l) => (
                    <div key={l.label} className="contents">
                      <dt className="text-fg-3">{l.label}</dt>
                      <dd className="text-fg-1">{l.value}</dd>
                    </div>
                  ))}
                </dl>
                {(p.screen.uploaded ?? []).length > 0 && (
                  <details className="text-[11px] text-fg-3">
                    <summary className="cursor-pointer">The files sent to the box</summary>
                    <ul className="mt-1 space-y-0.5 font-mono">
                      {(p.screen.uploaded ?? []).map((f) => (
                        <li key={f}>{f}</li>
                      ))}
                      {(p.screen.uploaded_more ?? 0) > 0 && <li>and {p.screen.uploaded_more} more</li>}
                    </ul>
                  </details>
                )}
                {(p.screen.excluded ?? []).length > 0 && (
                  <details className="text-[11px] text-fg-3">
                    <summary className="cursor-pointer">{(p.screen.excluded ?? []).length} files are not uploaded</summary>
                    <ul className="mt-1 space-y-0.5 font-mono">
                      {(p.screen.excluded ?? []).map((e) => (
                        <li key={e.path}>
                          {e.path} ({e.reason.replace(/_/g, " ")})
                        </li>
                      ))}
                    </ul>
                  </details>
                )}
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  {agreed ? (
                    <span className="text-[11px] text-good">Agreed on {p.consent?.at}</span>
                  ) : (
                    <ConfirmButton
                      variant="soft"
                      armedVariant="danger"
                      requireConfirm
                      disabled={busy !== ""}
                      onConfirm={() => post("/api/terminal/sandbox/hosted/consent", { provider: p.id, workspace }, "consent-" + p.id)}
                      confirmLabel="Agree and allow uploads?"
                      armedNote={`Launches on ${p.name} will upload the files above to ${p.name}'s machines. Any change to these facts asks again.`}
                    >
                      {p.consent_verdict && p.consent_verdict !== "consent_required" ? `Agree again (${p.consent_verdict.replace(/_/g, " ")})` : "Agree"}
                    </ConfirmButton>
                  )}
                  {p.consent && (
                    <ConfirmButton variant="soft" disabled={busy !== ""} onConfirm={() => post("/api/terminal/sandbox/hosted/consent", { provider: p.id, revoke: true }, "revoke-" + p.id)}>
                      Withdraw agreement
                    </ConfirmButton>
                  )}
                </div>
              </div>
            )}
            {(p.unverified ?? []).length > 0 && (
              <details className="text-[11px] text-fg-3">
                <summary className="cursor-pointer">Not yet proven with a real account</summary>
                <ul className="mt-1 list-disc space-y-0.5 pl-4">
                  {(p.unverified ?? []).map((u) => (
                    <li key={u}>{u}</li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        );
      })}
      <div className="space-y-1">
        <span className="block font-medium text-fg-1">Leftover boxes</span>
        {leftovers.length === 0 ? (
          <span className="block text-[11px] text-fg-3">None: every box this machine created was deleted and confirmed.</span>
        ) : (
          <ul className="space-y-1 text-[11px]">
            {leftovers.map((l) => (
              <li key={l.run_id} className="flex flex-wrap items-center justify-between gap-2 rounded-1 border border-line-2 px-2 py-1">
                <span className="text-fg-2">
                  {l.provider} <span className="font-mono">{l.vendor_id || "(create answer lost)"}</span>, {l.state.replace(/_/g, " ")}, started {minutesText(l.age_seconds)} ago
                  {l.expires_in_seconds > 0 ? `, stops by itself in ${minutesText(l.expires_in_seconds)}` : ", past its timeout"}
                </span>
                <ConfirmButton
                  variant="soft"
                  armedVariant="danger"
                  requireConfirm
                  disabled={busy !== ""}
                  onConfirm={() => post("/api/terminal/sandbox/hosted/leftovers/delete", { run_id: l.run_id }, "delete-" + l.run_id)}
                  confirmLabel="Delete at the provider?"
                  armedNote={l.action === "find_and_delete" ? "Lists the provider's boxes carrying this run's label, then deletes them." : "Deletes the box at the provider and waits for it to confirm."}
                >
                  {busy === "delete-" + l.run_id ? "deleting…" : "Delete"}
                </ConfirmButton>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
