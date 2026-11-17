// SandboxHostedStatus.tsx is the live half of the Hosted sandboxes panel
// (lane SBX-P7): per provider, whether a credential is in reach (where it
// comes from, never its value), the consent screen for a picked project and
// the agreement it records, the day's box-minutes with a dated estimate, and
// the leftover boxes of earlier runs with a delete that calls the provider
// only on the user's confirm. It reads GET /api/terminal/sandbox/hosted
// (which calls no provider) and writes through the Local routes with the
// confirm token. A credential is connected here too (dashboard CLI parity
// plan item B-G2, the form of `observer sandbox hosted connect <provider>`):
// one field per variable the provider needs, a password field for each
// secret, never pre-filled and cleared as soon as Connect is pressed; the
// daemon stores it in the OS keychain bound to the saved region's endpoint
// and never returns it. Guard rule R-165 refuses an agent's connect.

import { useState } from "react";
import { Button, ComboChip, ConfirmButton, ErrorState, InlineLoading } from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import { dollarsShown, fmtUSD } from "@/lib/format";
import { hostedConnectReady, hostedFieldIsSecret } from "@/lib/sandboxParity";
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
  /** clone_repositories are the repositories a clone-remote launch on this row may name. */
  clone_repositories?: string[] | null;
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
  const [repository, setRepository] = useState("");
  const query = workspace ? (repository ? { workspace, repository } : { workspace }) : undefined;
  const status = useApi<HostedStatusResponse>("/api/terminal/sandbox/hosted", query, [workspace, repository]);
  const roots = useProjectRootOptions(true);
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState<string | null>(null);
  // What is typed in each provider's Connect form, kept only until Connect.
  const [connectDraft, setConnectDraft] = useState<Record<string, Record<string, string>>>({});

  function connect(provider: string) {
    const fields = connectDraft[provider] ?? {};
    // Cleared before the request, so no value stays on the page.
    setConnectDraft((cur) => ({ ...cur, [provider]: {} }));
    void post("/api/terminal/sandbox/hosted/connect", { provider, fields }, "connect-" + provider);
  }

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
      repository={repository}
      onRepository={setRepository}
      rootOptions={roots.options}
      busy={busy}
      err={err}
      post={(path, body, key) => void post(path, body, key)}
      connectDraft={connectDraft}
      onConnectDraft={(provider, field, v) => setConnectDraft((cur) => ({ ...cur, [provider]: { ...(cur[provider] ?? {}), [field]: v } }))}
      connect={connect}
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
  /** repository is the clone-remote repository the consent is for ("" for the project's upload). */
  repository?: string;
  onRepository?: (v: string) => void;
  rootOptions: { id: string; label: string }[];
  busy: string;
  err: string | null;
  post: (path: string, body: unknown, key: string) => void;
  /** today is the UTC day the spend line counts (tests pin it). */
  today?: string;
  /** connectDraft is what is typed in each provider's Connect form (provider -> field -> value). */
  connectDraft?: Record<string, Record<string, string>>;
  onConnectDraft?: (provider: string, field: string, value: string) => void;
  /** connect stores the typed credential; absent, no Connect form renders. */
  connect?: (provider: string) => void;
};

/** credentialText is a provider's credential line: where it comes from, or
 * what connects one (never a value). */
export function credentialText(p: { id: string; credential: string; credential_env: string[] }, canConnect: boolean): string {
  const known = CREDENTIAL_LABEL[p.credential];
  if (known) return known;
  const env = p.credential_env.join(", ");
  return canConnect ? `none (connect one below, or set ${env} in the daemon's environment)` : `none (set ${env} in the daemon's environment)`;
}

/** consentWording is the agree button's confirm label and armed note (FX3-A10):
 * a clone-remote agreement uploads nothing from this machine, so it never
 * says it does. */
export function consentWording(providerName: string, repository: string): { confirmLabel: string; armedNote: string } {
  if (repository) {
    return {
      confirmLabel: "Agree and allow the box to clone?",
      armedNote: `Launches on ${providerName} clone ${repository} inside the box on ${providerName}'s machines; nothing is uploaded from this machine. Any change to these facts asks again.`,
    };
  }
  return {
    confirmLabel: "Agree and allow uploads?",
    armedNote: `Launches on ${providerName} will upload the files above to ${providerName}'s machines. Any change to these facts asks again.`,
  };
}

/** SandboxHostedStatusView renders one answer of GET /api/terminal/sandbox/hosted. */
export function SandboxHostedStatusView({ data, selected, workspace, onWorkspace, repository = "", onRepository, rootOptions, busy, err, post, today: todayProp, connectDraft, onConnectDraft, connect }: SandboxHostedStatusViewProps) {
  const setWorkspace = onWorkspace;
  const providers = (data?.providers ?? []).filter((p) => selected.includes(p.id));
  const cloneRepos = Array.from(new Set(providers.flatMap((p) => p.clone_repositories ?? [])));
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
      {onRepository && cloneRepos.length > 0 && (
        <div className="space-y-1">
          <span id="sandbox-hosted-repository" className="block font-medium text-fg-1">Clone in the box instead (clone-remote)</span>
          <ComboChip
            label="Repository to clone in the box"
            labelledBy="sandbox-hosted-repository"
            hideTriggerLabel
            fullWidth
            value={repository}
            onChange={(v) => onRepository(v)}
            options={[{ value: "", label: <span>No: upload the project</span>, searchable: "" }, ...cloneRepos.map((u) => ({ value: u, label: <span className="font-mono">{u}</span>, searchable: u }))]}
            buttonValueRender={() => <span className="font-mono">{repository || "No: upload the project"}</span>}
          />
          <span className="block text-[11px] text-fg-3">
            A clone-remote launch needs its own agreement: the box clones the repository itself and nothing leaves this machine. Agreeing replaces the project's agreement for that provider.
          </span>
        </div>
      )}
      {err && <p className="text-[11px] text-bad">{err}</p>}
      {providers.map((p) => {
        const used = spend.find((s) => s.provider === p.id);
        const agreed = p.consent_verdict === "ok";
        const canConnect = !!connect && !!onConnectDraft && p.credential_env.length > 0;
        const draft = connectDraft?.[p.id] ?? {};
        const ready = hostedConnectReady(p.credential_env, draft);
        return (
          <div key={p.id} className="space-y-2 rounded-2 border border-line-2 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-medium text-fg-1">{p.name}</span>
              <span className="flex flex-wrap items-center gap-2 text-[11px] text-fg-3">
                Credential: {credentialText(p, canConnect)}
                {canConnect && p.credential === "keystore" && (
                  <ConfirmButton
                    size="sm"
                    variant="soft"
                    disabled={busy !== ""}
                    confirmLabel={`Remove the stored ${p.name} credential?`}
                    onConfirm={() => post("/api/terminal/sandbox/hosted/disconnect", { provider: p.id }, "disconnect-" + p.id)}
                  >
                    Disconnect
                  </ConfirmButton>
                )}
              </span>
            </div>
            {canConnect && (
              <details className="text-[11px] text-fg-3" open={p.credential === ""}>
                <summary className="cursor-pointer">{p.credential === "keystore" ? `Replace the ${p.name} credential` : `Connect ${p.name}`}</summary>
                <form
                  className="mt-2 space-y-2"
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (ready) connect?.(p.id);
                  }}
                >
                  <p>
                    Stored in this machine&apos;s keychain, bound to the endpoint of the region saved above (save a changed
                    region first); never shown again. Same as <span className="font-mono">observer sandbox hosted connect {p.id}</span>.
                  </p>
                  <HostedKeyFields
                    names={p.credential_env}
                    values={draft}
                    disabled={busy !== ""}
                    onChange={(name, v) => onConnectDraft?.(p.id, name, v)}
                  />
                  <Button type="submit" size="sm" variant="soft" disabled={busy !== "" || !ready}>
                    {busy === "connect-" + p.id ? "connecting…" : "Connect"}
                  </Button>
                </form>
              </details>
            )}
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
                      onConfirm={() => post("/api/terminal/sandbox/hosted/consent", repository ? { provider: p.id, workspace, repository } : { provider: p.id, workspace }, "consent-" + p.id)}
                      {...consentWording(p.name, repository)}
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

/** HOSTED_KEY_FIELD_CLASS is the key fields' chrome on the Hosted sandboxes card. */
export const HOSTED_KEY_FIELD_CLASS = "w-full rounded-1 border border-line-2 bg-bg-2 px-2 py-1 font-mono text-[12px]";

/**
 * HostedKeyFields is the one owner of a hosted provider's key inputs, shared
 * by the Hosted sandboxes card's Connect form and the setup panel's key
 * step: one field per variable the provider needs (named by the provider's
 * own variable names), a masked input for every secret and plain text for an
 * *_ID field, never pre-filled and never auto-completed. The caller owns the
 * typed values and clears them as soon as they are sent.
 */
export function HostedKeyFields({
  names,
  values,
  disabled,
  onChange,
  className = HOSTED_KEY_FIELD_CLASS,
}: {
  names: string[];
  values: Record<string, string>;
  disabled: boolean;
  onChange: (name: string, value: string) => void;
  className?: string;
}) {
  return (
    <>
                  {names.map((name) => (
                    <label key={name} className="block space-y-1">
                      <span className="block font-mono text-fg-2">{name}</span>
                      <input
                        type={hostedFieldIsSecret(name) ? "password" : "text"}
                        className={className}
                        value={values[name] ?? ""}
                        autoComplete="off"
                        spellCheck={false}
                        disabled={disabled}
                        onChange={(e) => onChange(name, e.target.value)}
                      />
                    </label>
                  ))}
    </>
  );
}
