import { useEffect, useMemo, useState } from "react";
import { placeLink } from "@/lib/settingsPlaces";
import { NeedsSettingNotice } from "@/components/NeedsSettingNotice";
import { ChartShell, InlineLoading, ErrorState, Pill, SinglePicker, SuccessCheck } from "@/components/primitives";
import { apiReason, fetchJSON } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { markRestartPending } from "@/lib/restartPending";
import { ConfigSaveCancelled, saveConfigEdit } from "@/lib/configSectionSave";
import type { InstanceTestResult } from "@/lib/types";
import {
  changesBetween,
  changesSentence,
  draftProblem,
  emptyProfile,
  normalize,
  target,
  type SSHProfileDraft,
  type SSHProfilesEditorResponse,
} from "@/lib/sshProfiles";

// RemoteSystemsCard is the dashboard editor for SSH remote systems (T-488):
// the [terminal.ssh] switch and the [[terminal.ssh.profiles]] list that the
// New Terminal "System" picker and the top-bar instance switcher read. It
// replaced "add a [[terminal.ssh.profiles]] block to config.toml and restart
// the daemon". The daemon re-reads the list, so a save applies to the next
// launch. The route is owner-local and confirm-token gated; key_path is a
// PATH only (the key file is never read, uploaded or shown).

const FIELD =
  "w-full rounded-2 border border-line-2 bg-bg-3 px-2 py-1 text-[12px] text-fg-1 outline-none focus:border-accent disabled:opacity-40";
const BTN =
  "rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-2 hover:bg-bg-3 disabled:opacity-40";
const BTN_ACCENT =
  "rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] text-accent hover:bg-accent/25 disabled:opacity-50";

function TestResultLine({ result }: { result: InstanceTestResult }) {
  const trust = result.known_hosts_checked
    ? result.known_hosts_ok
      ? "host key trusted"
      : "host key not in known_hosts yet (open an SSH terminal to it once and accept the key)"
    : "host key could not be checked";
  return (
    <div
      className={`rounded-2 border px-2 py-1.5 text-[11px] ${
        result.auth_ok ? "border-ok/40 bg-ok/10 text-ok" : "border-warn/40 bg-warn/10 text-warn"
      }`}
    >
      {result.auth_ok ? "Connected and signed in" : "Could not sign in"} ({result.latency_ms} ms); {trust}.
      {result.stderr ? <span className="mt-1 block break-all font-mono text-[10.5px] text-fg-3">{result.stderr}</span> : null}
    </div>
  );
}

export function RemoteSystemsCard() {
  const res = useApi<SSHProfilesEditorResponse>("/api/terminal/ssh/profiles");
  const data = res.data;
  const writable = !!data?.config_writable;

  const [enabled, setEnabled] = useState(true);
  const [list, setList] = useState<SSHProfileDraft[]>([]);
  // editing: index into list being edited, "new" for the add form, null for none.
  const [editing, setEditing] = useState<number | "new" | null>(null);
  const [form, setForm] = useState<SSHProfileDraft>(emptyProfile());
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [testBusy, setTestBusy] = useState(false);
  const [testResult, setTestResult] = useState<InstanceTestResult | null>(null);
  const [testErr, setTestErr] = useState<string | null>(null);

  useEffect(() => {
    if (data) {
      setEnabled(data.enabled);
      setList(data.profiles ?? []);
    }
  }, [data]);

  const others = useMemo(
    () => list.filter((_, i) => editing === "new" || i !== editing),
    [list, editing],
  );
  const problem = editing === null ? null : draftProblem(form, others);
  const review = useMemo(
    () =>
      data
        ? changesSentence(
            changesBetween(data.profiles ?? [], list),
            enabled !== data.enabled ? enabled : undefined,
          )
        : "",
    [data, list, enabled],
  );

  function openForm(idx: number | "new") {
    setEditing(idx);
    setForm(idx === "new" ? emptyProfile() : { ...list[idx] });
    setTestResult(null);
    setTestErr(null);
  }

  function applyForm() {
    if (problem || editing === null) return;
    const next = normalize(form);
    setList((cur) => (editing === "new" ? [...cur, next] : cur.map((p, i) => (i === editing ? next : p))));
    setEditing(null);
    setSaved(false);
  }

  function remove(idx: number) {
    setList((cur) => cur.filter((_, i) => i !== idx));
    if (editing === idx) setEditing(null);
    setSaved(false);
  }

  async function save() {
    if (!data?.confirm_token) {
      setErr("No confirm token - reload the page.");
      return;
    }
    setBusy(true);
    setErr(null);
    setSaved(false);
    try {
      // Preview then save at the previewed etag (REVIEW-3 P3-18): the same
      // diff dialog every config save shows.
      const out = await saveConfigEdit(
        "/api/terminal/ssh/profiles",
        "terminal.ssh",
        { enabled, profiles: list },
        { "X-Observer-Confirm": data.confirm_token },
        { title: "Save remote systems" },
      );
      if (out.restart_required) markRestartPending("terminal-ssh");
      setSaved(true);
      res.reload();
    } catch (e) {
      if (!(e instanceof ConfigSaveCancelled)) setErr(apiReason(e));
    } finally {
      setBusy(false);
    }
  }

  async function testDraft() {
    if (!data?.confirm_token || problem) return;
    setTestBusy(true);
    setTestErr(null);
    setTestResult(null);
    try {
      const out = await fetchJSON<InstanceTestResult>("/api/terminal/ssh/profiles/test", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Observer-Confirm": data.confirm_token },
        body: JSON.stringify(normalize(form)),
      });
      setTestResult(out);
    } catch (e) {
      setTestErr(apiReason(e));
    } finally {
      setTestBusy(false);
    }
  }

  const setField = <K extends keyof SSHProfileDraft>(k: K, v: SSHProfileDraft[K]) =>
    setForm((f) => ({ ...f, [k]: v }));

  return (
    <div id="remote-systems" className="scroll-mt-6">
      <ChartShell
        title="Remote systems (SSH)"
        sub="Machines New Terminal may open an SSH shell on, and whose own superbased dashboard the top-bar switcher can open. Owner-local: only this machine can change the list. Applies to the next launch - no restart."
        right={
          <div className="flex flex-wrap items-center gap-1.5">
            <Pill variant={data?.enabled ? "success" : "neutral"}>{data?.enabled ? "SSH on" : "SSH off"}</Pill>
            <Pill variant="neutral">
              {(data?.profiles ?? []).length} system{(data?.profiles ?? []).length === 1 ? "" : "s"}
            </Pill>
          </div>
        }
      >
        {!data ? (
          res.error ? (
            <ErrorState
              className="py-4"
              title="Could not load the remote systems"
              error={res.error}
              onRetry={res.reload}
            />
          ) : (
            <InlineLoading label="Loading remote systems" />
          )
        ) : (
          <div className="space-y-4 p-1 text-[12px]">
            {!writable && (
              <div className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-fg-3">
                This dashboard was started without a writable config path, so remote systems can&apos;t be
                edited here.
              </div>
            )}
            {!data.terminal_enabled && (
              <NeedsSettingNotice
                text="The terminal surface is off on this machine ([terminal].enabled = false), so no SSH terminal can open until it is on. Turn it on in Settings > Session attach, under More settings."
                link={placeLink("session_attach")}
              />
            )}

            <label className="flex items-start gap-2">
              <input
                type="checkbox"
                checked={enabled}
                disabled={!writable}
                onChange={(e) => {
                  setSaved(false);
                  setEnabled(e.target.checked);
                }}
                className="mt-0.5"
              />
              <span>
                <span className="font-medium text-fg-1">Allow SSH remote-system terminals</span>
                <span className="block text-[11px] text-fg-3">
                  Shows the System picker in New Terminal and the instance switcher. It reaches only the
                  systems listed below, and ssh asks for host keys and passphrases in the terminal itself.
                </span>
              </span>
            </label>

            <div className="space-y-1.5">
              {list.length === 0 && (
                <div className="text-[11px] text-fg-3">No remote systems yet. Add one below.</div>
              )}
              {list.map((p, i) => (
                <div
                  key={`${p.name}-${i}`}
                  className="flex flex-wrap items-center gap-2 rounded-2 border border-line-2 bg-bg-3 px-2 py-1.5"
                >
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium text-fg-1">
                      {p.label || p.name} <span className="font-mono text-[10.5px] text-fg-3">{p.name}</span>
                    </div>
                    <div className="truncate font-mono text-[10.5px] text-fg-3">
                      {target(p)}
                      {p.jump ? ` via ${p.jump}` : ""}
                      {p.key_path ? ` · key ${p.key_path}` : ""}
                    </div>
                  </div>
                  <button type="button" className={BTN} disabled={!writable} onClick={() => openForm(i)}>
                    edit
                  </button>
                  <button type="button" className={BTN} disabled={!writable} onClick={() => remove(i)}>
                    remove
                  </button>
                </div>
              ))}
              {editing === null && (
                <button type="button" className={BTN} disabled={!writable} onClick={() => openForm("new")}>
                  add a remote system
                </button>
              )}
            </div>

            {editing !== null && (
              <div className="space-y-2 rounded-2 border border-accent/40 bg-bg-2 p-3">
                <div className="font-medium text-fg-1">{editing === "new" ? "New remote system" : `Edit ${form.name}`}</div>
                <div className="grid gap-2 sm:grid-cols-2">
                  <label className="space-y-0.5">
                    <span className="text-[11px] text-fg-3">Name (id: lowercase, digits, . _ -)</span>
                    <input className={`${FIELD} font-mono`} value={form.name} onChange={(e) => setField("name", e.target.value)} placeholder="devbox" />
                  </label>
                  <label className="space-y-0.5">
                    <span className="text-[11px] text-fg-3">Label (optional)</span>
                    <input className={FIELD} value={form.label} onChange={(e) => setField("label", e.target.value)} placeholder="Dev box" />
                  </label>
                  <label className="space-y-0.5">
                    <span className="text-[11px] text-fg-3">Host, IP or ~/.ssh/config alias</span>
                    <input className={`${FIELD} font-mono`} value={form.host} onChange={(e) => setField("host", e.target.value)} placeholder="devbox.example.com" />
                  </label>
                  <label className="space-y-0.5">
                    <span className="text-[11px] text-fg-3">User (optional)</span>
                    <input className={`${FIELD} font-mono`} value={form.user} onChange={(e) => setField("user", e.target.value)} />
                  </label>
                  <label className="space-y-0.5">
                    <span className="text-[11px] text-fg-3">SSH port (0 = default 22)</span>
                    <input
                      type="number"
                      min={0}
                      max={65535}
                      className={FIELD}
                      value={form.port}
                      onChange={(e) => setField("port", Number(e.target.value) || 0)}
                    />
                  </label>
                  {/* D-571: another saved system can be picked as the jump host. */}
                  <div className="space-y-0.5">
                    <span className="text-[11px] text-fg-3">Jump host (optional, user@host:port)</span>
                    <SinglePicker
                      options={[
                        ...list
                          .filter((p, i) => i !== editing && p.host)
                          .map((p) => ({ id: target(p), label: p.label || p.name, group: "Saved systems" })),
                        ...(form.jump && !list.some((p) => target(p) === form.jump) ? [{ id: form.jump, label: form.jump }] : []),
                      ]}
                      value={form.jump}
                      onChange={(v) => setField("jump", v)}
                      allowFree
                      freeLabel="Use"
                      placeholder="none"
                      ariaLabel="Jump host"
                    />
                  </div>
                  <label className="space-y-0.5 sm:col-span-2">
                    <span className="text-[11px] text-fg-3">
                      Private key path (optional). Only the path is saved and passed to ssh -i; the file is
                      never read or uploaded. Passphrases stay with ssh-agent or the terminal prompt.
                    </span>
                    <input className={`${FIELD} font-mono`} value={form.key_path} onChange={(e) => setField("key_path", e.target.value)} placeholder="/home/you/.ssh/id_ed25519" />
                  </label>
                </div>
                <details className="rounded-2 border border-line-2 bg-bg-3 p-2">
                  <summary className="cursor-pointer text-[11px] text-fg-2">Instance switcher options</summary>
                  <div className="mt-2 grid gap-2 sm:grid-cols-2">
                    <label className="space-y-0.5">
                      <span className="text-[11px] text-fg-3">Its dashboard port (0 = 8081)</span>
                      <input
                        type="number"
                        min={0}
                        max={65535}
                        className={FIELD}
                        value={form.dashboard_port}
                        onChange={(e) => setField("dashboard_port", Number(e.target.value) || 0)}
                      />
                    </label>
                    <label className="flex items-start gap-2 pt-4">
                      <input
                        type="checkbox"
                        checked={form.reverse_proxy}
                        onChange={(e) => setField("reverse_proxy", e.target.checked)}
                        className="mt-0.5"
                      />
                      <span className="text-[11px] text-fg-3">Also let it reach this machine&apos;s proxy (reverse forward)</span>
                    </label>
                  </div>
                </details>
                {problem && <div className="text-[11px] text-warn">{problem}</div>}
                {testErr && (
                  <div className="rounded-2 border border-danger/40 bg-danger/10 px-2 py-1.5 text-[11px] text-danger">{testErr}</div>
                )}
                {testResult && <TestResultLine result={testResult} />}
                <div className="flex flex-wrap items-center gap-2">
                  <button type="button" className={BTN_ACCENT} disabled={!!problem} onClick={applyForm}>
                    {editing === "new" ? "Add to the list" : "Update in the list"}
                  </button>
                  <button
                    type="button"
                    className={BTN}
                    disabled={!!problem || testBusy || !data.test_available}
                    title={data.test_available ? "Sign in once with ssh BatchMode and exit; opens nothing" : "Test needs the embedded terminal stack (observer start)"}
                    onClick={() => void testDraft()}
                  >
                    {testBusy ? "testing…" : "Test connection"}
                  </button>
                  <button type="button" className={BTN} onClick={() => setEditing(null)}>
                    cancel
                  </button>
                </div>
              </div>
            )}

            {err && (
              <div className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{err}</div>
            )}
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button type="button" className={BTN_ACCENT} disabled={busy || !writable || !review || editing !== null} onClick={() => void save()}>
                {busy ? "saving…" : "Save remote systems"}
              </button>
              {saved && <SuccessCheck label="Saved" className="!text-[11px]" />}
              {review ? (
                <span className="text-[11px] text-fg-2">{review}</span>
              ) : (
                <span className="text-[11px] text-fg-3">
                  {data.restart_required_on_save
                    ? "Changes take effect on the next daemon restart (this daemon reads them at start-up)."
                    : "Changes apply to the next launch - no restart needed."}
                </span>
              )}
            </div>
          </div>
        )}
      </ChartShell>
    </div>
  );
}
