import { Check, Copy, ExternalLink, History, LogIn, LogOut, RefreshCw, Send, type LucideIcon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import {
  Button,
  ChartShell,
  ConfirmButton,
  EmptyState,
  InlineLoading,
  Input,
  JsonPreview,
  Meter,
  Modal,
  Pill,
  SegmentedControl,
  SlideOver,
  StatCard,
  Tooltip,
  Stagger,
} from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { ObsJobRider, ObsLanding } from "@shared/primitives/ObsFlight";
import { apiCache, useApi, type ApiState } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { useDaemonRestart } from "@/lib/useDaemonRestart";
import { fmtBytes, fmtDateTime, fmtInt } from "@/lib/format";
import { orgDisplayLabel, orgDisplayLabelSentence } from "@/lib/orgName";
import type { EnrolmentInvite, EnrolmentStatus } from "@/lib/types";
import {
  apiErrorMessage,
  canSubmit,
  DECISION_TONE,
  enrolBody,
  formErrors,
  IDP_STATUS_COPY,
  METHOD_OPTIONS,
  NOTE_TONE,
  pendingGrantOf,
  pollDelayMs,
  pushCadenceLine,
  resyncLine,
  type ResyncReport,
  shareModeLabel,
  tenancyLabel,
  type EnrolForm,
  type EnrolMethod,
  type EnrolNote,
  type EnrolOutcome,
  type EnrolProbe,
  type EnrolmentOverview,
  type GrantDecision,
  type GrantReport,
  type IdPPoll,
  type IdPStart,
  type LeaveReport,
  type ManageResponse,
  type PendingGrant,
  type PushNowReport,
  leavePlanGroups,
  type EnrolLeaveRoute,
  type EnrolLeaveStep,
  type Tone,
} from "@/lib/enrolment";
import { MetricIcon } from "@/components/MetricIcon";
import {
  eligibleNow,
  shareHistoryCrossEnrolmentWarning,
  shareHistoryPreviewLine,
  shareHistoryProgress,
  type ShareHistoryReport,
} from "@/lib/shareHistory";

// EnrolmentSection is Settings > Enrolment: the whole `observer enroll` /
// `observer org status|push-now|grant show` / `observer unenroll` surface
// (backlog item 6 - no "run this command" dead end). Every action goes
// through /api/enrolment/* routes that run the CLI's own Go code paths on the
// daemon; this component chooses, shows and confirms.
//
// The management routes are owner-local (they write this machine's config
// and keychain). A paired remote viewer gets the read-only status view
// (/api/enrolment/status) with a note to manage from the machine itself.
export function EnrolmentSection({ icon }: { icon?: LucideIcon }) {
  const manage = useApi<ManageResponse>("/api/enrolment/manage", undefined, [], { refreshMs: 30000 });
  const local = !manage.error;

  return (
    <ChartShell
      title="Organization enrolment"
      icon={icon}
      sub="Teams visibility: when enrolled, this machine shares activity rollups with your organization's SuperBased server. An individual enrolment shares counts, costs, timings and hashes unless you opt in to more; an organization-managed enrolment shares full content. Enrol, check status, push and leave from here."
    >
      {local ? (
        <ManagedEnrolment manage={manage} />
      ) : (
        <ReadOnlyEnrolment reason={manage.status === 501 ? "process" : "remote"} />
      )}
    </ChartShell>
  );
}

type Post = <T>(path: string, body: unknown) => Promise<T>;

const BOX = "rounded-2 border px-3 py-2 text-[11.5px]";
const TONE_BOX: Record<Tone, string> = {
  success: "border-success/30 bg-success-soft text-fg-1",
  info: "border-line-1 bg-bg-2 text-fg-2",
  warn: "border-warn/30 bg-warn-soft text-fg-1",
  danger: "border-danger/40 bg-danger-soft text-danger",
  neutral: "border-line-1 bg-bg-2 text-fg-2",
};

function Notes({ notes }: { notes?: EnrolNote[] | null }) {
  if (!notes?.length) return null;
  return (
    <ul className="space-y-1.5">
      {notes.map((n, i) => (
        <li key={i} className={`${BOX} ${TONE_BOX[NOTE_TONE[n.level] ?? "info"]}`}>
          {n.text}
        </li>
      ))}
    </ul>
  );
}

function ErrorBox({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div role="alert" className={`${BOX} ${TONE_BOX.danger}`}>
      {message}
    </div>
  );
}

function ManagedEnrolment({ manage }: { manage: ApiState<ManageResponse> }) {
  const token = manage.data?.confirm_token ?? "";
  const ov = manage.data?.overview;
  const [outcome, setOutcome] = useState<EnrolOutcome | null>(null);
  const [decision, setDecision] = useState<GrantDecision | null>(null);
  const [decided, setDecided] = useState<Set<string>>(new Set());
  const [leave, setLeave] = useState<LeaveReport | null>(null);
  const [reenrol, setReenrol] = useState(false);

  const post: Post = <T,>(path: string, body: unknown) =>
    fetchJSON<T>(path, undefined, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Observer-Confirm": token },
      body: JSON.stringify(body),
    });

  const pending = pendingGrantOf(outcome, ov, decided);

  // refresh reloads this view and the shell's governance read (the Managed
  // banner, hidden sections) plus the read-only enrolment status, because an
  // enrol, a grant decision or a leave changes all of them mid-session.
  function refresh() {
    manage.reload();
    apiCache.invalidate("/api/governance");
    apiCache.invalidate("/api/enrolment/status");
    // Enrolling or leaving changes the org-plane consent state (the
    // Accept / Leave banner, Settings > Org enrichment).
    apiCache.invalidate("/api/intel/status");
  }

  function onEnrolled(out: EnrolOutcome) {
    setOutcome(out);
    setDecision(out.grant ?? null);
    setLeave(null);
    setReenrol(false);
    refresh();
  }

  return (
    <ChartState loading={manage.loading && !manage.data} error={null} denied={false} empty={false} height={160}>
      <div className="space-y-4">
        {leave && (
          <div className={`${BOX} ${TONE_BOX.info} space-y-1`}>
            <div className="font-medium text-fg-1">
              {leave.was_enrolled ? `Left ${orgDisplayLabel(leave.org_display)}.` : "Not enrolled; nothing to do."}
            </div>
            {leave.notes?.map((n, i) => (
              <div key={i} className="break-words">
                {n.text}
              </div>
            ))}
          </div>
        )}

        {outcome && <OutcomeCard outcome={outcome} pushLoop={!!ov?.push_loop_running} />}

        {pending && (
          <ConsentCard
            pending={pending}
            post={post}
            onDecided={(d) => {
              setDecision(d);
              setDecided((prev) => new Set(prev).add(pending.offer_id));
              refresh();
            }}
          />
        )}
        {decision && !pending && <DecisionCard decision={decision} />}

        {ov && !ov.enrolled && <JoinCard post={post} onEnrolled={onEnrolled} reenrol={false} />}

        {ov?.enrolled && (
          <EnrolledView
            ov={ov}
            post={post}
            onReenrol={() => setReenrol((v) => !v)}
            reenrolOpen={reenrol}
            onChanged={refresh}
            onPoll={() => manage.reload()}
            onLeft={(r) => {
              setLeave(r);
              setOutcome(null);
              setDecision(null);
              refresh();
            }}
          >
            {reenrol && <JoinCard post={post} onEnrolled={onEnrolled} reenrol />}
          </EnrolledView>
        )}
      </div>
    </ChartState>
  );
}

// JoinCard is the enrol form: the CLI's three ways to supply credentials,
// each sanity-checked before anything is sent.
function JoinCard({
  post,
  onEnrolled,
  reenrol,
}: {
  post: Post;
  onEnrolled: (o: EnrolOutcome) => void;
  reenrol: boolean;
}) {
  const [form, setForm] = useState<EnrolForm>({ method: "code", orgUrl: "", token: "", link: "" });
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [probe, setProbe] = useState<EnrolProbe | null>(null);
  const errors = touched ? formErrors(form) : {};
  const method = METHOD_OPTIONS.find((m) => m.value === form.method);

  function set<K extends keyof EnrolForm>(k: K, v: EnrolForm[K]) {
    setForm((f) => ({ ...f, [k]: v }));
    setErr(null);
    if (k === "orgUrl" || k === "method") setProbe(null);
  }

  async function check() {
    setTouched(true);
    setErr(null);
    setProbe(null);
    if (formErrors({ ...form, method: "idp" }).orgUrl) return;
    setBusy(true);
    try {
      setProbe(await post<EnrolProbe>("/api/enrolment/probe", { org_url: form.orgUrl.trim() }));
    } catch (e) {
      setErr(apiErrorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!canSubmit(form) || busy) return;
    setBusy(true);
    setErr(null);
    try {
      const out = await post<EnrolOutcome>("/api/enrolment/enrol", enrolBody(form));
      setForm((f) => ({ ...f, token: "", link: "" }));
      onEnrolled(out);
    } catch (e2) {
      setErr(apiErrorMessage(e2));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-2 border border-line-1 bg-bg-2 px-4 py-3 text-[12px]">
      <div className="mb-1 font-medium text-fg-1">{reenrol ? "Re-enrol this machine" : "Join an organization"}</div>
      <p className="mb-3 text-fg-3">
        {reenrol
          ? "Re-enrolling replaces this machine's current enrolment and credentials with the new one."
          : "This machine is not enrolled - nothing is shared. Enrolling writes an [org_client] block to your config.toml and stores the credential in your OS keychain (or a 0600 file). Only activity after enrolment is ever shared."}
      </p>
      <div className="mb-2 max-w-full overflow-x-auto">
        <SegmentedControl<EnrolMethod>
          options={METHOD_OPTIONS.map((m) => ({ value: m.value, label: m.label }))}
          value={form.method}
          onChange={(v) => set("method", v)}
        />
      </div>
      <p className="mb-3 text-fg-3">{method?.help}</p>

      {form.method === "idp" ? (
        <IdPFlow post={post} orgUrl={form.orgUrl} setOrgUrl={(v) => set("orgUrl", v)} onEnrolled={onEnrolled} />
      ) : (
        <form onSubmit={submit} className="space-y-3" autoComplete="off">
          {form.method === "code" ? (
            <>
              <div className="flex flex-col gap-2 sm:flex-row sm:items-start">
                <div className="min-w-0 flex-1">
                  <Input
                    label="Organization server"
                    aria-label="Organization server"
                    placeholder="https://observer.example.com"
                    value={form.orgUrl}
                    onChange={(e) => set("orgUrl", e.target.value)}
                    onBlur={() => setTouched(true)}
                    error={errors.orgUrl}
                    mono
                    spellCheck={false}
                    inputMode="url"
                  />
                </div>
                <Button type="button" variant="secondary" size="sm" className="self-start sm:mt-[22px]" onClick={() => void check()} disabled={busy}>
                  Check address
                </Button>
              </div>
              {probe && <div className={`${BOX} ${probe.ok ? TONE_BOX.success : TONE_BOX.warn}`}>{probe.message}</div>}
              <Input
                label="Enrolment code"
                aria-label="Enrolment code"
                placeholder="id.secret"
                value={form.token}
                onChange={(e) => set("token", e.target.value)}
                onBlur={() => setTouched(true)}
                error={errors.token}
                help="One-time. It is exchanged for a long-lived credential on this machine and never stored by the browser."
                mono
                spellCheck={false}
              />
            </>
          ) : (
            <Input
              label="Enrolment link"
              aria-label="Enrolment link"
              placeholder="https://observer.example.com/enrol/..."
              value={form.link}
              onChange={(e) => set("link", e.target.value)}
              onBlur={() => setTouched(true)}
              error={errors.link}
              mono
              spellCheck={false}
            />
          )}
          <ErrorBox message={err} />
          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" variant="primary" size="sm" iconLeft={LogIn} disabled={busy || (touched && !canSubmit(form))}>
              {busy ? "Enrolling..." : reenrol ? "Re-enrol" : "Enrol this machine"}
            </Button>
            <span className="text-[11px] text-fg-3">
              The server is checked first; the code is not spent if it cannot be reached.
            </span>
          </div>
        </form>
      )}
    </div>
  );
}

// IdPFlow is `observer enroll --idp`: show the code and the sign-in URL, then
// poll at the server's cadence until the approval enrols the machine.
function IdPFlow({
  post,
  orgUrl,
  setOrgUrl,
  onEnrolled,
}: {
  post: Post;
  orgUrl: string;
  setOrgUrl: (v: string) => void;
  onEnrolled: (o: EnrolOutcome) => void;
}) {
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [start, setStart] = useState<IdPStart | null>(null);
  const [state, setState] = useState<IdPPoll["status"] | null>(null);
  const [copied, setCopied] = useState(false);
  const timer = useRef<number | null>(null);
  const urlErr = touched ? formErrors({ method: "idp", orgUrl, token: "", link: "" }).orgUrl : undefined;

  useEffect(
    () => () => {
      if (timer.current) window.clearTimeout(timer.current);
    },
    [],
  );

  function schedule(flowId: string, interval: number) {
    if (timer.current) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => void poll(flowId), pollDelayMs(interval));
  }

  async function poll(flowId: string) {
    try {
      const r = await post<IdPPoll>("/api/enrolment/idp/poll", { flow_id: flowId });
      setState(r.status);
      if (r.status === "pending") {
        schedule(flowId, r.interval);
        return;
      }
      setStart(null);
      if (r.status === "approved" && r.outcome) {
        onEnrolled(r.outcome);
        return;
      }
      setErr(r.message || IDP_STATUS_COPY[r.status]);
    } catch (e) {
      setErr(apiErrorMessage(e));
      setStart(null);
    }
  }

  async function begin(e: React.FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (formErrors({ method: "idp", orgUrl, token: "", link: "" }).orgUrl || busy) return;
    setBusy(true);
    setErr(null);
    try {
      const s = await post<IdPStart>("/api/enrolment/idp/start", { org_url: orgUrl.trim() });
      setStart(s);
      setState("pending");
      schedule(s.flow_id, s.interval);
    } catch (e2) {
      setErr(apiErrorMessage(e2));
    } finally {
      setBusy(false);
    }
  }

  function cancel() {
    if (timer.current) window.clearTimeout(timer.current);
    setStart(null);
    setState(null);
  }

  if (start) {
    return (
      <div className="space-y-3">
        <div className="text-fg-2">
          You need an active account on that organization first (redeem your sign-in invite and sign in once). Then
          open the page below, sign in if asked, and enter the code. A phone or another computer is fine.
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <code className="rounded-2 border border-line-2 bg-bg-3 px-3 py-1.5 font-mono text-[18px] tracking-[0.12em] text-fg-0">
            {start.user_code}
          </code>
          <Button
            size="sm"
            variant="secondary"
            iconLeft={copied ? Check : Copy}
            onClick={() => {
              void navigator.clipboard?.writeText(start.user_code);
              setCopied(true);
            }}
          >
            {copied ? "Copied" : "Copy code"}
          </Button>
          <a
            href={start.verification_uri}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 text-accent underline underline-offset-2"
          >
            Open sign-in page <ExternalLink size={12} />
          </a>
        </div>
        <div className="break-all font-mono text-[11px] text-fg-3">{start.verification_uri}</div>
        <div className="flex flex-wrap items-center gap-2 text-fg-3">
          <InlineLoading label={IDP_STATUS_COPY[state ?? "pending"]} />
          <span>The code is good for about {Math.max(1, Math.round(start.expires_in / 60))} minutes.</span>
          <Button size="sm" variant="ghost" onClick={cancel}>
            Cancel
          </Button>
        </div>
      </div>
    );
  }

  return (
    <form onSubmit={begin} className="space-y-3" autoComplete="off">
      <Input
        label="Organization server"
        aria-label="Organization server"
        placeholder="https://observer.example.com"
        value={orgUrl}
        onChange={(e) => {
          setOrgUrl(e.target.value);
          setErr(null);
        }}
        onBlur={() => setTouched(true)}
        error={urlErr}
        mono
        spellCheck={false}
        inputMode="url"
      />
      <ErrorBox message={err} />
      <Button type="submit" variant="primary" size="sm" iconLeft={LogIn} disabled={busy}>
        {busy ? "Starting..." : "Start sign-in"}
      </Button>
    </form>
  );
}

// OutcomeCard reports what an enrolment did, in the CLI's own terms.
function OutcomeCard({ outcome, pushLoop }: { outcome: EnrolOutcome; pushLoop: boolean }) {
  const { restart, restarting, error } = useDaemonRestart();
  return (
    <div className={`${BOX} ${TONE_BOX.success} space-y-2`}>
      <div className="flex flex-wrap items-center gap-2">
        {/* Finish line (D-665..D-669): Obs lands on a successful enrolment. */}
        <ObsLanding size={32} />
        <span className="font-medium text-fg-0">
          Enrolled in {orgDisplayLabel(outcome.org_display)} as {outcome.user_email}.
        </span>
        <Pill variant={outcome.managed ? "accent" : "neutral"} case="none">
          {tenancyLabel(outcome.tenancy)}
        </Pill>
      </div>
      <div className="break-words text-fg-2">
        Pushing to <span className="break-all font-mono">{outcome.org_server_url}</span>.
        {outcome.block_written && outcome.config_path && (
          <>
            {" "}
            Wrote the default [org_client] block to <span className="break-all font-mono">{outcome.config_path}</span>{" "}
            (share.full_content = {String(outcome.full_content)}: {outcome.share_summary}).
          </>
        )}
      </div>
      <Notes notes={outcome.notes} />
      {outcome.restart_required && !pushLoop && (
        <div className={`${BOX} ${TONE_BOX.warn} space-y-2`}>
          <div>
            This daemon started before the machine was enrolled, so its push loop is not running yet. Restart it to
            begin pushing on a timer. Push now below works without a restart.
          </div>
          <ConfirmButton
            variant="primary"
            armedVariant="primary"
            size="sm"
            iconLeft={RefreshCw}
            loading={restarting}
            armedNote="The daemon re-execs in place; a proxied session may drop one in-flight request."
            onConfirm={() => void restart()}
          >
            Restart daemon now
          </ConfirmButton>
          {error && <div className="text-danger">{error}</div>}
        </div>
      )}
    </div>
  );
}

// ConsentCard is the governance-grant consent screen: the same words the CLI
// prompt prints (internal/orgenrol), and an explicit Accept / Decline.
function ConsentCard({
  pending,
  post,
  onDecided,
}: {
  pending: PendingGrant;
  post: Post;
  onDecided: (d: GrantDecision) => void;
}) {
  const d = pending.disclosure;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function decide(accept: boolean) {
    setBusy(true);
    setErr(null);
    try {
      onDecided(await post<GrantDecision>("/api/enrolment/grant-decision", { offer_id: pending.offer_id, accept }));
    } catch (e) {
      setErr(apiErrorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      aria-label="Organization governance request"
      className="rounded-2 border border-accent/40 bg-bg-2 px-4 py-3 text-[12px]"
    >
      <div className="mb-2 font-medium text-fg-0">{d.intro}</div>
      <dl className="mb-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-fg-2">
        <dt className="text-fg-3">Organization</dt>
        <dd className="break-words">{orgDisplayLabelSentence(d.org_display)}</dd>
        <dt className="text-fg-3">Server</dt>
        <dd className="break-all font-mono">{d.server_url}</dd>
        {d.expires_at && (
          <>
            <dt className="text-fg-3">Expires</dt>
            <dd>{fmtDateTime(d.expires_at)} (after this, local settings apply again)</dd>
          </>
        )}
      </dl>
      <div className="mb-1 font-medium text-fg-1">If you accept, the organization may:</div>
      <ul className="mb-3 list-disc space-y-1.5 pl-5">
        {(d.may ?? []).map((l) => (
          <li key={l.token} className="text-fg-2">
            {l.text} <code className="break-all font-mono text-[10.5px] text-fg-3">({l.token})</code>
          </li>
        ))}
      </ul>
      {d.config_writes && d.config_writes.length > 0 && (
        <div className="mb-3">
          <div className="mb-1 font-medium text-fg-1">Accepting will also write to this machine's config.toml:</div>
          <ul className="space-y-0.5">
            {d.config_writes.map((w) => (
              <li key={w} className="break-all font-mono text-[11px] text-fg-2">
                {w}
              </li>
            ))}
          </ul>
          {d.config_writes_note && <div className="mt-1 text-fg-3">{d.config_writes_note}</div>}
        </div>
      )}
      <div className="mb-1 font-medium text-fg-1">It may NOT:</div>
      <ul className="mb-3 list-disc space-y-1 pl-5 text-fg-2">
        {(d.may_not ?? []).map((l) => (
          <li key={l}>{l}</li>
        ))}
      </ul>
      <ErrorBox message={err} />
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <Button variant="primary" size="sm" onClick={() => void decide(true)} disabled={busy}>
          Accept
        </Button>
        <Button variant="secondary" size="sm" onClick={() => void decide(false)} disabled={busy}>
          Decline
        </Button>
        <span className="text-[11px] text-fg-3">
          Declining keeps this machine enrolled and reporting, but not governed. This request expires{" "}
          {fmtDateTime(pending.expires_at)}.
        </span>
      </div>
    </section>
  );
}

function DecisionCard({ decision }: { decision: GrantDecision }) {
  return (
    <div className={`${BOX} ${TONE_BOX[DECISION_TONE[decision.status] ?? "info"]} space-y-1.5`}>
      <div>{decision.message}</div>
      <Notes notes={decision.notes} />
    </div>
  );
}

// EnrolledView is `observer org status` plus the actions: push now, raw
// payload, re-enrol, leave, the grant report, and the teammate invite.
function EnrolledView({
  ov,
  post,
  onReenrol,
  reenrolOpen,
  onChanged,
  onPoll,
  onLeft,
  children,
}: {
  ov: EnrolmentOverview;
  post: Post;
  onReenrol: () => void;
  reenrolOpen: boolean;
  // onChanged refreshes the overview after an action that moves its facts
  // (a push updates "Last push" and any pause notice).
  onChanged: () => void;
  // onPoll re-reads only the overview (Share history's progress).
  onPoll: () => void;
  onLeft: (r: LeaveReport) => void;
  children?: React.ReactNode;
}) {
  const [payloadOpen, setPayloadOpen] = useState(false);
  const [push, setPush] = useState<PushNowReport | null>(null);
  const [busy, setBusy] = useState<"push" | "leave" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [leaveOpen, setLeaveOpen] = useState(false);
  const share = shareModeLabel(ov.share_mode);

  async function pushNow() {
    setBusy("push");
    setErr(null);
    try {
      setPush(await post<PushNowReport>("/api/enrolment/push-now", {}));
      onChanged();
    } catch (e) {
      setErr(apiErrorMessage(e));
    } finally {
      setBusy(null);
    }
  }

  async function leaveOrg() {
    setBusy("leave");
    setErr(null);
    try {
      const report = await post<LeaveReport>("/api/enrolment/leave", {});
      setLeaveOpen(false);
      onLeft(report);
    } catch (e) {
      setErr(apiErrorMessage(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-4">
      <Stagger className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <StatCard label="Organization" icon={<MetricIcon metric="organisation" />} value={<Clip>{orgDisplayLabelSentence(ov.org_display)}</Clip>} />
        <StatCard label="You" icon={<MetricIcon metric="member" />} value={<Clip>{ov.user_email || "-"}</Clip>} sub={tenancyLabel(ov.tenancy)} />
        <StatCard label="Server" icon={<MetricIcon metric="server" />} value={<Mono>{ov.org_server_url || "-"}</Mono>} />
        <StatCard
          label="Credential store"
          icon={<MetricIcon metric="credentialStore" />}
          value={<Clip>{ov.credential_store || "-"}</Clip>}
          sub={ov.enrolled_at ? `enrolled ${fmtDateTime(ov.enrolled_at)}` : undefined}
        />
      </Stagger>

      {ov.daemon_credential_warning ? (
        <div className={`${BOX} ${TONE_BOX.warn}`} role="status">
          {ov.daemon_credential_warning}
        </div>
      ) : null}

      {ov.machine_proof_warning ? (
        <div className={`${BOX} ${TONE_BOX.warn}`} role="status">
          {ov.machine_proof_warning}
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant="primary" iconLeft={Send} onClick={() => void pushNow()} disabled={busy !== null}>
          {busy === "push" ? "Pushing..." : "Push now"}
        </Button>
        <Button size="sm" variant="secondary" onClick={() => setPayloadOpen(true)}>
          View raw push payload
        </Button>
        <Button size="sm" variant="secondary" onClick={onReenrol}>
          {reenrolOpen ? "Close re-enrol" : "Re-enrol"}
        </Button>
        <Button size="sm" variant="danger" iconLeft={LogOut} disabled={busy !== null} onClick={() => setLeaveOpen(true)}>
          Leave organization
        </Button>
      </div>
      <LeaveDialog
        open={leaveOpen}
        orgLabel={orgDisplayLabel(ov.org_display)}
        plan={ov.leave_plan}
        steps={ov.leave_steps}
        busy={busy === "leave"}
        error={leaveOpen ? err : null}
        onCancel={() => setLeaveOpen(false)}
        onConfirm={() => void leaveOrg()}
      />
      <ErrorBox message={err} />
      {push && (
        <div className={`${BOX} ${TONE_BOX[push.empty ? "info" : "success"]} space-y-1`}>
          <div className="font-medium">{push.message}</div>
          {push.notes?.map((n, i) => (
            <div key={i} className="break-words font-mono text-[11px]">
              {n.text}
            </div>
          ))}
        </div>
      )}
      {children}

      {ov.governance_warning && <div className={`${BOX} ${TONE_BOX.warn}`}>{ov.governance_warning}</div>}

      <div className={`${BOX} ${TONE_BOX.neutral} space-y-1.5`}>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">Share mode</span>
          <Pill variant={share.tone} case="none">
            {share.text}
          </Pill>
          {!ov.pushing_enabled && (
            <Pill variant="warn" case="none">
              pushing disabled in config
            </Pill>
          )}
          {ov.pushing_enabled && !ov.push_loop_running && (
            <Pill variant="warn" case="none">
              push loop starts after a restart
            </Pill>
          )}
        </div>
        {ov.share_mode_line && <div className="break-words text-fg-2">{ov.share_mode_line}</div>}
        {ov.target_actions && ov.target_actions.length > 0 && (
          <div className="text-fg-3">Per-action raw targets: {ov.target_actions.join(", ")}</div>
        )}
      </div>

      <PushPaused paused={ov.push_paused} />
      <LastPush push={ov.last_push} />
      <div className="px-1 text-[11.5px] text-fg-3">{pushCadenceLine(ov, fmtDateTime)}</div>
      <ScopeTable ov={ov} />
      <ShareHistoryCard ov={ov} post={post} onPoll={onPoll} onPushNow={() => void pushNow()} pushing={busy === "push"} />
      <ResyncCard post={post} onDone={onChanged} />
      <GrantPanel governed={ov.governed} />
      <InviteTeammate />
      <RawPayloadDrawer open={payloadOpen} onClose={() => setPayloadOpen(false)} />
    </div>
  );
}

function ScopeTable({ ov }: { ov: EnrolmentOverview }) {
  if (!ov.tables?.length) return null;
  const resends = ov.pending_resends ?? {};
  const resendTotal = Object.values(resends).reduce((a, b) => a + b, 0);
  return (
    <div className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2 text-[11.5px]">
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">What can be shared</div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[260px] text-left">
          <thead className="text-fg-3">
            <tr>
              <th className="py-1 pr-3 font-medium">Table</th>
              <th className="py-1 pr-3 text-right font-medium">Captured</th>
              <th className="py-1 text-right font-medium">Not yet shared</th>
            </tr>
          </thead>
          <tbody className="text-fg-2">
            {ov.tables.map((r) => (
              <tr key={r.table} className="border-t border-line-1">
                <td className="py-1 pr-3 font-mono">{r.table}</td>
                <td className="py-1 pr-3 text-right tabular-nums">{fmtInt(r.historical)}</td>
                <td className="py-1 text-right tabular-nums">{fmtInt(r.eligible)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {resendTotal > 0 && <div className="mt-1 text-fg-3">Changed rows queued to re-send: {fmtInt(resendTotal)}</div>}
      {(ov.pending_deletions ?? 0) + (ov.pending_manifests ?? 0) > 0 && (
        <div className="mt-1 text-fg-3">
          Deletions queued to propagate: {fmtInt(ov.pending_deletions ?? 0)} (session manifests:{" "}
          {fmtInt(ov.pending_manifests ?? 0)})
        </div>
      )}
      {ov.eligible_reason && <div className="mt-1 text-fg-3">Why nothing is waiting: {ov.eligible_reason}</div>}
    </div>
  );
}

// ShareHistoryCard is `observer org backfill --all [--confirm]` (T-159): the
// history captured before this machine enrolled is not shared until someone
// rewinds the push cursor. Check runs the CLI's dry run; the confirm rewinds;
// progress then follows the overview's "Not yet shared" counts as the push
// loop (or Push now) drains them.
function ShareHistoryCard({
  ov,
  post,
  onPoll,
  onPushNow,
  pushing,
}: {
  ov: EnrolmentOverview;
  post: Post;
  onPoll: () => void;
  onPushNow: () => void;
  pushing: boolean;
}) {
  const [preview, setPreview] = useState<ShareHistoryReport | null>(null);
  const [started, setStarted] = useState<number | null>(null);
  // observed: the overview has been re-read since the rewind (the copy held
  // at the moment of the rewind still says nothing is waiting).
  const [observed, setObserved] = useState(false);
  const [busy, setBusy] = useState<"check" | "share" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const waiting = eligibleNow(ov.tables);
  const progress = started === null ? null : shareHistoryProgress(started, waiting, observed);

  useEffect(() => {
    if (started !== null) setObserved(true);
  }, [ov]); // eslint-disable-line react-hooks/exhaustive-deps

  // While the history drains, re-read the overview every 5s instead of the
  // page's 30s cadence so the bar moves.
  useEffect(() => {
    if (!progress || progress.done) return;
    const id = window.setInterval(onPoll, 5000);
    return () => window.clearInterval(id);
  }, [progress?.done, started]); // eslint-disable-line react-hooks/exhaustive-deps

  async function run(confirm: boolean) {
    setBusy(confirm ? "share" : "check");
    setErr(null);
    try {
      const rep = await post<ShareHistoryReport>("/api/enrolment/share-history", { confirm });
      if (rep.rewound) {
        setObserved(false);
        setStarted(rep.eligible + rep.would_unlock);
        setPreview(null);
        onPoll();
      } else {
        setPreview(rep);
      }
    } catch (e) {
      setErr(apiErrorMessage(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-2 rounded-2 border border-line-1 bg-bg-2 px-3 py-2 text-[11.5px]">
      <div className="flex items-center gap-2">
        <History className="h-3.5 w-3.5 text-fg-3" aria-hidden />
        <span className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">Share history</span>
      </div>
      <div className="text-fg-2">
        Activity captured before this machine enrolled is not shared on its own: only new activity ships. Share
        history sends the older rows too, under the same share mode as everything else.
      </div>

      {progress ? (
        <div className="space-y-1.5" aria-live="polite">
          {/* A job with real progress (D-665..D-669): Obs rides the true ratio,
              never ahead, and lands into celebrate when nothing is waiting. */}
          <ObsJobRider ratio={progress.done ? 1 : progress.ratio} />
          <Meter ratio={progress.ratio} tone={progress.done ? "success" : "accent"} label="History sent" />
          <div className="text-fg-2">
            {progress.done
              ? `Done: ${fmtInt(started ?? 0)} rows were queued and nothing is waiting now.`
              : `${fmtInt(progress.sent)} of ${fmtInt(started ?? 0)} rows sent; ${fmtInt(waiting)} still waiting. The push loop sends a batch on every cycle.`}
          </div>
          {!progress.done && (
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="secondary" iconLeft={Send} onClick={onPushNow} disabled={pushing}>
                {pushing ? "Pushing..." : "Push a batch now"}
              </Button>
              {!ov.push_loop_running && (
                <span className="text-fg-3">The push loop is not running in this daemon, so use Push a batch now.</span>
              )}
            </div>
          )}
        </div>
      ) : preview ? (
        <div className="space-y-2">
          <div className="text-fg-1">{shareHistoryPreviewLine(preview)}</div>
          {preview.would_unlock > 0 && (
            <div role="note" className="rounded-2 border border-warn/40 bg-warn/10 px-2 py-1.5 text-fg-1">
              {shareHistoryCrossEnrolmentWarning(orgDisplayLabel(ov.org_display))}
            </div>
          )}
          {preview.would_unlock > 0 && (
            <ConfirmButton
              variant="primary"
              armedVariant="primary"
              size="sm"
              iconLeft={History}
              loading={busy === "share"}
              armedNote={`This sends ${fmtInt(preview.would_unlock)} older rows to ${orgDisplayLabel(ov.org_display)}, including any captured under a previous enrolment. It cannot be taken back once they are pushed.`}
              onConfirm={() => void run(true)}
            >
              Share history
            </ConfirmButton>
          )}
        </div>
      ) : (
        <Button size="sm" variant="secondary" iconLeft={History} loading={busy === "check"} onClick={() => void run(false)}>
          Check older history
        </Button>
      )}
      <ErrorBox message={err} />
    </div>
  );
}

// ResyncCard is `observer org resync [--confirm]` with its default window
// (T-642): re-send rows that changed on this machine after they were pushed,
// and reconcile rows it deleted, so the organization converges. Check is the
// CLI's dry run; the confirm queues, and the push loop drains the queue.
function ResyncCard({ post, onDone }: { post: Post; onDone: () => void }) {
  const [rep, setRep] = useState<ResyncReport | null>(null);
  const [busy, setBusy] = useState<"check" | "queue" | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function run(confirm: boolean) {
    setBusy(confirm ? "queue" : "check");
    setErr(null);
    try {
      const r = await post<ResyncReport>("/api/enrolment/resync", { confirm });
      setRep(r);
      if (r.confirmed) onDone();
    } catch (e) {
      setErr(apiErrorMessage(e));
    } finally {
      setBusy(null);
    }
  }

  const pending = rep && !rep.confirmed && (rep.queued > 0 || rep.manifests > 0);
  return (
    <div className="space-y-2 rounded-2 border border-line-1 bg-bg-2 px-3 py-2 text-[11.5px]">
      <div className="flex items-center gap-2">
        <RefreshCw className="h-3.5 w-3.5 text-fg-3" aria-hidden />
        <span className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">Re-send changed rows</span>
      </div>
      <div className="text-fg-2">
        If the organization shows older values than this machine (fewer tokens, a missing end time, a row this
        machine has since removed), re-send the recent rows that changed after they were pushed.
      </div>
      {rep && <div className={rep.confirmed ? "text-fg-1" : "text-fg-2"}>{resyncLine(rep)}</div>}
      <div className="flex flex-wrap items-center gap-2">
        {pending ? (
          <ConfirmButton
            variant="primary"
            armedVariant="primary"
            size="sm"
            iconLeft={RefreshCw}
            loading={busy === "queue"}
            armedNote="Queues the rows for the push loop. The organization keeps the newest version of each row."
            onConfirm={() => void run(true)}
          >
            Re-send
          </ConfirmButton>
        ) : (
          <Button size="sm" variant="secondary" iconLeft={RefreshCw} loading={busy === "check"} onClick={() => void run(false)}>
            Check for changed rows
          </Button>
        )}
      </div>
      <ErrorBox message={err} />
    </div>
  );
}

// GrantPanel is `observer org grant show`.
function GrantPanel({ governed }: { governed: boolean }) {
  const rep = useApi<GrantReport>("/api/enrolment/grant", undefined, [governed]);
  const g = rep.data;
  if (!g || g.state === "not_enrolled") return null;
  if (g.state === "ungoverned") {
    return (
      <div className={`${BOX} ${TONE_BOX.neutral}`}>
        <span className="font-medium text-fg-1">Not governed.</span> This machine granted no authority to the
        organization; your dashboard and settings are entirely local.
      </div>
    );
  }
  return (
    <section aria-label="Organization grant" className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2 text-[11.5px]">
      <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        What this organization can manage
      </div>
      <dl className="mb-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-fg-2">
        <dt className="text-fg-3">Granted to</dt>
        <dd className="break-all">
          {orgDisplayLabelSentence(g.org_display)}
        </dd>
        <dt className="text-fg-3">Granted at</dt>
        <dd>{g.granted_at}</dd>
        <dt className="text-fg-3">Expires</dt>
        <dd className="break-words">{g.expiry_line}</dd>
        <dt className="text-fg-3">Consent</dt>
        <dd className="break-words">{g.consent}</dd>
        <dt className="text-fg-3">Receipt</dt>
        <dd className="break-all font-mono text-[10.5px]">{g.receipt}</dd>
      </dl>
      <ul className="mb-2 space-y-1">
        {(g.authority ?? []).map((a) => (
          <li key={a.token} className="text-fg-2">
            <code className="break-all font-mono text-[10.5px] text-fg-1">{a.token}</code> {a.text}
          </li>
        ))}
      </ul>
      {g.content_line && <div className="mb-2 text-fg-2">Content: {g.content_line}</div>}
      {g.families && g.families.length > 0 && (
        <ul className="mb-2 space-y-0.5 text-fg-2">
          {g.families.map((f) => (
            <li key={f.family}>
              <span className="font-mono">{f.family}</span>:{" "}
              {!f.accepted
                ? "not accepted in config (extraction/enforcement for it will not flow)"
                : !f.preauthorized
                  ? "accepted; enforcement not preauthorized"
                  : "accepted and preauthorized"}
            </li>
          ))}
        </ul>
      )}
      <Notes notes={g.verification} />
      {g.pinned && g.pinned.length > 0 && (
        <div className="mt-2 text-fg-3">
          <div className="mb-0.5 font-medium text-fg-2">Pinned settings</div>
          {g.pinned.map((l, i) => (
            <div key={i} className="break-words">
              {l}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

// ReadOnlyEnrolment is the status view for a viewer who cannot manage: a
// paired remote device (the management routes are owner-local), or a process
// mode with no enrolment manager.
function ReadOnlyEnrolment({ reason }: { reason: "remote" | "process" }) {
  const status = useApi<EnrolmentStatus>("/api/enrolment/status", undefined, [], { refreshMs: 15000 });
  const data = status.data;
  return (
    <ChartState
      loading={status.loading && !data}
      error={status.error}
      denied={status.denied}
      deniedPermission={status.deniedPermission}
      empty={false}
      height={160}
    >
      <div className="space-y-4">
        <div className={`${BOX} ${TONE_BOX.info}`}>
          {reason === "remote"
            ? "Enrolment is managed from this machine's own dashboard (it writes this machine's config and keychain), so enrol, push and leave are not offered on a paired device."
            : "This dashboard process cannot change the enrolment. Open the dashboard served by the running daemon to enrol, push or leave."}
        </div>
        {data?.enrolled ? (
          <>
            <Stagger className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <StatCard label="Organization" icon={<MetricIcon metric="organisation" />} value={<Clip>{orgDisplayLabelSentence(data.org_display)}</Clip>} />
              <StatCard label="You" icon={<MetricIcon metric="member" />} value={<Clip>{data.user_email || "-"}</Clip>} />
              <StatCard label="Server" icon={<MetricIcon metric="server" />} value={<Mono>{data.org_server_url || "-"}</Mono>} />
              <StatCard
                label="Credential store"
                icon={<MetricIcon metric="credentialStore" />}
                value={<Clip>{data.credential_store || "-"}</Clip>}
                sub={data.enrolled_at ? `enrolled ${fmtDateTime(data.enrolled_at)}` : undefined}
              />
            </Stagger>
            <PushPaused paused={data.push_paused} />
            <RetentionHeld held={data.retention_held} />
            <LastPush push={data.last_push} />
          </>
        ) : (
          <div className="rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-4 py-3 text-[12px] text-fg-2">
            <div className="mb-1 font-medium text-fg-1">Not enrolled</div>
            This machine is not enrolled in an organization - nothing is shared.
          </div>
        )}
      </div>
    </ChartState>
  );
}

// PushPaused renders the OPEN oversized-batch circuit. It is deliberately the
// loudest thing on the page while it is up: the push loop is parked for an hour
// and nothing is reaching the org server, which is otherwise only inferable from
// a "failed" row in the push history. The copy names the actual cause and the
// three knobs that fix it (the honest-disabled-copy rule: say WHICH dependency
// is at fault, never a bare "unavailable").
function PushPaused({ paused }: { paused?: EnrolmentStatus["push_paused"] }) {
  if (!paused) return null;
  return (
    <div className="rounded-2 border border-danger/40 bg-danger/5 px-3 py-2 text-[11.5px]">
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.06em] text-danger">Pushes paused</div>
      <div className="text-fg-2">
        The composed rollup is larger than the accepted push limit, so nothing is reaching the org server. The loop
        retries at <b>{paused.until}</b>.
      </div>
      {paused.reason && <div className="mt-1 text-fg-3">{paused.reason}</div>}
      <div className="mt-1 text-fg-3">
        Raise <Mono>[org_client].max_push_bytes</Mono>, narrow <Mono>[org_client.scope]</Mono>, or turn off a large{" "}
        <Mono>[org_client.share]</Mono> tier. The org server enforces its own body limit too, so raising the
        node-side value alone may not be enough.
      </div>
    </div>
  );
}

// RetentionHeld renders the T-830 hold: node retention is keeping rows past
// max_age_days because the org server has not accepted them, so a stuck push
// shows here instead of the local database silently growing.
function RetentionHeld({ held }: { held?: EnrolmentStatus["retention_held"] }) {
  if (!held || held.rows <= 0) return null;
  return (
    <div className="rounded-2 border border-warn/40 bg-warn-soft px-3 py-2 text-[11.5px]">
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.06em] text-warn">Retention held</div>
      <div className="text-fg-2">
        Retention held <b>{fmtInt(held.rows)}</b> rows awaiting push ({fmtInt(held.actions)} actions,{" "}
        {fmtInt(held.sessions)} sessions). They are older than {held.max_age_days} days but the org server has not
        accepted them yet, so they stay on this machine until it does.
      </div>
      <div className="mt-1 text-fg-3">
        Check the last push below and <Mono>observer doctor</Mono>; the next retention pass after a successful push removes them.
      </div>
    </div>
  );
}

function LastPush({ push }: { push?: EnrolmentStatus["last_push"] }) {
  if (!push) {
    return (
      <div className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2 text-[11.5px] text-fg-3">
        No push yet - the first rollup is shared on the next push interval, or use Push now.
      </div>
    );
  }
  const ok = push.status === "ok";
  return (
    <div className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2 text-[11.5px]">
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">Last push</div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-fg-2">
        <span>
          status <b className={ok ? "text-success" : "text-danger"}>{push.status}</b>
        </span>
        <span>{fmtDateTime(push.pushed_at)}</span>
        <span>{fmtInt(push.row_count)} rows</span>
        <span>{fmtBytes(push.bytes)}</span>
        {push.error && <span className="text-danger">{push.error}</span>}
      </div>
    </div>
  );
}

// InviteTeammate is the loop-closing nudge: an enrolled developer can hand a
// teammate a one-time enrolment code without going through an admin - IF the
// org has enabled it ([server].member_invites on the org server).
//
// Every authority decision is the org server's. This component only asks; a
// refusal is rendered as honest copy naming the exact cause (the disabled-copy
// rule: say WHICH dependency is missing, never a bare "unavailable"):
//
//   403 - the org has not enabled member invites, and names the server key
//   404 - the teammate isn't a member yet (an invite is a handoff, not a signup)
//   429 - this developer's monthly allowance is spent
//   409 - this agent isn't enrolled
//
// The minted code is held in component state only, shown once, and cleared on
// reset - it is never written anywhere node-side.
function InviteTeammate() {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "working" | "done" | "err">("idle");
  const [message, setMessage] = useState("");
  const [invite, setInvite] = useState<EnrolmentInvite | null>(null);
  const [copied, setCopied] = useState(false);

  async function mint(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim()) return;
    setState("working");
    setMessage("");
    try {
      const res = await fetch("/api/enrolment/invite", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() }),
      });
      const body = await res.json().catch(() => ({}) as Record<string, string>);
      if (!res.ok) {
        setState("err");
        setMessage(body.message || `server returned ${res.status}`);
        return;
      }
      setInvite(body as EnrolmentInvite);
      setState("done");
    } catch (err) {
      setState("err");
      setMessage(err instanceof Error ? err.message : String(err));
    }
  }

  function reset() {
    setInvite(null);
    setEmail("");
    setState("idle");
    setMessage("");
    setCopied(false);
  }

  if (!open) {
    return (
      <div className="rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-4 py-3 text-[12px] text-fg-2">
        <span className="font-medium text-fg-1">Working in a team?</span> Invite a teammate who is already a member of
        this organization - they get a one-time enrolment code.{" "}
        <Button size="sm" variant="secondary" onClick={() => setOpen(true)}>
          Invite a teammate
        </Button>
      </div>
    );
  }

  return (
    <div className="rounded-2 border border-line-1 bg-bg-2 px-4 py-3 text-[12px]">
      <div className="mb-2 flex items-center justify-between">
        <div className="font-medium text-fg-1">Invite a teammate</div>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => {
            reset();
            setOpen(false);
          }}
        >
          Close
        </Button>
      </div>

      {invite ? (
        <div className="space-y-2">
          <div className="text-fg-2">
            One-time code for <b className="text-fg-1">{invite.user_email}</b>. It works once and expires{" "}
            {fmtDateTime(invite.expires_at)}. They can enter the server address and this code in Settings &gt;
            Enrolment on their own dashboard, or run the command below.
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 break-all rounded-2 border border-line-1 bg-bg-3 px-2 py-1 font-mono text-[11.5px] text-fg-1">
              {invite.command}
            </code>
            <Button
              size="sm"
              variant="secondary"
              iconLeft={copied ? Check : Copy}
              onClick={() => {
                void navigator.clipboard?.writeText(invite.command);
                setCopied(true);
              }}
            >
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <div className="text-warn">
            Shown once. Nothing here is stored on this machine - close this panel and the code is gone.
          </div>
          {invite.monthly_cap > 0 && (
            <div className="text-fg-3">
              {invite.minted_this_month} of {invite.monthly_cap} invites used this month.
            </div>
          )}
          <Button size="sm" variant="secondary" onClick={reset}>
            Invite someone else
          </Button>
        </div>
      ) : (
        <form onSubmit={mint} className="space-y-2">
          <div className="text-fg-3">
            They must already be a member of your organization - an invite hands over a code, it does not create an
            account.
          </div>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <Input
              type="email"
              aria-label="Teammate email"
              required
              value={email}
              onChange={(ev) => setEmail(ev.target.value)}
              placeholder="teammate@example.com"
              className="flex-1"
            />
            <Button type="submit" size="sm" variant="secondary" disabled={state === "working" || !email.trim()}>
              {state === "working" ? "Minting..." : "Mint invite"}
            </Button>
          </div>
          {state === "err" && (
            <div className="rounded-2 border border-danger/40 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
              {message}
            </div>
          )}
        </form>
      )}
    </div>
  );
}

// RawPayloadDrawer fetches /api/enrolment/last-payload and shows it verbatim -
// this is the exact JSON last shared with the org, so a developer can audit
// precisely what was sent.
function RawPayloadDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [text, setText] = useState<string>("");
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const res = await fetch("/api/enrolment/last-payload");
      const raw = await res.text();
      try {
        setText(JSON.stringify(JSON.parse(raw), null, 2));
      } catch {
        setText(raw);
      }
    } catch (e) {
      setText(`failed to load: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoading(false);
    }
  }

  // Lazy-load when the drawer opens.
  if (open && text === "" && !loading) void load();

  return (
    <SlideOver
      open={open}
      onClose={onClose}
      title="Last shared payload"
      subtitle="The exact rollup last pushed to your org - byte-for-byte."
      width={760}
    >
      <div className="p-4">
        {loading ? (
          <InlineLoading label="Loading payload" />
        ) : text === "null" || text === "" ? (
          <EmptyState variant="inline" illustration="inbox" illustrationSize={96} title="Nothing pushed yet" />
        ) : (
          <JsonPreview value={text} maxHeight={560} />
        )}
      </div>
    </SlideOver>
  );
}

// Clip renders an identity value (organization name, email) at a readable
// size on one line inside a stat card, with the whole value on hover or focus.
function Clip({ children }: { children: React.ReactNode }) {
  return (
    <Tooltip content={<span className="break-all">{children}</span>} maxWidth={420}>
      <span tabIndex={0} className="block cursor-help truncate text-[17px] font-semibold focus:outline-none">
        {children}
      </span>
    </Tooltip>
  );
}

// LeaveDialog is the confirm step for Leave: it names exactly what leaving
// will change, including which AI tool proxy settings are removed (only the
// ones this machine's enrolment wrote) and which are kept, in the same words
// `observer unenroll` prints.
function LeaveDialog({
  open,
  orgLabel,
  plan,
  steps,
  busy,
  error,
  onCancel,
  onConfirm,
}: {
  open: boolean;
  orgLabel: string;
  plan?: EnrolLeaveRoute[] | null;
  steps?: EnrolLeaveStep[] | null;
  busy: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const { remove, keep } = leavePlanGroups(plan);
  return (
    <Modal
      open={open}
      onClose={onCancel}
      dismissible={!busy}
      icon={LogOut}
      title={`Leave ${orgLabel}?`}
      footer={
        <div className="flex flex-wrap justify-end gap-2">
          <Button size="sm" variant="secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button size="sm" variant="danger" iconLeft={LogOut} loading={busy} onClick={onConfirm}>
            Leave organization
          </Button>
        </div>
      }
    >
      <div className="space-y-3 text-[12.5px] text-fg-2">
        <p>
          This clears this machine's organization credentials and any organization governance of this dashboard. Data
          already shared stays with the organization. Agent sessions keep working at every step, and this machine ends
          as a plain individual node with all of its local data and settings.
        </p>
        {steps && steps.length > 0 && (
          <section aria-label="What leaving retires" className="space-y-2">
            <div className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
              What leaving does, in order
            </div>
            <ol className="list-decimal space-y-1 pl-4">
              {steps.map((s) => (
                <li key={s.id} className="break-words">
                  <span className="text-fg-1">{s.conferred}</span>
                  <span className="text-fg-3"> : {s.retired}</span>
                </li>
              ))}
            </ol>
          </section>
        )}
        <section aria-label="AI tool proxy settings" className="space-y-2">
          <div className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">AI tool proxy settings</div>
          {remove.length === 0 && keep.length === 0 && (
            <p className="text-fg-3">No AI tool proxy settings will be changed.</p>
          )}
          {remove.length > 0 && (
            <div className={`${BOX} ${TONE_BOX.warn}`}>
              <div className="mb-1 font-medium">Will be removed</div>
              <ul className="list-disc space-y-1 pl-4">
                {remove.map((r) => (
                  <li key={r.tool} className="break-words">
                    {r.message}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {keep.length > 0 && (
            <div className={`${BOX} ${TONE_BOX.info}`}>
              <div className="mb-1 font-medium">Will be kept</div>
              <ul className="list-disc space-y-1 pl-4">
                {keep.map((r) => (
                  <li key={r.tool} className="break-words">
                    {r.message}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
        <ErrorBox message={error} />
      </div>
    </Modal>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return (
    <Tooltip content={<span className="break-all font-mono">{children}</span>} maxWidth={420}>
      <span tabIndex={0} className="block cursor-help truncate font-mono text-[13px] focus:outline-none">
        {children}
      </span>
    </Tooltip>
  );
}
