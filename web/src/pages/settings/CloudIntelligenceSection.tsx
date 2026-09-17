import CloudEvidenceSettingsEditor, { DEFAULT_EVIDENCE_SETTINGS, effectiveEvidenceSettings, evidenceSettingsError } from "./CloudEvidenceSettingsEditor";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Button,
  ChartShell,
  ConfirmButton,
  Input,
  JsonPreview,
  Pill,
  StatCard,
  Table,
  Toggle,
  Tooltip,
} from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { CloudEnrichmentSummary } from "@/components/CloudEnrichmentSummary";
import { pushToast } from "@/components/Toast";
import { useApi } from "@/lib/useApi";
import { fetchJSON, apiReason } from "@/lib/api";
import { fmtDateTime, fmtInt, fmtRelative } from "@/lib/format";
import {
  cloudDisable,
  cloudEnable,
  cloudFmtWhen,
  cloudOutputTail,
  cloudStateMeta,
  CLOUD_ENRICH_LEVEL_LABELS,
  CLOUD_PURPOSE_LABELS,
} from "@/lib/cloud";
import type { CloudPlanView, CloudStatusWithDigestPlan } from "@/lib/cloud";
import { markRestartPending } from "@/lib/restartPending";
import { CloudLedgerCard } from "./CloudLedgerCard";
import type {
  CloudActionResponse,
  CloudConfigView,
  CloudGrantsResponse,
  CloudLoginState,
  CloudLogoutResponse,
  CloudSignInView,
  CloudSyncState,
  EnrolmentStatus,
} from "@/lib/types";

// CloudIntelligenceSection is the Settings → Cloud Intelligence page.
//
// The surfaces, in this order:
//
//   1. Cloud account — the prominent sign-in surface (operator directive
//      2026-09-03). State pill, credential backend, a primary Sign in button
//      that POSTs /api/cloud/login (the daemon spawns `observer cloud login`
//      as a subprocess — the same consent-gated CLI, never an in-process
//      network call) and polls /api/cloud/login/state every 2 s, showing the
//      AuthKit link while it runs for when the automatic browser open does
//      not reach you; Sign out when signed in; and the honest inline error
//      when no WorkOS client id is configured. When signed in, a "Sync now"
//      button POSTs /api/cloud/sync (the daemon equivalent of
//      `observer cloud sync` — operator directive: every `observer cloud` CLI
//      verb needs a dashboard equivalent) and polls /api/cloud/sync/state
//      every 2 s, showing the run state and a collapsible output tail. This
//      card also carries the two egress PREFERENCES (auto-sync, auto-enrich)
//      as toggles — they govern what leaves the machine and when, so they
//      belong with the account, not in a raw settings grid.
//   2. Consent grants — every consent receipt on this device plus the
//      grant/revoke controls for each STANDING purpose (POST
//      /api/cloud/consent/grant|revoke — the dashboard equivalent of
//      `observer cloud consent grant|revoke`), read from GET
//      /api/cloud/consent/grants. A revoke needs an inline second click
//      ("Revoke - cancels anything queued under it"); a non-grantable
//      purpose shows locked with its honest reason rather than a disabled
//      control with no explanation.
//   3. Delete cloud account — the destructive `observer cloud delete-account`
//      equivalent, gated behind an inline two-step confirm, with a "keep the
//      hosted account, only clear this device" (--local-only) checkbox.
//   Both 2 and 3 render only when the action routes are wired (same
//   `actions_available` flag as Sign in/Sign out/Sync now above) — an
//   embedder without CloudCommandRunner has nothing to run these against.
//   4. Advanced (collapsed) — the deployment/connection knobs (WorkOS client
//      id, hosted base URL, callback port). Not user preferences; compiled-in
//      defaults in a shipped build, exposed here only for staging/self-host
//      (schema prominence = expert). Both surfaces edit ONE [cloud] form,
//      saved through the ONE config-write seam (PUT /api/config/section/cloud).
//   5. Activity — the store-derived status (receipts / outbox / results) and
//      the outbox-by-state table, node-local facts only.
//
// Nothing on this page talks to the hosted service directly: sign-in presence
// is a local keychain read the daemon performs through an injected seam, and
// every outbound action is the `observer cloud` CLI running as a child.
export function CloudIntelligenceSection() {
  const status = useApi<CloudStatusWithDigestPlan>("/api/cloud/status", undefined, [], {
    refreshMs: 15000,
  });
  const data = status.data;
  const settings = useCloudConfigForm();
  const actionsAvailable = !!data?.sign_in?.actions_available;
  const signedIn = !!data?.sign_in?.signed_in;

  // Enterprise-first gate: an org-enrolled node's sessions are excluded from
  // personal cloud enrichment (see CloudAccountCard's header comment). Lifted
  // to this level so both the account card and the new enable card share one
  // probe instead of two.
  const enrolment = useApi<EnrolmentStatus>("/api/enrolment/status", undefined, [], {
    refreshMs: 30000,
  });
  const orgEnrolled = !!enrolment.data?.enrolled;
  const orgLabel = enrolment.data?.org_name || enrolment.data?.org_id || "your organization";

  return (
    <div className="space-y-5">
      <CloudAccountCard
        signIn={data?.sign_in ?? null}
        loading={status.loading && !data}
        error={status.error}
        onChanged={status.reload}
        settings={settings}
        orgEnrolled={orgEnrolled}
        orgLabel={orgLabel}
      />

      {data && !orgEnrolled && <CloudEnrichmentSummary data={data} />}

      <CloudEnableCard
        data={data}
        signedIn={signedIn}
        actionsAvailable={actionsAvailable}
        orgEnrolled={orgEnrolled}
        orgLabel={orgLabel}
        onChanged={status.reload}
      />

      <CloudLedgerCard actionsAvailable={actionsAvailable} />

      <details className="rounded-3 border border-line-2 bg-bg-2">
        <summary className="cursor-pointer list-none px-4 py-2.5 text-[12px] font-medium text-fg-2 hover:text-fg-1">
          Advanced
        </summary>
        <div className="space-y-5 border-t border-line-2 px-4 py-3">
          <CloudConsentGrantsCard actionsAvailable={actionsAvailable} />
          <CloudDeleteAccountCard actionsAvailable={actionsAvailable} onDeleted={status.reload} />
          <CloudAdvancedSettings settings={settings} />
        </div>
      </details>

      <ChartShell
        title="Cloud activity"
        sub="Optional signed-in personal enrichment (Signed-in Free). Every local Observer feature works fully without this. Node-local state only: consent receipts, the send outbox by state, and synced enrichment results. Uploads and result pulls run through `observer cloud sync` (manually, or on the schedule below when auto-sync is on)."
      >
        <ChartState
          loading={status.loading && !data}
          error={status.error}
          empty={false}
          height={120}
        >
          {data && <StatusBody data={data} />}
        </ChartState>
      </ChartShell>

      {data && data.active && <OutboxTable data={data} />}
    </div>
  );
}

// ---------- Cloud account (sign-in) ----------

type AccountPhase = "signed_in" | "signed_out" | "signing_in" | "unknown";

function accountPhase(si: CloudSignInView | null, login: CloudLoginState | null): AccountPhase {
  if (login?.running || si?.login_running) return "signing_in";
  if (!si || !si.known) return "unknown";
  return si.signed_in ? "signed_in" : "signed_out";
}

const PHASE_META: Record<AccountPhase, { label: string; variant: "success" | "neutral" | "info" | "warn" }> = {
  signed_in: { label: "Signed in", variant: "success" },
  signed_out: { label: "Not signed in", variant: "neutral" },
  signing_in: { label: "Signing in…", variant: "info" },
  unknown: { label: "Sign-in state unknown", variant: "warn" },
};

const CLIENT_ID_HINT = "Set [cloud].workos_client_id or WORKOS_CLIENT_ID";

function CloudAccountCard({
  signIn,
  loading,
  error,
  onChanged,
  settings,
  orgEnrolled,
  orgLabel,
}: {
  signIn: CloudSignInView | null;
  loading: boolean;
  error: Error | null;
  onChanged: () => void;
  settings: CloudConfigForm;
  orgEnrolled: boolean;
  orgLabel: string;
}) {
  const [login, setLogin] = useState<CloudLoginState | null>(null);
  const [busy, setBusy] = useState<"login" | "logout" | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [logoutMsg, setLogoutMsg] = useState<string | null>(null);
  const finishedRef = useRef(false);

  // "Sync now" — the dashboard equivalent of `observer cloud sync`. Own busy/
  // error/run state, independent of the login state machine above (the two
  // are mutually exclusive server-side, not client-side).
  const [sync, setSync] = useState<CloudSyncState | null>(null);
  const [syncBusy, setSyncBusy] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);
  const syncFinishedRef = useRef(false);

  // Enterprise-first gate: an org-enrolled node's sessions are stamped
  // authority='org' and are excluded from personal cloud enrichment
  // (internal/store/dataauthority.go, internal/cloudevidence) — a personal
  // sign-in here would complete but enrich nothing, and the backend refuses
  // it with 409 anyway. orgEnrolled/orgLabel are lifted to the page level
  // (CloudIntelligenceSection) so this card and the "Turn on Cloud
  // Intelligence" card share one probe. A failed or still-loading probe
  // resolves orgEnrolled=false there so it never hard-blocks a legitimate
  // personal sign-in.
  // onChanged (useApi's reload) is a fresh closure every render; hold it in a
  // ref so the polling effect below keys on `running` alone and never
  // re-arms its interval on each state update.
  const onChangedRef = useRef(onChanged);
  onChangedRef.current = onChanged;

  // Poll the login state every 2 s while a sign-in runs. The daemon reports
  // the AuthKit URL as soon as the child prints it and the outcome when the
  // child exits; on finish we refresh the status so the pill flips.
  const running = !!login?.running || !!signIn?.login_running;
  useEffect(() => {
    if (!running) return;
    let stopped = false;
    const tick = async () => {
      try {
        const st = await fetchJSON<CloudLoginState>("/api/cloud/login/state");
        if (stopped) return;
        setLogin((prev) => (prev && JSON.stringify(prev) === JSON.stringify(st) ? prev : st));
        if (st.finished && !finishedRef.current) {
          finishedRef.current = true;
          onChangedRef.current();
          pushToast(st.message || (st.ok ? "Signed in" : "Sign-in failed"), st.ok ? "success" : "danger");
        }
      } catch (e) {
        if (!stopped) setActionError(apiReason(e));
      }
    };
    void tick();
    const id = window.setInterval(() => void tick(), 2000);
    return () => {
      stopped = true;
      window.clearInterval(id);
    };
  }, [running]);

  const startLogin = useCallback(async () => {
    setActionError(null);
    setLogoutMsg(null);
    setBusy("login");
    finishedRef.current = false;
    try {
      const st = await fetchJSON<CloudLoginState>("/api/cloud/login", undefined, { method: "POST" });
      setLogin(st);
      if (st.finished && !st.running) {
        finishedRef.current = true;
        onChanged();
      }
    } catch (e) {
      setActionError(apiReason(e));
    } finally {
      setBusy(null);
    }
  }, [onChanged]);

  // Poll the sync state every 2 s while a sync runs. finished ⇔ `ok` has been
  // set (present, non-null) — the backend never emits a `finished` flag,
  // relying on `ok: bool|null` to carry that.
  const syncRunning = !!sync?.running;
  useEffect(() => {
    if (!syncRunning) return;
    let stopped = false;
    const tick = async () => {
      try {
        const st = await fetchJSON<CloudSyncState>("/api/cloud/sync/state");
        if (stopped) return;
        setSync((prev) => (prev && JSON.stringify(prev) === JSON.stringify(st) ? prev : st));
        if (!st.running && typeof st.ok === "boolean" && !syncFinishedRef.current) {
          syncFinishedRef.current = true;
          onChangedRef.current();
          pushToast(
            st.ok ? "Cloud sync finished" : st.exit_error || "Cloud sync failed",
            st.ok ? "success" : "danger",
          );
        }
      } catch (e) {
        if (!stopped) setSyncError(apiReason(e));
      }
    };
    void tick();
    const id = window.setInterval(() => void tick(), 2000);
    return () => {
      stopped = true;
      window.clearInterval(id);
    };
  }, [syncRunning]);

  const startSync = useCallback(async () => {
    setSyncError(null);
    syncFinishedRef.current = false;
    setSyncBusy(true);
    try {
      const st = await fetchJSON<CloudSyncState>("/api/cloud/sync", undefined, { method: "POST" });
      setSync(st);
      if (!st.running && typeof st.ok === "boolean") {
        syncFinishedRef.current = true;
      }
    } catch (e) {
      setSyncError(apiReason(e));
    } finally {
      setSyncBusy(false);
    }
  }, []);

  const logout = useCallback(async () => {
    setActionError(null);
    setLogoutMsg(null);
    setBusy("logout");
    try {
      const res = await fetchJSON<CloudLogoutResponse>("/api/cloud/logout", undefined, { method: "POST" });
      setLogin(null);
      setLogoutMsg(res.message || (res.ok ? "Signed out." : "Sign-out failed."));
      pushToast(res.ok ? "Signed out - local credentials cleared" : res.message || "Sign-out failed", res.ok ? "success" : "danger");
      onChanged();
    } catch (e) {
      setActionError(apiReason(e));
    } finally {
      setBusy(null);
    }
  }, [onChanged]);

  const phase = accountPhase(signIn, login);
  const meta = PHASE_META[phase];
  const actionsAvailable = !!signIn?.actions_available;
  const clientIDMissing = !!signIn?.known && !signIn.client_id_configured;
  const canSignIn = actionsAvailable && phase !== "signing_in" && !clientIDMissing && busy === null && !orgEnrolled;
  const pillLabel = orgEnrolled ? "Managed" : meta.label;
  const pillVariant = orgEnrolled ? "info" : meta.variant;
  const signInDisabledTitle = orgEnrolled
    ? `Personal cloud sign-in is managed by ${orgLabel} and is unavailable on this node.`
    : undefined;

  return (
    <div className="rounded-3 border border-accent/40 bg-bg-2 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <div className="text-[13px] font-semibold text-fg-1">Cloud account</div>
            <Pill variant={pillVariant} className="normal-case">
              {pillLabel}
            </Pill>
          </div>
          <p className="mt-1 max-w-[62ch] text-[11.5px] leading-relaxed text-fg-3">
            Sign in with your SuperBased account to enable optional cloud enrichment.
            Signing in only stores a device-bound credential on this machine; nothing
            about your sessions leaves it until you grant consent for a purpose.
          </p>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[10.5px] text-fg-3">
            {signIn?.known && (
              <>
                <span>
                  Credential backend:{" "}
                  <span className="font-mono text-fg-2">{signIn.credential_backend || "-"}</span>
                </span>
                <span>
                  API token:{" "}
                  <span className="font-mono text-fg-2">{signIn.api_token_present ? "stored" : "none"}</span>
                </span>
                <span>
                  WorkOS sign-in:{" "}
                  <span className="font-mono text-fg-2">{signIn.workos_sign_in_present ? "stored" : "none"}</span>
                </span>
              </>
            )}
            {signIn && !signIn.known && signIn.error && (
              <span className="text-warn">Could not read the credential store: {signIn.error}</span>
            )}
            {!signIn && !loading && !error && (
              <span>
                Sign-in state is not available on this dashboard (no account seam wired - use{" "}
                <span className="font-mono">observer cloud status</span>).
              </span>
            )}
            {error && <span className="text-danger">{error.message}</span>}
          </div>
        </div>

        <div className="flex shrink-0 flex-col items-end gap-2">
          <div className="flex items-center gap-2">
            {phase !== "signed_in" && (
              <Button
                variant="primary"
                onClick={() => void startLogin()}
                disabled={!canSignIn}
                title={signInDisabledTitle}
              >
                {phase === "signing_in" ? "Signing in…" : busy === "login" ? "Starting…" : "Sign in"}
              </Button>
            )}
            {phase === "signed_in" && (
              <>
                <Button
                  size="sm"
                  variant="soft"
                  onClick={() => void startSync()}
                  disabled={!actionsAvailable || syncRunning || syncBusy || orgEnrolled}
                  title={orgEnrolled ? signInDisabledTitle : "Drain the outbox and pull enrichment results now (same as `observer cloud sync`)"}
                >
                  {syncRunning ? "Syncing…" : syncBusy ? "Starting…" : "Sync now"}
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => void startLogin()}
                  disabled={!canSignIn}
                  title={signInDisabledTitle || "Run the sign-in again (refreshes the stored WorkOS sign-in)"}
                >
                  Sign in again
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => void logout()}
                  disabled={!actionsAvailable || busy !== null || phase !== "signed_in"}
                >
                  {busy === "logout" ? "Signing out…" : "Sign out"}
                </Button>
              </>
            )}
            {phase !== "signed_in" && (
              <Button size="sm" variant="secondary" disabled title="Sign in first">
                Sync now
              </Button>
            )}
          </div>
          {!actionsAvailable && signIn && (
            <div className="max-w-[40ch] text-right text-[10.5px] text-fg-3">
              Sign in / Sign out are available when the dashboard runs under{" "}
              <span className="font-mono">observer start</span>; otherwise run{" "}
              <span className="font-mono">observer cloud login</span> in a terminal.
            </div>
          )}
        </div>
      </div>

      {orgEnrolled && (
        <div className="mt-3 rounded-2 border border-info/30 bg-info-soft px-3 py-2 text-[11.5px] text-fg-2">
          <div className="font-semibold text-info">Managed by {orgLabel}</div>
          <p className="mt-1 leading-relaxed">
            This node is enrolled in {orgLabel}. Personal cloud enrichment is managed by your
            organization and is unavailable here - sessions captured on this node are org-owned.
            Signing in personally does nothing on an enrolled node.
          </p>
        </div>
      )}

      {clientIDMissing && (
        <div className="mt-3 rounded-2 border border-warn/40 bg-warn-soft px-3 py-2 text-[11.5px] text-warn">
          <span className="font-semibold">No WorkOS client id is configured.</span> {CLIENT_ID_HINT}{" "}
          (the public OAuth client id, not a secret) to start a new sign-in - set it under{" "}
          <span className="font-semibold">Advanced</span> below. An existing signed-in credential keeps
          working without it.
        </div>
      )}

      {(phase === "signing_in" || (login && !login.finished)) && (
        <div className="mt-3 rounded-2 border border-info/30 bg-info-soft px-3 py-2 text-[11.5px] text-fg-2">
          <div className="font-medium text-info">A browser window should have opened to sign in.</div>
          {login?.auth_url ? (
            <div className="mt-1">
              If it did not, open the sign-in page yourself:{" "}
              <a
                href={login.auth_url}
                target="_blank"
                rel="noreferrer noopener"
                className="font-medium text-accent underline underline-offset-2"
              >
                Open sign-in page
              </a>
              <span className="text-fg-3"> (opens in a new tab; the callback returns to 127.0.0.1 on this machine).</span>
            </div>
          ) : (
            <div className="mt-1 text-fg-3">Waiting for the sign-in page URL…</div>
          )}
          <div className="mt-1 text-[10.5px] text-fg-3">
            The sign-in waits up to 5 minutes for you to finish in the browser.
          </div>
        </div>
      )}

      {login?.finished && (
        <div
          className={
            "mt-3 rounded-2 border px-3 py-2 text-[11.5px] " +
            (login.ok
              ? "border-success/30 bg-success-soft text-success"
              : "border-danger/30 bg-danger-soft text-danger")
          }
        >
          {login.message || (login.ok ? "Signed in." : "Sign-in did not complete.")}
        </div>
      )}

      {logoutMsg && (
        <div className="mt-3 rounded-2 border border-line-2 bg-bg-3/40 px-3 py-2 text-[11.5px] text-fg-2">
          {logoutMsg}
        </div>
      )}

      {actionError && (
        <div className="mt-3 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
          {actionError}
        </div>
      )}

      {syncRunning && (
        <div className="mt-3 rounded-2 border border-info/30 bg-info-soft px-3 py-2 text-[11.5px] text-fg-2">
          <div className="font-medium text-info">Syncing… draining the outbox and pulling results.</div>
        </div>
      )}

      {!syncRunning && sync && typeof sync.ok === "boolean" && (
        <div
          className={
            "mt-3 rounded-2 border px-3 py-2 text-[11.5px] " +
            (sync.ok
              ? "border-success/30 bg-success-soft text-success"
              : "border-danger/30 bg-danger-soft text-danger")
          }
        >
          <div>
            {sync.ok
              ? `Synced${sync.finished_at ? " at " + fmtDateTime(sync.finished_at) : ""}.`
              : sync.exit_error || "Cloud sync failed."}
          </div>
          {sync.tail && (
            <details className="mt-1.5">
              <summary className="cursor-pointer text-[10.5px] text-fg-3 hover:text-fg-2">
                Output
              </summary>
              <div className="mt-1">
                <JsonPreview value={sync.tail} maxHeight={160} />
              </div>
            </details>
          )}
        </div>
      )}

      {syncError && (
        <div className="mt-3 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
          {syncError}
        </div>
      )}

      <CloudPreferences settings={settings} orgEnrolled={orgEnrolled} />
    </div>
  );
}

// ---------- Turn on Cloud Intelligence ----------

const CLOUD_ENABLE_SWITCH1_LABEL = "Name and tag my sessions";
const CLOUD_ENABLE_SWITCH1_DESC =
  "Uses the structural summary and up to one user prompt, as configured below, plus a daily activity summary.";
const CLOUD_ENABLE_SWITCH2_LABEL =
  "Include more user and assistant messages";
const CLOUD_ENABLE_SWITCH2_DESC =
  "Use the message counts and evidence limits below to describe the session and suggest a next step. Every send is listed under What we sent.";
const CLOUD_ENABLE_SWITCH3_LABEL = "Enrich sessions automatically";
const CLOUD_ENABLE_SWITCH3_DESC =
  "Use your allowance for eligible new sessions, longest-waiting first. Turn this off to choose sessions yourself from the Sessions page. Save below to apply.";

// EnableSwitchRow is a Toggle + label + description row shared by both the
// "Turn on" draft state and the live/on state of CloudEnableCard, so the
// three switches read identically in either state.
function EnableSwitchRow({
  on,
  onChange,
  disabled,
  label,
  description,
}: {
  on: boolean;
  onChange?: (next: boolean) => void;
  disabled?: boolean;
  label: string;
  description: string;
}) {
  return (
    <div className="space-y-1">
      <Toggle
        on={on}
        onChange={onChange}
        disabled={disabled}
        label={<span className="font-medium text-fg-2">{label}</span>}
      />
      <p className="pl-[42px] text-[10.5px] leading-snug text-fg-4">{description}</p>
    </div>
  );
}

// CloudDisclosure renders the ProviderPostureDisclosure verbatim, followed by
// the Privacy Policy link and a "What leaves this machine" link that scrolls
// to the ledger card below (id="cloud-ledger" — see CloudLedgerCard.tsx).
function CloudDisclosure({ disclosure }: { disclosure: string }) {
  function scrollToLedger(ev: React.MouseEvent) {
    ev.preventDefault();
    document.getElementById("cloud-ledger")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  if (!disclosure) return null;
  return (
    <p className="mt-3 text-[10.5px] leading-relaxed text-fg-4">
      {disclosure}{" "}
      <a
        href="https://superbased.app/privacy"
        target="_blank"
        rel="noreferrer"
        className="font-medium text-accent hover:text-accent-strong"
      >
        Privacy Policy
      </a>
      {" · "}
      <a
        href="#cloud-ledger"
        onClick={scrollToLedger}
        className="font-medium text-accent hover:text-accent-strong"
      >
        What leaves this machine
      </a>
    </p>
  );
}

// CLOUD_PLAN_PORTAL_BILLING_URL is where the "Manage plan" link points — the
// same URL CloudDigestCard's locked-state upsell button uses, so the two
// surfaces never disagree about where to send someone.
const CLOUD_PLAN_PORTAL_BILLING_URL = "https://cloud.superbased.app/portal/billing";

// CloudPlanLine renders the account plan the most recent sync observed
// (value-upgrade plan §W5) — a quiet upsell line, never a modal or a nag.
// `plan` null (no sync has ever reported one, or every usage fetch so far
// has failed) renders the honest "unknown until the next sync" line rather
// than fabricating a plan.
function CloudPlanLine({ plan }: { plan: CloudPlanView | null }) {
  if (!plan) {
    return (
      <p className="mt-1.5 text-[11px] leading-relaxed text-fg-3">
        Plan: unknown until the next sync
      </p>
    );
  }
  const label = plan.label || plan.name;
  const daily = plan.daily_cap != null ? String(plan.daily_cap) : "unknown";
  const monthly = plan.monthly_cap != null ? String(plan.monthly_cap) : "unknown";
  const digestWeekly =
    plan.digest_weekly === null
      ? "unknown"
      : plan.digest_weekly
        ? "included"
        : "Plus only";
  const retention =
    plan.results_retention_days != null
      ? `${plan.results_retention_days} days`
      : "unknown";
  return (
    <p className="mt-1.5 text-[11px] leading-relaxed text-fg-3">
      Plan: {label} - {daily}/day, {monthly}/month - weekly digests{" "}
      {digestWeekly} - results kept {retention}{" "}
      <a
        href={CLOUD_PLAN_PORTAL_BILLING_URL}
        target="_blank"
        rel="noreferrer"
        className="font-medium text-accent hover:text-accent-strong"
      >
        Manage plan
      </a>
    </p>
  );
}

// CloudEnableCard is the "Turn on Cloud Intelligence" card (plan of record
// W2): the developer-facing standing INTENT for per-session enrichment
// (internal/store/cloudpolicy.go's cloud_enrich_policy row), distinct from a
// consent receipt — this card only sets which level background/one-click
// enrichment is allowed to run at, never authorizes an upload by itself. It
// reads `policy` off GET /api/cloud/status and writes through
// POST /api/cloud/enable | /api/cloud/disable (the dashboard equivalents of
// `observer cloud enable|disable`), run as the same consent-gated CLI
// subprocess every other action on this page uses.
function CloudEnableCard({
  data,
  signedIn,
  actionsAvailable,
  orgEnrolled,
  orgLabel,
  onChanged,
}: {
  data: CloudStatusWithDigestPlan | null;
  signedIn: boolean;
  actionsAvailable: boolean;
  orgEnrolled: boolean;
  orgLabel: string;
  onChanged: () => void;
}) {
  const policy = data?.policy ?? null;
  const isOn = !!policy && policy.level !== "off";

  // All changes stay local until the operator clicks Turn on or Save.
  // Refresh the draft after a policy write succeeds.
  const [draftExcerpts, setDraftExcerpts] = useState(false);
  const [draftBackground, setDraftBackground] = useState(true);
  const [draftEvidence, setDraftEvidence] = useState(DEFAULT_EVIDENCE_SETTINGS);
  useEffect(() => {
    setDraftExcerpts(policy?.level === "excerpts");
    setDraftBackground(policy?.background ?? true);
    setDraftEvidence(policy?.evidence_settings ?? DEFAULT_EVIDENCE_SETTINGS);
  }, [policy?.updated_at]);
  const effectiveEvidence = effectiveEvidenceSettings(draftEvidence, draftExcerpts);
  const evidenceInvalid = !!evidenceSettingsError(effectiveEvidence);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function doEnable(withExcerpts: boolean, background: boolean) {
    setError(null);
    setBusy(true);
    try {
      const res = await cloudEnable(withExcerpts, background, effectiveEvidenceSettings(draftEvidence, withExcerpts));
      if (!res.ok) {
        setError(
          res.exit_error || cloudOutputTail(res.output) || "Turning on Cloud Intelligence failed.",
        );
        return;
      }
      pushToast("Cloud Intelligence is on.", "success");
      onChanged();
    } catch (e) {
      setError(apiReason(e));
    } finally {
      setBusy(false);
    }
  }

  async function doDisable() {
    setError(null);
    setBusy(true);
    try {
      const res = await cloudDisable();
      if (!res.ok) {
        setError(
          res.exit_error || cloudOutputTail(res.output) || "Turning off Cloud Intelligence failed.",
        );
        return;
      }
      pushToast("Cloud Intelligence is off.", "success");
      onChanged();
    } catch (e) {
      setError(apiReason(e));
    } finally {
      setBusy(false);
    }
  }

  if (orgEnrolled) {
    return (
      <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
        <div className="text-[13px] font-semibold text-fg-1">Turn on Cloud Intelligence</div>
        <div className="mt-3 rounded-2 border border-info/30 bg-info-soft px-3 py-2 text-[11.5px] text-fg-2">
          <div className="font-semibold text-info">Managed by {orgLabel}</div>
          <p className="mt-1 leading-relaxed">
            This node is enrolled in {orgLabel}. Personal cloud enrichment is managed by your
            organization and is unavailable here.
          </p>
        </div>
      </div>
    );
  }

  if (!signedIn) {
    return (
      <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
        <div className="text-[13px] font-semibold text-fg-1">Turn on Cloud Intelligence</div>
        <p className="mt-1 text-[11.5px] text-fg-3">Sign in above to turn on Cloud Intelligence.</p>
      </div>
    );
  }

  const disclosure = data?.disclosure ?? "";
  const disabledTitle = !actionsAvailable
    ? "Available when the dashboard runs under `observer start`; otherwise run `observer cloud enable` / `observer cloud disable` in a terminal."
    : undefined;

  if (isOn) {
    const wantsExcerpts = draftExcerpts;
    return (
      <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
        <div className="text-[13px] font-semibold text-fg-1">Cloud Intelligence is on</div>
        <p className="mt-1 text-[11.5px] text-fg-3">
          {CLOUD_ENRICH_LEVEL_LABELS[policy!.level]} - background {policy!.background ? "on" : "off"}{" "}
          - since {cloudFmtWhen(policy!.updated_at)}.
        </p>

        <div className="mt-3 space-y-2.5">
          <EnableSwitchRow
            on
            disabled
            label={CLOUD_ENABLE_SWITCH1_LABEL}
            description={CLOUD_ENABLE_SWITCH1_DESC}
          />
          <EnableSwitchRow
            on={wantsExcerpts}
            disabled={busy || !actionsAvailable}
            onChange={setDraftExcerpts}
            label={CLOUD_ENABLE_SWITCH2_LABEL}
            description={CLOUD_ENABLE_SWITCH2_DESC}
          />
          <EnableSwitchRow
            on={draftBackground}
            disabled={busy || !actionsAvailable}
            onChange={setDraftBackground}
            label={CLOUD_ENABLE_SWITCH3_LABEL}
            description={CLOUD_ENABLE_SWITCH3_DESC}
          />
        </div>

        <CloudEvidenceSettingsEditor value={draftEvidence} excerpts={draftExcerpts} disabled={busy || !actionsAvailable} onChange={setDraftEvidence} />
        <Button
          variant="primary"
          className="mt-3"
          disabled={busy || !actionsAvailable || evidenceInvalid}
          onClick={() => void doEnable(draftExcerpts, draftBackground)}
        >
          {busy ? "Saving…" : "Save enrichment settings"}
        </Button>

        <p className="mt-3 text-[11px] leading-relaxed text-fg-3">
          Results appear on each session's header and in the Sessions list once enrichment
          returns. While the hosted provider is still being enabled, a queued session stays
          queued - nothing is lost and nothing is invented.
        </p>
        <p className="mt-1.5 text-[11px] leading-relaxed text-fg-3">
          {data?.last_sync
            ? `Last sync: ${cloudFmtWhen(data.last_sync.finished_at)} - ${data.last_sync.sent} sent, ${data.last_sync.waiting_provider} waiting on provider, ${data.last_sync.results} results`
            : "Last sync: no sync yet"}
          {data?.provider_state === "waiting" &&
            " - the hosted provider is not accepting jobs yet."}
        </p>
        <CloudPlanLine plan={data?.plan ?? null} />

        <CloudDisclosure disclosure={disclosure} />

        <div className="mt-3">
          <ConfirmButton
            onConfirm={() => void doDisable()}
            variant="secondary"
            armedVariant="danger"
            timeoutMs={8000}
            confirmLabel="Click again to turn off"
            disabled={!actionsAvailable}
            loading={busy}
            title={disabledTitle}
          >
            Turn off
          </ConfirmButton>
        </div>

        {error && (
          <div className="mt-3 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
            {error}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
      <div className="text-[13px] font-semibold text-fg-1">Turn on Cloud Intelligence</div>
      <p className="mt-1 max-w-[62ch] text-[11.5px] leading-relaxed text-fg-3">
        After you turn this on, each session you finish is named and tagged for you in the
        background, a few minutes after it ends. You can turn it off here at any time.
      </p>

      <div className="mt-3 space-y-2.5">
        <EnableSwitchRow
          on
          disabled
          label={CLOUD_ENABLE_SWITCH1_LABEL}
          description={CLOUD_ENABLE_SWITCH1_DESC}
        />
        <EnableSwitchRow
          on={draftExcerpts}
          onChange={setDraftExcerpts}
          disabled={busy}
          label={CLOUD_ENABLE_SWITCH2_LABEL}
          description={CLOUD_ENABLE_SWITCH2_DESC}
        />
        <EnableSwitchRow
          on={draftBackground}
          onChange={setDraftBackground}
          disabled={busy}
          label={CLOUD_ENABLE_SWITCH3_LABEL}
          description={CLOUD_ENABLE_SWITCH3_DESC}
        />
      </div>

      <CloudEvidenceSettingsEditor value={draftEvidence} excerpts={draftExcerpts} disabled={busy || !actionsAvailable} onChange={setDraftEvidence} />

      <CloudDisclosure disclosure={disclosure} />

      <div className="mt-3">
        <Button
          variant="primary"
          onClick={() => void doEnable(draftExcerpts, draftBackground)}
          disabled={busy || !actionsAvailable || evidenceInvalid}
          title={disabledTitle}
        >
          {busy ? "Turning on…" : "Turn on"}
        </Button>
      </div>

      {error && (
        <div className="mt-3 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
          {error}
        </div>
      )}
    </div>
  );
}

// ---------- Consent grants ----------

// CloudConsentGrantsCard is the dashboard equivalent of `observer cloud
// consent grant|revoke|list`: every consent receipt already on this device,
// plus grant/revoke controls for each STANDING-grantable purpose. Renders
// nothing when the action routes aren't wired (actionsAvailable false) — the
// hooks below still run every render (React rules of hooks); only the
// endpoint they hit changes to `null` (useApi no-ops on a null path).
function CloudConsentGrantsCard({ actionsAvailable }: { actionsAvailable: boolean }) {
  const grants = useApi<CloudGrantsResponse>(
    actionsAvailable ? "/api/cloud/consent/grants" : null,
    undefined,
    [actionsAvailable],
    { refreshMs: 20000 },
  );
  const [busyPurpose, setBusyPurpose] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revokeArmed, setRevokeArmed] = useState<string | null>(null);

  // Auto-disarm the revoke confirm after a few seconds so a stray later click
  // elsewhere can never land on a still-armed "revoke" button.
  useEffect(() => {
    if (!revokeArmed) return;
    const id = window.setTimeout(() => setRevokeArmed(null), 6000);
    return () => window.clearTimeout(id);
  }, [revokeArmed]);

  async function runAction(purpose: string, verb: "grant" | "revoke") {
    setError(null);
    setBusyPurpose(purpose);
    try {
      const res = await fetchJSON<CloudActionResponse>(
        `/api/cloud/consent/${verb}`,
        undefined,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ purpose }),
        },
      );
      const label = CLOUD_PURPOSE_LABELS[purpose] ?? purpose;
      if (!res.ok) {
        setError(
          res.exit_error ||
            cloudOutputTail(res.output) ||
            `${verb === "grant" ? "Granting" : "Revoking"} ${label} failed.`,
        );
      } else {
        pushToast(
          verb === "grant"
            ? `Standing consent granted for ${label}.`
            : `Standing consent revoked for ${label}.`,
          "success",
        );
      }
      grants.reload();
    } catch (e) {
      setError(apiReason(e));
    } finally {
      setBusyPurpose(null);
    }
  }

  function onRevokeClick(purpose: string) {
    if (revokeArmed !== purpose) {
      setRevokeArmed(purpose);
      return;
    }
    setRevokeArmed(null);
    void runAction(purpose, "revoke");
  }

  if (!actionsAvailable) return null;

  const receipts = grants.data?.receipts ?? [];

  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
      <div className="text-[13px] font-semibold text-fg-1">Consent grants</div>
      <p className="mt-1 max-w-[66ch] text-[11.5px] leading-relaxed text-fg-3">
        Every consent receipt this device holds, and every purpose you can grant a standing
        (revocable any time) authorization for. A standing grant only lets a future Confirm and
        enrich skip the extra consent-recording step for that purpose - it never changes what is
        previewed or uploaded.
      </p>

      <ChartState loading={grants.loading && !grants.data} error={grants.error} empty={false} height={80}>
        {grants.data && (
          <div className="mt-3 space-y-3">
            <Table
              minWidth={520}
              head={
                <tr className="border-b border-line-2">
                  <th className="py-1.5 pl-1 font-medium">Purpose</th>
                  <th className="py-1.5 font-medium">Mode</th>
                  <th className="py-1.5 font-medium">Created</th>
                  <th className="py-1.5 font-medium">Review</th>
                  <th className="py-1.5 font-medium">State</th>
                </tr>
              }
            >
              {receipts.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-3 pl-1 text-fg-3">
                    No consent receipts yet.
                  </td>
                </tr>
              ) : (
                receipts.map((r) => (
                  <tr key={r.id} className="border-b border-line-1 last:border-b-0 align-top">
                    <td className="py-2 pl-1 text-fg-1">
                      {CLOUD_PURPOSE_LABELS[r.purpose] ?? r.purpose}
                    </td>
                    <td className="py-2 text-fg-2">
                      {r.mode === "standing" ? "Standing" : "Per-upload"}
                    </td>
                    <td className="py-2 font-mono text-[10.5px] text-fg-2">
                      {r.created_at ? fmtDateTime(r.created_at) : "-"}
                    </td>
                    <td className="py-2 font-mono text-[10.5px] text-fg-2">
                      {r.review_at ? fmtDateTime(r.review_at) : "-"}
                    </td>
                    <td className="py-2">
                      <Pill variant={r.live ? "success" : "neutral"}>
                        {r.live ? "live" : "revoked"}
                      </Pill>
                    </td>
                  </tr>
                ))
              )}
            </Table>

            <div className="space-y-1.5">
              <div className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
                Grant or revoke standing consent
              </div>
              <div className="flex flex-wrap gap-2">
                {(grants.data.grantable ?? []).map((g) => {
                  const label = CLOUD_PURPOSE_LABELS[g.purpose] ?? g.purpose;
                  const isBusy = busyPurpose === g.purpose;
                  if (!g.ok) {
                    return (
                      <span
                        key={g.purpose}
                        title={g.reason || "Not grantable on this device."}
                        className="cursor-help rounded-2 border border-line-2 bg-bg-3 px-2.5 py-1 text-[11px] text-fg-4"
                      >
                        {label} - locked
                      </span>
                    );
                  }
                  const live = receipts.some(
                    (r) => r.purpose === g.purpose && r.mode === "standing" && r.live,
                  );
                  if (live) {
                    const armed = revokeArmed === g.purpose;
                    return (
                      <Button
                        key={g.purpose}
                        size="sm"
                        variant={armed ? "danger" : "secondary"}
                        onClick={() => onRevokeClick(g.purpose)}
                        disabled={isBusy}
                        title={armed ? undefined : `Revoke standing consent for ${label}`}
                      >
                        {isBusy
                          ? "Working…"
                          : armed
                            ? "Revoke - cancels anything queued under it"
                            : `Revoke ${label}`}
                      </Button>
                    );
                  }
                  return (
                    <Button
                      key={g.purpose}
                      size="sm"
                      variant="soft"
                      onClick={() => void runAction(g.purpose, "grant")}
                      disabled={isBusy}
                    >
                      {isBusy ? "Working…" : `Grant ${label}`}
                    </Button>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </ChartState>

      {error && (
        <div className="mt-3 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
          {error}
        </div>
      )}
    </div>
  );
}

// ---------- Delete cloud account ----------

// CloudDeleteAccountCard is the dashboard equivalent of `observer cloud
// delete-account`: a destructive action behind an inline two-step confirm
// (never window.confirm - the confirm state and its warning copy render in
// the page). "Only clear this device" maps to --local-only, keeping the
// hosted account intact and only forgetting the local sign-in + node state.
function CloudDeleteAccountCard({
  actionsAvailable,
  onDeleted,
}: {
  actionsAvailable: boolean;
  onDeleted: () => void;
}) {
  const [localOnly, setLocalOnly] = useState(false);
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  useEffect(() => {
    if (!armed) return;
    const id = window.setTimeout(() => setArmed(false), 8000);
    return () => window.clearTimeout(id);
  }, [armed]);

  async function run() {
    if (!armed) {
      setArmed(true);
      setDone(null);
      setError(null);
      return;
    }
    setArmed(false);
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      const res = await fetchJSON<CloudActionResponse>(
        "/api/cloud/delete-account",
        undefined,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ local_only: localOnly }),
        },
      );
      if (!res.ok) {
        setError(res.exit_error || cloudOutputTail(res.output) || "Delete failed.");
        return;
      }
      const msg = localOnly
        ? "Local cloud state cleared - the hosted account is untouched."
        : "Cloud account deleted.";
      setDone(msg);
      pushToast(msg, "success");
      onDeleted();
    } catch (e) {
      setError(apiReason(e));
    } finally {
      setBusy(false);
    }
  }

  if (!actionsAvailable) return null;

  return (
    <div className="rounded-3 border border-danger/30 bg-bg-2 p-4">
      <div className="text-[13px] font-semibold text-fg-1">Delete cloud account</div>
      <p className="mt-1 max-w-[62ch] text-[11.5px] leading-relaxed text-fg-3">
        Permanently deletes your hosted cloud account and everything it holds - consent receipts,
        enrichment results, and the sign-in itself. This cannot be undone.
      </p>

      <label className="mt-3 flex items-center gap-2 text-[11.5px] text-fg-2">
        <input
          type="checkbox"
          checked={localOnly}
          onChange={(ev) => {
            setLocalOnly(ev.target.checked);
            setArmed(false);
          }}
          className="h-3.5 w-3.5 rounded-sm border-line-2"
        />
        Only clear this device (keep the hosted account)
      </label>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button
          variant="danger"
          onClick={() => void run()}
          disabled={busy}
          title={armed ? "Click again to confirm - this cannot be undone" : undefined}
        >
          {busy
            ? "Working…"
            : armed
              ? localOnly
                ? "Confirm - clear this device"
                : "Confirm - delete cloud account"
              : localOnly
                ? "Clear this device"
                : "Delete cloud account"}
        </Button>
        {armed && (
          <Button variant="secondary" onClick={() => setArmed(false)}>
            Cancel
          </Button>
        )}
      </div>

      {done && (
        <div className="mt-3 rounded-2 border border-success/30 bg-success-soft px-3 py-2 text-[11.5px] text-success">
          {done}
        </div>
      )}
      {error && (
        <div className="mt-3 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
          {error}
        </div>
      )}
    </div>
  );
}

// ---------- Cloud [cloud] form (shared by the preferences footer + Advanced) ----------

type ConfigEnvelope = { config?: { Cloud?: Partial<CloudConfigView> } };

const EMPTY_CLOUD: CloudConfigView = {
  BaseURL: "",
  LoginPort: 0,
  AutoSync: false,
  AutoSyncIntervalMinutes: 0,
  AutoEnrich: false,
  WorkOSClientID: "",
};


// CloudConfigForm is the shared editable [cloud] form. One form drives both
// the account card's egress toggles and the Advanced disclosure; save() sends
// the whole form to the ONE write seam regardless of which surface edited it.
type CloudConfigForm = {
  form: CloudConfigView;
  update: <K extends keyof CloudConfigView>(key: K, value: CloudConfigView[K]) => void;
  save: () => Promise<void>;
  dirty: boolean;
  saving: boolean;
  saveError: string | null;
  loading: boolean;
  error: Error | null;
  hasData: boolean;
};

function useCloudConfigForm(): CloudConfigForm {
  const cfg = useApi<ConfigEnvelope>("/api/config");
  const [form, setForm] = useState<CloudConfigView>(EMPTY_CLOUD);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Seed the form from the loaded config; re-seed on reload only while the
  // operator has not started editing (never clobber a half-typed value).
  useEffect(() => {
    if (!cfg.data || dirty) return;
    const c = cfg.data.config?.Cloud ?? {};
    setForm({
      BaseURL: c.BaseURL ?? "",
      LoginPort: c.LoginPort ?? 0,
      AutoSync: !!c.AutoSync,
      AutoSyncIntervalMinutes: c.AutoSyncIntervalMinutes ?? 0,
      AutoEnrich: !!c.AutoEnrich,
      WorkOSClientID: c.WorkOSClientID ?? "",
    });
  }, [cfg.data, dirty]);

  const update = <K extends keyof CloudConfigView>(key: K, value: CloudConfigView[K]) => {
    setForm((f) => ({ ...f, [key]: value }));
    setDirty(true);
  };

  const save = async () => {
    setSaving(true);
    setSaveError(null);
    try {
      const res = await fetchJSON<{ saved: boolean; restart_required: boolean }>(
        "/api/config/section/cloud",
        undefined,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            BaseURL: form.BaseURL,
            AutoSync: form.AutoSync,
            AutoSyncIntervalMinutes: Number(form.AutoSyncIntervalMinutes) || 0,
            AutoEnrich: form.AutoEnrich,
            WorkOSClientID: form.WorkOSClientID,
          }),
        },
      );
      if (!res.saved) {
        setSaveError("Save was not confirmed by the server.");
        return;
      }
      setDirty(false);
      cfg.reload();
      if (res.restart_required) markRestartPending("cloud");
      pushToast(
        res.restart_required
          ? "Cloud settings saved. Restart the daemon to apply the auto-sync schedule."
          : "Cloud settings saved.",
        "success",
      );
      // The status poll picks up client_id_configured on its next tick.
      window.dispatchEvent(new Event("dashboard-refresh"));
    } catch (e) {
      setSaveError(apiReason(e));
    } finally {
      setSaving(false);
    }
  };

  return {
    form,
    update,
    save,
    dirty,
    saving,
    saveError,
    loading: cfg.loading && !cfg.data,
    error: cfg.error,
    hasData: !!cfg.data,
  };
}

// CloudPreferences is the egress-preferences footer on the account card: the
// two toggles (auto-sync, auto-enrich) that govern what leaves the machine and
// when. They belong with the account, not in a raw settings grid.
function CloudPreferences({
  settings,
  orgEnrolled,
}: {
  settings: CloudConfigForm;
  orgEnrolled?: boolean;
}) {
  const { form, update, save, dirty, saving, saveError } = settings;
  return (
    <div className="mt-4 border-t border-line-2 pt-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Cloud preferences
        </div>
        <Button size="sm" variant="secondary" onClick={() => void save()} disabled={!dirty || saving}>
          {saving ? "Saving…" : "Save"}
        </Button>
      </div>
      {orgEnrolled && (
        <div className="mt-2 text-[10.5px] text-fg-4">
          These preferences do not take effect while this node is org-enrolled - personal cloud
          enrichment is unavailable here.
        </div>
      )}

      <div className="mt-2 grid grid-cols-1 gap-3 md:grid-cols-2">
        <div className="space-y-1.5 text-[11px] text-fg-3">
          <Toggle
            on={form.AutoSync}
            onChange={(next) => update("AutoSync", next)}
            label={<span>Sync automatically</span>}
          />
          <div className="text-[10.5px] text-fg-4">
            While <span className="font-mono">observer start</span> runs, spawn{" "}
            <span className="font-mono">observer cloud sync</span> on a schedule. Still
            consent-gated - nothing is sent without a live grant. Restart the daemon to apply.
          </div>
          {form.AutoSync && (
            <Input
              type="number"
              min={0}
              step={1}
              value={form.AutoSyncIntervalMinutes}
              onChange={(ev) => update("AutoSyncIntervalMinutes", Number(ev.target.value))}
              mono
              label="Interval (minutes)"
              help="0 = built-in default (60); otherwise at least 5."
            />
          )}
        </div>

        <div className="space-y-1.5 text-[11px] text-fg-3">
          <div className="text-[10.5px] text-fg-4">
            Background enrichment is controlled by the Turn on Cloud Intelligence card above.
          </div>
        </div>
      </div>

      {saveError && (
        <div className="mt-2 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11px] text-danger">
          {saveError}
        </div>
      )}
    </div>
  );
}

// CloudAdvancedSettings is the collapsed disclosure for the deployment/
// connection knobs (client id, hosted base URL, callback port). Not user
// preferences — compiled-in defaults in a shipped build; exposed only for
// staging/self-host (schema prominence = expert). Editing here dirties the
// same [cloud] form the preferences footer saves.
function CloudAdvancedSettings({ settings }: { settings: CloudConfigForm }) {
  const { form, update, save, dirty, saving, saveError, loading, error } = settings;
  return (
    <details className="rounded-3 border border-line-2 bg-bg-2">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-2.5 text-[12px] font-medium text-fg-2 hover:text-fg-1">
        <span>Advanced - connection &amp; sign-in config</span>
        <span className="text-[10.5px] font-normal text-fg-4">
          client id, hosted base URL, callback port
        </span>
      </summary>
      <div className="border-t border-line-2 px-4 py-3">
        <p className="mb-3 max-w-[66ch] text-[11px] leading-relaxed text-fg-3">
          Deployment defaults most people never change - the hosted service normally supplies
          these; set them only for staging or self-hosting. Environment variables
          (<span className="font-mono">SBO_CLOUD_BASE_URL</span>,{" "}
          <span className="font-mono">WORKOS_CLIENT_ID</span>) still take precedence over these
          values when set in the daemon's environment.
        </p>

        <ChartState loading={loading} error={error} empty={false} height={80}>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Input
              type="text"
              value={form.WorkOSClientID}
              onChange={(ev) => update("WorkOSClientID", ev.target.value)}
              placeholder="client_01…"
              spellCheck={false}
              mono
              label={
                <>
                  WorkOS client id{" "}
                  <span className="font-mono normal-case text-fg-4">[cloud].workos_client_id</span>
                </>
              }
              help="The public OAuth client id used to start a browser sign-in. Not a secret."
            />

            <Input
              type="url"
              value={form.BaseURL}
              onChange={(ev) => update("BaseURL", ev.target.value)}
              placeholder="https://cloud.superbased.app"
              spellCheck={false}
              mono
              label={
                <>
                  Cloud base URL <span className="font-mono normal-case text-fg-4">[cloud].base_url</span>
                </>
              }
              help="The hosted service every `observer cloud` command talks to. Must be an absolute http(s) URL."
            />
          </div>

          <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
            <div className="max-w-[52ch] text-[10.5px] text-fg-4">
              Login callback port <span className="font-mono">[cloud].login_port</span>:{" "}
              <span className="font-mono text-fg-3">{form.LoginPort || 9797}</span> - file-only
              (edit config.toml directly); it must match the redirect URI registered in WorkOS.
            </div>
            <Button size="sm" variant="secondary" onClick={() => void save()} disabled={!dirty || saving}>
              {saving ? "Saving…" : "Save"}
            </Button>
          </div>
        </ChartState>

        {saveError && (
          <div className="mt-3 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
            {saveError}
          </div>
        )}
      </div>
    </details>
  );
}


// ---------- Activity (store-derived status) ----------

function StatusBody({ data }: { data: CloudStatusWithDigestPlan }) {
  if (!data.active) {
    return (
      <div className="rounded-3 border border-dashed border-line-2 bg-bg-3/40 px-4 py-4 text-[12px] text-fg-2">
        <div className="mb-1 font-semibold text-fg-1">No cloud activity yet (optional)</div>
        <p className="leading-relaxed text-fg-3">
          No consent receipts, outbox items, or synced results exist on this
          node yet. Cloud Intelligence is entirely optional - every local
          feature (sessions, cost, cache, routing, analysis) works without it.
        </p>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-[11.5px] text-fg-3">
          <li>
            Sign in above, then enrich a session from its detail panel or with the{" "}
            <code className="rounded-1 border border-line-3 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1">
              observer cloud
            </code>{" "}
            CLI: <span className="font-mono">preview</span>,{" "}
            <span className="font-mono">consent</span>,{" "}
            <span className="font-mono">sync</span>.
          </li>
          <li>{data.descriptor}</li>
        </ul>
        <AutomationNote />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <StatCard label="Consent receipts" value={fmtInt(data.receipts_total)} />
        <StatCard label="Live receipts" value={fmtInt(data.receipts_live)} />
        <StatCard label="Outbox items" value={fmtInt(data.outbox_total)} />
        <StatCard label="Sendable now" value={fmtInt(data.sendable_count)} />
        <StatCard label="Synced results" value={fmtInt(data.results_total)} />
      </div>

      <div className="grid grid-cols-1 gap-3 text-[11.5px] sm:grid-cols-2">
        <div className="rounded-3 border border-line-2 bg-bg-2 px-3 py-2">
          <div className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
            Last result received
          </div>
          <div className="mt-0.5 font-mono text-fg-1">
            {data.last_result_at ? (
              <>
                {fmtDateTime(data.last_result_at)}{" "}
                <span className="font-sans text-fg-3">
                  ({fmtRelative(data.last_result_at)})
                </span>
              </>
            ) : (
              "-"
            )}
          </div>
          <div className="mt-0.5 text-[10.5px] text-fg-3">
            {data.has_synced
              ? "A result pull has advanced the cursor at least once."
              : "No results pulled yet (run `observer cloud sync`)."}
          </div>
        </div>

        <AllowanceCard known={data.allowance_known} />
      </div>

      <p className="text-[10.5px] text-fg-4">{data.descriptor}</p>
      <AutomationNote />
    </div>
  );
}

// AutomationNote states the W3b/R8 automation facts honestly: a suggested title
// needs only the first prompt while tags/description are a richer, separate
// consent; whether anything runs automatically is split across two cards now.
function AutomationNote() {
  return (
    <div className="rounded-3 border border-dashed border-line-2 bg-bg-3/30 px-3 py-2 text-[10.5px] leading-relaxed text-fg-3">
      <div className="mb-0.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        Titles &amp; automation
      </div>
      <p>
        A suggested <span className="font-medium text-fg-2">title</span> needs
        only your first prompt (the smallest disclosure); tags and a description
        unlock when you additionally share bounded excerpts.
      </p>
      <p className="mt-1">
        Automation is opt-in and off by default - whether background enrichment runs at all is
        the "Run in the background" switch on the Turn on Cloud Intelligence card above; syncing
        automatically (
        <code className="rounded-1 border border-line-3 bg-bg-3 px-1 py-0.5 font-mono text-[10px] text-fg-2">
          auto_sync
        </code>
        ) is on the Cloud account card above that. Consent still governs what leaves the machine.
      </p>
    </div>
  );
}

// AllowanceCard is an honest placeholder: the free-tier allowance is reported by
// the server at sync and is NOT stored node-side, so we show no number rather
// than a fabricated one.
function AllowanceCard({ known }: { known: boolean }) {
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 px-3 py-2">
      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        Free-tier allowance
        <Tooltip content="The daily/monthly allowance is reported by the server at sync and is not stored on this node. Nothing is shown until then - no fabricated numbers.">
          <span
            tabIndex={0}
            className="cursor-help rounded-full border border-line-3 px-1 text-[9px] text-fg-3 focus:outline-none"
          >
            ?
          </span>
        </Tooltip>
      </div>
      <div className="mt-0.5 text-fg-2">
        {known ? (
          "-"
        ) : (
          <span className="text-fg-3">Reported by the server at sync</span>
        )}
      </div>
    </div>
  );
}

function OutboxTable({ data }: { data: CloudStatusWithDigestPlan }) {
  const states = Object.keys(data.outbox_by_state).sort();
  if (states.length === 0) return null;
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
      <div className="mb-2 text-[12px] font-semibold text-fg-1">
        Outbox by state
      </div>
      <Table
        minWidth={420}
        head={
          <tr className="border-b border-line-2">
            <th className="py-1.5 pl-1 font-medium">State</th>
            <th className="py-1.5 text-right font-medium">Count</th>
            <th className="py-1.5 pl-4 font-medium">Meaning</th>
          </tr>
        }
      >
        {states.map((state) => {
          const meta = cloudStateMeta(state);
          return (
            <tr
              key={state}
              className="border-b border-line-1 last:border-b-0 align-top"
            >
              <td className="py-2 pl-1">
                <Pill variant={meta.variant}>{meta.label}</Pill>
              </td>
              <td className="py-2 text-right font-mono tabular-nums text-fg-1">
                {fmtInt(data.outbox_by_state[state])}
              </td>
              <td className="py-2 pl-4 text-[11px] leading-snug text-fg-3">
                {meta.meaning}
              </td>
            </tr>
          );
        })}
      </Table>
    </div>
  );
}
