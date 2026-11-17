import { useState } from "react";
import { ExternalLink, UserRound, type LucideIcon } from "lucide-react";
import { Button, ChartShell, ConfirmButton, Icon, Pill } from "@/components/primitives";
import { Summary } from "@/components/Summary";
import { ConnectProgressBlock } from "@/components/ConnectProgress";
import { pushToast } from "@/components/Toast";
import { apiCache, useApi } from "@/lib/useApi";
import { apiReason, fetchJSON } from "@/lib/api";
import { fmtRelative } from "@/lib/format";
import { SHARE_LEVELS, shareLevelOf, signInStep, type Account } from "@/lib/getStarted";
import { useAccount, useConnectFlow, type ConnectFlow } from "@/lib/useConnectFlow";
import { apiErrorCode, apiErrorMessage, UNSENT_ROWS, type LeaveReport, type ManageResponse } from "@/lib/enrolment";
import type { CloudLogoutResponse, CloudStatusResponse } from "@/lib/types";
import { EnrolmentSection } from "./EnrolmentSection";
import { CloudIntelligenceSection } from "./CloudIntelligenceSection";

// AccountSection is Settings > Account (Getting started v2): the one place
// that says who you are signed in as, where this machine is connected (with
// Open online), what is shared in plain words, and Disconnect. It merged
// two tabs: the Cloud Intelligence sign-in card and Enrolment.
//
//   - The account card. Sign in and connect runs the same connect flow as
//     the Overview Get started panel and the top bar (lib/useConnectFlow.ts).
//     Disconnect runs the existing leave route (POST /api/enrolment/leave,
//     the confirm token from /api/enrolment/manage), with the same "send
//     what is waiting first" refusal the detailed view handles.
//   - "AI summaries": the old Cloud Intelligence page, embedded below the
//     card without its own sign-in buttons (the card owns sign-in). Shown
//     only where that section is offered (`aiSummaries`).
//   - The detailed connection view (the old Enrolment page: status, push
//     now, the organization's grant, code / link / self-hosted server
//     sign-in) under a disclosure: "Connection details" when connected,
//     "Advanced: connect to a self-hosted server" when not. It opens by
//     itself when a grant waits for an answer.
//
// The section id stays "enrolment" (a floor section an organization can
// never hide); Settings.tsx maps ?section=account and ?section=cloud here.

export function AccountSection({
  icon,
  aiSummaries,
  aiSummariesReadOnly,
}: {
  icon?: LucideIcon;
  /** The AI summaries (Cloud Intelligence) section is offered on this machine. */
  aiSummaries: boolean;
  /** The organization pinned AI summaries read-only. */
  aiSummariesReadOnly: boolean;
}) {
  const flow = useConnectFlow();
  const { account, enrolment } = useAccount(flow);
  const manage = useApi<ManageResponse>("/api/enrolment/manage", undefined, [], { refreshMs: 30000 });
  const ov = manage.data?.overview;
  const pendingGrant = !!ov?.pending_grant;
  const managed = !!enrolment?.enrolled && enrolment.tenancy === "managed";

  return (
    <div className="space-y-5">
      <ChartShell title="Account" icon={icon} sub="Your SuperBased account and where this machine is connected. Everything works on this machine without one.">
        {account ? (
          <AccountCard
            account={account}
            flow={flow}
            managed={managed}
            shareRule={ov?.share_mode}
            confirmToken={manage.data?.confirm_token ?? ""}
            onChanged={() => {
              manage.reload();
              apiCache.invalidate("/api/enrolment/status");
              apiCache.invalidate("/api/connect/status");
              apiCache.invalidate("/api/governance");
            }}
          />
        ) : (
          <p className="text-[11.5px] text-fg-3">Reading your account...</p>
        )}
      </ChartShell>

      {aiSummaries && (
        <section aria-labelledby="sb-ai-summaries" className="space-y-3">
          <div>
            <h2 id="sb-ai-summaries" className="text-[14px] font-semibold text-fg-0">
              AI summaries
            </h2>
            <p className="mt-0.5 max-w-[70ch] text-[11.5px] text-fg-3">
              Optional names, tags and summaries for your sessions, made online for your account. Nothing is sent until you
              turn it on and agree to what is sent.
            </p>
          </div>
          <CloudIntelligenceSection icon={icon} readOnly={aiSummariesReadOnly} accountOwnsSignIn />
        </section>
      )}

      <details className="rounded-3 border border-line-2 bg-bg-2" open={pendingGrant || undefined}>
        <Summary className="px-4 py-2.5 text-small font-medium text-fg-2 hover:text-fg-1">
          {account?.connected ? "Connection details" : "Advanced: connect to a self-hosted server"}
        </Summary>
        <div className="border-t border-line-2 px-4 py-3">
          <EnrolmentSection icon={icon} />
        </div>
      </details>
    </div>
  );
}

const ROW = "grid grid-cols-1 gap-1 py-2 sm:grid-cols-[140px_minmax(0,1fr)] sm:gap-3";
const KEY = "text-[11px] font-medium text-fg-3";
const VAL = "min-w-0 text-[12px] text-fg-1";

function AccountCard({
  account,
  flow,
  managed,
  shareRule,
  confirmToken,
  onChanged,
}: {
  account: Account;
  flow: ConnectFlow;
  managed: boolean;
  shareRule?: string;
  confirmToken: string;
  onChanged: () => void;
}) {
  const level = shareLevelOf(flow.progress?.state === "connected" ? flow.progress.target?.share_level : shareRule) ?? shareLevelOf(shareRule);
  const step = signInStep(account, false);
  const cloud = useApi<CloudStatusResponse>("/api/cloud/status", undefined, [], { refreshMs: 30000 });
  const signOutAvailable = !!cloud.data?.sign_in?.actions_available && !!cloud.data.sign_in.signed_in;

  return (
    <div className="divide-y divide-line-1">
      <div className={ROW}>
        <span className={KEY}>Signed in as</span>
        <span className={VAL}>
          {account.signedIn ? (
            <span className="flex flex-wrap items-center gap-2">
              <span>{account.email || "Your SuperBased account"}</span>
              {signOutAvailable && !account.connected && <SignOut onChanged={onChanged} />}
            </span>
          ) : (
            <span className="text-fg-3">Not signed in</span>
          )}
        </span>
      </div>
      <div className={ROW}>
        <span className={KEY}>This machine</span>
        <span className={VAL}>
          {account.connected ? (
            <span className="flex flex-wrap items-center gap-2">
              <span>
                Connected to <span className="font-medium">{account.displayName}</span>
                {managed && (
                  <Pill variant="warn" case="none" className="ml-2">
                    Managed
                  </Pill>
                )}
              </span>
              {account.onlineUrl && (
                <a
                  href={account.onlineUrl}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="inline-flex items-center gap-1 rounded-2 border border-accent/40 bg-accent-soft px-2 py-0.5 text-[11px] font-medium text-accent hover:bg-accent/20"
                >
                  Open online
                  <Icon icon={ExternalLink} size={11} />
                </a>
              )}
            </span>
          ) : (
            <span className="text-fg-3">Not connected. Everything stays on this machine.</span>
          )}
          {account.connected && (
            <span className="mt-0.5 block text-[10.5px] text-fg-4">
              {account.lastSentAt ? `Last sent ${fmtRelative(account.lastSentAt)}` : "Nothing sent yet"}
            </span>
          )}
        </span>
      </div>
      {account.connected && (
        <div className={ROW}>
          <span className={KEY}>What is sent</span>
          <span className={VAL}>
            {level ? (
              <>
                <span className="font-medium">{SHARE_LEVELS[level].label}.</span>{" "}
                <span className="text-fg-3">{SHARE_LEVELS[level].detail}</span>
              </>
            ) : (
              <span className="text-fg-3">See Connection details below.</span>
            )}
          </span>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2 pt-3">
        {account.connected ? (
          <Disconnect
            name={account.displayName}
            managed={managed}
            locked={account.locked}
            confirmToken={confirmToken}
            onChanged={onChanged}
          />
        ) : step.kind === "unavailable" ? (
          <p className="text-[11.5px] text-fg-3">{step.reason}</p>
        ) : !flow.available ? (
          <p className="text-[11.5px] text-fg-3">Sign in from this machine&apos;s own browser.</p>
        ) : (
          !flow.active && (
            <Button variant="primary" iconLeft={UserRound} onClick={() => void flow.start()} loading={flow.busy}>
              {step.kind === "connect" ? "Connect this machine" : "Sign in and connect this machine"}
            </Button>
          )
        )}
      </div>
      <ConnectProgressBlock flow={flow} className="mt-2" />
    </div>
  );
}

function SignOut({ onChanged }: { onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const signOut = async () => {
    setBusy(true);
    try {
      const res = await fetchJSON<CloudLogoutResponse>("/api/cloud/logout", undefined, { method: "POST" });
      pushToast(res.ok ? "Signed out" : res.message || "Sign-out failed", res.ok ? "success" : "danger");
      apiCache.invalidate("/api/cloud/status");
      onChanged();
    } catch (e) {
      pushToast(apiReason(e), "danger");
    } finally {
      setBusy(false);
    }
  };
  return (
    <Button size="sm" variant="ghost" onClick={() => void signOut()} loading={busy}>
      Sign out
    </Button>
  );
}

function Disconnect({
  name,
  managed,
  locked,
  confirmToken,
  onChanged,
}: {
  name: string;
  managed: boolean;
  locked: boolean;
  confirmToken: string;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [unsent, setUnsent] = useState<string | null>(null);
  if (locked) {
    return <p className="text-[11.5px] text-fg-3">Your company&apos;s settings keep this machine connected.</p>;
  }
  const leave = async (dropUnsent: boolean) => {
    setBusy(true);
    setErr(null);
    try {
      const report = await fetchJSON<LeaveReport>("/api/enrolment/leave", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Observer-Confirm": confirmToken },
        body: JSON.stringify(dropUnsent ? { drop_unsent: true } : {}),
      });
      setUnsent(null);
      pushToast(report.was_enrolled ? `Disconnected from ${name}` : "This machine was not connected", "success");
      onChanged();
    } catch (e) {
      if (apiErrorCode(e) === UNSENT_ROWS) setUnsent(apiErrorMessage(e));
      else setErr(apiErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="space-y-2">
      <ConfirmButton
        variant="danger-outline"
        armedVariant="danger"
        size="sm"
        onConfirm={() => void leave(false)}
        loading={busy}
        disabled={!confirmToken}
        title={confirmToken ? undefined : "Open the dashboard on this machine to disconnect it"}
        confirmLabel="Disconnect?"
        armedNote={
          managed
            ? `${name} manages this machine. Disconnecting stops sending to it and removes what it set here. What was already sent stays with ${name}.`
            : `Stops sending this machine's activity to ${name}. What was already sent stays there, and everything keeps working here.`
        }
      >
        Disconnect
      </ConfirmButton>
      {unsent && (
        <div role="alert" className="space-y-1.5 rounded-2 border border-warn/40 bg-warn-soft px-3 py-2 text-[11.5px] text-fg-1">
          <p>{unsent}</p>
          <ConfirmButton
            variant="danger-outline"
            armedVariant="danger"
            size="sm"
            onConfirm={() => void leave(true)}
            loading={busy}
            confirmLabel="Disconnect anyway?"
            armedNote="What has not been sent yet will never reach it."
          >
            Disconnect anyway
          </ConfirmButton>
        </div>
      )}
      {err && (
        <p role="alert" className="text-[11.5px] text-danger">
          {err}
        </p>
      )}
    </div>
  );
}
