import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ExternalLink } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Callout } from "@shared/primitives/Callout";
import { Skeleton } from "@shared/primitives/Skeleton";
import { ApiError, approveConnect, connectNotNow, declineConnect, getConnectRequest } from "../api";
import type { ConnectChoice, ConnectRequestView } from "../api";
import type { DashboardCard } from "../lib/connectModel";
import { AuthShell } from "../components/AuthShell";
import {
  CONNECT_PAGE_TEXT,
  PURPOSE_TEXT,
  SDK_KEY_PAGE_TEXT,
  ageLabel,
  choiceAvailable,
  choiceLabel,
  connectPageState,
  connectPurpose,
  connectedDashboards,
  networkLine,
  osLabel,
  pickChoice,
  sdkClientLabel,
  sdkKeyAfter,
} from "../lib/connectModel";
import { invalidatePortal, usePortalQuery } from "../lib/query";

// ConnectApprove - the approve_url page, /connect/<request_id> (Getting
// started v2, docs/plans/onboarding-v2-connect-flow.md): a machine running
// `observer connect` waits here for the signed-in person. The page shows what
// asks to connect (name, system, Observer version, how long ago, its network
// against this browser's, and the code to compare with the terminal), the
// dashboards it can connect to (the personal dashboard first, a hinted team
// preselected), the disclosure of the chosen one, and Connect / Not now. A
// quiet "This is not my machine" declines. What shows per status is
// connectModel's connectPageState.
//
// The same page answers an AI Apps SDK's setup asking for the member's own
// SDK key (purpose "sdk_key"; the SDK quickstart plan section 3.6): it names
// the SDK and the project, shows the SDK key's disclosure, lists a dashboard
// whose plan does not include AI Apps disabled with the plan refusal's
// message and link, has no "Not now", and after Approve sends the browser to
// the chosen dashboard's AI apps page, where the first trace appears
// (waiting first while a new personal dashboard is set up).

/** ERROR_TEXT words the approval refusals the page can act on. */
const ERROR_TEXT: Readonly<Record<string, string>> = {
  not_pending: "This request was already answered or has expired.",
  target_unavailable: "That dashboard cannot take a machine right now. Pick another, or try again in a minute.",
  answer_not_allowed: "An SDK key needs a dashboard. Choose one, or decline.",
  disclosure_changed: "What this dashboard shares has changed. Read it again below, then choose.",
  passkey_signin_required: "This account uses a passkey. Sign in with it in this browser first, then approve again.",
  second_factor_required: "This account uses a passkey. Use it first, then approve again.",
};

export function ConnectApprove() {
  const { id = "" } = useParams();
  const q = usePortalQuery<ConnectRequestView>("connect:" + id, () => getConnectRequest(id), [id]);
  const [answered, setAnswered] = useState<ConnectRequestView | null>(null);
  const [picked, setPicked] = useState<string | null>(null);
  const [busy, setBusy] = useState<"connect" | "not_now" | "decline" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const v = answered ?? q.data;

  if (!v) {
    return (
      <AuthShell title="Connect a machine" width="wide">
        {q.error ? (
          <Callout tone="danger" title="This request was not found">
            It may have expired or been answered already. Run observer connect on the machine again.
          </Callout>
        ) : (
          <div aria-busy="true" className="flex flex-col gap-3">
            <Skeleton className="h-16 w-full border border-line-2" />
            <Skeleton className="h-24 w-full border border-line-2" />
          </div>
        )}
      </AuthShell>
    );
  }

  const purpose = connectPurpose(v);
  const words = PURPOSE_TEXT[purpose];
  const state = connectPageState(v);
  if (purpose === "sdk_key" && state !== "choose") {
    return <SdkKeyFinished id={id} view={v} onView={setAnswered} />;
  }
  if (state !== "choose") {
    const t = CONNECT_PAGE_TEXT[state];
    const dashboards = connectedDashboards(v);
    return (
      <AuthShell title={t.title} width="wide">
        <div className="flex flex-col gap-3">
          <p className="text-[13px] leading-snug text-fg-1">
            <strong className="font-semibold text-fg-0">{v.machine_name}</strong>
            {v.target && state === "connected" ? ` is connected to ${choiceLabel(v.target, "inline")}.` : ""}
          </p>
          <p className="text-[12.5px] leading-snug text-fg-2">{t.line}</p>
          {dashboards && (
            <div className="grid gap-3 sm:grid-cols-2" data-testid="connect-two-dashboards">
              {dashboards.map((d) => (
                <DashboardCardView key={d.id} card={d} />
              ))}
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2">
            {state === "connected" && !dashboards && v.open_url && (
              <Button variant="primary" iconRight={ExternalLink} href={v.open_url} target="_blank" rel="noopener">
                Open your dashboard
              </Button>
            )}
            {!dashboards?.some((d) => d.opens === "portal") && (
              <Link to="/home" className="text-[12.5px] font-medium text-accent hover:underline">
                Go to Home
              </Link>
            )}
          </div>
        </div>
      </AuthShell>
    );
  }

  const choice: ConnectChoice | undefined = pickChoice(v.choices, picked);
  const net = networkLine(v.network);

  async function run(kind: "connect" | "not_now" | "decline") {
    setBusy(kind);
    setError(null);
    try {
      const next =
        kind === "connect" && choice
          ? await approveConnect(id, choice)
          : kind === "not_now"
            ? await connectNotNow(id)
            : await declineConnect(id);
      setAnswered(next);
      invalidatePortal("connect:home");
    } catch (e) {
      const code = e instanceof ApiError ? e.code : "";
      // plan_required carries the plan refusal's own message (with its link).
      setError((code !== "plan_required" && ERROR_TEXT[code]) || (e instanceof Error ? e.message : "Something went wrong. Try again."));
      if (code === "disclosure_changed" || code === "not_pending") q.reload();
    } finally {
      setBusy(null);
    }
  }

  return (
    <AuthShell title={words.title} width="wide" intro={<p>{words.intro}</p>}>
      <div className="flex flex-col gap-4">
        <div className="rounded-2 border border-line-2 bg-bg-1 px-3 py-2.5">
          {purpose === "sdk_key" ? (
            <>
              <div className="text-[14px] font-semibold text-fg-0" data-testid="sdk-key-project">
                {v.project_name || "An app"}
              </div>
              <div className="mt-0.5 text-[12px] text-fg-2">
                {sdkClientLabel(v.client, v.client_version)} on {v.machine_name} ({osLabel(v.os)}, {v.arch}). Asked{" "}
                {ageLabel(v.age_seconds)}.
              </div>
            </>
          ) : (
            <>
              <div className="text-[14px] font-semibold text-fg-0">{v.machine_name}</div>
              <div className="mt-0.5 text-[12px] text-fg-2">
                {osLabel(v.os)}, {v.arch}, Observer {v.observer_version}. Asked {ageLabel(v.age_seconds)}.
              </div>
            </>
          )}
          {v.user_code && (
            <div className="mt-1.5 text-[12px] text-fg-2">
              Code <span className="font-mono font-semibold text-fg-0">{v.user_code}</span>: it should match your terminal.
            </div>
          )}
        </div>
        {net.warn ? (
          <Callout tone="warn">{net.text}</Callout>
        ) : (
          <p className="text-[12px] text-fg-3">{net.text}</p>
        )}

        <fieldset className="flex flex-col gap-2">
          <legend className="mb-1 text-[12px] font-semibold text-fg-1">{words.legend}</legend>
          {v.choices.map((c) => {
            const usable = choiceAvailable(c);
            return (
              <div key={c.org_id} className="flex flex-col gap-1">
                <label
                  className={
                    "flex items-center gap-2 rounded-2 border border-line-2 bg-bg-1 px-3 py-2 text-[12.5px] " +
                    (usable ? "cursor-pointer text-fg-1" : "cursor-not-allowed text-fg-3")
                  }
                >
                  <input
                    type="radio"
                    name="connect-target"
                    value={c.org_id}
                    checked={usable && choice?.org_id === c.org_id}
                    onChange={() => setPicked(c.org_id)}
                    disabled={busy !== null || !usable}
                  />
                  <span className="min-w-0 flex-1 truncate">{choiceLabel(c)}</span>
                  {purpose === "machine" && <span className="text-[11px] text-fg-3">{c.disclosure.title}</span>}
                </label>
                {!usable && c.refusal && (
                  <p className="px-3 text-[11.5px] leading-snug text-fg-2" data-testid="choice-refusal">
                    {c.refusal.message}{" "}
                    {c.refusal.upgrade_url && (
                      <a
                        className="font-medium text-accent hover:underline"
                        href={c.refusal.upgrade_url}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Change the plan
                      </a>
                    )}
                  </p>
                )}
              </div>
            );
          })}
        </fieldset>

        {choice && (
          <Callout tone={choice.share_level === "full" ? "warn" : "info"} title={choice.disclosure.title}>
            {choice.disclosure.text}
          </Callout>
        )}

        {error && (
          <div role="alert" className="rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[12px] text-danger">
            {error}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="primary"
            loading={busy === "connect"}
            disabled={!choice || busy !== null}
            onClick={() => void run("connect")}
          >
            {words.approve}
          </Button>
          {words.notNow && (
            <Button variant="secondary" loading={busy === "not_now"} disabled={busy !== null} onClick={() => void run("not_now")}>
              Not now
            </Button>
          )}
        </div>
        <p className="text-[11.5px] leading-relaxed text-fg-3">
          {words.notNow ? "Not now signs the machine in and sends nothing. " : ""}
          <button
            type="button"
            className="text-fg-2 underline decoration-line-3 underline-offset-2 hover:text-fg-0"
            disabled={busy !== null}
            onClick={() => void run("decline")}
          >
            {words.decline}
          </button>
          {v.expires_in > 0 ? ` This request ends in ${Math.max(1, Math.ceil(v.expires_in / 60))} min.` : ""}
        </p>
      </div>
    </AuthShell>
  );
}

/** DashboardCardView is one of the two dashboards after approval: its name,
 * what it holds, and the button that opens it (connectModel decides all of
 * it). The online card opens inside this portal, or the team's own
 * dashboard in a new tab. */
function DashboardCardView({ card }: { card: DashboardCard }) {
  const navigate = useNavigate();
  return (
    <div
      className="flex min-w-0 flex-col gap-2 rounded-2 border border-line-2 bg-bg-1 px-3 py-2.5"
      data-testid={`dashboard-card-${card.id}`}
    >
      <div className="text-[13px] font-semibold text-fg-0">{card.title}</div>
      <p className="flex-1 text-[12px] leading-snug text-fg-2">{card.role}</p>
      <div>
        {card.opens === "external" ? (
          <Button
            variant={card.id === "online" ? "primary" : "secondary"}
            iconRight={ExternalLink}
            href={card.href}
            target="_blank"
            rel="noopener noreferrer"
          >
            {card.button}
          </Button>
        ) : (
          <Button variant="primary" onClick={() => navigate(card.href)}>
            {card.button}
          </Button>
        )}
      </div>
      {card.note && <p className="text-[11.5px] text-fg-3">{card.note}</p>}
    </div>
  );
}

/** SDK_KEY_WAIT_MS is how often the page re-reads a request whose dashboard
 * is still being set up. */
const SDK_KEY_WAIT_MS = 3000;

/** SdkKeyFinished is an answered SDK key request: after Approve it sends the
 * browser to the chosen dashboard's AI apps page (the first trace appears
 * there), re-reading the request while a new personal dashboard is set up;
 * otherwise it says the request was declined or expired. connectModel's
 * sdkKeyAfter decides. */
function SdkKeyFinished({ id, view, onView }: { id: string; view: ConnectRequestView; onView: (v: ConnectRequestView) => void }) {
  const after = sdkKeyAfter(view);
  useEffect(() => {
    if (after.state === "go") {
      window.location.assign(after.href);
      return;
    }
    if (after.state !== "wait") return;
    const timer = window.setTimeout(() => {
      getConnectRequest(id).then(onView, () => undefined);
    }, SDK_KEY_WAIT_MS);
    return () => window.clearTimeout(timer);
  }, [after.state, after.state === "go" ? after.href : "", id, onView, view]);

  const state = connectPageState(view);
  const t =
    state === "declined"
      ? SDK_KEY_PAGE_TEXT.declined
      : state === "expired"
        ? SDK_KEY_PAGE_TEXT.expired
        : after.state === "wait"
          ? SDK_KEY_PAGE_TEXT.waiting
          : SDK_KEY_PAGE_TEXT.approved;
  return (
    <AuthShell title={t.title} width="wide">
      <div className="flex flex-col gap-3" data-testid="sdk-key-finished">
        <p className="text-[12.5px] leading-snug text-fg-2">{t.line}</p>
        <div className="flex flex-wrap items-center gap-2">
          {after.state === "go" && (
            <Button variant="primary" iconRight={ExternalLink} href={after.href}>
              Open the AI apps page
            </Button>
          )}
          <Link to="/home" className="text-[12.5px] font-medium text-accent hover:underline">
            Go to Home
          </Link>
        </div>
      </div>
    </AuthShell>
  );
}
