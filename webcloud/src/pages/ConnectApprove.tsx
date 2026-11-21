import { useState } from "react";
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
  ageLabel,
  choiceLabel,
  connectPageState,
  connectedDashboards,
  networkLine,
  osLabel,
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

/** ERROR_TEXT words the approval refusals the page can act on. */
const ERROR_TEXT: Readonly<Record<string, string>> = {
  not_pending: "This request was already answered or has expired.",
  target_unavailable: "That dashboard cannot take a machine right now. Pick another, or try again in a minute.",
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

  const state = connectPageState(v);
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

  const choice: ConnectChoice | undefined =
    v.choices.find((c) => c.org_id === picked) ?? v.choices.find((c) => c.preselected) ?? v.choices[0];
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
      setError(ERROR_TEXT[code] ?? (e instanceof Error ? e.message : "Something went wrong. Try again."));
      if (code === "disclosure_changed" || code === "not_pending") q.reload();
    } finally {
      setBusy(null);
    }
  }

  return (
    <AuthShell
      title="Connect this machine?"
      width="wide"
      intro={<p>A machine running Observer asked to sign in to your account. Check it is yours.</p>}
    >
      <div className="flex flex-col gap-4">
        <div className="rounded-2 border border-line-2 bg-bg-1 px-3 py-2.5">
          <div className="text-[14px] font-semibold text-fg-0">{v.machine_name}</div>
          <div className="mt-0.5 text-[12px] text-fg-2">
            {osLabel(v.os)}, {v.arch}, Observer {v.observer_version}. Asked {ageLabel(v.age_seconds)}.
          </div>
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
          <legend className="mb-1 text-[12px] font-semibold text-fg-1">Connect it to</legend>
          {v.choices.map((c) => (
            <label
              key={c.org_id}
              className="flex cursor-pointer items-center gap-2 rounded-2 border border-line-2 bg-bg-1 px-3 py-2 text-[12.5px] text-fg-1"
            >
              <input
                type="radio"
                name="connect-target"
                value={c.org_id}
                checked={choice?.org_id === c.org_id}
                onChange={() => setPicked(c.org_id)}
                disabled={busy !== null}
              />
              <span className="min-w-0 flex-1 truncate">{choiceLabel(c)}</span>
              <span className="text-[11px] text-fg-3">{c.disclosure.title}</span>
            </label>
          ))}
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
            Connect
          </Button>
          <Button variant="secondary" loading={busy === "not_now"} disabled={busy !== null} onClick={() => void run("not_now")}>
            Not now
          </Button>
        </div>
        <p className="text-[11.5px] leading-relaxed text-fg-3">
          Not now signs the machine in and sends nothing.{" "}
          <button
            type="button"
            className="text-fg-2 underline decoration-line-3 underline-offset-2 hover:text-fg-0"
            disabled={busy !== null}
            onClick={() => void run("decline")}
          >
            This is not my machine
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
