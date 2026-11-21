// AppsFirstRunCard - the "Your apps" first-run card (Plane A lane B5, plan
// W2-5, D7, D17). On the Overview it offers to turn app observability on and
// shows the SDK snippet; on a Your apps page it is the page body until the
// routes answer. The rules (what one click must do on this build) are the
// pure tables in lib/planeaFirstRun.ts.
//
// One consent, through the one enable seam (first-run plan 3.5, review
// FR-M02): POST /api/apps/enable, the call the Overview track, Settings >
// AI Apps, `observer apps on` and the VS Code action make. The daemon adds
// the obs component and sets the key through its own checks and opens the
// receiver in place, with no restart. Only a process without the seam (a
// dashboard the daemon does not serve) says a restart is needed. The data
// note is the daemon's one consent sentence (GET /api/apps/status consent,
// P-05), never a hard-coded "stays on this machine". A build without obs
// refuses loudly.

import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { GatedLink } from "@/components/GatedLink";
import { Telescope } from "lucide-react";
import {
  Button,
  Callout,
  ChartShell,
  ConfirmButton,
  CopyOnClick,
  InlineLoading,
  SegmentedControl,
} from "@/components/primitives";
import { localConfirmHeaders } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { useObsRoutesUp } from "@/lib/useObsRoutesUp";
import { refreshAfterAppsChange, useComponentState } from "@/lib/useComponents";
import { PRODUCT_NAMES } from "@shared/lib/productNames";
import { obsEnableState } from "@/lib/obsEnable";
import type { ConfigResponse } from "@/lib/types";
import {
  APPS_ENABLE_PATH,
  APPS_STATUS_PATH,
  appsRequestInit,
  type AppsEnableReport,
  type FirstRunApps,
} from "@/lib/firstRun";
import {
  FIRST_RUN_DISMISS_KEY,
  OBS_BUILDS,
  OBS_COMPONENT,
  SDK_SNIPPETS,
  enableResult,
  firstRunAction,
  firstRunNote,
  firstRunPageTitle,
  firstRunPhase,
  showOnOverview,
  snippetForReceiver,
  type OTLPReceiverState,
  type ObsComponentState,
} from "@/lib/planeaFirstRun";

function readDismissed(): boolean {
  try {
    return localStorage.getItem(FIRST_RUN_DISMISS_KEY) === "1";
  } catch {
    return false;
  }
}

function writeDismissed(): void {
  try {
    localStorage.setItem(FIRST_RUN_DISMISS_KEY, "1");
  } catch {
    // A private window: the card just shows again next time.
  }
}

export { useObsRoutesUp } from "@/lib/useObsRoutesUp";

/** SdkSnippet shows the install line and a minimal init per language. The
 *  init names the daemon's live receiver address (U-04): the caller's
 *  `receiver` when it has one, else the receiver's own report. */
export function SdkSnippet({ receiver }: { receiver?: string }) {
  const [lang, setLang] = useState<(typeof SDK_SNIPPETS)[number]["id"]>("python");
  const reported = useApi<OTLPReceiverState>(receiver ? null : "/api/sdk/receiver");
  const live = receiver || reported.data?.http_addr;
  const base = SDK_SNIPPETS.find((x) => x.id === lang) ?? SDK_SNIPPETS[0];
  const s = { ...base, code: snippetForReceiver(base.code, live) };
  return (
    <div className="space-y-2" data-testid="apps-sdk-snippet">
      <SegmentedControl
        options={SDK_SNIPPETS.map((x) => ({ value: x.id, label: x.label }))}
        value={lang}
        onChange={setLang}
      />
      <div className="flex items-center gap-2 font-mono text-[12px] text-fg-1">
        <span className="text-fg-3">$</span>
        <span className="min-w-0 truncate">{s.install}</span>
        <CopyOnClick value={s.install} ariaLabel="Copy the install command" className="text-[11px] text-accent">
          copy
        </CopyOnClick>
      </div>
      <div className="relative">
        <pre className="max-h-64 overflow-auto rounded-2 border border-line-2 bg-bg-3 p-3 text-[11px] leading-relaxed text-fg-1">
          {s.code}
        </pre>
        <span className="absolute right-2 top-2">
          <CopyOnClick value={s.code} ariaLabel="Copy the snippet" className="text-[11px] text-accent">
            copy
          </CopyOnClick>
        </span>
      </div>
    </div>
  );
}

export function AppsFirstRunCard({ variant }: { variant: "overview" | "page" }) {
  const state = useComponentState();
  const cfg = useApi<ConfigResponse>("/api/config");
  const apps = useApi<FirstRunApps & { confirm_token?: string }>(APPS_STATUS_PATH);
  const routesUp = useObsRoutesUp();
  const [dismissed, setDismissed] = useState(readDismissed);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ tone: "success" | "danger"; text: string } | null>(null);

  const component: ObsComponentState = useMemo(() => {
    const row = state.data?.view?.components.find((c) => c.id === OBS_COMPONENT);
    if (!state.data) return "unknown";
    // A build that does not list obs at all has no obs code.
    return row ? row.state : "absent";
  }, [state.data]);
  const enabled = obsEnableState(cfg.data?.config).observability;
  const phase = firstRunPhase({ component, enabled, routesUp: routesUp === true });
  const action = firstRunAction(phase, apps.data?.hot_enable);
  const consent = apps.data?.consent.sentence;

  if (variant === "overview" && !showOnOverview(phase, dismissed)) return null;
  if (phase === "on") return null;

  async function turnOn() {
    setBusy(true);
    setResult(null);
    try {
      const token = apps.data?.confirm_token || (await localConfirmHeaders())["X-Observer-Confirm"] || "";
      const res = await fetch(APPS_ENABLE_PATH, { ...appsRequestInit(token), credentials: "same-origin" });
      const text = await res.text();
      let body: AppsEnableReport | null = null;
      try {
        body = JSON.parse(text) as AppsEnableReport;
      } catch {
        body = null;
      }
      if (res.status === 404 || res.status === 501) {
        // A process without the seam: the one case a restart is the answer.
        setResult({
          tone: "danger",
          text: text.trim() || `This process cannot turn ${PRODUCT_NAMES.planea} on in place: run observer apps on, or restart the daemon.`,
        });
      } else {
        setResult(enableResult(body ?? { ok: false, message: text.trim() || `HTTP ${res.status}` }));
      }
    } catch (e: unknown) {
      setResult({ tone: "danger", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
      // FR-M10: the component state and the routes probe at once.
      refreshAfterAppsChange();
      cfg.reload();
      apps.reload();
    }
  }

  const title = variant === "overview" ? "See your own AI apps here" : firstRunPageTitle(phase);
  return (
    <ChartShell
      title={title}
      icon={Telescope}
      sub="Traces, sessions, cost and evals of the LLM apps you build, from the superbased SDK or any OpenTelemetry exporter."
      right={
        variant === "overview" ? (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              writeDismissed();
              setDismissed(true);
            }}
          >
            Not now
          </Button>
        ) : undefined
      }
    >
      <div className="space-y-3 p-1 text-[12px]" data-testid={`apps-first-run-${phase}`}>
        {phase === "loading" && <InlineLoading label="Checking this machine..." />}
        {phase === "absent" && (
          <Callout tone="info" title="Not in this edition">
            This edition of superbased does not include {PRODUCT_NAMES.planea}, so it cannot be turned on here.
            Editions that include it: {OBS_BUILDS.join(", ")}. Install one of them to see your AI apps on this machine.
          </Callout>
        )}
        {phase === "blocked" && (
          <Callout tone="warn" title="Blocked on this machine">
            {PRODUCT_NAMES.planea} is blocked here.{" "}
            <Link to="/settings/components?component=obs" className="text-accent hover:underline">
              Settings &gt; Components
            </Link>{" "}
            says why.
          </Callout>
        )}
        {action === "restart" && (
          <Callout tone="info" title="Waiting for a restart">
            {PRODUCT_NAMES.planea} is on in your config file, and this dashboard is not served by the daemon, so it cannot
            start it in place. Run observer apps on against the running daemon, or restart it.
          </Callout>
        )}
        {action === "turn_on" && (
          <div className="flex flex-wrap items-center gap-3">
            <ConfirmButton
              variant="primary"
              armedVariant="primary"
              onConfirm={() => void turnOn()}
              disabled={busy || result?.tone === "success"}
              loading={busy}
              confirmLabel="Turn on?"
              armedNote={firstRunNote(phase, consent)}
            >
              Turn on {PRODUCT_NAMES.planea}
            </ConfirmButton>
            <GatedLink to="/settings?section=observability" className="text-accent hover:underline">
              Settings &gt; AI Apps
            </GatedLink>
          </div>
        )}
        {action === "turn_on" && consent && <p className="text-fg-3">{consent}</p>}
        {result && (
          <p role="status" className={result.tone === "success" ? "text-success" : "text-danger"}>
            {result.text}
          </p>
        )}
        {phase !== "absent" && phase !== "blocked" && (
          <div>
            <p className="mb-2 text-fg-2">Then send traces from your app:</p>
            <SdkSnippet />
          </div>
        )}
      </div>
    </ChartShell>
  );
}
