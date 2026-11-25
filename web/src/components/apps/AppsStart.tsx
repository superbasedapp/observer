// AppsStart - the /apps route behind the persistent "AI Apps" nav item
// (review E-71). Once app observability answers it forwards to Traces;
// otherwise it is the first-run page: turn it on, wait for a restart, or, on
// a build without it, the edition does not include it (AppsFirstRunCard's
// "absent" row). It lives under components/, not pages/: it is core and
// carries no page of its own beyond the first-run card.
//
// Opened with ?enable=1 (SDK quickstart plan 3.7: the SDK's setup opens
// /apps?enable=1&from=setup when no terminal can ask the person y/N), the
// page puts the Turn on button and the one consent sentence first, calls
// the one enable seam on one click, and stays: opened by setup it waits for
// setup's hello trace and links it (plan 3.8). lib/planeaFirstRun.ts's
// APPS_START_MODE_RULES reads the query.

import { Navigate, useLocation } from "react-router-dom";
import { Telescope } from "lucide-react";
import { PageHeader } from "@/components/primitives";
import { PRODUCT_NAMES } from "@shared/lib/productNames";
import { useApi } from "@/lib/useApi";
import { APPS_STATUS_PATH, type FirstRunApps } from "@/lib/firstRun";
import { APPS_HOME_PATH, appsStartForwards, appsStartMode, type AppsStartMode } from "@/lib/planeaFirstRun";
import { useObsRoutesUp } from "@/lib/useObsRoutesUp";
import { useHrefGate } from "@/lib/governance";
import { AppsFirstRunCard } from "./AppsFirstRunCard";
import { AppsTrack } from "./AppsTrack";

export function AppsStart() {
  const up = useObsRoutesUp();
  const homeShown = useHrefGate()(APPS_HOME_PATH) === "shown";
  const mode = appsStartMode(useLocation().search);
  if (appsStartForwards(mode, up, homeShown)) return <Navigate to={APPS_HOME_PATH} replace />;
  return (
    <div className="space-y-6 p-4 sm:p-6" data-testid="apps-start" data-mode={mode}>
      <PageHeader
        icon={Telescope}
        title={PRODUCT_NAMES.planea}
        sub="Traces, sessions, cost and evals of the LLM apps you build."
      />
      {mode === "default" ? <AppsFirstRunCard variant="page" /> : <AppsEnableTrack mode={mode} />}
    </div>
  );
}

/** AppsEnableTrack runs the AI apps track on the page from GET
 *  /api/apps/status (the same facts the getting-started surface reads). */
function AppsEnableTrack({ mode }: { mode: Exclude<AppsStartMode, "default"> }) {
  const status = useApi<FirstRunApps>(APPS_STATUS_PATH);
  const loaded = status.data != null || status.error != null;
  return (
    <AppsTrack apps={status.data} loaded={loaded} codingHistory={false} onChanged={status.reload} mode={mode} />
  );
}
