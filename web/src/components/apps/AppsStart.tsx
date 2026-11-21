// AppsStart - the /apps route behind the persistent "AI Apps" nav item
// (review E-71). Once app observability answers it forwards to Traces;
// otherwise it is the first-run page: turn it on, wait for a restart, or, on
// a build without it, the edition does not include it (AppsFirstRunCard's
// "absent" row). It lives under components/, not pages/: it is core and
// carries no page of its own beyond the first-run card.

import { Navigate } from "react-router-dom";
import { Telescope } from "lucide-react";
import { PageHeader } from "@/components/primitives";
import { PRODUCT_NAMES } from "@shared/lib/productNames";
import { APPS_HOME_PATH } from "@/lib/planeaFirstRun";
import { useObsRoutesUp } from "@/lib/useObsRoutesUp";
import { useHrefGate } from "@/lib/governance";
import { AppsFirstRunCard } from "./AppsFirstRunCard";

export function AppsStart() {
  const up = useObsRoutesUp();
  const homeShown = useHrefGate()(APPS_HOME_PATH) === "shown";
  if (up === true && homeShown) return <Navigate to={APPS_HOME_PATH} replace />;
  return (
    <div className="space-y-6 p-4 sm:p-6" data-testid="apps-start">
      <PageHeader
        icon={Telescope}
        title={PRODUCT_NAMES.planea}
        sub="Traces, sessions, cost and evals of the LLM apps you build."
      />
      <AppsFirstRunCard variant="page" />
    </div>
  );
}
