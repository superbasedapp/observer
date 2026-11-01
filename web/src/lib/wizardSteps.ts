// wizardSteps: which setup wizard steps a Connected tools row gets, read from
// the server's per-row `wiring` (GET /api/tools/status, T-421). The server
// computes it from the same capability predicates `observer init` and
// `observer uninstall` use, so this module never names a tool. Pure (types
// only), so the node test runner covers it.

import type { ToolWiring } from "./types";

export type WizardStepKey = "hooks" | "mcp" | "route" | "telemetry";

/** One step the wizard renders for a tool. */
export type WizardStepPlan = {
  id: WizardStepKey;
  endpoint: string;
  /** The step's write is offered. */
  register: boolean;
  /** The step's removal is offered (the Remove panel). */
  remove: boolean;
  /** Why the write is not offered, when the server knows. */
  note?: string;
  /** What the write switches off in the tool, shown before the consent (FU-24). */
  tradeoff?: string;
};

const ENDPOINTS: Record<Exclude<WizardStepKey, "route">, string> = {
  hooks: "/api/setup/hooks",
  mcp: "/api/setup/mcp",
  telemetry: "/api/setup/telemetry",
};

/** wizardStepsFor lists the steps in wizard order (hooks, MCP, route, telemetry export). */
export function wizardStepsFor(w: ToolWiring | undefined): WizardStepPlan[] {
  if (!w) return [];
  const out: WizardStepPlan[] = [];
  for (const id of ["hooks", "mcp"] as const) {
    const p = w[id];
    if (p && (p.register || p.remove || p.note)) {
      out.push({ id, endpoint: ENDPOINTS[id], register: p.register, remove: p.remove, note: p.note });
    }
  }
  if (w.route_endpoint && (w.route.register || w.route.remove)) {
    out.push({
      id: "route",
      endpoint: w.route_endpoint,
      register: w.route.register,
      remove: w.route.remove,
      tradeoff: w.route.tradeoff,
    });
  }
  const t = w.telemetry;
  if (t && (t.register || t.remove)) {
    out.push({ id: "telemetry", endpoint: ENDPOINTS.telemetry, register: t.register, remove: t.remove, note: t.note });
  }
  return out;
}

/** hasWizard reports whether the row gets a Set up button at all. */
export function hasWizard(w: ToolWiring | undefined): boolean {
  return wizardStepsFor(w).some((s) => s.register || s.remove);
}
