// preflightFacts phrases the availability strip's secondary lines from the
// preflight's STRUCTURED fields (budget_launch, route_setup,
// launch_runtime outside_range, config_override, missing_interpreter,
// install_needs_program, install_unverified). It replaces rendering the
// server's `notes` verbatim: those are the resolver's engineering sentences
// ("#!/usr/bin/env node shim ... merged PATH", "packaged app (not probed)",
// "routing env will not propagate") and stay on the wire for observer adapters
// / doctor. A fact the dialog has no row for says nothing — the headline (the
// verdict) and the routing line (guiLaunchCopy) carry the rest.
//
// Table-driven (CLAUDE.md #5): one row per fact, walked in order. Its only
// runtime import is the pure runtimeCheck.ts, so it runs under the node test
// runner.

import type { ToolPreflight } from "./types.ts";
import { launchRuntimeAdvisory } from "./runtimeCheck.ts";

type FactRow = (tool: string, p: ToolPreflight) => string | null;

export const PREFLIGHT_FACT_ROWS: ReadonlyArray<FactRow> = [
  // T-685: the org's hard budget will refuse this launch. Reason first, then
  // what to do, so the refusal is never a dead end in the picker.
  (_tool, p) => (p.budget_launch ? `${p.budget_launch.reason} ${p.budget_launch.remedy}`.trim() : null),
  // T-685: the tool's own config file is missing, so it starts unproxied.
  (_tool, p) => (p.route_setup ? p.route_setup : null),
  // T-396: the installed tool's runtime is above the floor but outside the
  // vendor's declared range. Said, never blocking (the doctor says it too).
  (_tool, p) => launchRuntimeAdvisory(p),
  (_tool, p) =>
    p.config_override === "missing"
      ? "Nothing is at the binary path set for this tool. Change or remove it in Settings > Session attach (Launch binary paths)."
      : null,
  (_tool, p) =>
    p.config_override === "used" ? "Uses the binary path set in Settings > Session attach (Launch binary paths)." : null,
  (_tool, p) =>
    p.missing_interpreter
      ? `It needs ${p.missing_interpreter}, which isn't installed, so it will fail to start.`
      : null,
  (_tool, p) =>
    p.install_needs_program
      ? `The install command needs ${p.install_needs_program}, which isn't installed yet.`
      : null,
  (_tool, p) =>
    p.install_unverified
      ? "SuperBased can't confirm it's installed. The launch will tell you if it isn't."
      : null,
];

/** preflightFacts returns the strip's secondary lines, in table order. */
export function preflightFacts(tool: string, p: ToolPreflight | null): string[] {
  if (!p) return [];
  return PREFLIGHT_FACT_ROWS.map((row) => row(tool, p)).filter((s): s is string => !!s);
}
