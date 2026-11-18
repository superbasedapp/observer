// First-run guided tour — step data + types.
// Plan of record: docs/plans/first-run-guided-tour-plan-2026-07-23.md.
//
// A single linear walkthrough of the dashboard's key sections. Each step
// either anchors to a real UI element (via a `data-tour` selector) or
// renders a centered card (no target). Bodies are plain strings, rendered
// as text nodes only — never dangerouslySetInnerHTML — so the copy can
// never become an injection surface.

// The step type is shared with the org dashboard's tour (T-447).
import type { TourStep } from "@shared/lib/tour";

export type { TourPlacement, TourStep } from "@shared/lib/tour";

// The first-run tour is five places a new person needs (local dashboard
// first-run design, docs/plans/local-dashboard-first-run-options-2026-11-18.md
// section 5): Overview, Sessions, Cost, Terminals and Security. It never starts
// by itself: the Overview welcome band, the Help drawer and the command
// palette start it. The account chip, Live, Cache, Settings and the global
// filter each have their own Help entry.
export const TOUR_STEPS: TourStep[] = [
  {
    id: "overview",
    target: '[data-tour="nav-overview"]',
    path: "/",
    placement: "right",
    title: "Overview - your home base",
    body:
      "Spend, tokens and activity at a glance across all your AI tools and " +
      "projects, captured on this machine. Start here each day.",
  },
  {
    id: "sessions",
    target: '[data-tour="nav-sessions"]',
    path: "/sessions",
    placement: "right",
    title: "Sessions",
    body:
      "Every AI coding session, searchable and filterable. Open one to see " +
      "its timeline: each prompt, the files read and changed, tokens and cost.",
  },
  {
    id: "cost",
    target: '[data-tour="nav-cost"]',
    path: "/cost",
    placement: "right",
    title: "Cost",
    body:
      "Token spend by model, exact on proxied traffic and estimated from " +
      "session logs otherwise. The tabs track your budget and print a " +
      "monthly statement.",
  },
  {
    id: "terminals",
    target: '[data-tour="nav-terminals"]',
    path: "/terminals",
    placement: "right",
    title: "Terminals",
    body:
      "Start a coding agent right here with New terminal. Each terminal's " +
      "Session button shows its live usage: context, cost and limits.",
  },
  {
    id: "security",
    target: '[data-tour="nav-security"]',
    path: "/security",
    placement: "right",
    title: "Security",
    body:
      "Guardrails on your agents' own commands: dangerous-command policy, " +
      "MCP pins and taint tracking. Press ? on any screen for help. " +
      "That's the tour.",
  },
];

/** The tour's step ids, in order (pinned by tour.test.ts). */
export const TOUR_STEP_IDS = TOUR_STEPS.map((s) => s.id);
