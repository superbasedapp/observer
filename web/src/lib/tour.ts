// First-run guided tour — step data + types.
// Plan of record: docs/plans/first-run-guided-tour-plan-2026-07-23.md.
//
// A single linear walkthrough of the dashboard's key sections. Each step
// either anchors to a real UI element (via a `data-tour` selector) or
// renders a centered card (no target). Bodies are plain strings, rendered
// as text nodes only — never dangerouslySetInnerHTML — so the copy can
// never become an injection surface.

export type TourPlacement = "top" | "bottom" | "left" | "right" | "auto";

export type TourStep = {
  // Stable id (used as a React key + for debugging).
  id: string;
  // CSS selector of the anchor element. Omit for a centered card.
  target?: string;
  // Route to navigate to before showing the step (if not already there).
  path?: string;
  // Preferred bubble placement relative to the target. Default "bottom".
  placement?: TourPlacement;
  // Coach-mark heading.
  title: string;
  // Body copy — plain text, rendered as text nodes only.
  body: string;
  // Padding in px around the spotlight cutout. Default 6.
  spotlightPadding?: number;
};

export const TOUR_STEPS: TourStep[] = [
  {
    id: "welcome",
    // Centered card — no anchor.
    title: "Welcome to SuperBased",
    body:
      "This is your local control plane for every AI coding session - cost, " +
      "tokens, activity, and guardrails, all captured on your machine. " +
      "Here's a 60-second tour of where things live.",
  },
  {
    id: "overview",
    target: '[data-tour="nav-overview"]',
    path: "/",
    placement: "right",
    title: "Overview - your home base",
    body:
      "Spend, tokens, and activity at a glance across all your tools and " +
      "projects. Start here each day.",
  },
  {
    id: "live",
    target: '[data-tour="nav-live"]',
    path: "/live",
    placement: "right",
    title: "Live",
    body:
      "Watch sessions as they happen - active agents, current tools, and " +
      "streaming activity in real time.",
  },
  {
    id: "sessions",
    target: '[data-tour="nav-sessions"]',
    path: "/sessions",
    placement: "right",
    title: "Sessions",
    body:
      "Every AI coding session, searchable and filterable - open one to see " +
      "its full timeline, tokens, and cost.",
  },
  {
    id: "cost",
    target: '[data-tour="nav-cost"]',
    path: "/cost",
    placement: "right",
    title: "Cost",
    body:
      "Exact token spend broken down by model, tool, and project - plus " +
      "input/output and cache costs, with no estimates on proxied traffic.",
  },
  {
    id: "cache",
    target: '[data-tour="nav-cache"]',
    path: "/cache",
    placement: "right",
    title: "Cache",
    body:
      "Prompt-cache savings and keep-warm advice - see what your cache is " +
      "earning and when it's about to expire.",
  },
  {
    id: "terminals",
    target: '[data-tour="nav-terminals"]',
    path: "/terminals",
    placement: "right",
    title: "Terminals",
    body:
      "Launch and attach agent terminals right in the dashboard. Each one now " +
      "has a Git tree and file explorer so you can see the project without " +
      "leaving.",
  },
  {
    id: "security",
    target: '[data-tour="nav-security"]',
    path: "/security",
    placement: "right",
    title: "Security",
    body:
      "Guardrails on your agents' own commands - dangerous-command policy, " +
      "MCP pins, and taint tracking for your coding tools.",
  },
  {
    id: "settings",
    target: '[data-tour="nav-settings"]',
    path: "/settings",
    placement: "right",
    title: "Connect your tools",
    body:
      "Point Claude Code, Codex, Cursor, and more at SuperBased, tune privacy " +
      "and routing, and manage Teams sharing - all here in Settings.",
  },
  {
    id: "filter-and-help",
    target: '[data-tour="global-filter"]',
    placement: "bottom",
    title: "One filter, and help anywhere",
    body:
      "The date range and window up here scope the whole dashboard. Press ? " +
      "on any screen to open contextual help. That's the tour - explore away.",
  },
];
