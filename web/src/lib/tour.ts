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
    id: "get-started",
    target: '[data-tour="get-started"]',
    path: "/",
    placement: "bottom",
    title: "Get started",
    body:
      "Three steps: sign in and connect this machine (recommended, never " +
      "required), turn capture on for your AI tools, and use them as usual. " +
      "Once connected, this becomes one line with Open online dashboard.",
  },
  {
    id: "account",
    target: '[data-tour="topbar-account"]',
    placement: "bottom",
    title: "Your account, at the top",
    body:
      "Sign in from here at any time. Once this machine is connected, this " +
      "names your personal dashboard or team, with a button to open it online.",
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
      "Exact token spend, with no estimates on proxied traffic. The tabs " +
      "break it down by model, track your budget, and print a monthly " +
      "statement.",
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
      "Launch and attach agent terminals right in the dashboard. Each one " +
      "has a Git tree and file explorer so you can see the project without " +
      "leaving. Launch settings and the model Arena are the other two tabs.",
  },
  {
    id: "security",
    target: '[data-tour="nav-security"]',
    path: "/security",
    placement: "right",
    title: "Security",
    body:
      "Guardrails on your agents' own commands - dangerous-command policy, " +
      "MCP pins, and taint tracking for your coding tools. Verdicts, rules, " +
      "budgets, prompt guard and MCP each have their own tab.",
  },
  {
    id: "settings",
    target: '[data-tour="nav-settings"]',
    path: "/settings",
    placement: "right",
    title: "Settings",
    body:
      "Point Claude Code, Codex, Cursor, and more at SuperBased, tune privacy " +
      "and routing, and see your account and what this machine sends - all " +
      "here in Settings.",
  },
  {
    id: "filter-and-help",
    target: '[data-tour="global-filter"]',
    placement: "bottom",
    title: "One filter, and help anywhere",
    body:
      "The window, tool, project and model filters up here scope the whole dashboard; the " +
      "model filter is always here and greys out on a page it cannot narrow. The bell beside " +
      "Help collects what needs you. Press ? " +
      "on any screen to open contextual help. That's the tour - explore away.",
  },
];
