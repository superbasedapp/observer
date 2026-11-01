// Words for the sources lane C2 adds (internal/planlimits/src_lanec2.go).
// Pure data; plans.ts merges it. Keys of LANE_C2 are source ids; keys of
// LANE_C2_WORDS are new parameter keys and parameter choices.
import type { SourceWords } from "./types.ts";

export const LANE_C2: Record<string, SourceWords> = {
  "x_api.usage": {
    label: "App bearer token",
    howto: "Paste your X app's bearer token to read this month's post cap used.",
  },
  "x_api.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from console.x.com and the account number shown in the console's address bar.",
  },
  "stepfun.session": {
    label: "Pasted token",
    howto: "Paste the Oasis token from a signed-in platform.stepfun.com request. Observer never asks for your password.",
  },
  "helmcode.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from your signed-in Helmcode dashboard and pick which dashboard it came from.",
  },
  "longcat.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from a signed-in longcat.chat request.",
  },
  "notion_ai.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from app.notion.com and the ID of a Business or Enterprise workspace.",
  },
  "replicate.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from replicate.com, plus the user or organization name to read billing for.",
  },
  "raycast.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from a signed-in www.raycast.com request, not the desktop app's token.",
  },
  "lithosai.session": {
    label: "Pasted session",
    howto: "Paste the console Cookie header and the organization ID sent with a console billing request.",
  },
  "workbuddy.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header and the user agent from the same Chrome request to www.workbuddy.cn.",
  },
  "tinyapi.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from a signed-in tinyapi.rest request.",
  },
  "parallel.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from a signed-in platform.parallel.ai request.",
  },
  "claude_platform.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from platform.claude.com and your organization ID from its settings page.",
  },
};

export const LANE_C2_WORDS: Record<string, string> = {
  tenant: "Dashboard",
  helmcode_cloud: "Helmcode Cloud",
  nan_builders: "NaN Builders",
  account_name: "Account name",
  account_type: "Account type",
  user: "Personal account",
  organization: "Organization",
  user_agent: "Browser user agent",
};
