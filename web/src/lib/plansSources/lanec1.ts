// Words for the sources lane C1 adds (internal/planlimits/src_lanec1.go).
// Pure data; plans.ts merges it. Keys of LANE_C1 are source ids; keys of
// LANE_C1_WORDS are new parameter keys and parameter choices.
import type { SourceWords } from "./types.ts";

export const LANE_C1: Record<string, SourceWords> = {
  "opencode.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from an opencode.ai console request and enter your workspace ID.",
  },
  "alibaba_coding_plan.api": {
    label: "API key",
    howto: "Paste your Coding Plan API key. Uses an endpoint Alibaba Cloud has not documented.",
  },
  "alibaba_coding_plan.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from the console quota request, with its security token added as one more cookie.",
  },
  "alibaba_token_plan.cli": {
    label: "Bailian CLI",
    howto: "Sign in with the Bailian CLI on this machine, then pick your region and plan type.",
  },
  "alibaba_token_plan.session": {
    label: "Pasted session",
    howto: "Personal or Solo plans: paste the Cookie header from the Token Plan usage request in your browser.",
  },
  "qwen_cloud.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from a request on your Qwen Cloud individual Token Plan page.",
  },
  "devin.session": {
    label: "Pasted session",
    howto: "Paste the Authorization value of a Devin usage request, and its organization header as the organization ID.",
  },
  "manus.session": {
    label: "Pasted session",
    howto: "Paste a Cookie header from manus.im that holds the session cookie, or that cookie's value alone.",
  },
  "t3_chat.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from the customer data request on the T3 Chat settings page.",
  },
  "langdock.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from a request on your Langdock account usage page.",
  },
  "ollama.api": {
    label: "API key",
    howto: "Paste an Ollama API key from your key settings. Uses an endpoint Ollama has not documented.",
  },
  "zed.session": {
    label: "Pasted session",
    howto: "Sign in at zed.dev in a browser, then paste the Cookie header from a Zed cloud request.",
  },
  "perplexity.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from perplexity.ai, or the session token value alone.",
  },
  "xiaomi_mimo.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from the MiMo console balance page; it must hold the service token and user ID.",
  },
  "sakana.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from a request on the Sakana console billing page.",
  },
  "abacus.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from any Abacus AI apps request in your browser.",
  },
  "mistral.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from a Mistral admin request; it must hold the session cookie.",
  },
  "qoder.session": {
    label: "Pasted session",
    howto: "Paste the Cookie header from your Qoder account usage page and pick the matching site.",
  },
};

export const LANE_C1_WORDS: Record<string, string> = {
  variant: "Plan type",
  team: "Team",
  personal: "Personal or Solo",
};
