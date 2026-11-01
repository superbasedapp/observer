// Words for the sources lane B adds (internal/planlimits/src_laneb.go).
// Pure data; plans.ts merges it. Keys of LANE_B are source ids; keys of
// LANE_B_WORDS are new parameter keys and parameter choices.
import type { SourceWords } from "./types.ts";

export const LANE_B: Record<string, SourceWords> = {
  "litellm.gateway": {
    label: "Your LiteLLM proxy",
    howto: "Paste your proxy address and a virtual key. Add a user or team ID to see those budgets too.",
  },
  "bifrost.gateway": {
    label: "Your Bifrost gateway",
    howto: "Paste your gateway address and a virtual key. Observer reads its budgets and rate limits.",
  },
  "aixy.api": {
    label: "Aixy API key",
    howto: "Paste an Aixy gateway key. Observer reads the budgets that apply to it.",
  },
  "aixy.gateway": {
    label: "Your Aixy gateway",
    howto: "Paste your own Aixy gateway address and a key. Observer reads the budgets that apply to it.",
  },
  "llm_proxy.gateway": {
    label: "Your LLM proxy",
    howto: "Paste your proxy address and its key. Uses an endpoint the proxy project has not documented.",
  },
  "clawrouter.api": {
    label: "ClawRouter key",
    howto: "Paste a ClawRouter policy key. Uses an endpoint ClawRouter has not documented.",
  },
  "clawrouter.gateway": {
    label: "Your ClawRouter",
    howto: "Paste your own ClawRouter address and a policy key. Uses an endpoint ClawRouter has not documented.",
  },
  "sub2api.gateway": {
    label: "Your sub2api server",
    howto: "Paste your sub2api address and a group key. Uses an endpoint sub2api has not documented.",
  },
  "deepgram.api": {
    label: "API key",
    howto: "Paste a Deepgram API key and your project ID. Observer reads the project balance only.",
  },
  "charm_hyper.api": {
    label: "API key",
    howto: "Paste a Hyper API key. Observer reads your Hypercredits balance only.",
  },
  "gitkraken_ai.session": {
    label: "Pasted session",
    howto: "Paste the sign in token your GitKraken account page sends. Add your organization ID for its shared pool.",
  },
  "devpass.api": {
    label: "API key",
    howto: "Paste an LLM Gateway API key. Observer reads your DevPass credits and the key's spend.",
  },
  "atlas_cloud.api": {
    label: "API key",
    howto: "Paste an Atlas Cloud key that can read the account balance.",
  },
  "vercel_ai_gateway.api": {
    label: "API key",
    howto: "Paste an AI Gateway API key. Observer reads your team's credit balance and spend.",
  },
  "xkiro.api": {
    label: "API key",
    howto: "Paste an xKiro API key. Observer reads your daily free tokens and wallet. Reading is free.",
  },
  "tavily.api": {
    label: "API key",
    howto: "Paste a Tavily API key. Observer reads your plan and key credits.",
  },
  "linkup.api": {
    label: "API key",
    howto: "Paste a Linkup API key. Observer reads your balance only.",
  },
  "exa.admin": {
    label: "Service key",
    howto: "Paste an Exa team management service key and the ID of the API key to watch.",
  },
  "cosmic_ai.api": {
    label: "Access token",
    howto: "Paste a Cosmic personal access token and your project ID. Uses an endpoint Cosmic has not documented.",
  },
  "aerostack.api": {
    label: "Account token",
    howto: "Paste your Aerostack account token. It expires; paste a new one when asked.",
  },
  "sail_research.api": {
    label: "API key",
    howto: "Paste a Sail API key. Observer reads your organization's balance and recent spend.",
  },
  "sofya.api": {
    label: "API key",
    howto: "Paste a Sofya API key. Observer reads your credits only.",
  },
  "fal.api": {
    label: "API key",
    howto: "Paste a fal key that can read billing. Observer reads your credit balance only.",
  },
  "flora.api": {
    label: "API key",
    howto: "Paste a FLORA key with billing access and your workspace ID.",
  },
};

export const LANE_B_WORDS: Record<string, string> = {
  user_id: "User ID",
  api_key_id: "API key ID",
};
