// Words for the sources lane A adds (internal/planlimits/src_lanea.go).
// Pure data; plans.ts merges it. Keys of LANE_A are source ids; keys of
// LANE_A_WORDS are new parameter keys and parameter choices.
import type { SourceWords } from "./types.ts";

export const LANE_A: Record<string, SourceWords> = {
  "clinepass.api": { label: "Cline key", howto: "Paste a Cline API key. Uses an endpoint Cline has not documented." },
  "opencode_go.api": { label: "OpenCode key", howto: "Paste an OpenCode API key. Uses an endpoint OpenCode has not documented." },
  "factory.api": { label: "Factory key", howto: "Paste a Factory API key. Uses an endpoint Factory has not documented." },
  "fireworks.api": {
    label: "Fireworks key",
    howto: "Paste a Fireworks API key and your account ID. Uses an endpoint Fireworks has not documented.",
  },
  "zai.api": { label: "Z.ai key", howto: "Paste a Z.ai or BigModel key and pick its region. Uses an endpoint Z.ai has not documented." },
  "minimax.api": { label: "MiniMax key", howto: "Paste a MiniMax plan key and pick its region. Uses an endpoint MiniMax has not documented." },
  "kilo.api": { label: "Kilo key", howto: "Paste a Kilo API key. Uses an endpoint Kilo has not documented." },
  "synthetic.api": { label: "API key", howto: "Paste a Synthetic API key. Observer reads your quotas only." },
  "elevenlabs.api": {
    label: "ElevenLabs key",
    howto: "Paste an ElevenLabs key that can read your user. Uses an endpoint ElevenLabs has not documented.",
  },
  "warp.api": { label: "Warp key", howto: "Paste a Warp API key. Uses an endpoint Warp has not documented." },
  "deepinfra.api": { label: "DeepInfra key", howto: "Paste a DeepInfra API key. Uses an endpoint DeepInfra has not documented." },
  "codebuff.api": { label: "Codebuff key", howto: "Paste a Codebuff API key. Uses an endpoint Codebuff has not documented." },
  "venice.api": { label: "Venice key", howto: "Paste a Venice API key. Uses an endpoint Venice has not documented." },
  "command_code.api": {
    label: "Command Code key",
    howto: "Paste a Command Code API key. Uses an endpoint Command Code has not documented.",
  },
  "poe.api": { label: "Poe key", howto: "Paste a Poe API key. Uses an endpoint Poe has not documented." },
  "chutes.api": { label: "Chutes key", howto: "Paste a Chutes API key. Uses an endpoint Chutes has not documented." },
  "neuralwatt.api": { label: "Neuralwatt key", howto: "Paste a Neuralwatt API key. Uses an endpoint Neuralwatt has not documented." },
  "zenmux.management": { label: "Management key", howto: "Paste a ZenMux management key. Observer reads your plan and balance only." },
  "aiand.api": { label: "API key", howto: "Paste an ai& API key. Observer reads your last 30 days of request costs." },
  "ibm_bob.api": { label: "Bob key", howto: "Paste an IBM Bob API key. Uses an endpoint IBM has not documented." },
  "hugging_face.api": {
    label: "Hugging Face token",
    howto: "Paste a Hugging Face token that can read billing. Uses an endpoint Hugging Face has not documented.",
  },
  "v0.api": { label: "API key", howto: "Paste a v0 API key. A project ID is optional. Observer reads billing and limits only." },
};

export const LANE_A_WORDS: Record<string, string> = {};
