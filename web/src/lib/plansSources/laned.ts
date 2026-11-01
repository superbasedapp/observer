// Words for the sources lane D adds (internal/planlimits/src_laned.go).
// Pure data; plans.ts merges it. Keys of LANE_D are source ids; keys of
// LANE_D_WORDS are new parameter keys and parameter choices.
import type { SourceWords } from "./types.ts";

export const LANE_D: Record<string, SourceWords> = {
  "openai_api.admin": {
    label: "Admin key",
    howto: "Paste an OpenAI organization admin key. A project ID is optional and limits spend to that project.",
  },
  "openai_api.credit_grants": {
    label: "Credit balance",
    howto: "Paste an OpenAI API key to read your credit balance. Uses an endpoint OpenAI has not documented.",
  },
  "anthropic_api.admin": {
    label: "Admin key",
    howto: "Paste an Anthropic organization admin key to read this month's spend.",
  },
  "aws_bedrock.budget": {
    label: "AWS budget",
    howto: "Make a cost budget for Bedrock in AWS Budgets, then add its name, your account ID and an access key that can view budgets.",
  },
  "grok.agent": {
    label: "Grok CLI",
    howto: "Runs grok on this machine to read your billing. Grok must be signed in.",
  },
  "jetbrains_ai.quota_file": {
    label: "IDE quota file",
    howto: "Reads the AI credit quota your JetBrains IDE saved on this machine. No network call. It can lag behind the IDE.",
  },
  "nous_portal.hermes": {
    label: "Hermes sign in",
    howto: "Reads Hermes Agent's own Nous Portal sign in on this machine, read-only. Run hermes again when it expires.",
  },
  "muse_code.web": {
    label: "Pasted session",
    howto: "Paste your dev.meta.ai browser session and the ID of the team whose subscription quota you want to see.",
  },
  "coderabbit.cli": {
    label: "CodeRabbit CLI",
    howto: "Runs coderabbit on this machine to read your review count. CodeRabbit must be signed in.",
  },
  "doubao.arkcli": {
    label: "Ark CLI",
    howto: "Runs arkcli on this machine to read your Coding Plan and Agent Plan usage. Ark CLI must be signed in.",
  },
};

export const LANE_D_WORDS: Record<string, string> = {
  access_key_id: "AWS access key ID",
  budget_name: "Budget name",
};
