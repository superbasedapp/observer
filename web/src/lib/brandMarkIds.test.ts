// Pins shared/lib/brandMarkIds.ts: one case per HOST_RULES / IDP_RULES row,
// plus the honesty cases (unmatched -> null, never a guessed vendor).
import { test } from "node:test";
import assert from "node:assert/strict";
import { hostIdFor, idpIdFor } from "../../../shared/lib/brandMarkIds.ts";

const hosts: Array<[string | null, string | null]> = [
  ["aws-bedrock", "bedrock"],
  ["vertex_ai", "vertexai"],
  ["azure_openai", "azure"],
  ["openrouter", "openrouter"],
  ["ollama", "ollama"],
  ["lmstudio", "lmstudio"],
  ["groq", "groq"],
  ["together", "together"],
  ["fireworks", "fireworks"],
  ["cerebras", "cerebras"],
  ["baseten", "baseten"],
  ["huggingface", "huggingface"],
  ["nvidia-nim", "nvidia"],
  ["github-models", "github"],
  ["anthropic", "anthropic"],
  ["OpenAI", "openai"],
  ["google", "google"],
  ["custom", null],
  ["", null],
  [null, null],
];

const idps: Array<[string | null, string | null]> = [
  ["entra", "entra"],
  ["okta", "okta"],
  ["google", "google"],
  ["saml", "saml"],
  ["local", "local"],
  ["oidc", "generic"],
  ["generic", "generic"],
  ["ldap", null],
  [null, null],
];

test("hostIdFor: one case per rule + unmatched", () => {
  for (const [v, want] of hosts) assert.equal(hostIdFor(v), want, String(v));
});

test("idpIdFor: one case per rule + unmatched", () => {
  for (const [v, want] of idps) assert.equal(idpIdFor(v), want, String(v));
});
