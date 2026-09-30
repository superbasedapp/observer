// brandMarkIds — pure resolvers from the free-form strings the APIs send (a
// judge provider, a gateway upstream kind, an IdP preset) to the closed ids
// of the generated HOST_MARKS / IDP_MARKS tables (./brandMarks.tsx). Ordered
// rule tables walked top-down (CLAUDE.md #5); an unmatched value returns null
// and the caller renders no mark (unknown means unknown, never a guess).
//
// A HOST is where a model is served (Bedrock, Azure, OpenRouter, Ollama);
// a model's FAMILY is resolved separately (./modelFamilies.ts). A
// Bedrock-hosted Claude shows the Bedrock host mark AND the Claude family
// mark - the two tables never stand in for each other.

// The closed id unions are owned by the generated table module.
import type { HostId, IdpId } from "./brandMarks";

export type { HostId, IdpId };

const HOST_RULES: ReadonlyArray<readonly [RegExp, HostId]> = [
  [/bedrock|aws/, "bedrock"],
  [/vertex/, "vertexai"],
  [/azure|foundry/, "azure"],
  [/openrouter/, "openrouter"],
  [/ollama/, "ollama"],
  [/lm-?studio/, "lmstudio"],
  [/groq/, "groq"],
  [/together/, "together"],
  [/fireworks/, "fireworks"],
  [/cerebras/, "cerebras"],
  [/baseten/, "baseten"],
  [/hugging-?face|\bhf\b/, "huggingface"],
  [/nvidia|\bnim\b/, "nvidia"],
  [/github|copilot/, "github"],
  [/anthropic/, "anthropic"],
  [/openai/, "openai"],
  [/google|gemini/, "google"],
];

/** The host mark id for a provider / upstream string, or null. */
export function hostIdFor(value: string | null | undefined): HostId | null {
  if (!value) return null;
  const s = value.trim().toLowerCase();
  for (const [re, id] of HOST_RULES) if (re.test(s)) return id;
  return null;
}

const IDP_RULES: ReadonlyArray<readonly [RegExp, IdpId]> = [
  [/entra|azure|microsoft/, "entra"],
  [/okta/, "okta"],
  [/google/, "google"],
  [/saml/, "saml"],
  [/local|password|email/, "local"],
  [/oidc|generic|openid/, "generic"],
];

/** The identity-provider mark id for a rail / preset string, or null. */
export function idpIdFor(value: string | null | undefined): IdpId | null {
  if (!value) return null;
  const s = value.trim().toLowerCase();
  for (const [re, id] of IDP_RULES) if (re.test(s)) return id;
  return null;
}
