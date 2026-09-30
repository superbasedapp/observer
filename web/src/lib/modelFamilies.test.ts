// Pins shared/lib/modelFamilies.ts (the ordered RULES table that picks a
// model id's family mark). Three tables, one case per row:
//   1. one case per RULES row, in table order (a new rule needs a new row);
//   2. the key cases from the design brief (family beats host prefix, routes
//      are "auto", stealth ids stay unmarked, never guess);
//   3. every distinct model id seen in a real node DB when the table was built
//      (design kit brand-marks/generated/matcher-coverage.txt, 2026-09-28).
import { test } from "node:test";
import assert from "node:assert/strict";
import { modelFamily } from "../../../shared/lib/modelFamilies.ts";

type Case = [id: string, family: string | null];

const perRule: Case[] = [
  ["<synthetic>", "synthetic"],
  ["claude-opus-5", "claude"],
  ["anthropic/opus", "claude"],
  ["gpt-oss-120b", "gpt-oss"],
  ["gpt-5.5", "openai"],
  ["o3-mini", "openai"],
  ["gemma-3-27b", "gemma"],
  ["gemini-2.5-pro", "gemini"],
  ["grok-4", "grok"],
  ["llama-3.3-70b", "llama"],
  ["muse-spark-1.2", "meta-ai"],
  ["codestral-latest", "mistral"],
  ["deepseek-v4-flash", "deepseek"],
  ["qwen3-coder", "qwen"],
  ["kimi-k2", "kimi"],
  ["glm-4.6", "glm"],
  ["minimax-m2", "minimax"],
  ["nvidia/nemotron-3-ultra", "nemotron"],
  ["phi-4", "microsoft"],
  ["amazon.nova-pro", "nova"],
  ["command-r-plus", "cohere"],
  ["sonar-pro", "sonar"],
  ["step-3.7-flash", "stepfun"],
  ["sakana/fugu-ultra", "sakana"],
  ["laguna-s-2.1", "poolside"],
  ["composer-2.5", "cursor"],
  ["swe-1-6", "windsurf"],
  ["doubao-seed-1.6", "doubao"],
  ["hunyuan-t1", "hunyuan"],
  ["ernie-4.5", "ernie"],
  ["yi-lightning", "yi"],
  ["jamba-1.5-large", "jamba"],
  ["openrouter/auto", "auto"],
];

const briefCases: Case[] = [
  ["cursor-grok-4.6-high", "grok"],
  ["openrouter/deepseek/deepseek-v4-flash-0731", "deepseek"],
  ["openrouter/free", "auto"],
  ["auto", "auto"],
  ["copilot/auto", "auto"],
  ["kilo-auto/free", "auto"],
  ["<synthetic>", "synthetic"],
  ["big-pickle", null],
  ["x-preview-f-free", null],
  ["oswe-vscode-prime", null],
  ["gpt-4-turbo", "openai"],
  ["", null],
  ["  CLAUDE-SONNET-4-5  ", "claude"],
];

const observed: Case[] = [
  ["claude-sonnet-5", "claude"],
  ["claude-opus-4-8", "claude"],
  ["claude-opus-5", "claude"],
  ["claude-opus-4-7", "claude"],
  ["claude-opus-5-5", "claude"],
  ["gpt-5.6-sol", "openai"],
  ["claude-fable-5", "claude"],
  ["claude-fable-5-1", "claude"],
  ["claude-opus-4-6", "claude"],
  ["gpt-6-astra", "openai"],
  ["claude-haiku-4-5-20251001", "claude"],
  ["gpt-5.6-luna", "openai"],
  ["gemini-3-pro-high", "gemini"],
  ["codex-auto-review", "openai"],
  ["gemini-3.1-pro-high", "gemini"],
  ["gpt-5.5", "openai"],
  ["x-preview-f-free", null],
  ["gpt-5.6-terra", "openai"],
  ["claude-sonnet-4-6", "claude"],
  ["gpt-5.4-mini", "openai"],
  ["claude-sonnet-4-5", "claude"],
  ["gpt-5.4", "openai"],
  ["deepseek-v4-flash-free", "deepseek"],
  ["deepseek/deepseek-v4-flash", "deepseek"],
  ["gemini-default", "gemini"],
  ["claude-opus-4-8[1m]", "claude"],
  ["muse-spark-1.2-contributor-free", "meta-ai"],
  ["claude-opus-4-5-20251101", "claude"],
  ["openai-codex/gpt-5.5", "openai"],
  ["gemini-3-flash-a", "gemini"],
  ["kilo-auto/free", "auto"],
  ["gpt-5.4-nano", "openai"],
  ["muse-spark-1.2-contributor", "meta-ai"],
  ["cursor-grok-4.6-high", "grok"],
  ["nvidia/nemotron-3.5-lightning:free", "nemotron"],
  ["gemini-3.5-flash-low", "gemini"],
  ["gpt-4o", "openai"],
  ["gemini-3.5-flash", "gemini"],
  ["default", "auto"],
  ["grok-4.5", "grok"],
  ["gpt-5-mini", "openai"],
  ["cursor-grok-4.5-high", "grok"],
  ["GLM-5.3", "glm"],
  ["grok-4.6", "grok"],
  ["cline-pass/glm-5.2", "glm"],
  ["openrouter/free", "auto"],
  ["gpt-4.1-mini-2025-04-14", "openai"],
  ["claude-haiku-4.5", "claude"],
  ["gemini-3.6-flash", "gemini"],
  ["nemotron-3-ultra-550b-a55b:free", "nemotron"],
  ["<synthetic>", "synthetic"],
  ["gemini-3-flash-medium-a", "gemini"],
  ["auto", "auto"],
  ["swe-1-6-slow", "windsurf"],
  ["stepfun/step-3.7-flash", "stepfun"],
  ["sakana/fugu-ultra", "sakana"],
  ["turbo", "auto"],
  ["openrouter/deepseek/deepseek-v4-flash-0731", "deepseek"],
  ["gpt-5-6-thinking", "openai"],
  ["poolside/laguna-s-2.1-free", "poolside"],
  ["gemini-3-flash-agent", "gemini"],
  ["claude-fable-5[1m]", "claude"],
  ["claude-sonnet-4-5-20250929", "claude"],
  ["smart", "auto"],
  ["gemini-2.5-flash", "gemini"],
  ["step-3.7-flash:free", "stepfun"],
  ["openai/gpt-5.4-nano", "openai"],
  ["gpt-5.3-chat-latest", "openai"],
  ["gpt-4o-mini", "openai"],
  ["gemini-pro-agent", "gemini"],
  ["stepfun/step-3.7-flash:free", "stepfun"],
  ["mai-code-1-flash-secondary", "microsoft"],
  ["gemini-3.1-pro-low", "gemini"],
  ["gpt-5-mini-2025-08-07", "openai"],
  ["glm-5.2", "glm"],
  ["composer-2.5", "cursor"],
  ["claude-opus-4-7[1m]", "claude"],
  ["oswe-vscode-prime", null],
  ["cursor-grok-4.6-high-fast", "grok"],
  ["big-pickle", null],
  ["mistral-medium-3.5", "mistral"],
  ["gpt-4o-2024-08-06", "openai"],
  ["gpt-4.1-2025-04-14", "openai"],
  ["custom:GPT-5.4-Mini-[OpenAI-BYOK]-0", "openai"],
  ["copilot/auto", "auto"],
  ["pplx_pro_upgraded", "sonar"],
  ["observer/gpt-4o-mini-2024-07-18", "openai"],
  ["nemotron-3-ultra-free", "nemotron"],
  ["grok-code-fast-1", "grok"],
  ["gpt-5-5", "openai"],
];

for (const [name, cases] of [["per rule", perRule], ["brief", briefCases], ["observed ids", observed]] as const) {
  test(`modelFamily: ${name}`, () => {
    for (const [id, want] of cases) {
      assert.equal(modelFamily(id)?.id ?? null, want, `modelFamily(${JSON.stringify(id)})`);
    }
  });
}

test("synthetic is the only hidden family", () => {
  assert.equal(modelFamily("<synthetic>")?.hidden, true);
  for (const [id] of perRule) {
    if (id !== "<synthetic>") assert.ok(!modelFamily(id)?.hidden, id);
  }
});
