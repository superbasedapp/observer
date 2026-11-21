// Minimal superbased TypeScript SDK example.
//
//   cd sdk/typescript && npm install && npm run example
//
// Sends one trace to the Observer on this machine (turn on Settings > Your
// apps in its dashboard), or wherever SUPERBASED_DESTINATION /
// SUPERBASED_ORG_URL point. List it with `observer obs traces` or
// GET http://127.0.0.1:8081/api/obs/traces.

import { randomUUID } from "node:crypto";

import {
  diagnostics,
  init,
  propagateAttributes,
  ready,
  setToolResult,
  setUsage,
  shutdown,
  withAgentSpan,
  withLlmSpan,
  withToolSpan,
} from "@superbased/sdk";

async function main(): Promise<void> {
  init({ serviceName: "quickstart", release: "0.1.0" });
  console.log(`destination: ${(await ready()) || "local"}`);

  await propagateAttributes({ user: "demo", sessionId: "quickstart-1", tags: ["example"] }, () =>
    withAgentSpan("agent.run", {}, async () => {
      await withLlmSpan("chat", { model: "gpt-4o", provider: "openai", prompt: "Say hi" }, async (span) => {
        // ... your real model call goes here; use its real response id ...
        setUsage(span, { inputTokens: 1200, outputTokens: 64, cacheReadTokens: 1024, responseId: `chatcmpl-${randomUUID()}`, response: "hi" });
      });
      withToolSpan("web_search", { arguments: { q: "superbased" } }, (span) => {
        // ... your tool call (sync callbacks return synchronously) ...
        setToolResult(span, ["result"]);
      });
    }),
  );

  await shutdown(); // flush before exit; bounded, never rejects
  const d = diagnostics();
  console.log(d.failedExports ? `export failed: ${d.lastError}` : "sent one trace; list it with `observer obs traces`");
}

void main();
