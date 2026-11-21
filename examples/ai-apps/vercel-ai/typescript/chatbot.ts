// A Vercel AI SDK (v7) chatbot with one tool, traced with superbased.
//
// instrument(["vercel-ai"]) registers the AI SDK's own OpenTelemetry
// integration (@ai-sdk/otel) with the SDK's provider; its invoke_agent, step
// and chat spans carry the GenAI semantic conventions superbased reads.
// Model: gpt-5-nano through @ai-sdk/openai (a reasoning model: a reasoning
// effort and an output cap, no temperature).
import { writeFileSync } from "node:fs";
import { diagnostics, flush, getCurrentTraceId, init, instrument, Kind, propagateAttributes, shutdown, withSpan } from "@superbased/sdk";

const SERVICE = process.env.SUPERBASED_SERVICE_NAME ?? "vercel-ai-chatbot-ts";
const RUN_ID = process.env.RUN_ID ?? String(Date.now());

init({ serviceName: SERVICE, release: "examples-1" });
const ai = await import("ai");
console.error("instrument:", instrument(["vercel-ai"], { modules: { "vercel-ai": { ai, otel: await import("@ai-sdk/otel") } } }));
const { openai } = await import("@ai-sdk/openai");
const { z } = await import("zod");

const getOrderStatus = ai.tool({
  description: "Look up the shipping status of an order by its id.",
  inputSchema: z.object({ order_id: z.string() }),
  execute: async ({ order_id }: { order_id: string }) => ({ order_id, status: "shipped", eta_days: 2 }),
});

const user = "user-ada", session = `va-ts-${RUN_ID}`, tenant = "acme";
const traceIds: string[] = [];
const calls: any[] = [];
const messages: any[] = [];
await propagateAttributes({ user, sessionId: session, tenant }, async () => {
  for (const [i, text] of ["Hi, who are you?", "Where is my order A-1001?", "Thanks, bye."].entries()) {
    messages.push({ role: "user", content: text });
    const result: any = await withSpan(`turn-${i + 1}`, Kind.AGENT, async () => {
      traceIds.push(getCurrentTraceId());
      return ai.generateText({
        model: openai("gpt-5-nano"),
        system: "You are a terse support bot. One sentence answers.",
        messages,
        tools: { get_order_status: getOrderStatus },
        stopWhen: ai.stepCountIs(4),
        maxOutputTokens: 400,
        providerOptions: { openai: { reasoningEffort: "minimal" } },
      });
    });
    for (const s of result.steps ?? []) {
      calls.push({ kind: "step", input: s.usage?.inputTokens, output: s.usage?.outputTokens });
    }
    messages.push(...result.response.messages);
    console.log(`turn ${i + 1}: ${JSON.stringify(text)} -> ${JSON.stringify(result.text)}`);
  }
});

const ok = await flush();
const d = diagnostics();
writeFileSync(process.env.RUN_OUT ?? "run.json", JSON.stringify({
  service: SERVICE, run_id: RUN_ID, user, session, tenant, trace_ids: traceIds, calls,
  diagnostics: { destination: d.destination, destinations: d.destinations, failedExports: d.failedExports, droppedSpans: d.droppedSpans },
}, null, 2));
await shutdown();
process.exitCode = ok ? 0 : 1;
