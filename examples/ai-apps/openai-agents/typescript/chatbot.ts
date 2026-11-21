// An OpenAI Agents SDK (JS) chatbot with one function tool, traced with superbased.
//
// instrument(["openai-agents"]) adds a tracing processor beside the Agents
// SDK's own (exclusiveProcessor: false): agent, turn, generation and tool
// spans join the enclosing span's trace. Unlike the Python target, the Agents
// SDK's own trace upload to OpenAI keeps running beside it (see README.md).
import { writeFileSync } from "node:fs";
import { diagnostics, flush, getCurrentTraceId, init, instrument, Kind, propagateAttributes, shutdown, withSpan } from "@superbased/sdk";

const SERVICE = process.env.SUPERBASED_SERVICE_NAME ?? "openai-agents-chatbot-ts";
const RUN_ID = process.env.RUN_ID ?? String(Date.now());

init({ serviceName: SERVICE, release: "examples-1" });
const agentsModule = await import("@openai/agents");
console.error("instrument:", instrument(["openai-agents"], { modules: { "openai-agents": agentsModule } }));
const { Agent, run, tool } = agentsModule;
const { z } = await import("zod");

const getOrderStatus = tool({
  name: "get_order_status",
  description: "Look up the shipping status of an order by its id.",
  parameters: z.object({ order_id: z.string() }),
  execute: async ({ order_id }) => JSON.stringify({ order_id, status: "shipped", eta_days: 2 }),
});

const agent = new Agent({
  name: "support",
  instructions: "You are a terse support bot. One sentence answers.",
  model: "gpt-5-nano",
  // gpt-5-nano is a reasoning model: a reasoning effort and a token cap, no temperature.
  modelSettings: { reasoning: { effort: "minimal" }, maxTokens: 400 },
  tools: [getOrderStatus],
});

const user = "user-ada", session = `ag-ts-${RUN_ID}`, tenant = "acme";
const traceIds: string[] = [];
const calls: any[] = [];
let history: any[] = [];
await propagateAttributes({ user, sessionId: session, tenant }, async () => {
  for (const [i, text] of ["Hi, who are you?", "Where is my order A-1001?", "Thanks, bye."].entries()) {
    const result: any = await withSpan(`turn-${i + 1}`, Kind.AGENT, async () => {
      traceIds.push(getCurrentTraceId());
      return run(agent, [...history, { role: "user", content: text }]);
    });
    for (const r of result.rawResponses ?? []) {
      calls.push({ kind: "responses", id: r.responseId, input: r.usage.inputTokens, output: r.usage.outputTokens });
    }
    history = result.history;
    console.log(`turn ${i + 1}: ${JSON.stringify(text)} -> ${JSON.stringify(result.finalOutput)}`);
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
