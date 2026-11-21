// A LangGraph.js ReAct chatbot with one tool on Claude, traced with superbased.
//
// instrument(["langgraph"]) (the LangChain instrumentation; an ESM app hands
// over @langchain/core/callbacks/manager) records graph, node, tool and model
// spans. Three turns share one checkpointer thread. Model: claude-haiku-5-5
// through @langchain/anthropic at low effort (outputConfig: { effort: "low" });
// no temperature (Haiku 5.5 refuses a non-default one). The system prompt is a
// long policy marked with cache_control, so the first model call writes
// Anthropic's prompt cache and the later ones read it.
import { writeFileSync } from "node:fs";
import { diagnostics, flush, getCurrentTraceId, init, instrument, Kind, propagateAttributes, shutdown, withSpan } from "@superbased/sdk";

const SERVICE = process.env.SUPERBASED_SERVICE_NAME ?? "langgraph-anthropic-chatbot-ts";
const RUN_ID = process.env.RUN_ID ?? String(Date.now());

// The Anthropic SDK also traces each API call itself; init() turns that off
// (ANTHROPIC_OPEN_TELEMETRY), so each call is recorded once, by the LangChain
// instrumentation.

init({ serviceName: SERVICE, release: "examples-1" });
console.error("instrument:", instrument(["langgraph"], {
  modules: { langchain: await import("@langchain/core/callbacks/manager") },
}));

const { tool } = await import("@langchain/core/tools");
const { SystemMessage } = await import("@langchain/core/messages");
const { ChatAnthropic } = await import("@langchain/anthropic");
const { MemorySaver } = await import("@langchain/langgraph");
const { createReactAgent } = await import("@langchain/langgraph/prebuilt");
const { z } = await import("zod");

const getOrderStatus = tool(
  async ({ order_id }: { order_id: string }) => JSON.stringify({ order_id, status: "shipped", eta_days: 2 }),
  { name: "get_order_status", description: "Look up the shipping status of an order by its id.", schema: z.object({ order_id: z.string() }) },
);

// Long enough to cache on Haiku 5.5; the run id makes each run write its own entry.
const POLICY = `Policy set ${RUN_ID}.\n` + Array.from({ length: 119 }, (_, k) =>
  `Policy ${k + 1}: Orders placed on business day ${k + 1} ship within ${((k + 1) % 3) + 1} business days; ` +
  `returns are accepted within 30 days with the original receipt.`).join("\n");
const system = new SystemMessage({ content: [{
  type: "text", text: `You are a terse support bot. One sentence answers.\n\n${POLICY}`,
  cache_control: { type: "ephemeral" },
}] });

const model = new ChatAnthropic({ model: "claude-haiku-5-5", maxTokens: 2000, outputConfig: { effort: "low" } });
const agent = createReactAgent({ llm: model, tools: [getOrderStatus], checkpointSaver: new MemorySaver(), prompt: system });

const user = "user-ada", session = `lg-ts-${RUN_ID}`, tenant = "acme";
const traceIds: string[] = [];
const calls: any[] = [];
let seen = 0;
await propagateAttributes({ user, sessionId: session, tenant }, async () => {
  for (const [i, text] of ["Hi, who are you?", "Where is my order A-1001?", "Thanks, bye."].entries()) {
    const state: any = await withSpan(`turn-${i + 1}`, Kind.AGENT, async () => {
      traceIds.push(getCurrentTraceId());
      return agent.invoke({ messages: [{ role: "user", content: text }] }, { configurable: { thread_id: session } });
    });
    for (const m of state.messages.slice(seen)) {
      // LangChain's input_tokens is the whole prompt (Anthropic's input plus the cache).
      const u = m.usage_metadata, d = u?.input_token_details ?? {};
      if (u) calls.push({ kind: "chat", input: u.input_tokens, output: u.output_tokens, cached: d.cache_read ?? 0,
        cache_write: (d.cache_creation ?? 0) + (d.ephemeral_5m_input_tokens ?? 0) + (d.ephemeral_1h_input_tokens ?? 0) });
    }
    seen = state.messages.length;
    console.log(`turn ${i + 1}: ${JSON.stringify(text)} -> ${JSON.stringify(state.messages.at(-1).text ?? state.messages.at(-1).content)}`);
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
