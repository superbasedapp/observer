// A LangGraph.js ReAct chatbot with one tool, traced with superbased.
//
// instrument(["langgraph"]) (the LangChain instrumentation; an ESM app hands
// over @langchain/core/callbacks/manager) records graph, node, tool and model
// spans. Three turns share one checkpointer thread. Model: gpt-5-nano through
// @langchain/openai (a reasoning model: reasoning effort and a completion cap,
// no temperature).
import { writeFileSync } from "node:fs";
import { diagnostics, flush, getCurrentTraceId, init, instrument, Kind, propagateAttributes, shutdown, withSpan } from "@superbased/sdk";

const SERVICE = process.env.SUPERBASED_SERVICE_NAME ?? "langgraph-chatbot-ts";
const RUN_ID = process.env.RUN_ID ?? String(Date.now());

init({ serviceName: SERVICE, release: "examples-1" });
console.error("instrument:", instrument(["langgraph"], {
  modules: { langchain: await import("@langchain/core/callbacks/manager") },
}));

const { tool } = await import("@langchain/core/tools");
const { ChatOpenAI } = await import("@langchain/openai");
const { MemorySaver } = await import("@langchain/langgraph");
const { createReactAgent } = await import("@langchain/langgraph/prebuilt");
const { z } = await import("zod");

const getOrderStatus = tool(
  async ({ order_id }: { order_id: string }) => JSON.stringify({ order_id, status: "shipped", eta_days: 2 }),
  { name: "get_order_status", description: "Look up the shipping status of an order by its id.", schema: z.object({ order_id: z.string() }) },
);

const model = new ChatOpenAI({ model: "gpt-5-nano", reasoning: { effort: "minimal" }, maxTokens: 400 });
const agent = createReactAgent({
  llm: model, tools: [getOrderStatus], checkpointSaver: new MemorySaver(),
  prompt: "You are a terse support bot. One sentence answers.",
});

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
      const u = m.usage_metadata;
      if (u) calls.push({ kind: "chat", input: u.input_tokens, output: u.output_tokens });
    }
    seen = state.messages.length;
    console.log(`turn ${i + 1}: ${JSON.stringify(text)} -> ${JSON.stringify(state.messages.at(-1).content)}`);
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
