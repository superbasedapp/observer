// A small support chatbot on the OpenAI Node SDK, traced with superbased.
//
// init() then instrument(["openai"]) (ESM: hand the module over), per-request
// identity with propagateAttributes, three Chat Completions turns (one with a
// function tool call), one Responses API call and one streamed call.
// Every call uses gpt-5-nano: max_completion_tokens / max_output_tokens and a
// reasoning effort, no temperature. Runs on Node 22 as plain .ts (type
// stripping). With AI_GATEWAY_URL set, calls go through the org's AI gateway
// with gatewayFetch(), which sends the app identity headers and stamps the
// gateway's request id on the LLM span.
import { writeFileSync } from "node:fs";
import {
  diagnostics, flush, gatewayFetch, getCurrentTraceId, init, instrument, Kind,
  propagateAttributes, shutdown, withSpan, withToolSpan, setToolResult,
} from "@superbased/sdk";

const SERVICE = process.env.SUPERBASED_SERVICE_NAME ?? "openai-chatbot-ts";
const RUN_ID = process.env.RUN_ID ?? String(Date.now());
const MODEL = "gpt-5-nano";
const USER = "user-ada";

init({ serviceName: SERVICE, release: "examples-1" });
const openaiModule = await import("openai");
console.error("instrument:", instrument(["openai"], { modules: { openai: openaiModule } }));
const OpenAI = openaiModule.default;

const client = process.env.AI_GATEWAY_URL
  ? new OpenAI({ baseURL: process.env.AI_GATEWAY_URL, apiKey: process.env.AI_GATEWAY_KEY, fetch: gatewayFetch() })
  : new OpenAI(); // OPENAI_API_KEY from the environment

const orderTool = {
  type: "function" as const,
  function: {
    name: "get_order_status",
    description: "Look up the shipping status of an order by its id.",
    parameters: { type: "object", properties: { order_id: { type: "string" } }, required: ["order_id"] },
  },
};
const getOrderStatus = (orderId: string) => JSON.stringify({ order_id: orderId, status: "shipped", eta_days: 2 });

type Call = { kind: string; id: string; input?: number; output?: number; cached?: number; reasoning?: number };
const calls: Call[] = [];
const record = (kind: string, id: string, u: any) => {
  if (!u) return void calls.push({ kind, id });
  if ("prompt_tokens" in u) {
    calls.push({ kind, id, input: u.prompt_tokens, output: u.completion_tokens,
      cached: u.prompt_tokens_details?.cached_tokens ?? 0, reasoning: u.completion_tokens_details?.reasoning_tokens ?? 0 });
  } else {
    calls.push({ kind, id, input: u.input_tokens, output: u.output_tokens,
      cached: u.input_tokens_details?.cached_tokens ?? 0, reasoning: u.output_tokens_details?.reasoning_tokens ?? 0 });
  }
};

async function chat(messages: any[]) {
  const resp = await client.chat.completions.create({
    model: MODEL, messages, tools: [orderTool], max_completion_tokens: 400, reasoning_effort: "minimal",
  });
  record("chat", resp.id, resp.usage);
  return resp.choices[0].message;
}

const user = USER, session = `chat-ts-${RUN_ID}`, tenant = "acme";
const traceIds: string[] = [];

await propagateAttributes({ user, sessionId: session, tenant, tags: ["example"] }, async () => {
  const messages: any[] = [{ role: "system", content: "You are a terse support bot. Answer in one sentence." }];
  const turns = ["Hi! What can you help me with?", "Where is my order A-1001?", "Thanks. Say goodbye in five words."];
  for (const [i, text] of turns.entries()) {
    await withSpan(`turn-${i + 1}`, Kind.AGENT, async () => {
      traceIds.push(getCurrentTraceId());
      messages.push({ role: "user", content: text });
      let msg = await chat(messages);
      if (msg.tool_calls?.length) {
        messages.push(msg);
        for (const tc of msg.tool_calls as any[]) {
          const args = JSON.parse(tc.function.arguments || "{}");
          const result = await withToolSpan("get_order_status", { toolName: tc.function.name, callId: tc.id, arguments: args },
            async (span) => { const r = getOrderStatus(args.order_id); setToolResult(span, r); return r; });
          messages.push({ role: "tool", tool_call_id: tc.id, content: result });
        }
        msg = await chat(messages);
      }
      messages.push({ role: "assistant", content: msg.content ?? "" });
      console.log(`turn ${i + 1}: ${JSON.stringify(text)} -> ${JSON.stringify(msg.content)}`);
    });
  }
  await withSpan("responses-api", Kind.AGENT, async () => {
    traceIds.push(getCurrentTraceId());
    const r = await client.responses.create({
      model: MODEL, input: "Name one primary colour. One word.", max_output_tokens: 300, reasoning: { effort: "minimal" },
    });
    record("responses", r.id, r.usage);
    console.log("responses:", r.output_text);
  });
  await withSpan("streamed", Kind.AGENT, async () => {
    traceIds.push(getCurrentTraceId());
    const stream = await client.chat.completions.create({
      model: MODEL, messages: [{ role: "user", content: "Count to three, digits only." }],
      max_completion_tokens: 300, reasoning_effort: "minimal", stream: true, stream_options: { include_usage: true },
    });
    let text = "", id = "", usage: any = null;
    for await (const chunk of stream) {
      id = chunk.id || id;
      if (chunk.usage) usage = chunk.usage;
      text += chunk.choices?.[0]?.delta?.content ?? "";
    }
    record("chat-stream", id, usage);
    console.log("streamed:", text);
  });
});

const ok = await flush();
const d = diagnostics();
const out = {
  service: SERVICE, run_id: RUN_ID, user, session, tenant, trace_ids: traceIds, calls,
  diagnostics: { destination: d.destination, destinations: d.destinations, failedExports: d.failedExports, droppedSpans: d.droppedSpans },
};
writeFileSync(process.env.RUN_OUT ?? "run.json", JSON.stringify(out, null, 2));
console.error(JSON.stringify(out.diagnostics));
await shutdown();
process.exitCode = ok ? 0 : 1;
