// A CommonJS app with the one-line init (plan 2.3): init() first, the model
// library required afterwards. Prints what init() reported, what it reports
// after the first require, and the spans a chat completion produced.
"use strict";
const http = require("node:http");
const { InMemorySpanExporter } = require("@opentelemetry/sdk-trace-base");
const sb = require("@superbased/sdk");

const mem = new InMemorySpanExporter();
sb.init({ exporter: mem, discover: false, destination: "local", serviceName: "cjs-fixture" });
const before = sb.diagnostics().instrumented;

const server = http.createServer((req, res) => {
  req.resume();
  req.on("end", () => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        id: "chatcmpl-fixture",
        object: "chat.completion",
        created: 1763510400,
        model: "gpt-4o-mini",
        choices: [{ index: 0, finish_reason: "stop", message: { role: "assistant", content: "Paris." } }],
        usage: { prompt_tokens: 10, completion_tokens: 2, total_tokens: 12 },
      }),
    );
  });
});

server.listen(0, "127.0.0.1", async () => {
  try {
    const mod = require("openai"); // the first require: init() instruments it here
    const after = sb.diagnostics().instrumented;
    const OpenAI = mod.default ?? mod.OpenAI ?? mod;
    const client = new OpenAI({ apiKey: "sk-fixture", baseURL: `http://127.0.0.1:${server.address().port}/v1` });
    await client.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: "Capital of France?" }] });
    await sb.flush(5000);
    const spans = mem.getFinishedSpans().map((s) => s.name);
    console.log(JSON.stringify({ before, after, spans, instrumented: sb.instrumented() }));
  } finally {
    server.close();
    await sb.shutdown(1000);
  }
});
