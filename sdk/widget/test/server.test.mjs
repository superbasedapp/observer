// W5-6: the server half the README documents. The widget's body goes to the
// app's own route, which calls the SDK's feedback() with the ids it rendered.
// Runs the README's Node handler against the TypeScript SDK (sdk/typescript,
// built) and a loopback stand-in for the machine. Skipped where the SDK is
// not built next to this package.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import http from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SDK = join(here, "..", "..", "typescript", "dist", "esm", "index.js");
const TRACE = "4bf92f3577b34da6a3ce929d0e0e4736";

test("the package loads where there is no DOM (server rendering) and defines nothing there", () => {
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", `import(${JSON.stringify(join(here, "..", "dist", "index.js"))}).then((w) => { console.log(w.defineFeedbackElement(), typeof w.FeedbackElement); return import(${JSON.stringify(join(here, "..", "dist", "define.js"))}); }).then(() => console.log("define ok"))`], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.stdout.trim().split("\n"), ["superbased-feedback function", "define ok"]);
});

// The README's Node server half, verbatim in substance.
function handler(sdk) {
  return async (body) => {
    const { trace_id, span_id, value, comment } = body;
    if (typeof value !== "boolean") return { status: 400 };
    // Your app checks here that trace_id is an answer it rendered for this user (for example by verifying body.token).
    // The score name is the server's, not the browser's (R-C37).
    const r = await sdk.feedback(value, { traceId: trace_id, spanId: span_id, comment, name: "user_feedback" });
    return { status: r.ok ? 204 : 502 };
  };
}

test("the README's Node handler turns the widget's body into the SDK's feedback score", { skip: !existsSync(SDK) && "sdk/typescript is not built" }, async () => {
  const sdk = await import(SDK);
  const posted = [];
  const machine = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      posted.push({ path: req.url, auth: req.headers.authorization, body: JSON.parse(raw) });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ api_version: "v1", accepted: [{ index: 0, id: "sc_1" }], rejected: [] }));
    });
  });
  await new Promise((r) => machine.listen(0, "127.0.0.1", r));
  try {
    sdk.init({ exporter: { export: (_s, cb) => cb({ code: 0 }), shutdown: async () => {} }, destination: "local", nodeUrl: `http://127.0.0.1:${machine.address().port}` });
    const widgetBody = { trace_id: TRACE, span_id: "00f067aa0ba902b7", value: false, comment: "wrong city", name: "user_feedback", token: "sig" };
    assert.deepEqual(await handler(sdk)(widgetBody), { status: 204 });
    assert.equal(posted[0].path, "/api/obs/scores");
    assert.equal(posted[0].auth, undefined);
    const { id, ...rest } = posted[0].body;
    assert.match(id, /^sdk_/);
    assert.deepEqual(rest, { trace_id: TRACE, span_id: "00f067aa0ba902b7", name: "user_feedback", value: false, kind: "boolean", source: "feedback", comment: "wrong city" });
    assert.deepEqual(await handler(sdk)({ trace_id: TRACE, value: "yes" }), { status: 400 });
    // A forged body cannot choose the score name.
    assert.deepEqual(await handler(sdk)({ ...widgetBody, name: "accuracy" }), { status: 204 });
    assert.equal(posted[1].body.name, "user_feedback");
    await sdk.shutdown(500);
  } finally {
    machine.close();
  }
});

test("R-C37: the README's server examples record the server's score name, never the browser's", () => {
  const readme = readFileSync(join(here, "..", "README.md"), "utf8");
  const server = readme.slice(readme.indexOf("## The server half"), readme.indexOf("## Trust"));
  assert.ok(!/\{[^}]*\bname\b[^}]*\}\s*=\s*req\.body/.test(server), "the Node example does not destructure name from the body");
  assert.ok(!server.includes('body.get("name")'), "the Python example does not read name from the body");
  assert.ok(server.includes('name: "user_feedback"') && server.includes('name="user_feedback"'));
});
