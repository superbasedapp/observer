// Shared test helpers: SDK/global reset and a scripted local HTTP stub.
import http from "node:http";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { context, propagation, trace } from "@opentelemetry/api";

import * as sb from "../dist/esm/index.js";

const SDK_ENV = /^(SUPERBASED_(?!CONTRACT_DIR|REPO_ROOT|RECORD_FIXTURES)|OTEL_|OBSERVER_CAPTURE|ANTHROPIC_OPEN_TELEMETRY)/;

export async function reset() {
  await sb._resetForTests();
  trace.disable();
  context.disable();
  propagation.disable();
  for (const k of Object.keys(process.env)) if (SDK_ENV.test(k)) delete process.env[k];
  // Never read a real SDK-held credential file of the person running the tests.
  process.env.SUPERBASED_CREDENTIAL_FILE = NO_CREDENTIAL_FILE;
}

/** A credential-file path that never exists (reset() points SUPERBASED_CREDENTIAL_FILE here). */
export const NO_CREDENTIAL_FILE = join(tmpdir(), `sbo-no-sdk-credential-${process.pid}`, "sdk-credential");

export async function startStub() {
  const stub = {
    status: 200,
    body: "{}",
    headers: {},
    delayMs: 0,
    requests: [],
    /** Replies used one per request, before falling back to reply(). */
    queue: [],
    /** Optional (request) => {status, body, headers} | undefined, consulted first. */
    handler: null,
    reply(body, status = 200, headers = {}) {
      this.body = typeof body === "string" ? body : JSON.stringify(body);
      this.status = status;
      this.headers = headers;
    },
  };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks);
      let body;
      try {
        body = JSON.parse(raw.toString("utf8"));
      } catch {
        body = raw;
      }
      const rec = { method: req.method, path: req.url, headers: req.headers, body };
      stub.requests.push(rec);
      const routed = stub.handler ? stub.handler(rec) : undefined;
      const next = routed ?? stub.queue.shift();
      const [status, payload, headers] = next
        ? [next.status ?? 200, typeof next.body === "string" ? next.body : JSON.stringify(next.body ?? {}), next.headers ?? {}]
        : [stub.status, stub.body, stub.headers];
      setTimeout(() => {
        res.writeHead(status, { "Content-Type": "application/json", ...headers });
        res.end(payload);
      }, stub.delayMs);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  stub.url = `http://127.0.0.1:${server.address().port}`;
  stub.close = () =>
    new Promise((r) => {
      server.closeAllConnections?.();
      server.close(() => r());
    });
  return stub;
}

/** A URL on a port nothing listens on. */
export async function deadUrl() {
  const srv = net.createServer();
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  await new Promise((r) => srv.close(r));
  return `http://127.0.0.1:${port}`;
}

export function byName(spans) {
  return Object.fromEntries(spans.map((s) => [s.name, s]));
}
