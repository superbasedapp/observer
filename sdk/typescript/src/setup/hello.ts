/**
 * The hello span and the arrival check (plan 3.8).
 *
 * Hello: the SDK this package ships, `init({ destination, serviceName,
 * instrument: "off" })`, one span named `superbased setup: hello from
 * <service>` with `sbo.setup.hello = true` and no content, then `flush()`.
 * The runtime is imported here, on demand, and only here: the rest of setup
 * is Node built-ins.
 *
 * Arrival: the local leg reads `GET <node_url>/api/obs/trace/{id}`; the
 * online leg `GET <gateway>/v1/sdk/traces/{id}/cost` with the key in use
 * (scope `sdk:read`; a trace not stored yet is a 404). Every second, up to
 * 60 s.
 *
 * Refusals (the 3.8 table): an export the plan refused is read with the
 * runtime's one plan-refusal parser. The OTLP exporter retries a 429 and
 * drops its body, so after a failed online export setup sends one empty
 * OTLP request (no spans, nothing counted) to read the refusal the ingest
 * gateway answers. setup prints the server's message as sent and the
 * upgrade link when there is one, never a plan name of its own.
 *
 * The key the arrival check sends stays inside this module (read from the
 * runtime's settings, where it is not enumerable); it is never returned.
 */

import type * as Runtime from "../index.js";
import { obj, str, type HttpFn } from "./net.js";
import { EXIT, type Clock } from "./device.js";

/** The SDK-owned attribute on the hello span (attrs.ts `K.setupHello`; sdk-attribute-keys.json `sdk_owned`). */
export const SETUP_HELLO_ATTR = "sbo.setup.hello";
export const ARRIVAL_WINDOW_MS = 60_000;
export const ARRIVAL_EVERY_MS = 1000;

/** The hello span's name. */
export function helloSpanName(service: string): string {
  return `superbased setup: hello from ${service}`;
}

/** A plan refusal as setup says it: the message as sent, then the next step and link (pure). */
export function refusalLines(status: number, body: unknown): string[] {
  const b = obj(body);
  const message = str(b, "message");
  const code = str(b, "error");
  const link = str(b, "upgrade_url");
  const lines = [message || `The organization refused AI Apps ingest (${code || `HTTP ${status}`}).`];
  if (code === "plan_required") {
    if (link) lines.push(`Change the plan: ${link}`);
    return lines;
  }
  const resets = str(obj(b.quota), "resets_at");
  if (link) lines.push(`${resets ? `Ingest resumes ${resets}. ` : ""}More: ${link}`);
  else lines.push(`${resets ? `Ingest resumes ${resets}; ` : "This is not a plan limit: "}your organization set this cap itself (Settings > Server > Runtime settings).`);
  return lines;
}

/** Whether a body is one of the ingest plan refusals setup can meet (the AI gateway codes never reach setup). */
export function isIngestRefusal(status: number, body: unknown): boolean {
  const code = str(obj(body), "error");
  return (status === 403 && code === "plan_required") || (status === 429 && (code === "planea_events_quota_exceeded" || code === "planea_bytes_quota_exceeded"));
}

export interface HelloInput {
  destination: "local" | "online" | "both";
  serviceName: string;
  nodeUrl: string;
}

export type HelloOutcome =
  | {
      kind: "sent";
      traceId: string;
      /** The links (each "" when its base is unknown). */
      localUrl: string;
      onlineUrl: string;
      /** Check arrival (true = arrived; a stop when the check itself was refused). */
      arrival: (http: HttpFn, clock: Clock) => Promise<"arrived" | "not_seen" | { exit: number; message: string }>;
      shutdown: () => Promise<void>;
    }
  | { kind: "refused"; lines: string[]; shutdown: () => Promise<void> }
  | { kind: "failed"; exit: number; message: string; shutdown: () => Promise<void> };

/** Load the runtime this package ships (tests may hand one in). */
export async function loadRuntime(): Promise<typeof Runtime> {
  return (await import("../index.js")) as typeof Runtime;
}

/** Send the hello span through the runtime. */
export async function sendHello(input: HelloInput, http: HttpFn, sdk?: typeof Runtime): Promise<HelloOutcome> {
  const rt = sdk ?? (await loadRuntime());
  // setup prints its own link; the runtime's first-trace line would repeat it.
  process.env[rt.FIRST_TRACE_ENV] = "0";
  rt.init({ destination: input.destination, serviceName: input.serviceName, instrument: "off", nodeUrl: input.nodeUrl, exitHook: false });
  const shutdown = async () => {
    await rt.shutdown(2000);
  };
  await rt.ready();
  const d0 = rt.diagnostics();
  const s = rt.settings();
  const online = input.destination === "online" || input.destination === "both";
  if (online && !d0.destinations.some((x) => x.name === "online")) {
    return { kind: "failed", exit: EXIT.environment, message: `The online destination is not usable: ${d0.destinationProblems[0] ?? "no key"}.`, shutdown };
  }
  let traceId = "";
  rt.withSpan(helloSpanName(input.serviceName), { attributes: { [SETUP_HELLO_ATTR]: true } }, () => {
    traceId = rt.getCurrentTraceId();
  });
  await rt.flush(15_000);
  const d = rt.diagnostics();
  if (d.planRefusal) {
    return { kind: "refused", lines: refusalLines(d.planRefusal.status, { error: d.planRefusal.code, message: d.planRefusal.message, upgrade_url: d.planRefusal.upgradeUrl, quota: d.planRefusal.quota ? { resets_at: d.planRefusal.quota.resetsAt } : {} }), shutdown };
  }
  const gateway = s?.orgUrl ?? "";
  const key = s?.apiKey ?? "";
  if (online && d.failedExports > 0 && gateway && key) {
    // The exporter drops a retried status's body: ask once with nothing in it.
    try {
      const probe = await http({ method: "POST", url: `${gateway}/v1/traces`, headers: { Authorization: `Bearer ${key}` }, body: { resourceSpans: [] }, timeoutMs: 5000 });
      if (isIngestRefusal(probe.status, probe.body)) return { kind: "refused", lines: refusalLines(probe.status, probe.body), shutdown };
      if (probe.status === 401) return { kind: "failed", exit: EXIT.person, message: "The organization did not accept the SDK key; run setup again.", shutdown };
    } catch {
      // no answer: the arrival check reports it
    }
  }
  const nodeUrl = (s?.nodeUrl ?? input.nodeUrl).replace(/\/+$/, "");
  const id = encodeURIComponent(traceId);
  const localUrl = input.destination !== "online" ? `${nodeUrl}/apps/traces?trace=${id}` : "";
  const dash = d.dashboardUrl.replace(/\/+$/, "");
  const onlineUrl = online && dash ? `${dash}/trajectories?trace=${id}` : "";
  const arrival = async (h: HttpFn, clock: Clock) => {
    const until = clock.now() + ARRIVAL_WINDOW_MS;
    while (clock.now() < until) {
      try {
        if (online) {
          const a = await h({ method: "GET", url: `${gateway}/v1/sdk/traces/${id}/cost`, headers: { Authorization: `Bearer ${key}` }, timeoutMs: 5000 });
          if (a.status === 200) return "arrived" as const;
          if (a.status === 401) return { exit: EXIT.person, message: "The organization did not accept the SDK key; run setup again." };
          if (isIngestRefusal(a.status, a.body)) return { exit: EXIT.refused, message: refusalLines(a.status, a.body).join("\n") };
          if (a.status === 503) return "not_seen" as const; // this organization cannot say; the link still works
        } else {
          const a = await h({ method: "GET", url: `${nodeUrl}/api/obs/trace/${id}`, timeoutMs: 3000 });
          if (a.status === 200) return "arrived" as const;
        }
      } catch {
        // not answering yet
      }
      await clock.sleep(ARRIVAL_EVERY_MS);
    }
    return "not_seen" as const;
  };
  return { kind: "sent", traceId, localUrl, onlineUrl, arrival, shutdown };
}
