/**
 * superbased SDK for TypeScript / Node: send LLM-app and agent traces to
 * superbased over OpenTelemetry (OTLP/HTTP).
 *
 * A thin layer over OpenTelemetry JS 2.x that exports spans to the Observer
 * on this machine (`http://127.0.0.1:4318/v1/traces` by default), to an org
 * or SaaS OTLP gateway, or to both, and tags them with superbased attributes.
 * Anything it does, a raw OTel exporter pointed at Observer does too.
 *
 * IMPORTANT: never set `sbo.emitted_by=observer`: that is Observer's own
 * echo-guard marker and such a resource is DROPPED at ingestion.
 */

import { ProxyTracerProvider, trace, type TracerProvider } from "@opentelemetry/api";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { defaultResource, resourceFromAttributes } from "@opentelemetry/resources";
import {
  BatchSpanProcessor,
  ConsoleSpanExporter,
  SimpleSpanProcessor,
  type SpanExporter,
  type SpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";

import { K } from "./attrs.js";
import {
  destinationProblems,
  destinations,
  localEndpointNamed,
  resolveDestinationChoice,
  resolveSettings,
  type Destination,
  type DestinationChoice,
  type Settings,
  type SettingsInput,
} from "./config.js";
import { _resetContextForTests, Scope } from "./context.js";
import { discoverDestination, PendingProcessor, withDiscovered, withSdkFile, type SdkFileUse } from "./destination.js";
import { readSdkCredentialFile, type SdkFileState } from "./credfile.js";
import { homedir } from "node:os";
import { _resetGatewayForTests } from "./aigateway.js";
import {
  bounded,
  CountingExporter,
  Fanout,
  SwitchableProcessor,
  flushBounded,
  maybeLogFailures,
  resetStats,
  shutdownBounded,
  snapshot,
  stats,
} from "./export.js";
import { controlIdle, controlStats, resetControlForTests } from "./control.js";
import { policyStats, resetPolicyStats, SwitchableSampler, type MaskFn, type ShouldExportFn } from "./policy.js";
import { applyVendorTracing, dropScopePrefixes, resetVendorTracingForTests, type VendorTracing } from "./vendor.js";
import { _resetNetInputWarningForTests } from "./spans.js";
import { clearPromptCache } from "./prompts.js";
import { planRefusalStats, resetPlanRefusal, type PlanRefusalError } from "./planrefusal.js";
import { resetRuntime, runtime, SDK_MARKER, TRACER_NAME, VERSION } from "./runtime.js";
import { projectFacts, type ProjectFacts } from "./project.js";
import { _resetFirstTraceForTests, firstTraceWritten } from "./firsttrace.js";
import { _resetInstrumentForTests, autoInstrument, instrumentSetting, instrumentStatus, resolveInstrumentSetting, type InstrumentSetting } from "./instrument.js";

export { VERSION } from "./runtime.js";
export {
  admit,
  Degraded,
  DEFAULT_ADMISSION_ENDPOINT,
  DEFAULT_ADMIT_TIMEOUT_MS,
  SDK_ADMIT_PATH,
  parseVerdict,
  type AdmitOptions,
  type Verdict,
} from "./admit.js";
import { admitStats, resetAdmitStats } from "./admit.js";
export {
  DEFAULT_DISCOVER_TIMEOUT_MS,
  DEFAULT_ENDPOINT,
  DEFAULT_EXPORT_TIMEOUT_MS,
  DEFAULT_MAX_CONTENT_CHARS,
  DEFAULT_API_TIMEOUT_MS,
  DEFAULT_NODE_URL,
  DEFAULT_PROMPT_CACHE_TTL_MS,
  DEFAULT_SERVICE_NAME,
  DEFAULT_SHUTDOWN_TIMEOUT_MS,
  DESTINATION_CHOICES,
  destinations,
  parseKvList,
  resolveSettings,
  type Destination,
  type DestinationChoice,
  type Settings,
  type SettingsInput,
} from "./config.js";
export { FIRST_TRACE_ENV, FIRST_TRACE_PREFIX, linkAllowed, traceLink } from "./firsttrace.js";
export { normaliseServiceName, projectFacts, serviceNameLadder, type ProjectFacts, type ServiceNameSource } from "./project.js";
export { K as Attr, LIMITS, REQUEST_PARAMS, SEMCONV_COMMIT, SEMCONV_SCHEMA_URL } from "./attrs.js";
export {
  getCurrentAttributes,
  identify,
  propagateAttributes,
  type AttributeScope,
  type PropagateOptions,
  type TraceAttributes,
} from "./context.js";
export { DISCOVERY_PATH, isLoopbackUrl, parseDiscovery, readCredentialFile, type Discovered } from "./destination.js";
export {
  CREDENTIAL_FILE_ENV,
  EXPIRY_WARNING_DAYS,
  parseCredentialText,
  readCredentialRecord,
  sdkCredentialPath,
  type CredentialRead,
  type CredentialRecord,
  type PathFacts,
} from "./credfile.js";
export { keepTrace, TRUNCATED_MARK, type MaskFn, type ShouldExportFn } from "./policy.js";
export { continueTrace, extract, getTraceparent, inject, type Carrier } from "./propagation.js";
export {
  Kind,
  getCurrentSpanId,
  getCurrentTraceId,
  observe,
  setContent,
  setDocuments,
  setInput,
  setOutput,
  setRequestParams,
  setToolResult,
  setUsage,
  withAgentSpan,
  withEmbeddingSpan,
  withLlmSpan,
  withRetrieverSpan,
  withSpan,
  withToolSpan,
  type AgentInfo,
  type Content,
  type Document,
  type EmbeddingInfo,
  type LlmInfo,
  type ObserveOptions,
  type PromptRef,
  type RequestParams,
  type RetrieverInfo,
  type SpanOptions,
  type SpanKind,
  type ToolInfo,
  type Usage,
} from "./spans.js";
export {
  AllowanceExceededError,
  PlanRefusalError,
  PlanRequiredError,
  parsePlanRefusal,
  type PlanAllowance,
  type PlanInfo,
  type PlanQuota,
  type PlanRefusalFields,
  type PlanRefusalKind,
} from "./planrefusal.js";
export * from "./scores.js";
export * from "./cost.js";
export {
  AI_GATEWAY_KEY_ENV,
  AI_GATEWAY_URL_ENV,
  GATEWAY_UPSTREAM_HEADER,
  GatewayNotConfiguredError,
  GatewayRefusalError,
  anthropicOptions,
  gatewayBaseUrl,
  gatewayClientKey,
  gatewayEndpoint,
  gatewayKey,
  gatewayRefusal,
  gatewayRefusalFromResponse,
  openAIOptions,
  parseGatewayRefusal,
  resolveGatewayEndpoint,
  type GatewayBudget,
  type GatewayClientInput,
  type GatewayClientOptions,
  type GatewayEndpoint,
  type GatewayOptions,
  type GatewayProblem,
  type GatewayProvider,
  type GatewayRefusalFields,
  type GatewayRefusalKind,
  type GatewayResolveInput,
  type GatewayResolution,
  type GatewaySource,
} from "./aigateway.js";
export * from "./prompts.js";
export * from "./experiments.js";
export {
  ALIASES,
  ALREADY,
  AUTO_EXCLUDED,
  AUTO_SKIPPED_NOTE,
  INSTRUMENTED,
  NOT_INSTALLED,
  PENDING,
  PYTHON_ONLY,
  SKIPPED_HOST_PROVIDER,
  SKIPPED_NOT_INSTALLED,
  TARGETS,
  instrument,
  instrumented,
  resolveInstrumentSetting,
  uninstrument,
  type InstrumentOptions,
  type InstrumentSetting,
  type InstrumentTarget,
} from "./instrument.js";

export interface InitOptions extends SettingsInput {
  /** Also print spans to stdout (debugging). Env: SUPERBASED_CONSOLE. */
  console?: boolean;
  /** A SpanExporter to use instead of OTLP/HTTP (tests, custom transport). Replaces every destination. */
  exporter?: SpanExporter;
  /**
   * A tracer provider to hold the SDK's spans instead of the global one. An
   * OTel JS 1.x provider gets the SDK's processor added; a 2.x provider must
   * have been built with `spanProcessors: [spanProcessor()]`.
   */
  tracerProvider?: TracerProvider;
  /** Rewrite each content value before export (fail-safe: a throw withholds the value). Code only. */
  mask?: MaskFn;
  /** Return false to drop a finished span. Code only. */
  shouldExport?: ShouldExportFn;
  /**
   * Model-library instrumentation (plan 3.1): `"auto"` (the default) turns
   * on every installed target when the SDK owns the tracer provider, at once
   * when the library is loaded and otherwise on its first load (CommonJS;
   * ESM apps start with `--import @superbased/sdk/register`). `"off"` (or
   * `false`) turns none on; a list (`["openai", "langgraph"]`) turns on
   * exactly those, whatever the provider. `openai-agents` only when named.
   * Env: SUPERBASED_INSTRUMENT. An explicit option wins over the env.
   */
  instrument?: "auto" | "off" | boolean | readonly string[];
}

/** How the SDK holds spans: its own registered provider, the host's provider, or a private one. */
export type Mode = "" | "owned" | "attached" | "standalone";

interface State {
  provider: TracerProvider | null;
  ownProvider: NodeTracerProvider | null;
  mode: Mode;
  configKey: string;
  exitHooked: boolean;
  /** The destinations actually exporting (for diagnostics). */
  active: Destination[];
  problems: string[];
  /** Informational lines (discovery not answering); logged only with debug. */
  notes: string[];
  /** What the machine said about sign-in (null when no machine answered). */
  signedIn: boolean | null;
  /** The settings in force after discovery filled them in. */
  effective: Settings | null;
  ready: Promise<void>;
  /** Model client libraries that trace themselves, as the last init() left them (vendor.ts). */
  vendorTracing: Record<string, VendorTracing>;
  /** The instrument setting the last init() applied. */
  instrument: InstrumentSetting | null;
  /** The SDK-held credential file as the last init() read it (null when it was not needed). */
  sdkFile: SdkFileState | null;
  /** Whether its record is the credential in use. */
  sdkFileUsed: boolean;
  /** Its state after the ladders (sdkFile.state). */
  sdkFileUse: SdkFileUse;
}

const processor = new SwitchableProcessor();
const sampler = new SwitchableSampler();
let processorHandedOut = false;
const state: State = {
  provider: null,
  ownProvider: null,
  mode: "",
  configKey: "",
  exitHooked: false,
  active: [],
  problems: [],
  notes: [],
  signedIn: null,
  effective: null,
  ready: Promise.resolve(),
  vendorTracing: {},
  instrument: null,
  sdkFile: null,
  sdkFileUsed: false,
  sdkFileUse: "not_read",
};
let ownResource: Record<string, unknown> = {};
const objectIds = new WeakMap<object, number>();
let nextObjectId = 1;
let initGeneration = 0;

function oid(o: object | undefined): number {
  if (!o) return 0;
  let id = objectIds.get(o);
  if (!id) {
    id = nextObjectId++;
    objectIds.set(o, id);
  }
  return id;
}

/**
 * The SDK's span processor, for an app on OpenTelemetry JS 2.x that builds its
 * own provider (2.x providers take processors only at construction):
 *
 * ```ts
 * const provider = new NodeTracerProvider({ spanProcessors: [spanProcessor(), ...yours] });
 * provider.register();
 * init({ serviceName: "my-app" }); // exports through that provider
 * ```
 */
export function spanProcessor(): SpanProcessor {
  processorHandedOut = true;
  return processor;
}

function globalDelegate(): TracerProvider | null {
  const tp = trace.getTracerProvider();
  const d = tp instanceof ProxyTracerProvider ? tp.getDelegate() : tp;
  const noop = new ProxyTracerProvider().getDelegate();
  if (!d || d.constructor === noop.constructor) return null;
  return d;
}

function addable(tp: TracerProvider): tp is TracerProvider & { addSpanProcessor(p: SpanProcessor): void } {
  return typeof (tp as { addSpanProcessor?: unknown }).addSpanProcessor === "function";
}

function warnOnce(lines: string[]): void {
  for (const l of lines) {
    stats.lastError = l;
    stats.lastErrorAt = Date.now();
    try {
      console.warn(`@superbased/sdk: ${l}`);
    } catch {
      // ignore
    }
  }
}

/** One exporter per destination; each on its own batch processor, so one failing never blocks another. */
function buildDelegate(dests: Destination[], exporter: SpanExporter | undefined, console: boolean): SpanProcessor | null {
  const targets: Destination[] = exporter ? [dests[0] ?? { name: "local", endpoint: "", headers: {}, timeoutMs: 5000 }] : dests;
  const procs: SpanProcessor[] = targets.map(
    (d) =>
      new BatchSpanProcessor(
        new CountingExporter(
          exporter ?? new OTLPTraceExporter({ url: d.endpoint, headers: d.headers, timeoutMillis: d.timeoutMs }),
          d.name,
        ),
        { exportTimeoutMillis: d.timeoutMs },
      ),
  );
  if (console) procs.push(new SimpleSpanProcessor(new ConsoleSpanExporter()));
  if (procs.length === 0) return null;
  // Each destination's CountingExporter counts a span on its own; the console
  // processor counts nothing (review E-31).
  if (procs.length === 1 && targets.length === 1) return procs[0];
  return new Fanout(procs, targets.length);
}

/** A delegate that drops (and counts) every span: an online-only choice with no online URL. */
class DroppingProcessor implements SpanProcessor {
  onStart(): void {}
  onEnd(): void {
    stats.droppedSpans += 1;
  }
  async forceFlush(): Promise<void> {}
  async shutdown(): Promise<void> {}
}

function installExitHook(): void {
  if (state.exitHooked || typeof process === "undefined" || typeof process.on !== "function") return;
  state.exitHooked = true;
  let running = false;
  process.on("beforeExit", () => {
    // beforeExit fires again after the flush's work drains; only flush when
    // something is pending, so the loop ends.
    if (running || !runtime.settings?.exitHook || !processor.active) return;
    if (Number(snapshot().pendingSpans) === 0) return;
    running = true;
    void flush().finally(() => {
      running = false;
    });
  });
}

/**
 * The destination when it can be known without the machine; null = ask the
 * machine first (contract destination.md section 3; sdk-api-surface.md
 * section 6). The machine is asked when nothing chose a destination, and
 * also when an explicit `online` / `both` still lacks a gateway URL or a
 * credential, which discovery supplies (review finding R-B09; Python does
 * the same), and when an explicit `local` / `both` has no endpoint the app
 * named for the local destination: the machine advertises its receiver
 * (live finding L-01). A named endpoint (the option or
 * SUPERBASED_OTLP_ENDPOINT, or under `local` an OTEL_* one) needs no answer.
 */
function syncChoice(
  opts: InitOptions,
  env: Record<string, string | undefined>,
  s: Settings,
  fileChoice: DestinationChoice | "",
  inferOnline: boolean,
): [DestinationChoice | "", string] | null {
  // The option, then SUPERBASED_DESTINATION, then the SDK-held file's choice (rung 3, plan 3.4).
  const given = resolveDestinationChoice(opts.destination, env);
  const chosen = given.choice ? given : fileChoice ? { choice: fileChoice, source: "sdk_file" } : given;
  const onlineGap = (c: string) => (c === "online" || c === "both") && (!s.orgUrl || !s.apiKey);
  // A local destination the app named no endpoint for exports to the receiver
  // the machine advertises (a machine on other ports; live finding L-01).
  const localGap = (c: string) => (c === "local" || c === "both") && !localEndpointNamed(s, c as DestinationChoice);
  const canAsk = s.discover && s.discoverTimeoutMs > 0;
  // A caller-supplied exporter takes every span; control calls follow the choice ("" = online when configured, else local).
  if (opts.exporter) return [chosen.choice, "exporter"];
  if (chosen.choice && !(canAsk && (onlineGap(chosen.choice) || localGap(chosen.choice)))) return [chosen.choice, chosen.source];
  if (!canAsk) return chosen.choice ? [chosen.choice, chosen.source] : inferOnline ? ["online", "inferred"] : ["local", "default"];
  return null;
}

/**
 * The SDK-held file, read only when it can matter (plan 3.4): no destination
 * was chosen (its `destination` is rung 3), or `online` / `both` was chosen
 * without a key and a gateway of the app's own. An explicit `local` never
 * reads it.
 */
function sdkFileFor(chosen: DestinationChoice | "", s: Settings, env: Record<string, string | undefined>): SdkFileState | null {
  const needed = !chosen || ((chosen === "online" || chosen === "both") && !(s.apiKey && s.orgUrl));
  if (!needed) return null;
  let home = "";
  try {
    home = homedir();
  } catch {
    // no home: only SUPERBASED_CREDENTIAL_FILE (or %LOCALAPPDATA%) can name it
  }
  return readSdkCredentialFile(env, home);
}

/** No destination chosen and no machine answered: a gateway and a credential given to the app mean `online`. */
function inferred(s: Settings, otherwise: DestinationChoice): DestinationChoice {
  return s.orgUrl && s.apiKey ? "online" : otherwise;
}

function activate(
  s: Settings,
  choice: DestinationChoice | "",
  source: string,
  opts: InitOptions,
  printSpans: boolean,
  extraProblems: string[] = [],
  notes: string[] = [],
  signedIn: boolean | null = null,
): SpanProcessor {
  runtime.settings = s;
  runtime.resourceService = ""; // a new init: the next span says which service
  state.effective = s;
  state.notes = notes;
  state.signedIn = signedIn;
  if (s.debug) for (const n of notes) console.info(`@superbased/sdk: ${n}`);
  runtime.destination = choice;
  runtime.destinationSource = source;
  const dests = destinations(s, choice);
  state.active = opts.exporter ? dests.slice(0, 1) : dests;
  state.problems = [
    ...(s.destinationInvalid ? [s.destinationInvalid] : []),
    ...(s.samplingInvalid ? [s.samplingInvalid] : []),
    ...(state.instrument?.warnings ?? []),
    ...extraProblems,
    ...(opts.exporter ? [] : destinationProblems(s, choice)),
  ];
  if (state.problems.length) warnOnce(state.problems);
  return buildDelegate(dests, opts.exporter, printSpans) ?? new DroppingProcessor();
}

/**
 * Configure tracing to export to superbased over OTLP/HTTP. Idempotent.
 *
 * Every option maps to an env var (`SUPERBASED_*`, then the standard `OTEL_*`
 * one where it exists); an explicit option wins. See the README's settings
 * table.
 *
 * Destination (D18): `local` (this machine), `online` (the org or SaaS
 * gateway) or `both`, from the option, `SUPERBASED_DESTINATION`, the local
 * Observer's default, then a fallback. See {@link ready}.
 *
 * - No provider registered yet: the SDK registers its own (mode `owned`).
 * - An OTel JS 1.x SDK provider is registered: the SDK adds its processor to
 *   it (mode `attached`).
 * - An OTel JS 2.x provider built with `spanProcessors: [spanProcessor()]`:
 *   the SDK exports through it (mode `attached`).
 * - Any other provider is registered: the SDK keeps a private provider for
 *   its own spans (mode `standalone`); they still join the active trace.
 *
 * A second call with the same settings is a no-op; with different settings it
 * replaces the SDK's exporters in place, shutting the previous ones down.
 */
export function init(opts: InitOptions = {}): Settings {
  const { console: consoleOpt, exporter, tracerProvider, mask, shouldExport, instrument: instrumentOpt, ...input } = opts;
  const env = (typeof process !== "undefined" ? process.env : {}) as Record<string, string | undefined>;
  const s = resolveSettings(env, input, processProject());
  const instrumentChoice = resolveInstrumentSetting(instrumentOpt, env);
  const printSpans = consoleOpt ?? ["1", "true", "yes", "on"].includes((env.SUPERBASED_CONSOLE ?? "").toLowerCase());
  runtime.settings = s;
  runtime.resourceService = ""; // a new init: the next span says which service
  runtime.captureContent = s.captureContent;
  runtime.maxContentChars = s.maxContentChars;
  stats.debug = s.debug;
  sampler.set(s.sampleRate, s.parentBased);
  // A model client library that traces itself (the Anthropic SDKs) would
  // record every call a second time on the provider registered below.
  state.vendorTracing = applyVendorTracing();
  processor.policy = {
    captureContent: s.captureContent,
    maxContentChars: s.maxContentChars,
    mask,
    shouldExport,
    exportRatio: state.mode === "attached" ? s.sampleRate : undefined,
    dropScopePrefixes: dropScopePrefixes(state.vendorTracing),
  };

  const {
    captureContent: _c,
    maxContentChars: _m,
    exitHook: _e,
    debug: _d,
    sampleRate: _r,
    parentBased: _pb,
    discoverTimeoutMs: _t,
    apiTimeoutMs: _a,
    promptCacheTtlMs: _p,
    ...exportShape
  } = s;
  const configKey = JSON.stringify([exportShape, printSpans, oid(exporter), oid(tracerProvider), instrumentChoice]);
  if (processor.active && configKey === state.configKey) return publicView(s);

  // Process-wide identity on the resource (contract section 2): release and
  // environment as the standard service.version / deployment.environment.name.
  const base = new Scope().merged({ tenant: s.tenant, user: s.user, sessionId: s.sessionId, tags: s.tags, metadata: s.metadata });
  const ident: Record<string, unknown> = { [K.sdk]: SDK_MARKER, ...base.attributes() };
  if (s.release) ident[K.serviceVersion] = s.release;
  if (s.environment) ident[K.deploymentEnvironment] = s.environment;
  if (!state.provider || (tracerProvider && tracerProvider !== state.provider)) {
    const candidate = tracerProvider ?? globalDelegate();
    if (candidate && candidate === state.ownProvider) {
      state.provider = candidate;
      state.mode = "owned";
    } else if (candidate && addable(candidate)) {
      candidate.addSpanProcessor(processor);
      state.provider = candidate;
      state.mode = "attached";
    } else if (candidate && processorHandedOut) {
      state.provider = candidate;
      state.mode = "attached";
    } else {
      ownResource = { ...s.resourceAttributes, ...ident, "service.name": s.serviceName };
      const own = new NodeTracerProvider({
        resource: defaultResource().merge(resourceFromAttributes(ownResource as Record<string, string>)),
        spanProcessors: [processor],
        sampler,
      });
      state.ownProvider = own;
      state.provider = own;
      if (candidate) {
        state.mode = "standalone";
      } else {
        own.register();
        state.mode = "owned";
      }
    }
  }
  const provider = state.provider!;
  processor.policy.exportRatio = state.mode === "attached" ? s.sampleRate : undefined;
  // Identity the holding provider's resource does not carry is stamped on spans.
  const resAttrs = state.mode === "owned" || state.mode === "standalone" ? ownResource : {};
  const stamp: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(ident)) {
    if (JSON.stringify(resAttrs[k]) !== JSON.stringify(v)) stamp[k] = v as string | string[];
  }

  processor.shutdownTimeoutMs = s.shutdownTimeoutMs;
  const gen = ++initGeneration;
  state.instrument = instrumentChoice;
  const given = resolveDestinationChoice(opts.destination, env);
  const file = sdkFileFor(given.choice, s, env);
  const fileChoice: DestinationChoice | "" = !given.choice && file?.record?.destination ? file.record.destination : "";
  state.sdkFile = file;
  state.sdkFileUsed = false;
  state.sdkFileUse = file ? (file.present ? (file.record ? "unused" : "refused") : "absent") : "not_read";
  runtime.dashboardUrl = "";
  // A file consulted for the destination that names none says so (destination.md section 6a).
  const fileNotes: string[] =
    !given.choice && file?.record && !file.record.destination && !file.ignored.includes("destination")
      ? [`the SDK-held credential file ${file.path} names no destination (online or both), so it does not choose where traces go; run setup again to rewrite it`]
      : [];
  // Apply the SDK-held record after the machine's (ruling R10) and activate.
  const finish = (base: Settings, choice: DestinationChoice | "", source: string, extra: string[], notes: string[], signedIn: boolean | null, machineDashboard = "") => {
    const f = withSdkFile(base, file, choice);
    state.sdkFileUse = f.use;
    state.sdkFileUsed = f.use === "used";
    runtime.dashboardUrl = f.use === "used" ? f.dashboardUrl : f.settings.credentialSource === "file" ? machineDashboard : "";
    return activate(f.settings, choice, source, opts, printSpans, [...extra, ...fileNotes, ...f.problems], notes, signedIn);
  };
  // Only a key and a gateway the app gave make an unchosen destination `online` (rung 5).
  const inferOnline = !!(s.orgUrl && s.apiKey);
  const sync = syncChoice(opts, env, s, fileChoice, inferOnline);
  let delegate: SpanProcessor;
  runtime.admissionUrl = "";
  if (sync) {
    delegate = finish(s, sync[0], sync[1], [], [], null);
    state.ready = Promise.resolve();
  } else {
    const pending = new PendingProcessor();
    delegate = pending;
    runtime.destination = "";
    runtime.destinationSource = "discovering";
    state.active = [];
    state.problems = [];
    const chosen = given.choice ? given : fileChoice ? { choice: fileChoice, source: "sdk_file" } : given;
    state.ready = discoverDestination(s.nodeUrl, s.discoverTimeoutMs).then(({ found, error }) => {
      if (gen !== initGeneration) {
        pending.resolve(null);
        return;
      }
      const notes = error && error !== "discovery off" ? [error] : [];
      if (!found) {
        // No machine answered: the explicit choice, else inferred online, else local (a NOTE, not a warning).
        const choice = chosen.choice || (inferOnline ? "online" : "local");
        const source = chosen.choice ? chosen.source : choice === "online" ? "inferred" : "default";
        pending.resolve(finish(s, choice, source, [], notes, null));
        return;
      }
      const choice = chosen.choice || found.destination;
      const source = chosen.choice ? chosen.source : "machine";
      const { settings: merged, problems } = withDiscovered(s, found, choice);
      runtime.admissionUrl = found.admissionUrl;
      pending.resolve(finish(merged, choice, source, problems, notes, found.signedIn, found.dashboardUrl));
    });
  }
  // Control calls wait for the destination (review E-33); never rejects.
  runtime.ready = state.ready.then(
    () => undefined,
    () => undefined,
  );
  const old = processor.swap(delegate, stamp);
  if (old) void shutdownBounded(old, s.shutdownTimeoutMs);
  state.configKey = configKey;
  runtime.tracer = provider.getTracer(TRACER_NAME, VERSION);
  runtime.provider = provider;
  // Model-library instrumentation (plan 3.1): after the provider is known,
  // since the rule depends on who owns it. (Its warnings are reported with
  // the destination's problems.)
  const auto = autoInstrument(instrumentChoice, state.mode, provider);
  if (auto.note) {
    state.notes = [...state.notes, auto.note];
    if (s.debug) console.info(`@superbased/sdk: ${auto.note}`);
  }
  installExitHook();
  return publicView(s);
}

const views = new WeakMap<Settings, Settings>();
/** The fields that carry the credential (Python's repr=False fields). */
const SECRET_FIELDS = ["apiKey", "headers", "onlineHeaders"] as const;

/**
 * The settings as handed to the app: the same values, with the credential
 * fields (`apiKey`, and the header maps, which may carry `Authorization`)
 * readable but not enumerable, so `console.log`, `JSON.stringify` and a
 * spread never print the key (as Python's Settings repr hides it; review
 * R-C33). The SDK's own copy is unchanged.
 */
function publicView(s: Settings): Settings {
  let v = views.get(s);
  if (!v) {
    v = { ...s };
    for (const f of SECRET_FIELDS) Object.defineProperty(v, f, { value: s[f], enumerable: false, writable: false, configurable: false });
    views.set(s, v);
  }
  return v;
}

/**
 * Resolves once the destination is known (immediately unless init is asking
 * the local Observer for its default, which takes at most
 * `discoverTimeoutMs`). Spans finished before then are held, not lost.
 */
export async function ready(): Promise<DestinationChoice | ""> {
  await state.ready;
  return runtime.destination;
}

/**
 * The settings the last `init()` resolved (null before init). `apiKey` and the
 * header maps are readable but not enumerable, so logging the object never
 * prints the credential.
 */
export function settings(): Settings | null {
  return runtime.settings ? publicView(runtime.settings) : null;
}

/**
 * Export every finished span now. Bounded by `timeoutMs` (default: the
 * shutdownTimeoutMs setting). Resolves true when everything went out in time;
 * never rejects. Await it at the end of a serverless handler.
 */
export async function flush(timeoutMs?: number): Promise<boolean> {
  const ms = timeoutMs ?? runtime.settings?.shutdownTimeoutMs ?? 2000;
  const control = bounded(controlIdle(), ms); // pending score / experiment writes
  const d = processor.current;
  let ok = true;
  try {
    if (d) ok = await flushBounded(d, ms);
  } catch {
    ok = false;
  }
  return (await control) && ok;
}

/**
 * Flush and stop the SDK's exporters. Bounded by `timeoutMs` even when an
 * endpoint is down; never rejects (ECONNREFUSED, 302 and 401 included). The
 * host's provider, when the SDK attached to one, keeps running. A later
 * `init()` starts exporting again.
 */
export async function shutdown(timeoutMs?: number): Promise<boolean> {
  const old = processor.swap(null, {});
  state.configKey = "";
  if (!old) return true;
  try {
    return await shutdownBounded(old, timeoutMs ?? runtime.settings?.shutdownTimeoutMs ?? 2000);
  } catch {
    return false;
  } finally {
    maybeLogFailures();
  }
}

export interface Diagnostics {
  mode: Mode;
  initialized: boolean;
  /** local, online or both, or "" while discovering (or before init). */
  destination: DestinationChoice | "";
  /** Where it came from: argument, env, machine, inferred, default, exporter, or discovering. */
  destinationSource: string;
  /** The exporters running now. */
  destinations: Array<{ name: string; endpoint: string }>;
  /** Why the destination could not be honoured in full (also logged once as warnings). */
  destinationProblems: string[];
  /** The gateway's base URL in force ("" when none). */
  gatewayUrl: string;
  /** The degraded reason ("" when the destination is honoured in full; contract destination.md section 7). */
  degraded: string;
  /** Informational lines, for example why discovery got no answer. */
  notes: string[];
  /** What the machine reported about sign-in; null when no machine answered. */
  signedIn: boolean | null;
  /** Where the credential came from: argument, env, file (the machine's), sdk_file (the SDK-held file setup writes), or "" (never the credential itself). */
  credentialSource: string;
  /**
   * The SDK-held credential file (destination.md section 6a): its path, its
   * state (`absent`, `used`, `unused` (valid, but another record won or the
   * destination needs no key), `refused`, `expired`, or `not_read` (an
   * explicit `local`)), and the refused rule ("" otherwise). Never the key.
   */
  sdkFile: { path: string; state: SdkFileUse; reason: string };
  /** The dashboard base links point at for the online destination ("" when unknown). */
  dashboardUrl: string;
  /** The first-trace line's link (or refusal) once written, else "" (section 16). */
  firstTraceLink: string;
  pendingSpans: number;
  exportedSpans: number;
  failedExports: number;
  droppedSpans: number;
  /** Spans left out by head sampling (sampleRate). */
  sampledOutSpans: number;
  /** Spans dropped by shouldExport. */
  filteredSpans: number;
  /** The instrument setting in force (sdk-api-surface.md section 14): `auto`, `off`, or the list of targets. */
  instrument: "auto" | "off" | string[] | "";
  /**
   * Model-library instrumentation per target, as init() left it and kept
   * current: `instrumented`, `already`, `pending` (installed; turned on at its
   * first load), `not-installed` (a named target), `error: ...`, or
   * `skipped: <reason>` with reason `auto_excluded` (installed, turned on
   * only when named), `host_provider` (the app registered its own provider)
   * or `not_installed`. Empty when the setting is `off`.
   */
  instrumented: Record<string, string>;
  /** The service name in force, and the rung of the ladder that named it (argument, env, manifest, entry_dir, default; section 15). */
  serviceName: string;
  serviceNameSource: string;
  /** shouldExport hooks that threw (the span was kept). */
  shouldExportErrors: number;
  /** mask hooks that threw (that value was dropped). */
  maskErrors: number;
  lastHookError: string;
  lastError: string;
  /** Epoch ms of the last error, 0 when none. */
  lastErrorAt: number;
  /** Control API calls (scores, prompts, datasets, experiments) made and failed. */
  controlCalls: number;
  controlFailures: number;
  controlLastError: string;
  /** admit() calls that got no decision (admitted, or denied under failClosed), and why the last one (review E-39). */
  admissionDegraded: number;
  admissionLastError: string;
  /** Epoch ms of that last one, 0 when none. */
  admissionLastErrorAt: number;
  /** Per model client library that traces itself (`anthropic`): `off` (init() turned its own spans off; `instrument([...])` records the calls) or `kept` (the app set its switch, e.g. `ANTHROPIC_OPEN_TELEMETRY=true`). */
  vendorTracing: Record<string, VendorTracing>;
  /** Spans from such a library dropped at export (a client built before init()). */
  vendorSpansDropped: number;
  /** setUsage calls whose inputTokens was below its cache parts, recorded as a net count (input + cache). */
  usageNetInputCorrected: number;
  /**
   * The last time the organization's plan refused AI Apps ingest (an export,
   * or any other call to the gateway), else null: its `message`, and
   * `upgradeUrl`, where the org's billing owner changes the plan. Export never
   * throws: a refused export shows here, beside one warning line a minute.
   */
  planRefusal: PlanRefusalError | null;
  /** Epoch ms of that refusal, 0 when none. */
  planRefusalAt: number;
}

let projectCache: ProjectFacts | null = null;
/** This process's project facts, read once (the entry script does not change). */
function processProject(): ProjectFacts {
  projectCache ??= projectFacts();
  return projectCache;
}

function settingValue(st: InstrumentSetting | null): "auto" | "off" | string[] | "" {
  if (!st) return "";
  return st.mode === "list" ? [...st.names] : st.mode;
}

/** A snapshot of the SDK's export health. */
export function diagnostics(): Diagnostics {
  const snap = snapshot();
  return {
    mode: state.mode,
    initialized: processor.active,
    destination: runtime.destination,
    destinationSource: runtime.destinationSource,
    destinations: state.active.map((d) => ({ name: d.name, endpoint: d.endpoint })),
    destinationProblems: [...state.problems],
    gatewayUrl: state.effective?.orgUrl ?? "",
    degraded: state.effective && runtime.destination ? (destinationProblems(state.effective, runtime.destination)[0] ?? "") : "",
    notes: [...state.notes],
    signedIn: state.signedIn,
    credentialSource: state.effective?.credentialSource ?? "",
    sdkFile: { path: state.sdkFile?.path ?? "", state: state.sdkFileUse, reason: state.sdkFile?.reason ?? "" },
    dashboardUrl: runtime.dashboardUrl,
    firstTraceLink: firstTraceWritten(),
    pendingSpans: Number(snap.pendingSpans),
    exportedSpans: Number(snap.exportedSpans),
    failedExports: Number(snap.failedExports),
    droppedSpans: Number(snap.droppedSpans),
    sampledOutSpans: Number(snap.sampledOutSpans),
    filteredSpans: Number(snap.filteredSpans),
    serviceName: runtime.settings?.serviceName ?? "",
    serviceNameSource: runtime.settings?.serviceNameSource ?? "",
    instrument: settingValue(instrumentSetting()),
    instrumented: instrumentStatus(),
    shouldExportErrors: Number(snap.shouldExportErrors),
    maskErrors: Number(snap.maskErrors),
    lastHookError: String(snap.lastHookError),
    lastError: String(snap.lastError),
    lastErrorAt: Number(snap.lastErrorAt),
    controlCalls: controlStats.calls,
    controlFailures: controlStats.failures,
    controlLastError: controlStats.lastError,
    admissionDegraded: admitStats.degraded,
    admissionLastError: admitStats.lastError,
    admissionLastErrorAt: admitStats.lastErrorAt,
    vendorTracing: { ...state.vendorTracing },
    vendorSpansDropped: policyStats.vendorSpansDropped,
    usageNetInputCorrected: policyStats.usageNetInputCorrected,
    planRefusal: planRefusalStats.last,
    planRefusalAt: planRefusalStats.at,
  };
}

/** Forget all SDK state (tests only). Does not touch the global provider. */
export async function _resetForTests(): Promise<void> {
  const old = processor.swap(null, {});
  if (old) await shutdownBounded(old, 1000);
  Object.assign(state, {
    provider: null,
    ownProvider: null,
    mode: "",
    configKey: "",
    active: [],
    problems: [],
    notes: [],
    signedIn: null,
    effective: null,
    ready: Promise.resolve(),
    vendorTracing: {},
    instrument: null,
    sdkFile: null,
    sdkFileUsed: false,
    sdkFileUse: "not_read",
  });
  _resetInstrumentForTests();
  _resetFirstTraceForTests();
  projectCache = null;
  resetVendorTracingForTests();
  _resetNetInputWarningForTests();
  initGeneration++;
  processorHandedOut = false;
  ownResource = {};
  processor.policy = { captureContent: true, maxContentChars: 0 };
  sampler.set(1, true);
  resetRuntime();
  resetStats();
  resetPolicyStats();
  _resetContextForTests();
  resetControlForTests();
  resetAdmitStats();
  resetPlanRefusal();
  _resetGatewayForTests();
  clearPromptCache();
}
