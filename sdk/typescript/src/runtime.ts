/**
 * Process-wide SDK runtime state shared by the modules: the resolved
 * settings, the tracer and the content switches. One owner (init in
 * index.ts writes it); everything else reads it.
 */

import { trace, type Tracer, type TracerProvider } from "@opentelemetry/api";

import type { DestinationChoice, Settings } from "./config.js";

export const VERSION = "0.1.0";
export const TRACER_NAME = "@superbased/sdk";
export const SDK_MARKER = "superbased-typescript";

export interface Runtime {
  settings: Settings | null;
  tracer: Tracer | null;
  captureContent: boolean;
  maxContentChars: number;
  /** The destination in force ("" before it is known). */
  destination: DestinationChoice | "";
  /** Where that destination came from: argument, env, machine, default, endpoint or exporter. */
  destinationSource: string;
  /** The machine's admission URL from discovery ("" when not discovered). */
  admissionUrl: string;
  /** The provider holding the SDK's spans (instrumentations are registered on it). */
  provider: TracerProvider | null;
  /**
   * The resource `service.name` of the last span the SDK's processor saw
   * ("" before one): what service-scoped budget caps match, read from the
   * span because a provider's resource is not public in OTel JS 2.x.
   */
  resourceService: string;
  /**
   * Settles once the destination is known (init's discovery answer, bounded
   * by `discoverTimeoutMs`); never rejects. Every control call waits on it
   * before it picks a target (review E-33), as Python resolves at init.
   */
  ready: Promise<void>;
}

export const runtime: Runtime = {
  settings: null,
  tracer: null,
  captureContent: true,
  maxContentChars: 8000,
  destination: "",
  destinationSource: "",
  admissionUrl: "",
  provider: null,
  resourceService: "",
  ready: Promise.resolve(),
};

/** Wait until the destination is known (see {@link Runtime.ready}). */
export function destinationKnown(): Promise<void> {
  return runtime.ready;
}

export function tracer(): Tracer {
  return runtime.tracer ?? trace.getTracer(TRACER_NAME, VERSION);
}

export function truncateContent(value: string): string {
  const max = runtime.maxContentChars;
  return max > 0 && value.length > max ? value.slice(0, max) + "…[truncated]" : value;
}

/** Render any value as content text (strings as-is, the rest as JSON). */
export function contentText(v: unknown): string {
  if (typeof v === "string") return v;
  try {
    const s = JSON.stringify(v);
    return s === undefined ? String(v) : s;
  } catch {
    return String(v);
  }
}

export function resetRuntime(): void {
  Object.assign(runtime, {
    settings: null,
    tracer: null,
    captureContent: true,
    maxContentChars: 8000,
    destination: "",
    destinationSource: "",
    admissionUrl: "",
    provider: null,
    resourceService: "",
    ready: Promise.resolve(),
  });
}
