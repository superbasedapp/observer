// planeaCostSource.test - the honesty vocabulary of every Plane A cost cell
// (W4-2, lane C2; docs/plans/plane-a-sdk-buildout/contracts/cost-source.md).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  COST_SOURCES,
  costSourceRow,
  isPriced,
  parseCostDetail,
  provenanceText,
  provenanceTitle,
} from "../../../shared/components/planea/costSource.ts";
import { inspectorData, spanCostDetail } from "./planeaMap.ts";
import type { AppTraceDetail } from "./planeaApi.ts";

test("contract section 1: every value and its display label", () => {
  const want: Record<string, string> = {
    gateway_exact: "Gateway exact",
    proxy_exact: "Proxy exact",
    computed: "Computed",
    reported: "Reported",
    "": "Unpriced",
  };
  assert.deepEqual(Object.keys(COST_SOURCES).sort(), Object.keys(want).sort());
  for (const [k, label] of Object.entries(want)) assert.equal(costSourceRow(k).label, label);
  assert.equal(costSourceRow(undefined).label, "Unpriced");
  assert.equal(costSourceRow("future_source").label, "future_source");
  assert.equal(costSourceRow("gateway_exact").exact, true);
  assert.equal(isPriced(""), false);
  assert.equal(isPriced("computed"), true);
});

test("contract section 5: the trace label rows", () => {
  const src = (o: Record<string, number>) => ({ gateway_exact: 0, proxy_exact: 0, computed: 0, reported: 0, unpriced: 0, ...o });
  assert.equal(provenanceText(null), "source unknown");
  assert.equal(provenanceText({ label: "unpriced", complete: false, sources: src({ unpriced: 2 }) }), "Unpriced");
  assert.equal(provenanceText({ label: "gateway_exact", complete: true, sources: src({ gateway_exact: 1 }) }), "Gateway exact");
  assert.equal(provenanceText({ label: "computed", complete: false, sources: src({ computed: 1, unpriced: 1 }) }), "Computed, partial");
  assert.equal(provenanceText({ label: "mixed", complete: true, sources: src({ computed: 1, gateway_exact: 1 }) }), "Mixed");
  // L-21: a trace that made no model call is not "unpriced".
  assert.equal(provenanceText({ label: "no_model_calls", complete: true, sources: src({}) }), "No model calls");
  assert.match(provenanceTitle({ label: "no_model_calls", complete: true, sources: src({}) }), /no model call/);
  assert.match(provenanceTitle({ label: "computed", complete: false, sources: src({ computed: 1, unpriced: 1 }) }), /leaves the unpriced spans out/);
});

test("contract section 3: cost_detail parses from the org's text and the machine's object", () => {
  assert.deepEqual(parseCostDetail('{"reported":0.1,"gateway_exact":0.2}'), { reported: 0.1, gateway_exact: 0.2 });
  assert.deepEqual(parseCostDetail({ computed: 1 }), { computed: 1 });
  assert.deepEqual(parseCostDetail("not json"), {});
  assert.deepEqual(parseCostDetail(""), {});
  assert.deepEqual(parseCostDetail(null), {});
  assert.deepEqual(parseCostDetail([1]), {});
});

test("the machine's trace detail: the TraceCost source wins on the span", () => {
  const d: AppTraceDetail = {
    trace: { trace_id: "t", status: "ok", source: "sdk_otlp", started_at: "", ended_at: "", duration_ms: 0, span_count: 1, total_tokens: 10, cost_usd: 0.02 } as AppTraceDetail["trace"],
    spans: [
      {
        span_id: "s", parent_span_id: "", kind: "llm", name: "chat", status: "ok", started_at: "", ended_at: "", duration_ms: 1,
        model: "m", provider: "p", input_tokens: 10, output_tokens: 0, cache_read_tokens: null, cache_write_tokens: null,
        reasoning_tokens: null, cost_usd: 0.02, cost_source: "reported", cost_detail: { reported: 0.02 }, request_id: "msg_1",
      },
    ],
    content: [],
    cost: {
      trace_id: "t", cost_usd: 0.025,
      cost_provenance: { label: "proxy_exact", complete: true, sources: { proxy_exact: 1 } },
      spans: [{ span_id: "s", model: "m", cost_usd: 0.025, cost_source: "proxy_exact", reported_usd: 0.02, computed_usd: null, exact_usd: 0.025, cost_delta_usd: 0.005, gateway_request_id: null }],
    },
  };
  const out = inspectorData(d);
  assert.equal(out.spans[0].cost_source, "proxy_exact");
  assert.equal(out.spans[0].cost_usd, 0.025);
  assert.equal(out.spans[0].cost_delta_usd, 0.005);
  assert.equal(out.cost_provenance?.label, "proxy_exact");
  const det = spanCostDetail(d.cost!.spans[0], d.spans[0].cost_detail);
  assert.equal(det.proxy_exact, 0.025);
  assert.equal(det.reported, 0.02);
  assert.equal(det.delta_reported, 0.005);
});
