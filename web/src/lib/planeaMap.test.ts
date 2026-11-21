import { test } from "node:test";
import assert from "node:assert/strict";
import { CHILD_SPANS_SOURCE, contentBySpan, inspectorData, rollUpParentCosts, scoreChip, traceCost } from "./planeaMap.ts";
import type { PlaneASpan } from "../../../shared/components/planea/types.ts";
import type { AppTraceDetail } from "./planeaApi.ts";

const detail: AppTraceDetail = {
  trace: {
    trace_id: "t1", root_name: "run", source: "sdk_otlp", session_id: "s1", status: "ok",
    started_at: "2026-11-19T10:00:00Z", ended_at: "2026-11-19T10:00:02Z", duration_ms: 2000, span_count: 2,
    cost_usd: 0.5, input_tokens: 10, output_tokens: 2, cache_read_tokens: 0, cache_write_tokens: 0,
    reasoning_tokens: 0, total_tokens: 12,
  },
  spans: [
    {
      span_id: "a", parent_span_id: "", kind: "agent", name: "run", status: "ok",
      started_at: "2026-11-19T10:00:00Z", ended_at: "2026-11-19T10:00:02Z", duration_ms: 2000, model: "", provider: "",
      input_tokens: null, output_tokens: null, cache_read_tokens: null, cache_write_tokens: null, reasoning_tokens: null,
      cost_usd: null, cost_source: "", request_id: "",
    },
    {
      span_id: "b", parent_span_id: "a", kind: "llm", name: "chat", status: "ok",
      started_at: "2026-11-19T10:00:00Z", ended_at: "2026-11-19T10:00:01Z", duration_ms: 1000, model: "gpt-x", provider: "openai",
      input_tokens: 10, output_tokens: 2, cache_read_tokens: 4, cache_write_tokens: null, reasoning_tokens: null,
      cost_usd: 0.5, cost_source: "computed", request_id: "req-1",
    },
  ],
  content: [
    { span_id: "b", kind: "prompt", content: "hi", content_hash: "h1", time: "2026-11-19T10:00:00Z" },
    { span_id: "b", kind: "response", content: "", content_hash: "h2", time: "2026-11-19T10:00:01Z" },
  ],
  enrichments: {
    b: { found: true, provider: "openai", model: "gpt-x", input_tokens: 11, output_tokens: 2, cache_read_tokens: 0, cache_creation_tokens: 0, cost_usd: 0.6 },
  },
};

test("inspectorData: null tokens become 0, total is in + out, enrichment rides along", () => {
  const d = inspectorData(detail);
  assert.equal(d.spans.length, 2);
  const [a, b] = d.spans;
  assert.equal(a.input_tokens, 0);
  // U-10: the agent span carries its priced child's cost, labelled as such.
  assert.equal(a.cost_usd, 0.5);
  assert.equal(a.cost_source, CHILD_SPANS_SOURCE);
  assert.equal(a.total_tokens, 0);
  assert.equal(a.enrichment, undefined);
  assert.equal(b.total_tokens, 12);
  assert.equal(b.cache_read_tokens, 4);
  assert.equal(b.enrichment?.cost_usd, 0.6);
  assert.equal(d.trace.total_tokens, 12);
  assert.equal(d.trace.session_id, "s1");
  assert.deepEqual(d.trace_evals, []);
});

test("inspectorData: the trace cost and its provenance are one pair (FR-M07)", () => {
  const provenance = { label: "proxy exact", complete: true, sources: { proxy_exact: 1 } };
  const withCost: AppTraceDetail = {
    ...detail,
    // The stored total is the reported 0.5; the server's TraceCost is the
    // proxy-exact 0.6, labelled as such.
    cost: { trace_id: "t1", cost_usd: 0.6, cost_provenance: provenance, spans: [] },
    cost_provenance: provenance,
  };
  const d = inspectorData(withCost);
  assert.equal(d.trace.cost_usd, 0.6, "the TraceCost total, not the stored one");
  assert.deepEqual(d.cost_provenance, provenance);
  assert.deepEqual(traceCost(withCost), { usd: 0.6, provenance });

  const unpriced: AppTraceDetail = {
    ...detail,
    cost: { trace_id: "t1", cost_usd: null, cost_provenance: { label: "unpriced", complete: false, sources: {} }, spans: [] },
  };
  assert.equal(inspectorData(unpriced).trace.cost_usd, null, "an unpriced trace stays null, never 0");

  // A daemon that predates the TraceCost: the stored total with the detail's
  // provenance.
  assert.deepEqual(traceCost(detail), { usd: 0.5, provenance: null });
});

test("inspectorData: a span with no priced model call keeps a null cost (FR-M19)", () => {
  const toolOnly: AppTraceDetail = {
    ...detail,
    spans: [
      {
        ...detail.spans[0],
        span_id: "tool", kind: "tool", name: "search",
      },
    ],
  };
  const [tool] = inspectorData(toolOnly).spans;
  // null, so the span tree draws a dash, not "Unpriced" (0 used to fail
  // the inspector's cost_usd == null test).
  assert.equal(tool.cost_usd, null);
  assert.equal(tool.cost_source, "");
});

test("scoreChip: label is the display value, score the number (0 when categorical)", () => {
  assert.deepEqual(
    scoreChip({ id: "sc_1", trace_id: "t1", span_id: "b", name: "helpful", value: "0.8", value_num: 0.8, kind: "numeric", source: "sdk", created_at: "" }),
    { name: "helpful", label: "0.8", score: 0.8, span_id: "b" },
  );
  assert.deepEqual(
    scoreChip({ id: "sc_2", trace_id: "t1", name: "tone", value: "polite", value_num: null, kind: "categorical", source: "feedback", created_at: "" }),
    { name: "tone", label: "polite", score: 0 },
  );
});

test("contentBySpan: an empty body kept only its hash", () => {
  const c = contentBySpan(detail);
  assert.equal(c.b.length, 2);
  assert.equal(c.b[0].has_raw, true);
  assert.equal(c.b[1].has_raw, false);
  assert.equal(c.b[1].content_hash, "h2");
});

test("rollUpParentCosts: an agent span carries its priced children's cost, never Unpriced (U-10)", () => {
  const span = (id: string, parent: string, kind: string, usd: number, source: string): PlaneASpan =>
    ({ span_id: id, parent_span_id: parent, kind, cost_usd: usd, cost_source: source } as PlaneASpan);
  const spans = [
    span("root", "", "agent", 0, ""),
    span("chain", "root", "chain", 0, ""),
    span("llm1", "chain", "llm", 0.25, "computed"),
    span("llm2", "root", "llm", 0.5, "proxy_exact"),
    span("unpriced", "root", "llm", 0, ""),
    span("tool", "root", "tool", 0, ""),
  ];
  rollUpParentCosts(spans);
  const by = Object.fromEntries(spans.map((s) => [s.span_id, s]));
  assert.equal(by.root.cost_usd, 0.75, "nested parents never count a call twice");
  assert.equal(by.root.cost_source, CHILD_SPANS_SOURCE);
  assert.equal(by.chain.cost_usd, 0.25);
  assert.equal(by.tool.cost_source, "", "no priced descendant: left as it is");
  assert.equal(by.unpriced.cost_source, "", "a model call is never rolled up");
  assert.equal(by.llm2.cost_source, "proxy_exact");
});
