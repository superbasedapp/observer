// Component tests of the process capture budget UI, rendered with
// react-dom/server: the Settings capture limits rows, the data-volume card
// states, and the System tab's capture line, services block and rolled-up
// block.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { CaptureLine, RolledUpBlock, ServicesBlock } from "./ProcessesSection";
import { StructuredConfigSection } from "@/pages/settings/StructuredConfigSection";
import { SECTION_SPECS } from "@/pages/settings/sectionSpecs";
import { ProcessCaptureEstimateView } from "@/pages/settings/ProcessCaptureEstimateCard";
import type { ConfigResponse, ProcessSummaryResponse, ProcessSummaryRollup, ProcessSummaryService } from "@/lib/types";

// ---- Settings: capture limits rows ----

const CAPTURE = {
  Enabled: true,
  Budget: { PerToolCall: 200, PerSession: 5000, PerMinute: 300 },
  Services: { Track: true, DetachAfterMinutes: 10, ExemplarsPerService: 20, TailMinutes: 30, ExtraBasenames: ["my-dev-server"] },
  Fold: { Enabled: true, ExtraBasenames: [] },
  Metrics: { RingMinLifetimeSeconds: 30 },
  Rollups: { BucketSeconds: 60 },
  Unattributed: { PendingHours: 24, Mode: "rollup" },
};

function renderProcess(process: Record<string, unknown>): string {
  const config = { config: { Observer: { Process: process } } } as unknown as ConfigResponse;
  return renderToStaticMarkup(
    <MemoryRouter>
      <StructuredConfigSection spec={SECTION_SPECS.process} config={config} />
    </MemoryRouter>,
  );
}

test("the process section lists every capture limit with its saved value", () => {
  const html = renderProcess({ Enabled: true, Backend: "auto", Capture: CAPTURE });
  for (const label of [
    "Apply capture limits",
    "Rows per tool call",
    "Rows per session",
    "Rows per minute",
    "Track services",
    "Detach after (minutes)",
    "Rows per service",
    "Tail (minutes)",
    "Extra service programs",
    "Fold routine helpers",
    "Extra folded programs",
    "Metric ring minimum lifetime (s)",
    "Rollup bucket (s)",
    "Wait for correlation (hours)",
    "After the wait",
  ]) {
    assert.match(html, new RegExp(label.replace(/[()]/g, "\\$&")), label);
  }
  assert.match(html, /Capture limits/);
  assert.match(html, /value="200"/, "rows per tool call");
  assert.match(html, /value="5000"/, "rows per session");
  assert.match(html, /my-dev-server/, "the extra services list shows its value");
  assert.match(html, /<option[^>]*value="drop"/, "the unattributed mode offers drop");
});

test("a daemon whose config has no Capture object shows no capture limit rows", () => {
  const html = renderProcess({ Enabled: true, Backend: "auto" });
  assert.doesNotMatch(html, /Apply capture limits/);
  assert.doesNotMatch(html, /Rows per tool call/);
  assert.match(html, /Process table/, "the rest of the section is unchanged");
});

// ---- Settings: the data-volume card ----

const ESTIMATE = {
  basis: { days: 7, sessions: 41, observed_rows: 310000 },
  current: { rows_per_day: 44000, bytes_per_day: 30_000_000 },
  projected: { rows_per_day: 4400, bytes_per_day: 3_000_000, rollup_rows_per_day: 600, org_rows_per_day: 2100 },
  by_setting: [
    { key: "budget.per_session", rows_per_day: 44000 },
    { key: "fold.enabled", rows_per_day: 52000 },
    { key: "budget.per_tool_call", rows_per_day: 9000 },
  ],
};

test("data-volume card: loading", () => {
  const html = renderToStaticMarkup(<ProcessCaptureEstimateView state={{ kind: "loading" }} />);
  assert.match(html, /Data volume/);
  assert.match(html, /Estimating data volume/);
});

test("data-volume card: no history yet", () => {
  const html = renderToStaticMarkup(
    <ProcessCaptureEstimateView
      state={{ kind: "ready", estimate: { ...ESTIMATE, basis: { days: 0, sessions: 0, observed_rows: 0 } } }}
    />,
  );
  assert.match(html, /Not enough history yet/);
  assert.doesNotMatch(html, /Rows \/ day/);
});

test("data-volume card: a daemon without the endpoint", () => {
  const html = renderToStaticMarkup(<ProcessCaptureEstimateView state={{ kind: "unavailable" }} />);
  assert.match(html, /The estimate needs a newer daemon\./);
  assert.doesNotMatch(html, /error|Could not/i);
});

test("data-volume card: any other failure is said plainly", () => {
  const html = renderToStaticMarkup(<ProcessCaptureEstimateView state={{ kind: "error", message: "api 500" }} />);
  assert.match(html, /Could not estimate: api 500/);
});

test("data-volume card: current vs projected, rollup and org rows, per-setting deltas", () => {
  const html = renderToStaticMarkup(<ProcessCaptureEstimateView state={{ kind: "ready", estimate: ESTIMATE }} />);
  assert.match(html, /from the last 7 days, 41 sessions, 310,000 stored processes/);
  assert.match(html, /44,000 → 4,400/, "rows per day, current to projected");
  assert.match(html, /-90%/, "the projected fall");
  assert.match(html, /29 MB → 2\.9 MB/, "storage per day");
  assert.match(html, /Rollup rows \/ day/);
  assert.match(html, /Org push rows \/ day/);
  assert.match(html, /2,100/);
  // Per-setting list: biggest change first, a raise is amber, a cut is green.
  const list = html.slice(html.indexOf("capture-by-setting"));
  assert.ok(list.indexOf("Runs kept per tool call") < list.indexOf("Fold routine helpers"));
  assert.ok(list.indexOf("Fold routine helpers") < list.indexOf("Runs kept per session"));
  assert.match(list, /-80%/);
  assert.match(list, /\+18%/);
  assert.match(list, /no change/);
  assert.match(list, /9,000 \/ day/);
  assert.match(html, /bg-success|text-success/, "a cut reads green");
  assert.match(html, /bg-warn|text-warn/, "a raise reads amber");
});

// ---- System tab ----

const SUM: ProcessSummaryResponse = {
  observed: 92428,
  kept: 3412,
  folded: 61203,
  rolled_up: 24880,
  service_kept: 2933,
  service_rolled_up: 0,
  dropped: 0,
  budget: { per_tool_call: 200, per_session: 5000, per_minute: 300, hit: true },
};

test("capture line: kept of observed, folded, rolled up, service rows, budget hit", () => {
  const html = renderToStaticMarkup(<CaptureLine summary={SUM} />);
  assert.match(html, /Kept 3,412 of 92,428 · 61,203 folded · 24,880 rolled up · 2,933 service rows · budget hit/);
});

test("capture line: a session captured before capture limits says so", () => {
  const html = renderToStaticMarkup(<CaptureLine summary={{ ...SUM, legacy: true }} />);
  assert.match(html, /captured before capture limits/i);
  assert.doesNotMatch(html, /Kept 3,412/);
});

const SERVICES: ProcessSummaryService[] = [
  {
    root_key: "svc-1",
    exe: "vite",
    argv_preview: "vite --port 5173",
    started_at: "2026-11-04T10:00:00Z",
    last_seen: "2026-11-04T11:00:00Z",
    action_id: 812,
    turn_index: 14,
    message_id: "msg_abc123",
    kept: 20,
    rolled_up: 340,
    cpu_sum_ms: 12300,
    peak_rss_bytes: 220 * 1024 * 1024,
  },
];

test("services block: exe, argv, the tool call and a message link, kept and rolled up, CPU and memory", () => {
  const html = renderToStaticMarkup(
    <ServicesBlock
      services={SERVICES}
      renderMessageLink={(id) => (
        <button type="button" data-link={id}>
          {id}
        </button>
      )}
    />,
  );
  assert.match(html, /Services/);
  assert.match(html, /1 service</);
  assert.match(html, />vite</);
  assert.match(html, /vite --port 5173/);
  assert.match(html, /turn <\/span><span[^>]*>14/);
  assert.match(html, /#812/);
  assert.match(html, /data-link="msg_abc123"/, "the message id goes through the message link");
  assert.match(html, />340</, "rolled up");
  assert.match(html, /12\.3s/, "CPU");
  assert.match(html, /220 MB/, "peak memory");
  assert.doesNotMatch(html, /Pagination|1-10 of/, "one service needs no pager");
});

test("services block: more than ten page, ten a page; no handler leaves a plain id", () => {
  const many = Array.from({ length: 23 }, (_, i) => ({ ...SERVICES[0], root_key: `svc-${i}`, exe: `svc${String(i).padStart(2, "0")}` }));
  const html = renderToStaticMarkup(<ServicesBlock services={many} />);
  assert.match(html, /1-10 of 23/);
  assert.equal((html.match(/>svc\d\d</g) ?? []).length, 10);
  assert.match(html, /<span class="font-mono">msg_abc123<\/span>/);
});

function roll(kind: string, exe: string, count: number, extra: Partial<ProcessSummaryRollup> = {}): ProcessSummaryRollup {
  return { group_kind: kind, exe_basename: exe, count, ...extra };
}

test("rolled-up block: grouped by kind with exact counts, failures, durations, CPU, memory and the example", () => {
  const html = renderToStaticMarkup(
    <RolledUpBlock
      rollups={[
        roll("fold", "git.exe", 61203, { example_argv_preview: "git status --porcelain" }),
        roll("budget", "go.exe", 24880, {
          failed_count: 12,
          duration_sum_ms: 4_000_000,
          duration_max_ms: 90_000,
          cpu_sum_ms: 65_000,
          peak_rss_bytes: 512 * 1024 * 1024,
          example_argv_preview: "go test ./...",
        }),
      ]}
    />,
  );
  assert.match(html, /Rolled up/);
  // Group order: over budget before folded; each with its heading and a total chip.
  assert.ok(html.indexOf("Over budget") < html.indexOf("Folded helpers"));
  assert.match(html, /Over budget 24,880/);
  assert.match(html, /Folded helpers 61,203/);
  assert.match(html, /×24,880/);
  assert.match(html, /12 failed/);
  assert.match(html, /go test \.\/\.\.\./);
  assert.match(html, /1\.1h/, "total duration");
  assert.match(html, /1\.5m/, "longest");
  assert.match(html, /512 MB/);
  assert.doesNotMatch(html, /1-10 of/);
});

test("rolled-up block: ten rows a page", () => {
  const rows = Array.from({ length: 14 }, (_, i) => roll("fold", `tool${String(i).padStart(2, "0")}.exe`, 100 - i));
  const html = renderToStaticMarkup(<RolledUpBlock rollups={rows} />);
  assert.match(html, /1-10 of 14/);
  assert.equal((html.match(/>tool\d\d\.exe</g) ?? []).length, 10);
});
