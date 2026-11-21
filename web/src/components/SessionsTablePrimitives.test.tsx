// Component tests of the shared pieces the Sessions table redesign added
// (docs/plans/sessions-table-redesign-2026-11-21.md): DataTable's pinned
// columns and clip mode, the badges' glyph mode, and the quiet tag editor /
// shrinking tag pill. Rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable, pinnedOffsets } from "@shared/primitives/DataTable";
import { SurfaceBadge } from "@shared/primitives/SurfaceBadge";
import { ExecutionLocationBadge } from "@shared/primitives/ExecutionLocationBadge";
import { TagPill } from "@/components/TagPill";
import { TagEditor } from "@/components/TagEditor";

type Row = { id: string; a: string; b: string; c: string };
const rows: Row[] = [
  { id: "1", a: "a1", b: "b1", c: "c1" },
  { id: "2", a: "a2", b: "b2", c: "c2" },
];
const cols = (pinned: boolean): ColumnDef<Row, unknown>[] => [
  { id: "a", header: "A", accessorKey: "a", meta: { width: 40, sticky: pinned } },
  { id: "b", header: "B", accessorKey: "b", meta: { width: 100, sticky: pinned } },
  { id: "c", header: "C", accessorKey: "c", meta: { width: 60 } },
];

const PIN_ROWS: { name: string; columns: { id: string; columnDef: { meta?: { sticky?: boolean; width?: number } } }[]; left: [string, number][]; edge: number; last: string | null }[] = [
  { name: "no pinned columns", columns: [{ id: "a", columnDef: { meta: { width: 40 } } }], left: [], edge: 0, last: null },
  {
    name: "two leading pinned columns",
    columns: [
      { id: "a", columnDef: { meta: { width: 40, sticky: true } } },
      { id: "b", columnDef: { meta: { width: 100, sticky: true } } },
      { id: "c", columnDef: { meta: { width: 60 } } },
    ],
    left: [["a", 0], ["b", 40]],
    edge: 140,
    last: "b",
  },
  {
    name: "a pinned column without a width stops the walk",
    columns: [
      { id: "a", columnDef: { meta: { width: 40, sticky: true } } },
      { id: "b", columnDef: { meta: { sticky: true } } },
      { id: "c", columnDef: { meta: { width: 60, sticky: true } } },
    ],
    left: [["a", 0]],
    edge: 40,
    last: "a",
  },
  {
    name: "only LEADING columns pin",
    columns: [
      { id: "a", columnDef: { meta: { width: 40 } } },
      { id: "b", columnDef: { meta: { width: 100, sticky: true } } },
    ],
    left: [],
    edge: 0,
    last: null,
  },
];
for (const row of PIN_ROWS) {
  test(`pinnedOffsets: ${row.name}`, () => {
    const p = pinnedOffsets(row.columns);
    assert.deepEqual([...p.left.entries()], row.left);
    assert.equal(p.edge, row.edge);
    assert.equal(p.last, row.last);
  });
}

test("DataTable default markup is unchanged: a scrolling wrapper, no pinning", () => {
  const html = renderToStaticMarkup(<DataTable<Row> data={rows} columns={cols(false)} rowKey={(r) => r.id} />);
  assert.match(html, /class="table-scroll-x overflow-x-auto"/);
  assert.doesNotMatch(html, /overflow-x-clip/);
  assert.doesNotMatch(html, /left:/);
  assert.doesNotMatch(html, /sticky/);
});

test("DataTable pins leading sticky columns with offsets and an opaque fill", () => {
  const html = renderToStaticMarkup(<DataTable<Row> data={rows} columns={cols(true)} rowKey={(r) => r.id} zebra />);
  // Header + two body rows, each with two pinned cells.
  assert.equal((html.match(/style="left:0(px)?"/g) ?? []).length, 3);
  assert.equal((html.match(/style="left:40px"/g) ?? []).length, 3);
  assert.match(html, /sticky z-\[1\] bg-bg-2/);
  // The striped row's pinned cells mix the stripe so they stay opaque.
  assert.match(html, /color-mix\(in_srgb,var\(--bg-3\)_50%,var\(--bg-2\)\)/);
});

test("DataTable scrollX={false} clips instead of scrolling", () => {
  const html = renderToStaticMarkup(
    <DataTable<Row> data={rows} columns={cols(false)} rowKey={(r) => r.id} scrollX={false} stickyHeader />,
  );
  assert.match(html, /class="overflow-x-clip"/);
  assert.doesNotMatch(html, /table-scroll-x/);
  assert.match(html, /sticky top-0 z-10/);
});

test("glyph badges render the icon alone with the words as the accessible name", () => {
  const surface = renderToStaticMarkup(<SurfaceBadge glyph surface="desktop" host="claude-desktop" />);
  assert.match(surface, /role="img"/);
  assert.match(surface, /aria-label="Client: desktop · claude-desktop\. Captured from a standalone desktop app\."/);
  assert.doesNotMatch(surface, />desktop</);
  const ran = renderToStaticMarkup(<ExecutionLocationBadge glyph hideLocal location="vendor_cloud" vendorRef="cse_1" />);
  assert.match(ran, /aria-label="Ran: cloud\. Where it ran: /);
  assert.match(ran, /Vendor session: cse_1\./);
  // Unknown stays nothing, and hideLocal still hides local.
  assert.equal(renderToStaticMarkup(<SurfaceBadge glyph />), "");
  assert.equal(renderToStaticMarkup(<ExecutionLocationBadge glyph hideLocal location="local" />), "");
});

test("a shrinking tag pill can narrow and ellipsize its name", () => {
  const html = renderToStaticMarkup(<TagPill tag="refactor" shrink onClick={() => {}} />);
  assert.match(html, /min-w-0/);
  assert.match(html, /<span class="min-w-0 truncate">refactor<\/span>/);
  // Without shrink the pill is unchanged.
  assert.doesNotMatch(renderToStaticMarkup(<TagPill tag="refactor" onClick={() => {}} />), /truncate/);
});

test("the quiet tag editor trigger is a named glyph button", () => {
  const html = renderToStaticMarkup(<TagEditor quiet sessionId="s1" tags={[]} onTagsChange={() => {}} />);
  assert.match(html, /aria-label="Edit tags"/);
  assert.doesNotMatch(html, /\+ tag/);
  assert.match(renderToStaticMarkup(<TagEditor sessionId="s1" tags={[]} onTagsChange={() => {}} />), /\+ tag/);
});
