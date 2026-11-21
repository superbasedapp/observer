// Component test of the generic Settings section (pages/settings/
// SchemaSection.tsx): U-14 (user-facing help, never the raw Go doc
// comment) and U-15 (rows lay out against the card's width), Plane A UI
// review 2026-11-21. Rendered with react-dom/server under node's test
// runner (scripts/test-components.mjs).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { GroupCard } from "@/pages/settings/SchemaSection";
import type { ConfigSchemaLeaf } from "@/lib/configschema.gen";

const leaf = {
  path: "observability.enabled",
  field_path: "Observability.Enabled",
  kind: "bool",
  go_type: "bool",
  owner: "github.com/marmutapp/superbased-observer/internal/config.ObservabilityConfig",
  field: "Enabled",
  block: "observability",
  table: "observability",
  tier: "plain",
  restart: "restart",
  section: "observability",
  prominence: "primary",
  secret: false,
  doc: "Enabled gates the whole Plane A surface (plan §3).",
  help: "Turns AI Apps on.",
} as ConfigSchemaLeaf;

test("Settings shows the user-facing help, never the Go doc comment (U-14, U-15)", () => {
  const html = renderToStaticMarkup(
    <GroupCard
      group={{
        path: "observability",
        table: {
          path: "observability",
          field_path: "Observability",
          owner: leaf.owner,
          block: "observability",
          doc: "ObservabilityConfig is the [observability] surface.",
          help: "AI Apps: receive traces from the apps you build.",
        },
        leaves: [leaf],
      }}
      showExpert={false}
      shown={() => true}
      current={() => true}
      draft={{}}
      keyErrors={{}}
      hasValue={() => true}
      onChange={() => {}}
      disabled={false}
    />,
  );
  assert.match(html, /AI Apps: receive traces from the apps you build\./);
  assert.match(html, /Turns AI Apps on\./);
  assert.doesNotMatch(html, /ObservabilityConfig|Enabled gates|§/, "no Go doc comment reaches the page");
  // U-15: the card is a size container, and the two-column row needs the
  // card (not the viewport) to be wide enough.
  assert.match(html, /\[container-type:inline-size\]/);
  assert.match(html, /\[@container\(min-width:640px\)\]:grid-cols-\[200px_minmax\(0,1fr\)\]/);
  assert.doesNotMatch(html, /lg:grid-cols-\[220px/);
});
