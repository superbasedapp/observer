// The portal's signed-out screens (sign-in, sign-up, the connect code entry
// and approval pages, "Machine connected") all render through AuthShell,
// which has no top bar; the shared theme toggle rides in its corner
// (hosted sign-in fix, lane A), offering light, dark and system.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { ThemeProvider } from "@shared/lib/useTheme";
import { AuthShell } from "./AuthShell";

test("the signed-out shell carries the theme toggle with light, dark and system", () => {
  const out = renderToStaticMarkup(
    <ThemeProvider app="webcloud">
      <AuthShell title="Machine connected">
        <p>body</p>
      </AuthShell>
    </ThemeProvider>,
  );
  assert.match(out, /role="radiogroup" aria-label="Theme"/);
  for (const label of ["Light theme", "Dark theme", "Follow system"]) {
    assert.match(out, new RegExp(`aria-label="${label}"`));
  }
  // System is the portal's default.
  assert.match(out, /aria-checked="true" aria-label="Follow system"/);
  assert.match(out, /Machine connected/);
});
