// Pins the "Observability is off" empty state's model (obsEnable.ts, B-S1).
import assert from "node:assert/strict";
import test from "node:test";

import {
  OBS_KEYS,
  obsEnableDoneLine,
  obsEnableLabel,
  obsEnableNote,
  obsEnablePatches,
  obsEnableState,
} from "./obsEnable.ts";

test("obsEnableState reads only real booleans", () => {
  assert.deepEqual(obsEnableState({ Observability: { Enabled: false, Admission: { Enabled: true } } }), {
    observability: false,
    admission: true,
  });
  assert.deepEqual(obsEnableState({ Observability: { Enabled: "true" } }), { observability: null, admission: null });
  assert.deepEqual(obsEnableState(null), { observability: null, admission: null });
});

test("obsEnablePatches turns on exactly the needed switches still off", () => {
  const rows: { name: string; state: Parameters<typeof obsEnablePatches>[0]; needs: ("observability" | "admission")[]; want: unknown }[] = [
    {
      name: "egress: observability off",
      state: { observability: false, admission: false },
      needs: ["observability"],
      want: [{ key: OBS_KEYS.observability, value: true, was: false }],
    },
    {
      name: "policies: both off",
      state: { observability: false, admission: false },
      needs: ["observability", "admission"],
      want: [
        { key: "observability.enabled", value: true, was: false },
        { key: "observability.admission.enabled", value: true, was: false },
      ],
    },
    {
      name: "policies: only admission off",
      state: { observability: true, admission: false },
      needs: ["observability", "admission"],
      want: [{ key: "observability.admission.enabled", value: true, was: false }],
    },
    { name: "already on: only the restart is missing", state: { observability: true, admission: true }, needs: ["observability", "admission"], want: [] },
    { name: "unknown: no switch, never a guess", state: { observability: null, admission: false }, needs: ["observability"], want: null },
  ];
  for (const r of rows) assert.deepEqual(obsEnablePatches(r.state, r.needs), r.want, r.name);
});

test("the copy names the button and the restart, never a command or a file to edit by hand", () => {
  assert.equal(obsEnableLabel(["observability"]), "Turn on observability");
  assert.equal(obsEnableLabel(["observability", "admission"]), "Turn on observability and admission");
  const note = obsEnableNote(["observability", "admission"]);
  assert.match(note, /observability\.enabled = true and observability\.admission\.enabled = true/);
  assert.match(note, /restarts/);
  for (const s of [note, obsEnableDoneLine(true), obsEnableDoneLine(false)]) {
    assert.ok(!/observer serve|run `|~\/\.observer/.test(s), s);
    assert.ok(!/[—–]/.test(s), `dash in ${s}`);
  }
});
