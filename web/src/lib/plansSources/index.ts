// The per-lane source words, merged. Each lane owns one file so parallel
// work never edits the same lines; internal/planlimits/vocab_source_test.go
// reads every file in this directory.
import type { SourceWords } from "./types.ts";
import { LANE_A, LANE_A_WORDS } from "./lanea.ts";
import { LANE_B, LANE_B_WORDS } from "./laneb.ts";
import { LANE_C1, LANE_C1_WORDS } from "./lanec1.ts";
import { LANE_C2, LANE_C2_WORDS } from "./lanec2.ts";
import { LANE_D, LANE_D_WORDS } from "./laned.ts";
import { WAVE_1021, WAVE_1021_WORDS } from "./wave1021.ts";

const ALL: Record<string, SourceWords> = { ...LANE_A, ...LANE_B, ...LANE_C1, ...LANE_C2, ...LANE_D, ...WAVE_1021 };

export const LANE_SOURCE_LABELS: Record<string, string> = Object.fromEntries(
  Object.entries(ALL).map(([id, w]) => [id, w.label]),
);

export const LANE_SOURCE_HOWTO: Record<string, string> = Object.fromEntries(
  Object.entries(ALL).map(([id, w]) => [id, w.howto]),
);

/** LANE_WORDS: words for parameter keys and parameter choices lanes added. */
export const LANE_WORDS: Record<string, string> = {
  ...LANE_A_WORDS,
  ...LANE_B_WORDS,
  ...LANE_C1_WORDS,
  ...LANE_C2_WORDS,
  ...LANE_D_WORDS,
  ...WAVE_1021_WORDS,
};
