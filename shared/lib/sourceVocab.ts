import type { VocabTable } from "./vocabEntry.ts";

// sourceVocab - the ONE tone per capture source / tier: where a session's
// tokens (Cost model table) or its cache grading (Cache page, session Cache
// badge) came from. proxy (Tier 1, observed live on the wire, the accurate
// path) is success; a transcript / jsonl log reconstruction (Tier 2) is info;
// mixed (both paths walked the session, so figures can drift) is warn; none
// is neutral. Before 2026-09-28 proxy was info on Cost and the Cache page but
// success on the session badge, and mixed was info on the badge.
// Glyphs: VOCAB_ICONS.sourceTier.
export const SOURCE_TIER: VocabTable = {
  proxy: { tone: "success" },
  transcript: { tone: "info" },
  jsonl: { tone: "info" },
  mixed: { tone: "warn" },
  none: { tone: "neutral" },
};
