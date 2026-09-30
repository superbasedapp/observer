import type { VocabTable } from "./vocabEntry.ts";

// sessionVocab - the presentation tables for the session-detail vocabularies
// that the shared renderers in shared/components/sessiondetail own (the node
// panel and the org drawer mount the same components). Glyphs are
// VOCAB_ICONS.messageRole / .stopReason / .taskStatus / .jobStatus in
// ./vocabIcons.ts.

// MESSAGE_ROLE - a message row's role (MessagesTable). The design's role
// colours: user accent, assistant success, tool warn, system neutral.
export const MESSAGE_ROLE: VocabTable = {
  user: { tone: "accent" },
  assistant: { tone: "success" },
  tool: { tone: "warn" },
  system: { tone: "neutral" },
};

// STOP_REASON - how a turn ended (provider stop_reason). Routine completions
// (end_turn, tool_use) stay neutral; abnormal ends stand out in warn.
export const STOP_REASON: VocabTable = {
  end_turn: { tone: "neutral" },
  tool_use: { tone: "neutral" },
  max_tokens: { tone: "warn" },
  refusal: { tone: "warn" },
  pause_turn: { tone: "warn" },
  stop_sequence: { tone: "warn" },
};

// TASK_STATUS - a todo/plan item's status (internal/taskflow/types.go plus
// the synthetic "vanished"). in_progress is in flight (spins); completed is
// success; blocked is danger; vanished (dropped from the list while in
// progress, not a real completion) is warn; the rest are neutral.
export const TASK_STATUS: VocabTable = {
  pending: { tone: "neutral" },
  in_progress: { tone: "info", label: "in progress", spin: true },
  completed: { tone: "success" },
  cancelled: { tone: "neutral" },
  blocked: { tone: "danger" },
  deleted: { tone: "neutral" },
  vanished: { tone: "warn" },
};

// JOB_STATUS - an asynchronous job's state (session enrichment in
// IntelResultCard, guard evidence export on the node Security page).
// queued and running are in flight (spin); done / succeeded success;
// parked / partial / capped warn; failed / error danger.
export const JOB_STATUS: VocabTable = {
  queued: { tone: "info", spin: true },
  pending: { tone: "info", spin: true },
  running: { tone: "accent", spin: true },
  done: { tone: "success" },
  succeeded: { tone: "success" },
  parked: { tone: "warn" },
  partial: { tone: "warn" },
  capped: { tone: "warn" },
  failed: { tone: "danger" },
  error: { tone: "danger" },
};
