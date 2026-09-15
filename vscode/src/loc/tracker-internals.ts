// Pure snapshot/delta logic for the human lines-of-code capture.
//
// Split out of tracker.ts (the same `*-internals.ts` convention this
// extension already uses for daemon, binary and costBar) so the state
// machine is unit-testable without loading the `vscode` module. Nothing
// here imports vscode, does I/O, or knows about HTTP.
//
// The state machine implements the three safeguards from the plan's
// §3.3 "Human capture v1":
//
//   (a) EXTERNAL RELOAD. The per-document snapshot is refreshed whenever
//       the document changes while it is NOT dirty — VS Code reloading
//       a file an agent just wrote. Without this the agent's write
//       becomes part of the human's next save and is counted twice, as
//       both AI and human lines.
//   (b) WILL-SAVE vs DID-SAVE. The delta from the last clean snapshot to
//       the will-save text is the HUMAN's work; the delta from the
//       will-save text to the text actually written is the FORMATTER's
//       (format-on-save, organize-imports, trailing-whitespace trim) and
//       is reported as `system`, never as human lines.
//   (c) COUNTS ONLY. Nothing here retains or returns file text to the
//       caller — only Stats.

import { Stats, Confidence, diffCount, statsTotal } from './classify';

/** SaveDelta is one save's measured human and system halves. */
export interface SaveDelta {
  human: Stats;
  system: Stats;
  humanConfidence: Confidence;
  systemConfidence: Confidence;
  /**
   * possibleAgent is true when at least one buffer change since the last
   * save arrived in a shape a person's keystrokes do not produce (see
   * isAgentShapedChange). The daemon books such a save as `unknown`
   * rather than as the developer's own lines.
   */
  possibleAgent: boolean;
}

/**
 * BufferChangeShape is the part of a vscode TextDocumentChangeEvent the
 * agent-shape classifier needs, reduced to plain numbers so the rule is
 * testable without the `vscode` module.
 *
 * The wiring layer fills it from `e.contentChanges` and `e.reason`; it
 * never carries a line of text.
 */
export interface BufferChangeShape {
  /** How many separate ranges the event replaced. */
  ranges: number;
  /** Total characters inserted across every range. */
  insertedLength: number;
  /** Total newlines inserted across every range. */
  insertedLines: number;
  /** Total lines the event replaced (removed) across every range. */
  replacedLines: number;
  /** vscode's TextDocumentChangeReason, when it had one. */
  reason?: 'undo' | 'redo';
  /** Whether the document was dirty when the event arrived. */
  dirty: boolean;
}

/**
 * Thresholds for isAgentShapedChange. Named, because every one of them is
 * a judgement call and a reader is entitled to see the number.
 */
const AGENT_MULTI_RANGE_MIN = 2;
const AGENT_MULTI_RANGE_CHARS = 40;
const AGENT_REWRITE_LINES = 2;
const AGENT_INSERT_LINES = 30;

/**
 * agentShapeRules is the decision table (one row per shape, walked
 * top-down; CLAUDE.md rule #5). Each row returns true when the change
 * matches a shape a human editing session does not produce.
 */
const agentShapeRules: ReadonlyArray<{
  readonly why: string;
  readonly test: (c: BufferChangeShape) => boolean;
}> = [
  {
    // Several ranges rewritten at once with real content in them. A human
    // with multiple cursors inserts a character or two per range per
    // event; a WorkspaceEdit lands the whole edit as one event.
    why: 'multi-range replacement',
    test: (c) => c.ranges >= AGENT_MULTI_RANGE_MIN && c.insertedLength >= AGENT_MULTI_RANGE_CHARS,
  },
  {
    // A rewrite: two or more existing lines replaced by two or more new
    // ones in a single event. Typing cannot delete two lines and produce
    // two others atomically. This is the shape of Copilot agent mode
    // rewriting a function, which is the case M7 named.
    why: 'multi-line rewrite',
    test: (c) => c.replacedLines >= AGENT_REWRITE_LINES && c.insertedLines >= AGENT_REWRITE_LINES,
  },
  {
    // A large single-range insertion. This one ALSO catches a large
    // human paste, and it is kept anyway: `unknown` is the honest label
    // for a block of lines that were not typed and whose author the
    // editor cannot name, whereas crediting them to the developer is a
    // claim we cannot support. The threshold is set well above an
    // ordinary paste for the same reason.
    why: 'large insertion',
    test: (c) => c.insertedLines >= AGENT_INSERT_LINES,
  },
];

/**
 * isAgentShapedChange reports whether a buffer change looks like an
 * in-editor agent's WorkspaceEdit rather than a person typing.
 *
 * WHY IT EXISTS. Safeguard (a) — refresh the baseline when a CLEAN
 * document changes — only catches an agent that wrote to DISK. Copilot
 * Chat agent mode, the Cline and Kilo VS Code extensions and Cursor edit
 * the BUFFER, which dirties it exactly as typing does, so their lines were
 * being reported as the developer's (review finding M7).
 *
 * It is a heuristic and the pipeline treats it as one: a flagged save is
 * booked `unknown`, never reattributed to an agent. See the residual
 * noted in the plan's §7 — there is no VS Code API that names the author
 * of a TextDocumentChangeEvent, so a perfect signal is not available.
 */
export function isAgentShapedChange(c: BufferChangeShape): boolean {
  if (!c.dirty) {
    // A clean document is safeguard (a)'s job: the baseline is refreshed
    // outright, which is strictly better than flagging.
    return false;
  }
  if (c.reason === 'undo' || c.reason === 'redo') {
    // Undo/redo replays the user's own history, however large it is.
    return false;
  }
  if (c.insertedLength === 0 && c.replacedLines === 0) {
    return false;
  }
  return agentShapeRules.some((rule) => rule.test(c));
}

/** hasCounts reports whether a delta is worth reporting at all. */
export function hasCounts(delta: SaveDelta): boolean {
  return statsTotal(delta.human) > 0 || statsTotal(delta.system) > 0;
}

/**
 * SaveTracker holds one `lastCleanText` per document key and turns a
 * will-save/did-save pair into a SaveDelta.
 *
 * A "key" is whatever stable string the caller uses to identify a
 * document (the wiring layer passes `uri.toString()`). The tracker never
 * parses it.
 *
 * Memory: exactly one string per OPEN document, dropped on forget().
 * The caller is expected to forget a document when VS Code closes it.
 */
export class SaveTracker {
  private readonly clean = new Map<string, string>();
  private readonly pending = new Map<string, string>();
  /** Documents that saw an agent-shaped buffer change since their last save. */
  private readonly agentTouched = new Set<string>();

  /**
   * seed records the text of a document as its clean baseline. Call it
   * on open, and once at activation for every already-open document.
   * Seeding an already-tracked document is a no-op, so a spurious open
   * event cannot discard a snapshot that is mid-edit.
   */
  seed(key: string, text: string): void {
    if (!this.clean.has(key)) {
      this.clean.set(key, text);
    }
  }

  /**
   * external refreshes the baseline after a change that did NOT come
   * from the human typing — an on-disk reload of a clean document.
   * Safeguard (a).
   */
  external(key: string, text: string): void {
    this.clean.set(key, text);
    // The baseline now IS the agent's text, so nothing between here and
    // the next save can still be the agent's — any earlier suspicion is
    // resolved by the refresh and must not leak into the next save.
    this.agentTouched.delete(key);
  }

  /**
   * changed classifies one buffer change and, when it is agent-shaped,
   * marks the document so the NEXT save reports possibleAgent.
   *
   * It returns whether the change was flagged, purely so the wiring layer
   * can log it; the state that matters is held here.
   */
  changed(key: string, shape: BufferChangeShape): boolean {
    if (!isAgentShapedChange(shape)) {
      return false;
    }
    this.agentTouched.add(key);
    return true;
  }

  /** tracked reports whether a baseline exists for this key. */
  tracked(key: string): boolean {
    return this.clean.has(key);
  }

  /**
   * willSave stashes the document text as it stood when the save
   * started, BEFORE any will-save participant (formatter) edits it.
   * Safeguard (b), first half.
   */
  willSave(key: string, text: string): void {
    this.pending.set(key, text);
  }

  /**
   * didSave measures the save and advances the baseline to the text
   * that was actually written.
   *
   * When no will-save text was stashed (a save that bypassed the
   * will-save event) the saved text stands in for it, so the whole
   * delta lands in `human` and `system` is empty — the honest reading,
   * since without the will-save image there is no evidence a formatter
   * ran.
   *
   * When no baseline exists (a document saved before the extension ever
   * saw it) the saved text is its own baseline: the result is all-zero
   * and the caller drops it. Attributing a whole untracked file to the
   * human on its first save would be a fabricated number.
   */
  didSave(key: string, savedText: string, lang: string): SaveDelta {
    const base = this.clean.get(key) ?? savedText;
    const willSaveText = this.pending.get(key) ?? savedText;
    const possibleAgent = this.agentTouched.has(key);
    this.pending.delete(key);
    this.agentTouched.delete(key);
    this.clean.set(key, savedText);

    const human = diffCount(base, willSaveText, lang);
    const system = diffCount(willSaveText, savedText, lang);
    return {
      human: human.stats,
      system: system.stats,
      humanConfidence: human.confidence,
      systemConfidence: system.confidence,
      possibleAgent,
    };
  }

  /** forget drops all state for a document (call it on close). */
  forget(key: string): void {
    this.clean.delete(key);
    this.pending.delete(key);
    this.agentTouched.delete(key);
  }

  /** size is the number of tracked documents; for tests and diagnostics. */
  get size(): number {
    return this.clean.size;
  }
}

/**
 * toForwardSlashes normalizes a workspace-relative path to the forward
 * -slash form the daemon hashes. VS Code's asRelativePath can return
 * platform separators on Windows, and `src\a.go` and `src/a.go` must
 * hash to the same file.
 */
export function toForwardSlashes(relativePath: string): string {
  return relativePath.replace(/\\/g, '/');
}

/**
 * EditorTokenSource resolves the shared secret the extension sends as
 * `X-Observer-Token` on POST /api/loc/editor-change.
 *
 * Two places hold it, in this order:
 *
 *   1. The `observer.loc.editorToken` setting, when the operator typed one.
 *      An explicit setting always wins - it is how someone who runs the
 *      daemon on another machine, or under another user, supplies the value
 *      by hand.
 *   2. The daemon's generated token file (`[loc].editor_token_file`,
 *      default `<observer home>/loc-editor-token`, mode 0600). This is the
 *      normal path and needs no configuration at either end.
 *
 * The file may not exist yet: VS Code frequently starts before the daemon
 * does, and the daemon writes the file on ITS first start. So a miss is
 * re-checked, but at most once per `retryMs`, because this runs on the save
 * path and a stat per keystroke-flurry-then-save would be silly.
 *
 * All I/O is injected (`readFile`, `now`), so the whole resolution order is
 * unit-testable without a filesystem - the same discipline as the rest of
 * this file.
 */
export class EditorTokenSource {
  private cached = '';
  private lastReadAt = -Infinity;

  constructor(
    private readonly opts: {
      /** Current value of the observer.loc.editorToken setting. */
      setting: () => string;
      /** Absolute path of the daemon's token file. */
      tokenFile: () => string;
      /** Reads the token file; returns undefined when it is absent or unreadable. */
      readFile: (path: string) => string | undefined;
      /** Milliseconds between re-reads after a miss. Default 60_000. */
      retryMs?: number;
      /** Injected clock. */
      now?: () => number;
    },
  ) {}

  /**
   * get returns the token to send, or '' when none is available (the
   * daemon accepts an Origin-less loopback POST without one unless the
   * operator set [loc].editor_token_required).
   */
  get(): string {
    const configured = this.opts.setting().trim();
    if (configured) {
      return configured;
    }
    if (this.cached) {
      return this.cached;
    }
    const now = (this.opts.now ?? Date.now)();
    const retryMs = this.opts.retryMs ?? 60_000;
    if (now - this.lastReadAt < retryMs) {
      return '';
    }
    this.lastReadAt = now;
    const path = this.opts.tokenFile();
    if (!path) {
      return '';
    }
    // Trimmed: the daemon writes the token with a trailing newline so the
    // file is a normal text line, and a stray '\n' in a header value is a
    // protocol error, not a mismatch the daemon could explain.
    this.cached = (this.opts.readFile(path) ?? '').trim();
    return this.cached;
  }

  /** invalidate drops the cached token so the next get() re-reads. */
  invalidate(): void {
    this.cached = '';
    this.lastReadAt = -Infinity;
  }
}
