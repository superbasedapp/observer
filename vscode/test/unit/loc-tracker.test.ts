// Unit tests for src/loc/tracker-internals.ts and the POST in
// src/api/client.ts.
//
// The three scenarios named in the plan's acceptance criterion 4 are
// each a test here: (a) a human save shortly after an agent edit is not
// double counted, (b) an agent edit long before a human save leaves only
// the human delta, (c) a format-on-save reflow lands in `system`.
//
// SaveTracker is pure, so none of this needs the `vscode` module — the
// wiring layer (src/loc/tracker.ts) only translates VS Code events into
// these calls.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  EditorTokenSource,
  SaveTracker,
  hasCounts,
  isAgentShapedChange,
  toForwardSlashes,
  type BufferChangeShape,
} from '../../src/loc/tracker-internals';
import { classifierVersion, hasGeneratedHeader, zeroStats, statsTotal } from '../../src/loc/classify';
import { Client, LocEndpointMissingError, type EditorChangeRequest } from '../../src/api/client';

const KEY = 'file:///repo/src/a.go';

const AGENT_WROTE = ['package main', '', 'func agentAdded() int {', '\treturn 1', '}', ''].join(
  '\n',
);

describe('SaveTracker — safeguard (a), external reload', () => {
  test('a human save 1s after an agent edit does not claim the agent lines', () => {
    const t = new SaveTracker();
    // The human opened the file when it held only the package clause.
    t.seed(KEY, 'package main\n');

    // The agent writes the file; VS Code reloads the clean document and
    // the wiring layer refreshes the baseline.
    t.external(KEY, AGENT_WROTE);

    // One second later the human adds a single line and saves.
    const humanText = AGENT_WROTE + 'var humanWrote = 2\n';
    t.willSave(KEY, humanText);
    const delta = t.didSave(KEY, humanText, 'go');

    assert.deepEqual(delta.human, { ...zeroStats(), added_code: 1 });
    assert.deepEqual(delta.system, zeroStats());
    assert.equal(delta.humanConfidence, 'high');
  });

  test('WITHOUT the refresh the agent lines would be attributed to the human', () => {
    // The failure this safeguard exists to prevent, pinned so a
    // regression is visible rather than silent.
    const t = new SaveTracker();
    t.seed(KEY, 'package main\n');
    // No external() call — the agent's write is invisible to us.
    const humanText = AGENT_WROTE + 'var humanWrote = 2\n';
    t.willSave(KEY, humanText);
    const delta = t.didSave(KEY, humanText, 'go');
    assert.ok(delta.human.added_code > 1, 'the un-refreshed baseline over-counts');
  });
});

describe('SaveTracker — safeguard (a), stale agent edit', () => {
  test('an agent edit 5 minutes before the save leaves only the human delta', () => {
    const t = new SaveTracker();
    t.seed(KEY, 'package main\n');
    t.external(KEY, AGENT_WROTE); // five minutes ago; time is irrelevant

    // The human then edits two lines and adds one, across the session.
    const humanText = AGENT_WROTE.replace('return 1', 'return 42') + 'var humanWrote = 2\n';
    t.willSave(KEY, humanText);
    const delta = t.didSave(KEY, humanText, 'go');

    assert.deepEqual(delta.human, { ...zeroStats(), modified_code: 1, added_code: 1 });
    assert.deepEqual(delta.system, zeroStats());
  });
});

describe('SaveTracker — safeguard (b), will-save vs did-save', () => {
  test('a format-on-save reflow lands in system, not human', () => {
    const t = new SaveTracker();
    const before = 'package main\n\nfunc f() int {\n\treturn 1\n}\n';
    t.seed(KEY, before);

    // The human adds one line, badly indented.
    const typed = 'package main\n\nfunc f() int {\n\treturn 1\n}\n\nvar x  =    2\n';
    t.willSave(KEY, typed);
    // gofmt rewrites the spacing during the save.
    const formatted = 'package main\n\nfunc f() int {\n\treturn 1\n}\n\nvar x = 2\n';
    const delta = t.didSave(KEY, formatted, 'go');

    assert.deepEqual(delta.human, { ...zeroStats(), added_code: 1, blank: 1 });
    assert.deepEqual(delta.system, { ...zeroStats(), whitespace: 1 });
  });

  test('a formatter that adds a line lands the added line in system', () => {
    const t = new SaveTracker();
    t.seed(KEY, 'package main\n');
    const typed = 'package main\nvar x = 1\n';
    t.willSave(KEY, typed);
    const formatted = 'package main\n\nvar x = 1\n';
    const delta = t.didSave(KEY, formatted, 'go');

    assert.deepEqual(delta.human, { ...zeroStats(), added_code: 1 });
    assert.deepEqual(delta.system, { ...zeroStats(), blank: 1 });
  });

  test('a save with no will-save text puts the whole delta in human', () => {
    const t = new SaveTracker();
    t.seed(KEY, 'package main\n');
    const delta = t.didSave(KEY, 'package main\nvar x = 1\n', 'go');
    assert.deepEqual(delta.human, { ...zeroStats(), added_code: 1 });
    assert.deepEqual(delta.system, zeroStats());
  });
});

describe('SaveTracker — baseline lifecycle', () => {
  test('an untracked document reports nothing on its first save', () => {
    const t = new SaveTracker();
    const delta = t.didSave(KEY, 'package main\nvar x = 1\n', 'go');
    assert.equal(statsTotal(delta.human), 0);
    assert.equal(statsTotal(delta.system), 0);
    assert.equal(hasCounts(delta), false);
  });

  test('the baseline advances to the saved text, so a second save is incremental', () => {
    const t = new SaveTracker();
    t.seed(KEY, 'package main\n');
    t.willSave(KEY, 'package main\nvar a = 1\n');
    t.didSave(KEY, 'package main\nvar a = 1\n', 'go');

    t.willSave(KEY, 'package main\nvar a = 1\nvar b = 2\n');
    const second = t.didSave(KEY, 'package main\nvar a = 1\nvar b = 2\n', 'go');
    assert.deepEqual(second.human, { ...zeroStats(), added_code: 1 });
  });

  test('seed does not clobber an existing baseline', () => {
    const t = new SaveTracker();
    t.seed(KEY, 'package main\n');
    t.seed(KEY, 'package main\nvar typed = 1\n'); // spurious re-open
    t.willSave(KEY, 'package main\nvar typed = 1\n');
    const delta = t.didSave(KEY, 'package main\nvar typed = 1\n', 'go');
    assert.deepEqual(delta.human, { ...zeroStats(), added_code: 1 });
  });

  test('forget drops the baseline', () => {
    const t = new SaveTracker();
    t.seed(KEY, 'package main\n');
    assert.equal(t.size, 1);
    assert.equal(t.tracked(KEY), true);
    t.forget(KEY);
    assert.equal(t.size, 0);
    assert.equal(t.tracked(KEY), false);
  });

  test('an unchanged save reports nothing worth sending', () => {
    const t = new SaveTracker();
    t.seed(KEY, 'package main\n');
    t.willSave(KEY, 'package main\n');
    assert.equal(hasCounts(t.didSave(KEY, 'package main\n', 'go')), false);
  });
});

describe('toForwardSlashes', () => {
  test('normalizes Windows separators so the path hash matches', () => {
    assert.equal(toForwardSlashes('src\\loc\\a.go'), 'src/loc/a.go');
    assert.equal(toForwardSlashes('src/loc/a.go'), 'src/loc/a.go');
  });
});

// ---------------------------------------------------------------------
// Client.postEditorChange
// ---------------------------------------------------------------------

const BODY: EditorChangeRequest = {
  path: 'src/a.go',
  workspace_root: '/repo',
  language: 'go',
  category: 'code',
  human: { ...zeroStats(), added_code: 3, modified_code: 1, blank: 1 },
  system: zeroStats(),
  human_confidence: 'high',
  system_confidence: 'high',
  saved_at: '2026-09-07T10:11:12.345Z',
  classifier_version: classifierVersion,
  possible_agent: false,
};

interface Capture {
  url: string;
  init: RequestInit;
}

function stubFetch(status: number, captures: Capture[]): typeof fetch {
  return (async (input: string, init: RequestInit) => {
    captures.push({ url: input, init });
    return new Response(status === 204 ? null : '{}', { status });
  }) as unknown as typeof fetch;
}

describe('Client.postEditorChange', () => {
  test('POSTs JSON to /api/loc/editor-change with no Origin header', async () => {
    const captures: Capture[] = [];
    const c = new Client({ dashboardPort: 8081, fetchImpl: stubFetch(200, captures) });
    await c.postEditorChange(BODY);

    assert.equal(captures.length, 1);
    assert.equal(captures[0].url, 'http://127.0.0.1:8081/api/loc/editor-change');
    assert.equal(captures[0].init.method, 'POST');
    const headers = captures[0].init.headers as Record<string, string>;
    assert.equal(headers['Content-Type'], 'application/json');
    assert.equal(headers['X-Observer-Token'], undefined);
    // A non-browser client must stay Origin-less: the daemon's
    // browserGuard admits Origin-less loopback POSTs.
    assert.equal(headers['Origin'], undefined);
    assert.deepEqual(JSON.parse(captures[0].init.body as string), BODY);
  });

  test('sends X-Observer-Token when one is configured', async () => {
    const captures: Capture[] = [];
    const c = new Client({ dashboardPort: 8081, fetchImpl: stubFetch(200, captures) });
    await c.postEditorChange(BODY, 'sekret');
    const headers = captures[0].init.headers as Record<string, string>;
    assert.equal(headers['X-Observer-Token'], 'sekret');
  });

  test('204 is success', async () => {
    const c = new Client({ dashboardPort: 8081, fetchImpl: stubFetch(204, []) });
    await c.postEditorChange(BODY);
  });

  test('404 throws LocEndpointMissingError so the caller can stop posting', async () => {
    const c = new Client({ dashboardPort: 8081, fetchImpl: stubFetch(404, []) });
    await assert.rejects(() => c.postEditorChange(BODY), LocEndpointMissingError);
  });

  test('any other failure throws a plain Error', async () => {
    const c = new Client({ dashboardPort: 8081, fetchImpl: stubFetch(500, []) });
    await assert.rejects(() => c.postEditorChange(BODY), (err: Error) => {
      assert.ok(!(err instanceof LocEndpointMissingError));
      assert.match(err.message, /editor-change/);
      return true;
    });
  });

  test('the body type carries counts only — no field can hold file text', () => {
    // A structural pin: every value on the wire is either a scalar
    // identifier or a number bucket. If someone adds a `content` field
    // this test is where it shows up.
    const keys = Object.keys(BODY).sort();
    assert.deepEqual(keys, [
      'category',
      'classifier_version',
      'human',
      'human_confidence',
      'language',
      'path',
      'possible_agent',
      'saved_at',
      'system',
      'system_confidence',
      'workspace_root',
    ]);
    for (const bucket of [BODY.human, BODY.system]) {
      for (const value of Object.values(bucket)) {
        assert.equal(typeof value, 'number');
      }
    }
  });
});

// ---------------------------------------------------------------------
// Review fix (2026-09-07): M7 — in-editor agents counted as human
// ---------------------------------------------------------------------

/** shape builds a BufferChangeShape with dirty:true defaults. */
function shape(over: Partial<BufferChangeShape> = {}): BufferChangeShape {
  return {
    ranges: 1,
    insertedLength: 0,
    insertedLines: 0,
    replacedLines: 0,
    dirty: true,
    ...over,
  };
}

describe('isAgentShapedChange — safeguard (a2), in-editor agents', () => {
  test('a keystroke is not agent-shaped', () => {
    assert.equal(isAgentShapedChange(shape({ insertedLength: 1 })), false);
  });

  test('typing a whole line one keystroke at a time is not agent-shaped', () => {
    for (let i = 0; i < 80; i++) {
      assert.equal(isAgentShapedChange(shape({ insertedLength: 1 })), false);
    }
  });

  test('multi-cursor typing (2 ranges, 1 char each) is not agent-shaped', () => {
    assert.equal(isAgentShapedChange(shape({ ranges: 3, insertedLength: 3 })), false);
  });

  test('pressing Enter is not agent-shaped', () => {
    assert.equal(isAgentShapedChange(shape({ insertedLength: 1, insertedLines: 1 })), false);
  });

  test('a multi-range WorkspaceEdit IS agent-shaped', () => {
    assert.equal(isAgentShapedChange(shape({ ranges: 4, insertedLength: 240 })), true);
  });

  test('a multi-line rewrite IS agent-shaped', () => {
    // Copilot agent mode replacing a function body: 12 lines out, 14 in,
    // one range, one event.
    assert.equal(
      isAgentShapedChange(shape({ insertedLength: 400, insertedLines: 14, replacedLines: 12 })),
      true,
    );
  });

  test('a large single-range insertion IS agent-shaped', () => {
    assert.equal(isAgentShapedChange(shape({ insertedLength: 3000, insertedLines: 120 })), true);
  });

  test('a CLEAN document is left to safeguard (a), never flagged', () => {
    assert.equal(
      isAgentShapedChange(shape({ insertedLength: 3000, insertedLines: 120, dirty: false })),
      false,
    );
  });

  test('undo and redo replay the user own history however large', () => {
    for (const reason of ['undo', 'redo'] as const) {
      assert.equal(
        isAgentShapedChange(shape({ insertedLength: 3000, insertedLines: 120, reason })),
        false,
      );
    }
  });

  test('an empty change is not agent-shaped', () => {
    assert.equal(isAgentShapedChange(shape()), false);
  });
});

describe('SaveTracker — possibleAgent flows to the save', () => {
  test('an agent-shaped change makes the NEXT save report possibleAgent', () => {
    const t = new SaveTracker();
    t.seed(KEY, 'package main\n');
    // Copilot agent mode rewrites the buffer; the document is dirty, so
    // safeguard (a) does not fire.
    assert.equal(
      t.changed(KEY, shape({ ranges: 1, insertedLength: 400, insertedLines: 14, replacedLines: 12 })),
      true,
    );
    const text = 'package main\n' + Array.from({ length: 14 }, (_, i) => `var x${i} = ${i}`).join('\n') + '\n';
    t.willSave(KEY, text);
    const delta = t.didSave(KEY, text, 'go');
    assert.equal(delta.possibleAgent, true, 'an in-editor agent edit was reported as human');
    assert.ok(statsTotal(delta.human) > 0, 'the lines are still recorded, just not credited');
  });

  test('the flag is consumed by the save and does not leak into the next one', () => {
    const t = new SaveTracker();
    t.seed(KEY, 'package main\n');
    t.changed(KEY, shape({ ranges: 5, insertedLength: 300 }));
    t.willSave(KEY, 'package main\nvar a = 1\n');
    assert.equal(t.didSave(KEY, 'package main\nvar a = 1\n', 'go').possibleAgent, true);

    t.willSave(KEY, 'package main\nvar a = 1\nvar b = 2\n');
    const second = t.didSave(KEY, 'package main\nvar a = 1\nvar b = 2\n', 'go');
    assert.equal(second.possibleAgent, false, 'the flag leaked into a save the human typed');
    assert.deepEqual(second.human, { ...zeroStats(), added_code: 1 });
  });

  test('an ordinary typed save never reports possibleAgent', () => {
    const t = new SaveTracker();
    t.seed(KEY, 'package main\n');
    t.changed(KEY, shape({ insertedLength: 1 }));
    t.willSave(KEY, 'package main\nvar a = 1\n');
    assert.equal(t.didSave(KEY, 'package main\nvar a = 1\n', 'go').possibleAgent, false);
  });

  test('an on-disk reload clears an earlier suspicion', () => {
    const t = new SaveTracker();
    t.seed(KEY, 'package main\n');
    t.changed(KEY, shape({ ranges: 5, insertedLength: 300 }));
    // The agent then wrote the file to disk and VS Code reloaded it: the
    // baseline IS the agent's text now, so nothing is left to suspect.
    t.external(KEY, AGENT_WROTE);
    const text = AGENT_WROTE + 'var humanWrote = 2\n';
    t.willSave(KEY, text);
    const delta = t.didSave(KEY, text, 'go');
    assert.equal(delta.possibleAgent, false);
    assert.deepEqual(delta.human, { ...zeroStats(), added_code: 1 });
  });

  test('forget drops the flag with the rest of the state', () => {
    const t = new SaveTracker();
    t.seed(KEY, 'package main\n');
    t.changed(KEY, shape({ ranges: 5, insertedLength: 300 }));
    t.forget(KEY);
    t.seed(KEY, 'package main\n');
    t.willSave(KEY, 'package main\nvar a = 1\n');
    assert.equal(t.didSave(KEY, 'package main\nvar a = 1\n', 'go').possibleAgent, false);
  });
});

describe('hasGeneratedHeader — review fix L3', () => {
  test('the canonical banner in the first three lines marks a file generated', () => {
    assert.equal(hasGeneratedHeader(['// Code generated by oapi-codegen. DO NOT EDIT.']), true);
    assert.equal(
      hasGeneratedHeader(['//go:build !ignore', '', '// Code generated by mockgen. DO NOT EDIT.']),
      true,
    );
    assert.equal(hasGeneratedHeader(['# Code generated by protoc. DO NOT EDIT.']), true);
  });

  test('past the scan window it is prose about generated code', () => {
    assert.equal(
      hasGeneratedHeader([
        'package a',
        '',
        'var x = 1',
        '// Code generated files carry DO NOT EDIT. banners.',
      ]),
      false,
    );
  });

  test('half a banner is not a banner', () => {
    assert.equal(hasGeneratedHeader(['// Code generated by hand, edit freely']), false);
    assert.equal(hasGeneratedHeader([]), false);
  });
});

describe('EditorTokenSource — discovery order', () => {
  const FILE = '/home/dev/.observer/loc-editor-token';

  function source(
    opts: Partial<{
      setting: string;
      file: string | undefined;
      reads: string[];
      now: () => number;
      retryMs: number;
    }> = {},
  ) {
    const reads = opts.reads ?? [];
    return {
      reads,
      src: new EditorTokenSource({
        setting: () => opts.setting ?? '',
        tokenFile: () => FILE,
        readFile: (p) => {
          reads.push(p);
          return opts.file;
        },
        retryMs: opts.retryMs,
        now: opts.now,
      }),
    };
  }

  test('the setting wins over the token file and the file is never read', () => {
    const { src, reads } = source({ setting: '  from-setting  ', file: 'from-file' });
    assert.equal(src.get(), 'from-setting');
    assert.deepEqual(reads, []);
  });

  test('falls back to the token file, trimmed of the daemon trailing newline', () => {
    const { src, reads } = source({ file: 'abc123\n' });
    assert.equal(src.get(), 'abc123');
    assert.deepEqual(reads, [FILE]);
  });

  test('a found token is cached — no re-read on the next save', () => {
    const { src, reads } = source({ file: 'abc123\n' });
    assert.equal(src.get(), 'abc123');
    assert.equal(src.get(), 'abc123');
    assert.equal(reads.length, 1);
  });

  test('an absent file yields no token and is retried at most once per window', () => {
    let clock = 1_000;
    const { src, reads } = source({ file: undefined, retryMs: 60_000, now: () => clock });
    assert.equal(src.get(), '');
    assert.equal(src.get(), '');
    assert.equal(reads.length, 1, 'a missing file must not be stat-ed on every save');
    clock += 59_999;
    assert.equal(src.get(), '');
    assert.equal(reads.length, 1);
    clock += 2;
    assert.equal(src.get(), '');
    assert.equal(reads.length, 2, 'the daemon may start after the editor — the miss must be retried');
  });

  test('a daemon that starts later is picked up on the next window', () => {
    let clock = 0;
    let onDisk: string | undefined;
    const src = new EditorTokenSource({
      setting: () => '',
      tokenFile: () => FILE,
      readFile: () => onDisk,
      retryMs: 1_000,
      now: () => clock,
    });
    assert.equal(src.get(), '');
    onDisk = 'daemon-started\n';
    clock += 1_001;
    assert.equal(src.get(), 'daemon-started');
  });

  test('invalidate drops the cache so a cleared setting re-reads the file', () => {
    const { src, reads } = source({ file: 'from-file\n' });
    assert.equal(src.get(), 'from-file');
    src.invalidate();
    assert.equal(src.get(), 'from-file');
    assert.equal(reads.length, 2);
  });

  test('an empty token file resolves to no token rather than an empty header', () => {
    const { src } = source({ file: '   \n' });
    assert.equal(src.get(), '');
  });
});
