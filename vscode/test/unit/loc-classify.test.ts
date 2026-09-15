// Unit tests for src/loc/classify.ts — the TypeScript mirror of
// internal/loc.
//
// The diff/count cases below are deliberately the same scenarios
// internal/loc/count_test.go asserts (one-line replacement, 200-line
// reindent, mass rename, moved block, pure append, pure delete), with
// the same expected buckets. Together with loc-golden.test.ts they are
// the two halves of the drift gate: the golden test pins the line
// classifier, these pin the alignment and the transition table.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifierVersion,
  classifyLines,
  diffCount,
  language,
  splitLines,
  zeroStats,
  type Stats,
} from '../../src/loc/classify';

function stats(partial: Partial<Stats>): Stats {
  return { ...zeroStats(), ...partial };
}

describe('language', () => {
  test('a .go file is code', () => {
    assert.deepEqual(language('internal/store/loc.go'), { lang: 'go', category: 'code' });
  });

  test('a .md file is docs, not code', () => {
    assert.deepEqual(language('docs/README.md'), { lang: 'markdown', category: 'docs' });
  });

  test('a .yaml file is config, not code', () => {
    assert.deepEqual(language('.github/workflows/ci.yaml'), { lang: 'yaml', category: 'config' });
  });

  test('anything under node_modules is vendored', () => {
    assert.deepEqual(language('web/node_modules/react/index.js'), {
      lang: '',
      category: 'vendored',
    });
  });

  test('package-lock.json is generated', () => {
    assert.deepEqual(language('web/package-lock.json'), { lang: '', category: 'generated' });
  });

  test('a *.pb.go suffix is generated', () => {
    assert.deepEqual(language('api/v1/service.pb.go'), { lang: '', category: 'generated' });
  });

  test('testdata source files ARE counted (codeintel excludes them, loc does not)', () => {
    assert.deepEqual(language('internal/loc/testdata/x.go'), { lang: 'go', category: 'code' });
  });

  test('build/ source files are counted too', () => {
    assert.deepEqual(language('build/tool.go'), { lang: 'go', category: 'code' });
  });

  test('Windows separators split segments the same way', () => {
    assert.deepEqual(language('C:\\programsx\\app\\main.go'), { lang: 'go', category: 'code' });
    assert.deepEqual(language('C:\\repo\\node_modules\\pkg\\index.js'), {
      lang: '',
      category: 'vendored',
    });
  });

  test('a basename row beats the extension row', () => {
    // CMakeLists.txt would otherwise resolve as .txt docs.
    assert.deepEqual(language('CMakeLists.txt'), { lang: '', category: 'code' });
    assert.deepEqual(language('go.mod'), { lang: 'text', category: 'config' });
  });

  test('an unrecognised extension is unknown', () => {
    assert.deepEqual(language('weird/thing.qqq'), { lang: '', category: 'unknown' });
  });

  test('a directory merely named dist does not make a file generated', () => {
    // The denylist checks every segment EXCEPT the last.
    assert.deepEqual(language('dist'), { lang: '', category: 'unknown' });
    assert.deepEqual(language('dist/app.js'), { lang: '', category: 'generated' });
  });
});

describe('splitLines', () => {
  test('empty text is no lines at all', () => {
    assert.deepEqual(splitLines(''), []);
  });

  test('a trailing newline does not add an empty line', () => {
    assert.deepEqual(splitLines('a\nb\n'), ['a', 'b']);
  });

  test('CRLF is tolerated', () => {
    assert.deepEqual(splitLines('a\r\nb\r\n'), ['a', 'b']);
  });

  test('a lone newline is one empty line', () => {
    assert.deepEqual(splitLines('\n'), ['']);
  });
});

describe('classifyLines', () => {
  test('a line comment is comment', () => {
    const got = classifyLines('go', '// just a comment\n');
    assert.deepEqual(got.classes, ['comment']);
    assert.equal(got.confidence, 'high');
  });

  test('a block comment spanning lines is comment throughout', () => {
    const got = classifyLines('go', '/* one\n   two */\nx := 1\n');
    assert.deepEqual(got.classes, ['comment', 'comment', 'code']);
    assert.equal(got.confidence, 'high');
  });

  test('a comment token inside a string is NOT a comment', () => {
    const got = classifyLines('go', 'u := "https://example.com"\n');
    assert.deepEqual(got.classes, ['code']);
    assert.equal(got.confidence, 'high');
  });

  test('a comment token inside a Python string is NOT a comment', () => {
    const got = classifyLines('python', 'u = "a # b"\n');
    assert.deepEqual(got.classes, ['code']);
  });

  test('a blank line is blank', () => {
    const got = classifyLines('go', 'x := 1\n\ny := 2\n');
    assert.deepEqual(got.classes, ['code', 'blank', 'code']);
  });

  test('code before a trailing comment wins (cloc convention)', () => {
    const got = classifyLines('go', 'x := 1 // set x\n');
    assert.deepEqual(got.classes, ['code']);
  });

  test('an unterminated block comment degrades to unknown at medium', () => {
    const got = classifyLines('go', 'x := 1\n/* opened\n   never closed\n');
    assert.deepEqual(got.classes, ['code', 'unknown', 'unknown']);
    assert.equal(got.confidence, 'medium');
  });

  test('a blank line inside an unresolved region is unknown, never blank', () => {
    const got = classifyLines('go', '/* opened\n\nstill open\n');
    assert.deepEqual(got.classes, ['unknown', 'unknown', 'unknown']);
    assert.equal(got.confidence, 'medium');
  });

  test('a close without an open retro-unknowns the preceding lines', () => {
    const got = classifyLines('go', 'x := 1\ny := 2\n*/\nz := 3\n');
    assert.deepEqual(got.classes, ['unknown', 'unknown', 'unknown', 'code']);
    assert.equal(got.confidence, 'medium');
  });

  test('a Python bare triple-quoted statement is a docstring comment', () => {
    const got = classifyLines('python', 'def f():\n    """Doc."""\n    return 1\n');
    assert.deepEqual(got.classes, ['code', 'comment', 'code']);
  });

  test('an unknown language yields blank plus unknown at low confidence', () => {
    const got = classifyLines('', 'anything\n\nelse\n');
    assert.deepEqual(got.classes, ['unknown', 'blank', 'unknown']);
    assert.equal(got.confidence, 'low');
  });

  test('empty text classifies as nothing at high confidence', () => {
    const got = classifyLines('go', '');
    assert.deepEqual(got.classes, []);
    assert.equal(got.confidence, 'high');
  });
});

describe('diffCount', () => {
  test('a one-line replacement is one modified_code', () => {
    const got = diffCount('a := 1\n', 'a := 2\n', 'go');
    assert.deepEqual(got.stats, stats({ modified_code: 1 }));
    assert.equal(got.confidence, 'high');
  });

  test('a 200-line reindent is 200 whitespace and 0 modified', () => {
    const oldLines: string[] = [];
    const newLines: string[] = [];
    for (let i = 0; i < 200; i++) {
      oldLines.push(`value${i} := compute(${i})`);
      newLines.push(`\tvalue${i} := compute(${i})`);
    }
    const got = diffCount(oldLines.join('\n') + '\n', newLines.join('\n') + '\n', 'go');
    assert.deepEqual(got.stats, stats({ whitespace: 200 }));
  });

  test('a pure append counts only added_code', () => {
    const got = diffCount('a := 1\n', 'a := 1\nb := 2\nc := 3\n', 'go');
    assert.deepEqual(got.stats, stats({ added_code: 2 }));
  });

  test('a pure delete counts only deleted_code', () => {
    const got = diffCount('a := 1\nb := 2\nc := 3\n', 'a := 1\n', 'go');
    assert.deepEqual(got.stats, stats({ deleted_code: 2 }));
  });

  test('a mass rename is N modified lines by design', () => {
    const oldLines: string[] = [];
    const newLines: string[] = [];
    for (let i = 0; i < 50; i++) {
      oldLines.push(`alphaValue${i} := compute(${i})`);
      newLines.push(`betaValue${i} := compute(${i})`);
    }
    const got = diffCount(oldLines.join('\n') + '\n', newLines.join('\n') + '\n', 'go');
    assert.deepEqual(got.stats, stats({ modified_code: 50 }));
  });

  test('a moved block is counted gross: delete plus add, not modified', () => {
    const lines: string[] = [];
    for (let i = 0; i < 20; i++) {
      lines.push(`statement${i}()`);
    }
    const moved = [...lines.slice(5), ...lines.slice(0, 5)];
    const got = diffCount(lines.join('\n') + '\n', moved.join('\n') + '\n', 'go');
    assert.deepEqual(got.stats, stats({ deleted_code: 5, added_code: 5 }));
  });

  test('a comment replaced by a comment has no modified column', () => {
    const got = diffCount('// one\n', '// two\n', 'go');
    assert.deepEqual(got.stats, stats({ deleted_comment: 1, added_comment: 1 }));
  });

  test('code replaced by a comment is a deleted code plus an added comment', () => {
    const got = diffCount('a := 1\n', '// a := 1\n', 'go');
    assert.deepEqual(got.stats, stats({ deleted_code: 1, added_comment: 1 }));
  });

  test('an identical text counts nothing', () => {
    const got = diffCount('a := 1\nb := 2\n', 'a := 1\nb := 2\n', 'go');
    assert.deepEqual(got.stats, zeroStats());
  });

  test('an unknown language degrades to unknown lines at low confidence', () => {
    const got = diffCount('one\n', 'two\n', '');
    assert.deepEqual(got.stats, stats({ unknown: 2 }));
    assert.equal(got.confidence, 'low');
  });

  test('over the fallback threshold the alignment is skipped and confidence is low', () => {
    const big = new Array(20_001).fill('a := 1').join('\n') + '\n';
    const got = diffCount(big, 'a := 1\n', 'go');
    assert.equal(got.confidence, 'low');
    // Degenerate tiling: one whole delete, one whole insert, paired by
    // position for min(deleted, inserted) of them.
    assert.equal(got.stats.modified_code, 1);
    assert.equal(got.stats.deleted_code, 20_000);
  });

  test('an unterminated fragment drops the whole result to medium', () => {
    const got = diffCount('a := 1\n', '/* open\n', 'go');
    assert.equal(got.confidence, 'medium');
  });
});

describe('classifierVersion', () => {
  test('is the version exported by the generated Go tables', () => {
    assert.equal(typeof classifierVersion, 'number');
    assert.ok(classifierVersion >= 1);
  });
});
