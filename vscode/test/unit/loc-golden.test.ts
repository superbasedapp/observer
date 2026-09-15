// The DRIFT GATE, editor side.
//
// internal/loc has a golden corpus: `<name>.txt` fixtures with a sibling
// `<name>.expected` holding one character per line, all on one line, in
// the alphabet
//
//   c = code   # = comment   _ = blank   ? = unknown
//
// The Go test asserts internal/loc reproduces those strings. This test
// asserts the TypeScript port in src/loc/classify.ts reproduces the SAME
// strings from the SAME files. Together they pin the two runtimes to one
// ruler: if either classifier changes behaviour, one of the two suites
// goes red.
//
// The fixtures are read IN PLACE from internal/loc/testdata/lang — they
// are not copied into vscode/, so there is nothing to keep in sync. A
// run outside the repo checkout (a consumer who installed only the VSIX)
// has no fixtures; the suite skips rather than failing, since it is a
// development gate, not a runtime assertion.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { classifyLines, type LineClass, type Confidence } from '../../src/loc/classify';

const CORPUS = path.join(__dirname, '..', '..', '..', 'internal', 'loc', 'testdata', 'lang');

/**
 * corpusLangs mirrors internal/loc/classify_test.go's map of the same
 * name: a fixture's stem is not always its language id, so the mapping
 * is explicit on both sides.
 */
const corpusLangs: Record<string, string> = {
  go: 'go',
  python: 'python',
  javascript: 'javascript',
  typescript: 'typescript',
  ruby: 'ruby',
  shell: 'shell',
  sql: 'sql',
  html: 'html',
  css: 'css',
  yaml: 'yaml',
  json: 'json',
  markdown: 'markdown',
  lua: 'lua',
  c: 'c',
  rust: 'rust',
  php: 'php',
  haskell: 'haskell',
};

const SYMBOL: Record<LineClass, string> = {
  code: 'c',
  comment: '#',
  blank: '_',
  unknown: '?',
};

function render(classes: LineClass[]): string {
  return classes.map((c) => SYMBOL[c]).join('');
}

const corpusPresent = fs.existsSync(CORPUS);

describe('Go golden corpus — language fixtures', { skip: corpusPresent ? false : 'corpus not present' }, () => {
  const stems = fs
    .readdirSync(CORPUS)
    .filter((name) => name.endsWith('.txt'))
    .map((name) => name.slice(0, -'.txt'.length))
    .sort();

  test('every fixture on disk is declared in corpusLangs', () => {
    assert.deepEqual(stems, Object.keys(corpusLangs).sort());
  });

  for (const stem of stems) {
    test(`${stem} classifies exactly as the Go corpus expects`, () => {
      const text = fs.readFileSync(path.join(CORPUS, `${stem}.txt`), 'utf8');
      const want = fs.readFileSync(path.join(CORPUS, `${stem}.expected`), 'utf8').trim();
      const got = classifyLines(corpusLangs[stem], text);
      assert.equal(render(got.classes), want, `${stem}: classification drifted from Go`);
      assert.equal(got.confidence, 'high' satisfies Confidence);
    });
  }
});

const FRAGMENTS = path.join(CORPUS, 'fragments');
const fragmentsPresent = corpusPresent && fs.existsSync(FRAGMENTS);

describe(
  'Go golden corpus — fragment boundary fixtures',
  { skip: fragmentsPresent ? false : 'corpus not present' },
  () => {
    const stems = fs
      .readdirSync(FRAGMENTS)
      .filter((name) => name.endsWith('.txt'))
      .map((name) => name.slice(0, -'.txt'.length))
      .sort();

    test('the boundary cases are all present', () => {
      assert.deepEqual(stems, ['crlf', 'mid-block-close', 'mid-block-open', 'mid-string']);
    });

    for (const stem of stems) {
      test(`${stem} classifies exactly as the Go corpus expects`, () => {
        const text = fs.readFileSync(path.join(FRAGMENTS, `${stem}.txt`), 'utf8');
        const want = fs.readFileSync(path.join(FRAGMENTS, `${stem}.expected`), 'utf8').trim();
        const lang = fs.readFileSync(path.join(FRAGMENTS, `${stem}.lang`), 'utf8').trim();
        const got = classifyLines(lang, text);
        assert.equal(render(got.classes), want, `${stem}: classification drifted from Go`);
        // Every fragment fixture except `crlf` must degrade: the Go
        // suite asserts the same thing.
        assert.equal(got.confidence, stem === 'crlf' ? 'high' : 'medium');
      });
    }
  },
);
