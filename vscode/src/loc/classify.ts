// TypeScript mirror of the Go line classifier in internal/loc.
//
// WHY THIS EXISTS. The daemon counts the AI's lines; this extension
// counts the human's. If the two halves use different rulers the "AI vs
// human" comparison is meaningless, so both sides read the SAME table
// set — `classifier-tables.json`, generated from the Go tables by
// `go test ./internal/loc/ -run TestClassifierTablesJSONIsCurrent
// -update`. That file is GENERATED: never hand-edit it, a Go drift test
// fails if you do.
//
// The export carries the DATA, not the algorithm. Everything below is a
// deliberate line-for-line port of:
//
//   internal/loc/language.go  → language()
//   internal/loc/classify.go  → classifyLines() / scanLine()
//   internal/loc/diff.go      → splitLines() / diff()
//   internal/loc/count.go     → count()
//
// A rule change on the Go side is a code change here too. The golden
// mirror test (test/unit/loc-golden.test.ts) reads the Go corpus under
// internal/loc/testdata/lang and asserts this port reproduces it, so a
// one-sided change is loud at test time rather than silent in the
// numbers.

import tablesJson from './classifier-tables.json';

/** Coarse bucket a path falls into (internal/loc.Category). */
export type Category = 'code' | 'docs' | 'config' | 'generated' | 'vendored' | 'unknown';

/** What one line of a fragment was classified as (internal/loc.LineClass). */
export type LineClass = 'code' | 'comment' | 'blank' | 'unknown';

/** How much of a result rests on a guess (internal/loc.Confidence). */
export type Confidence = 'high' | 'medium' | 'low';

/**
 * Stats is the bucket set for one measured change. Every field is a LINE
 * COUNT; nothing here is bytes and nothing here is content. Field names
 * are the wire names (they match the Go struct's JSON tags).
 */
export interface Stats {
  added_code: number;
  modified_code: number;
  deleted_code: number;
  added_comment: number;
  deleted_comment: number;
  whitespace: number;
  blank: number;
  unknown: number;
}

/** zeroStats returns a fresh all-zero Stats. */
export function zeroStats(): Stats {
  return {
    added_code: 0,
    modified_code: 0,
    deleted_code: 0,
    added_comment: 0,
    deleted_comment: 0,
    whitespace: 0,
    blank: 0,
    unknown: 0,
  };
}

/** statsTotal is the number of line slots the change touched. */
export function statsTotal(s: Stats): number {
  return (
    s.added_code +
    s.modified_code +
    s.deleted_code +
    s.added_comment +
    s.deleted_comment +
    s.whitespace +
    s.blank +
    s.unknown
  );
}

// ---------------------------------------------------------------------
// Table shapes (mirrors internal/loc.ExportedTables)
// ---------------------------------------------------------------------

interface ExportedLangEntry {
  lang: string;
  category: string;
}

interface ExportedBlockPair {
  open: string;
  close: string;
  anchored?: boolean;
  detect_stray?: boolean;
}

interface ExportedStringDelim {
  open: string;
  close: string;
  multiline?: boolean;
  escape?: boolean;
  docstring?: boolean;
}

interface ExportedLangTokens {
  line_comments?: string[];
  anchored_line?: string[];
  blocks?: ExportedBlockPair[];
  strings?: ExportedStringDelim[];
  heredoc?: string;
}

interface ExportedTables {
  tables_version: number;
  classifier_version: number;
  extensions: Record<string, ExportedLangEntry>;
  basenames: Record<string, ExportedLangEntry>;
  vendored_segments: string[];
  vendored_segments_exact: string[];
  generated_segments: string[];
  generated_suffixes: string[];
  lockfile_basenames: string[];
  binary_extensions: string[];
  lex: Record<string, ExportedLangTokens>;
}

const tables = tablesJson as unknown as ExportedTables;

/** classifierVersion is loc.Version — stamp it on every count. */
export const classifierVersion: number = tables.classifier_version;

/** tablesVersion is the exported SHAPE version (loc.TablesVersion). */
export const tablesVersion: number = tables.tables_version;

// ---------------------------------------------------------------------
// Prepared lexer tables
// ---------------------------------------------------------------------

interface BlockPair {
  open: string;
  close: string;
  anchored: boolean;
  detectStray: boolean;
}

interface StringDelim {
  open: string;
  close: string;
  multiline: boolean;
  escape: boolean;
  docstring: boolean;
}

interface LangTokens {
  lineComments: string[];
  anchoredLine: string[];
  blocks: BlockPair[];
  strings: StringDelim[];
  heredoc: '' | 'shell' | 'php';
}

/**
 * byLengthDesc is the stable longest-first ordering internal/loc's
 * package init() applies, so a longer token is always tried before a
 * prefix of itself: `"""` before `"`, `--[[` before `--`, `{/*` before
 * `/*`. Array.prototype.sort is stable in ES2019+, matching Go's
 * sort.SliceStable.
 */
function byLengthDesc<T>(items: T[], key: (item: T) => string): T[] {
  return items
    .map((item, index) => ({ item, index }))
    .sort((a, b) => {
      const d = key(b.item).length - key(a.item).length;
      return d !== 0 ? d : a.index - b.index;
    })
    .map((entry) => entry.item);
}

function prepare(row: ExportedLangTokens): LangTokens {
  const heredoc = row.heredoc === 'shell' || row.heredoc === 'php' ? row.heredoc : '';
  return {
    lineComments: byLengthDesc(row.line_comments ?? [], (t) => t),
    anchoredLine: byLengthDesc(row.anchored_line ?? [], (t) => t),
    blocks: byLengthDesc(row.blocks ?? [], (b) => b.open).map((b) => ({
      open: b.open,
      close: b.close,
      anchored: b.anchored === true,
      detectStray: b.detect_stray === true,
    })),
    strings: byLengthDesc(row.strings ?? [], (s) => s.open).map((s) => ({
      open: s.open,
      close: s.close,
      multiline: s.multiline === true,
      escape: s.escape === true,
      docstring: s.docstring === true,
    })),
    heredoc,
  };
}

const lexTable: Map<string, LangTokens> = new Map(
  Object.entries(tables.lex).map(([lang, row]) => [lang, prepare(row)]),
);

const vendoredSegments = new Set(tables.vendored_segments);
const vendoredSegmentsExact = new Set(tables.vendored_segments_exact);
const generatedSegments = new Set(tables.generated_segments);
const lockfileBasenames = new Set(tables.lockfile_basenames);
const binaryExtensions = new Set(tables.binary_extensions);

// ---------------------------------------------------------------------
// language() — port of internal/loc/language.go
// ---------------------------------------------------------------------

/**
 * language reports the normalized language and coarse category for a
 * path, exactly as internal/loc.Language does.
 *
 * Both `/` and `\` split segments: the live corpus mixes POSIX targets
 * with Windows targets from cross-mount sessions.
 *
 * Resolution order — the denylists run BEFORE the language tables, so a
 * vendored or generated file never reports a language it would then be
 * lexed with:
 *
 *  1. vendored path segments   → (unknown, vendored)
 *  2. generated path segments  → (unknown, generated)
 *  3. lockfile basenames       → (unknown, generated)
 *  4. generated basename rules → (unknown, generated)
 *  5. binary extensions        → (unknown, generated)
 *  6. basenames table (whole lowercased basename)
 *  7. extensions table (lowercased extension)
 *  8. otherwise                → (unknown, unknown)
 *
 * Step 6 runs before step 7 because several basename rows carry an
 * extension that would otherwise win and be wrong (`CMakeLists.txt` is
 * not documentation; `go.mod` is not a `.mod` file).
 *
 * Note this table is loc's OWN and is deliberately NOT codeintel's:
 * `testdata/` and `build/` source files DO count here.
 */
export function language(path: string): { lang: string; category: Category } {
  const segments = splitSegments(path);
  if (segments.length === 0) {
    return { lang: '', category: 'unknown' };
  }
  const base = segments[segments.length - 1].toLowerCase();
  const ext = extensionOf(base);

  const denied = denylisted(segments, base, ext);
  if (denied) {
    return { lang: '', category: denied };
  }
  const byBase = tables.basenames[base];
  if (byBase) {
    return { lang: byBase.lang, category: byBase.category as Category };
  }
  if (ext !== '') {
    const byExt = tables.extensions[ext];
    if (byExt) {
      return { lang: byExt.lang, category: byExt.category as Category };
    }
  }
  return { lang: '', category: 'unknown' };
}

/** splitSegments splits on both separators, dropping empty segments. */
function splitSegments(path: string): string[] {
  return path.split(/[/\\]/).filter((s) => s !== '');
}

/**
 * extensionOf returns the lowercased extension of an already-lowercased
 * basename, without the dot. A dotfile with no further dot (`.bashrc`)
 * has no extension — its whole name is the lookup key.
 */
function extensionOf(base: string): string {
  const idx = base.lastIndexOf('.');
  if (idx <= 0 || idx === base.length - 1) {
    return '';
  }
  return base.slice(idx + 1);
}

/**
 * denylisted applies the five denylist rules in order and returns the
 * Category to report, or undefined when the path is not excluded.
 *
 * Directory rules examine every segment EXCEPT the last, so a source
 * file merely named `dist` is not mistaken for a build directory.
 */
function denylisted(segments: string[], base: string, ext: string): Category | undefined {
  for (let i = 0; i < segments.length - 1; i++) {
    const seg = segments[i];
    if (vendoredSegmentsExact.has(seg)) {
      return 'vendored';
    }
    if (vendoredSegments.has(seg.toLowerCase())) {
      return 'vendored';
    }
  }
  for (let i = 0; i < segments.length - 1; i++) {
    if (generatedSegments.has(segments[i].toLowerCase())) {
      return 'generated';
    }
  }
  if (lockfileBasenames.has(base)) {
    return 'generated';
  }
  if (generatedBasename(base, ext)) {
    return 'generated';
  }
  if (ext !== '' && binaryExtensions.has(ext)) {
    return 'generated';
  }
  return undefined;
}

/**
 * generatedBasename applies the basename/suffix generated rules. The
 * stem rules (`*_generated.*`, `*.generated.*`, `zz_generated*`) match on
 * the name with its extension removed, so they fire for any language.
 * `zz_generated` is a PREFIX rule (controller-gen writes
 * `zz_generated.deepcopy.go`); the others are suffixes.
 *
 * Deliberately ABSENT (same as Go): `*_string.go` and `*.d.ts`.
 */
function generatedBasename(base: string, ext: string): boolean {
  for (const suffix of tables.generated_suffixes) {
    if (base.endsWith(suffix)) {
      return true;
    }
  }
  const stem = ext !== '' ? base.slice(0, base.length - ext.length - 1) : base;
  return (
    stem.endsWith('_generated') || stem.endsWith('.generated') || stem.startsWith('zz_generated')
  );
}

/**
 * generatedHeaderScanLines and GENERATED_HEADER_MARKERS mirror
 * internal/loc/language.go: the canonical machine-generated banner
 * (`// Code generated … DO NOT EDIT.`) in a file's first few lines makes
 * it generated regardless of its name.
 *
 * The comment leader is deliberately not matched, so the rule holds for
 * `//`, `#` and `--` languages alike.
 */
const GENERATED_HEADER_SCAN_LINES = 3;
const GENERATED_HEADER_MARKERS = ['Code generated ', 'DO NOT EDIT.'] as const;

/**
 * hasGeneratedHeader reports whether the first few lines of a file carry
 * the machine-generated banner. The caller passes the lines it already
 * has, so nothing here reads a document.
 */
export function hasGeneratedHeader(firstLines: readonly string[]): boolean {
  const limit = Math.min(firstLines.length, GENERATED_HEADER_SCAN_LINES);
  for (let i = 0; i < limit; i++) {
    const line = firstLines[i];
    if (line.includes(GENERATED_HEADER_MARKERS[0]) && line.includes(GENERATED_HEADER_MARKERS[1])) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------
// classifyLines() — port of internal/loc/classify.go
// ---------------------------------------------------------------------

interface LexState {
  blockIdx: number;
  blockLine: number;
  strIdx: number;
  strLine: number;
  strDoc: boolean;
  inHeredoc: boolean;
  heredocTerm: string;
  heredocIndent: boolean;
}

/**
 * classifyLines classifies each line of a FRAGMENT as code, comment,
 * blank or unknown, and grades the result.
 *
 * The input is a fragment, not a file: it may begin in the middle of a
 * block comment and end in the middle of a string. Those cases degrade
 * to 'unknown' and a lower confidence rather than guessing, because
 * guessing "code" is what inflates a headline lines-of-code number.
 *
 * Line splitting: split on "\n" after trimming ONE trailing "\n", so a
 * fragment ending in a newline does not contribute a trailing empty
 * line. A trailing "\r" is stripped per line before classification. An
 * empty text returns ([], 'high').
 *
 * Classification rules, in the order they resolve:
 *
 *  - A line carried entirely inside a block comment is 'comment',
 *    blank or not.
 *  - A line whose first non-whitespace token opens a line comment, with
 *    no code before it, is 'comment'.
 *  - A line whose only content is a same-line block comment is
 *    'comment'.
 *  - Code wins over comment on a mixed line (cloc's convention).
 *  - A line whose trimmed text is empty, in no carried state, is
 *    'blank'.
 *  - Everything else is 'code'.
 *
 * Stated conventions: a Python bare triple-quoted string statement is
 * 'comment' (cloc's docstring convention); heredoc bodies are 'code';
 * `#include` and `#pragma` are 'code' in the C family.
 *
 * Fragment boundary rules: an unterminated block comment or multi-line
 * string makes every line from its opener to the end 'unknown' at
 * 'medium'; a block-comment CLOSE with no matching open retroactively
 * makes every line through it 'unknown' at 'medium'; a blank line
 * inside an unresolved region is 'unknown', never 'blank'; a language
 * with no token table yields 'blank' for blanks and 'unknown' for
 * everything else at 'low'.
 */
export function classifyLines(
  lang: string,
  text: string,
): { classes: LineClass[]; confidence: Confidence } {
  if (text === '') {
    return { classes: [], confidence: 'high' };
  }
  const lines = trimSuffix(text, '\n').split('\n');
  const out: LineClass[] = new Array<LineClass>(lines.length).fill('unknown');

  const tok = lexTable.get(lang);
  if (!tok) {
    for (let i = 0; i < lines.length; i++) {
      out[i] = trimSuffix(lines[i], '\r').trim() === '' ? 'blank' : 'unknown';
    }
    return { classes: out, confidence: 'low' };
  }

  const st: LexState = {
    blockIdx: -1,
    blockLine: 0,
    strIdx: -1,
    strLine: 0,
    strDoc: false,
    inHeredoc: false,
    heredocTerm: '',
    heredocIndent: false,
  };
  let retroThrough = -1;
  for (let i = 0; i < lines.length; i++) {
    const line = trimSuffix(lines[i], '\r');
    const res = scanLine(line, tok, st, i);
    if (res.stray && i > retroThrough) {
      retroThrough = i;
    }
    if (res.code) {
      out[i] = 'code';
    } else if (res.comment) {
      out[i] = 'comment';
    } else if (line.trim() === '') {
      out[i] = 'blank';
    } else {
      out[i] = 'code';
    }
  }

  let confidence: Confidence = 'high';
  if (st.blockIdx >= 0) {
    markUnknown(out, st.blockLine, out.length - 1);
    confidence = 'medium';
  }
  if (st.strIdx >= 0) {
    markUnknown(out, st.strLine, out.length - 1);
    confidence = 'medium';
  }
  if (retroThrough >= 0) {
    markUnknown(out, 0, retroThrough);
    confidence = 'medium';
  }
  return { classes: out, confidence };
}

/** trimSuffix removes ONE trailing occurrence of suffix. */
function trimSuffix(s: string, suffix: string): string {
  return s.endsWith(suffix) ? s.slice(0, s.length - suffix.length) : s;
}

/** markUnknown overwrites out[from..to] (inclusive) with 'unknown'. */
function markUnknown(out: LineClass[], from: number, to: number): void {
  const start = from < 0 ? 0 : from;
  for (let i = start; i <= to && i < out.length; i++) {
    out[i] = 'unknown';
  }
}

interface ScanResult {
  code: boolean;
  comment: boolean;
  stray: boolean;
}

/**
 * scanLine walks one line character by character, updating the carried
 * lexer state. Character-by-character scanning is what shields a `#`
 * inside a Python string, a `//` inside a JavaScript URL and a `--`
 * inside a SQL literal from being read as a comment.
 */
function scanLine(line: string, tok: LangTokens, st: LexState, lineNo: number): ScanResult {
  let code = false;
  let comment = false;
  let stray = false;

  if (st.inHeredoc) {
    let body = line;
    if (st.heredocIndent) {
      body = body.replace(/^[ \t]+/, '');
    }
    body = body.replace(/[ \t]+$/, '');
    if (tok.heredoc === 'php') {
      body = body.replace(/[;,]+$/, '');
    }
    if (body === st.heredocTerm) {
      st.inHeredoc = false;
    }
    return { code: true, comment: false, stray: false };
  }

  // An empty line never enters the scan loop below, so the carried
  // state has to be applied here: a blank line inside a block comment
  // is comment, and one inside a multi-line string belongs to it.
  if (line.length === 0) {
    if (st.blockIdx >= 0) {
      return { code: false, comment: true, stray: false };
    }
    if (st.strIdx >= 0 && st.strDoc) {
      return { code: false, comment: true, stray: false };
    }
    if (st.strIdx >= 0) {
      return { code: true, comment: false, stray: false };
    }
    return { code: false, comment: false, stray: false };
  }

  let first = -1;
  for (let k = 0; k < line.length; k++) {
    if (line[k] !== ' ' && line[k] !== '\t') {
      first = k;
      break;
    }
  }

  let pending = false;
  let pendingTerm = '';
  let pendingIndent = false;

  let i = 0;
  while (i < line.length) {
    if (st.blockIdx >= 0) {
      const bp = tok.blocks[st.blockIdx];
      comment = true;
      const j = indexClose(line, i, bp, first);
      if (j < 0) {
        break;
      }
      st.blockIdx = -1;
      i = j + bp.close.length;
      continue;
    }
    if (st.strIdx >= 0) {
      const sd = tok.strings[st.strIdx];
      if (st.strDoc) {
        comment = true;
      } else {
        code = true;
      }
      const found = scanForClose(line, i, sd);
      if (found < 0) {
        break;
      }
      st.strIdx = -1;
      st.strDoc = false;
      i = found + sd.close.length;
      continue;
    }

    if (line[i] === ' ' || line[i] === '\t') {
      i++;
      continue;
    }
    let handled = false;

    if (i === first) {
      for (let k = 0; k < tok.blocks.length; k++) {
        const bp = tok.blocks[k];
        if (!bp.anchored) {
          continue;
        }
        if (bp.detectStray && line.startsWith(bp.close, i)) {
          stray = true;
          comment = true;
          handled = true;
          break;
        }
        if (line.startsWith(bp.open, i)) {
          st.blockIdx = k;
          st.blockLine = lineNo;
          comment = true;
          handled = true;
          break;
        }
      }
      if (handled) {
        break;
      }
      for (const tk of tok.anchoredLine) {
        if (
          line.length - i >= tk.length &&
          line.slice(i, i + tk.length).toLowerCase() === tk.toLowerCase()
        ) {
          comment = true;
          handled = true;
          break;
        }
      }
      if (handled) {
        break;
      }
    }

    for (let k = 0; k < tok.blocks.length; k++) {
      const bp = tok.blocks[k];
      if (bp.anchored || !line.startsWith(bp.open, i)) {
        continue;
      }
      comment = true;
      handled = true;
      const j = indexClose(line, i + bp.open.length, bp, first);
      if (j < 0) {
        st.blockIdx = k;
        st.blockLine = lineNo;
        i = line.length;
      } else {
        i = j + bp.close.length;
      }
      break;
    }
    if (handled) {
      continue;
    }

    for (const bp of tok.blocks) {
      if (bp.anchored || !bp.detectStray || !line.startsWith(bp.close, i)) {
        continue;
      }
      stray = true;
      comment = true;
      handled = true;
      i += bp.close.length;
      break;
    }
    if (handled) {
      continue;
    }

    for (const tk of tok.lineComments) {
      if (line.startsWith(tk, i)) {
        comment = true;
        handled = true;
        break;
      }
    }
    if (handled) {
      break;
    }

    if (tok.heredoc !== '' && !pending && line.startsWith('<<', i)) {
      const hd = parseHeredoc(line, i, tok.heredoc);
      if (hd) {
        pending = true;
        pendingTerm = hd.term;
        pendingIndent = hd.indent;
        code = true;
        i = hd.next;
        continue;
      }
    }

    for (let k = 0; k < tok.strings.length; k++) {
      const sd = tok.strings[k];
      if (!line.startsWith(sd.open, i)) {
        continue;
      }
      handled = true;
      const isDoc = sd.docstring && !code;
      if (isDoc) {
        comment = true;
      } else {
        code = true;
      }
      const found = scanForClose(line, i + sd.open.length, sd);
      if (found >= 0) {
        i = found + sd.close.length;
      } else if (sd.multiline) {
        st.strIdx = k;
        st.strLine = lineNo;
        st.strDoc = isDoc;
        i = line.length;
      } else {
        // An unterminated single-line literal: the rest of the line is
        // its content, and the literal ends at the newline rather than
        // leaking into the next line.
        code = true;
        i = line.length;
      }
      break;
    }
    if (handled) {
      continue;
    }

    code = true;
    i++;
  }

  if (pending) {
    st.inHeredoc = true;
    st.heredocTerm = pendingTerm;
    st.heredocIndent = pendingIndent;
  }
  return { code, comment, stray };
}

/**
 * indexClose finds a block pair's close token at or after `from`,
 * honouring the pair's anchoring. Returns -1 when absent.
 */
function indexClose(line: string, from: number, bp: BlockPair, first: number): number {
  if (from > line.length) {
    return -1;
  }
  if (bp.anchored) {
    if (first >= from && line.startsWith(bp.close, first)) {
      return first;
    }
    return -1;
  }
  return line.indexOf(bp.close, from);
}

/**
 * scanForClose finds a string literal's close delimiter at or after
 * `from`, skipping escaped characters when the delimiter supports
 * escaping. Returns -1 when absent.
 */
function scanForClose(line: string, from: number, sd: StringDelim): number {
  for (let j = from; j < line.length; j++) {
    if (sd.escape && line[j] === '\\') {
      j++;
      continue;
    }
    if (line.startsWith(sd.close, j)) {
      return j;
    }
  }
  return -1;
}

/**
 * parseHeredoc recognises a heredoc introducer at position i (which
 * must already start with "<<") and returns its terminator word,
 * whether the terminator may be indented, and the index just past the
 * introducer. Returns undefined when this is not a heredoc.
 *
 * An UNQUOTED terminator must follow with no intervening whitespace and
 * must be all-uppercase (`[A-Z_][A-Z0-9_]*`). That restriction is what
 * stops Ruby's append operator (`arr << item`) and shell arithmetic
 * (`$((1 << n))`) from being read as heredocs; the cost is that a
 * lowercase `cat << eof` is missed, which degrades to ordinary per-line
 * classification rather than to a wrong answer.
 */
function parseHeredoc(
  line: string,
  i: number,
  kind: 'shell' | 'php',
): { term: string; indent: boolean; next: number } | undefined {
  let j = i + 2;
  let indent = false;
  if (kind === 'php') {
    if (j >= line.length || line[j] !== '<') {
      return undefined;
    }
    j++;
  } else if (j < line.length && line[j] === '<') {
    return undefined; // "<<<" is a here-string, not a heredoc
  }
  if (j < line.length && (line[j] === '-' || line[j] === '~')) {
    indent = true;
    j++;
  }
  let spaced = false;
  while (j < line.length && (line[j] === ' ' || line[j] === '\t')) {
    spaced = true;
    j++;
  }
  if (j >= line.length) {
    return undefined;
  }
  const q = line[j];
  if (q === "'" || q === '"') {
    let k = j + 1;
    while (k < line.length && line[k] !== q) {
      k++;
    }
    if (k >= line.length || k === j + 1) {
      return undefined;
    }
    return { term: line.slice(j + 1, k), indent, next: k + 1 };
  }
  let k = j;
  while (k < line.length && isWordChar(line[k])) {
    k++;
  }
  const term = line.slice(j, k);
  if (term === '' || spaced || !isUpperWord(term)) {
    return undefined;
  }
  return { term, indent, next: k };
}

/** isWordChar reports whether c may appear in a heredoc terminator. */
function isWordChar(c: string): boolean {
  return c === '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/** isUpperWord reports whether w matches `[A-Z_][A-Z0-9_]*`. */
function isUpperWord(w: string): boolean {
  if (w[0] !== '_' && (w[0] < 'A' || w[0] > 'Z')) {
    return false;
  }
  for (const c of w) {
    if (c === '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')) {
      continue;
    }
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------
// diff — port of internal/loc/diff.go
// ---------------------------------------------------------------------

/**
 * DIFF_FALLBACK_LINES is the line count above which the diff degrades to
 * plain counting (loc.DiffFallbackLines).
 */
export const DIFF_FALLBACK_LINES = 20000;

/**
 * MYERS_MAX_EDIT_DISTANCE bounds the greedy Myers search inside one
 * alignment problem (loc.myersMaxEditDistance). Above it the sub-problem
 * degrades to "delete everything, insert everything", which is still a
 * correct tiling.
 */
const MYERS_MAX_EDIT_DISTANCE = 1000;

/**
 * splitLines splits text into lines, tolerating CRLF and not emitting a
 * trailing empty line for a text ending in a newline. splitLines('')
 * returns [], so an absent image is an empty sequence rather than a
 * one-blank-line sequence. A lone "\n" is one empty line.
 */
export function splitLines(text: string): string[] {
  if (text === '') {
    return [];
  }
  return trimSuffix(text, '\n')
    .split('\n')
    .map((line) => trimSuffix(line, '\r'));
}

/**
 * normalizeWS collapses every run of whitespace to a single space and
 * trims the ends. Two lines with the same normalization differ only in
 * indentation or padding — the whitespace bucket, never modified.
 */
function normalizeWS(line: string): string {
  const trimmed = line.trim();
  return trimmed === '' ? '' : trimmed.split(/\s+/).join(' ');
}

/** diffDegraded reports whether diff falls back to plain counting. */
export function diffDegraded(oldLines: string[], newLines: string[]): boolean {
  return oldLines.length > DIFF_FALLBACK_LINES || newLines.length > DIFF_FALLBACK_LINES;
}

type Op = 'equal' | 'delete' | 'insert';

interface Hunk {
  op: Op;
  oldStart: number;
  oldEnd: number;
  newStart: number;
  newEnd: number;
}

interface Pair {
  oi: number;
  ni: number;
}

/**
 * diff aligns two line sequences in two passes and returns the hunks in
 * order (port of loc.Diff).
 *
 * Pass 1 runs Myers over the WHITESPACE-NORMALIZED lines; every matched
 * pair becomes an equal hunk and count() later decides from the RAW text
 * whether it is untouched or a whitespace-only change. This is what
 * makes a 200-line reindent read as 200 whitespace, 0 modified.
 *
 * Pass 2 re-runs Myers over the RAW lines of each maximal residue region
 * and splices the refined sub-alignment back in.
 */
function diff(oldLines: string[], newLines: string[]): Hunk[] {
  if (diffDegraded(oldLines, newLines)) {
    return degenerateHunks(oldLines.length, newLines.length);
  }
  if (oldLines.length === 0 && newLines.length === 0) {
    return [];
  }
  const oldNorm = oldLines.map(normalizeWS);
  const newNorm = newLines.map(normalizeWS);
  const pairs = lcsPairs(oldNorm, newNorm);
  const hunks = hunksFromPairs(pairs, 0, oldLines.length, 0, newLines.length);
  return refineResidues(hunks, oldLines, newLines);
}

/** degenerateHunks is the alignment used when no search is run. */
function degenerateHunks(oldLen: number, newLen: number): Hunk[] {
  const hunks: Hunk[] = [];
  if (oldLen > 0) {
    hunks.push({ op: 'delete', oldStart: 0, oldEnd: oldLen, newStart: 0, newEnd: 0 });
  }
  if (newLen > 0) {
    hunks.push({ op: 'insert', oldStart: oldLen, oldEnd: oldLen, newStart: 0, newEnd: newLen });
  }
  return hunks;
}

/**
 * lcsPairs returns the matched (old, new) index pairs of a longest
 * common subsequence, ascending and strictly increasing on both sides.
 * The common prefix and suffix are trimmed first (both are always part
 * of some optimal alignment).
 */
function lcsPairs(a: string[], b: string[]): Pair[] {
  const n = a.length;
  const m = b.length;
  if (n === 0 || m === 0) {
    return [];
  }

  let prefix = 0;
  while (prefix < n && prefix < m && a[prefix] === b[prefix]) {
    prefix++;
  }
  let suffix = 0;
  while (suffix < n - prefix && suffix < m - prefix && a[n - 1 - suffix] === b[m - 1 - suffix]) {
    suffix++;
  }

  const pairs: Pair[] = [];
  for (let i = 0; i < prefix; i++) {
    pairs.push({ oi: i, ni: i });
  }
  for (const p of middlePairs(a.slice(prefix, n - suffix), b.slice(prefix, m - suffix))) {
    pairs.push({ oi: p.oi + prefix, ni: p.ni + prefix });
  }
  for (let i = 0; i < suffix; i++) {
    pairs.push({ oi: n - suffix + i, ni: m - suffix + i });
  }
  return pairs;
}

/**
 * middlePairs aligns two sequences sharing no common prefix or suffix.
 * It first drops every line whose text occurs on ONE side only — such a
 * line can never appear in a common subsequence — which collapses the
 * classic pathological case to zero work.
 */
function middlePairs(a: string[], b: string[]): Pair[] {
  if (a.length === 0 || b.length === 0) {
    return [];
  }
  const inA = new Set(a);
  const inB = new Set(b);

  const aIdx: number[] = [];
  const aVal: string[] = [];
  for (let i = 0; i < a.length; i++) {
    if (inB.has(a[i])) {
      aIdx.push(i);
      aVal.push(a[i]);
    }
  }
  const bIdx: number[] = [];
  const bVal: string[] = [];
  for (let i = 0; i < b.length; i++) {
    if (inA.has(b[i])) {
      bIdx.push(i);
      bVal.push(b[i]);
    }
  }

  const matched = myersPairs(aVal, bVal, MYERS_MAX_EDIT_DISTANCE);
  if (!matched) {
    return [];
  }
  return matched.map((p) => ({ oi: aIdx[p.oi], ni: bIdx[p.ni] }));
}

/**
 * myersPairs runs the greedy O(ND) Myers shortest-edit-script and
 * returns the matched index pairs, or undefined when the search
 * exceeded maxD edits. It is iterative (never recursive) and keeps one
 * V-band per edit-distance step, so a large file cannot blow the stack
 * and memory stays bounded.
 */
function myersPairs(a: string[], b: string[], maxD: number): Pair[] | undefined {
  const n = a.length;
  const m = b.length;
  if (n === 0 || m === 0) {
    return [];
  }

  const limit = Math.min(n + m, maxD);
  const offset = limit + 1;
  const v = new Array<number>(2 * limit + 3).fill(0);
  const trace: number[][] = [];

  for (let d = 0; d <= limit; d++) {
    // Snapshot the band backtracking will read for this round.
    trace.push(v.slice(offset - d - 1, offset + d + 2));

    for (let k = -d; k <= d; k += 2) {
      let x: number;
      if (k === -d || (k !== d && v[offset + k - 1] < v[offset + k + 1])) {
        x = v[offset + k + 1];
      } else {
        x = v[offset + k - 1] + 1;
      }
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x++;
        y++;
      }
      v[offset + k] = x;
      if (x >= n && y >= m) {
        return backtrackPairs(trace, d, n, m);
      }
    }
  }
  return undefined;
}

/**
 * backtrackPairs walks the recorded V-bands backwards from the script
 * endpoint (n, m) and collects the diagonal (matched) steps.
 * trace[dd] is the band as it stood BEFORE round dd ran.
 */
function backtrackPairs(trace: number[][], d: number, n: number, m: number): Pair[] {
  const pairs: Pair[] = [];
  let x = n;
  let y = m;
  for (let dd = d; dd >= 0; dd--) {
    const band = trace[dd];
    const k = x - y;
    let prevK: number;
    if (k === -dd || (k !== dd && band[k + dd] < band[k + dd + 2])) {
      prevK = k + 1;
    } else {
      prevK = k - 1;
    }
    const prevX = band[prevK + dd + 1];
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      x--;
      y--;
      pairs.push({ oi: x, ni: y });
    }
    if (dd > 0) {
      x = prevX;
      y = prevY;
    }
  }
  pairs.reverse();
  return pairs;
}

/**
 * hunksFromPairs turns an ascending list of matched index pairs into the
 * hunk tiling of the two sequences. oldOff/newOff are added to every
 * index so a refined residue can be spliced back into whole-file
 * coordinates.
 */
function hunksFromPairs(
  pairs: Pair[],
  oldOff: number,
  oldLen: number,
  newOff: number,
  newLen: number,
): Hunk[] {
  const hunks: Hunk[] = [];
  let oi = 0;
  let ni = 0;

  let i = 0;
  while (i < pairs.length) {
    const p = pairs[i];
    if (p.oi > oi) {
      hunks.push({
        op: 'delete',
        oldStart: oldOff + oi,
        oldEnd: oldOff + p.oi,
        newStart: newOff + ni,
        newEnd: newOff + ni,
      });
    }
    if (p.ni > ni) {
      hunks.push({
        op: 'insert',
        oldStart: oldOff + p.oi,
        oldEnd: oldOff + p.oi,
        newStart: newOff + ni,
        newEnd: newOff + p.ni,
      });
    }
    let j = i;
    while (j + 1 < pairs.length && pairs[j + 1].oi === pairs[j].oi + 1 && pairs[j + 1].ni === pairs[j].ni + 1) {
      j++;
    }
    hunks.push({
      op: 'equal',
      oldStart: oldOff + p.oi,
      oldEnd: oldOff + pairs[j].oi + 1,
      newStart: newOff + p.ni,
      newEnd: newOff + pairs[j].ni + 1,
    });
    oi = pairs[j].oi + 1;
    ni = pairs[j].ni + 1;
    i = j + 1;
  }

  if (oi < oldLen) {
    hunks.push({
      op: 'delete',
      oldStart: oldOff + oi,
      oldEnd: oldOff + oldLen,
      newStart: newOff + ni,
      newEnd: newOff + ni,
    });
  }
  if (ni < newLen) {
    hunks.push({
      op: 'insert',
      oldStart: oldOff + oldLen,
      oldEnd: oldOff + oldLen,
      newStart: newOff + ni,
      newEnd: newOff + newLen,
    });
  }
  return hunks;
}

/**
 * refineResidues is pass 2: for every maximal run of adjacent
 * delete/insert hunks it re-aligns the region over the RAW lines and
 * splices the result back in.
 */
function refineResidues(hunks: Hunk[], oldLines: string[], newLines: string[]): Hunk[] {
  if (hunks.length === 0) {
    return hunks;
  }
  const out: Hunk[] = [];
  let i = 0;
  while (i < hunks.length) {
    if (hunks[i].op === 'equal') {
      out.push(hunks[i]);
      i++;
      continue;
    }

    let j = i;
    let oldStart = hunks[i].oldStart;
    let oldEnd = hunks[i].oldEnd;
    let newStart = hunks[i].newStart;
    let newEnd = hunks[i].newEnd;
    while (j < hunks.length && hunks[j].op !== 'equal') {
      oldStart = Math.min(oldStart, hunks[j].oldStart);
      oldEnd = Math.max(oldEnd, hunks[j].oldEnd);
      newStart = Math.min(newStart, hunks[j].newStart);
      newEnd = Math.max(newEnd, hunks[j].newEnd);
      j++;
    }

    if (oldEnd > oldStart && newEnd > newStart) {
      const pairs = lcsPairs(oldLines.slice(oldStart, oldEnd), newLines.slice(newStart, newEnd));
      if (pairs.length > 0) {
        out.push(
          ...hunksFromPairs(pairs, oldStart, oldEnd - oldStart, newStart, newEnd - newStart),
        );
        i = j;
        continue;
      }
    }
    out.push(...hunks.slice(i, j));
    i = j;
  }
  return out;
}

// ---------------------------------------------------------------------
// count — port of internal/loc/count.go
// ---------------------------------------------------------------------

type StatsDelta = Partial<Stats>;

/** deleteTable is the increment for one unpaired deleted line. */
const deleteTable: Record<LineClass, StatsDelta> = {
  unknown: { unknown: 1 },
  code: { deleted_code: 1 },
  comment: { deleted_comment: 1 },
  blank: { blank: 1 },
};

/** insertTable is the increment for one unpaired inserted line. */
const insertTable: Record<LineClass, StatsDelta> = {
  unknown: { unknown: 1 },
  code: { added_code: 1 },
  comment: { added_comment: 1 },
  blank: { blank: 1 },
};

/**
 * transitionTable is the class-transition table, indexed
 * [oldClass][newClass]. The only cell that collapses a pair into a
 * single count is code -> code (modified_code += 1): a one-line
 * replacement is one modified line, not one deleted plus one added.
 * Every other cell is exactly deleteTable[old] plus insertTable[new] —
 * including blank -> blank, which is blank += 2 because a blank line
 * really was removed and another really was added.
 */
const transitionTable: Record<LineClass, Record<LineClass, StatsDelta>> = {
  code: {
    code: { modified_code: 1 },
    comment: { deleted_code: 1, added_comment: 1 },
    blank: { deleted_code: 1, blank: 1 },
    unknown: { deleted_code: 1, unknown: 1 },
  },
  comment: {
    code: { deleted_comment: 1, added_code: 1 },
    comment: { deleted_comment: 1, added_comment: 1 },
    blank: { deleted_comment: 1, blank: 1 },
    unknown: { deleted_comment: 1, unknown: 1 },
  },
  blank: {
    code: { blank: 1, added_code: 1 },
    comment: { blank: 1, added_comment: 1 },
    blank: { blank: 2 },
    unknown: { blank: 1, unknown: 1 },
  },
  unknown: {
    code: { unknown: 1, added_code: 1 },
    comment: { unknown: 1, added_comment: 1 },
    blank: { unknown: 1, blank: 1 },
    unknown: { unknown: 2 },
  },
};

/** addStats accumulates a delta into s in place. */
function addStats(s: Stats, delta: StatsDelta): void {
  s.added_code += delta.added_code ?? 0;
  s.modified_code += delta.modified_code ?? 0;
  s.deleted_code += delta.deleted_code ?? 0;
  s.added_comment += delta.added_comment ?? 0;
  s.deleted_comment += delta.deleted_comment ?? 0;
  s.whitespace += delta.whitespace ?? 0;
  s.blank += delta.blank ?? 0;
  s.unknown += delta.unknown ?? 0;
}

/**
 * count folds diff hunks plus both sides' line classes into Stats
 * (port of loc.Count).
 *
 *  1. An equal pair whose RAW texts are identical contributes nothing;
 *     one whose raw texts differ contributes whitespace += 1 per PAIR.
 *  2. A change region is a maximal run of adjacent delete and insert
 *     hunks. Its deleted lines D and inserted lines I are paired by
 *     position for the first min(|D|, |I|); the rest are pure.
 *  3. Paired lines go through transitionTable.
 *  4. Pure deletes/inserts go through deleteTable/insertTable.
 *
 * Defensive about its inputs exactly like the Go original: an
 * out-of-range class reads as 'unknown', an out-of-range line as ''.
 */
function count(
  hunks: Hunk[],
  oldClasses: LineClass[],
  newClasses: LineClass[],
  oldLines: string[],
  newLines: string[],
): Stats {
  const stats = zeroStats();

  let i = 0;
  while (i < hunks.length) {
    if (hunks[i].op === 'equal') {
      const h = hunks[i];
      const n = Math.min(h.oldEnd - h.oldStart, h.newEnd - h.newStart);
      for (let k = 0; k < n; k++) {
        if (lineAt(oldLines, h.oldStart + k) !== lineAt(newLines, h.newStart + k)) {
          stats.whitespace++;
        }
      }
      i++;
      continue;
    }

    let j = i;
    const deleted: number[] = [];
    const inserted: number[] = [];
    while (j < hunks.length && hunks[j].op !== 'equal') {
      const h = hunks[j];
      if (h.op === 'delete') {
        for (let x = h.oldStart; x < h.oldEnd; x++) {
          deleted.push(x);
        }
      } else if (h.op === 'insert') {
        for (let x = h.newStart; x < h.newEnd; x++) {
          inserted.push(x);
        }
      }
      j++;
    }

    const paired = Math.min(deleted.length, inserted.length);
    for (let k = 0; k < paired; k++) {
      const o = classAt(oldClasses, deleted[k]);
      const n = classAt(newClasses, inserted[k]);
      addStats(stats, transitionTable[o][n]);
    }
    for (let k = paired; k < deleted.length; k++) {
      addStats(stats, deleteTable[classAt(oldClasses, deleted[k])]);
    }
    for (let k = paired; k < inserted.length; k++) {
      addStats(stats, insertTable[classAt(newClasses, inserted[k])]);
    }
    i = j;
  }

  return stats;
}

/** classAt reads classes[i], treating an out-of-range index as unknown. */
function classAt(classes: LineClass[], i: number): LineClass {
  if (i < 0 || i >= classes.length) {
    return 'unknown';
  }
  return classes[i];
}

/** lineAt reads lines[i], treating an out-of-range index as ''. */
function lineAt(lines: string[], i: number): string {
  if (i < 0 || i >= lines.length) {
    return '';
  }
  return lines[i];
}

const confidenceRank: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

/** minConfidence returns the weaker of two confidences. */
export function minConfidence(a: Confidence, b: Confidence): Confidence {
  return confidenceRank[b] < confidenceRank[a] ? b : a;
}

/**
 * diffCount is the whole measurement for one before/after pair: classify
 * both images, align them, and fold the alignment into buckets. It is
 * the mirror of internal/loc's editStats minus the category gate (the
 * caller skips generated and vendored files before reaching here).
 *
 * The result is never graded higher than its weakest input, and a
 * degraded alignment (either side over DIFF_FALLBACK_LINES) forces 'low'
 * because a degenerate alignment cannot tell a modified line from a
 * delete plus an add.
 */
export function diffCount(
  oldText: string,
  newText: string,
  lang: string,
): { stats: Stats; confidence: Confidence } {
  const oldLines = splitLines(oldText);
  const newLines = splitLines(newText);
  const oldSide = classifyLines(lang, oldText);
  const newSide = classifyLines(lang, newText);
  const stats = count(
    diff(oldLines, newLines),
    oldSide.classes,
    newSide.classes,
    oldLines,
    newLines,
  );
  let confidence = minConfidence(oldSide.confidence, newSide.confidence);
  if (diffDegraded(oldLines, newLines)) {
    confidence = 'low';
  }
  return { stats, confidence };
}
