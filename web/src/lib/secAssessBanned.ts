// secAssessBanned builds the one test the assessment views are held to: no
// sentence Observer writes may read as a clearance (depth plan section 13,
// limit 3: a result with nothing in it is not a clearance). The words and
// phrases are one shared list, internal/secassess/testdata/clearance_words.json,
// read by the Go test (internal/secassess/reading_test.go) and by the
// TypeScript tests and the e2e spec. This file holds only the builder, so the
// browser bundle carries no file reading: each test reads the JSON itself and
// hands the parsed list here.
//
// A word matches whole and in any case ("unsafe" and "cleanup" are not
// "safe" and "clean"). A phrase matches with any run of white space between
// its words ("No  issues" is "no issues"). Pure: no fetch, no React, no DOM.

/** The shared list as the JSON file holds it: `caught` and `allowed` are sample strings the list is tested against. */
export type ClearanceList = {
  words: string[];
  phrases: string[];
  caught?: string[];
  allowed?: string[];
};

/** escapeRegExp makes a literal safe to place inside a regular expression. */
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** clearanceRegExp is the case-insensitive test of the list: every word as a whole word, every phrase with white space between its words. It has no global flag, so it can be reused with `.test` and `.match`. */
export function clearanceRegExp(list: Pick<ClearanceList, "words" | "phrases">): RegExp {
  const alts: string[] = [];
  for (const w of list.words ?? []) {
    const t = w.trim();
    if (t !== "") alts.push(escapeRegExp(t));
  }
  for (const p of list.phrases ?? []) {
    const parts = p.trim().split(/\s+/).filter((x) => x !== "");
    if (parts.length > 0) alts.push(parts.map(escapeRegExp).join("\\s+"));
  }
  // A list with nothing in it matches nothing (an empty alternation would match everything).
  if (alts.length === 0) return /(?!)/;
  return new RegExp(`\\b(?:${alts.join("|")})\\b`, "i");
}

/** parseClearanceList reads the JSON text of the shared list and refuses a file that is not shaped like it. */
export function parseClearanceList(json: string): ClearanceList {
  const raw: unknown = JSON.parse(json);
  const o = raw as Partial<Record<keyof ClearanceList, unknown>> | null;
  const strings = (v: unknown): string[] => {
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) throw new Error("the clearance word list is not a list of strings");
    return v as string[];
  };
  if (o === null || typeof o !== "object") throw new Error("the clearance word list is not an object");
  return {
    words: strings(o.words),
    phrases: strings(o.phrases),
    caught: o.caught === undefined ? [] : strings(o.caught),
    allowed: o.allowed === undefined ? [] : strings(o.allowed),
  };
}
