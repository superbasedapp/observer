// jsonBody.ts is fetchJSON's reading of a successful response body (pure, so
// a node test needs no fetch). A route that answers a write with 204, or with
// 200 and no body (the hosted consent route did, and the dialog's Agree then
// showed "Unexpected end of JSON input" although the agreement was saved),
// is a success with nothing to read, not a parse error.

/**
 * parseJSONBody parses a successful response's text: undefined for a 204
 * or an empty (or whitespace-only) body, else the parsed JSON (a malformed
 * body still throws, as res.json() did).
 */
export function parseJSONBody<T>(status: number, text: string): T {
  if (status === 204 || text.trim() === "") return undefined as T;
  return JSON.parse(text) as T;
}
