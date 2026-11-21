import type { GuardMatchScope, GuardRuleRow } from "./guardCatalog";

// guardMatcherGuide — the plain-words guidance the custom guard rule editor
// (shared/components/guard/CustomRuleEditor.tsx) shows for each kind of thing
// a rule can stop, and for each matcher field. Pure data and two pure
// functions, so the editor, the org form's empty state and their tests read
// one table.
//
// Every syntax line here is grounded in the rule compiler, the one authority
// (internal/guard/policyfile.go compileRule / compileCmdConds /
// compileEvConds, docs/guard-policy-authoring.md "Matcher vocabulary"):
//   - command_base: compared to the parsed command's base, lower-cased, so
//     an exact, case-insensitive program name.
//   - command_regex: Go regexp (RE2) over the raw command text.
//   - arg_contains: a substring of any argument after the program.
//   - path_glob / path_not: policy.MatchAnyPathGlob, the built-in path tables'
//     matcher: "*" and "?" within one path segment, "**" across segments,
//     "~/" the home folder, matched without regard to case; no "[a-z]"
//     classes (internal/policy/paths.go matchGlob).
//   - url_domain: hostMatchesDomain, the URL host equals the domain or is a
//     subdomain of it (lower-cased; scheme, port, path and user stripped).
//   - mcp_server: policy.MCPServerFromTarget, the server half of
//     "mcp__server__tool" or "server/tool", compared exactly.
//   - mcp_tool: strings.HasSuffix over the call target, so the end of the
//     call name; no wildcards.
// A rule's matchers all have to match (AND), and a command matcher cannot sit
// in the same rule as any other matcher.

/** What a rule stops, as the editor's first choice. A UI notion: it picks the
 *  rule's matcher scope and which fields lead; it is never written to the
 *  bundle. */
export type GuardMatchKind = "command" | "path" | "domain" | "mcp" | "other";

/** One row of the kind guide. */
export type GuardMatchKindGuide = {
  kind: GuardMatchKind;
  /** The rule's matcher scope for this kind. */
  scope: GuardMatchScope;
  /** Short chooser label. */
  label: string;
  /** The empty state's button text ("A command"). */
  noun: string;
  /** One sentence: what to enter and how it matches. */
  help: string;
  /** Worked examples: the field label and what to type in it. */
  examples: readonly { field: string; value: string; note: string }[];
};

/** The kind guide, in chooser order. */
export const GUARD_MATCH_KIND_GUIDE: readonly GuardMatchKindGuide[] = [
  {
    kind: "command",
    scope: "command",
    label: "Command",
    noun: "A command",
    help: "Stops a shell command the agent runs. Enter the program name, or a regular expression over the whole command line for anything finer.",
    examples: [
      { field: "Program", value: "scp", note: "any scp command, in any letter case" },
      { field: "Command pattern", value: "(?i)\\bterraform\\s+(apply|destroy)\\b", note: "terraform apply or destroy" },
    ],
  },
  {
    kind: "path",
    scope: "event",
    label: "File path",
    noun: "A file path",
    help: "Stops reading or writing matching files. Enter one pattern at a time and press Enter: * and ? stay inside one folder, ** spans folders, ~/ is the home folder.",
    examples: [
      { field: "File paths", value: "~/.aws/**", note: "everything under the home folder's .aws folder" },
      { field: "File paths", value: "**/.env", note: "a .env file in any folder" },
    ],
  },
  {
    kind: "domain",
    scope: "event",
    label: "Domain",
    noun: "A domain",
    help: "Stops web requests to a site. Enter the domain only, without https:// or a path; its subdomains match too.",
    examples: [{ field: "Domain", value: "pastebin.com", note: "pastebin.com and any subdomain of it" }],
  },
  {
    kind: "mcp",
    scope: "event",
    label: "MCP tool",
    noun: "An MCP tool",
    help: "Stops calls to an MCP server, or to one of its tools. Enter the server name the AI tool knows it by, and optionally the full tool name.",
    examples: [
      { field: "MCP server", value: "github", note: "every tool of the github server" },
      { field: "MCP tool", value: "delete_file", note: "with the server above: only its delete_file tool" },
    ],
  },
  {
    kind: "other",
    scope: "event",
    label: "Other",
    noun: "Something else",
    help: "Conditions on the session instead of one target: after untrusted input, past a spend, or a repeated action. Pick the actions it applies to.",
    examples: [{ field: "Session cost over", value: "20", note: "every listed action once a session has cost more than $20" }],
  },
];

/** The guide row for a kind. */
export function guardMatchKindGuide(kind: GuardMatchKind): GuardMatchKindGuide {
  return GUARD_MATCH_KIND_GUIDE.find((g) => g.kind === kind) ?? GUARD_MATCH_KIND_GUIDE[0];
}

/** The kinds the org form's empty state offers as starting points. */
export const GUARD_MATCH_KIND_STARTERS: readonly GuardMatchKind[] = ["command", "path", "domain", "mcp"];

// KIND_FROM_ROW is the ordered table inferMatchKind walks: the first row
// whose test holds names the kind an existing rule is shown under.
const KIND_FROM_ROW: readonly { kind: GuardMatchKind; test: (r: GuardRuleRow) => boolean }[] = [
  { kind: "command", test: (r) => r.scope === "command" },
  { kind: "domain", test: (r) => !!r.event.url_domain.trim() },
  { kind: "mcp", test: (r) => !!(r.event.mcp_server.trim() || r.event.mcp_tool.trim()) },
  {
    kind: "path",
    test: (r) =>
      r.event.path_glob.length > 0 ||
      r.event.path_not.length > 0 ||
      r.event.path_outside_project ||
      r.event.path_sensitive ||
      r.event.access !== "",
  },
  {
    kind: "other",
    test: (r) =>
      !!(
        r.event.sink ||
        r.event.taint_source ||
        r.event.event_kind.length ||
        r.event.session_cost_usd_gt.trim() ||
        r.event.repeat_count_gt.trim()
      ),
  },
];

/** The kind an existing rule reads as; an event rule with no matchers yet
 *  starts on file paths. */
export function inferMatchKind(r: GuardRuleRow): GuardMatchKind {
  return KIND_FROM_ROW.find((row) => row.test(r))?.kind ?? "path";
}

/** Plain-words label, help and example for one matcher field. `key` is the
 *  bundle's key, shown only as a technical detail. */
export type GuardMatcherFieldCopy = { label: string; help: string; placeholder?: string; key: string };

/** Field copy, keyed by matcher. */
export const GUARD_MATCHER_FIELD_COPY = {
  command_base: {
    key: "match.command_base",
    label: "Program",
    help: "The program's name, matched exactly in any letter case.",
    placeholder: "scp",
  },
  command_regex: {
    key: "match.command_regex",
    label: "Command pattern",
    help: "A regular expression (RE2) over the whole command line. Start it with (?i) to ignore letter case.",
    placeholder: "(?i)\\bterraform\\s+(apply|destroy)\\b",
  },
  arg_contains: {
    key: "match.arg_contains",
    label: "Argument contains",
    help: "Text that appears in any argument after the program.",
    placeholder: "--force",
  },
  path_glob: {
    key: "match.path_glob",
    label: "File paths",
    help: "Press Enter after each pattern. * and ? stay inside one folder, ** spans folders, ~/ is the home folder. Letter case is ignored.",
    placeholder: "~/.aws/** then Enter",
  },
  path_not: {
    key: "match.path_not",
    label: "Except these paths",
    help: "Same patterns; a path that matches one is never stopped by this rule.",
    placeholder: "**/.env.example then Enter",
  },
  path_outside_project: {
    key: "match.path_outside_project",
    label: "Only outside the project",
    help: "",
  },
  path_sensitive: {
    key: "match.path_sensitive",
    label: "Only sensitive files (keys, credentials)",
    help: "",
  },
  access: {
    key: "match.access",
    label: "Reads or writes",
    help: "Narrow the rule to reads or to writes (a write, an edit or a config change). Either matches both.",
  },
  url_domain: {
    key: "match.url_domain",
    label: "Domain",
    help: "The domain only, without https:// or a path. Subdomains match too.",
    placeholder: "pastebin.com",
  },
  mcp_server: {
    key: "match.mcp_server",
    label: "MCP server",
    help: "The server's name as the AI tool knows it, matched exactly.",
    placeholder: "github",
  },
  mcp_tool: {
    key: "match.mcp_tool",
    label: "MCP tool",
    help: "The full tool name. It matches the end of the call's name, so a short word can match other tools.",
    placeholder: "delete_file",
  },
  sink: {
    key: "match.sink",
    label: "Where it ends up",
    help: "Matches an action that reaches this place, such as a git push.",
  },
  taint_source: {
    key: "match.taint_source",
    label: "After untrusted input from",
    help: "Matches once the session has taken in input from this source.",
  },
  event_kind: {
    key: "match.event_kind",
    label: "Action kinds",
    help: "The action's kind must be one of these.",
  },
  session_cost_usd_gt: {
    key: "match.session_cost_usd_gt",
    label: "Session cost over (USD)",
    help: "Matches once the session has cost more than this.",
    placeholder: "20.0",
  },
  repeat_count_gt: {
    key: "match.repeat_count_gt",
    label: "Repeated more than",
    help: "Matches when the same action repeats more times in a row than this.",
    placeholder: "5",
  },
} as const satisfies Record<string, GuardMatcherFieldCopy>;

/** A matcher field the copy table names. */
export type GuardMatcherField = keyof typeof GUARD_MATCHER_FIELD_COPY;
