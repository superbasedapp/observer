// Package cline implements the Adapter interface for Cline and Roo Code
// (VS Code extensions). Both use the same api_conversation_history.json
// format. See spec §4.4. Implemented in Phase 2.
//
// A `thinking` / `redacted_thinking` block mints no row: it accumulates
// into the per-message reasoning buffer and reaches the timeline as
// PrecedingReasoning on the tool_use rows that follow it in that message
// (FAN-OUT — one thought can precede several calls and each carries it).
// The posture holds for every retag of this parser (cline / roo-code /
// legacy kilo-code). See
// docs/plans/b3-reasoning-convergence-plan-2026-07-31.md §1.
//
// # XML pseudo-tools (audit IDE-07)
//
// Cline's legacy bundle does NOT put its built-in tool calls in
// Anthropic `tool_use` content blocks. It prompts the model to emit
// XML-ish pseudo-tags inside an ordinary assistant `text` block
// (`<read_file><path>x</path></read_file>`, `<execute_command>`,
// `<ask_followup_question>`, …). Before the scanner in xmltools.go,
// every file read / write / shell command was swallowed whole into the
// assistant_message row — the two live tasks on the operator's box
// produced ZERO tool rows — and the swallowed text additionally tripped
// the scrubber, because `ask_followup_question` contains the substring
// `sk_followup_question`, which matches the generic API-key rule.
//
// scanXMLTools walks a text block line-by-line against the
// xmlToolTags table, mints one tool ToolEvent per occurrence, and
// returns the prose with those spans REMOVED, so prose stays prose and
// the scrubber never sees a tag name. A tag counts as a call ONLY when
// it opens a line and is followed by a newline or its first parameter,
// and never inside a ``` / ~~~ code fence or a `<thinking>` span — so
// prose that MENTIONS a tag, a documentation fence, and the model's
// own reasoning all stay prose and mint nothing. `<write_to_file>`'s
// `<content>` and `<replace_in_file>`'s `<diff>` are file bodies: only
// the path plus a bounded excerpt is stored, never the body (CLAUDE.md
// "don't store file contents"). Tag names feed the SAME actionMap
// the tool_use path uses, so a tag and a block of the same name can
// never disagree about action_type. Two documented limitations: an
// XML call's Success is always true (Cline reports the outcome as free
// text in the next user message, with no machine-readable error flag),
// and three real tags (list_code_definition_names, new_task,
// plan_mode_respond) classify as `unknown` because neither actionMap
// nor internal/tooltax carries a row for them.
//
// # Surface attribution (audit IDE-05)
//
// This parser only ever reads an editor extension's globalStorage, so
// every session it sees stamps models.SurfaceIDE unconditionally; only
// the host varies. The host comes from the VS Code-family product the
// task path lives under (internal/platform/vscodehost.ProductForPath),
// REFINED by the sibling task_metadata.json's
// environment_history[].host_name when that file exists and names a
// host we recognise — the grounded live value is a DISPLAY name
// ("Visual Studio Code"), not a slug. Neither signal ⇒ an EMPTY host
// token: the IDE kind is grounded, the host is not guessed.
// task_metadata.json's model_usage[] additionally backfills the model
// on rows that carry none. See taskmeta.go.
//
// # Watch roots (audits IDE-14, IDE-23)
//
// roots.go enumerates the CROSS PRODUCT of every VS Code-family
// product (via internal/platform/vscodehost — Code, Code - Insiders,
// VSCodium, Cursor, Windsurf, Kiro, Qoder, Trae, plus the
// .vscode-server / .cursor-server remote layouts) and every extension
// id in the clineExtensions table: Cline's own saoudrizwan.claude-dev
// plus the FIVE Roo Code ids (roovscode.roo-cline, roovscode.roo-code,
// rooveterinaryinc.roo-cline, rooveterinaryinc.roo-code,
// rooveterinaryinc.roo-code-nightly). It previously covered upstream
// Code x 2 ids, so both fork hosts and four of five Roo install shapes
// were invisible. Roo's `roo-cline.customStoragePath` setting can
// RELOCATE the store entirely; roots.go reads each product's
// settings.json (JSONC-tolerant) and adds `<value>/tasks` when set.
//
// Two more ids joined 2026-09-03 (uncaptured-surfaces wiring plan,
// ticket U1): `saoudrizwan.cline-nightly` is Cline's own nightly
// channel — a separate Marketplace/Open VSX listing with its own
// globalStorage namespace but the same legacy task layout, so it
// retags to models.ToolCline exactly like stable. Roo Code's
// 2026-04-21 shutdown produced a community continuation, ZooCode
// (`ZooCodeOrganization.zoo-code`, v3.54.0), which parses through this
// same table into a NEW package-less retag, models.ToolZooCode — the
// roo-code precedent (no adapter identity, no integration registry
// row). Its `zoo-code.customStoragePath` relocation setting IS wired
// (2026-09-04, grounded from a live zoo-code@3.80.1 package.json); a
// relocated ZooCode or Roo store recovers its tool from the settings key
// via customRootTools (see roots.go's customStorageKeys / toolForPath).
package cline
