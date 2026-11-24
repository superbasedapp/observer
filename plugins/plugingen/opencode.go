package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/mcp"
	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
)

// ---------------------------------------------------------------------
// OpenCode npm plugin (plan row 6).
//
// Format grounding:
//
//   - opencode.ai/docs/plugins: a plugin is a JS/TS module exporting an
//     async function that receives a context and returns a hooks object;
//     npm plugins are listed under the "plugin" key of opencode.json and
//     auto-installed with Bun at startup (cached in
//     ~/.cache/opencode/node_modules/); local plugins live in
//     .opencode/plugins/ or ~/.config/opencode/plugins/.
//   - The published @opencode-ai/plugin type declarations: `Plugin` is
//     `(input: PluginInput, options?: PluginOptions) => Promise<Hooks>`,
//     and `Hooks` includes `config?: (input: Config) => Promise<void>` — a
//     MUTATING hook, which is the seam this plugin uses to add the MCP
//     server. (The docs page lists the other hooks but not `config`; the
//     shipped .d.ts is the authority for the signature.)
//   - @opencode-ai/sdk's generated types: `Config.mcp?: {[key: string]:
//     McpLocalConfig | McpRemoteConfig}`, with McpLocalConfig =
//     {type: "local", command: string[], environment?, enabled?, timeout?}.
//     That is exactly the shape internal/mcp's registerOpenCodeJSON
//     writes, so the transpose is a straight copy.
//
// What is generated vs hand-written here: plugingen owns
// src/wiring.generated.ts (the server entry, read back from the real
// registrar) and README.md. package.json, tsconfig.json and src/index.ts
// are hand-written glue — they contain no wiring, only the SDK plumbing
// that imports the generated constants.
// ---------------------------------------------------------------------

// openCodePackageName is the npm package name.
//
// SCOPED, on first-party grounding: opencode.ai/docs/plugins lists npm
// plugins in opencode.json's `plugin` array, states "Both regular and
// scoped npm packages are supported", and its own example array is
// ["opencode-helicone-session", "opencode-wakatime",
// "@my-org/custom-plugin"] — a scoped package sitting alongside two
// unscoped ones. So `@superbased/opencode-plugin` is a documented shape,
// not an assumption, and it keeps the package under the same npm scope as
// the binary shim `@superbased/observer`.
//
// The unscoped `opencode-<x>` prefix is only a convention; the scope is
// worth more than the convention here because it makes the publisher
// verifiable from the package name alone.
const openCodePackageName = "@superbased/opencode-plugin"

// openCodeServer is OpenCode's McpLocalConfig, and also the exact struct
// internal/mcp's registerOpenCodeJSON marshals. Field order here is the
// emitted key order.
type openCodeServer struct {
	Type        string            `json:"type"`
	Command     []string          `json:"command"`
	Enabled     bool              `json:"enabled"`
	Environment map[string]string `json:"environment,omitempty"`
}

// readOpenCodeEntry pulls the "observer" entry out of the opencode.json
// the MCP registrar just wrote. An unmodelled key is a hard error.
func readOpenCodeEntry(home string) (openCodeServer, error) {
	loc, ok := locate.ForClient("opencode", home)
	if !ok {
		return openCodeServer{}, fmt.Errorf("plugingen: locate.ForClient(%q): not supported", "opencode")
	}
	raw, err := os.ReadFile(loc.Path)
	if err != nil {
		return openCodeServer{}, fmt.Errorf("plugingen: read opencode config: %w", err)
	}
	var doc struct {
		MCP map[string]json.RawMessage `json:"mcp"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return openCodeServer{}, fmt.Errorf("plugingen: parse opencode config: %w", err)
	}
	entryRaw, ok := doc.MCP[mcp.ServerName]
	if !ok {
		return openCodeServer{}, fmt.Errorf("plugingen: opencode config has no %q server", mcp.ServerName)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(entryRaw, &keys); err != nil {
		return openCodeServer{}, fmt.Errorf("plugingen: parse opencode entry: %w", err)
	}
	for k := range keys {
		switch k {
		case "type", "command", "enabled", "environment":
		default:
			return openCodeServer{}, fmt.Errorf(
				"plugingen: opencode MCP entry carries unmodelled key %q — teach plugingen's openCodeServer struct about it before regenerating", k,
			)
		}
	}
	var entry openCodeServer
	if err := json.Unmarshal(entryRaw, &entry); err != nil {
		return openCodeServer{}, fmt.Errorf("plugingen: decode opencode entry: %w", err)
	}
	if entry.Type != "local" {
		return openCodeServer{}, fmt.Errorf("plugingen: opencode MCP type is %q, want \"local\"", entry.Type)
	}
	if len(entry.Command) == 0 || entry.Command[0] != pathBinary {
		return openCodeServer{}, fmt.Errorf("plugingen: opencode MCP command is %v, want %q at the head", entry.Command, pathBinary)
	}
	return entry, nil
}

// tsStringList renders a TypeScript string-array literal.
func tsStringList(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, it := range items {
		quoted = append(quoted, `"`+it+`"`)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// openCodeWiringTS renders the generated constants module the hand-written
// plugin imports. `type` is emitted with an `as const` assertion so the
// object still satisfies McpLocalConfig's literal "local" type, while
// `command` stays a mutable string[] (a whole-object `as const` would make
// it readonly and fail the assignment).
func openCodeWiringTS(entry openCodeServer) string {
	var b strings.Builder
	b.WriteString("// GENERATED by plugins/plugingen — do not edit by hand.\n")
	b.WriteString("// Regenerate with `make plugins-build`; CI gate: `make verify-plugins-build`.\n")
	b.WriteString("//\n")
	b.WriteString("// This is the MCP entry internal/mcp's Registrar writes into\n")
	b.WriteString("// ~/.config/opencode/opencode.json for `observer init --opencode`, read back\n")
	b.WriteString("// out of a sandbox HOME and transposed verbatim. The one deviation is the\n")
	b.WriteString("// binary: a published package cannot know an absolute install path, so the\n")
	b.WriteString("// generator drives the registrar with the PATH name.\n\n")
	b.WriteString("/** The stable MCP server id observer registers under. */\n")
	b.WriteString("export const OBSERVER_MCP_SERVER_NAME = \"" + mcp.ServerName + "\";\n\n")
	b.WriteString("/** OpenCode's McpLocalConfig entry for the observer MCP server. */\n")
	b.WriteString("export const OBSERVER_MCP_SERVER = {\n")
	b.WriteString("  type: \"" + entry.Type + "\" as const,\n")
	b.WriteString("  command: " + tsStringList(entry.Command) + ",\n")
	b.WriteString(fmt.Sprintf("  enabled: %t,\n", entry.Enabled))
	if len(entry.Environment) > 0 {
		keys := make([]string, 0, len(entry.Environment))
		for k := range entry.Environment {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("  environment: {\n")
		for _, k := range keys {
			b.WriteString("    \"" + k + "\": \"" + entry.Environment[k] + "\",\n")
		}
		b.WriteString("  },\n")
	}
	b.WriteString("};\n")
	return b.String()
}

func openCodeReadme(entry openCodeServer) string {
	argv := strings.Join(entry.Command, " ")
	var b strings.Builder
	b.WriteString(generatedBanner)
	b.WriteString(`
# ` + openCodePackageName + ` — OpenCode plugin

Local-first token, cost and cache observability for OpenCode. The plugin
registers observer's MCP server through OpenCode's ` + "`config`" + ` hook, so you
never edit ` + "`opencode.json`" + `'s ` + "`mcp`" + ` block by hand.

**` + binaryPrereqSentence + `.** This package is
wiring only — it declares an MCP server that runs ` + "`observer`" + `; it does not
download or bundle it.

` + "```bash" + `
npm i -g @superbased/observer     # or: pipx install superbased-observer
observer start                    # run the local daemon
` + "```" + `

## Install

Add the package to the ` + "`plugin`" + ` array of your ` + "`opencode.json`" + `
(` + "`~/.config/opencode/opencode.json`" + ` for every project, or a project-local
` + "`opencode.json`" + `):

` + "```json" + `
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["` + openCodePackageName + `"]
}
` + "```" + `

OpenCode installs npm plugins with Bun at startup and caches them in
` + "`~/.cache/opencode/node_modules/`" + ` — there is no separate ` + "`npm install`" + `
step.

> **On npm, but it can lag.** ` + "`" + openCodePackageName + "`" + ` is published on npm,
> but by hand, not with every observer release, so the npm version can be older
> than the observer you run. ` + "`npm view " + openCodePackageName + " version`" + ` shows
> the published version. This directory is the package source.

## What it wires

The plugin's ` + "`config`" + ` hook adds one entry to OpenCode's MCP map:

` + "```json" + `
{
  "mcp": {
    "` + mcp.ServerName + `": {
      "type": "` + entry.Type + `",
      "command": ` + tsStringList(entry.Command) + `,
      "enabled": ` + fmt.Sprintf("%t", entry.Enabled) + `
    }
  }
}
` + "```" + `

That is byte-for-byte the entry ` + "`observer init --opencode`" + ` writes — it is
generated from the same registrar (` + "`src/wiring.generated.ts`" + `), not
re-typed. ` + "`" + argv + "`" + ` speaks stdio MCP and exposes observer's
project, session, cost and cache queries as tools (reads of the local
database; ` + "`continue_session`" + ` writes a handover file only when you pass
` + "`write_file=true`" + `).

No lifecycle hooks are registered. OpenCode's ` + "`tool.execute.before/after`" + `
and ` + "`event`" + ` hooks could surface cost hints in-session, but observer's
capture does not need them: the watcher already reads OpenCode's own
session store, and ` + "`observer opencode`" + ` routes turns through the local
proxy for exact token counts.

## Double-wiring: handled, in the one case we can

The hook **skips itself when the server is already configured**:

` + "```ts" + `
if (config.mcp[OBSERVER_MCP_SERVER_NAME]) return;
` + "```" + `

So carrying both this plugin and ` + "`observer init --opencode`" + `'s write is
safe — whichever entry is already in the merged config wins, and the server
is declared exactly once. Note this is a **same-key** check inside
OpenCode's own config object, not a probe of what observer wrote; if you
registered the server under a DIFFERENT name, both load.

(The on-disk detect-and-skip that makes ` + "`observer init`" + ` stand down for the
Claude Code plugin is ` + "`internal/claudeplugin`" + ` — claude-code-only. There is
no OpenCode equivalent, and none was built this round;
` + "`observer init --opencode`" + ` still writes its entry. The config-hook guard
above is what makes that harmless.)

## Package layout

| Path | Owner |
|---|---|
| ` + "`src/wiring.generated.ts`" + ` | **Generated** by ` + "`plugins/plugingen`" + ` from the real MCP registrar. Never edit. |
| ` + "`README.md`" + ` | **Generated** (this file). |
| ` + "`src/index.ts`" + ` | Hand-written SDK glue: the ` + "`config`" + ` hook. |
| ` + "`package.json`" + `, ` + "`tsconfig.json`" + ` | Hand-written. The version is stamped by ` + "`scripts/sync-npm-version.sh`" + ` in lockstep with the observer release. |

Build (operator step, before a publish):

` + "```bash" + `
npm install && npm run build      # tsc → dist/
` + "```" + `

` + "`dist/`" + ` is not committed. ` + "`@opencode-ai/plugin`" + ` is a devDependency and
a **type-only** import, so the built plugin has no runtime dependencies.

## Links

- Docs: ` + homepage + `
- Source: https://github.com/superbasedapp/observer
- License: ` + license + `
`)
	return b.String()
}

// openCodeHandWrittenFiles lists the files under plugins/opencode that
// plugingen does NOT own. The stray-file test consults this so a
// hand-written package file is not reported as generator drift, and so
// adding one is a deliberate edit here rather than a silent exception.
func openCodeHandWrittenFiles() []string {
	return []string{
		filepath.ToSlash(filepath.Join("opencode", "package.json")),
		filepath.ToSlash(filepath.Join("opencode", "tsconfig.json")),
		filepath.ToSlash(filepath.Join("opencode", "src", "index.ts")),
	}
}
