package agentconfig

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Relocation rules (surface-gap arc Wave 0.4; docs/plans/surface-gap-wave-0-
// design-2026-10-25.md section 6). Many tools let an environment variable
// move their config home (CLAUDE_CONFIG_DIR, CODEX_HOME, KIRO_HOME, ...),
// and each reads the value its own way. The fileRelocations table declares,
// per FileRow id, the variables that move that file and how; ResolvePath
// applies them when PathEnv.Relocate is set. The rules sit in a table keyed
// by artifact id rather than on FileRow itself, so FileRow stays a
// comparable value and every existing consumer is untouched. Pure: the
// caller supplies the environment through PathEnv.Getenv.

// RelocSemantics is how a tool reads one relocation variable. The
// vocabulary is closed and names a reading shape, never a tool.
type RelocSemantics string

// The closed RelocSemantics vocabulary.
const (
	// RelocExactDir: the value is a directory that replaces Anchor.
	RelocExactDir RelocSemantics = "exact_dir"
	// RelocAbsoluteNotHomeAncestor: like RelocExactDir, but the tool
	// refuses a value that is the filesystem root, the home directory or an
	// ancestor of it (Kiro's KIRO_HOME rule).
	RelocAbsoluteNotHomeAncestor RelocSemantics = "absolute_not_home_ancestor"
	// RelocTildeExpand: like RelocExactDir, but a leading "~" is expanded
	// against the home directory first (Deep Agents' DEEPAGENTS_HOME).
	RelocTildeExpand RelocSemantics = "tilde_expand"
	// RelocFileNotDir: the value names the file itself (VT Code's
	// VTCODE_CONFIG).
	RelocFileNotDir RelocSemantics = "file_not_dir"
	// RelocAppendIfMissing: Sub is appended to the value unless its last
	// segment already is Sub, and the result replaces Anchor (DimCode's
	// DIMCODE_HOME and its "v2" store).
	RelocAppendIfMissing RelocSemantics = "append_if_missing"
	// RelocDoesNotMoveArtifact: the variable exists but does NOT move this
	// file (Dirac's DIRAC_DIR moves its data dir, never its Hooks folder).
	// Declared so a writer that follows the variable is visibly wrong.
	RelocDoesNotMoveArtifact RelocSemantics = "does_not_move_artifact"
	// RelocRootPlusSub: the value is a root directory; Sub is always joined
	// onto it and the result replaces Anchor (Goose's GOOSE_PATH_ROOT, which
	// re-roots its config as <root>/config).
	RelocRootPlusSub RelocSemantics = "root_plus_sub"
	// RelocAnchorSuffix: the value is a literal suffix appended to the
	// Anchor's last segment (Hermes' HERMES_DATA_DIR_SUFFIX turns ~/.hermes
	// into ~/.hermes<suffix>). The value is not a path, so it is never
	// refused as relative.
	RelocAnchorSuffix RelocSemantics = "anchor_suffix"
)

// Relocation is one environment variable that can move a FileRow's file.
type Relocation struct {
	// Env is the variable name.
	Env       string
	Semantics RelocSemantics
	// Anchor is the leading part of the row's path that the value replaces
	// ("~/.codex" in "~/.codex/config.toml"). Required for every semantics
	// but RelocFileNotDir and RelocDoesNotMoveArtifact.
	Anchor string
	// Sub is the segment RelocAppendIfMissing appends.
	Sub string
	// GOOS limits the rule to one OS ("linux", "darwin", "windows"); "" =
	// every OS whose path starts with Anchor.
	GOOS string
	// RelativeFallsThrough says the TOOL itself ignores a relative value and
	// falls back to its next location (Kiro requires an absolute KIRO_HOME).
	// When false (the default) a relative value is what the tool uses,
	// against a working directory Observer cannot know, so the walk stops
	// there and the row resolves to PathRelocationUnresolved instead of to a
	// lower location the tool would not read (FU-31).
	RelativeFallsThrough bool
	Grounding            Grounding
	Note                 string
}

// RelocIgnore is why a set relocation variable was refused. Closed.
type RelocIgnore string

// The closed RelocIgnore vocabulary.
const (
	// RelocIgnoreRelative: the value is not an absolute path for the OS
	// (the tool would read it against a working directory Observer cannot
	// know).
	RelocIgnoreRelative RelocIgnore = "relative_value"
	// RelocIgnoreHomeAncestor: the value is the root, the home directory or
	// an ancestor of it, which the tool refuses.
	RelocIgnoreHomeAncestor RelocIgnore = "home_ancestor"
	// RelocIgnoreDoesNotMove: the variable is declared not to move this file.
	RelocIgnoreDoesNotMove RelocIgnore = "does_not_move"
	// RelocIgnoreAnchorMismatch: the row's path does not start with Anchor
	// (a catalogue error; TestRelocationRowsWellFormed catches it).
	RelocIgnoreAnchorMismatch RelocIgnore = "anchor_mismatch"
	// RelocIgnoreUnknownSemantics: a semantics outside the closed set (a
	// catalogue error).
	RelocIgnoreUnknownSemantics RelocIgnore = "unknown_semantics"
)

// ErrUnknownArtifact is returned by ResolveArtifact for an id no FileRow has.
var ErrUnknownArtifact = errors.New("agentconfig: unknown artifact id")

// relocClaudeConfigDir and relocCodexHome are the two home rules seeded in
// Wave 0 (design section 6). Observer's own launcher, dashboard setup probe
// and Codex watcher already honour both variables; the writers move onto
// these rules in Wave 4.
var (
	relocClaudeConfigDir = Relocation{
		Env: "CLAUDE_CONFIG_DIR", Semantics: RelocExactDir, Anchor: "~/.claude",
		Grounding: Grounding{Kind: GroundSource, Source: "internal/intelligence/dashboard/setup.go reads CLAUDE_CONFIG_DIR; surface-gap review CC-8", Date: "2026-10-25"},
		Note:      "Moves the ~/.claude directory. ~/.claude.json moves too, by its own rule (relocClaudeJSON).",
	}
	// relocClaudeJSON settles CC-8: with CLAUDE_CONFIG_DIR set, Claude Code
	// keeps its global config at $CLAUDE_CONFIG_DIR/.claude.json (the binary
	// joins CLAUDE_CONFIG_DIR, else the home directory, with ".claude.json"),
	// so the value replaces the home directory the file sits in.
	relocClaudeJSON = Relocation{
		Env: "CLAUDE_CONFIG_DIR", Semantics: RelocExactDir, Anchor: "~",
		Grounding: mac4Live("Claude Code 2.1.311 with CLAUDE_CONFIG_DIR set created $CLAUDE_CONFIG_DIR/.claude.json and nothing under ~; " +
			"the binary has configPath join(CLAUDE_CONFIG_DIR || home, \".claude.json\"); also the Windows 11 Pro rerun 2026-10-25 D3 (integration SandboxConfigHome)"),
		Note: "Moves ~/.claude.json to $CLAUDE_CONFIG_DIR/.claude.json (inside the relocated directory, not beside it).",
	}
	relocCodexHome = Relocation{
		Env: "CODEX_HOME", Semantics: RelocExactDir, Anchor: "~/.codex",
		Grounding: Grounding{Kind: GroundSource, Source: "internal/adapter/codex/adapter.go reads CODEX_HOME; surface-gap review CX-4", Date: "2026-10-25"},
		Note:      "Moves the ~/.codex directory.",
	}
)

// The Cline home rules (surface-gap lane w2-d, S-6). The Cline SDK, its
// CLI, the VS Code extension and Cline for JetBrains share one store under
// ~/.cline (HOME, else USERPROFILE). Each file is resolved top-down: the
// file's own variable (where it has one), then CLINE_DATA_DIR for the data
// dir, then CLINE_DIR for the whole home. Every value is trimmed by the
// vendor; a relative one is read against a working directory Observer cannot
// know, so it is refused here.
var (
	clineGrounding    = Grounding{Kind: GroundSource, Source: "https://raw.githubusercontent.com/cline/cline/main/sdk/packages/shared/src/storage/paths.ts (resolveClineDir, resolveClineDataDir, resolveMcpSettingsPath, resolveProviderSettingsPath, resolveGlobalSettingsPath); apps/vscode/src/shared/storage/storage-context.ts resolveDataDirFromEnv; apps/vscode/src/hosts/vscode/mcp-settings-legacy-migration.ts getSharedMcpSettingsPath", Date: "2026-10-25"}
	relocClineDataDir = Relocation{
		Env: "CLINE_DATA_DIR", Semantics: RelocExactDir, Anchor: "~/.cline/data", Grounding: clineGrounding,
		Note: "Moves the data dir (~/.cline/data) that holds globalState.json, secrets.json and settings/.",
	}
	relocClineDir = Relocation{
		Env: "CLINE_DIR", Semantics: RelocExactDir, Anchor: "~/.cline", Grounding: clineGrounding,
		Note: "Moves the whole ~/.cline home (data/ included, unless CLINE_DATA_DIR is set).",
	}
)

// clineFileRule is a Cline file's own path variable (the value names the
// file itself).
func clineFileRule(env string) Relocation {
	return Relocation{Env: env, Semantics: RelocFileNotDir, Grounding: clineGrounding, Note: "Names the file itself."}
}

// fileRelocations is the ONE owner of relocation rules, keyed by FileRow id
// and walked top-down per row. A row absent here never moves. Seeded only
// with rules grounded in Observer's own readers; the rest of the review's
// relocation table (S-17) lands in Wave 4 with the writers that use it.
var fileRelocations = map[string][]Relocation{
	"claude-code/user-settings": {relocClaudeConfigDir},
	// The sign-in files sign-in seeding resolves (lane BOXSIGNIN): the
	// vendors' docs say CLAUDE_CONFIG_DIR keeps .credentials.json under it
	// and CODEX_HOME holds auth.json.
	"claude-code/credentials":   {relocClaudeConfigDir},
	"claude-code/global-config": {relocClaudeJSON},
	// FU-142: Claude Code reads its user CLAUDE.md, skills, agents and
	// commands from the directory CLAUDE_CONFIG_DIR names, the same
	// directory rule as its settings (the guidance rows of
	// internal/guidance/rules.go; the service's instruction scan, glob
	// targets and inventory ids follow it, instructions_relocate.go).
	"claude-code/instructions:~/.claude/CLAUDE.md":   {relocClaudeConfigDir},
	"claude-code/skill:~/.claude/skills/*/SKILL.md":  {relocClaudeConfigDir},
	"claude-code/agent:~/.claude/agents/*.md":        {relocClaudeConfigDir},
	"claude-code/command:~/.claude/commands/**/*.md": {relocClaudeConfigDir},
	"codex/auth":        {relocCodexHome},
	"codex/user-config": {relocCodexHome},
	"codex/user-hooks":  {relocCodexHome},
	// Only the Windows path of the managed defaults file lives in the Codex
	// home; Linux and macOS read /etc/codex.
	"codex/managed-config": {withGOOS(relocCodexHome, "windows")},
	// Cline (S-6): the shared MCP file every current Cline client reads, the
	// provider file the CLI launcher routes through, the CLI's global
	// settings, and the extension's global state (the route lever, IDE-8).
	"cline/mcp-settings":        {clineFileRule("CLINE_MCP_SETTINGS_PATH"), relocClineDataDir, relocClineDir},
	"cline-cli/mcp-settings":    {clineFileRule("CLINE_MCP_SETTINGS_PATH"), relocClineDataDir, relocClineDir},
	"cline-cli/providers":       {clineFileRule("CLINE_PROVIDER_SETTINGS_PATH"), relocClineDataDir, relocClineDir},
	"cline-cli/global-settings": {clineFileRule("CLINE_GLOBAL_SETTINGS_PATH"), relocClineDataDir, relocClineDir},
	"cline/global-state":        {relocClineDataDir, relocClineDir},

	// The 2026-10-21 wave (surface-gap lane w4-catalog, S-17; location
	// matrix Part 7). Declared here for the Wave 4 writers; no writer
	// follows them yet.
	"autohand/user-config":          {relocAutohandConfig, relocAutohandHome},
	"autohand/trusted-workspaces":   {relocAutohandHome},
	"cortex-code/user-settings":     {relocCortexHome, relocSnowflakeHome},
	"cortex-code/user-hooks":        {relocCortexHome, relocSnowflakeHome},
	"cortex-code/user-mcp":          {relocCortexHome, relocSnowflakeHome},
	"cortex-code/permissions":       {relocCortexHome, relocSnowflakeHome},
	"cortex-code/credential-cache":  {relocCortexHome, relocSnowflakeHome},
	"cortex-code/connections":       {relocSnowflakeHome},
	"cortex-code/snowflake-config":  {relocSnowflakeHome},
	"codebuddy/user-settings":       {relocCodeBuddyConfigDir},
	"codebuddy/user-local-settings": {relocCodeBuddyConfigDir},
	"codebuddy/user-mcp":            {relocCodeBuddyConfigDir},
	"codebuddy/user-mcp-alt":        {relocCodeBuddyConfigDir},
	"codebuddy/user-models":         {relocCodeBuddyConfigDir},
	"deepagents-code/user-config":   {relocDeepAgentsHome},
	"deepagents-code/user-hooks":    {relocDeepAgentsHome},
	"deepagents-code/user-mcp":      {relocDeepAgentsHome},
	"deepagents-code/auth":          {relocDeepAgentsHome},
	"deepagents-code/hooks-trust":   {relocDeepAgentsHome},
	"dimcode/user-config":           {relocDimCodeHome},
	"dimcode/user-hooks":            {relocDimCodeHome},
	"dimcode/hooks-disabled":        {relocDimCodeHome},
	"dimcode/user-mcp":              {relocDimCodeHome},
	"dimcode/providers":             {relocDimCodeHome},
	"dimcode/auth":                  {relocDimCodeHome},
	"dirac/global-state":            {relocDiracDataDirNot, relocDiracDir},
	"dirac/secrets":                 {relocDiracDataDirNot, relocDiracDir},
	"dirac/workspace-state":         {relocDiracDataDirNot, relocDiracDir},
	"dirac/remote-config-cache":     {relocDiracDataDirNot, relocDiracDir},
	"dirac/global-hooks":            {relocDiracHooksNot},
	"kimchi/harness-settings":       relocKimchiHarnessNot,
	"kimchi/harness-models":         relocKimchiHarnessNot,
	"kimchi/harness-auth":           relocKimchiHarnessNot,
	"kimchi/harness-trust":          relocKimchiHarnessNot,
	"kimchi/harness-bash-hooks":     relocKimchiHarnessNot,
	"kimchi/harness-mcp":            relocKimchiHarnessNot,
	"vtcode/user-legacy":            {relocVTCodeHome},
	"vtcode/user-config":            relocVTCodeConfig,

	// Wave 4 per-tool homes (lane w4-homes-b; relocate_homes.go holds the
	// rules and their grounding).
	"gemini-cli/user-settings":       {relocGeminiCLIHome},
	"qwen-code/user-settings":        {relocQwenHome},
	"goose/user-config":              relocGoose,
	"goose/user-permissions":         relocGoose,
	"goose/user-secrets":             relocGoose,
	"goose/tool-permissions-state":   relocGoose,
	"pi/auth":                        {relocPiAgentDir},
	"pi/keybindings":                 {relocPiAgentDir},
	"pi/managed-install":             {relocPiAgentDir},
	"pi/trust":                       {relocPiAgentDir},
	"pi/user-mcp":                    {relocPiAgentDir},
	"pi/user-models":                 {relocPiAgentDir},
	"pi/user-settings":               {relocPiAgentDir},
	"prime-agent/auth":               {relocPrimeAgentDir},
	"prime-agent/mcp-catalog":        {relocPrimeAgentDir},
	"prime-agent/user-models":        {relocPrimeAgentDir},
	"prime-agent/user-settings":      {relocPrimeAgentDir},
	"hermes/auth":                    relocHermes,
	"hermes/observer-plugin":         relocHermes,
	"hermes/shell-hooks-allowlist":   relocHermes,
	"hermes/user-config":             relocHermes,
	"hermes/user-env":                relocHermes,
	"opencode/user-config":           {relocOpencodeConfigDirNot, relocOpencodeXDG},
	"opencode/user-tui":              {relocOpencodeConfigDirNot, relocOpencodeXDG},
	"kilo-code-cli/user-config":      {relocKiloConfigDirNot, relocKiloXDG},
	"kilo-code/user-config":          {relocKiloConfigDirNot, relocKiloXDG},
	"grok/user-config":               {relocGrokHome},
	"grok/user-hooks":                {relocGrokHome},
	"grok/user-managed-config":       {relocGrokHome},
	"grok/user-requirements":         {relocGrokHome},
	"grok/user-sandbox":              {relocGrokHome},
	"grok/auth":                      {relocGrokHome},
	"grok/settings-cache":            {relocGrokHome},
	"qoder/user-settings":            {relocQoderConfigDir},
	"copilot-cli/user-settings":      {relocCopilotHome},
	"copilot-cli/app-state":          {relocCopilotHome},
	"copilot-cli/lsp-config":         {relocCopilotHome},
	"copilot-cli/permissions-state":  {relocCopilotHome},
	"copilot-cli/user-mcp":           {relocCopilotHome},
	"copilot-cli/providers":          {relocCopilotProviders, relocCopilotHome},
	"mistral-code/user-config":       {relocVibeHome},
	"mistral-code/user-hooks":        {relocVibeHome},
	"mistral-code/trusted-folders":   {relocVibeHome},
	"mistral-code/dotenv":            {relocVibeHome},
	"mistral-code/connector-cache":   {relocVibeHome},
	"junie/user-config":              {relocJunieHome},
	"junie/user-settings":            {relocJunieHome},
	"junie/allowlist":                {relocJunieHome},
	"junie/secure-credentials":       {relocJunieHome},
	"open-interpreter/user-config":   {relocInterpreterHome},
	"kimi-code/user-config":          {relocKimiCodeHome},
	"kimi-code/user-mcp":             {relocKimiCodeHome},
	"kimi-code/user-tui":             {relocKimiCodeHome},
	"crush/user-json":                {relocCrushGlobalConfig, relocCrushXDGConfig},
	"crush/user-crushrc":             {relocCrushGlobalConfig, relocCrushXDGConfig},
	"crush/state":                    relocCrushData,
	"kiro-cli/user-cli":              {relocKiroHome},
	"kiro-cli/user-hooks":            {relocKiroHome},
	"kiro-cli/user-mcp":              {relocKiroHome},
	"kiro-cli/user-permissions":      {relocKiroHome},
	"kiro-cli/workspace-permissions": {relocKiroHome},
	"devin/user-config":              relocDevinXDG,
	"devin/user-mcp":                 relocDevinXDG,
}

// The 2026-10-21 wave rules (lane w4-catalog). Each cites the location
// matrix row that grounds it (Part 7, vendor source per row).
var (
	relocAutohandConfig = Relocation{
		Env: "AUTOHAND_CONFIG", Semantics: RelocFileNotDir, Grounding: matrixE("section 1 (src/config.ts detectConfigPath)"),
		Note: "Names the config file itself; --config beats it for one run.",
	}
	relocAutohandHome = Relocation{
		Env: "AUTOHAND_HOME", Semantics: RelocExactDir, Anchor: "~/.autohand", Grounding: matrixE("section 1 (src/constants.ts)"),
		Note: "Moves the whole home and the config.* search. On Windows a value under \\Windows is ignored by the vendor, which this rule does not model.",
	}
	relocCortexHome = Relocation{
		Env: "CORTEX_HOME", Semantics: RelocExactDir, Anchor: "~/.snowflake/cortex",
		Grounding: Grounding{Kind: GroundAdapterDoc, Source: "docs/cortexcode-adapter.md section 2 (v1.2.18 bundle storage-root resolver)", Date: wave1021Date},
		Note:      "Bundle-grounded only (UNV in the vendor docs, matrix section 3); checked before SNOWFLAKE_HOME.",
	}
	relocSnowflakeHome = Relocation{
		Env: "SNOWFLAKE_HOME", Semantics: RelocExactDir, Anchor: "~/.snowflake", Grounding: matrixE("section 3 (cortex-code settings page)"),
		Note: "Moves ~/.snowflake (the cortex data home and the connection files).",
	}
	relocCodeBuddyConfigDir = Relocation{
		Env: "CODEBUDDY_CONFIG_DIR", Semantics: RelocExactDir, Anchor: "~/.codebuddy", Grounding: matrixE("section 4 (codebuddy.cn cli settings / env-vars)"),
		Note: "Moves settings, models and MCP; since 2.125.4 also ~/.codebuddy.json, which sits beside the anchor and carries no rule.",
	}
	relocDeepAgentsHome = Relocation{
		Env: "DEEPAGENTS_HOME", Semantics: RelocTildeExpand, Anchor: "~/.deepagents", Grounding: matrixE("section 5 (deepagents config-file page)"),
		Note: "An absolute path or one beginning with ~/ (shell env only).",
	}
	relocDimCodeHome = Relocation{
		Env: "DIMCODE_HOME", Semantics: RelocAppendIfMissing, Anchor: "~/.dimcode/v2", Sub: "v2",
		Grounding: Grounding{Kind: GroundAdapterDoc, Source: "internal/adapter/dimcode/store.go (binary-grounded); " + wave1021Matrix + " item 6", Date: wave1021Date},
		Note:      "The vendor docs say the home is $DIMCODE_HOME as-is; the binary appends v2 unless the value already ends in v2.",
	}
	relocDiracDir = Relocation{
		Env: "DIRAC_DIR", Semantics: RelocExactDir, Anchor: "~/.dirac", Grounding: matrixE("section 7 (src/shared/storage/storage-context.ts)"),
		Note: "Moves the data and settings home; --config sets it for one invocation.",
	}
	relocDiracDataDirNot = Relocation{
		Env: "DIRAC_DATA_DIR", Semantics: RelocDoesNotMoveArtifact, Grounding: matrixE("section 7 (cli/src/utils/path.ts, file-logger.ts)"),
		Note: "Moves only the CLI data and log location, never globalState.json, secrets.json or Hooks (review revision 2).",
	}
	relocDiracHooksNot = Relocation{
		Env: "DIRAC_DIR", Semantics: RelocDoesNotMoveArtifact, Grounding: matrixE("section 7 (src/core/storage/paths.ts getDiracHomePath, directoryEnsurers.ts)"),
		Note: "The global Hooks folder is built on the OS home alone (runtime check 32 open).",
	}
	relocVTCodeHome = Relocation{
		Env: "VTCODE_HOME", Semantics: RelocExactDir, Anchor: "~/.vtcode", Grounding: matrixE("section 10 (vtcode_paths.rs)"),
		Note: "Moves the legacy root only.",
	}
)

// relocKimchiHarnessNot: Kimchi's entry.ts sets both variables to
// ~/.config/kimchi/harness unconditionally, so a user-exported value never
// moves a harness file (matrix item 4).
var relocKimchiHarnessNot = []Relocation{
	{
		Env: "KIMCHI_CODING_AGENT_DIR", Semantics: RelocDoesNotMoveArtifact, Grounding: matrixE("section 8 (src/entry.ts)"),
		Note: "Overridden by entry.ts; Observer's hook writer and adapter still follow it (matrix item 4).",
	},
	{Env: "PI_CODING_AGENT_DIR", Semantics: RelocDoesNotMoveArtifact, Grounding: matrixE("section 8 (src/entry.ts)"), Note: "Overridden by entry.ts."},
}

// relocVTCodeConfig: VTCODE_CONFIG, an absolute directory, replaces the
// platform config dir on every OS; each OS has its own anchor.
var relocVTCodeConfig = []Relocation{
	{Env: "VTCODE_CONFIG", Semantics: RelocExactDir, Anchor: "$XDG_CONFIG_HOME/vtcode", GOOS: "linux", Grounding: matrixE("section 10 (vtcode_paths.rs)"), Note: vtcodeConfigRelocNote},
	{Env: "VTCODE_CONFIG", Semantics: RelocExactDir, Anchor: "~/Library/Application Support/com.vinhnx.vtcode", GOOS: "darwin", Grounding: matrixE("section 10 (vtcode_paths.rs)"), Note: vtcodeConfigRelocNote},
	{Env: "VTCODE_CONFIG", Semantics: RelocExactDir, Anchor: `%APPDATA%\vinhnx\vtcode\config`, GOOS: "windows", Grounding: matrixE("section 10 (vtcode_paths.rs)"), Note: vtcodeConfigRelocNote},
}

const vtcodeConfigRelocNote = "An absolute directory that beats every default. The Wave 0 design names it a file (file_not_dir); the matrix, from vtcode_paths.rs, " +
	"says a directory, which this rule follows. VTCODE_CONFIG_PATH (an explicit file) is a separate, higher layer, not a relocation."

// withGOOS returns r limited to one OS.
func withGOOS(r Relocation, goos string) Relocation {
	r.GOOS = goos
	return r
}

// RelocationsFor returns the relocation rules of one FileRow id (a copy;
// nil when the file never moves).
func RelocationsFor(id string) []Relocation {
	rows := fileRelocations[id]
	if len(rows) == 0 {
		return nil
	}
	return append([]Relocation(nil), rows...)
}

// RelocationVariables returns every variable that moves at least one
// catalogued file (a RelocDoesNotMoveArtifact rule moves nothing) or names
// the directory of one (a variable-only path token, such as
// OPENCODE_CONFIG_DIR's extra config dir), sorted and distinct: the names
// the login-env probe compares (CLI-4).
func RelocationVariables() []string {
	seen := map[string]bool{}
	for _, rules := range fileRelocations {
		for _, r := range rules {
			if r.Semantics != RelocDoesNotMoveArtifact {
				seen[r.Env] = true
			}
		}
	}
	for _, n := range pathTokenVariables() {
		seen[n] = true
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// EnvDrift is one relocation variable whose login-shell value differs from
// this process's (CLI-4): a tool started from the shell reads Login, while
// Observer's writers in this process follow Process.
type EnvDrift struct {
	Name    string
	Login   string
	Process string
}

// RelocationEnvDrift compares names between a login shell's environment and
// this process's, both injected. Only a variable the login shell sets is
// reported (one this process sets alone is the operator's explicit choice
// for the daemon); values are compared after trimming.
func RelocationEnvDrift(names []string, login, process func(string) string) []EnvDrift {
	var out []EnvDrift
	for _, n := range names {
		l, p := strings.TrimSpace(login(n)), strings.TrimSpace(process(n))
		if l != "" && l != p {
			out = append(out, EnvDrift{Name: n, Login: l, Process: p})
		}
	}
	return out
}

// ResolveArtifact resolves one FileRow by id with its relocations applied.
// Writers and inspectors name an artifact this way instead of building a
// path by hand.
func ResolveArtifact(id string, e PathEnv) (ResolvedPath, error) {
	for _, f := range filesTable() {
		if f.ID == id {
			e.Relocate = true
			return ResolvePath(f, e), nil
		}
	}
	return ResolvedPath{}, fmt.Errorf("%w: %q", ErrUnknownArtifact, id)
}

// relocation is one resolution's relocation outcome.
type relocation struct {
	applied bool
	// path is the final, native, absolute path when applied.
	path    string
	env     string
	ignored []string
	// unresolved names the variable whose relative value the tool would use
	// against its own working directory (Relocation.RelativeFallsThrough
	// false): the walk stopped there and the file has no path Observer can
	// name.
	unresolved string
}

// relocate walks the row's rules (fileRelocations) top-down: the first
// variable that is set and accepted applies; each set variable that is
// refused is recorded, and a relative value the tool itself would use stops
// the walk (unresolved).
func (e PathEnv) relocate(f FileRow, raw string) relocation {
	return e.relocateWith(fileRelocations[f.ID], raw)
}

// relocateWith is relocate over an explicit rule list (tests pass their own).
func (e PathEnv) relocateWith(rules []Relocation, raw string) relocation {
	var out relocation
	for _, r := range rules {
		if r.GOOS != "" && r.GOOS != e.goos() {
			continue
		}
		v := strings.TrimSpace(e.env(r.Env))
		if v == "" {
			continue
		}
		apply, known := relocSemantics[r.Semantics]
		if !known {
			out.ignored = append(out.ignored, r.Env+":"+string(RelocIgnoreUnknownSemantics))
			continue
		}
		path, refused := apply(e, r, raw, v)
		if refused != "" {
			out.ignored = append(out.ignored, r.Env+":"+string(refused))
			if refused == RelocIgnoreRelative && !r.RelativeFallsThrough {
				out.unresolved = r.Env
				return out
			}
			continue
		}
		out.applied, out.path, out.env = true, path, r.Env
		return out
	}
	return out
}

// relocSemantics is the semantics table: each entry turns (row path, value)
// into the relocated path or a refusal.
var relocSemantics = map[RelocSemantics]func(e PathEnv, r Relocation, raw, v string) (string, RelocIgnore){
	RelocExactDir: func(e PathEnv, r Relocation, raw, v string) (string, RelocIgnore) {
		return e.replaceAnchor(r, raw, v)
	},
	RelocAbsoluteNotHomeAncestor: func(e PathEnv, r Relocation, raw, v string) (string, RelocIgnore) {
		if e.isAbs(v) && e.isHomeOrAncestor(v) {
			return "", RelocIgnoreHomeAncestor
		}
		return e.replaceAnchor(r, raw, v)
	},
	RelocTildeExpand: func(e PathEnv, r Relocation, raw, v string) (string, RelocIgnore) {
		if (v == "~" || strings.HasPrefix(v, "~/") || strings.HasPrefix(v, `~\`)) && e.Home != "" {
			// The home is the value as set: judge it before Join rewrites
			// its separators (the replaceAnchorSub rule).
			return e.replaceAnchorSub(r, raw, e.Home, v[1:])
		}
		return e.replaceAnchor(r, raw, v)
	},
	RelocFileNotDir: func(e PathEnv, _ Relocation, _, v string) (string, RelocIgnore) {
		if !e.isAbs(v) {
			return "", RelocIgnoreRelative
		}
		return e.native(v), ""
	},
	RelocAppendIfMissing: func(e PathEnv, r Relocation, raw, v string) (string, RelocIgnore) {
		sub := r.Sub
		if e.lastSegment(v) == r.Sub {
			sub = ""
		}
		return e.replaceAnchorSub(r, raw, v, sub)
	},
	RelocDoesNotMoveArtifact: func(PathEnv, Relocation, string, string) (string, RelocIgnore) {
		return "", RelocIgnoreDoesNotMove
	},
	RelocRootPlusSub: func(e PathEnv, r Relocation, raw, v string) (string, RelocIgnore) {
		return e.replaceAnchorSub(r, raw, v, r.Sub)
	},
	RelocAnchorSuffix: func(e PathEnv, r Relocation, raw, v string) (string, RelocIgnore) {
		rest, ok := underAnchor(raw, r.Anchor)
		if !ok {
			return "", RelocIgnoreAnchorMismatch
		}
		expanded, ok := e.expand(r.Anchor + v + rest)
		if !ok {
			return "", RelocIgnoreAnchorMismatch
		}
		return expanded, ""
	},
}

// replaceAnchor swaps the row path's Anchor for the absolute value v.
func (e PathEnv) replaceAnchor(r Relocation, raw, v string) (string, RelocIgnore) {
	rest, ok := underAnchor(raw, r.Anchor)
	if !ok {
		return "", RelocIgnoreAnchorMismatch
	}
	if !e.isAbs(v) {
		return "", RelocIgnoreRelative
	}
	return e.Join(v, rest), ""
}

// replaceAnchorSub is replaceAnchor for a value the rule extends with sub
// ("" for none). Absoluteness is judged on the value as set, before Join
// rewrites its separators for e's OS: a host path pinned to another OS's
// separators is no longer absolute by the host's own rule.
func (e PathEnv) replaceAnchorSub(r Relocation, raw, v, sub string) (string, RelocIgnore) {
	rest, ok := underAnchor(raw, r.Anchor)
	if !ok {
		return "", RelocIgnoreAnchorMismatch
	}
	if !e.isAbs(v) {
		return "", RelocIgnoreRelative
	}
	return e.Join(v, sub, rest), ""
}

// underAnchor returns raw's remainder after anchor when raw is anchor
// itself or a path below it ("~/.claude" never matches "~/.claude.json").
func underAnchor(raw, anchor string) (string, bool) {
	if anchor == "" {
		return "", false
	}
	if raw == anchor {
		return "", true
	}
	if strings.HasPrefix(raw, anchor+"/") || strings.HasPrefix(raw, anchor+`\`) {
		return raw[len(anchor):], true
	}
	return "", false
}

// goos normalizes PathEnv.GOOS the way rawPath reads it.
func (e PathEnv) goos() string {
	switch e.GOOS {
	case "windows", "darwin":
		return e.GOOS
	}
	return "linux"
}

// isAbs reports whether v is an absolute path on the env's OS (a drive or
// UNC path on Windows, a leading "/" elsewhere; the FU-143 ruling, see
// PathEnv.IsAbs), or by PathEnv.IsAbs when a test injects one.
func (e PathEnv) isAbs(v string) bool {
	if e.IsAbs != nil {
		return e.IsAbs(v)
	}
	if e.windows() {
		if strings.HasPrefix(v, `\\`) || strings.HasPrefix(v, "//") {
			return true
		}
		return len(v) >= 3 && v[1] == ':' && (v[2] == '\\' || v[2] == '/')
	}
	return strings.HasPrefix(v, "/")
}

// trimmed is v in native separators without trailing separators (a root
// keeps its own).
func (e PathEnv) trimmed(v string) string {
	n := e.native(v)
	sep := "/"
	if e.windows() {
		sep = `\`
	}
	for len(n) > 1 && strings.HasSuffix(n, sep) && !(e.windows() && len(n) == 3 && n[1] == ':') {
		n = strings.TrimSuffix(n, sep)
	}
	return n
}

// isHomeOrAncestor reports whether the absolute v is the root, the home
// directory, or an ancestor of the home directory. Windows compares
// case-insensitively.
func (e PathEnv) isHomeOrAncestor(v string) bool {
	cv, ch := e.trimmed(v), e.trimmed(e.Home)
	if e.windows() {
		cv, ch = strings.ToLower(cv), strings.ToLower(ch)
	}
	sep := "/"
	if e.windows() {
		sep = `\`
	}
	isRoot := cv == "/" || (e.windows() && ((len(cv) == 3 && cv[1] == ':') || cv == `\\` || isUNCShareRoot(cv)))
	if isRoot || cv == ch {
		return true
	}
	return ch != "" && strings.HasPrefix(ch, strings.TrimSuffix(cv, sep)+sep)
}

// isUNCShareRoot reports whether a native Windows path is a UNC share root
// (\\server\share), the root of that filesystem.
func isUNCShareRoot(v string) bool {
	if !strings.HasPrefix(v, `\\`) {
		return false
	}
	return len(strings.Split(strings.TrimPrefix(v, `\\`), `\`)) <= 2
}

// lastSegment is v's final path segment.
func (e PathEnv) lastSegment(v string) string {
	t := e.trimmed(v)
	if i := strings.LastIndexAny(t, `/\`); i >= 0 {
		return t[i+1:]
	}
	return t
}

// AnchorMove is how a relocation rule moves the directory a row's path is
// anchored at (FU-142): Anchor as the catalogue spells it ("~/.claude"), Dir
// the absolute native directory that replaces it, Env the variable. With
// Unresolved the variable holds a relative value, so the tool reads a
// directory Observer cannot name and Dir is "".
type AnchorMove struct {
	Anchor     string
	Dir        string
	Env        string
	Unresolved bool
}

// RelocatedAnchor reports how e's relocation variables move row f's anchor
// directory: the rule ResolvePath applies to the row, as a directory move a
// caller that walks under the anchor (the instruction scan, a glob target)
// can follow. ok is false when nothing moves the row: Relocate is off, no
// rule's variable is set or accepted, or the rule that applies names the
// file itself (no anchor).
func RelocatedAnchor(f FileRow, e PathEnv) (AnchorMove, bool) {
	if !e.Relocate {
		return AnchorMove{}, false
	}
	raw := e.rawPath(f.Paths)
	if raw == "" {
		return AnchorMove{}, false
	}
	rules := fileRelocations[f.ID]
	rel := e.relocateWith(rules, raw)
	env := rel.env
	if rel.unresolved != "" {
		env = rel.unresolved
	} else if !rel.applied {
		return AnchorMove{}, false
	}
	for _, r := range rules {
		if r.Env != env || r.Anchor == "" || (r.GOOS != "" && r.GOOS != e.goos()) {
			continue
		}
		if _, under := underAnchor(raw, r.Anchor); !under {
			continue
		}
		if rel.unresolved != "" {
			return AnchorMove{Anchor: r.Anchor, Env: env, Unresolved: true}, true
		}
		dir, refused := relocSemantics[r.Semantics](e, r, r.Anchor, strings.TrimSpace(e.env(r.Env)))
		if refused != "" || dir == "" {
			return AnchorMove{}, false
		}
		return AnchorMove{Anchor: r.Anchor, Dir: dir, Env: env}, true
	}
	return AnchorMove{}, false
}
