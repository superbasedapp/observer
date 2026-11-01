package agentconfig

// The per-tool home rules of Wave 4 (surface-gap lane w4-homes-b; review
// S-17, CLI-4, W-4, OI-1 and FU-5). Each rule cites the location-matrix
// section that grounds it, and that section cites the vendor doc or source
// URL. The rules are referenced from fileRelocations (relocate.go), the one
// owner. A tool whose relocation the matrix marks UNV (muse, poolside) has
// no rule here.

const (
	homesDate   = "2026-10-26"
	homesMatrix = "docs/audits/surface-settings-location-matrix-2026-10-25.md"
)

// matrixAt grounds a rule in one section of the location matrix plus the
// vendor URL that section cites.
func matrixAt(section, vendor string) Grounding {
	return Grounding{Kind: GroundSource, Source: homesMatrix + " " + section + "; " + vendor, Date: homesDate}
}

// matrixDocAt is matrixAt for a section grounded in vendor docs only.
func matrixDocAt(section, vendor string) Grounding {
	return Grounding{Kind: GroundDoc, Source: homesMatrix + " " + section + "; " + vendor, Date: homesDate}
}

// exactDir is one RelocExactDir rule.
func exactDir(env, anchor string, g Grounding, note string) Relocation {
	return Relocation{Env: env, Semantics: RelocExactDir, Anchor: anchor, Grounding: g, Note: note}
}

// xdgDir is an exactDir rule for an XDG base-directory variable. The XDG
// spec has a relative value treated as invalid and ignored, so a refused
// value falls through to the default (RelativeFallsThrough).
func xdgDir(env, anchor string, g Grounding, note string) Relocation {
	r := exactDir(env, anchor, g, note)
	r.RelativeFallsThrough = true
	return r
}

// perOS returns r once per OS with that OS's anchor (an entry left empty
// is skipped).
func perOS(r Relocation, linux, darwin, windows string) []Relocation {
	var out []Relocation
	for _, a := range []struct{ goos, anchor string }{{"linux", linux}, {"darwin", darwin}, {"windows", windows}} {
		if a.anchor == "" {
			continue
		}
		c := r
		c.Anchor, c.GOOS = a.anchor, a.goos
		out = append(out, c)
	}
	return out
}

// relocChain concatenates rule lists in walk order.
func relocChain(lists ...[]Relocation) []Relocation {
	var out []Relocation
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

var (
	// gemini-cli: GEMINI_CLI_HOME is the root that holds .gemini.
	relocGeminiCLIHome = exactDir("GEMINI_CLI_HOME", "~",
		matrixAt("Part 6 section 1", "https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/cli/src/config/settings.ts"),
		"Replaces the home directory that holds .gemini, so the user file is $GEMINI_CLI_HOME/.gemini/settings.json.")

	// qwen-code: Storage.getGlobalQwenDir.
	relocQwenHome = exactDir("QWEN_HOME", "~/.qwen",
		matrixAt("Part 6 section 2", "https://raw.githubusercontent.com/QwenLM/qwen-code/main/packages/core/src/config/storage.ts"),
		"Moves the ~/.qwen directory.")

	// pi: config.ts getAgentDir.
	relocPiAgentDir = exactDir("PI_CODING_AGENT_DIR", "~/.pi/agent",
		matrixAt("Part 6 section 8", "https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/config.ts"),
		"Moves the agent dir (~/.pi/agent) on every OS.")

	// prime-agent: crates/pa-daemon/src/paths.rs (tilde-expanded).
	relocPrimeAgentDir = Relocation{
		Env: "PRIME_AGENT_CODING_AGENT_DIR", Semantics: RelocTildeExpand, Anchor: "~/.prime/agent",
		Grounding: matrixAt("Part 6 section 9", "https://github.com/PrimeIntellect-ai/prime-agent/blob/main/crates/pa-daemon/src/paths.rs"),
		Note:      "Moves the agent dir; a leading ~ is expanded. ~/.prime/config.json stays put.",
	}

	// opencode: OPENCODE_CONFIG_DIR ADDS a config directory (FU-103): the
	// MAC-4 macOS run had opencode 1.19.4 list the MCP servers of both the
	// global opencode.json and $OPENCODE_CONFIG_DIR/opencode.json, with
	// `opencode debug paths` still naming the global dir, which is the
	// docs' reading and not the source reading the matrix took. Like Kilo's
	// KILO_CONFIG_DIR it never moves the global files; the extra file is
	// its own row, opencode/config-dir-config, rooted at the variable-only
	// $OPENCODE_CONFIG_DIR path token. XDG_CONFIG_HOME roots the global dir
	// on every OS.
	relocOpencodeConfigDirNot = Relocation{
		Env: "OPENCODE_CONFIG_DIR", Semantics: RelocDoesNotMoveArtifact,
		Grounding: mac4Live("opencode 1.19.4 `opencode mcp list` showed the global and the $OPENCODE_CONFIG_DIR server together, and `opencode debug paths` kept the global config dir; " +
			"https://opencode.ai/docs/config says the same"),
		Note: "Adds one more config directory; the global opencode.json and tui.json are still read where they are.",
	}
	relocOpencodeXDG = xdgDir("XDG_CONFIG_HOME", "~/.config",
		matrixAt("Part 6 section 3", "https://github.com/anomalyco/opencode/blob/dev/packages/util/src/global-roots.ts"),
		"The global root is $XDG_CONFIG_HOME/opencode on every OS, Windows included.")

	// kilo: xdg-basedir on every OS; KILO_CONFIG_DIR is an EXTRA config
	// dir (precedence step 5), so it never moves kilo.jsonc.
	relocKiloXDG = xdgDir("XDG_CONFIG_HOME", "~/.config",
		matrixAt("Part 5 section 3", "https://github.com/Kilo-Org/kilocode/blob/main/packages/opencode/src/config/config.ts"),
		"Global.Path.config is xdg-basedir's config dir on every OS.")
	relocKiloConfigDirNot = Relocation{
		Env: "KILO_CONFIG_DIR", Semantics: RelocDoesNotMoveArtifact,
		Grounding: matrixAt("Part 5 section 3", "https://github.com/Kilo-Org/kilocode/blob/main/packages/opencode/src/config/paths.ts"),
		Note:      "Adds one more config directory to the search; the global kilo.jsonc is still read where it is.",
	}

	// grok: "To configure the default home directory, you can set $GROK_HOME".
	relocGrokHome = exactDir("GROK_HOME", "~/.grok",
		matrixDocAt("Part 6 section 6", "https://docs.x.ai/build/settings"),
		"The settings page names GROK_HOME the home directory and shows $GROK_HOME/config.toml; the hooks page names only ~/.grok/hooks, so the hooks dir following it is read from the home-directory wording (live check owed).")

	// qoder: %QODER_CONFIG_DIR%\settings.json else ~\.qoder\settings.json.
	relocQoderConfigDir = exactDir("QODER_CONFIG_DIR", "~/.qoder",
		matrixDocAt("Part 4 section 5", "https://docs.qoder.com/en/cli/settings-reference"),
		"Moves the user settings directory.")

	// copilot-cli: COPILOT_HOME (the legacy --config-dir flag wins).
	relocCopilotHome = exactDir("COPILOT_HOME", "~/.copilot",
		matrixDocAt("Part 3 section 5", "https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference"),
		"Moves ~/.copilot (settings, hooks, MCP, state). The --config-dir flag beats it for one run and is not modelled.")
	relocCopilotProviders = Relocation{
		Env: "COPILOT_PROVIDERS_CONFIG", Semantics: RelocFileNotDir,
		Grounding: matrixDocAt("Part 3 section 5", "https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference"),
		Note:      "Names the BYOK providers file itself.",
	}

	// vibe: vibe/core/paths/_vibe_home.py.
	relocVibeHome = exactDir("VIBE_HOME", "~/.vibe",
		matrixAt("Part 5 section 6", "https://github.com/mistralai/mistral-vibe/blob/main/vibe/core/paths/_vibe_home.py"),
		"Moves ~/.vibe (config, hooks, trust store, .env).")

	// junie: JUNIE_HOME (JUNIE_CONFIG_LOCATION adds an extra file and is not
	// a relocation; JUNIE_MCP_LOCATIONS governs MCP separately).
	relocJunieHome = exactDir("JUNIE_HOME", "~/.junie",
		matrixDocAt("Part 4 section 7", "https://junie.jetbrains.com/docs/environment-variables.html"),
		"Moves ~/.junie. JUNIE_CONFIG_LOCATION names an extra config file and is not modelled as a relocation.")

	// open-interpreter: codex-rs/utils/home-dir selects INTERPRETER_HOME.
	relocInterpreterHome = exactDir("INTERPRETER_HOME", "~/.openinterpreter",
		matrixAt("Part 3 section 3", "https://raw.githubusercontent.com/openinterpreter/openinterpreter/main/codex-rs/utils/home-dir/src/lib.rs"),
		"Moves ~/.openinterpreter (config.toml, hooks.json). The desktop codex-home is separate and UNV.")

	// kimi-code: KIMI_CODE_HOME, else ~/.kimi-code.
	relocKimiCodeHome = exactDir("KIMI_CODE_HOME", "~/.kimi-code",
		matrixDocAt("Part 6 section 11", "https://moonshotai.github.io/kimi-code/en/configuration/config-files.html"),
		"Moves the data dir that holds config.toml, mcp.json and tui.toml.")

	// crush: GlobalConfig() = $CRUSH_GLOBAL_CONFIG/crush.json >
	// $XDG_CONFIG_HOME/crush > ~/.config/crush, the same chain on every OS.
	relocCrushGlobalConfig = exactDir("CRUSH_GLOBAL_CONFIG", "~/.config/crush",
		matrixAt("Part 6 section 4", "https://github.com/charmbracelet/crush/blob/main/internal/config/load.go"),
		"Names a DIRECTORY that holds crush.json and crushrc. CRUSH_CONFIG is not read by Crush.")
	relocCrushXDGConfig = xdgDir("XDG_CONFIG_HOME", "~/.config",
		matrixAt("Part 6 section 4", "https://github.com/charmbracelet/crush/blob/main/internal/home/home.go"),
		"home.Config() honours XDG_CONFIG_HOME on every OS.")

	// kiro-cli: an absolute path that is not root, home or an ancestor of
	// home; Kiro itself ignores any other value (S-11), so a refused value
	// falls through to the default.
	relocKiroHome = Relocation{
		Env: "KIRO_HOME", Semantics: RelocAbsoluteNotHomeAncestor, Anchor: "~/.kiro", RelativeFallsThrough: true,
		Grounding: matrixDocAt("Part 4 section 3", "https://kiro.dev/docs/cli/v3/hooks-migration/"),
		Note:      "Moves ~/.kiro for the CLI. Kiro Crew's ~/.kiro/crew follows KIROCREW_HOME instead and carries no rule here.",
	}
)

// relocDevinXDG: the MCP page gives ~/.config/devin "(or
// $XDG_CONFIG_HOME/devin/)" for the non-Windows column (review S-10, the
// lane w2-f writer ladder for Linux and macOS); Windows is %APPDATA%\devin.
var relocDevinXDG = perOS(Relocation{
	Env: "XDG_CONFIG_HOME", Semantics: RelocExactDir, RelativeFallsThrough: true,
	Grounding: matrixDocAt("Part 4 section 2", "https://docs.devin.ai/desktop/cascade/mcp"),
	Note:      "Linux and macOS; Windows uses %APPDATA%\\devin.",
}, "~/.config", "~/.config", "")

// relocGoose: GOOSE_PATH_ROOT re-roots config as <root>/config (paths.rs);
// otherwise etcetera's Xdg strategy (Linux, macOS) honours XDG_CONFIG_HOME.
var relocGoose = relocChain(
	perOS(Relocation{
		Env: "GOOSE_PATH_ROOT", Semantics: RelocRootPlusSub, Sub: "config",
		Grounding: matrixAt("Part 6 section 5", "https://github.com/aaif-goose/goose/blob/main/crates/goose/src/config/paths.rs"),
		Note:      "An absolute root; config lives in <root>/config.",
	}, "~/.config/goose", "~/.config/goose", `%APPDATA%\Block\goose\config`),
	perOS(Relocation{
		Env: "XDG_CONFIG_HOME", Semantics: RelocExactDir, RelativeFallsThrough: true,
		Grounding: matrixAt("Part 6 section 5", "https://github.com/aaif-goose/goose/blob/main/crates/goose/src/config/paths.rs"),
		Note:      "etcetera's Xdg strategy on Linux and macOS; Windows uses the Windows strategy (%APPDATA%).",
	}, "~/.config", "~/.config", ""),
)

// relocHermes: HERMES_HOME (expandvars then expanduser) beats the platform
// default; HERMES_DATA_DIR_SUFFIX is appended to the DEFAULT directory name
// only (hermes_constants._platform_default_hermes_home), so it comes second.
// Profiles (--profile, the sticky <root>/active_profile file) are read by
// the caller, not modelled here.
var relocHermes = relocChain(
	perOS(Relocation{
		Env: "HERMES_HOME", Semantics: RelocTildeExpand,
		Grounding: matrixAt("Part 6 section 10", "https://github.com/NousResearch/hermes-agent/blob/main/hermes_constants.py"),
		Note:      "expandvars is not modelled; a leading ~ is expanded.",
	}, "~/.hermes", "~/.hermes", `%LOCALAPPDATA%\hermes`),
	perOS(Relocation{
		Env: "HERMES_DATA_DIR_SUFFIX", Semantics: RelocAnchorSuffix,
		Grounding: matrixAt("Part 6 section 10", "https://github.com/NousResearch/hermes-agent/blob/main/hermes_constants.py"),
		Note:      "A literal suffix on the default directory name (.hermes<suffix>, hermes<suffix> on Windows); ignored when HERMES_HOME is set.",
	}, "~/.hermes", "~/.hermes", `%LOCALAPPDATA%\hermes`),
)

// relocCrushData: GlobalConfigData() = $CRUSH_GLOBAL_DATA/crush.json >
// $XDG_DATA_HOME/crush > the per-OS data dir.
var relocCrushData = relocChain(
	perOS(Relocation{
		Env: "CRUSH_GLOBAL_DATA", Semantics: RelocExactDir,
		Grounding: matrixAt("Part 6 section 4", "https://github.com/charmbracelet/crush/blob/main/internal/config/load.go"),
		Note:      "Names the data DIRECTORY; its crush.json outranks the user file.",
	}, "~/.local/share/crush", "~/.local/share/crush", `%LOCALAPPDATA%\crush`),
	perOS(Relocation{
		Env: "XDG_DATA_HOME", Semantics: RelocExactDir, RelativeFallsThrough: true,
		Grounding: matrixAt("Part 6 section 4", "https://github.com/charmbracelet/crush/blob/main/internal/config/load.go"),
		Note:      "Linux and macOS; Windows uses %LOCALAPPDATA%.",
	}, "~/.local/share", "~/.local/share", ""),
)
