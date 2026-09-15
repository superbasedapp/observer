package integration

// guiHosts is the editor-HOST launch table: IDEs that have no adapter row
// of their own but host the extensions/plugins whose sessions Observer's
// adapters capture (inventory §4.1 "VS Code as a host", "JetBrains IDEs as
// a host"). One launch row here covers every vendor extension the host
// runs. Keyed by GUILaunchSpec.ID; the ID must not collide with any
// registry row's GUI.ID (pinned by TestGUILaunchIDsUnique).
//
// Rows are added only with a grounded executable layout — see
// GUILaunchSpec's honesty rule. Grounding for the two rows below
// (2026-09-03): the Windows install layouts were read off THIS box
// (`ls %LOCALAPPDATA%\Programs`, `ls %ProgramFiles%\JetBrains`), the
// winget ids from a live `winget search --id <id> --exact --source winget`,
// and the macOS .app bundle names from the Homebrew cask API
// (formulae.brew.sh/api/cask/<token>.json → artifacts[].app).
var guiHosts = map[string]GUILaunchSpec{
	// THE highest-leverage row (plan §2.2): one launch covers 13 adapter
	// surfaces that all run as VS Code extensions.
	"vscode": {
		ID:      "vscode",
		Label:   "Visual Studio Code",
		Surface: "ide",
		Binary: BinaryResolveSpec{
			// The REAL executable, never the `bin\code.cmd` PATH shim: a
			// .cmd is a batch script and spawning it allocates a console
			// window, which is exactly what a detached GUI launch must not
			// do (gui.go's Binary doc). On unix the vendor's own `code` IS
			// the launcher script and is the documented spelling
			// (inventory §4.1 "`code` / `code.cmd` / `Code.exe`").
			Names: BinaryNames{
				Unix:    []string{"code"},
				Windows: []string{"Code.exe"},
			},
			ProbeDirs: []ProbeDir{
				// User Installer — grounded on this box 2026-09-03
				// (Code.exe + bin/{code,code.cmd} present).
				{OS: ProbeWindows, Rel: "AppData/Local/Programs/Microsoft VS Code"},
				// System Installer — the vendor's other Windows layout.
				// NOT present on this box (only JetBrains lives under
				// %ProgramFiles% here); listed because the resolver skips a
				// missing dir harmlessly and an all-users install is common.
				{OS: ProbeWindows, Rel: "Microsoft VS Code", EnvRoot: "ProgramFiles"},
			},
			Installs: []InstallHint{
				{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "--id", "Microsoft.VisualStudioCode", "-e", "--source", "winget"}, Display: "winget install --id Microsoft.VisualStudioCode -e --source winget"},
				{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "visual-studio-code"}, Display: "brew install --cask visual-studio-code"},
			},
			InstallNote: "no grounded Linux channel: Microsoft ships .deb/.rpm/tarball downloads plus a " +
				"third-party snap, and which one applies depends on the distro — a single argv would be a " +
				"guess, so none is offered (see code.visualstudio.com/docs/setup/linux).",
		},
		DarwinApp:      "Visual Studio Code",
		ProjectDirArgv: true,
		Wrap: WrapSpec{
			Kind: WrapChildEnv,
			Env: []WrapEnvVar{
				{Name: "ANTHROPIC_BASE_URL", Suffix: ""},
				{Name: "OPENAI_BASE_URL", Suffix: "/v1"},
				{Name: "GOOGLE_GEMINI_BASE_URL", Suffix: ""},
			},
			ColdStartOnly: true,
			Reason: "cold start ONLY: `code <dir>` hands off to an already-running window, and that " +
				"process never re-reads its environment (inventory §4.3 open question 1). The wrap reaches " +
				"only the extensions that SPAWN a vendor CLI and inherit the process env (Claude Code " +
				"`anthropic.claude-code`, the Codex extension, the Gemini companion); extensions whose base " +
				"URL lives in the VS Code `state.vscdb` settings store (Cline, legacy Kilo, Cursor BYOK) are " +
				"unaffected — inventory §4.1/§4.2. Env inheritance into a GUI-launched VS Code is NOT " +
				"live-verified.",
		},
		Hosts: []string{
			"claude-code", "codex", "cline", "kilo-code", "kilo-code-cli", "copilot",
			"gemini-cli", "qwen-code", "kimi-code", "mistral-code", "droid", "opencode",
			"command-code",
		},
		Grounded: true,
		Note: "Windows layout grounded on this box 2026-09-03: " +
			"%LOCALAPPDATA%\\Programs\\Microsoft VS Code\\Code.exe (+ bin\\code, bin\\code.cmd). macOS " +
			"bundle \"Visual Studio Code.app\" grounded from the Homebrew cask `visual-studio-code`. " +
			"Hosts lists the 13 registry adapters whose extensions run inside VS Code (inventory §2.1-§2.13); " +
			"extensions are never launch rows of their own (plan §0 consequence 3).",
	},

	// Second-highest leverage (plan §2.2 / inventory §4.1): the JetBrains
	// ACP registry means one IDE row covers the whole ACP agent family.
	// Scoped to IntelliJ IDEA because that is the product grounded on this
	// box; the other JetBrains IDEs (PyCharm, GoLand, …) are the same shape
	// with a different exe stem and would each be their own row.
	"jetbrains-idea": {
		ID:      "jetbrains-idea",
		Label:   "IntelliJ IDEA",
		Surface: "ide",
		Binary: BinaryResolveSpec{
			// idea64.exe is the real launcher; bin\idea.bat is the batch
			// form and is deliberately not listed (console window).
			Names: BinaryNames{
				Unix:    []string{"idea"},
				Windows: []string{"idea64.exe"},
			},
			ProbeDirs: []ProbeDir{
				// ONE glob segment, expanded by toolresolve's expandGlobDirs
				// (filepath.Glob over the whole absolute path, so an interior
				// `*` segment works and EnvRoot dirs are glob-expanded too).
				// Grounded on this box 2026-09-03:
				// C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2025.2.6.2\bin\idea64.exe
				{OS: ProbeWindows, Rel: "JetBrains/IntelliJ IDEA*/bin", EnvRoot: "ProgramFiles"},
			},
			Installs: []InstallHint{
				{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "--id", "JetBrains.IntelliJIDEA.Community", "-e", "--source", "winget"}, Display: "winget install --id JetBrains.IntelliJIDEA.Community -e --source winget"},
				{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "intellij-idea-ce"}, Display: "brew install --cask intellij-idea-ce"},
			},
			InstallNote: "no grounded Linux channel: JetBrains ships a tarball plus a third-party snap; " +
				"the Toolbox App is the vendor's own installer and has no scriptable one-liner — see " +
				"jetbrains.com/idea/download.",
		},
		DarwinApp:      "IntelliJ IDEA CE",
		ProjectDirArgv: true,
		Wrap: WrapSpec{
			Kind: WrapChildEnv,
			Env: []WrapEnvVar{
				{Name: "ANTHROPIC_BASE_URL", Suffix: ""},
				{Name: "OPENAI_BASE_URL", Suffix: "/v1"},
				{Name: "GOOGLE_GEMINI_BASE_URL", Suffix: ""},
			},
			ColdStartOnly: true,
			Reason: "cold start ONLY: a re-used IDE instance never re-reads its environment " +
				"(inventory §4.3 open question 1). The wrap reaches only the plugins that SPAWN a vendor " +
				"CLI and inherit the IDE's env — Junie, the Kimi JB PTY wrapper, and every agent " +
				"registered through the JetBrains ACP registry (~/.jetbrains/acp.json: Factory/droid, " +
				"Qwen, Mistral, Grok) — inventory §2.9/§1.5 finding 5. Copilot and Gemini Code Assist are " +
				"WrapNone-class inside the IDE (inventory §4.2) and are not listed under Hosts. Env " +
				"inheritance into a GUI-launched IDE is NOT live-verified.",
		},
		Hosts: []string{
			// copilot-cli joined 2026-09-03: the AI Assistant's
			// `github-copilot` ACP agent IS Copilot CLI (1.0.79 live),
			// writing ~/.copilot/session-state with workspace.yaml
			// client_name "JetBrains.IntelliJ IDEA".
			"junie", "claude-code", "codex", "kimi-code", "qwen-code", "mistral-code",
			"droid", "grok", "copilot-cli",
		},
		Grounded: true,
		Note: "Windows layout grounded on this box 2026-09-03: %ProgramFiles%\\JetBrains\\IntelliJ IDEA " +
			"Community Edition 2025.2.6.2\\bin\\idea64.exe. macOS bundle \"IntelliJ IDEA CE.app\" grounded " +
			"from the Homebrew cask `intellij-idea-ce`. The JetBrains Toolbox apps layout " +
			"(%LOCALAPPDATA%\\JetBrains\\Toolbox\\apps\\*) is NOT probed: this box has only " +
			"%LOCALAPPDATA%\\JetBrains\\IdeaIC2025.2 (the IDE's config/system dir, not a Toolbox install), " +
			"so the Toolbox layout could not be grounded and is deliberately absent rather than guessed. " +
			"Ultimate Edition is a separate exe stem/winget id and would be its own row. " +
			"CAPTURE (batch-3 T1, 2026-09-03): the 2026.2 AI Assistant drives its ACP agents (Junie, " +
			"Claude Agent, Codex, GitHub Copilot) which each write their OWN store, all captured by their " +
			"own adapters; the IDE's aia-task-history/*.agentsession pointer files are read by " +
			"internal/surfaceenrich to stamp ide/jetbrains-idea (hosted, host-wins) on those sessions — " +
			"no JetBrains capture row exists by design (internal/platform/jetbrainshost doc).",
	},
	// Qoder Work (batch-3 T4, 2026-09-03): Alibaba's multi-agent DESKTOP app
	// that DRIVES qodercli (its only runtime per qoder-data.v1.json) and so
	// writes the qoder adapter's own ~/.qoder/projects store — one
	// conversation, byte-identical session/tool ids. It is a host row, not
	// an adapter: its %APPDATA%\com.qoder.app.stable\main.sqlite is read
	// by the qoder adapter ONLY to stamp desktop/qoder-work (hosted,
	// host-wins over the CLI's entrypoint=cli self-report) and, for a Work
	// chat with no CLI twin, to emit the conversation itself.
	"qoder-work": {
		ID:      "qoder-work",
		Label:   "Qoder Work",
		Surface: "desktop",
		Binary: BinaryResolveSpec{
			Names: BinaryNames{
				Windows: []string{"Qoder.exe"},
			},
			ProbeDirs: []ProbeDir{
				// Distinct from the IDE's "Qoder IDE" dir (the `qoder-ide`
				// row on the qoder registry entry).
				{OS: ProbeWindows, Rel: "AppData/Local/Programs/Qoder"},
			},
			InstallNote: "no grounded macOS or Linux channel: no Homebrew cask and no winget package found " +
				"for Qoder Work (checked 2026-09-03); the vendor ships a direct download (qoder.com).",
		},
		// PATH walk disabled: the IDE's bin\qoder shim is on PATH and would
		// resolve case-insensitively against Qoder.exe. Probe dirs only.
		ProbeOnly:      true,
		ProjectDirArgv: false,
		Wrap: WrapSpec{
			Kind: WrapNone,
			Reason: "no base-URL surface: Qoder Work's models are BYOK profiles held encrypted in its own " +
				"main.sqlite (byok_model_credentials — never read) and routed through qodercli, whose " +
				"registry row is native_exempt. Launch yes, wrap no.",
		},
		Hosts:    []string{"qoder"},
		Grounded: true,
		Note: "Windows layout grounded on this box 2026-09-03: %LOCALAPPDATA%\\Programs\\Qoder\\Qoder.exe " +
			"(Electron — resources\\app.asar + LICENSE.electron.txt; the identifier-shaped data dir " +
			"%APPDATA%\\com.qoder.app.stable is just its app name, not a Tauri layout), no bin\\ shim. " +
			"macOS bundle NOT grounded — DarwinApp left empty.",
	},
}
