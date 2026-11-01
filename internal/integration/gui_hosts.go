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
				"third-party snap, and which one applies depends on the distro - a single argv would be a " +
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
			// Grounded live 2026-09-27 (backlog item 8): inside a VS Code
			// Remote / WSL integrated terminal `code` resolves to
			// ~/.vscode-server/bin/<commit>/bin/remote-cli/code, which only
			// asks the running Windows-side window (VSCODE_IPC_HOOK_CLI) to
			// open the folder — no new process ever sees the injected env.
			HandoffPathSegments: []string{"remote-cli"},
			Reason: "cold start ONLY: `code <dir>` hands off to an already-running window, and that " +
				"process never re-reads its environment (inventory §4.3 open question 1). The wrap reaches " +
				"only the extensions that SPAWN a vendor CLI and inherit the process env (Claude Code " +
				"`anthropic.claude-code`, the Codex extension, the Gemini companion); extensions whose base " +
				"URL lives in the VS Code `state.vscdb` settings store (Cline, legacy Kilo, Cursor BYOK) are " +
				"unaffected - inventory §4.1/§4.2. Env inheritance into a GUI-launched VS Code is NOT " +
				"live-verified.",
		},
		// The second line joined 2026-10-28 (surface-gap lane w8-registry,
		// docs/audits/vendor-surface-inventory-2026-10-25.md sections 3.3,
		// 3.7, 3.8): extensions whose existence is vendor-grounded. Goose
		// (block.vscode-goose) and Poolside Assistant are listed because the
		// extension exists; whether each one's sessions reach the adapter's
		// store is a grounding run each (integration.CodingSurfaces carries
		// the per-surface state). The CLI-first tools with a VS Code
		// extension but no `observer` launcher (Autohand, Dirac, Kimchi,
		// Cortex Code) are deliberately NOT listed: Hosts also decides the
		// New Terminal picker's "runs inside VS Code" note (unlaunchable.go),
		// which would misdescribe a CLI; their extensions live in
		// CodingSurfaces only.
		// Antigravity: the Antigravity for VS Code extension writes the same
		// ~/.gemini/antigravity/brain transcripts and runs hooks.json
		// (live LC15 / LCX-5, 2026-10-26).
		Hosts: []string{
			"claude-code", "codex", "cline", "kilo-code", "kilo-code-cli", "copilot",
			"gemini-cli", "qwen-code", "kimi-code", "mistral-code", "droid", "opencode",
			"command-code",
			"goose", "poolside", "antigravity",
		},
		Grounded: true,
		Note: "Windows layout grounded on this box 2026-09-03: " +
			"%LOCALAPPDATA%\\Programs\\Microsoft VS Code\\Code.exe (+ bin\\code, bin\\code.cmd). macOS " +
			"bundle \"Visual Studio Code.app\" grounded from the Homebrew cask `visual-studio-code`. " +
			"Hosts lists the registry adapters whose extensions run inside VS Code (inventory 2026-09-03 §2.1-§2.13, " +
			"refreshed 2026-10-25); extensions are never launch rows of their own (plan §0 consequence 3).",
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
			// Unix: `idea` is the launcher the Homebrew cask links and the
			// name JetBrains' tarball docs suggest symlinking bin/idea.sh as;
			// `intellij-idea` is the command the classic snap installs
			// (snapcraft.io/intellij-idea, 2026-10-03).
			Names: BinaryNames{
				Unix:    []string{"idea", "intellij-idea"},
				Windows: []string{"idea64.exe"},
			},
			ProbeDirs: []ProbeDir{
				// ONE glob segment, expanded by toolresolve's expandGlobDirs
				// (filepath.Glob over the whole absolute path, so an interior
				// `*` segment works and EnvRoot dirs are glob-expanded too).
				// The glob matches the unified product's folder (JetBrains
				// documents C:\Program Files\JetBrains\IntelliJ IDEA\bin\idea64.exe;
				// the winget Nullsoft installer may suffix the version) AND a
				// legacy install grounded on this box 2026-09-03:
				// C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2025.2.6.2\bin\idea64.exe
				{OS: ProbeWindows, Rel: "JetBrains/IntelliJ IDEA*/bin", EnvRoot: "ProgramFiles"},
			},
			// Re-grounded 2026-10-03 for JetBrains' UNIFIED IntelliJ IDEA
			// (one product since 2025.3; blog.jetbrains.com/idea/2025/12/
			// intellij-idea-unified-release/). winget: `JetBrains.IntelliJIDEA`
			// carries 2025.3 through 2026.2.3, while
			// `JetBrains.IntelliJIDEA.Community` is frozen at 2025.2.6.2 and
			// `.Ultimate` at 2025.2.5 (microsoft/winget-pkgs
			// manifests/j/JetBrains/IntelliJIDEA). Homebrew: cask
			// `intellij-idea` (2026.2.3, installs "IntelliJ IDEA.app" + `idea`);
			// `intellij-idea-ce` was deprecated 2025-12-08 with replacement
			// `intellij-idea` (formulae.brew.sh/api/cask/<token>.json).
			Installs: []InstallHint{
				{OS: "windows", Channel: "winget", Argv: []string{"winget", "install", "--id", "JetBrains.IntelliJIDEA", "-e", "--source", "winget"}, Display: "winget install --id JetBrains.IntelliJIDEA -e --source winget"},
				{OS: "darwin", Channel: "brew", Argv: []string{"brew", "install", "--cask", "intellij-idea"}, Display: "brew install --cask intellij-idea"},
			},
			InstallNote: "no guided Linux install: JetBrains documents `sudo snap install intellij-idea --classic` " +
				"(root, and snap is outside the guided-install channel vocabulary), a tarball run as bin/idea.sh, " +
				"and the Toolbox App, none of which is a single unprivileged argv; see " +
				"jetbrains.com/help/idea/installation-guide.html.",
			UserInstallHint: "On Linux, install IntelliJ IDEA with the JetBrains Toolbox App or with snap: sudo snap install intellij-idea --classic.",
		},
		DarwinApp:      "IntelliJ IDEA",
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
				"CLI and inherit the IDE's env - Junie, the Kimi JB PTY wrapper, and every agent " +
				"registered through the JetBrains ACP registry (~/.jetbrains/acp.json: Factory/droid, " +
				"Qwen, Mistral, Grok) - inventory §2.9/§1.5 finding 5. Copilot and Gemini Code Assist are " +
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
			// Joined 2026-10-28 (lane w8-registry): the ACP agents whose
			// pointer sid round trip is live-proven (jetbrainshost acpAgents,
			// 2026-09-04 / 09-05), plus Kilo Code for JetBrains v7
			// (ai.kilocode.jetbrains, which downloads the pinned Kilo CLI and
			// shares kilo.jsonc; inventory section 2.4).
			"cline-cli", "kilo-code-cli", "devin", "opencode", "poolside", "antigravity-cli",
		},
		Grounded: true,
		Note: "Unified IntelliJ IDEA (2025.3+), re-grounded 2026-10-03: winget JetBrains.IntelliJIDEA, " +
			"Homebrew cask intellij-idea (bundle \"IntelliJ IDEA.app\"), Linux snap intellij-idea --classic " +
			"(command `intellij-idea`). Community Edition is no longer a separate product: JetBrains says " +
			"existing CE 2025.2 installs keep working (jetbrains.com/help/idea/intellij-idea-single-distribution.html) " +
			"and publishes open-source builds on github.com/JetBrains/intellij-community releases; neither is " +
			"offered as a guided install. A legacy CE install on Windows still resolves through the " +
			"IntelliJ IDEA* probe glob. Windows layout grounded on this box 2026-09-03: %ProgramFiles%\\JetBrains\\IntelliJ IDEA " +
			"Community Edition 2025.2.6.2\\bin\\idea64.exe. The JetBrains Toolbox apps layout " +
			"(%LOCALAPPDATA%\\JetBrains\\Toolbox\\apps\\*) is NOT probed: this box has only " +
			"%LOCALAPPDATA%\\JetBrains\\IdeaIC2025.2 (the IDE's config/system dir, not a Toolbox install), " +
			"so the Toolbox layout could not be grounded and is deliberately absent rather than guessed. " +
			"CAPTURE (batch-3 T1, 2026-09-03): the 2026.2 AI Assistant drives its ACP agents (Junie, " +
			"Claude Agent, Codex, GitHub Copilot) which each write their OWN store, all captured by their " +
			"own adapters; the IDE's aia-task-history/*.agentsession pointer files are read by " +
			"internal/surfaceenrich to stamp ide/jetbrains-idea (hosted, host-wins) on those sessions - " +
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
				"main.sqlite (byok_model_credentials - never read) and routed through qodercli, whose " +
				"registry row is native_exempt. Launch yes, wrap no.",
		},
		Hosts:    []string{"qoder"},
		Grounded: true,
		Note: "Windows layout grounded on this box 2026-09-03: %LOCALAPPDATA%\\Programs\\Qoder\\Qoder.exe " +
			"(Electron - resources\\app.asar + LICENSE.electron.txt; the identifier-shaped data dir " +
			"%APPDATA%\\com.qoder.app.stable is just its app name, not a Tauri layout), no bin\\ shim. " +
			"macOS bundle NOT grounded - DarwinApp left empty.",
	},
	// Visual Studio 2022 / 2026 (surface-gap S-3, lane w8-registry,
	// 2026-10-28). Copilot in Visual Studio reads MCP from
	// %USERPROFILE%\.mcp.json and <SOLUTIONDIR>\.mcp.json and runs no hooks;
	// Poolside Assistant also ships for it. UNVERIFIED as a launch row: the
	// install roots are vendor-documented but the IDE executable's place
	// under them is not grounded from a fetched page or a live install, so
	// the row is listed for the record only.
	"visual-studio": {
		ID:      "visual-studio",
		Label:   "Visual Studio",
		Surface: "ide",
		Wrap: WrapSpec{
			Kind: WrapNone,
			Reason: "no grounded routing lever: Copilot in Visual Studio talks to GitHub's service and reads only MCP " +
				"files (learn.microsoft.com/visualstudio/ide/mcp-servers); its bring-your-own-model URL (18.10 " +
				"Insiders) is a UI setting no writer reaches.",
		},
		Hosts:    []string{"copilot", "poolside"},
		Grounded: false,
		Note: "UNVERIFIED (2026-10-28): learn.microsoft.com documents the install paths " +
			"C:\\Program Files\\Microsoft Visual Studio\\18\\<Edition> (Visual Studio 2026) and " +
			"...\\2022\\<Edition>, and the winget ids Microsoft.VisualStudio.Community and " +
			"Microsoft.VisualStudio.2022.Community (use-command-line-parameters-to-install-visual-studio); " +
			"devenv.exe's directory under those roots was not grounded, so Binary is empty and the row is " +
			"never launchable. Hosts: Copilot (no capture of its Visual Studio chat history yet) and " +
			"Poolside Assistant for Visual Studio (store unverified); both are grounding runs " +
			"(integration.CodingSurfaces).",
	},
}
