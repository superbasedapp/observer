package integration

import "sort"

// InterventionSurfaceClass describes the local process boundary exposed by a
// product surface. Only SurfaceDedicatedProcess can produce a process target;
// shared hosts and remote execution are explicit unsupported inventory rows.
type InterventionSurfaceClass string

const (
	// SurfaceDedicatedProcess is a CLI or worker with its own process lifetime.
	SurfaceDedicatedProcess InterventionSurfaceClass = "dedicated_process"
	// SurfaceSharedHost is an IDE or desktop host that may contain unrelated work.
	SurfaceSharedHost InterventionSurfaceClass = "shared_host"
	// SurfaceRemoteExecution has no spend-bearing process on this node.
	SurfaceRemoteExecution InterventionSurfaceClass = "remote_execution"
	// SurfaceUnclassified is the fail-closed value for a registry row that has
	// not yet declared its intervention surfaces.
	SurfaceUnclassified InterventionSurfaceClass = "unclassified"
)

// NativeUsageKind describes whether one surface has a grounded local source
// for billable native usage. It is independent of pricing completeness.
type NativeUsageKind string

const (
	// NativeUsageUnavailable means the surface has no grounded local billable-
	// usage source.
	NativeUsageUnavailable NativeUsageKind = ""
	// NativeUsageApproximate means the surface has a grounded local source whose
	// billable usage is estimated.
	NativeUsageApproximate NativeUsageKind = "approximate"
	// NativeUsagePresent means the surface has a grounded local billable-usage
	// source.
	NativeUsagePresent NativeUsageKind = "present"
)

// Available reports whether the surface has any grounded local billable-usage
// source, regardless of whether that source is approximate.
func (k NativeUsageKind) Available() bool {
	return k == NativeUsageApproximate || k == NativeUsagePresent
}

// InterpreterKind is an interpreter whose direct script entrypoint can be
// bound without treating the generic interpreter binary as the adapter.
type InterpreterKind string

const (
	// InterpreterNode is a direct Node.js entrypoint.
	InterpreterNode InterpreterKind = "node"
	// InterpreterBun is a direct Bun entrypoint.
	InterpreterBun InterpreterKind = "bun"
	// InterpreterPython is a direct Python entrypoint.
	InterpreterPython InterpreterKind = "python"
)

// WorkerDiscoveryKind is a closed, data-driven installed-worker layout. The
// binding package evaluates these declarations relative to the resolved
// launcher and never executes the launcher to discover a child.
type WorkerDiscoveryKind string

const (
	// WorkerExactRelative names one exact launcher-relative native worker.
	WorkerExactRelative WorkerDiscoveryKind = "exact_relative"
	// WorkerVersionedSibling names native files in the launcher's directory
	// whose basename starts with the declared prefix.
	WorkerVersionedSibling WorkerDiscoveryKind = "versioned_sibling"
	// WorkerVersionedDirectory names one native file at the exact Inner path
	// inside every version-named subdirectory of the launcher-relative
	// Relative directory (Relative/<version>/Inner). It is the layout of a
	// self-updating installer whose shell shim execs a per-version payload.
	WorkerVersionedDirectory WorkerDiscoveryKind = "versioned_directory"
)

// WorkerDiscoverySpec declares a grounded native worker path relative to a
// resolved launcher. Relative is used by WorkerExactRelative (the worker
// file) and WorkerVersionedDirectory (the directory holding one subdirectory
// per version). Prefix is used by WorkerVersionedSibling. Inner is used by
// WorkerVersionedDirectory: the exact relative path of the worker inside each
// version subdirectory. Every form requires the discovered file to be a
// regular executable ELF before it enters an install manifest.
type WorkerDiscoverySpec struct {
	Kind     WorkerDiscoveryKind
	Relative string
	Prefix   string
	Inner    string
}

// InvocationSpec is the closed argv classifier for one process surface.
// CLILeadingArguments and NonCLILeadingArguments are exact values of the first
// argument after the target (argv[1] for native executables; argv[2] after an
// interpreted script).
//
// The default shape is INVERTED: on a dedicated-process surface the executable
// or interpreted entrypoint identity has already matched exactly, so the
// running process is that product's billable CLI unless its leading argument
// is declared non-billable. A prompt, an arbitrary flag, or an undeclared
// subcommand is therefore governed — `claude --resume`, `opencode run "..."`
// and `gemini -p "..."` are ordinary billable work, not unknown modes. The
// same target may still host a server, MCP, app-server, or local maintenance
// mode; those are named in NonCLILeadingArguments, which every dedicated
// surface inherits from the universal non-billable set (see
// universalNonBillableLeadingArguments) and may extend with grounded
// per-product verbs. A row-declared CLI argument always wins over the
// universal set.
//
// RequireDeclaredCLI restores the fail-closed shape for a surface whose argv
// genuinely cannot be read as CLI-by-default: an undeclared leading argument
// is then unclassified and can never become a process target. It is reserved
// for a product that multiplexes unrelated, non-billable work onto the same
// exact executable identity through argument shapes the registry cannot
// enumerate. No row declares it today.
type InvocationSpec struct {
	AllowNoArguments       bool
	CLILeadingArguments    []string
	NonCLILeadingArguments []string
	RequireDeclaredCLI     bool
}

// AllowsCLI reports whether the declaration identifies at least one CLI form.
func (s InvocationSpec) AllowsCLI() bool {
	if s.AllowNoArguments {
		return true
	}
	if !s.RequireDeclaredCLI {
		// Inverted mode: every leading argument outside the non-billable
		// declaration is the dedicated CLI.
		return true
	}
	for _, argument := range s.CLILeadingArguments {
		if argument != "" {
			return true
		}
	}
	return false
}

// ProcessBindingSpec states which installed process shapes are safe to bind
// for one dedicated surface. A shell launcher is never itself bindable. It
// may lead to a native target only through a grounded Workers declaration.
//
// NativeNames lists grounded basenames the RESOLVED native executable may
// carry besides the Binary row's launcher names, for an installer whose PATH
// entry is a symlink to a release asset kept under its own name (for example
// grok's ~/.local/bin/grok -> ~/.grok/downloads/grok-linux-x86_64). A
// resolved file whose name is in neither list is still refused, so a symlink
// to an unrelated program can never become a target.
//
// LaunchOverrideEnv names the environment variables the vendor's own launcher
// reads to run a binary OUTSIDE the declared layout (cline's CLINE_BIN_PATH,
// junie's JUNIE_DATA). The controller cannot bind such a binary, so a launch
// that sets one is never admitted on process cutoff.
type ProcessBindingSpec struct {
	AllowNative       bool
	Invocation        InvocationSpec
	Interpreters      []InterpreterKind
	Workers           []WorkerDiscoverySpec
	NativeNames       []string
	LaunchOverrideEnv []string
	UnsupportedReason string
}

// InterventionSurfaceSpec is one registry-backed product surface. Binary is
// populated from the owning Capability rather than copied into this table, so
// launcher discovery stays owned by BinaryResolveSpec.
type InterventionSurfaceSpec struct {
	ID          string
	Tool        string
	Class       InterventionSurfaceClass
	NativeUsage NativeUsageKind
	Binding     ProcessBindingSpec
	Binary      *BinaryResolveSpec
	Note        string
}

type interventionDeclaration struct {
	id          string
	class       InterventionSurfaceClass
	nativeUsage NativeUsageKind
	binding     ProcessBindingSpec
	note        string
}

var interventionDeclarations = map[string][]interventionDeclaration{
	"aider":           {dedicated("cli", interpreted(InterpreterPython), NativeUsageApproximate)},
	"antigravity":     {shared("ide", "the IDE/desktop host contains unrelated editor work")},
	"antigravity-cli": {dedicated("cli", native(), NativeUsagePresent)},
	"chatgpt-web":     {remote("web")},
	"claude-code":     {dedicated("cli", native(), NativeUsagePresent), shared("embedded", "desktop and IDE embedded surfaces are shared hosts")},
	"claude-web":      {remote("web")},
	"cline":           {shared("ide", "the VS Code extension runs in a shared Code host")},
	"cline-cli": {
		// npm `cline` 3.0.68, grounded read-only on demo node 1 (2026-10-08):
		// bin/cline is a Node resolver that spawnSync()s a compiled worker
		// with the user's argv, trying bin/.cline (written by postinstall)
		// first, then @cline/cli-<platform>-<arch>/bin/cline found by walking
		// up node_modules. Each declared worker is bound exactly; the Node
		// resolver is never a target.
		dedicated("cli", ProcessBindingSpec{
			AllowNative:       true,
			Invocation:        defaultInvocation(),
			Workers:           clineCLILinuxWorkers(),
			LaunchOverrideEnv: []string{"CLINE_BIN_PATH"},
		}, NativeUsagePresent),
	},
	"codex": {
		dedicated("cli", ProcessBindingSpec{
			AllowNative: true,
			Invocation: InvocationSpec{
				AllowNoArguments: true,
				// exec/fork/resume/review are billable even though `resume`
				// reads like maintenance; declaring them keeps that explicit
				// and protects them from any future universal entry.
				CLILeadingArguments:    []string{"exec", "fork", "resume", "review"},
				NonCLILeadingArguments: []string{"app-server", "mcp-server"},
			},
			Workers: codexLinuxWorkers(),
		}, NativeUsagePresent),
		shared("embedded", "desktop and IDE embedded cores require a separate child identity"),
	},
	"command-code": {dedicated("cli", interpreted(InterpreterNode), NativeUsageApproximate)},
	"copilot":      {shared("ide", "the VS Code extension runs in a shared Code host")},
	"copilot-cli":  {dedicated("cli", nativeOnlyWithUnsupportedLauncher("the npm loader hands off to an undeclared platform worker layout"), NativeUsageApproximate)},
	"copilot-web":  {remote("web")},
	"cowork":       {shared("desktop", "the desktop shell and its children do not isolate one governed session")},
	"crush": {
		// npm `@charmland/crush` 0.97.1, grounded read-only on demo node 1
		// (2026-10-08): the PATH entry links to run-crush.js, a GoReleaser
		// Node shim whose lib.js spawnSync()s <package>/bin/crush (a static
		// Go ELF) with the user's argv. A release-archive or `go install`
		// crush is that same Go binary named crush, bound natively.
		dedicated("cli", ProcessBindingSpec{
			AllowNative: true,
			Invocation:  defaultInvocation(),
			Workers:     []WorkerDiscoverySpec{{Kind: WorkerExactRelative, Relative: "bin/crush"}},
		}, NativeUsageApproximate),
	},
	"cursor":     {dedicated("cli", nativeInvoking(cursorInvocation()), NativeUsageApproximate), shared("ide", "the Cursor IDE host may contain unrelated sessions")},
	"deepseek":   {remote("web")},
	"devin":      {dedicated("cli", native(), NativeUsageApproximate), shared("desktop", "the Cascade desktop host is shared")},
	"droid":      {dedicated("cli", native(), NativeUsageApproximate)},
	"freebuff":   {dedicated("cli", nativeOnlyWithUnsupportedLauncher("the npm launcher downloads and spawns a worker outside its package; bind the grounded native candidate directly"), NativeUsageUnavailable), shared("desktop", "the desktop host is not a session-isolated worker")},
	"gemini-cli": {dedicated("cli", interpreted(InterpreterNode), NativeUsagePresent)},
	"gemini-web": {remote("web")},
	"goose":      {dedicated("cli", native(), NativeUsageApproximate)},
	"grok": {
		// Grounded read-only on demo node 1 (2026-10-08): the installer's
		// ~/.local/bin/grok links through ~/.grok/bin/grok to the release
		// asset ~/.grok/downloads/grok-linux-x86_64, a native ELF.
		dedicated("cli", ProcessBindingSpec{
			AllowNative: true,
			Invocation:  defaultInvocation(),
			NativeNames: []string{"grok-linux-x86_64"},
		}, NativeUsageApproximate),
	},
	"grokbot": {remote("provider-sandbox")},
	"hermes":  {dedicated("cli", unsupportedBinding("the Bourne launcher and Python worker relationship has no exact installed entrypoint declaration"), NativeUsagePresent)},
	"junie": {
		// The standalone CLI (2026-10-03): install.sh writes a bash shim at
		// ~/.local/bin/junie (junie.bat on Windows). Grounded on demo node 1
		// (2026-10-08, junie 3579.5, read-only): the shim execs
		// ~/.local/share/junie/versions/<v>/junie, a 100-byte bash script that
		// execs <v>/junie-app/bin/junie, a jpackage native ELF launcher that
		// runs the bundled JVM (lib/runtime) in its own process image. The
		// shim's own get_binary_path_in also accepts <v>/junie/bin/junie as
		// the Linux layout, so both inner paths are declared. Each version
		// directory's ELF is bound exactly; the shell shim and the script are
		// never targets. events.jsonl carries per-call modelUsage (tokens +
		// cost), live-captured from a CLI run on 2026-09-07.
		dedicated("cli", ProcessBindingSpec{
			AllowNative:       true,
			Invocation:        defaultInvocation(),
			Workers:           junieLinuxWorkers(),
			LaunchOverrideEnv: []string{"JUNIE_DATA"},
		}, NativeUsagePresent),
		shared("jetbrains-acp", "the ACP child is launched from a shared JetBrains host"),
	},
	"kilo-code":     {shared("ide", "the VS Code extension runs in a shared Code host")},
	"kilo-code-cli": {dedicated("cli", nativeOnlyWithUnsupportedLauncher("the npm shim hands off to an undeclared platform worker layout"), NativeUsagePresent)},
	"kimi-code":     {dedicated("cli", native(), NativeUsageApproximate)},
	"kiro-cli":      {dedicated("cli", native(), NativeUsageApproximate)},
	"kiro-crew":     {shared("desktop", "the desktop orchestrator is not the isolated kiro-cli child")},
	"mistral-code":  {dedicated("cli", interpreted(InterpreterPython), NativeUsageApproximate)},
	"muse": {
		dedicated("cli", ProcessBindingSpec{
			AllowNative: true,
			Invocation: InvocationSpec{
				AllowNoArguments:       true,
				CLILeadingArguments:    []string{"exec"},
				NonCLILeadingArguments: museNonBillableArguments(),
			},
			Workers: []WorkerDiscoverySpec{{Kind: WorkerVersionedSibling, Prefix: "muse-bin-"}},
		}, NativeUsageApproximate),
	},
	"open-interpreter": {dedicated("cli", native(), NativeUsageApproximate)},
	"openclaw":         {dedicated("cli", interpreted(InterpreterNode, InterpreterBun), NativeUsagePresent)},
	"opencode":         {dedicated("cli", native(), NativeUsagePresent), shared("desktop", "the Electron desktop host is shared")},
	"perplexity-web":   {remote("web")},
	"pi":               {dedicated("cli", interpreted(InterpreterNode), NativeUsageApproximate)},
	"poolside": {
		// The standalone `pool` CLI (2026-10-03): install.sh MOVES the native
		// binary to ~/.local/bin/pool, so the installed file is the target.
		// Usage source (T-706, demo node 1, 2026-10-08): a Linux `pool` 1.0.16
		// run writes ~/.local/state/poolside/trajectories/trajectory-
		// standalone_<sid>.ndjson, the same per-call
		// tool_call.inference.end token records the Windows ACP store
		// carries, and the adapter now watches that root.
		dedicated("cli", native(), NativeUsagePresent),
		shared("jetbrains-acp", "the ACP child is launched from a shared JetBrains host"),
	},
	// prime-agent 0.9.8 on demo node 1 (2026-10-08, read-only):
	// ~/.local/bin/prime-agent links to a native ELF named prime-agent under
	// ~/.local/share/prime-agent/releases/<version>/; a Node entrypoint stays
	// declared for a package-manager install.
	"prime-agent": {dedicated("cli", nativeOrInterpreted(InterpreterNode), NativeUsageApproximate)},
	"qoder":       {dedicated("cli", nativeOrInterpreted(InterpreterNode), NativeUsageUnavailable), shared("ide", "the hosted IDE surface is shared")},
	"qwen-code":   {dedicated("cli", interpreted(InterpreterNode), NativeUsageApproximate)},
	"zcode":       {dedicated("cli", interpretedInvoking(nonBillableInvocation(zcodeNonBillableArguments()...), InterpreterNode), NativeUsagePresent), shared("desktop", "the Electron desktop host is shared")},
	"zed":         {shared("ide", "Zed is the editor host and has no session-isolated worker declaration")},
	// The 2026-10-21 capture-only wave. Process shapes from each adapter's
	// grounding doc: npm Node entry points are interpreted, single-file
	// native builds (Bun / Node SEA / Rust) are native. Usage availability
	// follows the adapter's grounded token source.
	"autohand":        {dedicated("cli", nativeOrInterpreted(InterpreterNode), NativeUsageApproximate)},
	"codebuddy":       {dedicated("cli", interpreted(InterpreterNode), NativeUsageUnavailable)},
	"cortex-code":     {dedicated("cli", native(), NativeUsageApproximate)},
	"deepagents-code": {dedicated("cli", nativeOrInterpreted(InterpreterPython), NativeUsagePresent)},
	"dimcode":         {dedicated("cli", nativeOrInterpreted(InterpreterNode), NativeUsagePresent)},
	"dirac":           {dedicated("cli", interpreted(InterpreterNode), NativeUsagePresent)},
	"ibm-bob":         {dedicated("cli", interpreted(InterpreterNode), NativeUsageUnavailable)},
	"kimchi":          {dedicated("cli", native(), NativeUsagePresent)},
	"stakpak":         {dedicated("cli", native(), NativeUsagePresent)},
	"vtcode":          {dedicated("cli", native(), NativeUsagePresent)},
	// custom-agent (P-228): the developer's own program; Observer neither
	// launches nor binds it, so there is no process cutoff boundary.
	"custom-agent": {shared("own", "the developer's own agent process is not one Observer launches or binds; the proxy turn is the only control point")},
}

func dedicated(id string, binding ProcessBindingSpec, nativeUsage NativeUsageKind) interventionDeclaration {
	return interventionDeclaration{id: id, class: SurfaceDedicatedProcess, nativeUsage: nativeUsage, binding: binding}
}

func shared(id, note string) interventionDeclaration {
	return interventionDeclaration{id: id, class: SurfaceSharedHost, note: note}
}

func remote(id string) interventionDeclaration {
	return interventionDeclaration{id: id, class: SurfaceRemoteExecution, note: "provider work has no local process cutoff boundary"}
}

func native() ProcessBindingSpec {
	return ProcessBindingSpec{AllowNative: true, Invocation: defaultInvocation()}
}

func nativeInvoking(invocation InvocationSpec) ProcessBindingSpec {
	return ProcessBindingSpec{AllowNative: true, Invocation: invocation}
}

func interpretedInvoking(invocation InvocationSpec, kinds ...InterpreterKind) ProcessBindingSpec {
	return ProcessBindingSpec{Invocation: invocation, Interpreters: kinds}
}

// nonBillableInvocation is the default invocation extended with grounded
// per-product non-billable leading arguments. The universal set is merged in
// by composeInvocation, so a row lists only what the universal set misses.
func nonBillableInvocation(arguments ...string) InvocationSpec {
	spec := defaultInvocation()
	spec.NonCLILeadingArguments = arguments
	return spec
}

func nativeOnlyWithUnsupportedLauncher(reason string) ProcessBindingSpec {
	return ProcessBindingSpec{AllowNative: true, Invocation: defaultInvocation(), UnsupportedReason: reason}
}

func interpreted(kinds ...InterpreterKind) ProcessBindingSpec {
	return ProcessBindingSpec{Invocation: defaultInvocation(), Interpreters: kinds}
}

func nativeOrInterpreted(kinds ...InterpreterKind) ProcessBindingSpec {
	return ProcessBindingSpec{AllowNative: true, Invocation: defaultInvocation(), Interpreters: kinds}
}

func defaultInvocation() InvocationSpec {
	// The exact executable or interpreted entrypoint identity has already
	// matched, so every argument tail is that product's billable CLI unless the
	// universal non-billable set (merged by composeInvocation) or a grounded
	// per-product argument says otherwise. Prompts, arbitrary flags, and
	// undeclared subcommands are governed rather than abstained on.
	return InvocationSpec{AllowNoArguments: true}
}

// universalNonBillableLeadingArguments is the cross-vendor set of leading
// arguments that never submit a model request: a server/daemon mode the same
// executable also hosts, or local account/installation maintenance. Every
// dedicated-process surface inherits it. Entries are intentionally generic
// spellings shared by the CLI vendors Observer captures; a product whose verb
// of the same name IS billable declares it in CLILeadingArguments, which wins.
//
// -v is included as the common `-v, --version` spelling. A vendor that spells
// verbose as -v must declare -v in CLILeadingArguments for its row, or its
// `<tool> -v "<prompt>"` invocation would read as maintenance.
func universalNonBillableLeadingArguments() []string {
	return []string{
		// Server, daemon, and protocol-host modes hosted by the same binary.
		"acp", "app-server", "lsp", "mcp", "mcp-server", "serve",
		// Local account and installation maintenance.
		"auth", "completion", "config", "doctor", "help", "login", "logout",
		"update", "upgrade",
		// Universal version/help flag spellings.
		"-h", "--help", "-v", "--version",
	}
}

// museNonBillableArguments are the Muse verbs and flags beyond the universal
// set that perform local or account management without submitting a model
// request. Grounded in cmd/observer/muse.go's verbatim reading of
// `muse --help` (Muse Code 0.1.0 (0.1.0-R708.1), live install 2026-08-06):
// export/trace/skills/init are one-shot management verbs and -V is muse's
// version flag. exec/resume/session-message/sandbox stay billable.
func museNonBillableArguments() []string {
	return []string{"-V", "export", "init", "skills", "trace"}
}

// cursorNonBillableArguments are the cursor-agent verbs and flags beyond the
// universal set that do not submit a model request, grounded in
// cmd/observer/cursor.go's live `cursor-agent --help` reading. Chat execution,
// resume, worker, rule generation, and agent verbs stay billable.
func cursorNonBillableArguments() []string {
	return []string{
		"--list-models", "about", "install-shell-integration", "models",
		"status", "uninstall-shell-integration", "whoami",
	}
}

// cursorBillableArguments reclaims two universal spellings that ARE billable
// on cursor-agent, so the universal set never loosens an existing judgement:
// `cursor-agent mcp …` is deliberately controlled by the launch gate
// (cmd/observer/cursor_budget_test.go "mcp subtree"), and `cursor-agent acp`
// serves the agent protocol from this same dedicated binary rather than from
// the shared IDE host.
func cursorBillableArguments() []string {
	return []string{"acp", "mcp"}
}

func cursorInvocation() InvocationSpec {
	spec := nonBillableInvocation(cursorNonBillableArguments()...)
	spec.CLILeadingArguments = cursorBillableArguments()
	return spec
}

// zcodeNonBillableArguments are the Z.AI zcode verbs beyond the universal set
// that list or manage local state, grounded in cmd/observer/zcode.go's
// zcodeNonInteractiveSubcommands reading of the live CLI.
func zcodeNonBillableArguments() []string {
	return []string{"commands", "plugins", "skills", "version"}
}

// composeInvocation merges the universal non-billable set into one row's
// declaration. A row-declared CLI argument always wins, so a product whose
// verb collides with a universal spelling keeps its billable classification.
func composeInvocation(in InvocationSpec) InvocationSpec {
	out := in
	cli := make(map[string]bool, len(in.CLILeadingArguments))
	for _, argument := range in.CLILeadingArguments {
		cli[argument] = true
	}
	seen := make(map[string]bool, len(in.NonCLILeadingArguments))
	merged := make([]string, 0, len(in.NonCLILeadingArguments)+len(universalNonBillableLeadingArguments()))
	for _, argument := range in.NonCLILeadingArguments {
		if argument == "" || seen[argument] {
			continue
		}
		seen[argument] = true
		merged = append(merged, argument)
	}
	for _, argument := range universalNonBillableLeadingArguments() {
		if argument == "" || seen[argument] || cli[argument] {
			continue
		}
		seen[argument] = true
		merged = append(merged, argument)
	}
	out.NonCLILeadingArguments = merged
	return out
}

// NonBillableLeadingArguments returns the composed, registry-declared set of
// leading arguments that tool's dedicated process surfaces classify as
// non-billable. It is the ONE owner of that vocabulary: an Observer launch
// gate must derive its maintenance set from this call rather than maintaining
// a parallel table, so the launch gate and the process controller classify an
// invocation identically. The result is sorted and deduplicated.
func NonBillableLeadingArguments(tool string) []string {
	surfaces, ok := InterventionFor(tool)
	if !ok {
		return nil
	}
	seen := make(map[string]bool)
	out := make([]string, 0, 16)
	for _, surface := range surfaces {
		if surface.Class != SurfaceDedicatedProcess {
			continue
		}
		for _, argument := range surface.Binding.Invocation.NonCLILeadingArguments {
			if argument == "" || seen[argument] {
				continue
			}
			seen[argument] = true
			out = append(out, argument)
		}
	}
	sort.Strings(out)
	return out
}

func unsupportedBinding(reason string) ProcessBindingSpec {
	return ProcessBindingSpec{UnsupportedReason: reason}
}

func codexLinuxWorkers() []WorkerDiscoverySpec {
	return []WorkerDiscoverySpec{
		{Kind: WorkerExactRelative, Relative: "../vendor/x86_64-unknown-linux-musl/bin/codex"},
		{Kind: WorkerExactRelative, Relative: "../vendor/aarch64-unknown-linux-musl/bin/codex"},
		{Kind: WorkerExactRelative, Relative: "../node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex"},
		{Kind: WorkerExactRelative, Relative: "../node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex"},
		{Kind: WorkerExactRelative, Relative: "../../codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex"},
		{Kind: WorkerExactRelative, Relative: "../../codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex"},
	}
}

// clineCLILinuxWorkers is the resolution order of the npm `cline` package's
// own bin/cline resolver (3.0.68, read on demo node 1): the postinstall cache
// beside the resolver, then the platform package in the package's own
// node_modules, then in the global node_modules the package sits in.
func clineCLILinuxWorkers() []WorkerDiscoverySpec {
	return []WorkerDiscoverySpec{
		{Kind: WorkerExactRelative, Relative: ".cline"},
		{Kind: WorkerExactRelative, Relative: "../node_modules/@cline/cli-linux-x64/bin/cline"},
		{Kind: WorkerExactRelative, Relative: "../node_modules/@cline/cli-linux-arm64/bin/cline"},
		{Kind: WorkerExactRelative, Relative: "../../@cline/cli-linux-x64/bin/cline"},
		{Kind: WorkerExactRelative, Relative: "../../@cline/cli-linux-arm64/bin/cline"},
	}
}

// junieLinuxWorkers is the installer layout read from demo node 1 and from
// the vendor shim's own get_binary_path_in (2026-10-08): the shim lives in
// ~/.local/bin and every installed version is a directory under
// ~/.local/share/junie/versions.
func junieLinuxWorkers() []WorkerDiscoverySpec {
	return []WorkerDiscoverySpec{
		{Kind: WorkerVersionedDirectory, Relative: "../share/junie/versions", Inner: "junie-app/bin/junie"},
		{Kind: WorkerVersionedDirectory, Relative: "../share/junie/versions", Inner: "junie/bin/junie"},
	}
}

// InterventionFor returns every declared local/remote surface for tool. A
// known registry row without a declaration returns one unclassified surface,
// ensuring a newly added adapter cannot inherit process control accidentally.
func InterventionFor(tool string) ([]InterventionSurfaceSpec, bool) {
	capability, ok := For(tool)
	if !ok {
		return nil, false
	}
	decls, declared := interventionDeclarations[tool]
	if !declared || len(decls) == 0 {
		return []InterventionSurfaceSpec{{
			ID:    tool + "/unclassified",
			Tool:  tool,
			Class: SurfaceUnclassified,
			Note:  "registry row has no intervention surface declaration",
		}}, true
	}
	out := make([]InterventionSurfaceSpec, 0, len(decls))
	for _, decl := range decls {
		surface := InterventionSurfaceSpec{
			ID:          tool + "/" + decl.id,
			Tool:        tool,
			Class:       decl.class,
			NativeUsage: decl.nativeUsage,
			Binding:     cloneProcessBinding(decl.binding),
			Note:        decl.note,
		}
		if decl.class == SurfaceDedicatedProcess {
			surface.Binary = capability.Binary
			surface.Binding.Invocation = composeInvocation(surface.Binding.Invocation)
		}
		out = append(out, surface)
	}
	return out, true
}

// AllInterventionSurfaces returns the complete registry-derived surface
// inventory sorted by surface ID. Missing declarations remain visible as
// SurfaceUnclassified rows.
func AllInterventionSurfaces() []InterventionSurfaceSpec {
	capabilities := Capabilities()
	out := make([]InterventionSurfaceSpec, 0, len(capabilities))
	for _, capability := range capabilities {
		surfaces, _ := InterventionFor(capability.Tool)
		out = append(out, surfaces...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func cloneProcessBinding(in ProcessBindingSpec) ProcessBindingSpec {
	out := in
	out.Invocation.CLILeadingArguments = append([]string(nil), in.Invocation.CLILeadingArguments...)
	out.Invocation.NonCLILeadingArguments = append([]string(nil), in.Invocation.NonCLILeadingArguments...)
	out.Interpreters = append([]InterpreterKind(nil), in.Interpreters...)
	out.Workers = append([]WorkerDiscoverySpec(nil), in.Workers...)
	out.NativeNames = append([]string(nil), in.NativeNames...)
	out.LaunchOverrideEnv = append([]string(nil), in.LaunchOverrideEnv...)
	return out
}
