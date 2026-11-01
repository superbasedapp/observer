package components

// catalog_node.go holds the node binary's core, feature and integration
// rows (plan section 3.3). Adapter rows live in catalog_adapters.go, org
// server rows in catalog_server.go, external artifacts in
// catalog_artifacts.go.
//
// Reading a row: Levels.Implemented is what this build's code delivers
// TODAY (P0 gates nothing, so most features are L3 config toggles and
// nothing is compiled out); Levels.Target is the plan's destination and
// Levels.Phase the phase that delivers it. Distros is the plan's distro
// column: on / off / cond / out ("-" in the plan table).

// mod is the module-root import path prefix, kept out of every Packages
// entry so rows stay readable.
const modulePath = "github.com/marmutapp/superbased-observer"

// dist builds a distro column set in plan-table order.
func dist(minimal, developer, managed, full Default) map[Distro]Default {
	return map[Distro]Default{
		DistroMinimal:   minimal,
		DistroDeveloper: developer,
		DistroManaged:   managed,
		DistroFull:      full,
	}
}

// lv builds a Levels value.
func lv(implemented []Level, target []Level, phase string) Levels {
	return Levels{Implemented: implemented, Target: target, Phase: phase}
}

// Short level sets reused across rows.
var (
	onlyL0 = []Level{L0}
	onlyL3 = []Level{L3}
	l2l3   = []Level{L2, L3}
	l1l2l3 = []Level{L1, L2, L3}
)

// loopback is the common Listener shape for a 127.0.0.1 TCP bind.
func loopback(addr, auth, key string, trig Trigger) Listener {
	return Listener{Proto: "tcp", Addr: addr, Loopback: true, Auth: auth, ConfigKey: key, Trigger: trig}
}

const (
	on   = DefaultOn
	off  = DefaultOff
	cond = DefaultCond
	out  = DefaultOut
)

func nodeRows() []Component {
	return []Component{
		{
			ID: "core", Class: ClassCore, Binary: BinaryNode,
			Title:  "Core",
			About:  "Capture framework (watcher, adapter interface, hook receiver runtime), store and migrations, scrubbing, config and its migrator, the cost engine, the session message derivation, the integration registry data, the CLI root and doctor. Never removable.",
			Levels: lv(onlyL0, onlyL0, ""),
			// The generic OTLP receiver (internal/ingest/otlp: grpc, the OTLP
			// protos) and the neutral self-observability model
			// (internal/selfobs/shape: OTel attribute values) are core (D-436).
			DirectModules: []string{
				"github.com/BurntSushi/toml", "github.com/fsnotify/fsnotify", "github.com/spf13/cobra", "github.com/spf13/pflag", "github.com/google/uuid", "github.com/tailscale/hujson", "golang.org/x/sync", "golang.org/x/sys", "golang.org/x/term", "gopkg.in/yaml.v3", "modernc.org/sqlite", "go.opentelemetry.io/otel", "go.opentelemetry.io/proto/otlp", "google.golang.org/grpc", "google.golang.org/protobuf",
				// The owner-only local IPC transport (internal/localipc: the
				// Windows named pipe) is core since lane MP-L1K (T-715): the
				// MCP relay's IPC and the terminals attach channel share it.
				"github.com/Microsoft/go-winio",
				// The CLI root's double-click check on Windows
				// (cmd/observer/doubleclick_windows.go, T-920): started from
				// Explorer with no arguments, observer.exe launches the daemon
				// and opens the dashboard. Already in the build through cobra.
				"github.com/inconshreveable/mousetrap",
				// internal/cloudcontract (its SafeText NFC normalisation) is
				// core since the D-512 ruling (org wire vocabulary).
				"golang.org/x/text",
				// internal/keystore (the keychain-first secret store the Plans & limits
				// module and cloudcred share) is core.
				"github.com/zalando/go-keyring",
			},
			Surface: Surface{
				FilesWritten: []string{"~/.observer/observer.db", "~/.observer/config.toml", "~/.observer/plans-statusline-last.json"},
				// Plans & limits (docs/plans-and-limits.md) runs a vendor tool or
				// reads the keychain only for an account the user adds; its
				// vendor egress is described there (core declares no egress).
				Processes:   []string{"codex app-server, kiro-cli, amp, auggie, bl, coderabbit, arkcli, grok (only for a Plans & limits account using that tool)"},
				Credentials: []string{"OS keychain service sbo-plans-v1 (Plans & limits keys)"},
			},
			Tables:     []string{"sessions", "actions", "token_usage", "api_turns", "projects", "parse_cursors", "schema_meta", "session_pid_bridge"},
			Verbs:      []string{"scan", "watch", "init", "uninstall", "doctor", "adapters", "status", "hook", "config", "db", "start"},
			ConfigKeys: []string{"observer"},
			Stability:  StabilityStable,
			Distros:    dist(on, on, on, on),
		},
		{
			ID: "ui.dashboard", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Local dashboard",
			About:         "The node dashboard: the embedded web app and its JSON API on a loopback port. The version check is a browser fetch the user triggers.",
			Levels:        lv([]Level{L1, L3}, l1l2l3, "P2"),
			DirectModules: []string{"github.com/BurntSushi/toml"},
			Packages:      []string{"internal/intelligence/dashboard", "internal/intelligence/dashboard/webapp"},
			Surface: Surface{
				Listeners: []Listener{loopback("127.0.0.1:8081", "dashboard capability", "dashboard.addr", TriggerAutomatic)},
				Egress:    []Egress{{Host: "registry.npmjs.org", Purpose: "Version check, fetched by the browser when the user asks", Gate: "user action", Trigger: TriggerUserTriggered}},
				// Lane LEFT2-SEC (R-025, PT-04): the dashboard re-runs this
				// binary for a backfill, the self doctor and the prompt probe.
				Processes: []string{"observer (this binary: a backfill, the self doctor and the guard prompt probe)"},
			},
			Routes:       []string{"/api/status", "/api/health", "/api/sessions"},
			Verbs:        []string{"dashboard"},
			ConfigKeys:   []string{"dashboard"},
			Stability:    StabilityStable,
			Distros:      dist(on, on, on, on),
			RestartClass: "restart",
			Note:         "Owns no third-party module itself: websocket and excelize are hosted here for terminals and ui.export-xlsx until phase PB splits them. L1 since lane MP-L1M (T-715): the types, seam interfaces and CLI compositions the rest of the node shares with the dashboard are core internal/dashapi (re-exported here), cmd/observer reaches the server only through the ui_dashboard.go constructor seam, and a build without it starts headless with one reason.",
		},
		{
			ID: "ui.export-xlsx", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Spreadsheet export",
			About:         "Exports dashboard tables as .xlsx files, which brings the excelize module and five of its dependencies.",
			Levels:        lv([]Level{L1, L3}, l1l2l3, "P2"),
			HostedIn:      []string{"internal/intelligence/dashboard"},
			DirectModules: []string{"github.com/xuri/excelize/v2"},
			Routes:        []string{"/api/export.xlsx"},
			Stability:     StabilityStable,
			Distros:       dist(out, on, off, on),
		},
		{
			ID: "capture.proxy", Class: ClassFeature, Binary: BinaryNode,
			Title:         "API proxy",
			About:         "The local reverse proxy that AI tools can route through for accurate token and cost capture. Forwards requests to the model providers.",
			Levels:        lv([]Level{L1, L3}, l1l2l3, "P5"),
			Packages:      []string{"internal/proxy"},
			DirectModules: []string{"github.com/klauspost/compress"},
			Surface: Surface{
				Listeners: []Listener{loopback("127.0.0.1:8820", "none (loopback)", "proxy.port", TriggerAutomatic)},
				Egress:    []Egress{{Host: "<model provider APIs>", Purpose: "Forwards the routed AI tool's own requests upstream", Gate: "the AI tool routes through the proxy", Trigger: TriggerAutomatic}},
			},
			Tables:       []string{"api_turns", "limit_snapshots"},
			Verbs:        []string{"proxy"},
			ConfigKeys:   []string{"proxy"},
			Stability:    StabilityStable,
			Distros:      dist(out, on, on, on),
			RestartClass: "restart",
			Note:         "L1 since lane MP-L1L (T-715): every proxy seam (routing, compression, guard scan, MCP relay tools filter, obs admitter and gateway rail, limit sink, cache feed) has a proxy-tagged half, and a build without it starts with the proxy off. The cache engine, the MCP relay and the admission service stay in core.",
		},
		{
			ID: "proxy.compression", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Conversation compression",
			About:    "Rewrites upstream request bodies to compress long conversations and keeps a local stash of removed content.",
			Levels:   lv(onlyL3, l2l3, "P1"),
			Packages: []string{"internal/compression/conversation", "internal/compression/conversation/types", "internal/stash", "internal/stashalign"},
			Requires: []string{"capture.proxy"},
			Surface:  Surface{FilesWritten: []string{"~/.observer/stash/"}},
			Tables:   []string{"compression_events"},
			Routes:   []string{"/api/compression", "/api/experiments", "/api/config/profiles", "/api/config/profile-assignments"},
			// Compression profiles and their A/B experiments (T-674).
			Verbs:        []string{"profile", "experiment"},
			ConfigKeys:   []string{"compression"},
			Stability:    StabilityStable,
			Distros:      dist(out, off, off, off),
			RestartClass: "soft",
		},
		{
			ID: "proxy.routing", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Model routing",
			About:         "Advises on or rewrites the model a routed request uses. `routing apply` writes per-tool vendor config.",
			Levels:        lv([]Level{L1, L3}, l1l2l3, "P5"),
			DirectModules: []string{"github.com/BurntSushi/toml"},
			// The tier table, turn-kind classifier, command classes and the
			// shared decision types are core internal/routingcore since lane
			// MP-L1I (T-715, ruling D-512): the Model Value Report, the
			// store's model-value loader and the MCP recommendation tool use
			// them. The component owns the router engine, the policy
			// compiler, the bases pipeline, Simulate and routing apply.
			Packages:   []string{"internal/routing", "internal/routingconfig", "internal/routingapply"},
			Requires:   []string{"capture.proxy"},
			Surface:    Surface{VendorConfigs: []string{"~/.claude/settings.json model (routing apply)"}},
			Tables:     []string{"router_decisions", "model_calibration"},
			Routes:     []string{"/api/routing"},
			Verbs:      []string{"routing", "model-value"},
			ConfigKeys: []string{"routing"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			ID: "analytics", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Analytics",
			About:         "Cache tracking and expiry warnings, the next-message predictor, advisor, scoring, patterns, suggestions, learning, tasks, handoff and guidance. Pure analysis over captured data, plus two verbs the user runs by hand: `observer metrics` (a Prometheus /metrics listener while it runs) and `observer summarize` (calls the Anthropic Messages API with the user's own key). Nothing starts on its own: no listener and no egress unless one of those verbs is running.",
			Levels:        lv(onlyL3, onlyL3, ""),
			DirectModules: []string{"gopkg.in/yaml.v3"},
			Packages: []string{
				"internal/cachetrack", "internal/cachewarm", "internal/cachewarmsvc", "internal/predict",
				"internal/intelligence/advisor", "internal/intelligence/scoring", "internal/intelligence/patterns",
				"internal/intelligence/suggest", "internal/intelligence/learn", "internal/intelligence/discover",
				"internal/intelligence/modelvalue", "internal/intelligence/compaction", "internal/intelligence/summary",
				"internal/handoff", "internal/handoffsvc", "internal/guidance", "internal/taskflow", "internal/taskreport",
				"internal/metrics",
			},
			Surface: Surface{
				Listeners: []Listener{loopback("127.0.0.1:9090", "none (loopback); --addr can widen it", "", TriggerUserTriggered)},
				Egress:    []Egress{{Host: "api.anthropic.com", Purpose: "observer summarize: session summaries through the Anthropic Messages API with the user's own key", Gate: "user runs the verb", Trigger: TriggerUserTriggered}},
			},
			Tables:     []string{"cache_segments", "cache_entries", "cache_events", "limit_snapshots", "handoffs", "task_items", "task_transitions"},
			Routes:     []string{"/api/cache", "/api/patterns", "/api/suggestions", "/api/tasks", "/api/projects/guidance", "/api/suggest", "/api/discover"},
			Verbs:      []string{"cache-health", "cache-status", "predict", "advise", "score", "patterns", "learn", "suggest", "tasks", "handoff", "guidance", "discover", "metrics", "summarize"},
			ConfigKeys: []string{"cachetrack", "cachewarm", "predict", "advisor", "tasks", "handoff", "guidance"},
			Stability:  StabilityStable,
			Distros:    dist(on, on, on, on),
			Note:       "Stays L3: compiling pure analysis out buys nothing a reviewer can measure, and it feeds core surfaces.",
		},
		{
			ID: "compression.shell", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Shell output compression",
			About:         "Filters noisy shell command output on the hook path before it reaches the model.",
			Levels:        lv(onlyL3, onlyL3, ""),
			DirectModules: []string{"github.com/BurntSushi/toml"},
			Packages:      []string{"internal/compression/shell"},
			ConfigKeys:    []string{"compression"},
			Stability:     StabilityStable,
			Distros:       dist(on, on, on, on),
		},
		{
			ID: "compression.indexing", Class: ClassFeature, Binary: BinaryNode,
			Title:      "Tool output indexing",
			About:      "Indexes tool output excerpts into SQLite FTS5 tables for search and retrieval.",
			Levels:     lv(onlyL3, onlyL3, ""),
			Packages:   []string{"internal/compression/indexing"},
			Routes:     []string{"/api/search"},
			ConfigKeys: []string{"compression"},
			Stability:  StabilityStable,
			Distros:    dist(on, on, on, on),
		},
		{
			ID: "guard", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Guard",
			About:         "Policy decisions on the developer's own coding-agent tool calls: dangerous commands, MCP pins, prompt guard, budgets. Observe mode by default in minimal and developer. Making it inactive stops its background loops, its dashboard pages and `observer guard`, not its decisions: hook-time and proxy-time guard decisions keep running from [guard] (turn those off with [guard].enabled).",
			Levels:        lv(onlyL3, l2l3, "P1"),
			DirectModules: []string{"github.com/BurntSushi/toml"},
			Packages: []string{
				"internal/guard", "internal/guard/mcpsec", "internal/guard/compile", "internal/guard/export",
				"internal/guard/notify", "internal/guardfallback", "internal/guardposture", "internal/policy",
			},
			Surface: Surface{
				FilesWritten: []string{"guard state files beside the DB"},
				// Lane LEFT2-SEC (R-025, PT-04): the desktop notifier for a
				// guard ask (internal/guard/notify), one per OS.
				Processes: []string{"notify-send, osascript or powershell (the desktop notifier for a guard ask)"},
			},
			Tables:     []string{"guard_events", "guard_pins", "guard_approvals", "guard_policy_state", "guard_prompt_presend", "guard_prompt_reconsider"},
			Routes:     []string{"/api/guard"},
			Verbs:      []string{"guard"},
			ConfigKeys: []string{"guard"},
			Stability:  StabilityStable,
			Distros:    dist(on, on, on, on),
			Note:       "Not compile-out-able in this plan: the store, the hook runtime and managed governance depend on it, and it is the mechanism that restricts the other components.",
		},
		{
			ID: "guard.cloud", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Guard webhooks and judge",
			About:    "Sends guard alerts to configured webhooks and asks a configured LLM judge.",
			Levels:   lv(onlyL3, l1l2l3, "P2"),
			HostedIn: []string{"internal/guard/notify"},
			Requires: []string{"guard"},
			Surface: Surface{Egress: []Egress{
				{Host: "<configured webhook>", Purpose: "Guard alert delivery", Gate: "config", Trigger: TriggerOptIn},
				{Host: "<configured judge endpoint>", Purpose: "LLM judge decision", Gate: "config", Trigger: TriggerOptIn},
			}},
			ConfigKeys: []string{"guard"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			ID: "integration.hooks", Class: ClassIntegration, Binary: BinaryNode,
			Title:    "Hook registration",
			About:    "Registers Observer's hook command in each selected AI tool's own hook config, and re-registers on every start.",
			Levels:   lv(onlyL3, l2l3, "P1"),
			Packages: []string{"internal/hook/pluginshim", "internal/hook/hermesplugin", "internal/hook/commandcodemod", "internal/hookdisable"},
			// internal/hookdisable reads the TOML hook switches (VT Code's
			// use_root_config, FU-51) member-only.
			DirectModules: []string{"github.com/BurntSushi/toml"},
			HostedIn:      []string{"internal/hook"},
			Surface: Surface{
				VendorConfigs: []string{"~/.claude/settings.json hooks", "~/.codex/hooks.json", "~/.cursor/hooks.json", "other selected tools' hook configs"},
			},
			Routes:     []string{"/api/setup/hooks"},
			Teardown:   []TeardownStep{{Owner: "internal/clientwire Remover", What: "Removes Observer's hook entries, leaving a user-edited file in place and reported."}},
			Stability:  StabilityStable,
			Distros:    dist(on, on, on, on),
			ConfigKeys: []string{"observer"},
			Note:       "The hook RECEIVER runtime (`observer hook`) is core; only the registration writer is this component.",
		},
		{
			ID: "integration.mcp-server", Class: ClassIntegration, Binary: BinaryNode,
			Title:  "MCP server",
			About:  "The stdio MCP server AI tools spawn for on-demand project queries, and its registration in each tool's MCP config.",
			Levels: lv([]Level{L1, L3}, l1l2l3, "P2"),
			// The toml-writing registrar is core (internal/mcpregister) since
			// lane MP-L1H; the server itself imports no third-party module.
			Packages: []string{"internal/mcp"},
			Surface:  Surface{VendorConfigs: []string{"each selected AI tool's MCP server config"}},
			Teardown: []TeardownStep{{Owner: "internal/clientwire Remover", What: "Removes Observer's MCP server entries."}},
			Routes:   []string{"/api/setup/mcp", "/api/mcp/value"},
			// `observer serve` is the stdio MCP server a registered AI tool
			// spawns; `observer mcp` is the Agent Access node surface
			// (agentaccess.relay), not this component (T-661).
			// mcp-audit reads and prunes the call log the MCP server's retrieval
			// tools write (T-674).
			Verbs:      []string{"serve", "mcp-audit"},
			Tables:     []string{"mcp_audit"},
			Stability:  StabilityStable,
			Distros:    dist(out, off, off, off),
			ConfigKeys: []string{"observer"},
		},
		{
			ID: "integration.proxy-route", Class: ClassIntegration, Binary: BinaryNode,
			Title:         "Proxy routing config",
			About:         "Points AI tools at the local proxy: ANTHROPIC_BASE_URL in Claude Code settings, codex base_url and other per-tool routes.",
			Levels:        lv(onlyL3, l2l3, "P1"),
			DirectModules: []string{"github.com/BurntSushi/toml"},
			Packages:      []string{"internal/proxyroute", "internal/routeprov"},
			Requires:      []string{"capture.proxy"},
			Surface:       Surface{VendorConfigs: []string{"~/.claude/settings.json env.ANTHROPIC_BASE_URL", "~/.codex/config.toml base_url", "other proxied tools' route settings"}},
			Teardown: []TeardownStep{
				{Owner: "internal/clientwire Remover", What: "Removes the route first; the proxy listener stops only after the route is off."},
			},
			// The dashboard's Claude Code and Codex route writers (T-671):
			// an inactive component writes no vendor config (L2).
			Routes:    []string{"/api/setup/claude", "/api/setup/codex"},
			Stability: StabilityStable,
			Distros:   dist(out, on, on, on),
		},
		{
			ID: "integration.statusline", Class: ClassIntegration, Binary: BinaryNode,
			Title:     "Claude Code statusline",
			About:     "Installs Observer's statusLine command in Claude Code settings. Opt-in through `observer init --statusline`.",
			Levels:    lv(onlyL3, l2l3, "P1"),
			Packages:  []string{"internal/statusline"},
			Surface:   Surface{VendorConfigs: []string{"~/.claude/settings.json statusLine"}},
			Teardown:  []TeardownStep{{Owner: "observer statusline uninstall", What: "Removes the statusLine entry."}},
			Routes:    []string{"/api/statusline"},
			Verbs:     []string{"statusline"},
			Stability: StabilityStable,
			Distros:   dist(off, off, off, off),
			Note:      "The plan table shows this out of minimal, but the plan gives it no L1 level, so minimal compiles it in and inactive (L2) until a phase adds L1.",
		},
		{
			ID: "integration.shell-wrap", Class: ClassIntegration, Binary: BinaryNode,
			Title:         "Command wrapping",
			About:         "PATH shims so typing a tool's name runs it through Observer, placed first on PATH by marked blocks in shell rc files or the PowerShell profile.",
			Levels:        lv([]Level{L1, L3}, l1l2l3, "P2"),
			DirectModules: []string{"golang.org/x/sys"},
			Packages:      []string{"internal/shellwrap", "internal/shellwrapsvc"},
			Surface: Surface{
				FilesWritten:  []string{"~/.observer/shims/"},
				OSIntegration: []string{"bash and zsh rc blocks", "fish conf.d drop-in", "PowerShell profile block"},
				Processes:     []string{"reg (reads the Windows shell folder over WSL interop)"},
			},
			Teardown:   []TeardownStep{{Owner: "observer shell-wrap disable", What: "Removes the shims and the marked blocks byte-exactly."}},
			Routes:     []string{"/api/shell-wrap"},
			Verbs:      []string{"shell-wrap"},
			ConfigKeys: []string{"shell_wrap"},
			Ledger:     []string{"SHELLWRAP-1"},
			Stability:  StabilityStable,
			Distros:    dist(out, off, out, off),
		},
		{
			ID: "integration.agent-config", Class: ClassIntegration, Binary: BinaryNode,
			Title:         "AI tool settings editor",
			About:         "The dashboard editor for AI tools' own settings files, validated against vendor schemas.",
			Levels:        lv(onlyL3, l2l3, "P1"),
			Packages:      []string{"internal/agentconfig", "internal/agentconfig/vendorschema", "internal/agentconfigsvc", "internal/agentconfigorg"},
			DirectModules: []string{"github.com/santhosh-tekuri/jsonschema/v6", "golang.org/x/text"},
			Surface:       Surface{VendorConfigs: []string{"AI tool settings files the user edits in the dashboard"}},
			Tables:        []string{"agent_config_layers", "agent_config_writes", "agent_config_org_state"},
			Routes:        []string{"/api/agent-config"},
			Verbs:         []string{"agent-config"},
			Stability:     StabilityStable,
			Distros:       dist(off, on, off, on),
			Note:          "The plan table shows this out of minimal, but the plan gives it no L1 level, so minimal compiles it in and inactive (L2) until a phase adds L1.",
		},
		{
			ID: "codeintel", Class: ClassFeature, Binary: BinaryNode,
			Title:  "Code intelligence",
			About:  "In-process symbol, import and call-graph extraction with search and analysis, using tree-sitter grammars run under the wazero WebAssembly runtime (about 5.1 MB of grammars).",
			Levels: lv([]Level{L1, L3}, l1l2l3, "P2"),
			// The facade (internal/codeintelapi) and the MCP regex fallback
			// (internal/codeintel/parse/livesym, stdlib only) are core since
			// lane MP-L1H (T-715): the MCP symbol tools answer from them with
			// no index.
			Packages: []string{
				"internal/codeintel", "internal/codeintel/resolve", "internal/codeintel/semantic", "internal/codeintel/parse",
				"internal/codeintel/parse/goast", "internal/codeintel/parse/heuristic", "internal/codeintel/parse/treesitter",
				"internal/codeintel/index", "internal/codeintel/analyze",
				"internal/codeintel/query", "internal/codeintel/surface",
			},
			DirectModules: []string{"github.com/tetratelabs/wazero", "github.com/klauspost/compress"},
			Tables:        []string{"codeintel_files", "codeintel_nodes", "codeintel_edges", "codeintel_sites", "codeintel_embeddings", "codeintel_minhash"},
			Verbs:         []string{"codeintel", "index"},
			ConfigKeys:    []string{"codeintel"},
			Stability:     StabilityPreview,
			Distros:       dist(out, off, off, off),
		},
		{
			ID: "terminals", Class: ClassFeature, Binary: BinaryNode,
			Title:  "Terminals",
			About:  "The terminal cockpit: dashboard terminals over a websocket, session attach, launching and installing AI tools, and workspaces. Runs vendor CLIs and installers.",
			Levels: lv([]Level{L1, L3}, l1l2l3, "P2"),
			// Since lane MP-L1K (T-715) the neutral vocabulary core packages
			// speak is core: internal/termcore (run kinds, standing denial
			// classes, the shell pseudo-tool, sandbox sentinels, project-root
			// validators), internal/localipc (the owner-only socket / pipe
			// transport the MCP relay shares) and internal/toolinstall (pure
			// install / runtime planning the launch preflight and doctor read).
			Packages: []string{
				"internal/termsession", "internal/termsvc", "internal/termrun", "internal/termfeed", "internal/termlease",
				"internal/termoob", "internal/termscan", "internal/termstatus", "internal/attachsock",
				"internal/workspace", "internal/guilaunch", "internal/launch",
			},
			HostedIn:      []string{"internal/intelligence/dashboard"},
			DirectModules: []string{"github.com/creack/pty", "github.com/coder/websocket", "golang.org/x/sys"},
			Surface: Surface{
				Listeners: []Listener{
					{Proto: "unix", Addr: "~/.observer/attach/<socket>", Loopback: true, Auth: "owner-only (0700 dir, 0600 socket)", Trigger: TriggerAutomatic},
					{Proto: "pipe", Addr: `\\.\pipe\observer-attach-<hash>`, Loopback: true, Auth: "owner-only ACL, deny network", Trigger: TriggerAutomatic},
				},
				Processes: []string{"vendor AI tool CLIs", "vendor installers", "wt, cmd or osascript (the terminal emulator for an external launch)", "x-terminal-emulator, gnome-terminal, konsole, xfce4-terminal or xterm (the first one found, for an external launch on a Linux desktop)"},
			},
			Tables:     []string{"terminal_run", "terminal_run_session", "terminal_commands", "tool_installs", "workspace_layouts", "launch_seeds"},
			Routes:     []string{"/api/terminal", "/api/launch", "/api/attach", "/ws/terminal", "/ws/launch", "/api/tools/launch"},
			Verbs:      []string{"workspaces", "ide"},
			ConfigKeys: []string{"terminal", "launch"},
			Ledger:     []string{"ATT-1"},
			Stability:  StabilityStable,
			Distros:    dist(out, on, off, on),
		},
		{
			ID: "terminals.ssh", Class: ClassFeature, Binary: BinaryNode,
			Title:      "SSH terminals",
			About:      "Remote terminals through SSH profiles and local port forwards. Runs the system ssh client.",
			Levels:     lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages:   []string{"internal/sshforward", "internal/sshprofile"},
			Requires:   []string{"terminals"},
			Surface:    Surface{Processes: []string{"ssh", "ssh-keygen (the known_hosts pre-flight)"}},
			Routes:     []string{"/api/terminal/ssh"},
			Verbs:      []string{"ssh"},
			ConfigKeys: []string{"terminal"},
			Stability:  StabilityStable,
			Distros:    dist(out, on, off, on),
		},
		{
			// The isolation engine (sandbox plan v2 section 11.1, roadmap
			// F0-11, ruled D-774 "Yes to both"): the bwrap planners and one
			// small API, a one-shot isolated run of a single program with no
			// network, for a caller outside the sandbox module. It does not
			// require dashboard terminals, so an org that wants isolated
			// scanner runs need not turn terminals on. A consumer receives an
			// extrun.IsolationFactory from the cmd layer only while this row
			// is active (cmd/observer/isolation_wire.go), never an import.
			ID: "isolation", Class: ClassFeature, Binary: BinaryNode,
			Title:     "Isolation engine",
			About:     "Runs a single program with no network, a read-only project and one writable output and cache directory (bubblewrap; Linux and WSL2). Used by sandboxed terminals and by scanners that ask for isolation.",
			Levels:    lv([]Level{L1, L2}, []Level{L1, L2}, ""),
			Packages:  []string{"internal/sandbox", "internal/isolation"},
			Surface:   Surface{Processes: []string{"bwrap"}},
			Stability: StabilityPreview,
			Distros:   dist(out, off, off, off),
		},
		{
			// The signed seal over each terminal run's execution evidence
			// digest (ledger SHR-6, lane GATES-SEC): an opt-in child of
			// isolation, active only under a [components] block that selects
			// it (componentOptInRules, cmd/observer/evidence_seal.go). Off,
			// no key is made and run rows are byte-identical.
			ID: "isolation.seal", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Signed run evidence",
			About:    "Signs each terminal run's execution evidence digest with a key on this machine, so a later edit of the stored run facts by someone without the key no longer verifies. A managed node registers the key with its org, which verifies and countersigns the seal; an individual node's seal is self-attested. Tamper evidence for the stored record, not proof of what happened on the machine.",
			Levels:   lv(l1l2l3, l1l2l3, ""),
			Requires: []string{"isolation"},
			Surface: Surface{
				FilesWritten: []string{"the OS keychain (service sbo-exec-evidence-v1, the Ed25519 seal key), or a 0600 file beside the database where no keychain exists (reported)"},
			},
			Ledger:    []string{"SHR-6"},
			Stability: StabilityPreview,
			Distros:   dist(out, off, off, off),
		},
		{
			ID: "terminals.sandbox", Class: ClassFeature, Binary: BinaryNode,
			Title:      "Sandboxes and VMs",
			About:      "Runs dashboard terminal launches inside an isolation backend, with an honest capture level per run. Backends today: bubblewrap (Linux and WSL2), Docker or Podman containers through the separate, opt-in terminals.sandbox.oci driver, Windows ProcessContainers through the opt-in terminals.sandbox.mxc driver, and on macOS the opt-in beta Seatbelt and Apple container drivers.",
			Levels:     lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages:   []string{"internal/sandboxnet", "internal/sandboxbackend", "internal/sandboxselect", "internal/policyfam/terminalsisolation"},
			Requires:   []string{"terminals", "isolation"},
			Surface:    Surface{Processes: []string{"bwrap", "git (workspace clone and worktree preparation)", "observer (the sandbox-host and sandbox-guest network helpers, and the capture relay's host-side children: observer hook and the sandbox-gate launch-gate helper)"}, Listeners: []Listener{{Proto: "unix", Addr: "<sandbox forwarder socket>", Loopback: true, Auth: "owner-only", Trigger: TriggerOptIn}, {Proto: "unix", Addr: "<capture relay socket>", Loopback: true, Auth: "owner-only, peer uid checked, per-run keyed frames", Trigger: TriggerOptIn}, {Proto: "unix", Addr: "<observer dir>/sandbox-relay/attach/attach.sock", Loopback: true, Auth: "owner-only, peer uid checked, per-run link key", Trigger: TriggerAutomatic}}},
			Routes:     []string{"/api/terminal/sandbox"},
			Verbs:      []string{"sandbox"},
			ConfigKeys: []string{"terminal"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			// The oci-runc sandbox driver (sandbox plan v2 sections 4.6 and
			// 11.3, phase P3, lane SBX-P3A): Docker Engine or Podman driven
			// through the Engine API on a local unix socket. A driver is its
			// own component: inactive in every distro (section 10.1), and on
			// an install with no [components] block it stays off too until a
			// block names it (sandboxDriverOptIn, cmd/observer). Nothing
			// probes, dials a socket or starts while [terminal.sandbox] is off
			// or "oci-runc" is not in [terminal.sandbox].backends.
			ID: "terminals.sandbox.oci", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Container sandboxes (Docker, Podman)",
			About:    "Runs sandboxed terminal launches inside a container on this machine's own Docker Engine or Podman (Linux and WSL2), driven through the engine's local socket. Rootless engines are preferred; a rootful one only after an explicit opt-in.",
			Levels:   lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages: []string{"internal/sandboxoci", "internal/sandboxengine"},
			Requires: []string{"terminals.sandbox"},
			Surface: Surface{
				Processes:    []string{"observer (the sandbox-oci-host helper on the host and the sandbox-oci-init process inside the container)", "the container engine's own processes, started by the engine (Docker Engine or Podman), never by Observer"},
				Listeners:    []Listener{{Proto: "unix", Addr: "<per-run socket dir> bound read-only into the container at /tmp/.observer-sandbox-net", Loopback: true, Auth: "owner-only, peer uid checked, per-run keyed frames", Trigger: TriggerOptIn}},
				FilesWritten: []string{"~/.observer/sandbox-oci/ (the install id, the engine identities recorded at first use, the per-run plan files)"},
			},
			ConfigKeys: []string{"terminal"},
			Ledger:     []string{"SBX-BE-3", "SBX-BE-10"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			// The mxc-process sandbox driver (sandbox plan v2 sections 4.6,
			// 5.2 and 11.3, phase P6, lane SBX-P6): Microsoft Execution
			// Containers' ProcessContainer on native Windows 11, through MXC's
			// mxc_ffi C ABI (loaded only in a per-run helper process, never
			// the daemon) and `wxc-exec --config <file>` under the terminal's
			// own ConPTY. Inactive in every distro; on an install with no
			// [components] block it stays opt-in (sandboxDriverOptIn). The
			// MXC files are bundled, hash-pinned and Authenticode-checked,
			// only in the Windows packages of the distros that compile this
			// row. Nothing probes, opens a file or starts while
			// [terminal.sandbox] is off or "mxc-process" is not in
			// [terminal.sandbox].backends.
			ID: "terminals.sandbox.mxc", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Windows sandboxes (MXC)",
			About:         "Runs sandboxed terminal launches on native Windows 11 inside a Microsoft Execution Containers ProcessContainer (AppContainer with the PSEC BaseContainer tier and a per-container firewall), with the MXC files bundled and hash-checked. Needs Windows 11 build 26100.9278, 26200.9278 or later; host ACLs are never changed. On WSL2 use the Linux backends instead.",
			Levels:        lv([]Level{L1, L3}, l1l2l3, "P6"),
			Packages:      []string{"internal/sandboxmxc", "internal/sandboxmxcdll"},
			DirectModules: []string{"golang.org/x/sys"},
			Requires:      []string{"terminals.sandbox"},
			Surface: Surface{
				Processes: []string{"observer (the sandbox-mxc-probe and sandbox-mxc-host helpers, the only processes that load mxc_ffi.dll)", "wxc-exec.exe (MXC's executor, bundled and hash-checked, run inside the terminal's ConPTY)"},
				Listeners: []Listener{
					{Proto: "tcp", Addr: "127.0.0.1:<per-run port> (the run's one loopback port: relay, model proxy and egress gateway)", Loopback: true, Auth: "per-run token, scoped to the run's network tier; relay frames keyed per run", Trigger: TriggerOptIn},
					{Proto: "pipe", Addr: `\\.\pipe\observer-attach-<hash of the run's OOB endpoint>`, Loopback: true, Auth: "owner-only ACL, deny network", Trigger: TriggerOptIn},
				},
				FilesWritten: []string{"~/.observer/sandbox-mxc/ (the per-run plan files)", "%TEMP%\\observer-sbx-<run> (the run's launch record and its private temp directory, removed at the end of the run)"},
			},
			ConfigKeys: []string{"terminal"},
			Ledger:     []string{"SBX-BE-15", "SBX-SUP-1"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			// The Landlock-only sandbox driver, the process_lite row (sandbox
			// plan v2 sections 4.1 and 13 P3, lane SBX-P3B): beta
			// (Verification = doc; register entry LIN-1 owes a native Linux
			// 7.1+ host), explicit-only, never picked automatically. Its own
			// component, inactive in every distro and on an install with no
			// [components] block (sandboxDriverSelected, cmd/observer).
			// Nothing reads the Landlock ABI or starts while
			// [terminal.sandbox] is off or "process_lite" is not in
			// [terminal.sandbox].backends.
			ID: "terminals.sandbox.landlock", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Landlock-only sandboxes (beta)",
			About:    "Runs sandboxed terminal launches under Linux Landlock alone, for hosts that block the user namespaces bubblewrap needs. Weaker than bubblewrap: no private /proc, process list or network, and UDP stays open below Landlock ABI 10. Needs Landlock ABI 9 (Linux 7.1 or newer); used only when chosen by name.",
			Levels:   lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages: []string{"internal/sandboxlandlock"},
			Requires: []string{"terminals.sandbox"},
			Surface: Surface{
				Processes: []string{
					"observer (the sandbox-host helper on the host and the sandbox-landlock-exec step that restricts itself, checks the ruleset and then runs the agent)",
				},
				Listeners: []Listener{
					{Proto: "unix", Addr: "<per-run socket dir>/relay.sock (the capture relay)", Loopback: true, Auth: "owner-only, peer uid checked, per-run keyed frames", Trigger: TriggerOptIn},
				},
				FilesWritten: []string{"~/.observer/sandbox-landlock/plans/ (the per-run plan files)", "the per-run socket dir and TMPDIR under the user's temp dir"},
			},
			ConfigKeys: []string{"terminal"},
			Ledger:     []string{"SBX-BE-17"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			// The macOS Seatbelt sandbox driver (sandbox plan v2 section 13
			// P5, lane SBX-P5): beta (Verification = doc, never run on a Mac;
			// register section 13.9). Its own component, inactive in every
			// distro and on an install with no [components] block
			// (sandboxDriverSelected, cmd/observer). Nothing reads the macOS
			// version, stats sandbox-exec or runs anything while
			// [terminal.sandbox] is off or "seatbelt" is not in
			// [terminal.sandbox].backends; off macOS the probe refuses at its
			// platform row.
			ID: "terminals.sandbox.seatbelt", Class: ClassFeature, Binary: BinaryNode,
			Title:    "macOS Seatbelt sandboxes (beta)",
			About:    "Runs sandboxed terminal launches under Apple's Seatbelt on macOS, with a profile generated from the same bind and protect tables as the Linux sandbox. Beta: built from vendor documentation and not yet proven on a Mac.",
			Levels:   lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages: []string{"internal/sandboxsbpl"},
			Requires: []string{"terminals.sandbox"},
			Surface: Surface{
				Processes: []string{
					"sandbox-exec (Apple's /usr/bin/sandbox-exec, the only path ever run)",
					"observer (the sandbox-seatbelt-host helper on the host and the sandbox-seatbelt-selftest check under the profile)",
				},
				Listeners: []Listener{
					{Proto: "unix", Addr: "<per-run socket dir>/relay.sock (the capture relay)", Loopback: true, Auth: "owner-only, peer uid checked, per-run keyed frames", Trigger: TriggerOptIn},
					{Proto: "tcp", Addr: "127.0.0.1:<ephemeral> (the run's egress gateway, internet tier)", Loopback: true, Auth: "loopback; refuses host-local destinations and the model-provider hosts", Trigger: TriggerOptIn},
				},
				FilesWritten: []string{"~/.observer/sandbox-seatbelt/plans/ (the per-run plan files)", "the per-run socket dir and TMPDIR under the user's temp dir"},
			},
			ConfigKeys: []string{"terminal"},
			Ledger:     []string{"SBX-MAC-1"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			// The Apple container sandbox driver (sandbox plan v2 section 13
			// P5, lane SBX-P5): macOS 26 on Apple silicon, the user's own
			// `container` CLI; beta (Verification = doc). Same opt-in rule as
			// the other drivers; nothing runs `container` while the sandbox
			// is off or "apple-container" is not listed.
			ID: "terminals.sandbox.apple-container", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Apple container sandboxes (beta)",
			About:    "Runs sandboxed terminal launches inside a lightweight Linux VM through Apple's own container CLI (macOS 26 on Apple silicon), with no network but the run's own sockets. Beta: built from vendor documentation and not yet proven on a Mac.",
			Levels:   lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages: []string{"internal/sandboxapple"},
			Requires: []string{"terminals.sandbox"},
			Surface: Surface{
				Processes: []string{
					"container (Apple's container CLI, installed by the user; container run, inspect, ls, rm, system status, image ls; never container machine)",
					"observer (the sandbox-apple-host helper on the host; a linux/arm64 observer from the configured image runs inside as the guest helper)",
				},
				Listeners:    []Listener{{Proto: "unix", Addr: "<per-run socket dir> mounted read-only into the container at /tmp/.observer-sandbox-net", Loopback: true, Auth: "owner-only, peer uid checked, per-run keyed frames", Trigger: TriggerOptIn}},
				FilesWritten: []string{"~/.observer/sandbox-apple-container/ (the install id and the per-run plan files)"},
			},
			ConfigKeys: []string{"terminal"},
			Ledger:     []string{"SBX-MAC-1"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			// The Cloud Hypervisor microVM sandbox driver (sandbox plan v2
			// section 13 P4, lane SBX-P4): beta (Verification = doc; register
			// LIN-2 onward), Linux and WSL2 with /dev/kvm. Its own component,
			// inactive in every distro and on an install with no [components]
			// block (sandboxDriverSelected, cmd/observer). Nothing opens
			// /dev/kvm, stats a binary, reads the content store or touches
			// the network while [terminal.sandbox] is off or
			// "cloud-hypervisor" is not in [terminal.sandbox].backends; the
			// probe never boots a VM and never fetches.
			ID: "terminals.sandbox.vm", Class: ClassFeature, Binary: BinaryNode,
			Title:    "microVM sandboxes (Cloud Hypervisor, beta)",
			About:    "Runs sandboxed terminal launches inside a Cloud Hypervisor microVM on this machine (Linux and WSL2 with /dev/kvm), with no network device and the terminal carried over vsock, booted from Observer's signed guest image set. Beta: built from vendor documentation and not yet proven end to end on real hardware.",
			Levels:   lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages: []string{"internal/sandboxvm", "internal/sandboxvmm"},
			Requires: []string{"terminals.sandbox"},
			Surface: Surface{
				Processes: []string{
					"cloud-hypervisor (the user's own Cloud Hypervisor 54 binary, one per run, started by the sandbox-vm-host helper)",
					"virtiofsd (one per shared folder, unprivileged; for a live workspace inside bwrap)",
					"bwrap (the mount namespace around a live workspace's virtiofsd)",
					"mkfs.ext4 (only for a disk_image workspace copy)",
					"debugfs inside bwrap (only to read a disk_image copy back: the host root read-only, every namespace unshared, the fresh target dir the only writable path)",
					"observer (the sandbox-vm-host helper on the host; sandbox-vm-init is PID 1 inside the guest)",
				},
				Listeners: []Listener{
					{Proto: "unix", Addr: "<run socket dir>/api.sock (the VMM's REST API, peer pid checked; the socket dir is the run state dir, or /tmp/obvm-<uid>/<run> when that is too deep)", Loopback: true, Auth: "owner-only directory, peer credentials the recorded VMM pid", Trigger: TriggerOptIn},
					{Proto: "unix", Addr: "<run socket dir>/vsock.sock (the VMM's hybrid vsock; the relay mux with per-run keyed frames)", Loopback: true, Auth: "owner-only directory, per-run keyed frames", Trigger: TriggerOptIn},
				},
				FilesWritten: []string{"~/.observer/sandbox-vm/ (the per-run 0700 state dirs: plan, sockets, serial log, process records, disk copies)", "~/.observer/sandbox-content/sandbox.rootfs and sandbox.guest_binary (only through `observer sandbox content import` or a user fetch)", "/tmp/obvm-<uid>/<run>/ (a run's sockets, only when its state dir is too deep for the 107-byte socket path limit)"},
			},
			ConfigKeys: []string{"terminal"},
			Ledger:     []string{"SBX-BE-4", "SBX-BE-5", "SBX-IMG-1"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			// Re-adoption of a LOCAL container run whose host helper went
			// away, and the Podman checkpoint and restore (sandbox plan v2
			// section 5.5, gap G50, lane GATES-SBX, operator ruling P-129).
			// Inactive in every distro and opt-in on an install with no
			// [components] block (sandboxFeatureOptIn, cmd/observer). With it
			// off the oci reaper reaps exactly as before; a checkpoint only
			// ever runs on a user action.
			ID: "terminals.sandbox.oci.readopt", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Re-adopt container runs and Podman checkpoints (beta)",
			About:    "Keeps a container run whose helper was killed (SIGKILL or the OOM killer) on rootful Docker with live-restore or on Podman, and offers to re-attach it with an empty scrollback and a marker, instead of removing it (a daemon exit or restart still removes the run: the helper removes its container when the daemon hangs up); a run nobody re-adopts within the bound (10 minutes) is removed as before. Also lets you checkpoint a run on rootful Podman with CRIU to a local file and restore it, only when you ask.",
			Levels:   lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages: []string{"internal/sandboxadopt"},
			Requires: []string{"terminals.sandbox.oci"},
			Surface: Surface{
				Processes:    []string{"observer (the sandbox readopt helper, started by you from `observer sandbox readopt` in your own terminal)"},
				FilesWritten: []string{"~/.observer/sandbox-adopt/ (each run's kept plan and offer, and a checkpoint export you asked for, owner-only)"},
			},
			ConfigKeys: []string{"terminal"},
			Ledger:     []string{"SBX-BE-6"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			// Credential injection for sandboxed runs (sandbox plan v2
			// sections 7.2 and 7.3, gap G24, lane GATES-SBX, operator
			// ruling P-129). Inactive in every distro and opt-in on an
			// install with no [components] block (sandboxFeatureOptIn,
			// cmd/observer). With it off the proxy has no injector and the
			// hosted driver's home_relay rule is as before.
			ID: "terminals.sandbox.credentials", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Credential injection for sandboxed runs (beta)",
			About:    "Keeps your own provider API key on this machine (the OS keychain) for a hosted sandboxed run with key custody home_relay: the box gets only a per-run sentinel, and Observer's proxy swaps it for your key on requests to that provider's model host. The provider-injected custody (a vendor's own secret broker) is described but not offered yet.",
			Levels:   lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages: []string{"internal/sandboxcred"},
			Requires: []string{"terminals.sandbox"},
			Surface: Surface{
				FilesWritten: []string{"the OS keychain, service sbo-sandbox-cred-v1 (your provider keys; a 0600 file store under ~/.observer/sandbox-cred/keys only when no keychain is usable)", "~/.observer/sandbox-cred/runs/ (each hosted run's sentinel and relay token hashes, owner-only, removed at the end of the run)"},
			},
			ConfigKeys: []string{"terminal"},
			Ledger:     []string{"SBX-NET-2"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			// MXC's weaker AppContainer tier (lane GATES-SBX decision 5,
			// operator ruling P-129): the mxc-appcontainer row, probe-only in
			// this release. Inactive in every distro and opt-in
			// (sandboxDriverOptIn); nothing runs while the row is not listed.
			ID: "terminals.sandbox.mxc.appcontainer", Class: ClassFeature, Binary: BinaryNode,
			Title: "Windows sandboxes, AppContainer tier (beta)",
			About: "Checks whether Microsoft Execution Containers offers its weaker AppContainer tier on this machine (Windows Home often has no ProcessContainer tier). Weaker than ProcessContainer: an AppContainer sees every folder whose access list grants ALL APPLICATION PACKAGES. Probe only in this release; a launch is refused by name.",
			// No package of its own: it uses terminals.sandbox.mxc's
			// internal/sandboxmxc (its per-row tier set, tiers.go).
			Levels:   lv([]Level{L1, L3}, l1l2l3, "P6"),
			Requires: []string{"terminals.sandbox.mxc"},
			Surface: Surface{
				Processes: []string{"observer (mxc-process's own sandbox-mxc-probe helper, the only process that loads mxc_ffi.dll)"},
			},
			ConfigKeys: []string{"terminal"},
			Ledger:     []string{"SBX-BE-9"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			// The wslc row (lane GATES-SBX decision 6): WSL containers on
			// Windows 11, probe-only in this release.
			ID: "terminals.sandbox.wslc", Class: ClassFeature, Binary: BinaryNode,
			Title:    "WSL container sandboxes, wslc (beta)",
			About:    "Checks for WSL and the wslc CLI on Windows 11 for running sandboxed launches in a Linux container with no network. Probe only in this release (the supported wslc version is not recorded yet); a launch is refused by name.",
			Levels:   lv([]Level{L1, L3}, l1l2l3, "P6"),
			Packages: []string{"internal/sandboxwslc"},
			Requires: []string{"terminals.sandbox"},
			Surface: Surface{
				Processes: []string{"wsl.exe --version and wslc --version, wslc run --help (read only, while the row is listed)"},
			},
			ConfigKeys: []string{"terminal"},
			Ledger:     []string{"SBX-BE-9"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			// The hcs row (lane GATES-SBX decision 7): Hyper-V isolated
			// containers, probe-only in this release.
			ID: "terminals.sandbox.hcs", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Hyper-V isolated container sandboxes, HCS (beta)",
			About:         "Checks the Windows edition and the Hyper-V and Containers features for running sandboxed launches in Hyper-V isolated containers with no network. Probe only in this release (no utility VM image is published yet); a launch is refused by name.",
			Levels:        lv([]Level{L1, L3}, l1l2l3, "P6"),
			Packages:      []string{"internal/sandboxhcs"},
			DirectModules: []string{"golang.org/x/sys"},
			Requires:      []string{"terminals.sandbox"},
			ConfigKeys:    []string{"terminal"},
			Ledger:        []string{"SBX-BE-9"},
			Stability:     StabilityPreview,
			Distros:       dist(out, off, off, off),
		},
		// The hosted sandbox drivers (sandbox plan v2 section 13 P7, lane
		// SBX-P7, operator ruling P-080): E2B, Modal and Vercel Sandbox,
		// each its own component, inactive in every distro and opt-in on an
		// install with no [components] block (sandboxDriverSelected). Each
		// is beta (Verification doc) until a live receipt. Nothing reads a
		// credential, calls the vendor, uploads or starts a timer before a
		// user launches a sandboxed terminal on the row (or confirms a
		// leftover-box action); the probe reads local facts only.
		hostedDriverRow("terminals.sandbox.e2b", "E2B hosted sandboxes (beta)",
			"Runs sandboxed terminal launches in an E2B Firecracker microVM on E2B's machines, through E2B's REST and envd process API. Your workspace files are uploaded after you consent once; hooks reach this machine through the capture relay. Beta: built from E2B's documentation, not yet run with a real account.",
			"internal/sandboxremote/e2b", nil),
		hostedDriverRow("terminals.sandbox.modal", "Modal hosted sandboxes (beta)",
			"Runs sandboxed terminal launches in a Modal sandbox (gVisor) on Modal's machines, through Modal's own Go SDK. Your workspace files are uploaded after you consent once; hooks reach this machine through the capture relay. Beta: built from Modal's documentation and SDK, not yet run with a real account.",
			"internal/sandboxremote/modal", []string{"github.com/modal-labs/modal-client/go", "google.golang.org/grpc"}),
		hostedDriverRow("terminals.sandbox.vercel", "Vercel hosted sandboxes (beta)",
			"Runs sandboxed terminal launches in a Vercel Sandbox Firecracker microVM on Vercel's machines, through Vercel's REST API. Your workspace files are uploaded after you consent once; hooks reach this machine through the capture relay. Beta: built from Vercel's documentation, not yet run with a real account.",
			"internal/sandboxremote/vercel", nil),
		{
			// The security pillar's module root (security pillar plan
			// docs/plans/security-pillar-plan-2026-10-19.md section 4.2,
			// Phase A). Its children (security.trust, security.secrets,
			// security.deps, security.code and the drivers) are added by the
			// phases that build them, each with its own row.
			ID: "security", Class: ClassFeature, Binary: BinaryNode,
			Title:  "Code security",
			About:  "Agent-aware code and supply-chain security on top of Guard: the findings store, the signed per-project posture the commit gate reads, the quick-scan channel and the Code security page. The core Guard rules R-112 to R-114 and R-165 are Guard's and stay active when this module is skipped.",
			Levels: lv(l1l2l3, l1l2l3, ""),
			Packages: []string{
				"internal/secfinding", "internal/secfinding/sarif", "internal/secscan", "internal/secsvc",
				"internal/secrules", "internal/secipc", "internal/secverify", "internal/secexcept", "internal/secmcp", "internal/secgithooks",
				"internal/secchange", "internal/seccifetch", "internal/secchangeexport",
				// The scanner drivers' shared pure cores (lane GATES-SEC): the
				// engine supply chain (pins, the offline signature pre-check,
				// the companion tree record) Opengrep, Trivy and KICS share,
				// and the IaC engines' core. Linked only by a compiled driver.
				"internal/secengine", "internal/seciac",
			},
			DirectModules: []string{"github.com/BurntSushi/toml"},
			Requires:      []string{"guard"},
			Surface: Surface{
				Egress: []Egress{
					{Host: "<the org server named by --org-url>", Purpose: "CI verify fetch: the org's signed CI policy, the change records of a pull request's commits (commit shas and patch fingerprint hashes) and pinned drivers from the org's security mirror", Gate: "`observer security verify fetch` only, run by a CI job with a CI credential; no daemon path links it", Trigger: TriggerUserTriggered},
				},
				Listeners: []Listener{
					{Proto: "unix", Addr: "~/.observer/security/attach/attach.sock", Loopback: true, Auth: "owner-only (0700 dir, 0600 socket)", Trigger: TriggerAutomatic},
					{Proto: "pipe", Addr: `\\.\pipe\observer-attach-<hash of the security endpoint>`, Loopback: true, Auth: "owner-only ACL, deny network", Trigger: TriggerAutomatic},
				},
				FilesWritten: []string{"~/.observer/security/ (signed per-project posture files, dirty markers, seen marks)"},
			},
			Tables:       []string{"sec_findings", "sec_finding_events", "sec_scan_runs", "sec_baselines", "sec_finding_exceptions", "sec_finding_sightings", "sec_finding_commits"},
			Routes:       []string{"/api/security"},
			Verbs:        []string{"security"},
			ConfigKeys:   []string{"security"},
			Ledger:       []string{"SHR-4", "SECP-1", "SECP-2", "SECP-3", "SECP-4", "SECP-11", "SECP-17", "SECP-23"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, on, off, on),
		},
		{
			// Security Phase B (lanes sec-b, sec-b2, sec-trustfix,
			// sec-trust2, sec-trust3): repository trust at the launch
			// chokepoint (the repo.trust row of launch_gates.go), rules
			// S-701 to S-705, the config baseline, the session-start flag and
			// `observer security trust`. On in the developer and full
			// distros and on an install with no [components] block: the
			// orchestrator offered it (plans decision log P-044) once the
			// blockers of P-022, P-029, P-031 and P-037 were closed.
			ID: "security.trust", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Repository trust",
			About:         "Checks the commands a repository makes an agent run (project hooks, MCP stdio servers, plugins, folder-open tasks) before an agent launches there, and records the developer's accept of each exact digest.",
			Levels:        lv(l1l2l3, l1l2l3, ""),
			Packages:      []string{"internal/sectrust", "internal/sectrustitem"},
			DirectModules: []string{"github.com/BurntSushi/toml", "github.com/tailscale/hujson", "gopkg.in/yaml.v3"},
			Requires:      []string{"security"},
			// [security.trust]; config.ComponentSections sets it aside while this
			// component is not active.
			ConfigKeys:   []string{"security"},
			Tables:       []string{"sec_config_baseline", "sec_config_files"},
			Routes:       []string{"/api/security/trust"},
			Ledger:       []string{"SECP-5"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, on, off, on),
		},
		{
			// Security Phase D3 (lane sec-d3): user-configured scanner
			// drivers (driver kind custom, plan section 8.6). Off in every
			// distro; background only, never in a hook or the quick scan.
			// Runs go through the hardened runner (internal/extrun) and,
			// where the isolation component can hold them, its no-network
			// one-shot, which the cmd layer injects (never an import).
			ID: "security.scan.custom", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Custom scanners",
			About:    "Runs a scanner you configured through a structured, digest-pinned manifest (templates for gosec, Bandit and Semgrep) and reads only its SARIF. Findings are flag-only by default.",
			Levels:   lv(l1l2l3, l1l2l3, ""),
			Packages: []string{"internal/seccustom", "internal/seccustomsvc"},
			Requires: []string{"security"},
			// [security.custom] (scheduled runs); config.ComponentSections
			// sets it aside while this component is not active.
			ConfigKeys: []string{"security"},
			Surface: Surface{
				Processes:    []string{"the executable a custom scanner manifest pins (gosec, bandit, semgrep from the built-in templates) and its declared companions (go, python3)", "bwrap (isolated runs, through the isolation component)"},
				FilesWritten: []string{"~/.observer/security/custom/ (accepted manifests and their audit log)", "<user cache>/superbased-observer/scanners/ (per-driver caches and per-run directories)"},
			},
			Routes:       []string{"/api/security/scanners/custom"},
			Ledger:       []string{"SECP-21"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, off, off, off),
		},
		{
			// Security Phase C (lanes sec-c and sec-c2): secret detection on
			// proposed writes (S-721), written files (the post-write seam),
			// staged and committed diffs (the commit quick scan and the
			// commit scan). A runtime child: its rules sit in the security
			// pack table (internal/secrules) and fire only while this id is
			// in the project's signed active pack set; its packages ship
			// with the module root until a phase splits them for L1.
			ID: "security.secrets", Class: ClassFeature, Binary: BinaryNode,
			Title:        "Secret detection",
			About:        "Finds typed secrets in what an agent writes (before the write, in the hook), in written files, and in the diff a commit or push records, so the commit gate can stop an unscanned secret.",
			Levels:       lv([]Level{L2, L3}, l1l2l3, "P2"),
			Requires:     []string{"security"},
			ConfigKeys:   []string{"security"},
			Ledger:       []string{"SECP-18", "SECP-25"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Note:         "No package of its own yet: internal/secdetect, internal/secquickscan and internal/secpostwrite are compiled with the module root, so a build without the root drops them and this row is inactive (L2) otherwise.",
			Distros:      dist(out, on, off, on),
		},
		{
			// Security Phase C: the native diff rules (CI workflow rules
			// S-771 to S-778, test tampering and the other diff observations
			// S-761 and S-767 to S-769), flag only. Runtime child like
			// security.secrets.
			ID: "security.code", Class: ClassFeature, Binary: BinaryNode,
			Title:        "Code rules",
			About:        "Native diff rules on agent changes and commits: dangerous GitHub Actions workflows and weakened tests. Flag only; no process, no egress.",
			Levels:       lv([]Level{L2, L3}, l1l2l3, "P2"),
			Requires:     []string{"security"},
			ConfigKeys:   []string{"security"},
			Ledger:       []string{"SECP-25"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Note:         "No package of its own yet: internal/secciwf and internal/secdiffobs are compiled with the module root, so a build without the root drops them and this row is inactive (L2) otherwise.",
			Distros:      dist(out, on, off, on),
		},
		{
			// Security Phase D1 (lanes sec-d1 and sec-d1fix): the install
			// gate and the online lane (security pillar plan sections 5.4,
			// 8.2, 8.3 and 8.5). On by default in the developer and full
			// distros (D-764 Q23), with the first-run disclosure accepted
			// before any online query; offered by lane sec-deps4 (decision
			// log P-036) after the operator's download rulings PT-19.
			ID: "security.deps", Class: ClassFeature, Binary: BinaryNode,
			Title:  "Package checks",
			About:  "Checks packages an AI agent installs (and dependencies a manifest edit adds) against the signed malicious-packages list, popular names for typosquats, and, unless switched off, the OSV database and the public registry, before the install runs. Private package names never leave the machine.",
			Levels: lv(l1l2l3, l1l2l3, ""),
			Packages: []string{
				"internal/secfeed", "internal/secfeed/online", "internal/secask",
				// OSV matching and the database store (Phase D2, section 8.2):
				// security.deps owns matching; its two driver children use them.
				"internal/secscan/depscan", "internal/secscan/depdriver", "internal/secscan/scalibrchild",
				"internal/secscan/osvdb", "internal/secscan/osvnet",
			},
			DirectModules: []string{"github.com/BurntSushi/toml", "golang.org/x/mod", "gopkg.in/yaml.v3"},
			Requires:      []string{"security"},
			ConfigKeys:    []string{"security"},
			Surface: Surface{
				Listeners: []Listener{
					{Proto: "unix", Addr: "~/.observer/security/ask/attach/attach.sock", Loopback: true, Auth: "owner-only (0700 dir, 0600 socket)", Trigger: TriggerAutomatic},
					{Proto: "pipe", Addr: `\\.\pipe\observer-attach-<hash of the ask endpoint>`, Loopback: true, Auth: "owner-only ACL, deny network", Trigger: TriggerAutomatic},
				},
				Egress: []Egress{
					{Host: "api.osv.dev", Purpose: "Online package check: ecosystem, public package name and version", Gate: "default on where the component is active, disclosed at first run, off per node; never on a managed node", Trigger: TriggerAutomatic},
					{Host: "<public package registries>", Purpose: "Online package check: whether a public package exists and when it was first published", Gate: "as api.osv.dev", Trigger: TriggerAutomatic},
					{Host: "superbased.app", Purpose: "The signed malicious-packages and popular-names lists (signed content channel)", Gate: "where the component is active, with no consent (a plain download of public files, not a query about packages; operator ruling PT-19); [security.deps].index_download = false switches it off and the checks then use the index on disk; never on a managed node", Trigger: TriggerAutomatic},
				},
				FilesWritten: []string{"~/.observer/security/content/ (the signed index)", "~/.observer/security/pkgcache.json (online answers for the hook)", "~/.observer/security/deps-settings.json", "~/.observer/security/online-disclosure.json", "~/.observer/security/deps-index-verified.json (the index verified once per version)", "~/.observer/security/deps-notes/ (one marker per session that had the not-set-up note)", "~/.observer/security/deps-feed-etag.json (the feed envelopes' ETags)"},
			},
			Tables:       []string{"sec_pkg_cache"},
			Routes:       []string{"/api/security/deps"},
			Ledger:       []string{"SECP-7", "SECP-22", "SECP-26", "SHR-7"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, on, off, on),
		},
		{
			// Security Phase C (lane sec-c3): opt-in local git hooks
			// (security pillar plan section 5.8, ruling Q12, ledger
			// SECP-14). Off in every distro: it writes into a repository,
			// so it runs only on the developer's per-repository consent.
			// Runtime child like security.secrets.
			ID: "security.githooks", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Local git hooks",
			About:    "On your consent per repository, a marked block in the pre-commit and pre-push hooks that checks a commit or push for secrets. Advisory for a human (--no-verify skips it), fail-open, removed byte-exactly.",
			Levels:   lv([]Level{L2, L3}, l1l2l3, "P2"),
			Requires: []string{"security"},
			Surface: Surface{
				FilesWritten: []string{"<repository>/.git/hooks/pre-commit and pre-push, or a core.hooksPath inside the repository (a marked block, per-repository consent)"},
			},
			ConfigKeys:   []string{"security"},
			Ledger:       []string{"SECP-14"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Note:         "No package of its own beyond the pure internal/secgithooks, which is compiled with the module root, so a build without the root drops it and this row is inactive (L2) otherwise.",
			Distros:      dist(out, off, off, off),
		},
		{
			// Security Phase H (lane sec-h): feedback to the agent after a
			// write (security pillar plan sections 5.11 (c), 6.1, 6.2 step 2
			// and 6.5 "Feedback to the agent after writes": Off, Q13). Off
			// in every distro and opt-in under a [components] block
			// (securityOptIn). Selected, it registers the post-tool events
			// no other binding registers (Gemini CLI AfterTool, Qwen Code
			// and Qoder PostToolUse, the plugin shim's tool.execute.after,
			// the Cline PostToolUse file hook) and puts up to three
			// templated lines into the host's post-tool reply. No process
			// and no egress of its own: the hook asks the daemon over the
			// module root's owner-only quick-scan endpoint. Runtime child
			// like security.secrets.
			ID: "security.feedback", Class: ClassFeature, Binary: BinaryNode,
			Title:      "Feedback to the agent",
			About:      "After a write that produced a new high-confidence finding, the agent reads one templated line per finding in its own tool result, built from rule data only. Off unless you turn it on.",
			Levels:     lv([]Level{L2, L3}, l1l2l3, "P2"),
			Requires:   []string{"security"},
			Recommends: []string{"judge.client"},
			Surface: Surface{
				FilesWritten: []string{"the post-tool hook entries of Gemini CLI, Qwen Code and Qoder, the plugin shim's tool.execute.after handler, and ~/.cline/hooks/PostToolUse (only while selected, removed when deselected)"},
			},
			ConfigKeys:   []string{"security"},
			Ledger:       []string{"SECP-4", "SECP-15"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Note:         "No package of its own yet: the pure internal/secfeedback, internal/secexplain and internal/secframework are compiled with the module root, so a build without the root drops them and this row is inactive (L2) otherwise.",
			Distros:      dist(out, off, off, off),
		},
		{
			// Security Phase F2, node half (lane sec-f2a): the signed AI
			// change record per commit (security pillar plan sections 5.9
			// and 7.10, rulings Q8 and Q9). Off in every distro (Q9) and
			// opt-in under a [components] block (securityOptIn): with no
			// block no key is made, nothing is recorded, no change record
			// row is pushed and no repository is written. Selected, records
			// are kept and (managed, or an individual's own findings share)
			// shipped by default (Q8); git notes and the commit trailer
			// still need a person's per-repository consent. Runtime child
			// like security.githooks.
			ID: "security.provenance", Class: ClassFeature, Binary: BinaryNode,
			Title:    "AI change records",
			About:    "For each commit the attribution ties to agent activity, a signed record of the sessions, agents, models, line split, guard, scanner and finding summary (never prompt text), labelled node-reported attribution. Kept on this node and shipped to the org with the security rows; written into a repository as a git note or a commit trailer only on your per-repository consent.",
			Levels:   lv([]Level{L2, L3}, l1l2l3, "P2"),
			Requires: []string{"security"},
			Surface: Surface{
				Processes: []string{"git (read-only reads of a commit's tree and patch; `git notes` and the prepare-commit-msg hook only in a repository you consented for)"},
				FilesWritten: []string{
					"the OS keychain (service sbo-change-record-v1, the Ed25519 signing key), or a 0600 file beside the database where no keychain exists (reported as file_key)",
					"<repository>/.git refs/notes/observer and its prepare-commit-msg hook block (per-repository consent only)",
					"<repository>/.git refs/notes/ai (the experimental git-ai export, `observer security provenance export --notes`, under the same per-repository consent)",
				},
			},
			Tables:     []string{"sec_change_records", "sec_change_keys", "sec_change_consent"},
			ConfigKeys: []string{"security"},
			Ledger:     []string{"SECP-31", "SECP-32"},
			Teardown: []TeardownStep{{
				Owner: "observer security provenance consent --withdraw-all",
				What:  "Withdraws your consent in every repository and removes the prepare-commit-msg trailer block byte-exactly; git notes already written stay (a separate ref, delete them with git update-ref -d refs/notes/observer).",
			}},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Note:         "No package of its own: the pure internal/secchange is compiled with the module root, so a build without the root drops it and this row is inactive (L2) otherwise.",
			Distros:      dist(out, off, off, off),
		},
		{
			// Security Phase D2 (lane sec-d2): the linked OSV-SCALIBR
			// inventory driver (security pillar plan sections 4.2 and 8.4,
			// spike JSP-9b). The facade internal/secscan/scalibrfacade is the
			// only importer of SCALIBR and keeps a stub API under the omit
			// tag, so the row lists the module, not the package (the
			// ui.export-xlsx pattern). The scan runs in a child process of
			// the daemon through internal/extrun. dist(out, out, off, on)
			// (D-766: on in full, where it is compiled in), offered with
			// security.deps by lane sec-deps4 (decision log P-036); its
			// database waits for the developer's one-time accept (PT-19).
			ID: "security.scan.scalibr", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Dependency scan (OSV-SCALIBR)",
			About:         "Reads a project's lockfiles and manifests with the linked OSV-SCALIBR extractors, in a child process, and matches the packages against the local OSV database one ecosystem at a time. A missing database, a failed self-test or an unsupported platform shows as \"not scanned\", never clean. Beta on Windows and macOS.",
			Levels:        lv(l1l2l3, l1l2l3, ""),
			HostedIn:      []string{"internal/secscan/scalibrfacade"},
			DirectModules: []string{"github.com/google/osv-scalibr"},
			Requires:      []string{"security.deps"},
			Surface: Surface{
				Processes: []string{"observer (the scan child, `observer security scan-child`, through the shared runner)"},
				Egress: []Egress{
					{Host: "osv-vulnerabilities.storage.googleapis.com", Purpose: "The per-ecosystem OSV database exports (no project data sent)", Gate: "after the developer's one-time accept (the Scanners card's confirm dialog, or `observer security scan db accept`; about 300 MB; never an agent, R-165), then automatic; individual node only (operator ruling PT-19)", Trigger: TriggerAutomatic},
					{Host: "api.osv.dev", Purpose: "Online matching: ecosystem, public package name and version", Gate: "`observer security scan --online` only, with security.deps online checks on and disclosed, individual node only", Trigger: TriggerOptIn},
				},
				FilesWritten: []string{
					"~/.observer/security/osv/ (the local OSV databases and their epochs)",
					"~/.observer/security/osv-db-consent.json (the developer's one-time accept of the database download: time, surface, account)",
					"~/.observer/security/deps-scan-last.json (each project's last scan per driver, by project hash)",
					"~/.observer/security/deps-scan.lock (one dependency scan at a time per machine)",
					"<user cache>/superbased-observer/scanners/deps/runs/ (the isolated scan child's run directory: links to the databases, removed after each run)",
				},
			},
			Ledger:       []string{"SECP-8", "SECP-19"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, out, off, on),
		},
		{
			// Security Phase D2 (lane sec-d2): the osv-scanner subprocess
			// driver, the configurable alternative to SCALIBR (Q17) and the
			// developer distro's default (D-766: dist(out, on, off, off)),
			// offered with security.deps by lane sec-deps4 (P-036). Never
			// bundled: used if installed, and with no osv-scanner it starts
			// no process and reports "not scanned".
			ID: "security.scan.osv", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Dependency scan (osv-scanner)",
			About:    "Runs a separately installed osv-scanner offline against the local OSV database. Not installed: no process starts, the project's dependencies show as \"not scanned\" and the vendor install is offered; nothing is installed without your consent.",
			Levels:   lv(l1l2l3, l1l2l3, ""),
			Packages: []string{"internal/secscan/osvscanner"},
			Requires: []string{"security.deps"},
			Surface: Surface{
				Processes: []string{"osv-scanner (separately installed, run with --offline and --no-call-analysis=all)"},
				// Observer, not osv-scanner, downloads the database this
				// driver reads (the same store as security.scan.scalibr), so
				// the download is declared on every child that triggers it.
				Egress: []Egress{
					{Host: "osv-vulnerabilities.storage.googleapis.com", Purpose: "The per-ecosystem OSV database exports osv-scanner reads offline (no project data sent)", Gate: "as security.scan.scalibr: after the developer's one-time accept, then automatic; individual node only (operator ruling PT-19)", Trigger: TriggerAutomatic},
				},
				FilesWritten: []string{
					"~/.observer/security/osv/ (the local OSV databases and their epochs)",
					"~/.observer/security/osv-db-consent.json (the developer's one-time accept of the database download: time, surface, account)",
					"~/.observer/security/osv-canary/ (the self-test project)",
					"~/.observer/security/osv-scanner-home/ (the engine's own HOME and cache)",
					"~/.observer/security/deps-scan-last.json (each project's last scan per driver, by project hash)",
					"~/.observer/security/deps-scan.lock (one dependency scan at a time per machine)",
				},
			},
			Ledger:       []string{"SECP-8"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, on, off, off),
		},
		{
			// Security Phase G lane G1 (sec-g1): the Opengrep process driver
			// and Observer's own observer-code rule pack (security pillar plan
			// sections 4.4, 5.5, 8.1 and 8.5; spike JSP-8). Off in every
			// distro (dist(out, off, off, off), section 4.2) and opt-in under a
			// [components] block (securityOptIn): it starts a third-party
			// process. Never bundled: used if installed, pinned and verified;
			// with no Opengrep it starts nothing. Findings are flag only (no
			// rule has a precision figure yet, PR7).
			ID: "security.scan.opengrep", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Code rules (Opengrep)",
			About:         "Runs Observer's own observer-code rules (Python, JavaScript and TypeScript, Go) with a pinned and verified Opengrep (installed by you, or by the guided install after a one-time size consent), full, diff-scoped, after agent writes, on each new commit or on a schedule. Not installed: no process starts. Findings are flag only.",
			Levels:        lv(l1l2l3, l1l2l3, ""),
			Packages:      []string{"internal/secrulepack", "internal/secscan/opengrep", "internal/secscan/opengrep/opengrepnet"},
			DirectModules: []string{"gopkg.in/yaml.v3"},
			Requires:      []string{"security.code"},
			// [security.scan.opengrep]; config.ComponentSections sets it aside while this
			// component is not active.
			ConfigKeys: []string{"security"},
			Surface: Surface{
				Egress: []Egress{
					{Host: "github.com (release downloads, redirected only to release-assets.githubusercontent.com or objects.githubusercontent.com)", Purpose: "the guided install of the pinned Opengrep release, about 47 MB, checked against its sha256 pin", Gate: "consent", Trigger: TriggerUserTriggered},
					{Host: "superbased.app", Purpose: "the signed observer-code rule pack and engine pins (individual node; a managed node uses its org mirror)", Gate: "config: [security.scan.opengrep].feed, and only while an Opengrep engine is installed (P-061)", Trigger: TriggerOptIn},
				},
				Processes: []string{
					"opengrep (separately installed, pinned by sha256, with the files its self-extracting bundle unpacks into its own cache checked against the first verified run)",
					"git (Opengrep's own git ls-files and baseline, with the git hardening; and `git rev-parse` to resolve a --diff ref)",
					"bwrap (isolated runs, through the isolation component)",
				},
				FilesWritten: []string{
					"~/.observer/security/code-content/ (a signed rule pack or engine manifest an operator imported)",
					"~/.observer/security/opengrep-engine.json (the unpacked tree's digests and the last self-test)",
					"~/.observer/security/code-scan.lock (one Opengrep scan at a time per machine)",
					"~/.observer/security/opengrep-install-consent.json (the developer's size consent, signed), opengrep-install.json, code-content-fetch.json, opengrep-heads.json (the schedule's last run is read from the database, not a file)",
					"<user cache>/superbased-observer/scanners/opengrep/ (the guided install's bin/, the rule pack copy, the engine's own HOME and cache, per-run output directories)",
				},
			},
			Ledger:       []string{"SECP-27", "SECP-29"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, off, off, off),
		},
		{
			// Security Phase G lane G5 (sec-g5): the sarif-import driver
			// (security pillar plan sections 4.4 and 4.5.3 "In"). Reads ONE
			// SARIF file the developer names (a tool they ran themselves);
			// never runs a tool, never watches a folder. Off in every distro
			// and opt-in under a [components] block (securityOptIn). Findings
			// are flag only and carry an inferred lineage.
			ID: "security.scan.sarif-import", Class: ClassFeature, Binary: BinaryNode,
			Title:        "SARIF import",
			About:        "Imports one SARIF file that a scanner you ran yourself wrote (CodeQL, gosec, Bandit, Semgrep, the Claude or Codex Security plugin) as flag-only findings, each with an inferred lineage to the latest AI edit of its file. Observer never runs the tool; an import never shows a project clean.",
			Levels:       lv(l1l2l3, l1l2l3, ""),
			Packages:     []string{"internal/secscan/sarifimport"},
			Requires:     []string{"security.code"},
			Ledger:       []string{"SECP-33"},
			RestartClass: "hot",
			Stability:    StabilityPreview,
			Distros:      dist(out, off, off, off),
		},
		{
			// Security Phase G lane G5 (sec-g5): the linked actionlint driver
			// (security pillar plan sections 4.4 "actionlint as a linked
			// driver", 5.6 and 8.7). MIT, in process behind a facade, its
			// shellcheck and pyflakes integrations off: it starts no process
			// and reads no repository actionlint config. Library-linked, so
			// compiled only in the managed and full distros
			// (dist(out, out, off, off), section 4.2) and opt-in under a
			// [components] block (securityOptIn). Findings are flag only.
			// No Verbs: Verbs are top-level verbs the gate owns, and `security`
			// belongs to security.code; the `security actionlint` subcommand
			// refuses on its own when the component is not selected (the
			// same holds for sarif-import's `security import-sarif`).
			// actionlint itself is the in-module copy
			// internal/thirdparty/actionlint (its UPSTREAM file records the
			// release and the patch), so its direct modules are the copy's.
			ID: "security.scan.actionlint", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Workflow lint (actionlint)",
			About:    "Lints a project's GitHub Actions workflows with actionlint, linked into Observer with its shellcheck and pyflakes integrations off, so no process starts. Findings are flag only.",
			Levels:   lv(l1l2l3, l1l2l3, ""),
			Packages: []string{"internal/secscan/actionlint", "internal/thirdparty/actionlint"},
			DirectModules: []string{
				"github.com/bmatcuk/doublestar/v4", "github.com/fatih/color", "github.com/mattn/go-colorable",
				"github.com/mattn/go-runewidth", "github.com/mattn/go-shellwords", "github.com/robfig/cron/v3",
				"go.yaml.in/yaml/v4", "golang.org/x/sync", "golang.org/x/sys",
			},
			Requires:     []string{"security.code"},
			Ledger:       []string{"SECP-33"},
			RestartClass: "hot",
			Stability:    StabilityPreview,
			Distros:      dist(out, out, off, off),
		},
		{
			// Security lane GATES-SEC (operator ruling P-129, plan 5.6 P2, gap
			// G4): the Trivy process driver, misconfiguration only (`trivy
			// config` over Dockerfiles, Kubernetes, Terraform, CloudFormation
			// and Helm). Off in every distro (dist(out, off, off, off),
			// section 4.2) and opt-in under a [components] block
			// (securityOptIn): it starts a third-party process. Never bundled:
			// used if installed, or installed by the guided install after a
			// one-time size consent, pinned AND signature-checked (CVE-2026-
			// 33634). With no Trivy nothing starts and the project reads
			// not_scanned. Findings are flag only.
			ID: "security.scan.trivy", Class: ClassFeature, Binary: BinaryNode,
			Title:    "IaC checks (Trivy)",
			About:    "Checks a project's Dockerfiles, Kubernetes, Terraform, CloudFormation and Helm files with a pinned and signature-checked Trivy (installed by you, or by the guided install after a one-time size consent), on demand, on a schedule or after an agent writes such a file. Misconfiguration only, with every network path off. Not installed: no process starts. Findings are flag only.",
			Levels:   lv(l1l2l3, l1l2l3, ""),
			Packages: []string{"internal/secscan/trivy", "internal/secscan/trivy/trivynet"},
			Requires: []string{"security.code"},
			// [security.scan.trivy]; config.ComponentSections sets it aside while this
			// component is not active.
			ConfigKeys: []string{"security"},
			Surface: Surface{
				Egress: []Egress{
					{Host: "github.com (release downloads, redirected only to release-assets.githubusercontent.com or objects.githubusercontent.com)", Purpose: "the guided install of the pinned Trivy release archive and its sigstore bundle, checked against its sha256 pin and the pinned signing identity", Gate: "consent", Trigger: TriggerUserTriggered},
				},
				Processes: []string{
					"trivy (separately installed, pinned by sha256, `config` only, with --skip-check-update, --skip-version-check, --disable-telemetry and an in-memory cache)",
					"bwrap (isolated runs, through the isolation component)",
				},
				FilesWritten: []string{
					"~/.observer/security/iac-trivy.json (the engine's first-use digest, flag check and self-test), iac-trivy-install.json and iac-trivy-install-consent.json (signed)",
					"~/.observer/security/iac-scan.lock (one IaC scan at a time per machine)",
					"<user cache>/superbased-observer/scanners/trivy/ (the guided install's bin/, the engine's own HOME and cache, the canary project, per-run output directories)",
				},
			},
			Ledger:       []string{"SECP-34"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, off, off, off),
		},
		{
			// Security lane GATES-SEC: the KICS process driver (plan 5.6 P2,
			// gap G4). Off in every distro and opt-in (securityOptIn). KICS
			// v2.2.0 publishes no release binaries and no signature, so there
			// is no guided install and no egress of its own: a KICS on this
			// machine is the developer's own, decided by its digest (labelled
			// on an individual node, refused on a managed node without an org
			// mirror pin). KICS asks api.github.com for its latest release on
			// every start with no flag to turn it off, so it runs only inside
			// the isolation component's no-network one-shot; elsewhere the
			// project reads not_scanned.
			ID: "security.scan.kics", Class: ClassFeature, Binary: BinaryNode,
			Title:    "IaC checks (KICS)",
			About:    "Checks a project's infrastructure-as-code files with KICS (installed by you; KICS publishes no release binaries), only inside the isolation component's no-network run, with its queries tree checked against the first verified run. Not installed or not isolated: no process starts. Findings are flag only.",
			Levels:   lv(l1l2l3, l1l2l3, ""),
			Packages: []string{"internal/secscan/kics"},
			Requires: []string{"security.code"},
			// [security.scan.kics]; config.ComponentSections sets it aside while this
			// component is not active.
			ConfigKeys: []string{"security"},
			Surface: Surface{
				Processes: []string{
					"kics (separately installed, decided by its sha256, run only inside the isolation component's no-network one-shot, with its queries tree checked against the first verified run)",
					"bwrap (the isolated run, through the isolation component)",
				},
				FilesWritten: []string{
					"~/.observer/security/iac-kics.json (the engine's first-use digest, flag check, self-test and queries tree record)",
					"~/.observer/security/iac-scan.lock (one IaC scan at a time per machine)",
					"<user cache>/superbased-observer/scanners/kics/ (the engine's own HOME and cache, the canary project, per-run output directories)",
				},
			},
			Ledger:       []string{"SECP-34"},
			RestartClass: "restart",
			Stability:    StabilityPreview,
			Distros:      dist(out, off, off, off),
		},
		{
			ID: "remote", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Remote dashboard",
			About:         "Remote access to the dashboard over a tailnet, device pairing and outbound push notifications.",
			Levels:        lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages:      []string{"internal/remoteauth", "internal/remotecfg", "internal/remotenotify", "internal/tailnet"},
			DirectModules: []string{"golang.org/x/crypto"},
			Surface: Surface{
				Listeners: []Listener{{Proto: "tcp", Addr: "<tailnet address via tailscale serve>", Loopback: false, Auth: "paired device session", Trigger: TriggerOptIn}},
				Egress:    []Egress{{Host: "<configured push endpoint>", Purpose: "Remote push notifications", Gate: "config", Trigger: TriggerOptIn}},
				Processes: []string{"tailscale", "sudo (the Tailscale guided setup: operator grant, login and install)", "sh (the Tailscale install script, run by sudo, which also runs curl)"},
			},
			Tables:     []string{"remote_sessions", "remote_session_state", "remote_audit"},
			Migrations: []MigrationRef{{File: "internal/db/migrations/066_remote_sessions.sql", Class: MigrationSingletonSeed, Note: "Seeds a singleton state row even when remote is never used."}},
			Routes:     []string{"/api/remote"},
			Verbs:      []string{"remote"},
			ConfigKeys: []string{"remote"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, out, off),
		},
		{
			ID: "capture.browser", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Browser chat capture",
			About:    "The native-messaging host and loopback ingest listener that receive captures from the browser extension. Writes native-messaging host manifests and, on Windows, HKCU registry keys.",
			Levels:   lv(onlyL3, l1l2l3, "P2"),
			Packages: []string{"internal/browserhost", "internal/browserhost/hostfiles", "internal/ingest/browser"},
			Bundles:  []string{"adapter.chatgpt-web", "adapter.claude-web", "adapter.perplexity-web", "adapter.gemini-web", "adapter.copilot-web"},
			Surface: Surface{
				Listeners:     []Listener{loopback("127.0.0.1:8821", "local token", "browser.listener.listen_addr", TriggerOptIn)},
				OSIntegration: []string{"native-messaging host manifests per browser", "Windows HKCU NativeMessagingHosts keys"},
				// Lane LEFT2-SEC (R-025, PT-04): the reg.exe writer behind the
				// Windows host keys (internal/browserhost).
				Processes: []string{"reg (the Windows NativeMessagingHosts keys, over WSL interop from Linux)"},
			},
			Teardown:   []TeardownStep{{Owner: "browser native-messaging host remover (`observer components teardown capture.browser`)", What: "Removes the host manifests, the registry keys and the host files; the extension itself keeps running in the browser (artifact.browser-extension reports it)."}},
			Verbs:      []string{"browser"},
			ConfigKeys: []string{"browser"},
			Ledger:     []string{"MODPKG-5"},
			Stability:  StabilityPreview,
			Distros:    dist(out, on, off, on),
		},
		{
			ID: "integration.service", Class: ClassIntegration, Binary: BinaryNode,
			Title:     "System service",
			About:     "Writes a systemd unit and runs systemctl through `observer service` (Linux only). A launchd plist ships for manual install; Observer writes no service on macOS or Windows.",
			Levels:    lv(onlyL3, l2l3, "P1"),
			Packages:  []string{"internal/service"},
			Surface:   Surface{FilesWritten: []string{"systemd unit file"}, Processes: []string{"systemctl", "journalctl (`observer service logs`)"}, OSIntegration: []string{"systemd unit (Linux)"}},
			Teardown:  []TeardownStep{{Owner: "observer service uninstall", What: "Stops and removes the unit."}},
			Verbs:     []string{"service"},
			Stability: StabilityStable,
			Distros:   dist(off, off, off, off),
			Note:      "The plan table shows this out of minimal, but the plan gives it no L1 level, so minimal compiles it in and inactive (L2) until a phase adds L1.",
		},
		{
			ID: "ingest.otlp", Class: ClassFeature, Binary: BinaryNode,
			Title:         "OTLP ingest",
			About:         "Receives OpenTelemetry traces and logs from AI tools (Claude Code OTel, vendor OTLP) on loopback gRPC and HTTP, and the opt-in edit that points a tool's own exporter at it.",
			Levels:        lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages:      []string{"internal/otlpvendor", "internal/telemetrywire"},
			DirectModules: []string{"go.opentelemetry.io/proto/otlp", "github.com/BurntSushi/toml"},
			Recommends:    []string{"adapter.claude-code"},
			Surface: Surface{
				Listeners: []Listener{
					loopback("127.0.0.1:4317", "token file", "ingest.otel.grpc_addr", TriggerOptIn),
					loopback("127.0.0.1:4318", "token file", "ingest.otel.http_addr", TriggerOptIn),
				},
				VendorConfigs: []string{"AI tool OTel exporter settings (opt-in)"},
			},
			Tables:     []string{"otel_content"},
			Routes:     []string{"/api/setup/telemetry"},
			Teardown:   []TeardownStep{{Owner: "internal/clientwire Remover", What: "Removes the telemetry exporter entries Observer wrote."}},
			ConfigKeys: []string{"ingest"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
			Note:       "Ruling D-436: the generic OTLP receiver (internal/ingest/otlp) is core, because it also serves Plane A traces and the observer-edge; this component is the vendor mapping table (internal/otlpvendor), the logs handler and the exporter-config edit (internal/telemetrywire). Compiled out by -tags sbo_omit_ingest_otlp (P2, MP-L1C): the cmd/observer wiring pair (otlp_ingest.go, otlp_proxyroute.go, init_otlp.go, otlp_route_marker.go vs their _omit.go files), the clientwire writer (telemetry_wire.go vs telemetry_omit.go) and the dashboard setup route; [ingest.otel] is then reported at start, never obeyed, and `observer init --otlp-export` refuses. Such a build cannot remove exporter entries an earlier full build wrote: remove ingest.otlp in a build that has it first.",
		},
		{
			ID: "export.otel", Class: ClassFeature, Binary: BinaryNode,
			Title:         "OpenTelemetry export",
			About:         "Exports Observer's own traces to a configured OTLP endpoint, the guard-event feed, and the self-observability decision-run sink.",
			Levels:        lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages:      []string{"internal/exporter/otel", "internal/selfobs/emit/otelsink"},
			DirectModules: []string{"go.opentelemetry.io/otel", "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp", "go.opentelemetry.io/otel/sdk", "go.opentelemetry.io/otel/trace"},
			Surface: Surface{Egress: []Egress{
				{Host: "<configured OTLP endpoint>", Purpose: "Trace export", Gate: "config", Trigger: TriggerOptIn},
				{Host: "<configured self-observability gateway>", Purpose: "Self-observability decision runs", Gate: "config", Trigger: TriggerOptIn},
			}},
			ConfigKeys: []string{"exporter", "selfobs"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
			Note:       "Compiled out by -tags sbo_omit_export_otel (P2, MP-L1C): the cmd/observer wiring pair (otel.go, guardotel.go, selfobs_sink.go vs otel_omit.go, guardotel_omit.go, selfobs_sink_omit.go) drops internal/exporter/otel, the self-observability OTLP sink (internal/selfobs/emit/otelsink) and the OpenTelemetry SDK; [exporter.otel] and [selfobs] are then reported at start, never obeyed. Ruling D-436: the neutral self-observability model (selfobs run, keys, shape, conformance) and the emit.Sink contract with its Nop are core, so every producer keeps compiling and emits through Nop.",
		},
		{
			ID: "obs", Class: ClassFeature, Binary: BinaryNode,
			Title:  "Plane A observability",
			About:  "General observability of a hosted LLM app: span ingest, input admission, evals, alerts and self-observability. The admin plane, never shown on the node dashboard.",
			Levels: lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages: []string{
				"internal/obs", "internal/obs/admission", "internal/obs/egress", "internal/obs/eval", "internal/obs/span",
				"internal/obs/ingest", "internal/obs/alert", "internal/obs/store", "internal/obs/httpapi", "internal/evalcore",
				"internal/orgserver/gateway/classify", "internal/orgserver/gateway/convention",
			},
			DirectModules: []string{"go.opentelemetry.io/proto/otlp", "google.golang.org/protobuf", "golang.org/x/text"},
			// Self-observability is emitted through the core emit.Sink
			// (D-436), so obs no longer needs export.otel compiled: without
			// it, decision runs go to emit.Nop.
			RequiresCompiled: []string{"judge.client"},
			Surface: Surface{Egress: []Egress{
				{Host: "<configured judge endpoint>", Purpose: "Admission and eval judging", Gate: "config", Trigger: TriggerOptIn},
				{Host: "<configured webhook>", Purpose: "Alert delivery", Gate: "config", Trigger: TriggerOptIn},
			}},
			// Registered through ExtraRoutes by the obs wiring only.
			Routes:     []string{"/api/obs"},
			Verbs:      []string{"obs", "eval"},
			ConfigKeys: []string{"observability"},
			Stability:  StabilityPreview,
			Distros:    dist(out, out, out, off),
			Note:       "Out of developer per D-389. Compiled out by -tags sbo_omit_obs (no_obs is a one-release alias) and by sbo_omit_judge_client, which obs requires; the binary then reports obs omitted. The self-observability model (internal/selfobs run, keys, shape, conformance, emit) is core and the [selfobs] key belongs to export.otel (D-436); with those packages no longer counted as obs, a -tags sbo_omit_obs build carries none of obs's packages, so obs claims L1 (MP-L1C).",
		},
		{
			ID: "processobs", Class: ClassFeature, Binary: BinaryNode,
			Title:  "Process observation",
			About:  "Observes the processes AI tools spawn: eBPF on Linux (needs CAP_BPF), an ETW bridge on Windows behind an elevated scheduled task, and the pid bridge.",
			Levels: lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages: []string{
				"internal/processobs", "internal/processobs/bridge", "internal/processobs/poll", "internal/processobs/linuxebpf",
				"internal/processbridge/setup", "internal/processobs/etw",
			},
			DirectModules: []string{"github.com/cilium/ebpf", "golang.org/x/sys"},
			Surface: Surface{
				Listeners:     []Listener{loopback("127.0.0.1:8823", "local token", "observer.process.etw.listen_addr", TriggerOptIn)},
				OSIntegration: []string{"eBPF programs (CAP_BPF, Linux)", "elevated Scheduled Task for the ETW bridge (Windows)"},
				// Lane LEFT2-SEC (R-025, PT-04): the read-only task query and the
				// Windows observer.exe the WSL bridge runs as its capturer.
				Processes: []string{"schtasks (the read-only bridge task query)", "observer (the Windows observer.exe the WSL process bridge runs as its capturer)"},
			},
			Tables:     []string{"process_runs", "process_events", "process_network_bodies"},
			Routes:     []string{"/api/process"},
			Verbs:      []string{"process", "process-bridge"},
			ConfigKeys: []string{"observer"},
			Stability:  StabilityExperimental,
			Distros:    dist(out, off, off, off),
			Note:       "Phase PB moved its model to internal/procmodel and the boot id to internal/bootid (both core), so store, proxy, metrics, diag, arena and intervention no longer import it. internal/pidbridge and its session_pid_bridge table are core, not this component (T-671 audit): they are the proxy's session attribution written by the hook path (spec 9 and 14, migration 004), used with or without process observation. Compiled out by -tags sbo_omit_processobs (P2, MP-L1B): the cmd/observer wiring pair (processobs.go, process_cmd.go, process_bridge*.go vs processobs_omit.go) and the dashboard feature files (process_enable.go, process_etw_*.go, process_feature.go vs process_feature_omit.go); the process verbs then refuse with exit code 3 and the process setup routes answer 404 component_not_installed. The read-only process findings pages stay and show no rows.",
		},
		{
			ID: "org.client", Class: ClassFeature, Binary: BinaryNode,
			Title:  "Org client",
			About:  "Enrolment with an org server, the push loop, the signed policy rails, grants, budgets, pricing, display and intel. Talks only to the org server the operator enrolled with.",
			Levels: lv(onlyL3, l2l3, "P1"),
			Packages: []string{
				"internal/orgclient", "internal/orgclient/gen", "internal/orgenrol", "internal/orgbudget", "internal/orgintel",
				"internal/orgpricing", "internal/pushsched", "internal/policyfresh", "internal/policystate", "internal/govern",
				"internal/govern/sidecar", "internal/grantverify", "internal/policyfam", "internal/policyfam/nodegov",
				"internal/policyfam/nodefeatures", "internal/policyfam/nodefeatures/lkgsidecar", "internal/policyfam/egress",
				"internal/policyfam/admission", "internal/policyfam/planebadmission", "internal/policyfam/providers",
			},
			// The OS keychain is reached through internal/keystore (core).
			DirectModules: []string{"github.com/google/uuid", "github.com/oapi-codegen/runtime"},
			Surface: Surface{
				Egress:      []Egress{{Host: "<enrolled org server>", Purpose: "Push, policy and grant rails", Gate: "enrolment", Trigger: TriggerAutomatic}},
				Credentials: []string{"OS keychain (enrolment credential)"},
			},
			Tables:     []string{"org_enrolment", "org_push_log", "org_push_changes", "org_push_deletions", "org_policy_resource_state"},
			Routes:     []string{"/api/enrolment", "/api/requests", "/api/intel"},
			Verbs:      []string{"enroll", "unenroll", "org", "request", "requests", "intel"},
			ConfigKeys: []string{"org_client"},
			Stability:  StabilityStable,
			Distros:    dist(off, cond, on, on),
			Note:       "L2 only (rev S1): compiled into every distro. Catalog validation refuses any distro or manifest that omits it or targets L1 for it.",
		},
		{
			ID: "org.update", Class: ClassFeature, Binary: BinaryNode,
			Title:      "Self-update",
			About:      "Applies updates fetched only from the enrolled org server's mirror, with a fork-exec-and-watch handshake and rollback.",
			Levels:     lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages:   []string{"internal/update"},
			Requires:   []string{"org.client"},
			Surface:    Surface{Egress: []Egress{{Host: "<enrolled org server>", Purpose: "Update manifest and artifacts", Gate: "enrolment", Trigger: TriggerAutomatic}}, FilesWritten: []string{"the observer binary (atomic swap)"}},
			Tables:     []string{"update_state", "update_events"},
			Migrations: []MigrationRef{{File: "internal/db/migrations/105_update_state.sql", Class: MigrationSingletonSeed, Note: "Seeds the update_state singleton."}},
			Routes:     []string{"/api/update"},
			Verbs:      []string{"update"},
			ConfigKeys: []string{"update"},
			Ledger:     []string{"UPD-6"},
			Stability:  StabilityStable,
			Distros:    dist(out, on, on, on),
		},
		{
			ID: "agentaccess.relay", Class: ClassFeature, Binary: BinaryNode,
			Title:  "Agent Access relay",
			About:  "The MCP relay with a local policy decision point and record chain. Rewrites MCP client config to route through the relay.",
			Levels: lv([]Level{L1, L3}, l1l2l3, "P2"),
			// Core since lane MP-L1I (T-715), each a pure vocabulary shared
			// with the org server or the org client: internal/dpop/jose (the
			// JOSE primitives the org client signs its source-node key proof
			// with), internal/mcpintel/correlate (the MCP-call correlation the
			// node session panel and the org drawer must agree on) and
			// internal/mcpintel/discover (the MCP inventory identity hashes the
			// push wire and ingest must agree on). The component owns the
			// relay, its PDP, record chain, projector and egress.
			Packages: []string{
				"internal/mcprelay", "internal/mcprelay/localpdp", "internal/mcprelay/coverage", "internal/mcprelay/project",
				"internal/mcprelay/record", "internal/mcpaccess", "internal/policyfam/mcpaccess", "internal/agentid", "internal/dpop",
				"internal/mcpegress", "internal/netpolicy",
			},
			DirectModules: []string{"cel.dev/cel-go"},
			Requires:      []string{"org.client"},
			Surface: Surface{
				VendorConfigs: []string{"MCP client config entries (wrapped through the relay)"},
				Credentials:   []string{"OS keychain"},
				// Lane LEFT2-SEC (R-025, PT-04): the stdio wrapper starts the
				// server the user's MCP client config names.
				Processes: []string{"the configured MCP server (the stdio wrapper starts the command the MCP client entry names)"},
			},
			Tables:   []string{"mcp_relay_state", "mcp_relay_record", "mcp_relay_launch_spec"},
			Teardown: []TeardownStep{{Owner: "observer mcp unwrap", What: "Restores the original MCP client entries."}},
			Routes:   []string{"/api/mcp-access"},
			// `observer mcp` is the canonical Agent Access node tree
			// (mcp_cmd.go); `observer mcp-relay` is its older spelling (T-661).
			Verbs:      []string{"mcp", "mcp-relay"},
			ConfigKeys: []string{"mcp_relay"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			ID: "cloud.intelligence", Class: ClassFeature, Binary: BinaryNode,
			Title:  "Cloud Intelligence",
			About:  "The signed-in personal cloud plane: consent-gated evidence upload and enrichment, run as a manual or opt-in subprocess.",
			Levels: lv([]Level{L1, L3}, l1l2l3, "P2"),
			// internal/cloudcontract (the versioned wire and result
			// vocabulary) is core since lane MP-L1I (T-715, ruling D-512):
			// the org wire (orgcontract, orgintel, the store's cloud and org
			// intel tables, the dashboard's views) speaks it. The component
			// owns the evidence builder, the network lane, the credential
			// store and the consent gateway.
			// The OS keychain is reached through internal/keystore (core).
			Packages: []string{"internal/cloudevidence", "internal/cloudclient", "internal/cloudpop", "internal/cloudcred", "internal/cloudgateway"},
			Surface: Surface{
				Egress:      []Egress{{Host: "<hosted cloud base URL>", Purpose: "Evidence upload and results", Gate: "consent", Trigger: TriggerOptIn}},
				Credentials: []string{"OS keychain (cloud credential)"},
			},
			Tables:     []string{"cloud_outbox", "cloud_results", "cloud_consent_receipts"},
			Routes:     []string{"/api/cloud"},
			Verbs:      []string{"cloud"},
			ConfigKeys: []string{"cloud"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, out, off),
		},
		{
			ID: "egress.pricing-feed", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Pricing feed",
			About:    "Fetches the model price table from superbased.app every 24 hours so cost and budgets stay accurate. On by default (D-374).",
			Levels:   lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages: []string{"internal/pricingfeed", "internal/pricingfeed/client", "internal/pricingfeedgate"},
			Surface: Surface{Egress: []Egress{
				{Host: "superbased.app", Purpose: "Model price table refresh every 24 hours", Gate: "default on, opt out in [pricing.feed]", Trigger: TriggerAutomatic},
			}},
			Tables:     []string{"pricing_feed_cache"},
			Verbs:      []string{"pricing"},
			ConfigKeys: []string{"pricing"},
			Stability:  StabilityStable,
			Distros:    dist(out, on, out, on),
			Note:       "Stays on by default in developer (operator ruling D-374: a stale feed breaks budgets). Managed nodes use the org pricing rail.",
		},
		{
			ID: "egress.aggregate-share", Class: ClassFeature, Binary: BinaryNode,
			Title:      "Aggregate share",
			About:      "Submits consented, aggregate-only usage statistics to aggregate.superbased.app.",
			Levels:     lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages:   []string{"internal/aggregate", "internal/aggregateclient", "internal/aggregatesource", "internal/aggregatesvc"},
			Surface:    Surface{Egress: []Egress{{Host: "aggregate.superbased.app", Purpose: "Aggregate usage submission", Gate: "consent", Trigger: TriggerOptIn}}},
			Tables:     []string{"aggregate_consent", "aggregate_submissions"},
			Verbs:      []string{"aggregate"},
			ConfigKeys: []string{"aggregate_share"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, out, off),
		},
		{
			ID: "notify.email", Class: ClassFeature, Binary: BinaryNode,
			Title:      "Email and digest",
			About:      "Sends email notifications and the periodic digest over a configured SMTP server.",
			Levels:     lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages:   []string{"internal/notify/email", "internal/notify/digest"},
			Surface:    Surface{Egress: []Egress{{Host: "<configured SMTP server>", Purpose: "Email delivery", Gate: "config", Trigger: TriggerOptIn}}},
			Tables:     []string{"digest_state"},
			Verbs:      []string{"digest"},
			ConfigKeys: []string{"email", "digest"},
			Stability:  StabilityStable,
			Distros:    dist(out, off, off, off),
		},
		{
			ID: "projects", Class: ClassFeature, Binary: BinaryNode,
			Title:  "Projects and lines of code",
			About:  "Per-project spend and ROI, a read-only HEAD-only commit scanner, lines-of-code tracking with a loopback editor endpoint, and skills history.",
			Levels: lv(onlyL3, l2l3, "P1"),
			Packages: []string{
				"internal/commitscan", "internal/commitlog", "internal/projectroi", "internal/loc",
				"internal/skillhistory", "internal/skillscan",
			},
			Surface: Surface{
				Processes:    []string{"git (read-only log)"},
				FilesWritten: []string{"~/.observer/loc-editor-token"},
			},
			Tables:     []string{"file_changes", "project_commits", "project_commit_files", "project_commit_scan"},
			Routes:     []string{"/api/projects", "/api/loc", "/api/project"},
			Verbs:      []string{"project", "loc"},
			ConfigKeys: []string{"projects", "loc"},
			Ledger:     []string{"COMMIT-1", "COMMIT-2"},
			Stability:  StabilityStable,
			Distros:    dist(on, on, on, on),
		},
		{
			ID: "judge.client", Class: ClassFeature, Binary: BinaryNode,
			Title:     "Judge client",
			About:     "The one LLM-as-judge client: an OpenAI-compatible chat completions caller with secret redaction and a payload cap for any non-loopback judge. Used by the commit alignment judge and, in builds with obs, the eval and admission judges.",
			Levels:    lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages:  []string{"internal/judgeclient"},
			Surface:   Surface{Egress: []Egress{{Host: "<configured judge endpoint>", Purpose: "LLM judge call for a configured judge", Gate: "config", Trigger: TriggerOptIn}}},
			Stability: StabilityPreview,
			Distros:   dist(out, off, out, off),
			Note:      "Split out of obs in phase PB (D-408) so the alignment judge stays in developer while obs leaves it (D-389). Required only as code: it starts nothing and is active only through a component that calls it. Compiled out by -tags sbo_omit_judge_client (P2, MP-L1A), which also compiles out obs.",
		},
		{
			ID: "projects.alignment-judge", Class: ClassFeature, Binary: BinaryNode,
			Title:            "Commit alignment judge",
			About:            "The opt-in tier-J grade of delivered versus missed work, using the judge client.",
			Levels:           lv(onlyL3, l2l3, "P1"),
			HostedIn:         []string{"internal/intelligence/alignment"},
			Requires:         []string{"projects"},
			RequiresCompiled: []string{"judge.client"},
			Surface:          Surface{Egress: []Egress{{Host: "<configured judge endpoint>", Purpose: "Commit alignment grading", Gate: "config", Trigger: TriggerOptIn}}},
			ConfigKeys:       []string{"projects"},
			Stability:        StabilityPreview,
			Distros:          dist(out, off, out, off),
			Note:             "Stays in developer (D-408): the judge client is its own component since phase PB, so this tier no longer follows obs out of developer (D-389).",
		},
		{
			ID: "archive", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Corpus archive",
			About:         "Moves cold rows into a separate archive.db with copy, verify, then delete, and an operator-invoked reclaim.",
			Levels:        lv([]Level{L1, L3}, l1l2l3, "P5"),
			DirectModules: []string{"modernc.org/sqlite"},
			// internal/archive (the pure row, marker, digest and leftover
			// vocabulary) is core since lane MP-L1H (T-715): the store's
			// hot-side seam, codeintel's archived-project read and the
			// dashboard's storage leftovers speak it. The component owns the
			// cold store and the mover.
			Packages:   []string{"internal/archivestore", "internal/archivestore/migrations", "internal/archivesvc"},
			Surface:    Surface{FilesWritten: []string{"~/.observer/archive.db"}},
			Tables:     []string{"codeintel_archived_projects", "process_archived_windows"},
			Verbs:      []string{"archive"},
			ConfigKeys: []string{"archive"},
			Stability:  StabilityPreview,
			Distros:    dist(out, off, off, off),
		},
		{
			ID: "benchmark", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Benchmarks and arena",
			About:         "Runs AI agents against benchmark tasks and side-by-side arena comparisons in git worktrees.",
			Levels:        lv([]Level{L1, L3}, l1l2l3, "P2"),
			DirectModules: []string{"github.com/BurntSushi/toml"},
			Packages:      []string{"internal/benchmark", "internal/arena", "internal/arenamodels"},
			Requires:      []string{"terminals"},
			Surface:       Surface{Processes: []string{"AI agent CLIs", "git (worktrees)"}},
			Tables:        []string{"benchmark_runs", "benchmark_attempts", "benchmark_scores", "arena_runs", "arena_candidates"},
			Routes:        []string{"/api/benchmarks", "/api/arena"},
			Verbs:         []string{"benchmark"},
			ConfigKeys:    []string{"benchmark"},
			Stability:     StabilityPreview,
			Distros:       dist(out, on, out, on),
		},
		{
			ID: "intervention", Class: ClassFeature, Binary: BinaryNode,
			Title:         "Intervention",
			About:         "Signals or stops vendor AI tool processes when an authority allows it.",
			Levels:        lv(onlyL3, l2l3, "P1"),
			Packages:      []string{"internal/intervention", "internal/intervention/inspectionbroker", "internal/jobobject", "internal/codexipc"},
			DirectModules: []string{"golang.org/x/sys"},
			Surface:       Surface{OSIntegration: []string{"process signals", "Windows Job Objects"}, Processes: []string{"ps or powershell (finds a running Codex app)", "taskkill (stops a Codex app on Windows)"}},
			Stability:     StabilityPreview,
			Distros:       dist(off, off, off, off),
			Note:          "The plan table shows this out of minimal, but the plan gives it no L1 level, so minimal compiles it in and inactive (L2) until a phase adds L1.",
		},
		{
			ID: "demo", Class: ClassFeature, Binary: BinaryNode,
			Title:    "Demo data",
			About:    "Embedded demo fixtures the dashboard can load to show the product without real sessions.",
			Levels:   lv([]Level{L1, L3}, l1l2l3, "P2"),
			Packages: []string{"internal/demo"},
			// The demo fixtures are parsed with the Claude Code parser.
			RequiresCompiled: []string{"adapter.claude-code"},
			Routes:           []string{"/api/demo"},
			Stability:        StabilityStable,
			Distros:          dist(out, on, out, on),
		},
	}
}

// hostedDriverRow is one hosted sandbox driver's component row (lane
// SBX-P7): the shared remote core packages belong to the module row; the
// vendor's wire client to this row.
func hostedDriverRow(id, title, about, pkg string, modules []string) Component {
	return Component{
		ID: id, Class: ClassFeature, Binary: BinaryNode,
		Title: title, About: about,
		Levels:        lv([]Level{L1, L3}, l1l2l3, "P2"),
		Packages:      []string{pkg},
		DirectModules: modules,
		Requires:      []string{"terminals.sandbox"},
		Surface: Surface{
			Processes: []string{
				"observer (the sandbox-hosted-host helper on this machine, the only process that reads the provider credential and calls the provider, for one launched run)",
				"observer (the in-box Linux observer: sandbox-guest --relay-stdio and the agent's launcher, inside the provider's box)",
			},
			FilesWritten: []string{"~/.observer/sandbox-hosted/ (per-provider consent records, the spend ledger, the per-run plan and teardown records, per-box secrets, the transcript quarantine and the saved diffs)"},
		},
		ConfigKeys: []string{"terminal"},
		Ledger:     []string{"SBX-BE-8", "SBX-BE-16"},
		Stability:  StabilityPreview,
		Distros:    dist(out, off, off, off),
	}
}
