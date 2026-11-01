package components

import "github.com/marmutapp/superbased-observer/internal/integration"

// catalog_adapters.go holds one adapter row per integration-registry tool
// id (plan 3.3, the "adapter.<tool> (45 rows)" line). The list below is
// written out by hand ON PURPOSE: the invariant suite pins it one to one
// against integration.Tools() and against the adapter fan-in
// (internal/adapter/defaults), so deriving it from either would make those
// tests vacuous.
//
// Integration facts (proxy, hook, MCP, route, token tier) stay owned by
// internal/integration; an adapter row carries only what packaging needs:
// the implementing package, the bundles that package forces, and the
// relationships between rows. Stability is DERIVED from the registry
// lifecycle (one owner): active is stable, deprecated and dead are
// deprecated.

// adapterSpec is one compact adapter definition.
type adapterSpec struct {
	tool  string // integration registry tool id
	title string // display name
	pkg   string // implementing package; owned by the first row that names it
	// bundles lists the other tool ids served by the same package.
	bundles []string
	// requires lists tool ids whose package this one imports.
	requires []string
	// recommends lists tool ids suggested alongside.
	recommends []string
	// alsoRequires lists non-adapter component ids it needs.
	alsoRequires []string
	note         string
	// processes are the programs the adapter's own packages start
	// (Surface.Processes; the process declaration test checks each).
	processes []string
}

// adapterSpecs is the closed adapter table, sorted by tool id.
var adapterSpecs = []adapterSpec{
	{tool: "aider", title: "Aider", pkg: "internal/adapter/aider"},
	{tool: "autohand", title: "Autohand Code", pkg: "internal/adapter/autohand"},
	{
		tool: "antigravity", title: "Antigravity", pkg: "internal/adapter/antigravity", bundles: []string{"antigravity-cli"},
		note: "Also reads the vendor Local State, calls DPAPI on Windows and runs `security` on macOS (possible Keychain prompt) to decrypt desktop stores.",
		// Lane LEFT2-SEC (R-025, PT-04): the five baseline gaps and the
		// discovery site, now declared.
		processes: []string{
			"powershell (Windows process discovery and the desktop bridge, over WSL interop from Linux; the OSCrypt key's DPAPI read over WSL interop)",
			"ps and lsof (process discovery on macOS and Linux)",
			"security (the macOS keychain read of the OSCrypt key)",
			"secret-tool (the Linux secret service read of the OSCrypt key)",
		},
	},
	{tool: "antigravity-cli", title: "Antigravity CLI", pkg: "internal/adapter/antigravity", bundles: []string{"antigravity"}},
	{tool: "chatgpt-web", title: "ChatGPT (web)", pkg: "internal/adapter/browserchat", bundles: []string{"claude-web", "perplexity-web", "gemini-web", "copilot-web"}, alsoRequires: []string{"capture.browser"}},
	{tool: "claude-code", title: "Claude Code", pkg: "internal/adapter/claudecode"},
	{tool: "claude-web", title: "Claude.ai (web)", pkg: "internal/adapter/browserchat", bundles: []string{"chatgpt-web", "perplexity-web", "gemini-web", "copilot-web"}, alsoRequires: []string{"capture.browser"}},
	{
		tool: "cline", title: "Cline", pkg: "internal/adapter/cline",
		note: "Also parses the rowless Roo Code and ZooCode extension stores (per-file retags, no registry rows by design).",
	},
	{tool: "cline-cli", title: "Cline CLI", pkg: "internal/adapter/clinecli"},
	{tool: "codebuddy", title: "CodeBuddy Code", pkg: "internal/adapter/codebuddy"},
	{tool: "codex", title: "Codex", pkg: "internal/adapter/codex", bundles: []string{"open-interpreter"}},
	{tool: "command-code", title: "Command Code", pkg: "internal/adapter/commandcode"},
	{tool: "cortex-code", title: "Cortex Code", pkg: "internal/adapter/cortexcode"},
	{tool: "copilot", title: "GitHub Copilot", pkg: "internal/adapter/copilot"},
	{tool: "copilot-cli", title: "GitHub Copilot CLI", pkg: "internal/adapter/copilotcli"},
	{tool: "copilot-web", title: "Microsoft Copilot (web)", pkg: "internal/adapter/browserchat", bundles: []string{"chatgpt-web", "claude-web", "perplexity-web", "gemini-web"}, alsoRequires: []string{"capture.browser"}},
	{tool: "cowork", title: "Claude Cowork", pkg: "internal/adapter/cowork"},
	{tool: "crush", title: "Crush", pkg: "internal/adapter/crush"},
	{tool: "cursor", title: "Cursor", pkg: "internal/adapter/cursor"},
	{tool: "deepagents-code", title: "Deep Agents Code", pkg: "internal/adapter/deepagents"},
	{tool: "deepseek", title: "DeepSeek Harness", pkg: "internal/adapter/deepseek"},
	{tool: "devin", title: "Devin (formerly Windsurf)", pkg: "internal/adapter/devin"},
	{tool: "dimcode", title: "DimCode", pkg: "internal/adapter/dimcode"},
	{tool: "dirac", title: "Dirac", pkg: "internal/adapter/dirac"},
	{tool: "droid", title: "Factory Droid", pkg: "internal/adapter/droid"},
	{tool: "freebuff", title: "Freebuff", pkg: "internal/adapter/freebuff"},
	{tool: "gemini-cli", title: "Gemini CLI", pkg: "internal/adapter/gemini"},
	{tool: "gemini-web", title: "Gemini (web)", pkg: "internal/adapter/browserchat", bundles: []string{"chatgpt-web", "claude-web", "perplexity-web", "copilot-web"}, alsoRequires: []string{"capture.browser"}},
	{tool: "goose", title: "Goose", pkg: "internal/adapter/goose"},
	{tool: "grok", title: "Grok CLI", pkg: "internal/adapter/grok"},
	{tool: "grokbot", title: "Grok Bot desktop", pkg: "internal/adapter/grokbot"},
	{tool: "hermes", title: "Hermes Agent", pkg: "internal/adapter/hermes"},
	{tool: "ibm-bob", title: "IBM Bob", pkg: "internal/adapter/ibmbob"},
	{tool: "junie", title: "JetBrains Junie", pkg: "internal/adapter/junie"},
	{
		tool: "kilo-code", title: "Kilo Code", pkg: "internal/adapter/kilocode", bundles: []string{"kilo-code-cli"}, requires: []string{"cline"},
		note: "The legacy extension adapter wraps the cline parser.",
	},
	{tool: "kilo-code-cli", title: "Kilo Code CLI", pkg: "internal/adapter/kilocode", bundles: []string{"kilo-code"}, requires: []string{"cline"}},
	{tool: "kimchi", title: "Kimchi", pkg: "internal/adapter/kimchi"},
	{tool: "kimi-code", title: "Kimi Code", pkg: "internal/adapter/kimicode"},
	{tool: "kiro-cli", title: "Kiro CLI", pkg: "internal/adapter/kirocli"},
	{
		tool: "kiro-crew", title: "Kiro Crew", pkg: "internal/adapter/kirocrew", recommends: []string{"kiro-cli"},
		note: "kiro-cli owns the turns a Crew chat writes to its store; without it those turns are not captured.",
	},
	{tool: "mistral-code", title: "Mistral Vibe", pkg: "internal/adapter/mistralcode"},
	{tool: "muse", title: "Meta Muse Code", pkg: "internal/adapter/muse"},
	{tool: "open-interpreter", title: "Open Interpreter", pkg: "internal/adapter/codex", bundles: []string{"codex"}},
	{tool: "openclaw", title: "OpenClaw", pkg: "internal/adapter/openclaw"},
	{tool: "opencode", title: "OpenCode", pkg: "internal/adapter/opencode"},
	{tool: "perplexity-web", title: "Perplexity (web)", pkg: "internal/adapter/browserchat", bundles: []string{"chatgpt-web", "claude-web", "gemini-web", "copilot-web"}, alsoRequires: []string{"capture.browser"}},
	{tool: "pi", title: "Pi", pkg: "internal/adapter/pi"},
	{tool: "poolside", title: "Poolside", pkg: "internal/adapter/poolside"},
	{tool: "prime-agent", title: "Prime Agent", pkg: "internal/adapter/primeagent"},
	{tool: "qoder", title: "Qoder", pkg: "internal/adapter/qoder"},
	{tool: "qwen-code", title: "Qwen Code", pkg: "internal/adapter/qwencode"},
	{tool: "stakpak", title: "Stakpak", pkg: "internal/adapter/stakpak"},
	{tool: "vtcode", title: "VT Code", pkg: "internal/adapter/vtcode"},
	{tool: "zcode", title: "ZCode", pkg: "internal/adapter/zcode"},
	{tool: "zed", title: "Zed agent", pkg: "internal/adapter/zed"},
}

// adapterModules lists the third-party modules an adapter package imports
// directly, beyond what core already brings (modernc sqlite is core).
var adapterModules = map[string][]string{
	"internal/adapter/antigravity": {"modernc.org/sqlite", "github.com/billgraziano/dpapi", "golang.org/x/crypto"},
	"internal/adapter/deepseek":    {"github.com/klauspost/compress"},
	"internal/adapter/zed":         {"github.com/klauspost/compress", "modernc.org/sqlite"},
	"internal/adapter/copilot":     {"github.com/tailscale/hujson"},
}

// adapterExtraPkgs lists packages outside internal/adapter that only one
// adapter package uses, owned by that adapter's row.
var adapterExtraPkgs = map[string][]string{
	// OS-keychain decryption of the Antigravity desktop store (DPAPI on
	// Windows, the macOS Keychain through `security`).
	"internal/adapter/antigravity": {"internal/platform/oscrypt"},
}

// adapterSQLite lists the adapter packages that open the vendor's SQLite
// store directly (the modernc driver is a core module; listing it keeps
// the per-package import declaration exact).
var adapterSQLite = map[string]bool{
	"internal/adapter/clinecli": true, "internal/adapter/crush": true, "internal/adapter/cursor": true,
	"internal/adapter/devin": true, "internal/adapter/freebuff": true, "internal/adapter/goose": true,
	"internal/adapter/hermes": true, "internal/adapter/kilocode": true, "internal/adapter/kirocli": true,
	"internal/adapter/openclaw": true, "internal/adapter/opencode": true, "internal/adapter/qoder": true, "internal/adapter/zcode": true,
	"internal/adapter/ibmbob": true, "internal/adapter/deepagents": true, "internal/adapter/stakpak": true, "internal/adapter/dimcode": true,
}

// adapterL1 lists the adapter tools that claim L1 (lanes MP-ADP and MP-L1D,
// T-598): their package is registered only from its own build-tagged file
// in internal/adapter/defaults (adapter_<pkg>.go), nothing else in the node
// binary imports it (cmd/observer and internal/hook reach the adapter
// through build-tagged files of their own: hook receivers, backfill passes,
// watcher wiring, the browser bridge's normalizer), and the
// package-absence invariant proves it leaves the binary with the row's
// omit tag. A bundled row (kilo-code-cli, open-interpreter, antigravity-cli,
// the *-web rows) claims with the package that hosts it. Since MP-L1D every
// adapter row claims L1.
var adapterL1 = map[string]bool{
	"aider": true, "antigravity": true, "antigravity-cli": true, "cline": true, "codex": true, "cline-cli": true, "command-code": true, "copilot": true,
	"copilot-cli": true, "cowork": true, "crush": true, "cursor": true, "deepseek": true, "devin": true, "droid": true,
	"claude-code": true, "freebuff": true, "gemini-cli": true, "goose": true, "grok": true, "grokbot": true, "hermes": true,
	"junie": true, "kilo-code": true, "kilo-code-cli": true, "kimi-code": true, "kiro-cli": true,
	"kiro-crew": true, "mistral-code": true, "muse": true, "open-interpreter": true, "openclaw": true, "opencode": true,
	"pi": true, "poolside": true, "prime-agent": true, "qoder": true, "qwen-code": true,
	"zcode": true, "zed": true,
	"autohand": true, "ibm-bob": true, "cortex-code": true, "codebuddy": true, "deepagents-code": true, "dimcode": true,
	"dirac": true, "kimchi": true, "stakpak": true, "vtcode": true,
	"chatgpt-web": true, "claude-web": true, "perplexity-web": true, "gemini-web": true, "copilot-web": true,
}

// AdapterID returns the catalog id for a registry tool id.
func AdapterID(tool string) string { return "adapter." + tool }

// stabilityFromLifecycle maps the registry lifecycle onto the catalog's
// stability vocabulary.
func stabilityFromLifecycle(l integration.Lifecycle) Stability {
	if l == integration.LifecycleActive {
		return StabilityStable
	}
	return StabilityDeprecated
}

func adapterRows() []Component {
	owned := map[string]bool{}
	rows := make([]Component, 0, len(adapterSpecs))
	for _, s := range adapterSpecs {
		c := Component{
			ID:      AdapterID(s.tool),
			Class:   ClassAdapter,
			Binary:  BinaryNode,
			Title:   s.title,
			About:   "Captures " + s.title + " sessions from its local store (see the integration registry for its hook, proxy, MCP and token facts).",
			Levels:  lv(onlyL3, l1l2l3, "P5"),
			Distros: dist(off, on, off, on),
			Note:    s.note,
		}
		c.Surface.Processes = s.processes
		if adapterL1[s.tool] {
			c.Levels = lv([]Level{L1, L3}, l1l2l3, "P5")
		}
		if owned[s.pkg] {
			c.HostedIn = []string{s.pkg}
		} else {
			owned[s.pkg] = true
			c.Packages = append([]string{s.pkg}, adapterExtraPkgs[s.pkg]...)
			c.DirectModules = append(c.DirectModules, adapterModules[s.pkg]...)
			if adapterSQLite[s.pkg] {
				c.DirectModules = appendUnique(c.DirectModules, "modernc.org/sqlite")
			}
		}
		for _, b := range s.bundles {
			c.Bundles = append(c.Bundles, AdapterID(b))
		}
		for _, r := range s.requires {
			c.Requires = append(c.Requires, AdapterID(r))
		}
		c.Requires = append(c.Requires, s.alsoRequires...)
		for _, r := range s.recommends {
			c.Recommends = append(c.Recommends, AdapterID(r))
		}
		lc, _, _ := integration.LifecycleFor(s.tool)
		c.Stability = stabilityFromLifecycle(lc)
		c.Data = []DataOwnership{
			{Table: "sessions", Ownership: "shared", Selector: "tool = '" + s.tool + "'"},
			{Table: "actions", Ownership: "shared", Selector: "via sessions.tool = '" + s.tool + "'"},
			{Table: "token_usage", Ownership: "shared", Selector: "tool = '" + s.tool + "'"},
		}
		// Every adapter is compiled into every prebuilt distro (adapters
		// reach L1 only through custom builds, plan 3.3 notes): off in
		// minimal and managed (selected locally or by policy), on in
		// developer and full. A deprecated adapter keeps the same cells:
		// capture is never gated on lifecycle (docs/harness-lifecycle-policy.md).
		// The one exception is the browser-chat family: its package is
		// bundled with capture.browser, which minimal compiles out, so the
		// five web rows follow capture.browser's cells.
		for _, r := range s.alsoRequires {
			if r == "capture.browser" {
				c.Distros = dist(out, on, off, on)
			}
		}
		rows = append(rows, c)
	}
	return rows
}

func appendUnique(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}
