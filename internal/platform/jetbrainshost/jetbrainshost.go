package jetbrainshost

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// Product describes one JetBrains IDE product line whose config directory
// this package knows how to classify.
type Product struct {
	// DirPrefixes are the config-directory name prefixes the IDE creates
	// under the vendor root, before the version suffix — e.g.
	// "IntelliJIdea" (Ultimate) and "IdeaIC" (Community) for IntelliJ
	// IDEA. Matched as a case-sensitive prefix of the directory name.
	DirPrefixes []string
	// DisplayName is the product name JetBrains itself uses in client
	// strings its AI Assistant hands to spawned agents
	// ("JetBrains.IntelliJ IDEA" → "IntelliJ IDEA").
	DisplayName string
	// Host is the lowercase surface-host token this product stamps
	// alongside models.SurfaceIDE — e.g. "jetbrains-idea".
	Host string
}

// HostGeneric is the surface-host token for a JetBrains IDE whose product
// line is not in the table (a new product, or a client string this
// package has not seen). It is still a grounded JetBrains host — only the
// product refinement is unknown.
const HostGeneric = "jetbrains"

// VendorDirName is the vendor root directory name under the per-OS config
// base: "JetBrains".
const VendorDirName = "JetBrains"

// TaskHistoryDirName is the AI Assistant's per-task store inside a
// product config directory (2026.2): "aia-task-history".
const TaskHistoryDirName = "aia-task-history"

// AgentSessionExt is the extension of the one-line file that names the
// ACP agent session a task drove: ".agentsession".
const AgentSessionExt = ".agentsession"

// ClientNamePrefix is the prefix JetBrains AI Assistant puts on the client
// identity it hands to a spawned agent — Codex's `originator`, Copilot
// CLI's `client_name` — followed by the product DisplayName.
const ClientNamePrefix = "JetBrains."

// acpRegistryPrefix is the ACP registry id namespace inside an
// .agentsession token: "acp.registry.<agent>:<session id>".
const acpRegistryPrefix = "acp.registry."

// products is the ordered table of every JetBrains product line this
// package classifies. Prefixes are checked longest-first per product so
// "PyCharmCE" never falls through to a hypothetical "PyCharm" collision;
// across products the table is walked in order.
var products = []Product{
	{DirPrefixes: []string{"IntelliJIdea", "IdeaIC", "IdeaIU"}, DisplayName: "IntelliJ IDEA", Host: "jetbrains-idea"},
	{DirPrefixes: []string{"PyCharmCE", "PyCharm"}, DisplayName: "PyCharm", Host: "jetbrains-pycharm"},
	{DirPrefixes: []string{"WebStorm"}, DisplayName: "WebStorm", Host: "jetbrains-webstorm"},
	{DirPrefixes: []string{"GoLand"}, DisplayName: "GoLand", Host: "jetbrains-goland"},
	{DirPrefixes: []string{"CLion"}, DisplayName: "CLion", Host: "jetbrains-clion"},
	{DirPrefixes: []string{"Rider"}, DisplayName: "Rider", Host: "jetbrains-rider"},
	{DirPrefixes: []string{"PhpStorm"}, DisplayName: "PhpStorm", Host: "jetbrains-phpstorm"},
	{DirPrefixes: []string{"RubyMine"}, DisplayName: "RubyMine", Host: "jetbrains-rubymine"},
	{DirPrefixes: []string{"RustRover"}, DisplayName: "RustRover", Host: "jetbrains-rustrover"},
	{DirPrefixes: []string{"DataGrip"}, DisplayName: "DataGrip", Host: "jetbrains-datagrip"},
	{DirPrefixes: []string{"DataSpell"}, DisplayName: "DataSpell", Host: "jetbrains-dataspell"},
	{DirPrefixes: []string{"AndroidStudio"}, DisplayName: "Android Studio", Host: "jetbrains-android-studio"},
}

// acpAgents maps the ACP registry agent id in an .agentsession token to
// the Observer tool that owns that agent's own session store. Grounded
// on the operator's IntelliJ IDEA 2026.2 runs (acp-agents/installed.json
// + one task per agent). The session id half of the token is the owning
// adapter's sessions.id VERBATIM for every row here — no transform — a
// requirement for membership, since the enricher stamps by exact
// sessions.id (surfaceenrich matches Load(sessionID) exactly).
//
// The 2026-09-04 run added cline / kilo / devin / opencode, whose owner
// sessions were captured with ids that match their pointer sid exactly
// (cline-cli `<ms>_<rand>_cli`, kilo-code-cli / opencode `ses_…`, devin's
// human slug). mistral-vibe (added 2026-09-05) is here too but needs a
// NormalizeSessionID: mistral-code stores the vibe dir's 8-hex suffix as
// sessions.id while the pointer carries meta.json's full uuid, so the
// normalizer truncates the pointer sid to match. antigravity-acp (added
// 2026-09-04) is here too — it drives the agy backend into a THIRD
// ~/.gemini/antigravity-acp tree the antigravity adapter now watches
// (ToolAntigravityCLI). ONE agent that ran still can't be stamped and is
// DELIBERATELY NOT here:
//   - pi (pi-acp): pi sessions were captured but JetBrains wrote no
//     .agentsession pointer for them, so the enricher has nothing to read
//     (a JetBrains-side gap, confirmed 2026-09-04; not fixable here).
//
// The 2026-09-05 run added poolside, whose own trajectory-<agentId>_
// <sessionId>.ndjson filename carries the exact ACP pointer sid (no
// truncation, no transform) — see internal/adapter/poolside.
//
// cortex-code, stakpak and codebuddy-code gained Observer adapters on
// 2026-10-21 but are still NOT here: the one cortex-code pointer on the
// grounding host (sid ca8ac860-…) matches no session in either OS's
// ~/.snowflake/cortex/conversations, and no stakpak or codebuddy-code
// .agentsession pointer exists yet, so pointer sid == sessions.id is
// unproven for all three. Add a row only after one JetBrains run proves it,
// or as an ALIAS when the registry id runs the very package a mapped row was
// proven with (github-copilot-cli, below). Every other unmapped agent of an
// Observer adapter is listed in unmappedACPAgents with its live check.
//
// The registry also lists agents with no Observer adapter at all
// (auggie) and agents the operator confirmed broken on 2026-09-04 (kimi,
// qwen-code, factory-droid, glm-acp-agent, grok-build, goose) — none
// belong here. (History: the 2026-09-05 cortex-code investigation found
// the JetBrains-downloaded cortex.exe 1.0.73 wrote no local store; the
// standalone 1.2.18 install's ~/.snowflake/cortex store is what the
// 2026-10-21 adapter reads, and that pointer predates it.)
// acpAgentMapping is an acpAgents value: the owning Observer tool plus an
// optional session-id normalizer. NormalizeSessionID is nil for every
// agent whose pointer sid IS the owner's sessions.id verbatim (the common
// case); it is set only where the owning adapter stores a DIFFERENT id
// than the pointer carries, so the enricher's exact-id Load can still hit.
type acpAgentMapping struct {
	Tool               string
	NormalizeSessionID func(sid string) string
}

var acpAgents = map[string]acpAgentMapping{
	"junie":          {Tool: models.ToolJunie},
	"claude-acp":     {Tool: models.ToolClaudeCode},
	"codex-acp":      {Tool: models.ToolCodex},
	"github-copilot": {Tool: models.ToolCopilotCLI},
	"cline":          {Tool: models.ToolClineCLI},
	"kilo":           {Tool: models.ToolKiloCodeCLI},
	"devin":          {Tool: models.ToolDevin},
	"opencode":       {Tool: models.ToolOpenCode},
	"poolside":       {Tool: models.ToolPoolside},
	// mistral-code stores sessions.id as the vibe session dir's 8-hex
	// suffix (the `vibe --resume <8hex>` handle), but the JetBrains pointer
	// carries meta.json's full uuid. Truncate at the first hyphen — the
	// same rule sessionIDFromPath itself falls back to — so the exact-id
	// Load matches. Verified live 2026-09-04:
	// "002d67cb-2300-2d9f-60f3-09445460cbcc" -> "002d67cb".
	"mistral-vibe": {Tool: models.ToolMistralCode, NormalizeSessionID: truncateAtHyphen},
	// antigravity-acp drives the agy backend, which writes a THIRD
	// ~/.gemini/antigravity-acp tree with the same .db schema; the
	// antigravity adapter captures it as ToolAntigravityCLI and the
	// conversation uuid (== trajectory_meta.cascade_id) is the pointer sid
	// verbatim, so no normalizer is needed.
	"antigravity-acp": {Tool: models.ToolAntigravityCLI},
	// github-copilot-cli (surface-gap S-1, lane w8-registry, 2026-10-28) is
	// an ALIAS, not a new agent: the registry now ships two Copilot
	// entries, github-copilot = @github/copilot-language-server and
	// github-copilot-cli = @github/copilot (inventory 2026-10-25 X2), and
	// @github/copilot is the package the 2026-09-03 live run proved under
	// the old github-copilot id (Copilot CLI 1.0.79, ~/.copilot/session-state,
	// pointer sid == sessions.id). The pointer sid is minted by that agent
	// binary, so the proof follows the package. A pointer run under the new
	// id re-confirms it (LCR-63); a mismatch is a miss (no session with that
	// id), never a stamp on someone else's session.
	"github-copilot-cli": {Tool: models.ToolCopilotCLI},
}

// unmappedACPAgents are the ACP registry agents of Observer adapters that
// acpAgents deliberately does NOT map yet, each with why and the live check
// that would add it (surface-gap S-1, FU-58; the ACP registry read of
// 2026-10-25, docs/audits/vendor-surface-inventory-2026-10-25.md section 5).
// Their sessions are still captured by their own adapters; only the
// ide/jetbrains-* stamp is missing. Never consulted by ParseAgentSession.
var unmappedACPAgents = map[string]UnmappedACPAgent{
	"opencode-v2":    {Tool: models.ToolOpenCode, Reason: "OpenCode V2 (2.x, `opencode acp`) is a separate registry entry beside opencode 1.x, not a rename; the 2.x line changed its plugin contract (FU-121), so its session id is not assumed to round trip", LiveCheck: "LCR-63"},
	"cursor":         {Tool: models.ToolCursor, Reason: "no JetBrains pointer run yet (`cursor-agent acp`)", LiveCheck: "LCR-63"},
	"gemini":         {Tool: models.ToolGeminiCLI, Reason: "no JetBrains pointer run yet (`@google/gemini-cli`)", LiveCheck: "LCR-63"},
	"autohand":       {Tool: models.ToolAutohand, Reason: "no JetBrains pointer run yet; the registry ships a separate adapter package (`@autohandai/autohand-acp`)", LiveCheck: "LCR-63"},
	"bob":            {Tool: models.ToolIBMBob, Reason: "no JetBrains pointer run yet (`@ibm/bob`)", LiveCheck: "LCR-63"},
	"dimcode":        {Tool: models.ToolDimCode, Reason: "no JetBrains pointer run yet (`dimcode`)", LiveCheck: "LCR-63"},
	"dirac":          {Tool: models.ToolDirac, Reason: "no JetBrains pointer run yet (`dirac-cli`)", LiveCheck: "LCR-63"},
	"kimchi":         {Tool: models.ToolKimchi, Reason: "no JetBrains pointer run yet (`kimchi --mode acp`)", LiveCheck: "LCR-63"},
	"qoder":          {Tool: models.ToolQoder, Reason: "no JetBrains pointer run yet (`@qoder-ai/qodercli`)", LiveCheck: "LCR-63"},
	"vtcode":         {Tool: models.ToolVTCode, Reason: "no JetBrains pointer run yet (`vtcode acp`); its hooks run only in the TUI", LiveCheck: "LCR-63"},
	"deepagents":     {Tool: models.ToolDeepAgentsCode, Reason: "the registry package is the JS deepagentsjs line, not dcode, so whether it writes the store the adapter reads is unknown", LiveCheck: "LCR-63"},
	"cortex-code":    {Tool: models.ToolCortexCode, Reason: "the one pointer seen (2026-09-05) matched no session: the JetBrains-downloaded cortex 1.0.73 wrote no local store", LiveCheck: "LCR-63"},
	"stakpak":        {Tool: models.ToolStakpak, Reason: "no .agentsession pointer seen yet", LiveCheck: "LCR-63"},
	"codebuddy-code": {Tool: models.ToolCodeBuddy, Reason: "no .agentsession pointer seen yet", LiveCheck: "LCR-63"},
	"goose":          {Tool: models.ToolGoose, Reason: "confirmed broken in the 2026-09-04 run", LiveCheck: "LCR-63"},
	"grok-build":     {Tool: models.ToolGrok, Reason: "confirmed broken in the 2026-09-04 run", LiveCheck: "LCR-63"},
	"qwen-code":      {Tool: models.ToolQwenCode, Reason: "confirmed broken in the 2026-09-04 run", LiveCheck: "LCR-63"},
	"factory-droid":  {Tool: models.ToolDroid, Reason: "confirmed broken in the 2026-09-04 run", LiveCheck: "LCR-63"},
	"pi-acp":         {Tool: models.ToolPi, Reason: "JetBrains writes no .agentsession pointer for pi-acp (confirmed 2026-09-04)", LiveCheck: "LCR-63"},
	// kimi (FU-58 X1): the registry's kimi entry downloads the ARCHIVED
	// Python kimi-cli (MoonshotAI/kimi-cli, data in ~/.kimi), not Kimi Code
	// (~/.kimi-code), so a registry-installed Kimi is not captured at all,
	// which fits the 2026-09-04 "broken" note. Tool is empty on purpose.
	"kimi": {Tool: "", Reason: "the registry kimi entry is the archived Python Kimi CLI, whose ~/.kimi store no adapter reads; Kimi Code (~/.kimi-code) is a different product", LiveCheck: "LCR-66"},
}

// UnmappedACPAgent is one unmappedACPAgents value.
type UnmappedACPAgent struct {
	// Tool is the Observer tool whose product the registry entry is, or ""
	// when no adapter captures it.
	Tool string
	// Reason says why it is not mapped.
	Reason string
	// LiveCheck names the pending live check that would map it.
	LiveCheck string
}

// UnmappedACPAgents returns the unmapped agent table as a fresh copy, for
// the doctor and the coding-surface rows.
func UnmappedACPAgents() map[string]UnmappedACPAgent {
	out := make(map[string]UnmappedACPAgent, len(unmappedACPAgents))
	for k, v := range unmappedACPAgents {
		out[k] = v
	}
	return out
}

// truncateAtHyphen returns s up to (not including) the first '-', or s
// unchanged when there is none.
func truncateAtHyphen(s string) string {
	if i := strings.IndexByte(s, '-'); i > 0 {
		return s[:i]
	}
	return s
}

// Products returns the ordered product table. Callers get a fresh copy;
// mutating the result never affects the package's own table.
func Products() []Product {
	out := make([]Product, len(products))
	copy(out, products)
	return out
}

// VendorRoot returns the JetBrains vendor config root under home root h,
// following the per-OS convention in the package doc. It returns "" for
// a home whose OS is not one of crossmount.OSWindows/OSDarwin/OSLinux.
func VendorRoot(h crossmount.HomeRoot) string {
	switch h.OS {
	case crossmount.OSWindows:
		if h.Origin == "native" && runtime.GOOS == "windows" {
			if appData := os.Getenv("APPDATA"); appData != "" {
				return filepath.Join(appData, VendorDirName)
			}
		}
		return filepath.Join(h.Path, "AppData", "Roaming", VendorDirName)
	case crossmount.OSDarwin:
		return filepath.Join(h.Path, "Library", "Application Support", VendorDirName)
	case crossmount.OSLinux:
		return filepath.Join(h.Path, ".config", VendorDirName)
	default:
		return ""
	}
}

// ProductForDir classifies a product config-directory NAME
// ("IntelliJIdea2026.2", "PyCharmCE2025.3") by its prefix. ok is false
// for a name that is not a product directory (the vendor root also holds
// "acp-agents", "consentOptions", "PermanentDeviceId", …).
func ProductForDir(dirName string) (Product, bool) {
	for _, p := range products {
		for _, prefix := range p.DirPrefixes {
			if strings.HasPrefix(dirName, prefix) && len(dirName) > len(prefix) && isVersionStart(dirName[len(prefix)]) {
				return p, true
			}
		}
	}
	return Product{}, false
}

// isVersionStart reports whether c can begin a JetBrains version suffix
// ("2026.2", "252.1"): a digit. Guards a prefix match from claiming an
// unrelated directory that merely starts with the same letters.
func isVersionStart(c byte) bool { return c >= '0' && c <= '9' }

// HostForClientName resolves the client identity a JetBrains-spawned
// agent records ("JetBrains.IntelliJ IDEA") into a surface-host token.
// ok is false when s does not carry the JetBrains prefix at all (the
// string belongs to some other host — the caller keeps its own table).
// A JetBrains prefix with an unknown product resolves to HostGeneric.
func HostForClientName(s string) (host string, ok bool) {
	if !strings.HasPrefix(s, ClientNamePrefix) {
		return "", false
	}
	name := strings.TrimSpace(strings.TrimPrefix(s, ClientNamePrefix))
	for _, p := range products {
		if strings.EqualFold(name, p.DisplayName) {
			return p.Host, true
		}
	}
	return HostGeneric, true
}

// TaskHistoryDir is one AI Assistant task-history directory resolved under
// a home: its path plus the product it belongs to (for the host token).
type TaskHistoryDir struct {
	Path    string
	Product Product
	// ProductDir is the version-suffixed config directory name the store
	// was found under ("IntelliJIdea2026.2") — for diagnostics only.
	ProductDir string
}

// TaskHistoryDirs lists every product's aia-task-history directory under
// home root h, by reading the vendor root through readDir (injected so
// this package stays pure; pass os.ReadDir-shaped output — names only).
// Entries readDir returns that are not product directories are skipped;
// a readDir error (vendor root absent) yields nil. The returned paths
// are NOT stat'ed — a product that has never run AI Assistant simply has
// no such directory, and the consumer's walk tolerates that.
func TaskHistoryDirs(h crossmount.HomeRoot, readDir func(string) ([]string, error)) []TaskHistoryDir {
	root := VendorRoot(h)
	if root == "" || readDir == nil {
		return nil
	}
	names, err := readDir(root)
	if err != nil {
		return nil
	}
	var out []TaskHistoryDir
	for _, name := range names {
		p, ok := ProductForDir(name)
		if !ok {
			continue
		}
		out = append(out, TaskHistoryDir{
			Path:       filepath.Join(root, name, TaskHistoryDirName),
			Product:    p,
			ProductDir: name,
		})
	}
	return out
}

// AgentSession is the decoded content of one .agentsession file.
type AgentSession struct {
	// Agent is the ACP registry agent id ("junie", "claude-acp", …).
	Agent string
	// SessionID is the agent's OWN session id — the sessions.id the
	// owning adapter emits, verbatim.
	SessionID string
	// Tool is the Observer tool id owning that agent's store, or "" when
	// Agent is not in the grounded table.
	Tool string
}

// ParseAgentSession decodes the one-line .agentsession content
// ("acp.registry.<agent>:<session id>"). ok is false for anything that
// does not have that exact shape, including an empty session id — a task
// whose agent never started a session writes no .agentsession at all,
// so a malformed one is a format change, not a normal state. Tool is
// resolved through the grounded table and may be "" (unknown agent).
func ParseAgentSession(text string) (AgentSession, bool) {
	line := strings.TrimSpace(text)
	if nl := strings.IndexAny(line, "\r\n"); nl >= 0 {
		line = strings.TrimSpace(line[:nl])
	}
	if !strings.HasPrefix(line, acpRegistryPrefix) {
		return AgentSession{}, false
	}
	rest := strings.TrimPrefix(line, acpRegistryPrefix)
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 || colon == len(rest)-1 {
		return AgentSession{}, false
	}
	agent, sid := rest[:colon], rest[colon+1:]
	if strings.ContainsAny(sid, " \t/\\") {
		return AgentSession{}, false
	}
	m := acpAgents[agent]
	if m.NormalizeSessionID != nil {
		sid = m.NormalizeSessionID(sid)
	}
	return AgentSession{Agent: agent, SessionID: sid, Tool: m.Tool}, true
}

// ToolForACPAgent returns the Observer tool owning an ACP registry
// agent's own store, and whether the agent is in the grounded table.
func ToolForACPAgent(agent string) (string, bool) {
	m, ok := acpAgents[agent]
	return m.Tool, ok
}

// ACPAgents returns the grounded agent-id → tool table as a fresh copy
// (for docs / diagnostics that render the mapping).
func ACPAgents() map[string]string {
	out := make(map[string]string, len(acpAgents))
	for k, v := range acpAgents {
		out[k] = v.Tool
	}
	return out
}

// Surface returns the models.SessionSurface a task hosted by product p
// stamps on the agent session sid: kind models.SurfaceIDE, the product's
// host token, and Hosted=true — the hosting layer's record replaces the
// agent's own self-report (see models.SessionSurface.Hosted).
func Surface(sid string, p Product) models.SessionSurface {
	host := p.Host
	if host == "" {
		host = HostGeneric
	}
	return models.SessionSurface{
		SessionID:   sid,
		Surface:     models.SurfaceIDE,
		SurfaceHost: host,
		Hosted:      true,
	}
}
