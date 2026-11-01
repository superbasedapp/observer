package diag

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/vscodehost"
)

// vendorpolicy.go reads the vendor org-policy CACHES a tool keeps on disk
// (surface-gap arc finding S-15, operator decision D17, 2026-10-25: "allow
// reading cached vendor policy files (Cline remote config, Factory org
// settings) for doctor and managed-integrity rows; never credentials").
//
// Read discipline:
//
//   - Only the cache files the table names are opened, never a credential
//     store (no secrets.json, providers.json or auth file), and each is read
//     up to vendorPolicyMaxBytes.
//   - Only the member paths a rule names are scanned
//     (credfile.ObjectPath, the D9 / D16 member-only read); every other
//     member, such as Cline's openAiHeaders or remoteMCPServers[].headers,
//     is skipped over, never decoded.
//   - No value read from a cache is surfaced: a finding names the tool, the
//     rule, the file and a fixed message. A pinned base URL is only judged
//     loopback or not.
//
// Grounding, per rule (VendorPolicyFinding.Grounding): the Cline members are
// read from the vendor's remote-config schema (source-grounded, not
// live-verified); of the Factory org cache only managedSettings.modelPolicy
// (allowAllFactoryModels, allowCustomModels, isFastModelsAllowed) is
// live-grounded. mcpPolicy.enabled / mcpPolicy.allowlist and
// modelPolicy.allowedBaseUrls are the vendor's documented system-file
// members; that the cache carries them under managedSettings is inferred
// until pending-work row FU-39 grounds the cache's member names live.

// vendorPolicyMaxBytes bounds one cache read; a larger file is skipped.
const vendorPolicyMaxBytes = 1 << 20

// VendorPolicyKind is what a cached vendor policy does to Observer's wiring.
type VendorPolicyKind string

const (
	// VendorPolicyBlocksMCP: Observer's MCP server cannot run in the tool.
	VendorPolicyBlocksMCP VendorPolicyKind = "blocks_mcp"
	// VendorPolicyPinsRoute: the tool's provider base URL is pinned to a
	// host other than a loopback proxy.
	VendorPolicyPinsRoute VendorPolicyKind = "pins_route"
	// VendorPolicyRouteVeto: the policy would refuse a loopback BYOK route
	// Observer could write. Informational where Observer writes no route for
	// the tool (doctor detail only; it never crosses the org wire).
	VendorPolicyRouteVeto VendorPolicyKind = "route_veto"
)

// Grounding of a rule's member names.
const (
	VendorPolicySourceGrounded = "source-grounded (vendor schema), not live-verified"
	VendorPolicyLiveGrounded   = "live-grounded member"
	VendorPolicyInferred       = "inferred member name (pending FU-39), not live-verified"
)

// VendorPolicyFinding is one rule that holds in one cache file.
type VendorPolicyFinding struct {
	Tool string
	Rule string
	Kind VendorPolicyKind
	// File is the cache file read (absolute); Dir is its directory, the
	// location a managed-integrity item names (Cline's file name carries the
	// vendor org id, which never crosses).
	File, Dir string
	// Warn: the finding drops or blocks part of Observer's wiring now.
	Warn      bool
	Message   string
	Grounding string
}

// vendorPolicyDoc is a member-only view over one cache's bytes.
type vendorPolicyDoc struct{ raw []byte }

// member returns the member at path (credfile.ObjectPath); ok is false when
// it is absent or the document is not an object.
func (d vendorPolicyDoc) member(path ...string) (json.RawMessage, bool) {
	v, ok, err := credfile.ObjectPath(d.raw, path)
	if err != nil || !ok {
		return nil, false
	}
	return v, true
}

// boolIs reports whether the member at path is the JSON boolean want.
func (d vendorPolicyDoc) boolIs(want bool, path ...string) bool {
	v, ok := d.member(path...)
	if !ok {
		return false
	}
	var b bool
	return json.Unmarshal(v, &b) == nil && b == want
}

// vendorPolicyRule is one row of a cache's rule table: when holds is true,
// the finding is raised.
type vendorPolicyRule struct {
	id        string
	kind      VendorPolicyKind
	warn      bool
	grounding string
	message   string
	holds     func(d vendorPolicyDoc) bool
}

// vendorPolicyCache is one cache a tool keeps: where its files are and the
// rules over them.
type vendorPolicyCache struct {
	tool  string
	files func(home string, getenv func(string) string) []string
	rules []vendorPolicyRule
}

// vendorPolicyCaches is the table (CLAUDE.md #5): one row per cache.
var vendorPolicyCaches = []vendorPolicyCache{
	{tool: "cline", files: clineRemoteConfigFiles, rules: clineRemoteConfigRules},
	{tool: "droid", files: factoryOrgCacheFiles, rules: factoryOrgCacheRules},
}

// clineRemoteConfigRules read Cline's cached org remote config
// (cache/remote_config_<orgId>.json under the extension's globalStorage).
var clineRemoteConfigRules = []vendorPolicyRule{
	{
		id: "cline.remote.mcp_marketplace_off", kind: VendorPolicyBlocksMCP, warn: true, grounding: VendorPolicySourceGrounded,
		message: "the Cline organization's remote config sets mcpMarketplaceEnabled to false, which blocks every local MCP server, Observer's included",
		holds:   func(d vendorPolicyDoc) bool { return d.boolIs(false, "mcpMarketplaceEnabled") },
	},
	{
		id: "cline.remote.mcp_not_allowlisted", kind: VendorPolicyBlocksMCP, warn: true, grounding: VendorPolicySourceGrounded,
		message: "the Cline organization's remote config allows only the MCP servers in allowedMCPServers, and Observer's server (" + mcpregister.ServerName + ") is not one of them",
		holds:   clineMCPNotAllowlisted,
	},
	{
		id: "cline.remote.route_pinned", kind: VendorPolicyPinsRoute, warn: true, grounding: VendorPolicySourceGrounded,
		message: "the Cline organization's remote config pins a provider base URL (providerSettings) to a host other than a local proxy, so Cline's model traffic does not reach Observer's proxy",
		holds: func(d vendorPolicyDoc) bool {
			for _, p := range clineRemoteBaseURLPaths {
				if v, ok := d.member(p...); ok && nonLoopbackURL(v) {
					return true
				}
			}
			return false
		},
	},
}

// clineRemoteBaseURLPaths are the remote-config members that set a
// provider's base URL (vendor schema: providerSettings.OpenAiCompatible,
// .Anthropic and .LiteLLM).
var clineRemoteBaseURLPaths = [][]string{
	{"providerSettings", "OpenAiCompatible", "openAiBaseUrl"},
	{"providerSettings", "Anthropic", "baseUrl"},
	{"providerSettings", "LiteLLM", "baseUrl"},
}

// clineMCPNotAllowlisted: allowedMCPServers is a non-empty list of {id}
// entries and none is Observer's server name (an empty list means no
// restriction, per the vendor schema).
func clineMCPNotAllowlisted(d vendorPolicyDoc) bool {
	v, ok := d.member("allowedMCPServers")
	if !ok {
		return false
	}
	var entries []struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(v, &entries) != nil || len(entries) == 0 {
		return false
	}
	for _, e := range entries {
		if e.ID == mcpregister.ServerName {
			return false
		}
	}
	return true
}

// factoryOrgCacheRules read Factory's cached org managed settings
// (~/.factory/org-managed-settings.cache.json).
var factoryOrgCacheRules = []vendorPolicyRule{
	{
		id: "factory.orgcache.mcp_policy_blocks_all", kind: VendorPolicyBlocksMCP, warn: true, grounding: VendorPolicyInferred,
		message: "the Factory organization's cached policy turns mcpPolicy on with an empty allowlist, which blocks every MCP server, Observer's included",
		holds: func(d vendorPolicyDoc) bool {
			return d.boolIs(true, "managedSettings", "mcpPolicy", "enabled") && factoryAllowlistLen(d) == 0
		},
	},
	{
		id: "factory.orgcache.mcp_not_allowlisted", kind: VendorPolicyBlocksMCP, warn: true, grounding: VendorPolicyInferred,
		message: "the Factory organization's cached policy allows only the MCP servers in mcpPolicy.allowlist, and no entry names Observer's server",
		holds: func(d vendorPolicyDoc) bool {
			return d.boolIs(true, "managedSettings", "mcpPolicy", "enabled") && factoryAllowlistLen(d) > 0 && !factoryAllowlistNamesObserver(d)
		},
	},
	{
		id: "factory.orgcache.custom_models_off", kind: VendorPolicyRouteVeto, warn: false, grounding: VendorPolicyLiveGrounded,
		message: "the Factory organization's cached policy sets modelPolicy.allowCustomModels to false, so a BYOK custom model pointed at Observer's proxy would be refused (Observer writes no Factory route today)",
		holds: func(d vendorPolicyDoc) bool {
			return d.boolIs(false, "managedSettings", "modelPolicy", "allowCustomModels")
		},
	},
	{
		id: "factory.orgcache.base_urls_exclude_loopback", kind: VendorPolicyRouteVeto, warn: false, grounding: VendorPolicyInferred,
		message: "the Factory organization's cached policy lists modelPolicy.allowedBaseUrls without a loopback entry, so a BYOK route to Observer's proxy would be refused (Observer writes no Factory route today)",
		holds:   factoryBaseURLsExcludeLoopback,
	},
}

// factoryAllowlistLen is the length of managedSettings.mcpPolicy.allowlist
// (0 when absent or not a list).
func factoryAllowlistLen(d vendorPolicyDoc) int {
	v, ok := d.member("managedSettings", "mcpPolicy", "allowlist")
	if !ok {
		return 0
	}
	var list []json.RawMessage
	if json.Unmarshal(v, &list) != nil {
		return 0
	}
	return len(list)
}

// factoryAllowlistNamesObserver reports whether an entry of
// managedSettings.mcpPolicy.allowlist names Observer's MCP server: a string
// entry equal to the server name, or an object entry whose name, id or
// serverName member is (case-insensitive). The entry shape is inferred
// (pending FU-39); an entry that only contains the name as a substring does
// not count.
func factoryAllowlistNamesObserver(d vendorPolicyDoc) bool {
	v, ok := d.member("managedSettings", "mcpPolicy", "allowlist")
	if !ok {
		return false
	}
	var list []json.RawMessage
	if json.Unmarshal(v, &list) != nil {
		return false
	}
	for _, raw := range list {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			if strings.EqualFold(strings.TrimSpace(s), mcpregister.ServerName) {
				return true
			}
			continue
		}
		var obj struct {
			Name       string `json:"name"`
			ID         string `json:"id"`
			ServerName string `json:"serverName"`
		}
		if json.Unmarshal(raw, &obj) == nil {
			for _, n := range []string{obj.Name, obj.ID, obj.ServerName} {
				if strings.EqualFold(strings.TrimSpace(n), mcpregister.ServerName) {
					return true
				}
			}
		}
	}
	return false
}

// factoryBaseURLsExcludeLoopback: allowedBaseUrls is a non-empty list of
// strings and none is a loopback URL.
func factoryBaseURLsExcludeLoopback(d vendorPolicyDoc) bool {
	v, ok := d.member("managedSettings", "modelPolicy", "allowedBaseUrls")
	if !ok {
		return false
	}
	var list []string
	if json.Unmarshal(v, &list) != nil || len(list) == 0 {
		return false
	}
	for _, u := range list {
		if isLoopbackURL(u) {
			return false
		}
	}
	return true
}

// nonLoopbackURL reports whether raw is a JSON string holding a non-empty
// URL whose host is not loopback.
func nonLoopbackURL(raw json.RawMessage) bool {
	var s string
	if json.Unmarshal(raw, &s) != nil || strings.TrimSpace(s) == "" {
		return false
	}
	return !isLoopbackURL(s)
}

// isLoopbackURL reports whether s names a loopback host (localhost or a
// loopback address), the only place Observer's proxy listens.
func isLoopbackURL(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// clineRemoteConfigPrefix starts every cached Cline remote config file name
// (remote_config_<orgId>.json).
const clineRemoteConfigPrefix = "remote_config_"

// clineRemoteConfigFiles lists the cached remote configs under every VS Code
// product's globalStorage for the Cline extension.
func clineRemoteConfigFiles(home string, _ func(string) string) []string {
	var out []string
	for _, ref := range vscodehost.GlobalStorageDirs(crossmount.HomeRoot{Path: home, OS: runtime.GOOS}) {
		// A directory listing, never filepath.Glob: a profile path may hold a
		// glob metacharacter ("[" in a Windows user folder) that a pattern
		// would misread.
		dir := filepath.Join(ref.Path, "saoudrizwan.claude-dev", "cache")
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if name := e.Name(); strings.HasPrefix(name, clineRemoteConfigPrefix) && strings.HasSuffix(name, ".json") {
				out = append(out, filepath.Join(dir, name))
			}
		}
	}
	sort.Strings(out)
	return out
}

// factoryOrgCacheArtifact is the agentconfig FileRow of Factory's org cache.
const factoryOrgCacheArtifact = "droid/org-managed-settings-cache"

// factoryOrgCacheFiles resolves Factory's org cache through its FileRow.
func factoryOrgCacheFiles(home string, getenv func(string) string) []string {
	got, err := agentconfig.ResolveArtifact(factoryOrgCacheArtifact, agentconfig.PathEnv{GOOS: runtime.GOOS, Home: home, Getenv: getenv})
	if err != nil || got.Status != agentconfig.PathResolved || got.Path == "" {
		return []string{filepath.Join(home, ".factory", "org-managed-settings.cache.json")}
	}
	return []string{filepath.Clean(got.Path)}
}

// readVendorPolicyCache reads one cache file through the one capped
// regular-file reader (agentconfigsvc.ReadRegularFile, R-188 F7): a FIFO, a
// device or a directory at the path is refused without blocking, and so is
// a file over vendorPolicyMaxBytes. A symlink is followed only when it
// resolves inside the cache's own directory (vendorPolicyCacheTarget). ok is
// false when the file is absent, refused or unreadable.
var readVendorPolicyCache = func(path string) ([]byte, bool) {
	target, ok := vendorPolicyCacheTarget(path)
	if !ok {
		return nil, false
	}
	b, err := agentconfigsvc.ReadRegularFile(target, vendorPolicyMaxBytes)
	if err != nil {
		return nil, false
	}
	return b, true
}

// vendorPolicyCacheTarget returns the file a cache path names: the path
// itself, or, for a symlink, its resolved target when that lies inside the
// resolved cache directory. A link leaving the directory (to /dev/tty, a
// FIFO elsewhere, another tool's credentials) is refused.
func vendorPolicyCacheTarget(path string) (string, bool) {
	fi, err := os.Lstat(path) //nolint:gosec // a fixed vendor cache path from the table above
	if err != nil {
		return "", false
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		return path, true
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(dir, resolved)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return resolved, true
}

// VendorPolicyFindings walks the cache table under home: every rule that
// holds in a cache file present on this host, in table order. getenv reads
// the relocation variables (nil reads none).
func VendorPolicyFindings(home string, getenv func(string) string) []VendorPolicyFinding {
	if home == "" {
		return nil
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	var out []VendorPolicyFinding
	for _, c := range vendorPolicyCaches {
		for _, file := range c.files(home, getenv) {
			raw, ok := readVendorPolicyCache(file)
			if !ok || !credfile.IsObject(raw) {
				continue
			}
			doc := vendorPolicyDoc{raw: raw}
			for _, r := range c.rules {
				if r.holds(doc) {
					out = append(out, VendorPolicyFinding{
						Tool: c.tool, Rule: r.id, Kind: r.kind, File: file, Dir: filepath.Dir(file),
						Warn: r.warn, Message: r.message, Grounding: r.grounding,
					})
				}
			}
		}
	}
	return out
}

// checkVendorPolicyCaches is the doctor row: OK when no cached vendor org
// policy drops Observer's wiring, WARN naming each rule that does. A
// route-veto finding where Observer writes no route is detail on an OK row.
// Nothing here changes a file.
func checkVendorPolicyCaches(homeDir string, getenv func(string) string) Check {
	const name = "vendor.policy-caches"
	findings := VendorPolicyFindings(homeDir, getenv)
	if len(findings) == 0 {
		return Check{Name: name, Status: StatusOK, Message: "no cached vendor org policy (Cline remote config, Factory org settings) blocks Observer's MCP server or pins a tool's route"}
	}
	status := StatusOK
	var details []string
	for _, f := range findings {
		if f.Warn {
			status = StatusWarn
		}
		details = append(details, fmt.Sprintf("%s: %s [%s; %s]", f.Tool, f.Message, f.File, f.Grounding))
	}
	msg := fmt.Sprintf("cached vendor org policy read (%d finding(s)): nothing in it drops Observer's wiring", len(findings))
	if status == StatusWarn {
		msg = fmt.Sprintf("cached vendor org policy read (%d finding(s)): it blocks Observer's MCP server or pins a tool's route - see below; the organization that set it can change it", len(findings))
	}
	return Check{Name: name, Status: status, Message: msg, Details: details}
}
