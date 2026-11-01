package sectrust

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/tailscale/hujson"
	"gopkg.in/yaml.v3"

	"github.com/marmutapp/superbased-observer/internal/hookdisable"
)

// decode parses JSON (with comments), TOML or YAML into a generic value,
// choosing the syntax from the file name. Markdown has no structure to
// judge and decodes to nil.
func decode(rel string, data []byte) (any, error) {
	lower := strings.ToLower(rel)
	var v any
	switch {
	case strings.HasSuffix(lower, ".toml"):
		var m map[string]any
		if _, err := toml.Decode(string(data), &m); err != nil {
			return nil, err
		}
		v = m
	case strings.HasSuffix(lower, ".yml"), strings.HasSuffix(lower, ".yaml"):
		if err := yaml.Unmarshal(data, &v); err != nil {
			return nil, err
		}
	case strings.HasSuffix(lower, ".md"), strings.HasSuffix(lower, ".mdc"):
		return nil, nil
	default:
		std, err := hujson.Standardize(data)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(std, &v); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// leaf is one flattened key path and its scalar value.
type leaf struct {
	raw   []string // the key segments as written
	lower []string // the same, lower-cased
	val   any
}

func (l leaf) has(seg string) bool {
	for _, p := range l.lower {
		if p == seg {
			return true
		}
	}
	return false
}

func (l leaf) last() string { return l.lower[len(l.lower)-1] }

func (l leaf) str() string {
	s, _ := l.val.(string)
	return s
}

func (l leaf) key() string { return strings.Join(l.raw, ".") }

// dotted is the lower-cased key path joined with dots; VS Code writes
// dotted keys flat ("chat.tools.autoApprove"), so a dotted comparison
// matches both spellings.
func (l leaf) dotted() string { return strings.Join(l.lower, ".") }

// flatten turns a decoded tree into leaves, at most maxLeaves.
func flatten(v any, raw []string, out *[]leaf) {
	if len(*out) >= maxLeaves {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			flatten(t[k], append(append([]string(nil), raw...), k), out)
		}
	case []any:
		for i, x := range t {
			flatten(x, append(append([]string(nil), raw...), fmt.Sprint(i)), out)
		}
	default:
		if len(raw) == 0 {
			return
		}
		lower := make([]string, len(raw))
		for i, s := range raw {
			lower[i] = strings.ToLower(s)
		}
		*out = append(*out, leaf{raw: raw, lower: lower, val: v})
	}
}

// mcpContainers are the keys that hold a map of MCP servers. Those marked
// rootOnly count only at the top of the file ("servers" and "mcp" are
// common words elsewhere).
var mcpContainers = []struct {
	key      string
	rootOnly bool
}{
	{"mcpservers", false},
	{"mcp_servers", false},
	{"context_servers", false},
	{"servers", true},
	{"mcp", true},
}

// mcpContainerAt reports whether segment i of a lower-cased path is an MCP
// container.
func mcpContainerAt(lower []string, i int) bool {
	for _, c := range mcpContainers {
		if lower[i] == c.key && (!c.rootOnly || i == 0) {
			return true
		}
	}
	return false
}

// inMCP reports whether a leaf sits inside an MCP server entry, whose env
// and URL keys are the server's own (judged by the MCP rows, not as the
// agent's).
func (l leaf) inMCP() bool {
	for i := range l.lower {
		if mcpContainerAt(l.lower, i) {
			return true
		}
	}
	return false
}

// structured judges one settings, MCP, hooks or permissions file. tableRel
// is the path-table row it was read for (matched against the hookdisable
// switches, whose project rows are root-relative).
func (c *checker) structured(file, tableRel string, data []byte) {
	v, err := decode(file, data)
	if err != nil {
		c.parseError(file, data, err)
		return
	}
	if v == nil {
		return
	}
	var leaves []leaf
	flatten(v, nil, &leaves)
	c.hookSwitches(file, tableRel, leaves)
	c.mcpServers(file, v)
	hookFile := strings.Contains(strings.ToLower(tableRel), "hooks")
	for _, l := range leaves {
		if envContainer(l) {
			if !l.inMCP() {
				c.envVar(file, l.key(), l.raw[len(l.raw)-1], l.str(), true)
			}
			continue
		}
		c.commandLeaf(file, l, hookFile)
		for _, r := range leafRules {
			if r.match(l) {
				c.add(Reason{Code: r.code, File: file, Key: l.key(), Excerpt: excerpt(fmt.Sprint(l.val)), value: fmt.Sprint(l.val)})
				break
			}
		}
	}
}

// hookSwitches applies the project rows of the shipped hookdisable table.
func (c *checker) hookSwitches(file, tableRel string, leaves []leaf) {
	for _, s := range hookdisable.Switches {
		if s.Scope != hookdisable.ScopeProject || s.ProjectRel != tableRel || s.WriteGuardOnly {
			continue // a write-guard-only row turns nothing off (hookdisable.Switch.WriteGuardOnly)
		}
		want := strings.ToLower(s.Key)
		for _, l := range leaves {
			if b, ok := l.val.(bool); ok && b == s.Off && l.dotted() == want {
				c.add(Reason{Code: "hooks_off_switch", File: file, Key: l.key(), Excerpt: fmt.Sprint(l.val), value: fmt.Sprint(l.val)})
			}
		}
	}
}

// commandKeys are the leaf names that hold a command a hook runs.
var commandKeys = map[string]bool{"command": true, "bash": true, "powershell": true, "cmd": true, "script": true}

// credentialHelpers run a command to produce a credential.
var credentialHelpers = map[string]bool{"apikeyhelper": true, "awscredentialexport": true, "awsauthrefresh": true, "otelheadershelper": true}

// commandLeaf raises the repository-run command reasons a leaf can carry
// (hooks, the status line, credential helpers). MCP servers are judged per
// server entry by mcpServers.
func (c *checker) commandLeaf(file string, l leaf, hookFile bool) {
	s := strings.TrimSpace(l.str())
	if s == "" || l.inMCP() {
		return
	}
	k := l.last()
	switch {
	case l.has("statusline") && commandKeys[k]:
		c.addRun("statusline_command", file, l.key(), s, true)
	case (l.has("hooks") || hookFile) && commandKeys[k]:
		c.addRun("hook_command", file, l.key(), s, true)
	case credentialHelpers[k]:
		c.addRun("credential_helper_command", file, l.key(), s, true)
	}
}

// leafRule is one key rule over a flattened leaf; the first matching row
// raises its code.
type leafRule struct {
	code  string
	match func(l leaf) bool
}

// leafRules is the ordered key-rule table for structured files.
var leafRules = []leafRule{
	{"base_url_override", func(l leaf) bool {
		return reBaseURLKey.MatchString(l.last()) && !l.inMCP() && remoteURL(l.str())
	}},
	{"auto_approve", bypass},
	{"trust_disabled", func(l leaf) bool {
		d := l.dotted()
		return (d == "security.foldertrust.enabled" || d == "folder_trust.enabled") && l.val == false
	}},
	{"trust_self_grant", func(l leaf) bool {
		return l.last() == "trust_level" && strings.EqualFold(l.str(), "trusted")
	}},
}

// bypassRow is one auto-approve or permission-bypass switch: a key match
// and the value that turns approvals off.
type bypassRow struct {
	key   func(l leaf) bool
	value func(l leaf) bool
}

func dottedIs(names ...string) func(leaf) bool {
	return func(l leaf) bool {
		d := l.dotted()
		for _, n := range names {
			if d == n {
				return true
			}
		}
		return false
	}
}

func lastIs(names ...string) func(leaf) bool {
	return func(l leaf) bool {
		for _, n := range names {
			if l.last() == n {
				return true
			}
		}
		return false
	}
}

func isTrue(l leaf) bool { b, ok := l.val.(bool); return ok && b }

func strIs(vals ...string) func(leaf) bool {
	return func(l leaf) bool {
		s := strings.ToLower(l.str())
		for _, v := range vals {
			if s == v {
				return true
			}
		}
		return false
	}
}

// bypassTable is the auto-approve key table (JSP-7 reason auto_approve).
var bypassTable = []bypassRow{
	{dottedIs("chat.tools.autoapprove", "chat.tools.global.autoapprove"), isTrue},
	{func(l leaf) bool { return strings.HasSuffix(l.dotted(), "defaultmode") }, strIs("bypasspermissions")},
	{dottedIs("enableallprojectmcpservers"), isTrue},
	{lastIs("approval_policy", "approval-policy", "ask_for_approval"), strIs("never")},
	{lastIs("sandbox_mode"), strIs("danger-full-access")},
	{lastIs("autoaccept", "yolo", "yes-always", "yes_always", "dangerouslyskippermissions", "dangerously-skip-permissions", "trustalltools"), isTrue},
	{lastIs("defaultapprovalmode"), strIs("yolo")},
	{func(l leaf) bool { return l.has("allow") }, strIs("*", "shell(*)", "bash", "bash(*)")},
}

// bypass reports whether a leaf turns approvals off.
func bypass(l leaf) bool {
	for _, r := range bypassTable {
		if r.key(l) && r.value(l) {
			return true
		}
	}
	return false
}

// envContainer reports whether a leaf is a variable inside an environment
// block: a map named env or environment, or VS Code's
// terminal.integrated.env.<os>.
func envContainer(l leaf) bool {
	if len(l.lower) < 2 {
		return false
	}
	parent := strings.Join(l.lower[:len(l.lower)-1], ".")
	if p := l.lower[len(l.lower)-2]; p == "env" || p == "environment" {
		return true
	}
	switch parent {
	case "terminal.integrated.env.linux", "terminal.integrated.env.osx", "terminal.integrated.env.windows":
		return true
	}
	return false
}

// mcpServers walks the decoded tree for MCP server maps and judges each
// server once: a stdio server is a repository-run command, a URL server is
// information (https to a host name, or loopback) or flagged (anything
// else).
func (c *checker) mcpServers(file string, v any) {
	var walk func(v any, raw []string)
	walk = func(v any, raw []string) {
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			path := append(append([]string(nil), raw...), k)
			lower := strings.ToLower(k)
			isContainer := false
			for _, ct := range mcpContainers {
				if lower == ct.key && (!ct.rootOnly || len(raw) == 0) {
					isContainer = true
				}
			}
			if !isContainer {
				walk(m[k], path)
				continue
			}
			servers, ok := m[k].(map[string]any)
			if !ok {
				continue
			}
			names := make([]string, 0, len(servers))
			for n := range servers {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if srv, ok := servers[n].(map[string]any); ok {
					c.mcpServer(file, strings.Join(append(path, n), "."), srv)
				}
			}
		}
	}
	walk(v, nil)
}

// mcpServer judges one MCP server entry.
func (c *checker) mcpServer(file, key string, srv map[string]any) {
	if cmd := mcpCommand(srv); cmd != "" {
		c.addRun("mcp_server_command", file, key, cmd, true)
		return
	}
	for _, k := range []string{"url", "httpUrl", "serverUrl", "uri"} {
		if u, ok := srv[k].(string); ok && u != "" {
			code := "mcp_server_url"
			if !safeServerURL(u) {
				code = "mcp_server_url_insecure"
			}
			c.add(Reason{Code: code, File: file, Key: key, Excerpt: excerpt(redactURL(u)), value: u})
			return
		}
	}
}

// mcpCommand renders a stdio server's launch command (command, args and
// env, in a fixed order) as the content its digest covers; "" when the
// entry is not a stdio server. command may be a string, an argv array or a
// {path, args} map (Zed).
func mcpCommand(srv map[string]any) string {
	var parts []string
	switch cmd := srv["command"].(type) {
	case string:
		parts = append(parts, cmd)
	case []any:
		for _, a := range cmd {
			parts = append(parts, fmt.Sprint(a))
		}
	case map[string]any:
		if p, ok := cmd["path"].(string); ok {
			parts = append(parts, p)
		}
		if args, ok := cmd["args"].([]any); ok {
			for _, a := range args {
				parts = append(parts, fmt.Sprint(a))
			}
		}
	}
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return ""
	}
	if args, ok := srv["args"].([]any); ok {
		for _, a := range args {
			parts = append(parts, fmt.Sprint(a))
		}
	}
	for _, envKey := range []string{"env", "environment"} {
		if env, ok := srv[envKey].(map[string]any); ok {
			names := make([]string, 0, len(env))
			for n := range env {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				parts = append(parts, n+"="+fmt.Sprint(env[n]))
			}
		}
	}
	return strings.Join(parts, " ")
}

// safeServerURL reports an MCP URL that is information only: https to a
// host name, or http(s) to loopback.
func safeServerURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if isLoopbackHost(host) {
		return u.Scheme == "http" || u.Scheme == "https"
	}
	_, isIP := parseIP(host)
	return u.Scheme == "https" && !isIP
}

// redactURL drops a URL's user information and query (both can carry
// credentials) before it becomes an excerpt.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// isLoopbackHost reports a loopback host name or address.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, ok := parseIP(host)
	return ok && (ip.IsLoopback() || ip.IsUnspecified())
}

// remoteURL reports a URL value that points somewhere other than loopback
// (Observer is the local base URL, so only a loopback override is benign).
func remoteURL(s string) bool {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return true
	}
	return !isLoopbackHost(u.Hostname())
}

// parseIP parses a host as an IP address (an IPv6 zone is dropped).
func parseIP(host string) (netip.Addr, bool) {
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip, err := netip.ParseAddr(host)
	return ip, err == nil
}
