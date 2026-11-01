package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// Claude Code managed policy (surface-gap arc CC-5, S-9 and the CC-6
// doctor half; docs/audits/surface-settings-precedence-gap-review-
// 2026-10-25.md). Claude Code reads its administrator policy from up to
// four sources, ranked (https://code.claude.com/docs/en/managed-settings,
// read 2026-10-25):
//
//  1. server-managed settings (the claude.ai console; not on the disk, so
//     not read here, and not fetched at all while ANTHROPIC_BASE_URL points
//     at the proxy, D-114);
//  2. MDM or OS policy: the com.anthropic.claudecode managed-preferences
//     plist on macOS, the `Settings` value under HKLM\SOFTWARE\Policies\
//     ClaudeCode on Windows;
//  3. the managed settings file plus its managed-settings.d/*.json drop-ins,
//     merged, in the system directory: /etc/claude-code (Linux and WSL),
//     /Library/Application Support/ClaudeCode (macOS), C:\Program Files\
//     ClaudeCode (Windows; the legacy C:\ProgramData path is not read);
//  4. the user-writable HKCU twin of the registry value, used only when no
//     administrator document is present above it.
//
// By default ("first-wins") the highest-ranked source with a policy key is
// the policy and the rest are ignored; managedSourcesBehavior "merge" in
// that source applies every administrator source. A policyHelper named by
// the selected source replaces the managed settings with its own output.
// managed-mcp.json in the same directory takes exclusive control of MCP.
//
// This file owns the paths (from the one agentconfig FileRow, never a copy)
// and the reading of the file channel; the OS sources live in
// claudepolicy_unix.go / _windows.go / _other.go. Findings is the doctor's
// table of what the policy does to Observer's own wiring. Nothing here
// writes, and nothing here stands Observer's registration down: the reader
// only reports.

// claudeManagedSettingsFileID is the agentconfig FileRow that owns the
// managed settings path per OS.
const claudeManagedSettingsFileID = "claude-code/managed-settings"

// ClaudeManagedPathSet is where Claude Code's file channel lives on one OS.
type ClaudeManagedPathSet struct {
	// Settings is managed-settings.json.
	Settings string
	// DropInDir is the managed-settings.d directory beside it.
	DropInDir string
	// MCP is managed-mcp.json beside it.
	MCP string
}

var claudeManagedRow = sync.OnceValue(func() agentconfig.FileRow {
	for _, f := range agentconfig.Files() {
		if f.ID == claudeManagedSettingsFileID {
			return f
		}
	}
	return agentconfig.FileRow{}
})

// ClaudeManagedPaths returns Claude Code's managed file paths for goos, from
// the agentconfig FileRow claude-code/managed-settings. goos is an explicit
// input so a test, or a reader for another OS's home, never depends on the
// host: "windows" yields the C:\Program Files\ClaudeCode paths with Windows
// separators on any host. A GOOS the row does not name (another unix) gets
// the Linux paths, which is where Claude Code reads on every non-macOS unix.
func ClaudeManagedPaths(goos string) ClaudeManagedPathSet {
	row := claudeManagedRow()
	p := row.Paths
	settings := p.Linux
	switch goos {
	case "darwin":
		settings = p.Darwin
	case "windows":
		settings = p.Windows
	}
	if settings == "" {
		return ClaudeManagedPathSet{}
	}
	dir, join := path.Dir(settings), path.Join
	if goos == "windows" {
		dir = settings[:max(strings.LastIndex(settings, `\`), 0)]
		join = func(elem ...string) string { return strings.Join(elem, `\`) }
	}
	return ClaudeManagedPathSet{
		Settings:  settings,
		DropInDir: join(dir, row.DropInDir),
		MCP:       join(dir, "managed-mcp.json"),
	}
}

// ClaudePolicySourceKind names one Claude Code managed source, ranked by
// claudePolicySourceRank.
type ClaudePolicySourceKind string

const (
	// ClaudeSourceMDM is the macOS managed-preferences plist or the Windows
	// HKLM registry value (one per OS).
	ClaudeSourceMDM ClaudePolicySourceKind = "mdm"
	// ClaudeSourceFile is managed-settings.json plus its drop-ins.
	ClaudeSourceFile ClaudePolicySourceKind = "file"
	// ClaudeSourceHKCU is the user-writable HKCU registry value (Windows).
	ClaudeSourceHKCU ClaudePolicySourceKind = "hkcu"
)

// claudePolicySourceRank is the ranking below server-managed settings.
var claudePolicySourceRank = []ClaudePolicySourceKind{ClaudeSourceMDM, ClaudeSourceFile, ClaudeSourceHKCU}

// ClaudeMCPRule is one allowedMcpServers / deniedMcpServers entry: exactly
// one of its fields is set.
type ClaudeMCPRule struct {
	ServerName    string   `json:"serverName,omitempty"`
	ServerCommand []string `json:"serverCommand,omitempty"`
	ServerURL     string   `json:"serverUrl,omitempty"`
}

// ClaudePolicyDoc is a managed settings document reduced to the keys
// Observer reasons about. The zero value is an empty document.
type ClaudePolicyDoc struct {
	// PolicyKeys reports a key other than the two control keys
	// (wslInheritsWindowsSettings, managedSourcesBehavior): only such a
	// document counts as delivering a policy.
	PolicyKeys bool
	// HasPolicyHelper / PolicyHelper: the policyHelper key and its path.
	HasPolicyHelper bool
	PolicyHelper    string
	// ManagedSourcesBehavior and ParentSettingsBehavior are the two
	// combining switches ("" when unset).
	ManagedSourcesBehavior string
	ParentSettingsBehavior string
	// AllowManagedMcpServersOnly is the MCP allowlist lock (nil = unset).
	AllowManagedMcpServersOnly *bool
	// AllowedSet reports an allowedMcpServers key; AllowedMcpServers its
	// entries (an empty list allows no server).
	AllowedSet        bool
	AllowedMcpServers []ClaudeMCPRule
	// DeniedMcpServers are the deniedMcpServers entries.
	DeniedMcpServers []ClaudeMCPRule
	// DisableAllHooks and AllowManagedHooksOnly are the two hook switches
	// (nil = unset). They are read here so the MDM (macOS plist, HKLM) and
	// HKCU channels are covered, not only the file the hookdisable table
	// names (surface-gap FU-36).
	DisableAllHooks       *bool
	AllowManagedHooksOnly *bool
	// ObserverHookEvents are the events whose managed hooks carry
	// Observer's own `hook claude-code <event>` command, sorted.
	ObserverHookEvents []string
}

// claudePolicyControlKeys are the keys that do not make a document a policy.
var claudePolicyControlKeys = map[string]bool{"wslInheritsWindowsSettings": true, "managedSourcesBehavior": true}

// ParseClaudePolicyDocument reads one managed settings JSON object. A
// document that is not a JSON object is an error (Claude Code refuses to
// start on one). An entry of a list it cannot decode is skipped, as Claude
// Code drops an invalid entry and keeps the rest.
func ParseClaudePolicyDocument(data []byte) (ClaudePolicyDoc, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return ClaudePolicyDoc{}, errors.New("not a JSON object")
	}
	var d ClaudePolicyDoc
	for k := range top {
		if !claudePolicyControlKeys[k] {
			d.PolicyKeys = true
			break
		}
	}
	if raw, ok := top["policyHelper"]; ok {
		d.HasPolicyHelper = true
		var h struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(raw, &h)
		d.PolicyHelper = h.Path
	}
	_ = json.Unmarshal(top["managedSourcesBehavior"], &d.ManagedSourcesBehavior)
	_ = json.Unmarshal(top["parentSettingsBehavior"], &d.ParentSettingsBehavior)
	if raw, ok := top["allowManagedMcpServersOnly"]; ok {
		var b bool
		if json.Unmarshal(raw, &b) == nil {
			d.AllowManagedMcpServersOnly = &b
		}
	}
	if raw, ok := top["allowedMcpServers"]; ok {
		d.AllowedSet = true
		d.AllowedMcpServers = decodeClaudeMCPRules(raw)
	}
	d.DeniedMcpServers = decodeClaudeMCPRules(top["deniedMcpServers"])
	d.DisableAllHooks = decodeClaudePolicyBool(top, "disableAllHooks")
	d.AllowManagedHooksOnly = decodeClaudePolicyBool(top, "allowManagedHooksOnly")
	d.ObserverHookEvents = claudeObserverHookEvents(top["hooks"])
	return d, nil
}

// decodeClaudePolicyBool reads a boolean key (nil when unset or not a
// boolean, which Claude Code ignores).
func decodeClaudePolicyBool(top map[string]json.RawMessage, key string) *bool {
	raw, ok := top[key]
	if !ok {
		return nil
	}
	var b bool
	if json.Unmarshal(raw, &b) != nil {
		return nil
	}
	return &b
}

// claudeObserverHookEvents returns the events of a managed hooks object
// whose command handlers run Observer's `hook claude-code <event>`.
func claudeObserverHookEvents(raw json.RawMessage) []string {
	var byEvent map[string][]struct {
		Hooks []struct {
			Type    string `json:"type"`
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &byEvent) != nil {
		return nil
	}
	var out []string
	for ev, groups := range byEvent {
		hit := false
		for _, g := range groups {
			for _, h := range g.Hooks {
				if h.Type == "command" && observerHookEventInvocation(h.Command, "claude-code", ev) {
					hit = true
				}
			}
		}
		if hit {
			out = append(out, ev)
		}
	}
	sort.Strings(out)
	return out
}

func decodeClaudeMCPRules(raw json.RawMessage) []ClaudeMCPRule {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil
	}
	out := []ClaudeMCPRule{}
	for _, it := range items {
		var r ClaudeMCPRule
		if json.Unmarshal(it, &r) == nil && (r.ServerName != "" || len(r.ServerCommand) > 0 || r.ServerURL != "") {
			out = append(out, r)
		}
	}
	return out
}

// mergeClaudePolicyDocs applies a later drop-in over an earlier document:
// single values are replaced, lists combine (managed-settings page, "Split
// a file-based policy across teams").
func mergeClaudePolicyDocs(base, over ClaudePolicyDoc) ClaudePolicyDoc {
	out := base
	out.PolicyKeys = base.PolicyKeys || over.PolicyKeys
	if over.HasPolicyHelper {
		out.HasPolicyHelper, out.PolicyHelper = true, over.PolicyHelper
	}
	if over.ManagedSourcesBehavior != "" {
		out.ManagedSourcesBehavior = over.ManagedSourcesBehavior
	}
	if over.ParentSettingsBehavior != "" {
		out.ParentSettingsBehavior = over.ParentSettingsBehavior
	}
	if over.AllowManagedMcpServersOnly != nil {
		out.AllowManagedMcpServersOnly = over.AllowManagedMcpServersOnly
	}
	if over.AllowedSet {
		out.AllowedSet = true
		out.AllowedMcpServers = append(append([]ClaudeMCPRule{}, base.AllowedMcpServers...), over.AllowedMcpServers...)
	}
	out.DeniedMcpServers = append(append([]ClaudeMCPRule(nil), base.DeniedMcpServers...), over.DeniedMcpServers...)
	if over.DisableAllHooks != nil {
		out.DisableAllHooks = over.DisableAllHooks
	}
	if over.AllowManagedHooksOnly != nil {
		out.AllowManagedHooksOnly = over.AllowManagedHooksOnly
	}
	if len(over.ObserverHookEvents) > 0 {
		seen := map[string]bool{}
		var evs []string
		for _, e := range append(append([]string(nil), base.ObserverHookEvents...), over.ObserverHookEvents...) {
			if !seen[e] {
				seen[e] = true
				evs = append(evs, e)
			}
		}
		sort.Strings(evs)
		out.ObserverHookEvents = evs
	}
	return out
}

// ClaudePolicySource is what one managed source holds.
type ClaudePolicySource struct {
	Kind ClaudePolicySourceKind
	// Location names it for a person (a path, a registry key).
	Location string
	// Found reports that the source exists (even when it cannot be read).
	Found bool
	// Problem is non-empty when it exists but cannot be used; it reads as
	// a clause after Location.
	Problem string
	// Doc is the parsed document (zero when Problem is set).
	Doc ClaudePolicyDoc
}

// admin reports an administrator source (HKCU is user-writable, not one).
func (s ClaudePolicySource) admin() bool { return s.Kind != ClaudeSourceHKCU }

// usable reports a found, parsed source.
func (s ClaudePolicySource) usable() bool { return s.Found && s.Problem == "" }

// ClaudeManagedMCP is what managed-mcp.json holds.
type ClaudeManagedMCP struct {
	Path    string
	Found   bool
	Problem string
	// Servers counts its servers; ObserverServer reports that one of them
	// runs Observer's MCP server (the per-node binary or the npx pin).
	Servers        int
	ObserverServer bool
}

// ClaudeManagedPolicy is every managed source this machine holds.
type ClaudeManagedPolicy struct {
	// Sources are the found sources, in rank order.
	Sources    []ClaudePolicySource
	ManagedMCP ClaudeManagedMCP
}

// Deployed reports that any managed source or managed-mcp.json exists.
func (p ClaudeManagedPolicy) Deployed() bool {
	return len(p.Sources) > 0 || p.ManagedMCP.Found
}

// claudePolicyMaxBytes caps one document read (a real one is a few KB).
const claudePolicyMaxBytes = 1 << 20

// ReadClaudeManagedFiles reads the file channel at paths: managed-
// settings.json merged with every managed-settings.d/*.json in name order
// (hidden files and other extensions skipped), and managed-mcp.json.
func ReadClaudeManagedFiles(paths ClaudeManagedPathSet) (ClaudePolicySource, ClaudeManagedMCP) {
	src := ClaudePolicySource{Kind: ClaudeSourceFile, Location: paths.Settings}
	var problems, dropIns []string
	baseFound, dirUnreadable := false, false
	readDoc := func(p string) {
		data, found, err := readClaudePolicyFile(p)
		if !found {
			return
		}
		src.Found = true
		if p == paths.Settings {
			baseFound = true
		} else {
			dropIns = append(dropIns, p)
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s %v", p, err))
			return
		}
		d, err := ParseClaudePolicyDocument(data)
		if err != nil {
			problems = append(problems, p+" is not a JSON object")
			return
		}
		src.Doc = mergeClaudePolicyDocs(src.Doc, d)
	}
	if paths.Settings != "" {
		readDoc(paths.Settings)
	}
	if paths.DropInDir != "" {
		entries, err := os.ReadDir(paths.DropInDir)
		switch {
		case err == nil:
			for _, e := range entries {
				n := e.Name()
				if strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".json") || e.IsDir() {
					continue
				}
				readDoc(filepath.Join(paths.DropInDir, n))
			}
		case !errors.Is(err, os.ErrNotExist):
			src.Found = true
			dirUnreadable = true
			problems = append(problems, paths.DropInDir+" could not be read")
		}
	}
	src.Location = claudeFileChannelLocation(paths, baseFound, dropIns, dirUnreadable)
	if len(problems) > 0 {
		src.Problem = strings.Join(problems, "; ")
		src.Doc = ClaudePolicyDoc{}
	}
	return src, readClaudeManagedMCP(paths.MCP)
}

// claudeFileChannelLocation names the file channel by what exists in it
// (FU-109, MAC-4): managed-settings.json when it is there, else the one
// drop-in, else the drop-in directory. A machine with only a
// managed-settings.d/ drop-in is never reported as the base file, which
// does not exist. With nothing found the base path stays the name.
func claudeFileChannelLocation(paths ClaudeManagedPathSet, baseFound bool, dropIns []string, dirUnreadable bool) string {
	switch {
	case baseFound:
		return paths.Settings
	case len(dropIns) == 1:
		return dropIns[0]
	case len(dropIns) > 1:
		return fmt.Sprintf("%s (%d drop-ins)", paths.DropInDir, len(dropIns))
	case dirUnreadable:
		return paths.DropInDir
	}
	return paths.Settings
}

func readClaudeManagedMCP(p string) ClaudeManagedMCP {
	m := ClaudeManagedMCP{Path: p}
	if p == "" {
		return m
	}
	data, found, err := readClaudePolicyFile(p)
	if !found {
		return m
	}
	m.Found = true
	if err != nil {
		m.Problem = err.Error()
		return m
	}
	var doc struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if json.Unmarshal(data, &doc) != nil {
		m.Problem = "is not a JSON object"
		return m
	}
	m.Servers = len(doc.MCPServers)
	for _, s := range doc.MCPServers {
		if claudeRunsObserverMCP(s.Command, s.Args) {
			m.ObserverServer = true
		}
	}
	return m
}

// claudeRunsObserverMCP reports a stdio server that starts Observer's MCP
// server: an observer binary running `serve`, or the npx pin of the
// @superbased/observer package (directly or through `cmd /c`).
func claudeRunsObserverMCP(command string, args []string) bool {
	argv := append([]string{command}, args...)
	for i, a := range argv {
		if isObserverBinaryToken(a) && i+1 < len(argv) && argv[i+1] == "serve" {
			return true
		}
		if strings.HasPrefix(a, "@superbased/observer") && i+1 < len(argv) && argv[i+1] == "serve" {
			return true
		}
	}
	return false
}

// readClaudePolicyFile reads a regular file of at most claudePolicyMaxBytes.
func readClaudePolicyFile(p string) (data []byte, found bool, err error) {
	fi, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, errors.New("could not be inspected")
	}
	if !fi.Mode().IsRegular() {
		return nil, true, errors.New("is not a regular file")
	}
	f, err := os.Open(p) //nolint:gosec // G304: a fixed managed-policy path.
	if err != nil {
		return nil, true, errors.New("could not be read")
	}
	defer func() { _ = f.Close() }()
	data, err = io.ReadAll(io.LimitReader(f, claudePolicyMaxBytes+1))
	if err != nil || len(data) > claudePolicyMaxBytes {
		return nil, true, errors.New("could not be read")
	}
	return data, true, nil
}

// claudePolicyReader reads this host's Claude Code managed policy. A test
// binary never reads the host's policy: tests replace the reader, and the
// default returns "no policy" so a developer box with one cannot change a
// test's outcome.
var claudePolicyReader = func() ClaudeManagedPolicy {
	if testing.Testing() {
		return ClaudeManagedPolicy{}
	}
	return readClaudeManagedPolicyHost()
}

// ReadClaudeManagedPolicy returns this host's Claude Code managed policy
// (the zero value when none is deployed).
func ReadClaudeManagedPolicy() ClaudeManagedPolicy { return claudePolicyReader() }

// readClaudeManagedPolicyHost assembles the OS sources (claudeOSPolicy,
// per-OS) and the file channel at this OS's paths, in rank order.
func readClaudeManagedPolicyHost() ClaudeManagedPolicy {
	mdm, hkcu, goos := claudeOSPolicy()
	file, mcp := ReadClaudeManagedFiles(ClaudeManagedPaths(goos))
	return assembleClaudePolicy(mcp, mdm, file, hkcu)
}

// assembleClaudePolicy keeps the found sources, in rank order.
func assembleClaudePolicy(mcp ClaudeManagedMCP, sources ...ClaudePolicySource) ClaudeManagedPolicy {
	p := ClaudeManagedPolicy{ManagedMCP: mcp}
	for _, k := range claudePolicySourceRank {
		for _, s := range sources {
			if s.Kind == k && s.Found {
				p.Sources = append(p.Sources, s)
			}
		}
	}
	return p
}

// ClaudeMCPEntry is Observer's user-scope MCP entry as the node wrote it
// (~/.claude.json mcpServers.<Name>).
type ClaudeMCPEntry struct {
	Name    string
	Command string
	Args    []string
}

func (e ClaudeMCPEntry) argv() []string { return append([]string{e.Command}, e.Args...) }

// ClaudePolicySeverity grades a finding.
type ClaudePolicySeverity int

const (
	// ClaudePolicyInfo is context: nothing of Observer's is lost.
	ClaudePolicyInfo ClaudePolicySeverity = iota
	// ClaudePolicyWarn means the policy drops or blocks part of Observer's
	// wiring.
	ClaudePolicyWarn
)

// ClaudePolicyFinding is one doctor row.
type ClaudePolicyFinding struct {
	ID       string
	Severity ClaudePolicySeverity
	Message  string
}

// claudePolicyView is the resolved policy one Findings pass reads.
type claudePolicyView struct {
	p ClaudeManagedPolicy
	// selected is the source Claude Code uses (nil when none delivers a
	// policy key); applied is selected, or every administrator source with
	// a policy key under managedSourcesBehavior "merge".
	selected *ClaudePolicySource
	applied  []ClaudePolicySource
	merge    bool
	observer *ClaudeMCPEntry
}

func newClaudePolicyView(p ClaudeManagedPolicy, observer *ClaudeMCPEntry) claudePolicyView {
	v := claudePolicyView{p: p, observer: observer}
	adminPresent := false
	for i := range p.Sources {
		s := &p.Sources[i]
		if s.admin() {
			adminPresent = true
		}
		if v.selected == nil && s.usable() && s.Doc.PolicyKeys && (s.admin() || !adminPresent) {
			v.selected = s
		}
	}
	if v.selected == nil {
		return v
	}
	// The behavior comes from the highest-ranked source carrying it or a
	// policy key; HKCU never merges with another source.
	for _, s := range p.Sources {
		if s.usable() && s.admin() && (s.Doc.PolicyKeys || s.Doc.ManagedSourcesBehavior != "") {
			v.merge = s.Doc.ManagedSourcesBehavior == "merge"
			break
		}
	}
	if !v.merge || !v.selected.admin() {
		v.applied = []ClaudePolicySource{*v.selected}
		return v
	}
	for _, s := range p.Sources {
		if s.usable() && s.admin() && s.Doc.PolicyKeys {
			v.applied = append(v.applied, s)
		}
	}
	return v
}

// allowlist returns the managed allowedMcpServers that applies and the
// source it comes from: with the allowManagedMcpServersOnly lock on (true
// in any administrator source), the highest-ranked administrator source
// that sets one; otherwise the highest-ranked applied source that sets one.
func (v claudePolicyView) allowlist() (rules []ClaudeMCPRule, from string, locked, ok bool) {
	pool := v.applied
	for _, s := range v.p.Sources {
		if s.usable() && s.admin() && s.Doc.AllowManagedMcpServersOnly != nil && *s.Doc.AllowManagedMcpServersOnly {
			locked = true
		}
	}
	if locked {
		pool = nil
		for _, s := range v.p.Sources {
			if s.usable() && s.admin() {
				pool = append(pool, s)
			}
		}
	}
	for _, s := range pool {
		if s.Doc.AllowedSet {
			return s.Doc.AllowedMcpServers, s.Location, locked, true
		}
	}
	return nil, "", locked, false
}

// claudeAllowlistAdmits applies Claude Code's stdio rule: once the list has
// a serverCommand entry, the server must match one exactly (every argument,
// in order); otherwise a serverName entry matching its label admits it.
func claudeAllowlistAdmits(rules []ClaudeMCPRule, e ClaudeMCPEntry) bool {
	hasCommand := false
	for _, r := range rules {
		if len(r.ServerCommand) > 0 {
			hasCommand = true
		}
	}
	for _, r := range rules {
		if hasCommand && stringSlicesMatch(r.ServerCommand, e.argv()) {
			return true
		}
		if !hasCommand && r.ServerName != "" && r.ServerName == e.Name {
			return true
		}
	}
	return false
}

// claudeDenylistBlocks reports a deniedMcpServers entry matching the server
// by name or by command; nothing overrides a denylist match.
func claudeDenylistBlocks(rules []ClaudeMCPRule, e ClaudeMCPEntry) bool {
	for _, r := range rules {
		if (r.ServerName != "" && r.ServerName == e.Name) || stringSlicesMatch(r.ServerCommand, e.argv()) {
			return true
		}
	}
	return false
}

func stringSlicesMatch(a, b []string) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// claudePolicyRules is the doctor's ordered rule table: each row reads the
// resolved view and returns its findings (zero or more). One test case per
// row pins it (claudepolicy_test.go).
var claudePolicyRules = []struct {
	id   string
	eval func(v claudePolicyView) []ClaudePolicyFinding
}{
	{"source-unusable", func(v claudePolicyView) []ClaudePolicyFinding {
		var out []ClaudePolicyFinding
		for _, s := range v.p.Sources {
			if s.Problem == "" {
				continue
			}
			if s.admin() {
				out = append(out, ClaudePolicyFinding{Severity: ClaudePolicyWarn, Message: fmt.Sprintf(
					"Claude Code managed policy %s: %s - Claude Code refuses to start on an administrator document it cannot parse", s.Location, s.Problem)})
			} else {
				out = append(out, ClaudePolicyFinding{Severity: ClaudePolicyInfo, Message: fmt.Sprintf(
					"Claude Code user policy %s: %s - Claude Code reports it and ignores it", s.Location, s.Problem)})
			}
		}
		return out
	}},
	{"sources-ignored", func(v claudePolicyView) []ClaudePolicyFinding {
		if v.selected == nil || v.merge {
			return nil
		}
		var ignored []string
		for _, s := range v.p.Sources {
			if s.Location != v.selected.Location && s.usable() && s.Doc.PolicyKeys {
				ignored = append(ignored, s.Location)
			}
		}
		if len(ignored) == 0 {
			return nil
		}
		return []ClaudePolicyFinding{{Severity: ClaudePolicyWarn, Message: fmt.Sprintf(
			"Claude Code applies its managed policy from %s and ignores %s (managedSourcesBehavior is first-wins): Observer settings deployed in an ignored source have no effect; merge them into %s, or set managedSourcesBehavior to \"merge\" there",
			v.selected.Location, strings.Join(ignored, ", "), v.selected.Location)}}
	}},
	{"sources-merge", func(v claudePolicyView) []ClaudePolicyFinding {
		if !v.merge || len(v.applied) < 2 {
			return nil
		}
		var names []string
		for _, s := range v.applied {
			names = append(names, s.Location)
		}
		return []ClaudePolicyFinding{{Severity: ClaudePolicyInfo, Message: fmt.Sprintf(
			"managedSourcesBehavior is \"merge\": Claude Code combines %s by kind of key (lists union, locks take the strictest value, allowlists come whole from the highest-ranked source)",
			strings.Join(names, ", "))}}
	}},
	{"policy-helper", func(v claudePolicyView) []ClaudePolicyFinding {
		if v.selected == nil || !v.selected.Doc.HasPolicyHelper {
			return nil
		}
		helper := v.selected.Doc.PolicyHelper
		if helper == "" {
			helper = "no path given"
		}
		return []ClaudePolicyFinding{{Severity: ClaudePolicyWarn, Message: fmt.Sprintf(
			"%s names a policyHelper (%s): when the helper emits managedSettings, that output is the only managed settings for the session, so an Observer route, env or hook entry in any managed source is dropped unless the helper emits it too",
			v.selected.Location, helper)}}
	}},
	{"parent-settings-merge", func(v claudePolicyView) []ClaudePolicyFinding {
		for _, s := range v.applied {
			if s.Doc.ParentSettingsBehavior == "merge" {
				return []ClaudePolicyFinding{{Severity: ClaudePolicyInfo, Message: fmt.Sprintf(
					"%s sets parentSettingsBehavior to \"merge\": a host that embeds Claude Code (an Agent SDK app, an IDE extension) adds its own restrictive settings; such a host can also pass strictMcpConfig or replace the environment, which no file on this machine shows",
					s.Location)}}
			}
		}
		return nil
	}},
	{"managed-mcp-exclusive", func(v claudePolicyView) []ClaudePolicyFinding {
		m := v.p.ManagedMCP
		switch {
		case !m.Found:
			return nil
		case m.Problem != "":
			return []ClaudePolicyFinding{{Severity: ClaudePolicyWarn, Message: fmt.Sprintf(
				"%s %s: Claude Code reports the enterprise MCP config as failed and loads none of its servers", m.Path, m.Problem)}}
		case m.ObserverServer:
			return []ClaudePolicyFinding{{Severity: ClaudePolicyInfo, Message: fmt.Sprintf(
				"%s carries Observer's MCP server and takes exclusive control: developers cannot add, change or use any other MCP server (including plugin servers and --mcp-config)", m.Path)}}
		}
		return []ClaudePolicyFinding{{Severity: ClaudePolicyWarn, Message: fmt.Sprintf(
			"%s takes exclusive MCP control and does not carry Observer's server: the user-scope MCP entry Observer registered does not load; remove the file, or add Observer's server to it",
			m.Path)}}
	}},
	{"mcp-allowlist", func(v claudePolicyView) []ClaudePolicyFinding {
		if v.observer == nil {
			return nil
		}
		rules, from, locked, ok := v.allowlist()
		if !ok || claudeAllowlistAdmits(rules, *v.observer) {
			return nil
		}
		entry, _ := json.Marshal(ClaudeMCPRule{ServerCommand: v.observer.argv()})
		tail := "it does not load unless an allowedMcpServers in your own settings admits it"
		if locked {
			tail = "allowManagedMcpServersOnly locks the list to managed settings, so it does not load"
		}
		return []ClaudePolicyFinding{{Severity: ClaudePolicyWarn, Message: fmt.Sprintf(
			"the managed allowedMcpServers in %s does not admit Observer's MCP server (%s): %s; add the entry %s to that list",
			from, strings.Join(v.observer.argv(), " "), tail, entry)}}
	}},
	{"hooks-disabled", func(v claudePolicyView) []ClaudePolicyFinding {
		for _, s := range v.applied {
			if s.Doc.DisableAllHooks != nil && *s.Doc.DisableAllHooks {
				return []ClaudePolicyFinding{{Severity: ClaudePolicyWarn, Message: fmt.Sprintf(
					"%s sets disableAllHooks: Claude Code runs no hook, Observer's included, so the hook gates and the hook budget stop do not act on this machine",
					s.Location)}}
			}
		}
		return nil
	}},
	{"managed-hooks-only", func(v claudePolicyView) []ClaudePolicyFinding {
		for _, s := range v.applied {
			if s.Doc.AllowManagedHooksOnly == nil || !*s.Doc.AllowManagedHooksOnly {
				continue
			}
			if missing := claudeEventsMissing(s.Doc.ObserverHookEvents); len(missing) > 0 {
				return []ClaudePolicyFinding{{Severity: ClaudePolicyWarn, Message: fmt.Sprintf(
					"%s sets allowManagedHooksOnly: Claude Code skips the user-level hooks Observer registers in %s, and the managed settings do not carry Observer's hook for %s",
					s.Location, claudeUserSettingsLabel(), strings.Join(missing, ", "))}}
			}
			return []ClaudePolicyFinding{{Severity: ClaudePolicyInfo, Message: fmt.Sprintf(
				"%s sets allowManagedHooksOnly and carries Observer's hooks as managed hooks: the user-level copies are skipped", s.Location)}}
		}
		return nil
	}},
	{"mcp-denylist", func(v claudePolicyView) []ClaudePolicyFinding {
		if v.observer == nil {
			return nil
		}
		for _, s := range v.applied {
			if claudeDenylistBlocks(s.Doc.DeniedMcpServers, *v.observer) {
				return []ClaudePolicyFinding{{Severity: ClaudePolicyWarn, Message: fmt.Sprintf(
					"deniedMcpServers in %s blocks Observer's MCP server (%s): nothing overrides a denylist match", s.Location, strings.Join(v.observer.argv(), " "))}}
			}
		}
		return nil
	}},
}

// claudeUserSettingsFileID is the agentconfig artifact of Claude Code's
// user settings file, where Observer registers its hooks.
const claudeUserSettingsFileID = "claude-code/user-settings"

// claudeUserSettingsLabel names Claude Code's user settings file for a
// doctor message, home-relative ("~/..."), from its agentconfig artifact (the
// one owner of the path), so no literal path is spelled here.
func claudeUserSettingsLabel() string {
	got, err := agentconfig.ResolveArtifact(claudeUserSettingsFileID, agentconfig.PathEnv{GOOS: "linux", Home: "~"})
	if err != nil || got.Path == "" {
		return "Claude Code's user settings file"
	}
	return filepath.ToSlash(got.Path)
}

// claudeEventsMissing returns the Claude Code events Observer registers
// that covered does not carry, in registration order.
func claudeEventsMissing(covered []string) []string {
	have := map[string]bool{}
	for _, e := range covered {
		have[e] = true
	}
	var out []string
	for _, e := range claudeCodeEvents {
		if !have[e] {
			out = append(out, e)
		}
	}
	return out
}

// Findings returns what the policy does to Observer's Claude Code wiring,
// in rule order. observer is Observer's user-scope MCP entry (nil when this
// node has none registered, which skips the MCP list rows).
func (p ClaudeManagedPolicy) Findings(observer *ClaudeMCPEntry) []ClaudePolicyFinding {
	v := newClaudePolicyView(p, observer)
	var out []ClaudePolicyFinding
	for _, r := range claudePolicyRules {
		for _, f := range r.eval(v) {
			f.ID = r.id
			out = append(out, f)
		}
	}
	return out
}
