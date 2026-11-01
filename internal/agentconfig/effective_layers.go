package agentconfig

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

// effective_layers.go turns files the I/O boundary has read into the
// evaluator's observations, runs every family, and maps each result onto a
// closed LayerFinding code (surface-gap Wave 4, lane w4-layers: CC-4, OBS-9,
// CLI-2, CLI-3, CLI-5, CLI-6, CLI-7, W-6, IDE-3, S-18, S-22). Pure: the
// boundary (internal/agentconfigsvc.EffectiveLayers) resolves the paths,
// refuses never-read files, decodes each file through its format engine and
// hands over the trees; nothing here opens a file. A value is never kept:
// each observation carries a coarse class from the family's closed set.

// DocumentKey is the Key of a family that observes a whole file (a first
// file wins family): the observation is the file's presence.
const DocumentKey = "*"

// The closed value classes the classifiers produce.
const (
	classLoopback   = "loopback"
	classVendorHost = "vendor_host"
	classOtherHost  = "other_host"
	classValue      = "value"
	classEmpty      = "empty"
	classUnset      = "unset"
	classSet        = "set" // present in a credential-bearing file, value not read

	classOn            = "on"
	classOff           = "off"
	classWithObserver  = "with_observer"
	classWithout       = "without_observer"
	classPresent       = "present"
	classRouted        = "routed"
	classUnverified    = "unverified"
	classOther         = "other"
	classAPIKey        = "api_key"
	classGoogleSignIn  = "google_sign_in"
	classVertex        = "vertex"
	observerModName    = "observer-guard"
	anthropicRouteVar  = "ANTHROPIC_BASE_URL"
	vscodeEnvNameKey   = "name"
	vscodeEnvValueKey  = "value"
	vtcodeCommandField = "command"
)

var (
	urlClasses       = []string{classLoopback, classVendorHost, classOtherHost, classValue, classEmpty, classSet}
	switchClasses    = []string{classOn, classOff}
	hookArrayClasses = []string{classWithObserver, classWithout, classEmpty}
	providerClasses  = []string{classRouted, classUnverified, classOther}
	authClasses      = []string{classAPIKey, classGoogleSignIn, classVertex, classOther}
)

// vendorHosts are the providers' own API hosts (a route at one of them is a
// direct connection, not a third-party endpoint).
var vendorHosts = map[string]bool{
	"api.anthropic.com":           true,
	"api.openai.com":              true,
	"dashscope.aliyuncs.com":      true,
	"dashscope-intl.aliyuncs.com": true,
}

// ClassifyContext holds what a classifier may need beyond the value.
type ClassifyContext struct {
	// OwnHookCommand reports whether a hook command is Observer's
	// (internal/hook.IsObserverHookCommand). Nil classifies no array as
	// holding Observer's entry.
	OwnHookCommand func(command string) bool
}

// classifier maps one value to the family's class; ok=false means the
// value is not one the tool reads (a wrong type), so the source does not
// set the key.
type classifier func(v any, cc ClassifyContext) (class string, ok bool)

// familyClassifiers is the classifier of every family, keyed by family id
// (a side table, so Family stays free of funcs). TestFamiliesWellFormed
// pins one per family.
var familyClassifiers = withPolicyKeyClassifiers(map[string]classifier{
	"claude-code/env":                           classifyURL,
	"claude-code/disableAllHooks":               classifyTrueOff,
	"qwen-code/disableAllHooks":                 classifyTrueOff,
	"gemini-cli/hooksConfig.enabled":            classifyFalseOff,
	"droid/hooksDisabled":                       classifyTrueOff,
	"codebuddy/disableAllHooks":                 classifyTrueOff,
	"command-code/mods.disableAll":              classifyTrueOff,
	"command-code/mods.disabled":                classifyListNames(observerModName),
	"qwen-code/model.baseUrl":                   classifyURL,
	"crush/providers.openai.base_url":           classifyURL,
	"opencode/provider.openai.options.baseURL":  classifyURL,
	"aider/openai-api-base":                     classifyURL,
	"crush/models.large.provider":               classifyProvider(map[string]string{"openai": classRouted}),
	"qwen-code/security.auth.selectedType":      classifyProvider(map[string]string{"openai": classRouted, "qwen-oauth": classUnverified}),
	"gemini-cli/security.auth.selectedType":     classifyGeminiAuth,
	"gemini-cli/security.auth.enforcedType":     classifyGeminiAuth,
	"vtcode/workspace.use_root_config":          classifyTrueOn,
	"vtcode/hooks.lifecycle.pre_tool_use":       classifyHookArray,
	"vtcode/hooks.lifecycle.user_prompt_submit": classifyHookArray,
	"stakpak/mcp":                               func(any, ClassifyContext) (string, bool) { return classPresent, true },
	"copilot/claudeCode.environmentVariables":   classifyVSCodeEnv(anthropicRouteVar),
})

// withPolicyKeyClassifiers adds classifyKeySet for every policy-key family
// (ibmBobPolicyFamilies), whose ids come from the catalogue.
func withPolicyKeyClassifiers(m map[string]classifier) map[string]classifier {
	for _, f := range ibmBobPolicyFamilies() {
		m[f.ID] = classifyKeySet
	}
	return m
}

// classifyKeySet classes any value as set: a policy-key family observes
// that a source sets the key, never what it sets.
func classifyKeySet(any, ClassifyContext) (string, bool) { return classSet, true }

// classifyURL classes a base URL.
func classifyURL(v any, _ ClassifyContext) (string, bool) {
	if _, ok := v.(KeyPresent); ok {
		return classSet, true
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return urlClass(s), true
}

func urlClass(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return classEmpty
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return classValue
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case host == "localhost" || strings.HasSuffix(host, ".localhost"):
		return classLoopback
	case vendorHosts[host]:
		return classVendorHost
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Unmap().IsLoopback() {
		return classLoopback
	}
	return classOtherHost
}

func classifyTrueOff(v any, _ ClassifyContext) (string, bool) {
	b, ok := v.(bool)
	if !ok {
		return "", false
	}
	if b {
		return classOff, true
	}
	return classOn, true
}

func classifyFalseOff(v any, _ ClassifyContext) (string, bool) {
	b, ok := v.(bool)
	if !ok {
		return "", false
	}
	if b {
		return classOn, true
	}
	return classOff, true
}

// classifyTrueOn classes a layer-drop switch: true is the switch set.
func classifyTrueOn(v any, _ ClassifyContext) (string, bool) {
	b, ok := v.(bool)
	if !ok {
		return "", false
	}
	if b {
		return classOn, true
	}
	return classOff, true
}

// classifyListNames: a list naming name is off, any other list on.
func classifyListNames(name string) classifier {
	return func(v any, _ ClassifyContext) (string, bool) {
		list, ok := v.([]any)
		if !ok {
			return "", false
		}
		for _, e := range list {
			if s, ok := e.(string); ok && strings.TrimSpace(s) == name {
				return classOff, true
			}
		}
		return classOn, true
	}
}

// classifyProvider maps a provider name onto routed / unverified / other.
func classifyProvider(known map[string]string) classifier {
	return func(v any, _ ClassifyContext) (string, bool) {
		s, ok := v.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return "", false
		}
		if c, ok := known[strings.ToLower(strings.TrimSpace(s))]; ok {
			return c, true
		}
		return classOther, true
	}
}

// classifyGeminiAuth maps Gemini CLI's AuthType values.
func classifyGeminiAuth(v any, _ ClassifyContext) (string, bool) {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", false
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "gemini-api-key", "use_gemini":
		return classAPIKey, true
	case "oauth-personal", "login_with_google", "cloud-shell", "compute-default-credentials":
		return classGoogleSignIn, true
	case "vertex-ai", "use_vertex_ai":
		return classVertex, true
	}
	return classOther, true
}

// classifyHookArray classes a hook-group array by whether a group carries
// one of Observer's commands.
func classifyHookArray(v any, cc ClassifyContext) (string, bool) {
	list, ok := v.([]any)
	if !ok {
		return "", false
	}
	if len(list) == 0 {
		return classEmpty, true
	}
	if cc.OwnHookCommand != nil && anyOwnCommand(list, cc.OwnHookCommand) {
		return classWithObserver, true
	}
	return classWithout, true
}

// anyOwnCommand walks groups and their hooks for an Observer command.
func anyOwnCommand(v any, own func(string) bool) bool {
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if anyOwnCommand(e, own) {
				return true
			}
		}
	case map[string]any:
		if c, ok := t[vtcodeCommandField].(string); ok && own(c) {
			return true
		}
		for k, e := range t {
			if k != vtcodeCommandField && anyOwnCommand(e, own) {
				return true
			}
		}
	}
	return false
}

// classifyVSCodeEnv classes the named variable in a VS Code
// [{name, value}] environment array; unset when the array lacks it.
func classifyVSCodeEnv(name string) classifier {
	return func(v any, _ ClassifyContext) (string, bool) {
		list, ok := v.([]any)
		if !ok {
			return "", false
		}
		for _, e := range list {
			m, ok := e.(map[string]any)
			if !ok || m[vscodeEnvNameKey] != name {
				continue
			}
			s, _ := m[vscodeEnvValueKey].(string)
			return urlClass(s), true
		}
		return classUnset, true
	}
}

// LayerFile is one catalogued file as the boundary read it. Tree is nil for
// a file that is absent, unreadable, never read or does not decode, which
// observes nothing. Inactive names why the tool skips a present file (an
// untrusted folder); "" is active.
type LayerFile struct {
	Row      FileRow
	Project  string
	Tree     map[string]any
	Inactive string
}

// RuntimeTree is one runtime source of one tool in the family key space
// (Claude Code's launch environment is {"env": {"ANTHROPIC_BASE_URL": ...}};
// opencode's OPENCODE_CONFIG_CONTENT is the decoded document).
type RuntimeTree struct {
	Tool  string
	Layer RuntimeLayer
	Tree  map[string]any
	// Project, when set, scopes the tree to one project's pass (a .env file
	// in the project directory); "" applies to every pass.
	Project string
}

// LayerInput is one evaluation pass: every file read (user, system and
// managed files once, project files once per project), the runtime trees,
// and the projects to evaluate.
type LayerInput struct {
	Files    []LayerFile
	Runtime  []RuntimeTree
	Projects []string
	Classify ClassifyContext
	// Families restricts the pass (nil: every family).
	Families []Family
}

// FindingCode is a closed LayerFinding code.
type FindingCode string

// The closed FindingCode vocabulary (layerFindingRules).
const (
	FindingProjectRouteOverride FindingCode = "project_route_override"
	FindingRouteShadowed        FindingCode = "route_shadowed"
	FindingIDERouteOverride     FindingCode = "ide_route_override"
	FindingProjectHooksDisabled FindingCode = "project_hooks_disabled"
	FindingHooksDisabled        FindingCode = "hooks_disabled"
	FindingHooksOffOverridden   FindingCode = "hooks_off_overridden"
	FindingHookArrayReplaced    FindingCode = "hook_array_replaced"
	FindingLayersDropped        FindingCode = "layers_dropped"
	FindingMCPFirstFileOnly     FindingCode = "mcp_first_file_only"
	FindingAuthPinsVendorHost   FindingCode = "auth_pins_vendor_host"
	FindingInactiveProvider     FindingCode = "inactive_provider"
	FindingProviderUnverified   FindingCode = "provider_unverified"
	FindingUserPolicyOverride   FindingCode = "user_policy_override"
)

// LayerFinding is one family result that matters to Observer.
type LayerFinding struct {
	Family  string
	Tool    string
	Concern Concern
	Code    FindingCode
	// Project is the project directory the finding holds in ("" for the
	// user level).
	Project string
	Key     KeyPath
	// Class is the effective class.
	Class    string
	Winning  SourceRef
	Shadowed []SourceRef
	Inactive []SourceRef
}

// RouteShadowed is a route finding in the shape the review names (CLI-2):
// the file (or runtime layer) whose value the tool uses instead of
// Observer's.
type RouteShadowed struct {
	Tool      string
	FileRowID string
	Runtime   RuntimeLayer
	Project   string
	Key       KeyPath
	Class     string
}

// ShadowedRoutes lists the route findings of fs as RouteShadowed.
func ShadowedRoutes(fs []LayerFinding) []RouteShadowed {
	var out []RouteShadowed
	for _, f := range fs {
		if f.Code != FindingProjectRouteOverride && f.Code != FindingRouteShadowed {
			continue
		}
		out = append(out, RouteShadowed{Tool: f.Tool, FileRowID: f.Winning.FileID, Runtime: f.Winning.Runtime, Project: f.Project, Key: f.Key, Class: f.Class})
	}
	return out
}

// findingInput is what a finding rule sees.
type findingInput struct {
	f           Family
	res         EffectiveResult
	shadowClass map[string]bool // classes of the shadowed sources
	winProject  bool            // the winner is a project-scope file
	userSet     bool            // a user-writable runtime layer sets the key (winning or shadowed)
}

// layerFindingRule is one row of the finding table.
type layerFindingRule struct {
	concern Concern
	match   func(in findingInput) bool
	code    FindingCode
}

// layerFindingRules is walked top-down per result; the first row of the
// result's concern that matches names the finding, and no match is no
// finding. One test case per row (TestLayerFindingRules).
var layerFindingRules = []layerFindingRule{
	{ConcernRoute, func(in findingInput) bool { return in.res.EffectiveClass != in.f.ObserverClass && in.winProject }, FindingProjectRouteOverride},
	{ConcernRoute, func(in findingInput) bool {
		return in.res.EffectiveClass != in.f.ObserverClass && in.shadowClass[in.f.ObserverClass]
	}, FindingRouteShadowed},
	{ConcernIDERoute, func(in findingInput) bool {
		return in.res.EffectiveClass != classUnset && in.res.EffectiveClass != in.f.ObserverClass
	}, FindingIDERouteOverride},
	{ConcernHooksOff, func(in findingInput) bool { return in.res.EffectiveClass == in.f.OffClass && in.winProject }, FindingProjectHooksDisabled},
	{ConcernHooksOff, func(in findingInput) bool { return in.res.EffectiveClass == in.f.OffClass }, FindingHooksDisabled},
	{ConcernHooksOff, func(in findingInput) bool { return in.shadowClass[in.f.OffClass] }, FindingHooksOffOverridden},
	{ConcernHookArray, func(in findingInput) bool {
		return in.res.EffectiveClass != in.f.ObserverClass && in.shadowClass[in.f.ObserverClass]
	}, FindingHookArrayReplaced},
	{ConcernLayerDrop, func(in findingInput) bool { return in.res.EffectiveClass == in.f.OffClass }, FindingLayersDropped},
	{ConcernMCP, func(in findingInput) bool { return len(in.res.Shadowed) > 0 }, FindingMCPFirstFileOnly},
	{ConcernAuth, func(in findingInput) bool { return in.res.EffectiveClass != in.f.ObserverClass }, FindingAuthPinsVendorHost},
	{ConcernProvider, func(in findingInput) bool { return in.res.EffectiveClass == classOther }, FindingInactiveProvider},
	{ConcernProvider, func(in findingInput) bool { return in.res.EffectiveClass == classUnverified }, FindingProviderUnverified},
	{ConcernUserPolicy, func(in findingInput) bool { return in.userSet }, FindingUserPolicyOverride},
}

// EvaluateLayers runs every family (or in.Families) over in: once at the
// user level (no project files) and once per project, keeping a project
// pass's finding only when a project file decides it, so a user-level
// finding is reported once. A layer-drop family that is set marks the
// dropped scopes inactive for the tool's other families in the same pass.
func EvaluateLayers(in LayerInput) ([]LayerFinding, error) {
	fams := in.Families
	if fams == nil {
		fams = effectiveFamilies
	}
	passes := append([]string{""}, uniqueProjects(in.Projects)...)
	var out []LayerFinding
	for _, p := range passes {
		files := passFiles(in.Files, p)
		pin := in
		pin.Runtime = passRuntime(in.Runtime, p)
		dropped, err := droppedScopes(fams, files, pin)
		if err != nil {
			return nil, err
		}
		for _, f := range fams {
			fs, err := evaluateFamily(f, files, pin, dropped[f.Tool], p)
			if err != nil {
				return nil, err
			}
			out = append(out, fs...)
		}
	}
	return out, nil
}

// passFiles keeps the non-project files and the project files of p.
func passFiles(all []LayerFile, p string) []LayerFile {
	var out []LayerFile
	for _, lf := range all {
		if isProjectScope(lf.Row.Scope) {
			if p == "" || lf.Project != p {
				continue
			}
		}
		out = append(out, lf)
	}
	return out
}

// passRuntime keeps the runtime trees of every pass and of p, p's first,
// so a project's own .env decides that project's pass.
func passRuntime(all []RuntimeTree, p string) []RuntimeTree {
	var own, shared []RuntimeTree
	for _, rt := range all {
		switch {
		case rt.Project == "":
			shared = append(shared, rt)
		case p != "" && rt.Project == p:
			own = append(own, rt)
		}
	}
	return append(own, shared...)
}

func isProjectScope(s Scope) bool { return s == ScopeProjectShared || s == ScopeProjectLocal }

func uniqueProjects(ps []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ps {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// dropRecord is a layer drop in force for a tool: the scopes and the family
// that dropped them.
type dropRecord struct {
	scopes map[Scope]bool
	reason string
}

// droppedScopes evaluates the layer-drop families of one pass.
func droppedScopes(fams []Family, files []LayerFile, in LayerInput) (map[string]dropRecord, error) {
	out := map[string]dropRecord{}
	for _, f := range fams {
		if f.Concern != ConcernLayerDrop {
			continue
		}
		res, err := Evaluate(f, observe(f, files, in.Runtime, in.Classify, dropRecord{}), nil)
		if err != nil {
			return nil, err
		}
		for _, r := range res {
			if r.EffectiveClass == f.OffClass {
				rec := dropRecord{scopes: map[Scope]bool{}, reason: f.ID}
				for _, s := range f.DropScopes {
					rec.scopes[s] = true
				}
				out[f.Tool] = rec
			}
		}
	}
	return out, nil
}

// evaluateFamily runs one family in one pass and maps its results.
func evaluateFamily(f Family, files []LayerFile, in LayerInput, drop dropRecord, project string) ([]LayerFinding, error) {
	if f.Concern == ConcernLayerDrop {
		drop = dropRecord{}
	}
	obs := observe(f, files, in.Runtime, in.Classify, drop)
	res, err := Evaluate(f, obs, nil)
	if err != nil {
		return nil, err
	}
	classOf := map[string]string{}
	for _, o := range obs {
		if o.Present {
			classOf[o.Source.String()+"|"+o.Key.String()] = o.Class
		}
	}
	rows := fileRowsByID()
	var out []LayerFinding
	for _, r := range res {
		if r.Reason == ReasonNoObservation {
			continue
		}
		winProject := (r.Winning.FileID != "" && isProjectScope(rows[r.Winning.FileID].Scope)) ||
			(r.Winning.Runtime != "" && projectRuntime(in.Runtime, f.Tool, r.Winning.Runtime, project))
		if project != "" && !winProject {
			continue
		}
		fi := findingInput{f: f, res: r, shadowClass: map[string]bool{}, winProject: winProject, userSet: userWritableLayers[r.Winning.Runtime]}
		for _, s := range r.Shadowed {
			fi.shadowClass[classOf[s.String()+"|"+r.Key.String()]] = true
			fi.userSet = fi.userSet || userWritableLayers[s.Runtime]
		}
		code, ok := findingCode(fi)
		if !ok {
			continue
		}
		out = append(out, LayerFinding{
			Family: f.ID, Tool: f.Tool, Concern: f.Concern, Code: code, Project: project,
			Key: r.Key, Class: r.EffectiveClass, Winning: r.Winning, Shadowed: r.Shadowed, Inactive: r.Inactive,
		})
	}
	return out, nil
}

// projectRuntime reports whether the tree observed for (tool, layer) in a
// pass is the project's own (passRuntime puts those first).
func projectRuntime(rts []RuntimeTree, tool string, layer RuntimeLayer, project string) bool {
	for _, rt := range rts {
		if rt.Tool == tool && rt.Layer == layer && rt.Tree != nil {
			return project != "" && rt.Project == project
		}
	}
	return false
}

// findingCode walks layerFindingRules.
func findingCode(in findingInput) (FindingCode, bool) {
	for _, r := range layerFindingRules {
		if r.concern == in.f.Concern && r.match(in) {
			return r.code, true
		}
	}
	return "", false
}

// observe builds one family's observations from a pass's files and the
// runtime trees. A file of another tool or shape is skipped; a dropped
// scope or an inactive file is observed inactive.
func observe(f Family, files []LayerFile, runtime []RuntimeTree, cc ClassifyContext, drop dropRecord) []Observation {
	cls := familyClassifiers[f.ID]
	if cls == nil {
		return nil
	}
	var out []Observation
	seen := map[string]bool{}
	for _, lf := range files {
		if lf.Row.Tool != f.Tool || lf.Row.Shape != f.Shape || lf.Tree == nil || seen[lf.Row.ID] {
			continue
		}
		seen[lf.Row.ID] = true
		inactive := lf.Inactive
		if inactive == "" && drop.scopes[lf.Row.Scope] {
			inactive = drop.reason
		}
		out = append(out, observeTree(f, SourceRef{FileID: lf.Row.ID}, lf.Tree, cls, cc, inactive)...)
	}
	layers := map[RuntimeLayer]bool{}
	for _, rt := range runtime {
		if rt.Tool != f.Tool || rt.Tree == nil || layers[rt.Layer] {
			continue
		}
		if _, ranked := f.RuntimeRanks[rt.Layer]; !ranked {
			continue
		}
		layers[rt.Layer] = true
		out = append(out, observeTree(f, SourceRef{Runtime: rt.Layer}, rt.Tree, cls, cc, "")...)
	}
	return out
}

// observeTree reads one source's tree at the family's key.
func observeTree(f Family, src SourceRef, tree map[string]any, cls classifier, cc ClassifyContext, inactive string) []Observation {
	mk := func(key KeyPath, v any, present bool) Observation {
		o := Observation{Source: src, Key: append(KeyPath(nil), key...), Active: inactive == "", InactiveReason: inactive}
		if present {
			if c, ok := cls(v, cc); ok {
				o.Present, o.Class = true, c
			}
		}
		return o
	}
	if len(f.Key) == 1 && f.Key[0] == DocumentKey {
		return []Observation{mk(f.Key, tree, true)}
	}
	v, ok := lookupTree(tree, f.Key)
	if !policies[f.Policy].exactKey {
		m, isMap := v.(map[string]any)
		if !ok || !isMap {
			return nil
		}
		names := f.Members
		if len(names) == 0 {
			for k := range m {
				names = append(names, k)
			}
			sort.Strings(names)
		}
		var out []Observation
		for _, n := range names {
			mv, has := m[n]
			if !has {
				continue
			}
			out = append(out, mk(append(append(KeyPath(nil), f.Key...), n), mv, true))
		}
		return out
	}
	return []Observation{mk(f.Key, v, ok)}
}

// String renders a finding for the doctor.
func (lf LayerFinding) String() string {
	where := ""
	if lf.Project != "" {
		where = " in project " + lf.Project
	}
	return fmt.Sprintf("%s %s: %s (%s from %s)%s", lf.Tool, lf.Key, lf.Code, lf.Class, lf.Winning, where)
}
