package guard

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Policy-file parsing + matcher compilation (guard spec §4.4): the
// declarative TOML rule format for user (~/.observer/guard-policy.toml)
// and project (<root>/.observer/guard-policy.toml) layers. Matcher
// vocabulary v1; CEL stays behind the Q1 v2 gate.
//
// Parsing is STRICT (unknown keys, unknown matcher fields, missing
// required fields, invalid regexes are all errors) — `observer guard
// lint` (G5) calls the same parser, and a policy file that parses
// here is a policy file that loads. The one asymmetry is the ORG
// layer's unknown keys: the LOADER ignores + notes them so a bundle
// from a newer server cannot disarm an older node's org floor (see
// parsePolicyFile), while Lint still reports them so the authoring/
// publish gate refuses a typo. Go's regexp is RE2: linear-time,
// no catastrophic backtracking class to lint for (a documented selling
// point vs PCRE-based competitors).

// Layer names (trust order is encoded in merge.go, not here).
const (
	layerUser    = "user"
	layerProject = "project"
	// layerTrustedProject is the dashboard-authored, daemon-local
	// per-project layer (guard-rule-management-ui plan §3): it lives
	// under ~/.observer (inside R-160's deny surface, so the agent
	// cannot write it) and therefore carries user-level weaken/disable
	// semantics scoped to one project root — the ONE layer allowed a
	// top-level `disable = [...]` key, and the ONE project-scoped layer
	// that may relax a decision (never below the org floor). Distinct
	// from layerProject, the in-repo, agent-writable, escalate-only file.
	layerTrustedProject = "trusted_project"
	// layerOrg is the org policy-bundle layer (spec §14.2, G13) — the
	// same TOML format as user/project files, delivered signed by the
	// org server and merged as the strictness floor.
	layerOrg = "org"
)

// policyFile is one parsed+compiled policy source.
type policyFile struct {
	layer     string
	rules     []policy.Rule
	overrides []rawOverride
	// notes are non-fatal parse notes: the TOML key paths this binary
	// did not understand and IGNORED. Only the org layer ever fills
	// this (user/project files stay strict — see parsePolicyFile).
	// File order, no de-duplication (the decoder reports each path
	// once).
	notes []string
	// disable is the top-level `disable = [...]` rule-ID list. It is
	// honored ONLY for the trusted-project layer (an unknown-key error
	// for every other layer, enforced in parsePolicyFile); the caller
	// unions it into the per-project engine's Config.Disabled.
	disable []string
}

// rawOverride is a parsed [[override]] entry, kept pre-merge so the
// §4.6 one-way checks can compare against the catalog before any
// engine sees it.
type rawOverride struct {
	RuleID   string
	Decision policy.Decision
	HasDec   bool
	Enforced bool
	// Overridable is the §14.2 org-granted override grant
	// (`overridable = true` on an [[override]] row). It is PARSED on
	// every layer so the key never trips the strict unknown-key check,
	// but only the ORG layer may act on it — merge.go drops it
	// elsewhere with a load issue, and `observer guard lint` reports
	// the same issue against a user/project file.
	Overridable bool
	Layer       string
}

// tomlPolicyFile is the on-disk shape.
type tomlPolicyFile struct {
	Rule     []tomlRule     `toml:"rule"`
	Override []tomlOverride `toml:"override"`
	// Disable is the optional top-level `disable = [...]` list. Decoded
	// for every layer so it never lands in the decoder's Undecoded set,
	// but parsePolicyFile REJECTS it for any layer except
	// trusted_project (the "disable is a config posture" split for the
	// user + in-repo-project layers is preserved as an unknown-key error).
	Disable []string `toml:"disable"`
}

// tomlRule is one [[rule]] entry (§4.4).
type tomlRule struct {
	ID        string       `toml:"id"`
	Category  string       `toml:"category"`
	Severity  string       `toml:"severity"`
	Decision  string       `toml:"decision"`
	Enforce   bool         `toml:"enforce"`
	AppliesTo []string     `toml:"applies_to"`
	Match     tomlMatchers `toml:"match"`
}

// tomlOverride is one [[override]] entry (§4.4).
type tomlOverride struct {
	Rule     string `toml:"rule"`
	Decision string `toml:"decision"`
	Enforce  bool   `toml:"enforce"`
	// Overridable is org-layer-only (see rawOverride.Overridable).
	Overridable bool `toml:"overridable"`
}

// tomlMatchers is the §4.4 matcher vocabulary v1. Fields are AND-ed.
// session_cost_usd_gt / repeat_count_gt match the G12 budget/anomaly
// stamps (Event.SessionCostUSD / Event.RepeatCount); like
// taint_source they imply no event kind on their own, so a rule using
// only them must set applies_to explicitly.
type tomlMatchers struct {
	PathGlob           []string `toml:"path_glob"`
	PathNot            []string `toml:"path_not"`
	PathOutsideProject bool     `toml:"path_outside_project"`
	PathSensitive      bool     `toml:"path_sensitive"`
	CommandRegex       string   `toml:"command_regex"`
	CommandBase        string   `toml:"command_base"`
	ArgContains        string   `toml:"arg_contains"`
	URLDomain          string   `toml:"url_domain"`
	MCPServer          string   `toml:"mcp_server"`
	MCPTool            string   `toml:"mcp_tool"`
	EventKind          []string `toml:"event_kind"`
	TaintSource        string   `toml:"taint_source"`
	Sink               string   `toml:"sink"`
	SessionCostUSDGt   float64  `toml:"session_cost_usd_gt"`
	RepeatCountGt      int      `toml:"repeat_count_gt"`
}

// validEventKinds is the user-facing event_kind vocabulary.
var validEventKinds = map[string]policy.EventKind{
	"tool_call":     policy.KindToolCall,
	"file_access":   policy.KindFileAccess,
	"shell_exec":    policy.KindShellExec,
	"mcp_call":      policy.KindMCPCall,
	"api_request":   policy.KindAPIRequest,
	"api_response":  policy.KindAPIResponse,
	"config_change": policy.KindConfigChange,
	"session_meta":  policy.KindSessionMeta,
}

// sink vocabulary v1 → (implied kinds, per-event condition). The
// condition composes with the rule's other matchers.
var validSinks = map[string]struct {
	kinds []policy.EventKind
	desc  string
}{
	"shell_exec":           {[]policy.EventKind{policy.KindShellExec}, "shell execution"},
	"git_push":             {[]policy.EventKind{policy.KindShellExec}, "git push"},
	"out_of_project_write": {[]policy.EventKind{policy.KindFileAccess, policy.KindConfigChange}, "out-of-project write"},
	"mcp_call":             {[]policy.EventKind{policy.KindMCPCall}, "MCP call"},
}

// Lint strictly checks one policy file the way loading would: the
// same parse + compile pass, PLUS a throwaway engine construction so
// override targets resolve (an [[override]] on an unknown rule ID is
// only detectable against the rule tables). layer is "user",
// "project", "trusted_project" or "org" — project and org files
// additionally get the §4.6 one-way merge pass so relaxation attempts
// surface as problems here instead of as silent load-time drops (the
// trusted_project layer is weaken-allowed, so its standalone merge pass
// only catches parse/compile problems — the real org-floor check is
// org-aware and lives in LintTrustedProject; org overrides are
// escalate-only: the bundle is a strictness floor, and the server's
// publish path lints with layer "org" so a relaxing bundle is caught
// BEFORE it is signed). Returns nil when the file is clean.
//
// `observer guard lint` (G5) and `observer-org policy publish` (G13)
// are the callers; a file that lints clean is a file that loads with
// zero LoadIssues.
//
// Lint is the AUTHORING half of a pair: AcceptOrgBundleTOML is the
// CONSUMER half a node runs over a bundle a possibly-NEWER server
// signed, and it alone tolerates unknown keys (GUARD-FWD-1 in
// docs/security.md). Both share lintParsed, so what counts as a FATAL
// problem is defined once.
func Lint(raw []byte, layer string) []string {
	pf, err := parsePolicyFile(raw, layer)
	if err != nil {
		return []string{err.Error()}
	}
	// Lint stays STRICT on every layer, including org — it is the
	// AUTHORING gate (see AcceptOrgBundleTOML for the consumer one).
	// Re-reporting the parse notes here, and short-circuiting on them,
	// keeps the publish gate byte-identical to the pre-tolerance
	// behaviour: the same wording, the same single-problem result, and
	// "fix the typo first" before any downstream problem it caused.
	if len(pf.notes) > 0 {
		return []string{unknownKeysProblem(pf.notes)}
	}
	return lintParsed(pf, layer)
}

// AcceptOrgBundleTOML is the CONSUMER gate for a signed org bundle:
// the check a NODE runs before it caches and loads one. It returns the
// FATAL problems only — everything Lint reports (syntax, bad rule ids,
// invalid decisions/severities/matchers, §4.6 floor violations, engine
// construction) EXCEPT the unknown-key report, which comes back as
// notes instead. Empty problems = accept; notes name the TOML key
// paths this binary did not understand and ignored.
//
// The asymmetry with Lint is deliberate and is the fix for GUARD-FWD-1
// (docs/security.md): tolerance belongs at CONSUMPTION, strictness at
// AUTHORING.
//
//   - AUTHORING (Lint, layer "org"): the SERVER defines the bundle
//     vocabulary, so an unknown key there is a typo — `overidable` —
//     and must be refused before the bundle is signed, stored and
//     shipped to a fleet. api.LintOrgBundle is that gate.
//   - CONSUMPTION (this function + parseOrgBundle): the node may be
//     running an OLDER binary than the server that signed the bundle,
//     so an unknown key is simply a key from the future. Refusing it
//     was fail-OPEN — the org layer is escalate-only, so dropping it
//     can only LOOSEN policy, and one new key would have silently
//     disarmed every older node's org guardrails.
//
// Both gates share lintParsed, so their fatal-problem sets cannot
// drift. Callers: internal/orgclient's fetch gate (before the cache is
// written) — the loader half is internal/guard/bundle.go, which
// surfaces the same notes on PolicyState.Notes.
func AcceptOrgBundleTOML(raw []byte) (problems, notes []string) {
	pf, err := parsePolicyFile(raw, layerOrg)
	if err != nil {
		return []string{err.Error()}, nil
	}
	return lintParsed(pf, layerOrg), pf.notes
}

// unknownKeysProblem is the one wording for an undecoded-key report,
// shared by the strict parse error and Lint so the two can never
// disagree about how an unknown key reads.
func unknownKeysProblem(keys []string) string {
	return fmt.Sprintf("unknown keys: %s", strings.Join(keys, ", "))
}

// lintParsed runs the post-parse half of the checks — the §4.6 merge
// pass for the layer plus a throwaway engine construction so override
// targets resolve — over an already-parsed file, and returns the FATAL
// problems. It is the ONE definition of "fatal" that Lint and
// AcceptOrgBundleTOML both call, which is what keeps the authoring and
// consumer gates from drifting apart. Returns nil when clean.
func lintParsed(pf *policyFile, layer string) []string {
	var problems []string
	var extra []policy.Rule
	var overrides []policy.Override
	switch layer {
	case layerProject:
		var mergeIssues []string
		extra, overrides, _, mergeIssues = mergeLayers(nil, nil, pf, nil)
		problems = append(problems, mergeIssues...)
	case layerTrustedProject:
		// The trusted layer's own merge pass: weakening/disable are
		// allowed, so a standalone lint (no org bundle in scope) surfaces
		// only parse/compile problems here. The REAL org-floor check runs
		// in LintTrustedProject (org-aware) and in the per-project engine
		// build — both feed the floor from the actual org bundle.
		var mergeIssues []string
		extra, overrides, _, mergeIssues = mergeLayers(nil, nil, nil, pf)
		problems = append(problems, mergeIssues...)
	case layerOrg:
		var mergeIssues []string
		extra, overrides, _, mergeIssues = mergeLayers(pf, nil, nil, nil)
		problems = append(problems, mergeIssues...)
	default:
		// The user layer has no relaxation check to fail in isolation
		// (its only one is against an org floor, which lint has no
		// bundle for), but it CAN carry an authoring mistake the merge
		// reports — an `overridable` key only the org may grant. Take
		// the issues so lint says what loading would record.
		var mergeIssues []string
		extra, overrides, _, mergeIssues = mergeLayers(nil, pf, nil, nil)
		problems = append(problems, mergeIssues...)
	}
	if _, err := policy.New(policy.Config{
		ExtraRules: extra,
		Overrides:  overrides,
	}); err != nil {
		problems = append(problems, err.Error())
	}
	return problems
}

// LintTrustedProject lints trusted per-project content EXACTLY as the
// per-project engine build loads it: the standard trusted-project
// parse+compile pass PLUS the real §4.6 org-floor check against the org
// bundle at the configured [guard.rules] org_bundle path (cfg + home
// resolve it exactly as guard.New does). A trusted relaxation of an
// org-floored rule is a load issue surfaced HERE, before the write —
// which the plain Lint(raw, "trusted_project") cannot see because it has
// no org context. When no org bundle is present the result equals
// Lint(raw, "trusted_project"): weakening/disabling built-ins is allowed
// on the trusted layer by design.
//
// It is the dashboard's save/validate gate for the trusted-project file;
// `observer guard lint` uses the pure Lint (no org context) for the CLI.
func LintTrustedProject(cfg config.GuardConfig, home string, raw []byte) []string {
	pf, err := parsePolicyFile(raw, layerTrustedProject)
	if err != nil {
		return []string{err.Error()}
	}
	var org *policyFile
	if p := OrgBundlePath(cfg, home); p != "" {
		org = loadVerifiedOrgLayer(os.ReadFile, p)
	}
	extra, overrides, _, issues := mergeLayers(org, nil, nil, pf)
	problems := append([]string{}, issues...)
	if _, perr := policy.New(policy.Config{
		ExtraRules: extra,
		Overrides:  overrides,
	}); perr != nil {
		problems = append(problems, perr.Error())
	}
	return problems
}

// parsePolicyFile parses + compiles one policy source. Strict: any
// problem is an error naming the offending entry.
//
// ONE deliberate exception, the org layer's forward-compatibility
// rule: an unknown key in a SIGNED org bundle is IGNORED and recorded
// on policyFile.notes instead of failing the parse. Strictness there
// was fail-OPEN in the worst way — bundle.go turns a parse error into
// "running without the org layer", so the first bundle using a key a
// newer server knows would silently disarm the org guard floor on
// every older node. User and project files stay strict: they are
// hand-edited locally, and a typo there must fail loudly. Lint
// re-reports pf.notes as a problem on EVERY layer, so this tolerance
// reaches only the two CONSUMER gates — AcceptOrgBundleTOML (the
// node's fetch gate) and parseOrgBundle (the loader) — and never an
// authoring surface.
func parsePolicyFile(raw []byte, layer string) (*policyFile, error) {
	var f tomlPolicyFile
	meta, err := toml.Decode(string(raw), &f)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	var ignored []string
	if undec := meta.Undecoded(); len(undec) > 0 {
		keys := make([]string, 0, len(undec))
		for _, k := range undec {
			keys = append(keys, k.String())
		}
		if layer != layerOrg {
			return nil, errors.New(unknownKeysProblem(keys))
		}
		ignored = keys
	}
	// `disable` is a trusted-project-only capability. For the user and
	// in-repo-project layers it stays an unknown-key error (the field is
	// decoded, so it would otherwise be silently accepted — this preserves
	// the strict "disable is a config posture, not a policy-file key"
	// split). The ORG layer gets the same tolerance as any other key this
	// binary does not honour there (GUARD-FWD-1): a signed bundle carrying
	// `disable` is accepted with the key IGNORED and noted, never rejected
	// — a rejection here would strand the node on a stale bundle (or, from
	// the on-disk cache, drop the whole org floor: fail-open).
	if meta.IsDefined("disable") && layer != layerTrustedProject {
		if layer != layerOrg {
			return nil, fmt.Errorf("unknown keys: disable")
		}
		ignored = append(ignored, "disable")
		f.Disable = nil
	}

	pf := &policyFile{layer: layer, notes: ignored, disable: f.Disable}
	seen := map[string]bool{}
	for i := range f.Rule {
		r, err := compileRule(&f.Rule[i], layer)
		if err != nil {
			return nil, fmt.Errorf("rule %d (%s): %w", i+1, f.Rule[i].ID, err)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("rule %d: duplicate id %q", i+1, r.ID)
		}
		seen[r.ID] = true
		pf.rules = append(pf.rules, r)
	}
	for i, ov := range f.Override {
		if ov.Rule == "" {
			return nil, fmt.Errorf("override %d: missing rule id", i+1)
		}
		ro := rawOverride{RuleID: ov.Rule, Enforced: ov.Enforce, Overridable: ov.Overridable, Layer: layer}
		if ov.Decision != "" {
			d, err := policy.ParseDecision(ov.Decision)
			if err != nil {
				return nil, fmt.Errorf("override %d (%s): %w", i+1, ov.Rule, err)
			}
			ro.Decision, ro.HasDec = d, true
		}
		pf.overrides = append(pf.overrides, ro)
	}
	return pf, nil
}

// PolicyRuleRefs structurally parses raw as a §4.4 policy file and returns
// the rule IDs it references: overrides = [[override]].rule targets (existing
// rule IDs whose decisions the file escalates), declared = [[rule]].id
// entries the file defines itself, disabled = the top-level `disable = [...]`
// list (meaningful only for a trusted-project file; a stray one elsewhere is
// still reported so the dry-run counts are honest — Lint is what rejects it).
// It powers the org dashboard's §14.2 dry-run statistics (G14) and the node
// dashboard's per-layer counts: override targets have server-side hit
// history, newly declared matchers do not. The parse is deliberately LOOSE —
// no matcher compilation, no unknown-key strictness — because every authoring
// surface runs Lint alongside it; a structurally unparseable file returns
// the parse error. Order follows file order; duplicates are preserved
// (Lint reports them).
func PolicyRuleRefs(raw []byte) (overrides, declared, disabled []string, err error) {
	var f tomlPolicyFile
	if _, err := toml.Decode(string(raw), &f); err != nil {
		return nil, nil, nil, fmt.Errorf("guard.PolicyRuleRefs: parse: %w", err)
	}
	for _, ov := range f.Override {
		if ov.Rule != "" {
			overrides = append(overrides, ov.Rule)
		}
	}
	for _, r := range f.Rule {
		if r.ID != "" {
			declared = append(declared, r.ID)
		}
	}
	for _, id := range f.Disable {
		if id != "" {
			disabled = append(disabled, id)
		}
	}
	return overrides, declared, disabled, nil
}

// compileRule turns one [[rule]] entry into a policy.Rule row.
func compileRule(tr *tomlRule, layer string) (policy.Rule, error) {
	var zero policy.Rule
	if tr.ID == "" {
		return zero, fmt.Errorf("missing id")
	}
	if policy.IsBuiltinRuleID(tr.ID) {
		return zero, fmt.Errorf("id collides with built-in rule %s — use [[override]] to tune built-ins", tr.ID)
	}
	if tr.Category == "" {
		return zero, fmt.Errorf("missing category (destructive|boundary|secrets|exfil|posture|mcp|taint|budget|anomaly)")
	}
	if tr.Decision == "" {
		return zero, fmt.Errorf("missing decision (allow|flag|ask|deny)")
	}
	dec, err := policy.ParseDecision(tr.Decision)
	if err != nil {
		return zero, err
	}
	sev := policy.SeverityWarn
	if tr.Severity != "" {
		if sev, err = policy.ParseSeverity(tr.Severity); err != nil {
			return zero, err
		}
	}
	cmdScoped, evScoped, kinds, safe, err := compileMatchers(&tr.Match)
	if err != nil {
		return zero, err
	}
	if cmdScoped == nil && evScoped == nil {
		return zero, fmt.Errorf("no matchers — the rule would never fire")
	}
	if cmdScoped != nil && evScoped != nil {
		return zero, fmt.Errorf("cannot mix command-scoped (command_regex/command_base/arg_contains) and event-scoped matchers in one rule — split into two rules")
	}

	// applies_to: explicit list wins; otherwise the matchers imply it.
	if len(tr.AppliesTo) > 0 {
		kinds = kinds[:0]
		for _, k := range tr.AppliesTo {
			ek, ok := validEventKinds[k]
			if !ok {
				return zero, fmt.Errorf("unknown applies_to kind %q", k)
			}
			kinds = append(kinds, ek)
		}
	}
	if len(kinds) == 0 {
		return zero, fmt.Errorf("cannot infer applies_to from the matchers — set applies_to explicitly")
	}

	// Observe = min(decision, flag): observe mode records, never
	// blocks/asks, unless the rule is per-rule-enforced (§4.1 — the
	// engine then picks the Enforce column regardless of mode).
	observe := dec
	if observe > policy.DecisionFlag {
		observe = policy.DecisionFlag
	}
	r := policy.Rule{
		ID:        tr.ID,
		Category:  policy.Category(tr.Category),
		Severity:  sev,
		AppliesTo: kinds,
		Observe:   observe,
		Enforce:   dec,
		SafePat:   safe,
		Doc:       layer + " rule " + tr.ID,
		Source:    layer,
		Enforced:  tr.Enforce,
	}
	r.Match = evScoped
	r.MatchCmd = cmdScoped
	return r, nil
}

// cmdCond / evCond are the per-condition closure shapes the compiled
// matchers AND-combine.
type (
	cmdCond = func(*policy.MatchContext, *policy.Command) (bool, string)
	evCond  = func(*policy.MatchContext) (bool, string)
)

// compileMatchers builds the matcher closures. Returns exactly one of
// (cmdScoped, evScoped) non-nil — except when the rule mixes both
// classes, in which case both are returned and the caller raises the
// mixed-matcher error with the rule's context. kinds are the implied
// event kinds; safe are the path_not exemptions.
func compileMatchers(m *tomlMatchers) (cmdScoped policy.MatchCmdFn, evScoped policy.MatchFn, kinds []policy.EventKind, safe []policy.SafeFn, err error) {
	cmdConds, err := compileCmdConds(m)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	evConds, kinds, err := compileEvConds(m)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// path_not compiles into safe patterns (exempts THIS rule only —
	// the engine's structural safe-pattern-first ordering applies).
	if len(m.PathNot) > 0 {
		nots := m.PathNot
		safe = append(safe, func(ctx *policy.MatchContext, _ *policy.Command) bool {
			if ctx.Path == "" {
				return false
			}
			_, ok := policy.MatchAnyPathGlob(nots, ctx.Path, ctx.Cfg.Home)
			return ok
		})
	}

	switch {
	case len(cmdConds) > 0 && len(evConds) > 0:
		return andCmd(cmdConds), andEv(evConds), kinds, safe, nil
	case len(cmdConds) > 0:
		return andCmd(cmdConds), nil, appendKinds(kinds, policy.KindShellExec), safe, nil
	case len(evConds) > 0:
		return nil, andEv(evConds), kinds, safe, nil
	default:
		return nil, nil, kinds, safe, nil
	}
}

// compileCmdConds builds the command-scoped condition list
// (command_regex / command_base / arg_contains).
func compileCmdConds(m *tomlMatchers) ([]cmdCond, error) {
	var conds []cmdCond
	if m.CommandRegex != "" {
		re, err := regexp.Compile(m.CommandRegex)
		if err != nil {
			return nil, fmt.Errorf("command_regex: %w", err)
		}
		pat := m.CommandRegex
		conds = append(conds, func(_ *policy.MatchContext, cmd *policy.Command) (bool, string) {
			if re.MatchString(cmd.Raw) {
				return true, "command matches " + pat
			}
			return false, ""
		})
	}
	if m.CommandBase != "" {
		base := strings.ToLower(m.CommandBase)
		conds = append(conds, func(_ *policy.MatchContext, cmd *policy.Command) (bool, string) {
			if cmd.Base == base {
				return true, "command " + cmd.Base
			}
			return false, ""
		})
	}
	if m.ArgContains != "" {
		needle := m.ArgContains
		conds = append(conds, func(_ *policy.MatchContext, cmd *policy.Command) (bool, string) {
			for i := 1; i < len(cmd.Argv); i++ {
				if strings.Contains(cmd.Argv[i], needle) {
					return true, "argument contains " + needle
				}
			}
			return false, ""
		})
	}
	return conds, nil
}

// compileEvConds builds the event-scoped condition list (path_*, url,
// mcp_*, taint_source, sink, event_kind) plus the kinds they imply.
func compileEvConds(m *tomlMatchers) (conds []evCond, kinds []policy.EventKind, err error) {
	addEv := func(f evCond, implied ...policy.EventKind) {
		conds = append(conds, f)
		kinds = appendKinds(kinds, implied...)
	}
	if len(m.PathGlob) > 0 {
		globs := m.PathGlob
		addEv(func(ctx *policy.MatchContext) (bool, string) {
			if ctx.Path == "" {
				return false, ""
			}
			if pat, ok := policy.MatchAnyPathGlob(globs, ctx.Path, ctx.Cfg.Home); ok {
				return true, "path matches " + pat
			}
			return false, ""
		}, policy.KindFileAccess, policy.KindConfigChange)
	}
	if m.PathOutsideProject {
		addEv(policy.OutsideProjectPath, policy.KindFileAccess, policy.KindConfigChange)
	}
	if m.PathSensitive {
		addEv(func(ctx *policy.MatchContext) (bool, string) {
			if desc, ok := policy.SensitiveResolvedPath(ctx.Path, ctx.Cfg.Home); ok {
				return true, desc
			}
			return false, ""
		}, policy.KindFileAccess, policy.KindConfigChange)
	}
	if m.URLDomain != "" {
		dom := strings.ToLower(m.URLDomain)
		addEv(func(ctx *policy.MatchContext) (bool, string) {
			if hostMatchesDomain(ctx.Event.Target, dom) {
				return true, "URL host under " + dom
			}
			return false, ""
		}, policy.KindToolCall, policy.KindAPIRequest)
	}
	if m.MCPServer != "" {
		server := m.MCPServer
		addEv(func(ctx *policy.MatchContext) (bool, string) {
			if policy.MCPServerFromTarget(ctx.Event.Target) == server {
				return true, "MCP server " + server
			}
			return false, ""
		}, policy.KindMCPCall)
	}
	if m.MCPTool != "" {
		tool := m.MCPTool
		addEv(func(ctx *policy.MatchContext) (bool, string) {
			if strings.HasSuffix(ctx.Event.Target, tool) {
				return true, "MCP tool " + tool
			}
			return false, ""
		}, policy.KindMCPCall)
	}
	if m.TaintSource != "" {
		// A pure condition — implies no kind on its own (a
		// taint_source-only rule must set applies_to or event_kind).
		source := m.TaintSource
		conds = append(conds, func(ctx *policy.MatchContext) (bool, string) {
			if ctx.Event.Taint.HasSource(source) {
				return true, "session tainted by " + source
			}
			return false, ""
		})
	}
	if m.SessionCostUSDGt > 0 {
		// G12 budget data: matches the guard-stamped spend-so-far.
		// Pure condition — implies no kind on its own (a cost-only
		// rule must set applies_to or event_kind). Strict-greater
		// semantics; re-matches every stamped event while over the
		// threshold (the built-in B-601 dedups its own records; user
		// rules own their volume).
		limit := m.SessionCostUSDGt
		conds = append(conds, func(ctx *policy.MatchContext) (bool, string) {
			if ctx.Event.SessionCostUSD > limit {
				return true, fmt.Sprintf("session spend $%.2f > $%.2f", ctx.Event.SessionCostUSD, limit)
			}
			return false, ""
		})
	}
	if m.RepeatCountGt > 0 {
		// G12 anomaly data: matches the guard-stamped consecutive-
		// identical run length. Pure condition — implies no kind on
		// its own. Strict-greater semantics (the built-in A-610 fires
		// on the crossing edge instead; documented difference).
		limit := m.RepeatCountGt
		conds = append(conds, func(ctx *policy.MatchContext) (bool, string) {
			if ctx.Event.RepeatCount > limit {
				return true, fmt.Sprintf("action repeated %d× consecutively (> %d)", ctx.Event.RepeatCount, limit)
			}
			return false, ""
		})
	}
	if m.Sink != "" {
		s, ok := validSinks[m.Sink]
		if !ok {
			return nil, nil, fmt.Errorf("unknown sink %q (shell_exec|git_push|out_of_project_write|mcp_call)", m.Sink)
		}
		sink := m.Sink
		addEv(func(ctx *policy.MatchContext) (bool, string) {
			return sinkCondition(ctx, sink, s.desc)
		}, s.kinds...)
	}
	if len(m.EventKind) > 0 {
		for _, k := range m.EventKind {
			ek, ok := validEventKinds[k]
			if !ok {
				return nil, nil, fmt.Errorf("unknown event_kind %q", k)
			}
			kinds = appendKinds(kinds, ek)
		}
		want := m.EventKind
		conds = append(conds, func(ctx *policy.MatchContext) (bool, string) {
			for _, k := range want {
				if validEventKinds[k] == ctx.Event.Kind {
					return true, "event kind " + k
				}
			}
			return false, ""
		})
	}
	return conds, kinds, nil
}

// andCmd AND-combines command-scoped conditions; the detail strings
// of all passing conditions join for the verdict reason.
func andCmd(conds []cmdCond) policy.MatchCmdFn {
	return func(ctx *policy.MatchContext, cmd *policy.Command) (bool, string) {
		var details []string
		for _, c := range conds {
			hit, d := c(ctx, cmd)
			if !hit {
				return false, ""
			}
			details = append(details, d)
		}
		return true, strings.Join(details, "; ")
	}
}

// andEv AND-combines event-scoped conditions.
func andEv(conds []evCond) policy.MatchFn {
	return func(ctx *policy.MatchContext) (bool, string) {
		var details []string
		for _, c := range conds {
			hit, d := c(ctx)
			if !hit {
				return false, ""
			}
			details = append(details, d)
		}
		return true, strings.Join(details, "; ")
	}
}

// sinkCondition evaluates the sink vocabulary against an event.
func sinkCondition(ctx *policy.MatchContext, sink, desc string) (bool, string) {
	switch sink {
	case "shell_exec":
		if ctx.Event.Kind == policy.KindShellExec {
			return true, desc
		}
	case "git_push":
		for i := range ctx.Cmds {
			c := &ctx.Cmds[i]
			if c.Base == "git" {
				pos := c.Positionals()
				if len(pos) > 0 && pos[0] == "push" {
					return true, desc
				}
			}
		}
	case "out_of_project_write":
		return policy.OutsideProjectWrite(ctx, desc)
	case "mcp_call":
		if ctx.Event.Kind == policy.KindMCPCall {
			return true, desc
		}
	}
	return false, ""
}

// hostMatchesDomain reports whether the target's URL host equals dom
// or is a subdomain of it. Non-URL targets never match.
func hostMatchesDomain(target, dom string) bool {
	t := strings.ToLower(strings.TrimSpace(target))
	i := strings.Index(t, "://")
	if i < 0 {
		return false
	}
	host := t[i+3:]
	for _, cut := range []string{"/", "?", "#"} {
		if j := strings.Index(host, cut); j >= 0 {
			host = host[:j]
		}
	}
	if j := strings.Index(host, "@"); j >= 0 {
		host = host[j+1:]
	}
	if j := strings.LastIndex(host, ":"); j >= 0 && !strings.Contains(host[j:], "]") {
		host = host[:j]
	}
	host = strings.TrimSuffix(host, ".")
	return host == dom || strings.HasSuffix(host, "."+dom)
}

// appendKinds appends kinds not already present.
func appendKinds(kinds []policy.EventKind, add ...policy.EventKind) []policy.EventKind {
	for _, k := range add {
		dup := false
		for _, have := range kinds {
			if have == k {
				dup = true
				break
			}
		}
		if !dup {
			kinds = append(kinds, k)
		}
	}
	return kinds
}
