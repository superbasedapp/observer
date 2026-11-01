package agentconfig

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// The effective-layer evaluator (surface-gap arc Wave 0.5; docs/plans/
// surface-gap-wave-0-design-2026-10-25.md section 7). ResolveFiles sorts
// values by FileRow.Precedence and stops there; a tool's real chain also
// merges maps per key, lets a deny from any layer win, replaces or
// concatenates arrays, replaces same-name entries and lets its launch
// environment beat every file. Evaluate applies one setting family's rule to
// key-scoped observations: which source sets the key, and a coarse class of
// what it sets, never the value. Pure: the observations come from the I/O
// boundaries (agentconfigsvc, the security trust check's project reader,
// credential-safe member reads), never from a file read here.
//
// This chain is the TOOL's own. Observer's authored layers (Layer, the
// PrecedenceRow table in precedence.go) are a different chain and are not
// touched.

// RuntimeLayer is a source that is not a file. Closed.
type RuntimeLayer string

// The closed RuntimeLayer vocabulary.
const (
	// RuntimeLaunchEnv: the environment the tool process was launched with
	// (a desktop host sets it for its sessions).
	RuntimeLaunchEnv RuntimeLayer = "launch_env"
	// RuntimeCLIFlag: a command-line flag, or a file named by one
	// (Claude Code's --settings).
	RuntimeCLIFlag RuntimeLayer = "cli_flag"
	// RuntimeDotenv: a .env file the tool itself loads into its own
	// environment at start (aider's load_dotenv(override=True) over ~/.env,
	// <git root>/.env and ./.env, CLI-7). Where it ranks against the launch
	// environment is the family's RuntimeRanks: aider lets it override,
	// Gemini CLI loads it only for a variable that is unset.
	RuntimeDotenv RuntimeLayer = "dotenv"
	// RuntimeConfigContent: configuration handed over inline through an
	// environment variable and merged over the config files
	// (OPENCODE_CONFIG_CONTENT). Read from the injected environment only.
	RuntimeConfigContent RuntimeLayer = "config_content"
	// RuntimeManagedPrefs: an OS managed-preferences / policy channel only an
	// administrator writes (macOS /Library/Managed Preferences, an MDM
	// profile; the Windows HKLM policy key). Read by its owner
	// (internal/hook) and handed over by key name only.
	RuntimeManagedPrefs RuntimeLayer = "managed_prefs"
	// RuntimeUserPrefs: the user's own OS preferences domain, which a tool
	// reads through the same API as its managed policy (macOS
	// ~/Library/Preferences/<domain>.plist, written by `defaults write`; the
	// Windows HKCU policy key, FU-115). User-writable, so a policy key set
	// here is not tamper-proof (FU-105). Key names only.
	RuntimeUserPrefs RuntimeLayer = "user_prefs"
)

// userWritableLayers are the runtime layers whose policy keys the user can
// write (ConcernUserPolicy reads them).
var userWritableLayers = map[RuntimeLayer]bool{RuntimeUserPrefs: true}

// SourceRef names one source: a FileRow id, or a runtime layer. Exactly one
// is set.
type SourceRef struct {
	FileID  string
	Runtime RuntimeLayer
}

// String renders the source for messages.
func (s SourceRef) String() string {
	if s.FileID != "" {
		return s.FileID
	}
	return "runtime:" + string(s.Runtime)
}

// Observation is one source's view of one key: whether the source sets it,
// and a coarse class of what it sets (from the family's closed Classes),
// never the value. Active is false for a source the tool skips (an untrusted
// project, a layer dropped by --setting-sources); InactiveReason says why.
type Observation struct {
	Source         SourceRef
	Key            KeyPath
	Present        bool
	Class          string
	Active         bool
	InactiveReason string
}

// Policy is how a family's sources combine. Closed.
type Policy string

// The closed Policy vocabulary.
const (
	// PolicyHighestWins: the highest-ranked source that sets the key wins.
	PolicyHighestWins Policy = "highest_wins"
	// PolicyDenyWins: DenyClass from any active source wins; otherwise
	// highest wins (Cursor hooks).
	PolicyDenyWins Policy = "deny_wins"
	// PolicyMapMerge: each key under the family's map key is decided on its
	// own, highest wins (Claude Code merges env per variable).
	PolicyMapMerge Policy = "map_merge"
	// PolicyArrayReplace: the highest source that defines the array wins
	// whole, even an empty one (VT Code lifecycle hooks).
	PolicyArrayReplace Policy = "array_replace"
	// PolicyArrayConcat: arrays concatenate across sources; KeepClass from
	// any active source survives (Kilo plugin arrays).
	PolicyArrayConcat Policy = "array_concat"
	// PolicySameNameReplace: entries are keyed by name under the family's
	// key, and the highest source defining a name replaces it (Vibe hooks).
	PolicySameNameReplace Policy = "same_name_replace"
	// PolicyRuntimeOverride: highest wins, and the family's Override layers
	// beat every other source when set.
	PolicyRuntimeOverride Policy = "runtime_override"
	// PolicyFirstFileWins: the tool searches its files in order and loads
	// only the first one it finds, whole; nothing is merged from the others
	// (Stakpak's MCP search, S-22). The first file searched is the one with
	// the highest rank.
	PolicyFirstFileWins Policy = "first_file_wins"
)

// ReasonCode says why an EffectiveResult came out as it did. Closed.
type ReasonCode string

// The closed ReasonCode vocabulary.
const (
	ReasonNoObservation    ReasonCode = "no_observation"
	ReasonSingleSource     ReasonCode = "single_source"
	ReasonOutranked        ReasonCode = "outranked"
	ReasonRuntimeOverride  ReasonCode = "runtime_override"
	ReasonDenyPresent      ReasonCode = "deny_present"
	ReasonArrayReplaced    ReasonCode = "array_replaced"
	ReasonMerged           ReasonCode = "merged"
	ReasonSameNameReplaced ReasonCode = "same_name_replaced"
	ReasonFirstFileWins    ReasonCode = "first_file_wins"
)

// Family is one setting family's rule: which files (by Tool and Shape) and
// runtime layers feed it, how they combine, and the ranks of its runtime
// layers relative to FileRow.Precedence.
type Family struct {
	ID    string
	Tool  string
	Shape string
	// Key is the setting's key; for map_merge and same_name_replace it is
	// the map or name-table key, and observations sit one level or more
	// below it.
	Key    KeyPath
	Policy Policy
	// Classes is the family's closed value-class vocabulary.
	Classes []string
	// RuntimeRanks places runtime layers among the files' precedences.
	RuntimeRanks map[RuntimeLayer]int
	// Override lists runtime layers that beat every other source when set
	// (applied under every policy except a deny).
	Override []RuntimeLayer
	// DenyClass is the class PolicyDenyWins lets win from any source.
	DenyClass string
	// KeepClass is the class PolicyArrayConcat keeps from any source.
	KeepClass string
	// Members, for a map_merge or same_name_replace family, are the members
	// of the map the observation producer reads (empty: every member).
	// Claude Code's env block also holds credentials: only the route
	// variable is ever classified.
	Members []string
	// DropScopes, for a ConcernLayerDrop family, are the scopes of the
	// tool's files the tool stops reading when the family's effective class
	// is OffClass (EvaluateLayers marks them inactive for every other
	// family of the tool).
	DropScopes []Scope
	// FileRanks replaces FileRow.Precedence for the files it names, for
	// this family only: a key whose layering differs from the file's
	// (Factory's hooksDisabled is a session default, most local wins, so
	// the org system file that wins every hard control ranks lowest for
	// it). Every key must be a file of the family's tool and shape
	// (TestFamiliesWellFormed).
	FileRanks map[string]int
	// Concern says what the family decides for Observer, and so which
	// LayerFinding rules apply to its results (layerFindingRules). Closed:
	// ConcernRoute, ConcernHooksOff, ConcernHookArray, ConcernLayerDrop,
	// ConcernMCP, ConcernAuth, ConcernIDERoute, ConcernProvider,
	// ConcernUserPolicy.
	Concern Concern
	// ObserverClass is the class that means Observer is in force for this
	// key (loopback for a route, on for a hook switch, with_observer for a
	// hook array); "" when the family has none.
	ObserverClass string
	// OffClass is the class that means the family's switch is set
	// (ConcernHooksOff off, ConcernLayerDrop on, ConcernAuth a sign-in mode
	// that pins the vendor host); "" when the family has none.
	OffClass  string
	Grounding Grounding
	Note      string
}

// Concern is what a family decides for Observer. Closed.
type Concern string

// The closed Concern vocabulary.
const (
	// ConcernRoute: a base-URL key; Observer's class is loopback.
	ConcernRoute Concern = "route"
	// ConcernHooksOff: a switch that turns the tool's hooks off.
	ConcernHooksOff Concern = "hooks_off"
	// ConcernHookArray: a hook array a higher layer replaces whole.
	ConcernHookArray Concern = "hook_array"
	// ConcernLayerDrop: a switch that drops whole layers (VT Code's
	// use_root_config drops the system and user files).
	ConcernLayerDrop Concern = "layer_drop"
	// ConcernMCP: an MCP server list resolved by file.
	ConcernMCP Concern = "mcp"
	// ConcernAuth: a saved sign-in mode; a mode other than an API key pins
	// the vendor's own host whatever base URL is set (CLI-6).
	ConcernAuth Concern = "auth"
	// ConcernIDERoute: an IDE setting that hands the agent process its
	// environment (VS Code's claudeCode.environmentVariables, IDE-3).
	ConcernIDERoute Concern = "ide_route"
	// ConcernProvider: which provider the tool talks to; Observer's route
	// is in one provider's entry, so another active provider bypasses it
	// (CLI-3).
	ConcernProvider Concern = "provider"
	// ConcernUserPolicy: a tool policy key that a user-writable source
	// (RuntimeUserPrefs) sets, which the tool applies as policy although an
	// administrator did not deploy it (IBM Bob on macOS, FU-105). Report
	// only: it never changes what Observer enforces.
	ConcernUserPolicy Concern = "user_policy"
)

// EffectiveResult is one key's outcome.
type EffectiveResult struct {
	Key            KeyPath
	EffectiveClass string
	Winning        SourceRef
	// Shadowed are the other active sources that set the key, highest rank
	// first.
	Shadowed []SourceRef
	// Inactive are sources that set the key but that the tool skips.
	Inactive []SourceRef
	Reason   ReasonCode
}

// Evaluate errors. All are table or caller bugs, never a verdict.
var (
	ErrBadFamily      = errors.New("agentconfig: malformed setting family")
	ErrBadObservation = errors.New("agentconfig: malformed observation")
	ErrAmbiguousRank  = errors.New("agentconfig: two sources share a rank")
)

// policyEval decides one key from its active, present observations, highest
// rank first (never empty).
type policyEval func(f Family, ranked []Observation) EffectiveResult

// policies is the policy table; exactKey says the family's observations must
// sit exactly at Family.Key (otherwise strictly below it).
var policies = map[Policy]struct {
	eval     policyEval
	exactKey bool
}{
	PolicyHighestWins:     {evalHighest(ReasonOutranked), true},
	PolicyRuntimeOverride: {evalHighest(ReasonOutranked), true},
	PolicyMapMerge:        {evalHighest(ReasonOutranked), false},
	PolicySameNameReplace: {evalHighest(ReasonSameNameReplaced), false},
	PolicyArrayReplace:    {evalHighest(ReasonArrayReplaced), true},
	PolicyDenyWins:        {evalDenyWins, true},
	PolicyArrayConcat:     {evalArrayConcat, true},
	PolicyFirstFileWins:   {evalHighest(ReasonFirstFileWins), true},
}

// Evaluate applies f to obs. rank resolves each source's rank and whether it
// belongs to the family; nil uses DefaultRank(f). It returns one result per
// observed key, sorted by key, and exactly one result (possibly
// no_observation) for an exact-key family.
func Evaluate(f Family, obs []Observation, rank func(SourceRef) (int, bool)) ([]EffectiveResult, error) {
	if err := validateFamily(f); err != nil {
		return nil, err
	}
	if rank == nil {
		rank = DefaultRank(f)
	}
	p := policies[f.Policy]
	classes := map[string]bool{}
	for _, c := range f.Classes {
		classes[c] = true
	}
	type group struct {
		key      KeyPath
		eligible []Observation
		inactive []SourceRef
	}
	groups := map[string]*group{}
	seen := map[string]bool{}
	ranks := map[SourceRef]int{}
	for _, o := range obs {
		if (o.Source.FileID == "") == (o.Source.Runtime == "") {
			return nil, fmt.Errorf("%w: source must name exactly one of a file or a runtime layer", ErrBadObservation)
		}
		r, ok := rank(o.Source)
		if !ok {
			return nil, fmt.Errorf("%w: %s is not a source of family %s", ErrBadObservation, o.Source, f.ID)
		}
		ranks[o.Source] = r
		if !keyFits(f.Key, o.Key, p.exactKey) {
			return nil, fmt.Errorf("%w: key %s does not fit family %s", ErrBadObservation, o.Key, f.ID)
		}
		dup := o.Source.String() + "|" + o.Key.String()
		if seen[dup] {
			return nil, fmt.Errorf("%w: %s observed twice for %s", ErrBadObservation, o.Source, o.Key)
		}
		seen[dup] = true
		if !o.Present {
			continue
		}
		if !classes[o.Class] {
			return nil, fmt.Errorf("%w: class %q is not in family %s", ErrBadObservation, o.Class, f.ID)
		}
		g := groups[o.Key.String()]
		if g == nil {
			g = &group{key: append(KeyPath(nil), o.Key...)}
			groups[o.Key.String()] = g
		}
		if o.Active {
			g.eligible = append(g.eligible, o)
		} else {
			g.inactive = append(g.inactive, o.Source)
		}
	}
	if err := distinctRanks(ranks); err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]EffectiveResult, 0, len(keys)+1)
	for _, k := range keys {
		g := groups[k]
		sort.SliceStable(g.eligible, func(i, j int) bool { return ranks[g.eligible[i].Source] > ranks[g.eligible[j].Source] })
		sort.SliceStable(g.inactive, func(i, j int) bool { return ranks[g.inactive[i]] > ranks[g.inactive[j]] })
		var res EffectiveResult
		if len(g.eligible) == 0 {
			res = EffectiveResult{Reason: ReasonNoObservation}
		} else {
			res = p.eval(f, g.eligible)
		}
		res.Key, res.Inactive = g.key, g.inactive
		out = append(out, res)
	}
	if len(out) == 0 && p.exactKey {
		out = append(out, EffectiveResult{Key: append(KeyPath(nil), f.Key...), Reason: ReasonNoObservation})
	}
	return out, nil
}

// evalHighest is highest-wins with the family's Override layers first;
// multi names the reason when a lower source was beaten.
func evalHighest(multi ReasonCode) policyEval {
	return func(f Family, ranked []Observation) EffectiveResult {
		if i := overrideIndex(f, ranked); i >= 0 {
			return pick(ranked, i, ranked[i].Class, ReasonRuntimeOverride)
		}
		reason := ReasonSingleSource
		if len(ranked) > 1 {
			reason = multi
		}
		return pick(ranked, 0, ranked[0].Class, reason)
	}
}

// evalDenyWins lets the highest-ranked deny win from any source, else
// falls back to highest-wins.
func evalDenyWins(f Family, ranked []Observation) EffectiveResult {
	for i, o := range ranked {
		if o.Class == f.DenyClass {
			return pick(ranked, i, f.DenyClass, ReasonDenyPresent)
		}
	}
	return evalHighest(ReasonOutranked)(f, ranked)
}

// evalArrayConcat keeps KeepClass when any source carries it (the arrays
// concatenate), else reports the highest source's class.
func evalArrayConcat(f Family, ranked []Observation) EffectiveResult {
	reason := ReasonSingleSource
	if len(ranked) > 1 {
		reason = ReasonMerged
	}
	for i, o := range ranked {
		if o.Class == f.KeepClass {
			return pick(ranked, i, f.KeepClass, reason)
		}
	}
	return pick(ranked, 0, ranked[0].Class, reason)
}

// overrideIndex is the index of the highest-ranked observation from one of
// the family's Override layers, or -1.
func overrideIndex(f Family, ranked []Observation) int {
	for i, o := range ranked {
		for _, l := range f.Override {
			if o.Source.Runtime == l {
				return i
			}
		}
	}
	return -1
}

// pick builds a result with ranked[i] as the winner and every other ranked
// source shadowed, in rank order.
func pick(ranked []Observation, i int, class string, reason ReasonCode) EffectiveResult {
	res := EffectiveResult{EffectiveClass: class, Winning: ranked[i].Source, Reason: reason}
	for j, o := range ranked {
		if j != i {
			res.Shadowed = append(res.Shadowed, o.Source)
		}
	}
	return res
}

// keyFits reports whether key sits at prefix (exact) or strictly below it.
func keyFits(prefix, key KeyPath, exact bool) bool {
	if exact {
		return key.String() == prefix.String()
	}
	if len(key) <= len(prefix) {
		return false
	}
	return key[:len(prefix)].String() == prefix.String()
}

// distinctRanks refuses two sources that share a rank: the tool's order
// between them would be undefined.
func distinctRanks(ranks map[SourceRef]int) error {
	byRank := map[int]SourceRef{}
	for s, r := range ranks {
		if other, ok := byRank[r]; ok && other != s {
			return fmt.Errorf("%w: %s and %s both rank %d", ErrAmbiguousRank, other, s, r)
		}
		byRank[r] = s
	}
	return nil
}

// validateFamily checks a family's own shape.
func validateFamily(f Family) error {
	if _, ok := policies[f.Policy]; !ok {
		return fmt.Errorf("%w: %s: unknown policy %q", ErrBadFamily, f.ID, f.Policy)
	}
	if len(f.Key) == 0 || len(f.Classes) == 0 {
		return fmt.Errorf("%w: %s: no key or no classes", ErrBadFamily, f.ID)
	}
	has := func(c string) bool {
		for _, x := range f.Classes {
			if x == c {
				return true
			}
		}
		return false
	}
	switch {
	case f.Policy == PolicyDenyWins && !has(f.DenyClass):
		return fmt.Errorf("%w: %s: deny_wins needs a DenyClass from its Classes", ErrBadFamily, f.ID)
	case f.Policy == PolicyArrayConcat && !has(f.KeepClass):
		return fmt.Errorf("%w: %s: array_concat needs a KeepClass from its Classes", ErrBadFamily, f.ID)
	case f.Policy == PolicyRuntimeOverride && len(f.Override) == 0:
		return fmt.Errorf("%w: %s: runtime_override needs an Override layer", ErrBadFamily, f.ID)
	}
	for _, l := range f.Override {
		if _, ok := f.RuntimeRanks[l]; !ok {
			return fmt.Errorf("%w: %s: override layer %q has no rank", ErrBadFamily, f.ID, l)
		}
	}
	return nil
}

// DefaultRank ranks a family's sources: a file by its FileRow.Precedence
// (the one precedence owner), and only when the file is the family's tool
// and shape; a runtime layer by Family.RuntimeRanks.
func DefaultRank(f Family) func(SourceRef) (int, bool) {
	return func(s SourceRef) (int, bool) {
		if s.Runtime != "" {
			r, ok := f.RuntimeRanks[s.Runtime]
			return r, ok
		}
		row, ok := fileRowsByID()[s.FileID]
		if !ok || row.Tool != f.Tool || row.Shape != f.Shape {
			return 0, false
		}
		if r, ok := f.FileRanks[s.FileID]; ok {
			return r, true
		}
		return row.Precedence, true
	}
}

var (
	fileRowsOnce sync.Once
	fileRowsMap  map[string]FileRow
)

// fileRowsByID indexes the Files table by id.
func fileRowsByID() map[string]FileRow {
	fileRowsOnce.Do(func() {
		fileRowsMap = map[string]FileRow{}
		for _, f := range filesTable() {
			fileRowsMap[f.ID] = f
		}
	})
	return fileRowsMap
}
