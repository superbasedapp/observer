package guardrecipesvc

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardrecipe"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Env is what every call needs: the loaded config (config.Load over the
// config file, the same load the guard runs on), the home directory the
// policy paths expand against, the project roots the guard knows, and the
// rule pack of the modules this node runs (so the effective rules match the
// daemon's).
type Env struct {
	Config            config.Config
	Home              string
	KnownProjectRoots []string
	PackRules         []policy.Rule
	// Prepare, when set, runs on every guard the service builds (the current
	// and the proposed one) before it is used: a replay caller wires the same
	// hooks its own simulate route wires, so the two agree. nil does nothing.
	Prepare func(*guard.Guard)
	// Now stamps applied_at; nil means time.Now.
	Now func() time.Time
	// GovernancePins is the governance overlay's pins in force
	// (config.GovernanceOutcome.PinsInForce from the same LoadGovernance
	// that produced Config). A preview derives the mode an apply leaves in
	// force through them, so a pin that holds [guard] mode below a level's
	// shows as such (sweep finding CFG-9). nil: no pins.
	GovernancePins map[string]any
	// DroppedLayers and LintUser are the guard-layering seams (seams.go);
	// nil uses this package's fallbacks.
	DroppedLayers DroppedLayersFunc
	LintUser      UserLintFunc
	// ReplayFS, when set, is the filesystem memo the before and after guards
	// share (guard.Options.ReplayFS): a replay caller passes one so the two
	// judge a week of actions with one lookup per distinct path. nil (every
	// apply and preview) builds guards that ask the filesystem as usual.
	ReplayFS *guard.ReplayFS
	// Evaluate, when set, runs one guard over a replay's inputs in place of
	// g.EvaluateActions: the dashboard passes a chunked evaluator that counts
	// progress and stops when the replay is abandoned. It must return the
	// verdicts EvaluateActions would (a stopped run may return a prefix; the
	// caller that stopped it discards the result). nil is EvaluateActions.
	Evaluate func(g *guard.Guard, inputs []guard.ActionInput) []guard.ActionVerdict
}

func (e Env) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

// maxUserRecipes bounds how many user recipe files the catalog reads.
const maxUserRecipes = 200

// Catalog returns the recipe catalog: the embedded recipes plus the
// person's own *.toml files in the guard-recipes directory. A user file that
// does not load is skipped and named in Set.Issues.
func Catalog(env Env) (*guardrecipe.Set, error) {
	set, err := guardrecipe.Builtin()
	if err != nil {
		return nil, err
	}
	dir := guard.RecipeDir(env.Config.Guard, env.Home)
	if dir == "" {
		return set, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			set.Issues = append(set.Issues, fmt.Sprintf("guard recipes directory %s: %v", dir, err))
		}
		return set, nil
	}
	n := 0
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".toml")
		if !ok || e.IsDir() || !e.Type().IsRegular() {
			continue
		}
		if n++; n > maxUserRecipes {
			set.Issues = append(set.Issues, fmt.Sprintf("guard recipes directory %s: more than %d recipes, the rest are not read", dir, maxUserRecipes))
			break
		}
		raw, err := readBounded(filepath.Join(dir, e.Name()), guardrecipe.MaxRecipeBytes)
		if err != nil {
			set.Issues = append(set.Issues, fmt.Sprintf("user recipe %q: %v", name, err))
			continue
		}
		set.AddUser(name, raw)
	}
	return set, nil
}

// readBounded reads a file of at most limit bytes: it stats the file first
// and reads through a limit, so a large file costs neither the memory nor
// the time of reading it whole (sweep finding RC-10).
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // the person's own recipe directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("file is larger than %d bytes", limit)
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("file is larger than %d bytes", limit)
	}
	return raw, nil
}

// CatalogRules is the built-in rule catalog as the compiler needs it: one
// entry per rule ID with its strictest row's decisions (the reduction the
// guard's merge seeds the effective policy with), integrity flagged.
func CatalogRules() []guardrecipe.CatalogRule {
	var out []guardrecipe.CatalogRule
	idx := map[string]int{}
	for _, info := range policy.Catalog() {
		if i, ok := idx[info.ID]; ok {
			c := &out[i]
			c.Observe = policy.StricterOf(mustDecision(c.Observe), info.Observe).String()
			c.Enforce = policy.StricterOf(mustDecision(c.Enforce), info.Enforce).String()
			continue
		}
		idx[info.ID] = len(out)
		out = append(out, guardrecipe.CatalogRule{
			ID: info.ID, Category: string(info.Category),
			Observe: info.Observe.String(), Enforce: info.Enforce.String(),
			Integrity: policy.IsIntegrityRuleID(info.ID),
		})
	}
	return out
}

// compileCatalog is CatalogRules plus the rule pack rows of the modules
// this node runs (env.PackRules), so a recipe pack naming one is judged
// tighten-only like a built-in; mode emulation leaves those alone.
func compileCatalog(env Env) []guardrecipe.CatalogRule {
	out := CatalogRules()
	idx := map[string]int{}
	for i, c := range out {
		idx[c.ID] = i
	}
	for _, r := range env.PackRules {
		if i, ok := idx[r.ID]; ok {
			c := &out[i]
			c.Observe = policy.StricterOf(mustDecision(c.Observe), r.Observe).String()
			c.Enforce = policy.StricterOf(mustDecision(c.Enforce), r.Enforce).String()
			continue
		}
		idx[r.ID] = len(out)
		out = append(out, guardrecipe.CatalogRule{
			ID: r.ID, Category: string(r.Category),
			Observe: r.Observe.String(), Enforce: r.Enforce.String(),
			Integrity: policy.IsIntegrityRuleID(r.ID), ModuleRule: true,
		})
	}
	return out
}

func mustDecision(s string) policy.Decision {
	d, _ := policy.ParseDecision(s)
	return d
}

// Request is one apply: the selection plus where it lands.
type Request struct {
	Level       string
	Packs       []string
	Scope       guardrecipe.Scope
	ProjectRoot string
	// Via names the surface ("cli" or "dashboard") for the file header.
	Via string
}

// RecipePath resolves where a scope's applied recipe file lives.
func RecipePath(env Env, scope guardrecipe.Scope, projectRoot string) (string, error) {
	switch scope {
	case guardrecipe.ScopeGlobal:
		p := guard.UserRecipePolicyPath(env.Config.Guard, env.Home)
		if p == "" {
			return "", errors.New("no user policy file is configured ([guard.rules] user_policy is empty), so a global recipe has no layer to join")
		}
		return p, nil
	case guardrecipe.ScopeProject:
		if strings.TrimSpace(projectRoot) == "" {
			return "", errors.New("a project recipe needs a project root")
		}
		p := guard.TrustedProjectRecipePath(env.Config.Guard, env.Home, projectRoot)
		if p == "" {
			return "", errors.New("the trusted per-project layer is off ([guard.rules] trusted_project_dir is empty), so a project recipe has no layer to join")
		}
		return p, nil
	default:
		return "", fmt.Errorf("scope %q not in {global, project}", scope)
	}
}

// Applied is one applied recipe file as found on disk.
type Applied struct {
	Scope       guardrecipe.Scope `json:"scope"`
	ProjectRoot string            `json:"project_root,omitempty"`
	Path        string            `json:"path"`
	// Readable is false for a file in the recipe slot whose header this
	// binary cannot read (hand-written, or a newer format): it still loads
	// as policy, and apply or remove replaces it.
	Readable bool             `json:"readable"`
	Meta     guardrecipe.Meta `json:"meta"`
	// Updates lists "name vN -> vM" for applied recipes the catalog now
	// carries a newer revision of; Missing lists applied recipes the catalog
	// no longer has.
	Updates []string `json:"updates,omitempty"`
	Missing []string `json:"missing,omitempty"`
	// Drift explains why a project recipe is not what is in force ("" when
	// it is); set by ListApplied. The global recipe's is LevelDrift.
	Drift string `json:"drift,omitempty"`
}

// ReadApplied returns the applied recipe of one scope, nil when none.
func ReadApplied(env Env, set *guardrecipe.Set, scope guardrecipe.Scope, projectRoot string) (*Applied, error) {
	path, err := RecipePath(env, scope, projectRoot)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the managed recipe file this package owns
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("guardrecipesvc.ReadApplied: %w", err)
	}
	a := &Applied{Scope: scope, ProjectRoot: projectRoot, Path: path}
	a.Meta, a.Readable = guardrecipe.ParseMeta(raw)
	if !a.Readable {
		return a, nil
	}
	refs := append([]guardrecipe.Ref(nil), a.Meta.Packs...)
	if a.Meta.Level != nil {
		refs = append([]guardrecipe.Ref{*a.Meta.Level}, refs...)
	}
	for _, ref := range refs {
		r, ok := set.Get(ref.Name)
		switch {
		case !ok:
			a.Missing = append(a.Missing, ref.Name)
		case r.Version > ref.Version:
			a.Updates = append(a.Updates, fmt.Sprintf("%s v%d -> v%d", ref.Name, ref.Version, r.Version))
		}
	}
	return a, nil
}

// ListApplied returns the global recipe and every known project's.
func ListApplied(env Env, set *guardrecipe.Set) (global *Applied, projects []Applied, issues []string) {
	g, err := ReadApplied(env, set, guardrecipe.ScopeGlobal, "")
	if err != nil {
		issues = append(issues, err.Error())
	}
	global = g
	if guard.TrustedProjectPolicyPath(env.Config.Guard, env.Home, "/") == "" {
		return global, nil, issues
	}
	roots := append([]string(nil), env.KnownProjectRoots...)
	sort.Strings(roots)
	var cur *guard.Guard
	for _, root := range roots {
		a, err := ReadApplied(env, set, guardrecipe.ScopeProject, root)
		if err != nil {
			issues = append(issues, err.Error())
			continue
		}
		if a == nil {
			continue
		}
		if a.Readable {
			if cur == nil {
				// One guard for every project's in-force check; a build
				// failure leaves the checks to build their own (and make no
				// claim when that fails too).
				cur, _ = guard.New(guard.Options{Config: env.Config.Guard, Home: env.Home, KnownProjectRoots: env.KnownProjectRoots, PackRules: env.PackRules})
			}
			a.Drift = strings.Join(inForceNotes(env, cur, a), " ")
		}
		projects = append(projects, *a)
	}
	return global, projects, issues
}

// Change is one rule row whose effective decision an apply or remove moves.
type Change struct {
	RuleID   string `json:"rule_id"`
	Doc      string `json:"doc"`
	Category string `json:"category"`
	// Before and After are the decision the row takes on a match under the
	// mode in force: "off" (the guard is off or the rule is disabled),
	// "absent" (the row does not exist), "allow" (silent), "flag", "ask" or
	// "deny".
	Before string `json:"before"`
	After  string `json:"after"`
}

// Preview is what an apply or remove would do, computed against the real
// guard and written nowhere.
type Preview struct {
	Scope       guardrecipe.Scope `json:"scope"`
	ProjectRoot string            `json:"project_root,omitempty"`
	Path        string            `json:"path"`
	Remove      bool              `json:"remove"`
	Level       string            `json:"level,omitempty"`
	Packs       []string          `json:"packs,omitempty"`
	// Text is the recipe file the apply writes ("" for a remove).
	Text string `json:"text,omitempty"`
	// Config writes a global apply or remove makes.
	LevelBefore      string `json:"level_before"`
	LevelAfter       string `json:"level_after"`
	ModeBefore       string `json:"mode_before"`
	ModeAfter        string `json:"mode_after"`
	PromptModeBefore string `json:"prompt_mode_before"`
	PromptModeAfter  string `json:"prompt_mode_after"`
	// ModeNote explains a mode the apply cannot set (an organization floor)
	// or one a project recipe leaves machine-wide.
	ModeNote string `json:"mode_note,omitempty"`
	// Changes are the rule rows whose effective decision moves.
	Changes []Change `json:"changes"`
	// Problems refuse the change while any is present: lint failures of the
	// compiled file (at the layer it joins, the organization's in view), a
	// pack row that could only lower a rule, and a policy layer or project
	// policy the change would drop.
	Problems []string `json:"problems,omitempty"`
	// Issues are new load notes the proposed policy raises (an org floor
	// keeping a rule above the recipe's decision, an unloaded module's rule).
	Issues []string `json:"issues,omitempty"`
	Advice []string `json:"advice,omitempty"`
	Inputs []string `json:"inputs,omitempty"`
	// Replaces is the applied recipe this apply or remove replaces.
	Replaces *Applied `json:"replaces,omitempty"`
}

// plan is a computed apply: the preview plus what the write needs.
type plan struct {
	preview  *Preview
	text     []byte
	previous *guardrecipe.Previous
	edit     func(*config.GuardConfig)
	// fileMoves reports that the edit changes a [guard] key the config file
	// holds. On a managed node the floor or a governance pin can keep the
	// values in force (the preview's before/after) from moving while the
	// file's own value does, and the file is what a later unenroll or remove
	// reads (sweep findings RC-7, RC-8).
	fileMoves bool
	// cur and next are the guard as it is and as the change leaves it.
	cur, next *guard.Guard
}

// PreviewApply computes an apply without writing anything.
func PreviewApply(env Env, set *guardrecipe.Set, req Request) (*Preview, error) {
	p, err := planApply(env, set, req)
	if err != nil {
		return nil, err
	}
	return p.preview, nil
}

// PreviewRemove computes a remove without writing anything. ok is false when
// the scope has no applied recipe.
func PreviewRemove(env Env, set *guardrecipe.Set, scope guardrecipe.Scope, projectRoot string) (*Preview, bool, error) {
	p, ok, err := planRemove(env, set, scope, projectRoot)
	if err != nil || !ok {
		return nil, ok, err
	}
	return p.preview, true, nil
}

func planApply(env Env, set *guardrecipe.Set, req Request) (*plan, error) {
	if req.Scope == "" {
		req.Scope = guardrecipe.ScopeGlobal
	}
	path, err := RecipePath(env, req.Scope, req.ProjectRoot)
	if err != nil {
		return nil, err
	}
	current, err := ReadApplied(env, set, req.Scope, req.ProjectRoot)
	if err != nil {
		return nil, err
	}
	g := env.Config.Guard
	// The file's own [guard] values: what an apply records and compares.
	own := writableGuard(g)
	meta := guardrecipe.Meta{AppliedAt: env.now().Format(time.RFC3339), AppliedVia: req.Via}
	if req.Scope == guardrecipe.ScopeProject {
		meta.ProjectRoot = req.ProjectRoot
	}
	// A global apply records what it replaces so remove can put it back; a
	// re-apply carries the ORIGINAL record forward, so remove after several
	// applies returns to the state before the first. A pack-only re-apply
	// also carries the mode the earlier apply set, while the file still
	// holds it, so remove still restores it (RC-7).
	var previous *guardrecipe.Previous
	if req.Scope == guardrecipe.ScopeGlobal {
		previous = &guardrecipe.Previous{Level: own.Level, Mode: own.Mode, PromptMode: own.Prompt.Mode}
		if current != nil && current.Readable && current.Meta.Previous != nil {
			previous = current.Meta.Previous
		}
		meta.Previous = previous
		if req.Level == "" {
			meta.Mode, meta.PromptMode = carriedModes(current, own)
		}
	}
	sel := guardrecipe.Selection{Level: req.Level, Packs: req.Packs, Scope: req.Scope, FloorMode: g.Lock.Floor.Mode}
	compiled, err := guardrecipe.Compile(set, sel, compileCatalog(env), meta)
	if err != nil {
		return nil, err
	}
	pv := &Preview{
		Scope: req.Scope, ProjectRoot: req.ProjectRoot, Path: path,
		Level: req.Level, Packs: compiled.Meta.PackNames(), Text: string(compiled.Text),
		Advice: compiled.Advice, Inputs: compiled.Inputs, Replaces: current,
	}
	edit := func(*config.GuardConfig) {}
	switch {
	case req.Scope == guardrecipe.ScopeGlobal && req.Level == "":
		// A pack-only selection replaces the level too: the level key
		// clears, and the mode stays as it is.
		edit = func(c *config.GuardConfig) { c.Level = "" }
	case req.Scope == guardrecipe.ScopeGlobal:
		level, mode, prompt := req.Level, compiled.Mode, compiled.PromptMode
		edit = func(c *config.GuardConfig) {
			c.Level = level
			c.Mode = mode
			c.Prompt.Mode = prompt
		}
	case req.Level != "":
		pv.ModeNote = projectModeNote(set, req.Level, compiled.ModeNote)
	}
	if !g.Enabled {
		pv.ModeNote = joinNotes(pv.ModeNote, guardOffNote)
	}
	cur, next, fileMoves, err := fillPreview(env, pv, compiled.Text, false, edit)
	if err != nil {
		return nil, err
	}
	pv.Problems = append(append([]string(nil), compiled.Problems...), lintCompiled(env, cur, req.Scope, req.ProjectRoot, compiled)...)
	pv.Problems = append(pv.Problems, newlyDropped(env, cur, next)...)
	return &plan{preview: pv, text: compiled.Text, previous: previous, edit: edit, fileMoves: fileMoves, cur: cur, next: next}, nil
}

// carriedModes is the mode and prompt mode a pack-only re-apply records as
// set by the recipe: the earlier apply's, each while the file still holds
// it ("" otherwise).
func carriedModes(current *Applied, own config.GuardConfig) (mode, prompt string) {
	if current == nil || !current.Readable {
		return "", ""
	}
	m := current.Meta
	if m.Mode != "" && own.Mode == m.Mode {
		mode = m.Mode
	}
	if m.PromptMode != "" && own.Prompt.Mode == m.PromptMode {
		prompt = m.PromptMode
	}
	return mode, prompt
}

// projectModeNote explains what a project recipe does with the level's
// mode and prompt mode, both machine-wide (RC-13: the prompt mode is not
// held in the project at all). floorNote is the compiler's note when the
// organization's floor kept it from holding the mode (CFG-2).
func projectModeNote(set *guardrecipe.Set, level, floorNote string) string {
	note := "The mode is machine-wide, so a project recipe keeps it as it is and holds the level's mode in this project with explicit rows."
	if floorNote != "" {
		note = "The mode is machine-wide, so a project recipe keeps it as it is. " + floorNote
	}
	if r, ok := set.Get(level); ok && r.PromptMode != "" {
		note += fmt.Sprintf(" The prompt guard's mode is machine-wide too and a project recipe cannot hold it: the level's prompt mode %q is not applied in this project.", r.PromptMode)
	}
	return note
}

// joinNotes joins two notes with a space, skipping an empty one.
func joinNotes(a, b string) string {
	return strings.TrimSpace(strings.TrimSpace(a) + " " + strings.TrimSpace(b))
}

func planRemove(env Env, set *guardrecipe.Set, scope guardrecipe.Scope, projectRoot string) (*plan, bool, error) {
	path, err := RecipePath(env, scope, projectRoot)
	if err != nil {
		return nil, false, err
	}
	current, err := ReadApplied(env, set, scope, projectRoot)
	if err != nil || current == nil {
		return nil, false, err
	}
	pv := &Preview{Scope: scope, ProjectRoot: projectRoot, Path: path, Remove: true, Replaces: current}
	edit := func(*config.GuardConfig) {}
	if scope == guardrecipe.ScopeGlobal && current.Readable && current.Meta.Previous != nil {
		m, prev := current.Meta, *current.Meta.Previous
		// The level, mode and prompt mode go back only while the file still
		// holds what the apply set: a change made since is the person's and
		// stays. The edit runs on the file's own values (writableGuard), so
		// a floor or a pin holding the mode elsewhere does not hide them.
		edit = func(c *config.GuardConfig) {
			if c.Level == m.LevelName() {
				c.Level = prev.Level
			}
			if m.Mode != "" && c.Mode == m.Mode {
				c.Mode = prev.Mode
			}
			if m.PromptMode != "" && c.Prompt.Mode == m.PromptMode {
				c.Prompt.Mode = prev.PromptMode
			}
		}
		own := writableGuard(env.Config.Guard)
		var notes []string
		if m.Mode != "" && own.Mode != m.Mode {
			notes = append(notes, fmt.Sprintf("the mode stays %q: it changed after the recipe set %q", own.Mode, m.Mode))
		}
		if m.PromptMode != "" && own.Prompt.Mode != m.PromptMode {
			notes = append(notes, fmt.Sprintf("the prompt mode stays %q: it changed after the recipe set %q", own.Prompt.Mode, m.PromptMode))
		}
		pv.ModeNote = strings.Join(notes, "; ")
	}
	cur, next, fileMoves, err := fillPreview(env, pv, nil, true, edit)
	if err != nil {
		return nil, false, err
	}
	pv.Problems = newlyDropped(env, cur, next)
	return &plan{preview: pv, edit: edit, fileMoves: fileMoves, cur: cur, next: next}, true, nil
}

// lintCompiled runs the guard's own lint over a compiled file at the layer it
// joins, with the organization's layer in view, so the grammar has one
// owner: the trusted layer's org-floor-aware lint for a project; for this
// machine, Env.LintUser when a test sets it, else the plain user lint plus
// the guard's own org-collision lint.
func lintCompiled(env Env, cur *guard.Guard, scope guardrecipe.Scope, projectRoot string, c *guardrecipe.Compiled) []string {
	if scope == guardrecipe.ScopeProject {
		problems := guard.LintTrustedProject(env.Config.Guard, env.Home, c.Text)
		return append(problems, orgRuleIDCollisions(cur, projectRoot, c.RuleIDs)...)
	}
	if env.LintUser != nil {
		return env.LintUser(env.Config.Guard, env.Home, c.Text)
	}
	return append(guard.Lint(c.Text, "user"), userRuleIDCollisions(cur, c.Text)...)
}

// writableGuard is g as the config file holds it. On a managed node the
// governance pins and the guard floor replace the mode (and other switches)
// in the loaded config, and Lock.Local keeps the file's own values; every
// [guard] edit this package makes runs on those, and every record it keeps
// or compares is one (sweep finding RC-8: recording the floored value lost
// the file's own, so a later unenroll could leave the guard off). Writing
// and reporting only: never feed the result to guard.New.
func writableGuard(g config.GuardConfig) config.GuardConfig {
	return g.WithLocalSwitches()
}

// fillPreview builds the guard as it is and as the apply or remove would
// leave it (the edited [guard] keys, and the recipe file served from memory
// in place of the one on disk) and records the config moves, the rule rows
// whose effective decision changes and the new load issues. fileMoves
// reports that the edit changes a key the config file holds.
func fillPreview(env Env, pv *Preview, text []byte, remove bool, edit func(*config.GuardConfig)) (cur, next *guard.Guard, fileMoves bool, err error) {
	before := env.Config.Guard
	fileBefore := writableGuard(before)
	fileAfter := fileBefore
	edit(&fileAfter)
	fileMoves = fileBefore.Level != fileAfter.Level || fileBefore.Mode != fileAfter.Mode || fileBefore.Prompt.Mode != fileAfter.Prompt.Mode
	after := before
	after.Level = fileAfter.Level
	after.Mode, after.Prompt.Mode = inForce(env, fileAfter)
	pv.LevelBefore, pv.LevelAfter = before.Level, after.Level
	pv.ModeBefore, pv.ModeAfter = modeOr(before.Mode), modeOr(after.Mode)
	pv.PromptModeBefore, pv.PromptModeAfter = before.Prompt.Mode, after.Prompt.Mode
	if fileAfter.Mode != fileBefore.Mode && fileAfter.Mode != after.Mode {
		pv.ModeNote = joinNotes(pv.ModeNote, fmt.Sprintf("Your organization holds the mode at %q, so the %q written to the config file is not in force.", modeOr(after.Mode), fileAfter.Mode))
	}
	if fileAfter.Prompt.Mode != fileBefore.Prompt.Mode && fileAfter.Prompt.Mode != after.Prompt.Mode {
		pv.ModeNote = joinNotes(pv.ModeNote, fmt.Sprintf("Your organization holds the prompt mode at %q, so the %q written to the config file is not in force.", after.Prompt.Mode, fileAfter.Prompt.Mode))
	}

	cur, err = guard.New(guard.Options{Config: before, Home: env.Home, KnownProjectRoots: env.KnownProjectRoots, PackRules: env.PackRules, ReplayFS: env.ReplayFS})
	if err != nil {
		return nil, nil, false, fmt.Errorf("build the current guard: %w", err)
	}
	served := pv.Path
	readFile := func(p string) ([]byte, error) {
		if samePath(p, served) {
			if remove {
				return nil, fs.ErrNotExist
			}
			return text, nil
		}
		return os.ReadFile(p) //nolint:gosec // the guard's own policy files
	}
	next, err = guard.New(guard.Options{Config: after, Home: env.Home, KnownProjectRoots: env.KnownProjectRoots, PackRules: env.PackRules, ReadFile: readFile, ReplayFS: env.ReplayFS})
	if err != nil {
		return nil, nil, false, fmt.Errorf("build the proposed guard: %w", err)
	}
	if env.Prepare != nil {
		env.Prepare(cur)
		env.Prepare(next)
	}
	root := ""
	if pv.Scope == guardrecipe.ScopeProject {
		root = pv.ProjectRoot
	}
	pv.Changes = diffRules(guardMode(cur, before), cur.EffectiveRulesFor(root), guardMode(next, after), next.EffectiveRulesFor(root))
	seen := map[string]bool{}
	for _, s := range cur.LoadIssues() {
		seen[s] = true
	}
	for _, s := range next.LoadIssues() {
		if !seen[s] {
			pv.Issues = append(pv.Issues, s)
			seen[s] = true
		}
	}
	return cur, next, fileMoves, nil
}

// guardMode is the mode a guard evaluates under; a disabled guard is off.
func guardMode(g *guard.Guard, c config.GuardConfig) policy.Mode {
	if !c.Enabled {
		return policy.ModeOff
	}
	return g.Mode()
}

// inForce is the mode and prompt mode the guard runs under once the config
// file holds g's values: the governance pins first, then the managed-node
// floor, in the order config.Load applies them. A pin can lower the mode a
// level writes and the floor only raises it, so both are needed for the
// preview to show what will really be in force (sweep finding CFG-9).
func inForce(env Env, g config.GuardConfig) (mode, prompt string) {
	if len(env.GovernancePins) > 0 {
		c := env.Config
		c.Guard = g
		governed, _ := config.ApplyGovernancePinsTo(c, env.GovernancePins)
		g = governed.Guard
	}
	return floorMode(env.Config.Guard, g.Mode), floorPromptMode(env.Config.Guard, g.Prompt.Mode)
}

// floorMode applies the managed-node org floor to a mode the apply would
// write, the way config.Load will when it reads the written file back.
func floorMode(g config.GuardConfig, mode string) string {
	f := g.Lock.Floor.Mode
	switch {
	case f == "enforce":
		return "enforce"
	case f == "observe" && mode == "off":
		return "observe"
	}
	return mode
}

// promptRank orders [guard.prompt] modes by how much they stop.
var promptRank = map[string]int{"off": 0, "warn": 1, "ask-once": 2, "redact": 3, "block": 4}

// floorPromptMode applies the managed-node org floor to a prompt mode.
func floorPromptMode(g config.GuardConfig, mode string) string {
	f := g.Lock.Floor.PromptMode
	if f != "" && promptRank[mode] < promptRank[f] {
		return f
	}
	return mode
}

func modeOr(m string) string {
	if strings.TrimSpace(m) == "" {
		return "observe"
	}
	return m
}

// samePath compares two file paths as the guard resolves them.
func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ca, cb := filepath.Clean(a), filepath.Clean(b)
	if os.PathSeparator == '\\' {
		return strings.EqualFold(ca, cb)
	}
	return ca == cb
}

// effective is the decision a row takes on a match under the engine mode:
// the observe decision, or the enforce decision in enforce mode or for an
// enforced row, capped at flag by an explicit `enforce = false`.
func effective(mode policy.Mode, r policy.RuleInfo) string {
	if mode == policy.ModeOff {
		return "off"
	}
	d := r.Observe
	if mode == policy.ModeEnforce || r.Enforced {
		d = r.Enforce
	}
	if r.EnforceCappedBy != "" && d > policy.DecisionFlag {
		d = policy.DecisionFlag
	}
	return d.String()
}

// diffRules pairs rule rows by (ID, Doc) and returns every row whose
// effective decision moves, in rule-ID order.
func diffRules(beforeMode policy.Mode, before []policy.RuleInfo, afterMode policy.Mode, after []policy.RuleInfo) []Change {
	type key struct{ id, doc string }
	type row struct {
		info policy.RuleInfo
		dec  string
	}
	index := func(mode policy.Mode, rules []policy.RuleInfo) (map[key]row, []key) {
		m := map[key]row{}
		var order []key
		for _, r := range rules {
			k := key{r.ID, r.Doc}
			if _, ok := m[k]; ok {
				continue
			}
			m[k] = row{r, effective(mode, r)}
			order = append(order, k)
		}
		return m, order
	}
	bm, border := index(beforeMode, before)
	am, aorder := index(afterMode, after)
	out := []Change{}
	// A row missing on one side was disabled (a built-in) or not defined
	// there (a recipe or user rule).
	missing := func(mode policy.Mode, k key) string {
		if mode == policy.ModeOff || policy.IsBuiltinRuleID(k.id) {
			return "off"
		}
		return "absent"
	}
	seen := map[key]bool{}
	for _, k := range append(border, aorder...) {
		if seen[k] {
			continue
		}
		seen[k] = true
		b, bok := bm[k]
		a, aok := am[k]
		c := Change{RuleID: k.id, Doc: k.doc}
		switch {
		case bok && aok:
			if b.dec == a.dec {
				continue
			}
			c.Category, c.Before, c.After = string(a.info.Category), b.dec, a.dec
		case aok:
			c.Category, c.Before, c.After = string(a.info.Category), missing(beforeMode, k), a.dec
		default:
			c.Category, c.Before, c.After = string(b.info.Category), b.dec, missing(afterMode, k)
		}
		if c.Before == c.After {
			continue
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}
