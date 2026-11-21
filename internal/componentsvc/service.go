package componentsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

// Teardowner runs teardown steps through the existing removers. The
// production implementation is NewTeardown; tests inject a fake so nothing
// touches a real home.
type Teardowner interface {
	// RemoveToolWiring removes parts of Observer's wiring from one tool's
	// own config ("" = every tool the removers detect).
	RemoveToolWiring(tool string, parts []string, dryRun bool) []StepOutcome
	// RemoveBrowserHost removes the browser native-messaging host.
	RemoveBrowserHost(dryRun bool) StepOutcome
}

// StepOutcome is what one teardown step did to one target.
type StepOutcome struct {
	Component string   `json:"component"`
	Kind      StepKind `json:"kind"`
	// Target names the tool, browser or file the outcome is about.
	Target string `json:"target"`
	// Changed is true when something was (or, in a dry run, would be)
	// removed.
	Changed bool `json:"changed"`
	// Detail lists what was removed, one entry per file or key.
	Detail []string `json:"detail,omitempty"`
	// NeedsAttention lists entries left in place because the file changed
	// since Observer wrote it; the operator removes them by hand.
	NeedsAttention []string `json:"needs_attention,omitempty"`
	// Command is the verb a StepManual step needs.
	Command string `json:"command,omitempty"`
	// Link and LinkLabel are the dashboard page that does a StepManual
	// step's undo (Step.Link), carried so a result list can offer it too.
	Link      string `json:"link,omitempty"`
	LinkLabel string `json:"link_label,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Options configures a Service.
type Options struct {
	// ConfigPath is the resolved global config.toml path. Required.
	ConfigPath string
	// Compiled overrides the binary's compiled node set (tests); nil means
	// components.Compiled.
	Compiled []string
	// Teardown runs teardown steps. Nil means previews still list the steps
	// but Apply reports them as not run.
	Teardown Teardowner
	// Audit records one metadata-only row per applied change (the action
	// name and a detail line naming ids, never a value). Nil = no audit.
	Audit func(ctx context.Context, action, detail string)
	// Purge is the store seam for typed purge plans. Nil = purge
	// unavailable (reported, never faked).
	Purge PurgeStore
	// Load overrides how the current block is read (tests). Nil reads the
	// ungoverned config at ConfigPath.
	Load func() (config.Config, error)
	// Governed returns the node's managed-governance input (the enrolment,
	// grant, verified node.components policy and local ceiling, read at the
	// cmd boundary). Nil means ungoverned: an individual node, exactly as
	// before. On an org-managed node every change that would narrow the
	// node is refused with a reason naming the organization (ledger
	// MODPKG-7, ruling D-434).
	Governed func(ctx context.Context) componentstate.Governed
	// Lock takes the cross-process advisory lock on a path and returns its
	// releaser. Apply holds it on ConfigPath across its read-modify-write of
	// the block, and PurgeExecute across the whole purge transaction, so a
	// purge's inactivity re-check and an Apply that re-activates the
	// component cannot interleave even when they run in different processes
	// (the CLI and the daemon's dashboard; ledger MODPKG-12). Nil means
	// internal/hook.LockSettingsFile, the lock every Observer writer of a
	// config file already takes.
	Lock func(path string) (func(), error)
}

// Service is the one writer of the [components] block.
type Service struct {
	opts Options
	// mu serialises Apply so two concurrent writers cannot interleave the
	// read-modify-write of the block.
	mu sync.Mutex
}

// New builds a Service.
func New(opts Options) (*Service, error) {
	if strings.TrimSpace(opts.ConfigPath) == "" {
		return nil, errors.New("componentsvc.New: ConfigPath is required")
	}
	return &Service{opts: opts}, nil
}

// Change is one requested edit of the selection.
type Change struct {
	// SetBase, when non-nil, replaces the base: "" or "all" for every
	// compiled component, or a prebuilt distro name.
	SetBase *string `json:"set_base,omitempty"`
	// Add activates ids (and removes them from the remove list).
	Add []string `json:"add,omitempty"`
	// Remove deactivates ids (and removes them from the add list). Every
	// selected component that requires a removed one is removed too and
	// listed in Preview.Cascade.
	Remove []string `json:"remove,omitempty"`
	// Reset clears add and remove before the rest of the change applies.
	Reset bool `json:"reset,omitempty"`
}

// Preview is the dry run of a Change.
type Preview struct {
	// Current and Proposed are the [components] blocks before and after.
	Current  config.ComponentsConfig `json:"current"`
	Proposed config.ComponentsConfig `json:"proposed"`
	// Activated and Deactivated are the effective-set differences.
	Activated   []string `json:"activated"`
	Deactivated []string `json:"deactivated"`
	// Cascade lists dependants removed with a requested removal.
	Cascade []string `json:"cascade"`
	// Teardown is the ordered teardown of every deactivated component.
	Teardown []Step `json:"teardown"`
	// Refused lists requested ids that cannot be honoured, with the reason.
	Refused []string `json:"refused"`
	// Issues are the proposed selection's problems (componentstate).
	Issues []string `json:"issues"`
	// RestartRequired is true when the effective set changes: the daemon
	// resolves it once at start.
	RestartRequired bool `json:"restart_required"`
	// Fingerprint binds an Apply to exactly this preview.
	Fingerprint string `json:"fingerprint"`
	// NoChange is true when the proposed block equals the current one.
	NoChange bool `json:"no_change"`
	// ManagedBy names the organization when this node is org-managed;
	// ManagedRefused then lists the parts of the change it refuses (a
	// distro, a removal, a reset, or an add the organization's policy
	// blocks). Apply refuses the whole change while it is non-empty.
	ManagedBy      string   `json:"managed_by,omitempty"`
	ManagedRefused []string `json:"managed_refused"`
}

// ApplyOptions parameterise Apply.
type ApplyOptions struct {
	// ExpectFingerprint, when set, must equal the fresh preview's
	// Fingerprint, or Apply refuses with ErrStalePreview.
	ExpectFingerprint string
	// SkipTeardown writes the selection but leaves every write a
	// deactivated component made in place (reported).
	SkipTeardown bool
	// DryRun computes everything and writes nothing.
	DryRun bool
	// Principal names who applied it in the audit row ("cli", "dashboard",
	// "init").
	Principal string
}

// ApplyResult reports what Apply did.
type ApplyResult struct {
	Preview  Preview       `json:"preview"`
	Wrote    bool          `json:"wrote"`
	Teardown []StepOutcome `json:"teardown"`
	// TeardownSkipped is true when no teardown ran (SkipTeardown, or no
	// Teardowner wired).
	TeardownSkipped bool `json:"teardown_skipped"`
}

// ErrStalePreview is returned when ExpectFingerprint does not match.
var ErrStalePreview = errors.New("componentsvc: the selection changed since the preview; preview again")

// ErrManagedByOrg is returned when Apply refuses a change on an org-managed
// node (ledger MODPKG-7, ruling D-434). The wrapped message names the
// organization and each refused part.
var ErrManagedByOrg = errors.New("componentsvc: this machine is managed by an organization")

// State resolves the current snapshot.
func (s *Service) State(ctx context.Context) (componentstate.Snapshot, error) {
	cfg, err := s.load()
	if err != nil {
		return componentstate.Snapshot{}, err
	}
	return componentstate.ResolveGoverned(cfg.Components, s.opts.Compiled, s.governed(ctx)), nil
}

// governed returns the governance input, the zero value when none is wired.
func (s *Service) governed(ctx context.Context) componentstate.Governed {
	if s.opts.Governed == nil {
		return componentstate.Governed{}
	}
	return s.opts.Governed(ctx)
}

// Preview computes what a Change would do, writing nothing.
func (s *Service) Preview(ctx context.Context, ch Change) (Preview, error) {
	cfg, err := s.load()
	if err != nil {
		return Preview{}, err
	}
	return s.preview(cfg.Components, ch, s.governed(ctx)), nil
}

func (s *Service) preview(cur config.ComponentsConfig, ch Change, g componentstate.Governed) Preview {
	before := componentstate.ResolveGoverned(cur, s.opts.Compiled, g)
	var managedRefused []string
	if g.OrgManaged {
		ch, managedRefused = managedChange(before, ch, g)
	}
	prop, refused, cascade := s.propose(before, cur, ch)
	after := componentstate.ResolveGoverned(prop, s.opts.Compiled, g)

	p := Preview{
		Current: canon(cur), Proposed: canon(prop),
		Refused: nonNil(refused), Cascade: nonNil(cascade), Issues: nonNil(after.Issues),
		Activated: []string{}, Deactivated: []string{}, Teardown: []Step{},
		ManagedRefused: nonNil(managedRefused),
	}
	if g.OrgManaged {
		p.ManagedBy = g.OrgLabel()
		p.Refused = append(p.Refused, managedRefused...)
		sort.Strings(p.Refused)
	}
	was, now := toSet(before.ActiveIDs()), toSet(after.ActiveIDs())
	for id := range now {
		if !was[id] {
			p.Activated = append(p.Activated, id)
		}
	}
	for id := range was {
		if !now[id] {
			p.Deactivated = append(p.Deactivated, id)
		}
	}
	sort.Strings(p.Activated)
	sort.Strings(p.Deactivated)
	if steps := teardownPlan(p.Deactivated); steps != nil {
		p.Teardown = steps
	}
	p.RestartRequired = len(p.Activated)+len(p.Deactivated) > 0
	p.NoChange = sectionKey(p.Current) == sectionKey(p.Proposed)
	h := sha256.New()
	h.Write([]byte(sectionKey(p.Current) + "\n=>\n" + sectionKey(p.Proposed)))
	p.Fingerprint = hex.EncodeToString(h.Sum(nil))[:24]
	return p
}

// managedChange splits a Change on an org-managed node (ledger MODPKG-7,
// ruling D-434) into the part that may apply and the refused parts, each a
// line naming the organization. Narrowing is refused outright (a base
// distro, a removal, a reset); an add is refused when the organization's
// policy or the local ceiling blocks the component, and otherwise kept (a
// component the policy allows may be selected locally, plan 6.2 row 6).
func managedChange(before componentstate.Snapshot, ch Change, g componentstate.Governed) (Change, []string) {
	var refused []string
	out := Change{}
	if ch.SetBase != nil {
		refused = append(refused, g.ManagedRefusal("select "+strings.TrimSpace(*ch.SetBase)))
	}
	if ch.Reset {
		refused = append(refused, g.ManagedRefusal("reset"))
	}
	for _, id := range ch.Remove {
		refused = append(refused, g.ManagedRefusal("remove "+id))
	}
	for _, id := range ch.Add {
		if d, ok := before.Decision(id); ok && d.State == components.StateBlocked {
			switch d.Reason {
			case components.ReasonPolicyDenied, components.ReasonPolicyUnlisted:
				refused = append(refused, fmt.Sprintf("add %s: blocked by the component policy of %s (%s); request it from your organization", id, g.OrgLabel(), d.Reason))
				continue
			case components.ReasonAboveCeiling:
				refused = append(refused, fmt.Sprintf("add %s: outside this machine's local component ceiling", id))
				continue
			}
		}
		out.Add = append(out.Add, id)
	}
	sort.Strings(refused)
	return out, refused
}

// propose applies a Change to a block. Removals cascade to every selected
// component whose requires closure reaches a removed one, so a removal is
// never silently overridden by the resolver.
func (s *Service) propose(before componentstate.Snapshot, cur config.ComponentsConfig, ch Change) (config.ComponentsConfig, []string, []string) {
	add := toSet(cur.Add)
	rem := toSet(cur.Remove)
	if ch.Reset {
		add, rem = map[string]bool{}, map[string]bool{}
	}
	out := config.ComponentsConfig{Distro: cur.Distro}
	var refused []string
	if ch.SetBase != nil {
		b := strings.TrimSpace(*ch.SetBase)
		switch {
		case b == "" || b == componentstate.BaseAll:
			out.Distro = ""
		case components.Distro(b).Valid():
			out.Distro = b
		default:
			refused = append(refused, fmt.Sprintf("base %q: not a prebuilt distro", b))
		}
	}
	for _, id := range ch.Add {
		if why := nodeIDProblem(id); why != "" {
			refused = append(refused, id+": "+why)
			continue
		}
		add[id] = true
		delete(rem, id)
	}
	var cascade []string
	removing := map[string]bool{}
	for _, id := range ch.Remove {
		if why := nodeIDProblem(id); why != "" {
			refused = append(refused, id+": "+why)
			continue
		}
		if c, _ := components.Get(id); c.Class == components.ClassCore {
			refused = append(refused, id+": core cannot be removed")
			continue
		}
		removing[id] = true
	}
	if len(removing) > 0 {
		// Dependants: every currently active component whose requires
		// closure reaches a removed id goes too.
		for _, id := range before.ActiveIDs() {
			if removing[id] {
				continue
			}
			for _, r := range requiresClosure(id) {
				if removing[r] {
					if c, _ := components.Get(id); c.Class != components.ClassCore {
						cascade = append(cascade, id)
					}
					break
				}
			}
		}
		for _, id := range cascade {
			removing[id] = true
		}
		for id := range removing {
			rem[id] = true
			delete(add, id)
		}
	}
	out.Add = sortedKeys(add)
	out.Remove = sortedKeys(rem)
	sort.Strings(cascade)
	sort.Strings(refused)
	return out, refused, cascade
}

// Apply previews ch again, refuses a stale preview, writes the block and
// runs the teardown of every deactivated component.
func (s *Service) Apply(ctx context.Context, ch Change, ao ApplyOptions) (ApplyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The cross-process half of the serialisation (ledger MODPKG-12): a
	// purge in another process holds the same lock across its transaction.
	// A dry run writes nothing and takes no lock.
	if !ao.DryRun {
		release, err := s.lockConfig()
		if err != nil {
			return ApplyResult{Teardown: []StepOutcome{}}, err
		}
		defer release()
	}
	cfg, err := s.load()
	if err != nil {
		return ApplyResult{}, err
	}
	p := s.preview(cfg.Components, ch, s.governed(ctx))
	res := ApplyResult{Preview: p, Teardown: []StepOutcome{}}
	if ao.ExpectFingerprint != "" && ao.ExpectFingerprint != p.Fingerprint {
		return res, ErrStalePreview
	}
	if len(p.ManagedRefused) > 0 {
		return res, fmt.Errorf("%w (%s): %s", ErrManagedByOrg, p.ManagedBy, strings.Join(p.ManagedRefused, "; "))
	}
	if len(p.Refused) > 0 && p.NoChange {
		return res, fmt.Errorf("componentsvc.Apply: nothing to apply: %s", strings.Join(p.Refused, "; "))
	}
	if !p.NoChange && !ao.DryRun {
		if err := writeSection(s.opts.ConfigPath, cfg, p.Proposed); err != nil {
			return res, err
		}
		res.Wrote = true
	}
	switch {
	case ao.SkipTeardown || s.opts.Teardown == nil:
		res.TeardownSkipped = len(p.Teardown) > 0
	default:
		res.Teardown = s.runTeardown(p.Teardown, ao.DryRun)
	}
	if res.Wrote && s.opts.Audit != nil {
		s.opts.Audit(ctx, "components.apply", fmt.Sprintf("principal=%s base=%s activated=%s deactivated=%s cascade=%s teardown_steps=%d teardown_skipped=%v",
			nonEmpty(ao.Principal, "cli"), nonEmpty(p.Proposed.Distro, componentstate.BaseAll),
			strings.Join(p.Activated, ","), strings.Join(p.Deactivated, ","), strings.Join(p.Cascade, ","),
			len(p.Teardown), res.TeardownSkipped))
	}
	return res, nil
}

// RunTeardown runs the teardown of components that are already inactive
// (for example after a hand edit of the block, or a teardown skipped at
// apply time). Active components are refused.
func (s *Service) RunTeardown(ctx context.Context, ids []string, dryRun bool) ([]StepOutcome, error) {
	if s.opts.Teardown == nil {
		return nil, errors.New("componentsvc.RunTeardown: no teardown is wired in this process")
	}
	snap, err := s.State(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if snap.Active(id) {
			return nil, fmt.Errorf("componentsvc.RunTeardown: %s is active; remove it first", id)
		}
	}
	out := s.runTeardown(teardownPlan(ids), dryRun)
	if !dryRun && s.opts.Audit != nil {
		s.opts.Audit(ctx, "components.teardown", "ids="+strings.Join(ids, ","))
	}
	return out, nil
}

func (s *Service) runTeardown(steps []Step, dryRun bool) []StepOutcome {
	out := []StepOutcome{}
	for _, st := range steps {
		switch st.Kind {
		case StepToolWiring:
			for _, o := range s.opts.Teardown.RemoveToolWiring(st.Tool, st.Parts, dryRun) {
				o.Component, o.Kind = st.Component, st.Kind
				out = append(out, o)
			}
		case StepBrowserHost:
			o := s.opts.Teardown.RemoveBrowserHost(dryRun)
			o.Component, o.Kind = st.Component, st.Kind
			out = append(out, o)
		case StepManual:
			o := StepOutcome{Component: st.Component, Kind: st.Kind, Target: st.Component, Command: st.Command, Link: st.Link, LinkLabel: st.LinkLabel, Detail: []string{st.What}}
			switch {
			case missingVerb(st):
				o.NeedsAttention = []string{standIn(st)}
			case st.Command != "":
				o.NeedsAttention = []string{"run `" + st.Command + "` to remove it"}
			}
			out = append(out, o)
		}
	}
	return out
}

// lockConfig takes the cross-process lock on the config file (Options.Lock,
// else internal/hook.LockSettingsFile).
func (s *Service) lockConfig() (func(), error) {
	lock := s.opts.Lock
	if lock == nil {
		lock = hook.LockSettingsFile
	}
	release, err := lock(s.opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("componentsvc: lock %s: %w", s.opts.ConfigPath, err)
	}
	return release, nil
}

func (s *Service) load() (config.Config, error) {
	if s.opts.Load != nil {
		return s.opts.Load()
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath, GovernanceSidecar: config.NoGovernanceSidecar})
	if err != nil {
		return config.Config{}, fmt.Errorf("componentsvc: load %s: %w", s.opts.ConfigPath, err)
	}
	return cfg, nil
}

// writeSection writes the block with comment-preserving structural patches
// (config.PatchFile). cfg is the ungoverned config the fallback
// re-serialize renders when the file does not exist yet.
func writeSection(path string, cfg config.Config, sec config.ComponentsConfig) error {
	next := cfg
	next.Components = sec
	cur := cfg.Components
	// A delete is emitted only for a key the file has: a structural delete
	// of an absent key is not surgical, and PatchFile would then re-render
	// the whole file and drop the operator's comments.
	var patches []config.Patch
	if !sec.Configured() {
		if !cur.Configured() {
			return nil
		}
		// An empty selection removes the whole table: the loaded config
		// omits a zero [components], so deleting key by key would leave an
		// empty table the surgical check rejects.
		patches = []config.Patch{{Path: []string{"components"}, Delete: true}}
	} else if sec.Distro != "" || cur.Distro != "" {
		patches = append(patches, structural([]string{"components", "distro"}, sec.Distro))
	}
	if sec.Configured() && (len(sec.Add) > 0 || len(cur.Add) > 0) {
		patches = append(patches, structuralList([]string{"components", "add"}, sec.Add))
	}
	if sec.Configured() && (len(sec.Remove) > 0 || len(cur.Remove) > 0) {
		patches = append(patches, structuralList([]string{"components", "remove"}, sec.Remove))
	}
	if len(patches) == 0 {
		return nil
	}
	if _, err := config.PatchFile(path, next, patches); err != nil {
		return fmt.Errorf("componentsvc: write [components]: %w", err)
	}
	return nil
}

func structural(path []string, v string) config.Patch {
	if v == "" {
		return config.Patch{Path: path, Delete: true}
	}
	return config.Patch{Path: path, Value: v}
}

func structuralList(path []string, v []string) config.Patch {
	if len(v) == 0 {
		return config.Patch{Path: path, Delete: true}
	}
	items := make([]any, len(v))
	for i, x := range v {
		items[i] = x
	}
	return config.Patch{Path: path, Value: items}
}

func nodeIDProblem(id string) string {
	c, ok := components.Get(id)
	switch {
	case !ok:
		return "not a component (observer components list shows the ids)"
	case c.Binary != components.BinaryNode:
		return "an org server component, not a node one"
	}
	return ""
}

func requiresClosure(id string) []string {
	seen := map[string]bool{}
	var walk func(string)
	var out []string
	walk = func(x string) {
		c, ok := components.Get(x)
		if !ok {
			return
		}
		for _, r := range c.Requires {
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
				walk(r)
			}
		}
	}
	walk(id)
	return out
}

func canon(c config.ComponentsConfig) config.ComponentsConfig {
	return config.ComponentsConfig{Distro: strings.TrimSpace(c.Distro), Add: uniqSorted(c.Add), Remove: uniqSorted(c.Remove)}
}

func sectionKey(c config.ComponentsConfig) string {
	c = canon(c)
	return c.Distro + "|" + strings.Join(c.Add, ",") + "|" + strings.Join(c.Remove, ",")
}

func toSet(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func sortedKeys(m map[string]bool) []string {
	out := []string{}
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func uniqSorted(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func nonNil(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
