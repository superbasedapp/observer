//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_assess_ground.go is what the plan and the launch learn about the
// project and about the developer's choices on the plan (depth plan W3 and W4):
// the scope and the earlier run of a threat model, the facts read from the
// project's own files, the start command, the notes before the start, the
// tools in the box, the environment files, and the digest the task carries.
// It is built once for a request, by one function, and the plan and the launch
// both read the same value, so the task the developer read is the task that
// starts (G16).
//
// Only the project folder's own files are read (secassesssvc.Survey, never an
// environment file's contents) and the node's own findings store; nothing is
// sent anywhere.

// The refusals of the plan's choices. The words are the server's own sentence;
// the dialog shows it (web ASSESS_REFUSALS).
const (
	codeScopeInvalid    = "scope_invalid"
	codeStartInvalid    = "start_invalid"
	codeSecretFilesOpen = "secret_files_open"
	// codeFindingsUnreadable is the refusal of the Refuse setting when the
	// findings store could not be read: a control that cannot check does not
	// wave a run through.
	codeFindingsUnreadable = "findings_unreadable"
)

// securityAssessNone is the word that stands for "no comparison" (previous_run)
// and "no declared start command" (start): a choice made on purpose, as against
// a field left alone so that the default stands.
const securityAssessNone = secassess.StartNone

// securityAssessMaxScopeQuery bounds how many scope paths a request is read for;
// NormalizeScope refuses everything past its own limit by name.
const securityAssessMaxScopeQuery = 32

// securityAssessMaxRetestQuery bounds how many finding ids a retest request is
// read for; BuildRetestBasis refuses everything past its own limit by name.
const securityAssessMaxRetestQuery = 32

// securityAssessMaxGroundFindings is how many open findings the digest lists.
const securityAssessMaxGroundFindings = 20

// The findings reads page by securityAssessFindingsPage rows, at most
// securityAssessFindingsPages pages: the list for the digest stops at its 20
// rows, the secret check stops at the first environment or key file, and a read
// that runs out of pages before it has its answer says it is incomplete (which
// the Refuse setting treats as unreadable) instead of answering "none".
const (
	securityAssessFindingsPage  = 200
	securityAssessFindingsPages = 50
	securityAssessSecretsPage   = 500
	securityAssessSecretsPages  = 40
)

// securityAssessChoices are the developer's choices on the plan, as sent. A
// field left empty is a choice not made: the default stands.
type securityAssessChoices struct {
	ScopePaths []string
	ScopeNote  string
	// PreviousRun is a run id, securityAssessNone or "".
	PreviousRun string
	// Start is a plan's choice string, a typed command, securityAssessNone or "".
	Start string
	// Prepare says the developer ticked the selected plan's preparation steps
	// (a migrate, a seed) to run first. The default is off: they change local
	// data in the project, so they are never in the task unless chosen.
	Prepare bool
	// Objective is the developer's own objective for a red team exercise (cleaned
	// to at most secassess.MaxObjective characters; "" none). RetestOf is the
	// earlier run a retest replays and RetestFindings the finding ids chosen for
	// it, in order.
	Objective      string
	RetestOf       string
	RetestFindings []string
}

// securityAssessChoicesFromQuery reads the choices of a plan request.
func securityAssessChoicesFromQuery(q url.Values) securityAssessChoices {
	c := securityAssessChoices{
		ScopePaths: q["scope_path"], ScopeNote: q.Get("scope_note"),
		PreviousRun: strings.TrimSpace(q.Get("previous_run")), Start: strings.TrimSpace(q.Get("start")),
		Prepare:   strings.EqualFold(strings.TrimSpace(q.Get("prepare")), "yes"),
		Objective: q.Get("objective"), RetestOf: strings.TrimSpace(q.Get("of_run")), RetestFindings: q["finding"],
	}
	if len(c.ScopePaths) > securityAssessMaxScopeQuery {
		c.ScopePaths = c.ScopePaths[:securityAssessMaxScopeQuery]
	}
	if len(c.RetestFindings) > securityAssessMaxRetestQuery {
		c.RetestFindings = c.RetestFindings[:securityAssessMaxRetestQuery]
	}
	return c
}

// securityAssessHeldChoices are the choices a held run was asked for: they win
// over anything a later plan or launch says, so the run the organization
// approved is the run that starts. An empty recorded value means "none" for the
// two choices that have a default.
func securityAssessHeldChoices(r secassesssvc.Run) securityAssessChoices {
	c := securityAssessChoices{
		ScopePaths: r.ScopePaths, ScopeNote: r.ScopeNote, PreviousRun: r.PreviousRun, Start: r.Start, Prepare: r.Prepare,
		Objective: r.Objective, RetestOf: r.RetestOf, RetestFindings: r.RetestFindings,
	}
	if c.PreviousRun == "" {
		c.PreviousRun = securityAssessNone
	}
	if c.Start == "" {
		c.Start = securityAssessNone
	}
	return c
}

// securityAssessGroundIn is what the ground is built from.
type securityAssessGroundIn struct {
	Kind secassess.Kind
	Root string
	// Hash is the project's root hash; RunID the run being planned (left out of
	// the earlier-run options).
	Hash, RunID string
	Choices     securityAssessChoices
	Cfg         config.SecurityAssessmentsConfig
	// Tier is the sandbox network tier in force for the run.
	Tier string
	// TargetPort is the port of the target the developer confirmed (0 unknown);
	// the preflight warns when the start command listens elsewhere.
	TargetPort int
	// DefaultFindings makes a retest with no finding chosen take the ones it can
	// replay in full (secassess.DefaultRetestIDs): the plan's first answer. A
	// launch never does.
	DefaultFindings bool
}

// securityAssessGround is everything the plan and the launch learn about the
// project and the choices.
type securityAssessGround struct {
	kind secassess.Kind
	cfg  config.SecurityAssessmentsConfig
	// facts are the project's facts; surveyed says the folder could be read.
	facts    secassess.ProjectFacts
	surveyed bool

	// The threat model's scope and earlier run.
	scopePaths      []string
	scopeRefused    []secassess.ScopeRefusal
	scopeNote       string
	options         []secassesssvc.PreviousOption
	previous        string
	previousDefault string

	// The pen test's start command, notes, tools and environment files.
	starts []secassess.StartPlan
	start  secassess.StartSelection
	// prepare says the preparation steps of the selected plan are in the task:
	// the developer ticked them AND the selected plan has some.
	prepare bool
	notes   []secassess.Note
	tools   secassess.ToolFacts
	secret  secassess.SecretMode
	// secretIn is what secret was resolved from. The sandbox the run will use is
	// known only after the eligibility verdict, which comes after the ground, so
	// the ground resolves once with no sandbox (right for every mode but mask)
	// and resolveMask resolves again once the verdict names one (decision D32).
	secretIn secassess.SecretModeInput
	env      []string
	// probe is what the request helper does for this run (a kind that probes):
	// on, off (the setting) or withheld (python3 is known to be absent).
	probe secassesssvc.ProbePlan

	// The digest the task carries.
	mode      secassess.GroundingMode
	grounding secassess.Rendered

	// objective is the red team exercise's objective, cleaned (a kind that asks for
	// an exercise); retest is what a retest kind learned about the run it replays.
	objective string
	retest    *securityAssessRetestGround
}

// securityAssessExecutable says a file mode carries an execute bit. The probe runs
// for a Linux daemon only, where the bits are real; it is a variable so a test on
// another operating system (which has none) can stand in.
var securityAssessExecutable = func(m os.FileMode) bool { return m.Perm()&0o111 != 0 }

// securityAssessToolDirs are the folders the box's standard tools live in; the
// daemon looks there (and says so), it cannot look inside the box.
var securityAssessToolDirs = []string{"/usr/bin", "/usr/local/bin", "/bin"}

// securityAssessToolFacts says which of the tool table's commands are in the
// given folders. Only a Linux daemon can say (the box is a Linux sandbox that
// shares the host's folders); anywhere else every tool is unknown, never absent.
func securityAssessToolFacts(goos string, dirs []string) secassess.ToolFacts {
	if goos != "linux" {
		return nil
	}
	out := secassess.ToolFacts{}
	for _, row := range secassess.ToolRows {
		found := false
		for _, d := range dirs {
			// A regular file with an execute bit: a plain file named like a tool is
			// not the tool.
			if fi, err := os.Stat(filepath.Join(d, row.Command)); err == nil && fi.Mode().IsRegular() && securityAssessExecutable(fi.Mode()) {
				found = true
				break
			}
		}
		out[row.Command] = found
	}
	return out
}

// securityAssessToolsNow reads the tool inventory the plan and the launch use;
// it is a variable so a test can stand in for a Linux daemon's answer.
var securityAssessToolsNow = func() secassess.ToolFacts {
	return securityAssessToolFacts(runtime.GOOS, securityAssessToolDirs)
}

// securityAssessOwnRule says a finding came from an assessment import (its rule
// id is the module's own): those are not given back to the next assessment, so
// a model is not grounded on its own earlier output.
func securityAssessOwnRule(id string) bool {
	return strings.HasPrefix(id, "assess.") || strings.HasPrefix(id, "other/assess.")
}

// securityAssessGroundMode reads the grounding setting; a value this build does
// not know reads as full (the setting's loader refuses one).
func securityAssessGroundMode(a config.SecurityAssessmentsConfig) secassess.GroundingMode {
	switch secassess.GroundingMode(a.Grounding) {
	case secassess.GroundingOff, secassess.GroundingNoFindings:
		return secassess.GroundingMode(a.Grounding)
	}
	return secassess.GroundingFull
}

// securityAssessGround builds the ground of one request, once.
func (s *Server) securityAssessGround(ctx context.Context, st *store.Store, in securityAssessGroundIn) securityAssessGround {
	g := securityAssessGround{kind: in.Kind, cfg: in.Cfg, mode: securityAssessGroundMode(in.Cfg)}
	k := in.Kind
	if !k.Scopable && !k.Grounded && !k.Probing {
		return g
	}
	// A nil *store.Store must not become a non-nil interface: no store is
	// "cannot read", and the source says so by being nil.
	var src securityAssessFindingsSource
	if st != nil {
		src = st
	}
	if in.Root != "" {
		if survey, err := secassesssvc.Survey(ctx, in.Root); err == nil {
			g.facts, g.surveyed = secassess.AnalyzeProject(survey), true
		}
	}
	if k.Scopable {
		g.scopePaths, g.scopeRefused = secassess.NormalizeScope(in.Choices.ScopePaths)
		g.scopeNote = secassess.CleanScopeNote(in.Choices.ScopeNote)
		g.previousOptions(s, in)
	}
	if k.Probing {
		g.starts = secassess.PlanStarts(g.facts)
		g.start = secassess.SelectStart(g.starts, in.Choices.Start)
		g.prepare = in.Choices.Prepare && g.start.Plan != nil && len(g.start.Plan.Prepare) > 0
		g.env = append([]string{}, g.facts.EnvFiles...)
		g.tools = securityAssessToolsNow()
		g.probe = secassesssvc.PlanProbe(in.Cfg.ProbeHelper, g.tools)
	}
	if k.Exercise {
		g.objective = secassess.CleanObjective(in.Choices.Objective)
	}
	if k.Retest {
		g.retest = s.securityAssessRetestGroundOf(in, in.DefaultFindings)
	}
	var list securityAssessOpenList
	if k.Grounded && g.mode == secassess.GroundingFull {
		list = securityAssessReadOpenList(ctx, src, in.Hash)
	}
	if k.Probing {
		// Mask needs the run's sandbox to be able to hide files (decision D32),
		// which is known only after the eligibility verdict: until resolveMask
		// runs the setting resolves with no sandbox, to a warning. Only the Refuse
		// setting reads the findings store for this; when it does, a store that
		// cannot answer is a refusal, never "none".
		sm := secassess.SecretModeInput{Configured: in.Cfg.WorkspaceSecretMode, EnvFiles: len(g.env), Tier: in.Tier}
		if in.Cfg.WorkspaceSecretMode == secassess.SecretRefuse {
			state := securityAssessReadSecretState(ctx, src, in.Hash)
			sm.OpenSecret, sm.FindingsUnreadable, sm.Scan, sm.LastScan = state.OpenSecret, state.Unreadable, state.Scan, state.LastScan
		}
		g.secretIn = sm
		g.secret = secassess.EffectiveSecretMode(sm)
		g.notes = secassess.Preflight(g.facts, secassess.PreflightInput{
			Tier: in.Tier, Start: g.start.Plan, PrepareChosen: g.prepare, TargetPort: in.TargetPort,
		})
	}
	if k.Grounded {
		g.grounding = secassess.RenderGrounding(secassess.GroundingInput{
			Facts: g.facts, Starts: g.starts, Findings: list.Refs, FindingsTotal: list.Total, DepsDirect: g.facts.DepCount,
		}, g.mode, secassess.MaxGroundingBytes)
	}
	return g
}

// resolveMask resolves the environment-files mode again with what is known of
// the run's sandbox: the one place the setting meets the machine (decision D32).
// A kind that does not probe has no such mode and is left alone. The plan calls
// it after the eligibility verdict and the launch after it too, before anything
// reads secret.
func (g *securityAssessGround) resolveMask(c secassess.MaskCapability) {
	if !g.kind.Probing {
		return
	}
	g.secretIn.Mask = c
	g.secret = secassess.EffectiveSecretMode(g.secretIn)
}

// asksForMask says the launch asks the sandbox to hide the workspace's secret
// files: the mode in force is mask, which resolveMask gives only to a run whose
// sandbox can.
func (g securityAssessGround) asksForMask() bool {
	return g.kind.Probing && g.secret.Effective == secassess.SecretMask
}

// previousOptions fills the earlier runs a threat model can be compared with and
// the one in force: "" for "none", the run id the developer named (kept even when
// it is no longer an option, so the check says the earlier copy is gone instead
// of the run silently comparing with nothing), else the default (the newest
// checked run with the same scope). A string that is no run id at all (a
// hand-made request; the dialog sends ids it was given) is no choice.
func (g *securityAssessGround) previousOptions(s *Server, in securityAssessGroundIn) {
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	g.options, g.previousDefault = secassesssvc.PreviousChoices(runs.All(), runs.Side(), in.Hash, in.RunID, g.scopePaths)
	switch choice := in.Choices.PreviousRun; {
	case choice == securityAssessNone:
		g.previous = ""
	case choice == "":
		g.previous = g.previousDefault
	case secassess.ValidRunID(choice):
		g.previous = choice
	default:
		g.previous = g.previousDefault
	}
}

// refusal is the first choice that is refused, as the closed code and the
// sentence; code is "" when every choice is acceptable. The launch refuses a
// scope place that was not accepted (withScope); the plan shows it beside the
// scope instead and builds the task from the places that were.
func (g securityAssessGround) refusal(withScope bool) (code, reason string) {
	if withScope && len(g.scopeRefused) > 0 {
		r := g.scopeRefused[0]
		return codeScopeInvalid, "The scope place " + r.Path + " was not accepted. " + r.Reason
	}
	if g.start.Error != "" {
		return codeStartInvalid, g.start.Error
	}
	if g.kind.Retest {
		if g.retest != nil && g.retest.code != "" {
			return g.retest.code, g.retest.reason
		}
		if g.probe.Mode != secassess.HelperOn {
			return codeRetestHelper, reasonRetestHelper
		}
	}
	if g.secret.Refuse {
		if g.secret.Unreadable {
			return codeFindingsUnreadable, secassess.ReasonFindingsUnreadable
		}
		return codeSecretFilesOpen, secassess.ReasonSecretFilesOpen
	}
	return "", ""
}

// fill puts the ground into a prompt input: the one place the plan and the
// launch both do it.
func (g securityAssessGround) fill(in *secassess.PromptInput) {
	k := g.kind
	if k.Scopable {
		in.ScopePaths, in.ScopeNote = g.scopePaths, g.scopeNote
	}
	if k.Grounded {
		in.Grounding = g.grounding.Text
	}
	if k.Scopable || k.Probing {
		in.AIApp = g.facts.AIApp
		if g.surveyed {
			in.Facts = g.facts.AppFacts()
			in.SpecSummary = secassess.GroundingSpecLine(g.facts)
		}
	}
	if k.Probing {
		in.StartCommand, in.StartCwd, in.StartSource = g.start.Command, g.start.Cwd, g.start.Source
		in.Prepare = nil
		// The preparation steps are in the task only when the developer ticked
		// them (g.prepare is false when the selected plan has none).
		if g.prepare {
			for _, step := range g.start.Plan.Prepare {
				in.Prepare = append(in.Prepare, strings.Join(step, " "))
			}
		}
		in.EnvFiles, in.SecretMode = len(g.env), g.secret.Effective
		in.PaceRPS, in.RequestBudget = g.cfg.PentestPaceRPS, g.cfg.PentestRequestBudget
		in.Tools = g.tools
		in.Helper = g.probe.Mode == secassess.HelperOn
	}
	if k.Exercise {
		in.Objective = g.objective
	}
	if k.Retest && g.retest.usable() {
		in.Replay = g.retest.basis
	}
}

// record sets the choices a run keeps at launch: what the plan decided, not
// what the settings say later.
func (g securityAssessGround) record(run *secassesssvc.Run) {
	k := g.kind
	if k.Scopable {
		run.ScopePaths, run.ScopeNote, run.PreviousRun = g.scopePaths, g.scopeNote, g.previous
		if run.Sets != nil {
			run.Sets.AIApp = g.facts.AIApp
		}
	}
	if k.Probing {
		// The choice (not the bare command) is what round-trips: a held run
		// replays it through SelectStart and gets the same plan and folder. The
		// mode in force is the resolved one (mask acts as warn where the run's
		// sandbox cannot hide files, with the reason).
		run.Start, run.Prepare, run.SecretMode, run.SecretModeWhy = g.start.Choice, g.prepare, g.secret.Effective, g.secret.Why
		run.Helper = g.probe.Mode
		if run.Start == securityAssessNone {
			run.Start = "" // a declared none is no command: "" reads as none everywhere
		}
	}
	if k.Grounded {
		run.Grounding = string(g.mode)
	}
	if k.Exercise {
		run.Objective = g.objective
	}
	if k.Retest && g.retest.usable() {
		run.RetestOf, run.RetestFindings = g.retest.basis.Of, g.retest.basis.IDs()
	}
}

// ---- the plan's wire blocks ------------------------------------------------

type securityAssessScopeRefusalJS struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type securityAssessScopeJS struct {
	Dirs    []string                       `json:"dirs"`
	Paths   []string                       `json:"paths"`
	Note    string                         `json:"note"`
	Refused []securityAssessScopeRefusalJS `json:"refused,omitempty"`
	MaxPath int                            `json:"max_paths"`
	MaxNote int                            `json:"max_note"`
}

// securityAssessRunScopeJS is a run's recorded scope, as the runs list shows it.
type securityAssessRunScopeJS struct {
	Paths []string `json:"paths"`
	Note  string   `json:"note,omitempty"`
}

type securityAssessGroundingJS struct {
	Mode     string   `json:"mode"`
	Sections []string `json:"sections"`
	Bytes    int      `json:"bytes"`
	Dropped  int      `json:"dropped"`
	AIApp    bool     `json:"ai_app"`
}

type securityAssessPreviousJS struct {
	Options []secassesssvc.PreviousOption `json:"options"`
	// Selected is the run in force ("" none); Default the server's own pick.
	Selected string `json:"selected"`
	Default  string `json:"default_run"`
	Note     string `json:"note"`
}

type securityAssessStartPlanJS struct {
	Command string `json:"command"`
	// Choice is what the dialog sends back as `start` to select this plan (the
	// command, and its folder when the project's file names one); Cwd is that
	// folder.
	Choice  string   `json:"choice"`
	Cwd     string   `json:"cwd,omitempty"`
	Port    int      `json:"port,omitempty"`
	Source  string   `json:"source"`
	Prepare []string `json:"prepare,omitempty"`
	Needs   []string `json:"needs,omitempty"`
}

type securityAssessStartJS struct {
	Plans []securityAssessStartPlanJS `json:"plans"`
	// SelectedCommand is the CHOICE string in force (a plan's Choice, the typed
	// command, "none" or "" when nothing is chosen).
	SelectedCommand string `json:"selected_command"`
	Edit            string `json:"edit"`
	Edited          bool   `json:"edited"`
	Error           string `json:"error,omitempty"`
	NoneFound       bool   `json:"none_found"`
	// NotPreselected says the project names plans but none was chosen for the
	// developer (the likeliest plan's program is no well-known runner), so the
	// dialog shows the plans and asks.
	NotPreselected bool `json:"not_preselected,omitempty"`
	// Prepare says the selected plan's preparation steps are in the task: the
	// developer ticked them (the default is off).
	Prepare bool `json:"prepare"`
}

type securityAssessToolJS struct {
	ID      string `json:"id"`
	Purpose string `json:"purpose"`
	Command string `json:"command"`
	// Present is null when Observer could not tell.
	Present  *bool  `json:"present"`
	Guarded  bool   `json:"guarded"`
	Fallback string `json:"fallback"`
}

type securityAssessEnvJS struct {
	Files      []string `json:"files"`
	Count      int      `json:"count"`
	Configured string   `json:"configured"`
	Effective  string   `json:"effective"`
	// Downgrade is the closed word for why a configured mask acts as warn
	// (secassess.MaskDowngradeWhy); omitted when it does not.
	Downgrade string `json:"downgrade,omitempty"`
	Line      string `json:"line"`
}

type securityAssessSafetyJS struct {
	ID       string `json:"id"`
	Rule     string `json:"rule"`
	Prompt   bool   `json:"prompt"`
	Helper   string `json:"helper"`
	Observer string `json:"observer"`
	// ObserverKind is what the Observer cell does: "prevents", "detects",
	// "stops" or "" (nothing); the dialog words its pill from it.
	ObserverKind string `json:"observer_kind"`
	PromptOnly   bool   `json:"prompt_only"`
}

// previousNote is the sentence the plan gives about the comparison.
//
// What is true: Observer puts nothing from the earlier run in the task, and the
// task asks the agent not to open other runs' folders. The earlier run's files
// stay in the project's .observer/assessments folder, so that is a request, not
// a barrier (SECASSESS-7).
const securityAssessPreviousNote = "Observer gives the agent nothing from the earlier run and asks it not to open other runs' folders. That is a request, not a barrier: the earlier run's files stay in the project's .observer/assessments folder. Observer compares the two models itself once the new one is checked."

func (g securityAssessGround) scopeJS() *securityAssessScopeJS {
	if !g.kind.Scopable {
		return nil
	}
	js := &securityAssessScopeJS{
		Dirs: append([]string{}, g.facts.Dirs...), Paths: append([]string{}, g.scopePaths...), Note: g.scopeNote,
		MaxPath: secassess.MaxScopeChoices, MaxNote: secassess.MaxScopeNote,
	}
	for _, r := range g.scopeRefused {
		js.Refused = append(js.Refused, securityAssessScopeRefusalJS{Path: r.Path, Reason: r.Reason})
	}
	return js
}

func (g securityAssessGround) groundingJS() *securityAssessGroundingJS {
	if !g.kind.Grounded {
		return nil
	}
	return &securityAssessGroundingJS{
		Mode: string(g.mode), Sections: append([]string{}, g.grounding.Sections...), Bytes: len(g.grounding.Text),
		Dropped: g.grounding.Dropped, AIApp: g.facts.AIApp,
	}
}

func (g securityAssessGround) previousJS() *securityAssessPreviousJS {
	if !g.kind.Scopable {
		return nil
	}
	opts := g.options
	if opts == nil {
		opts = []secassesssvc.PreviousOption{}
	}
	return &securityAssessPreviousJS{Options: opts, Selected: g.previous, Default: g.previousDefault, Note: securityAssessPreviousNote}
}

func (g securityAssessGround) startJS() *securityAssessStartJS {
	if !g.kind.Probing {
		return nil
	}
	// A declared none reads as nothing selected (the dialog's none radio is its own
	// choice).
	selected := g.start.Choice
	if selected == securityAssessNone {
		selected = ""
	}
	js := &securityAssessStartJS{
		Plans: []securityAssessStartPlanJS{}, SelectedCommand: selected, Edit: g.start.Edit,
		Edited: g.start.Edited, Error: g.start.Error, NoneFound: len(g.starts) == 0,
		NotPreselected: g.start.NotPreselected, Prepare: g.prepare,
	}
	for _, p := range g.starts {
		row := securityAssessStartPlanJS{Command: p.Command(), Choice: p.Choice(), Cwd: p.Cwd, Port: p.Port, Source: p.Source, Needs: p.Needs}
		for _, step := range p.Prepare {
			row.Prepare = append(row.Prepare, strings.Join(step, " "))
		}
		js.Plans = append(js.Plans, row)
	}
	return js
}

func (g securityAssessGround) preflightJS() []secassess.Note {
	if !g.kind.Probing {
		return nil
	}
	if g.notes == nil {
		return []secassess.Note{}
	}
	return g.notes
}

func (g securityAssessGround) toolsJS() []securityAssessToolJS {
	if !g.kind.Probing {
		return nil
	}
	out := make([]securityAssessToolJS, 0, len(secassess.ToolRows))
	for _, r := range secassess.ToolRows {
		row := securityAssessToolJS{ID: r.ID, Purpose: r.Purpose, Command: r.Command, Guarded: r.Guarded, Fallback: r.Fallback}
		if have, known := g.tools[r.Command]; known {
			h := have
			row.Present = &h
		}
		out = append(out, row)
	}
	return out
}

// securityAssessMaskAudit is the audit line's words for what the workspace
// secret mask covered: a state word and counts, never a path.
func securityAssessMaskAudit(m secassess.MaskReport) []string {
	m = secassess.CleanMaskReport(m)
	switch {
	case !m.Reported:
		return []string{"secret_mask=unreported"}
	case m.Complete:
		return []string{"secret_mask=complete", "secret_masked=" + strconv.Itoa(m.Masked)}
	}
	return []string{"secret_mask=partial", "secret_masked=" + strconv.Itoa(m.Masked), "secret_mask_gaps=" + strconv.Itoa(m.Gaps)}
}

// securityAssessMaskReasonJS is one closed reason the mask left a place
// uncovered, with its count and the words for it.
type securityAssessMaskReasonJS struct {
	ID    string `json:"id"`
	Count int    `json:"count"`
	Words string `json:"words"`
}

// securityAssessMaskJS is what the workspace secret mask covered for a run, as
// the launch response and the run row carry it: counts, closed reasons and the
// sentence (Partial says some files may still be readable inside the box).
type securityAssessMaskJS struct {
	Reported bool                         `json:"reported"`
	Masked   int                          `json:"masked"`
	Complete bool                         `json:"complete"`
	Gaps     int                          `json:"gaps"`
	Reasons  []securityAssessMaskReasonJS `json:"reasons,omitempty"`
	Words    string                       `json:"words"`
	Partial  bool                         `json:"partial"`
}

// securityAssessMaskView is the wire form of a report, in the table's order.
func securityAssessMaskView(m secassess.MaskReport) securityAssessMaskJS {
	m = secassess.CleanMaskReport(m)
	words, partial := secassess.MaskWords(m)
	out := securityAssessMaskJS{Reported: m.Reported, Masked: m.Masked, Complete: m.Complete, Gaps: m.Gaps, Words: words, Partial: partial}
	for _, row := range secassess.MaskGapReasons {
		if n := m.Reasons[row.ID]; n > 0 {
			out.Reasons = append(out.Reasons, securityAssessMaskReasonJS{ID: row.ID, Count: n, Words: row.Words})
		}
	}
	return out
}

// securityAssessMaskReportOf is the report of a launch that asked for the mask:
// the outcome the launcher gave (counts and closed reasons), or a report that
// says nothing came back.
func securityAssessMaskReportOf(o *SecretMaskOutcome) secassess.MaskReport {
	if o == nil {
		return secassess.MaskReport{}
	}
	return secassess.CleanMaskReport(secassess.MaskReport{Reported: true, Masked: o.Masked, Complete: o.Complete, Gaps: o.Gaps, Reasons: o.Reasons})
}

func (g securityAssessGround) envJS() *securityAssessEnvJS {
	if !g.kind.Probing {
		return nil
	}
	line := g.secret.Words
	if g.secret.TierWords != "" {
		line = strings.TrimSpace(line + " " + g.secret.TierWords)
	}
	return &securityAssessEnvJS{
		Files: append([]string{}, g.env...), Count: len(g.env),
		Configured: g.secret.Configured, Effective: g.secret.Effective, Downgrade: g.secret.Why, Line: line,
	}
}

// securityAssessSafetyView is the safety table for a run: the Helper column
// holds only when the request helper is written for it.
func securityAssessSafetyView(k secassess.Kind, f secassess.SafetyFacts) []securityAssessSafetyJS {
	if !k.Probing {
		return nil
	}
	rows := secassess.SafetyRowsWith(f)
	out := make([]securityAssessSafetyJS, 0, len(rows))
	for _, r := range rows {
		out = append(out, securityAssessSafetyJS{
			ID: r.ID, Rule: r.Rule, Prompt: r.Prompt, Helper: r.Helper, Observer: r.Observer, ObserverKind: string(r.ObserverKind),
			PromptOnly: r.PromptOnly(),
		})
	}
	return out
}

// securityAssessProbeJS is the plan's request helper block: whether Observer
// writes the helper into the run folder and with what limits.
type securityAssessProbeJS struct {
	// State is on, off (the setting) or withheld (python3 is known to be absent
	// from the box's standard folders).
	State string `json:"state"`
	// Files are the two files written into the run folder (state on).
	Files []string `json:"files,omitempty"`
	// Dir is the run folder, relative to the project.
	Dir string `json:"dir"`
	// WithheldReason is the server's sentence for a helper left out.
	WithheldReason string `json:"withheld_reason,omitempty"`
	// Budget and PaceRPS are the limits the helper's settings file carries.
	Budget  int `json:"budget"`
	PaceRPS int `json:"pace_rps"`
}

// probeJS is the plan's helper block, nil for a kind that does not probe.
func (g securityAssessGround) probeJS(runID string) *securityAssessProbeJS {
	if !g.kind.Probing {
		return nil
	}
	js := &securityAssessProbeJS{
		State: g.probe.Mode, Dir: secassess.ResultPaths(runID).Dir, WithheldReason: g.probe.Reason,
		Budget: g.cfg.PentestRequestBudget, PaceRPS: g.cfg.PentestPaceRPS,
	}
	if g.probe.Mode == secassess.HelperOn {
		js.Files = []string{secassess.FileProbeHelper, secassess.FileProbeConfig}
	}
	return js
}

// securityAssessChoicesDetail is the launch line's section for the plan's
// choices: counts and words only, never a path, a note or a command ("" for a
// run whose kind has none).
func securityAssessChoicesDetail(run secassesssvc.Run) string {
	k, ok := secassess.KindByID(run.Kind)
	if !ok || (!k.Scopable && !k.Probing) {
		return ""
	}
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	parts := []string{"choices"}
	if k.Scopable {
		parts = append(parts, "scope_paths="+strconv.Itoa(len(run.ScopePaths)), "scope_note="+yes(run.ScopeNote != ""), "previous="+yes(run.PreviousRun != ""))
	}
	if k.Probing {
		start := "none"
		if run.Start != "" {
			start = "declared"
		}
		parts = append(parts, "start="+start, "prepare="+yes(run.Prepare))
		// The mode IN FORCE (mask acts as warn), beside the configured one the
		// settings section carries: the audit row says what happened, not only
		// what the setting asked for. A downgrade carries its closed reason word,
		// and a run that asked the sandbox to hide files carries what the mask
		// covered, as counts: never a path.
		if run.SecretMode != "" {
			parts = append(parts, "secret_mode_in_force="+securityAssessAuditWord(run.SecretMode))
		}
		if run.SecretModeWhy != "" {
			parts = append(parts, "secret_mode_downgrade="+securityAssessAuditWord(run.SecretModeWhy))
		}
		if run.SecretMask != nil {
			parts = append(parts, securityAssessMaskAudit(*run.SecretMask)...)
		}
		// The request helper's mode in force: off (the setting) and withheld
		// (python3 was not seen) read differently, and the settings section
		// carries only the setting.
		if run.Helper != "" {
			parts = append(parts, "helper="+securityAssessAuditWord(run.Helper))
		}
	}
	// Whether an objective was given and how many findings a retest replays:
	// a word and a count, never the objective or an id.
	if k.Exercise {
		parts = append(parts, "objective="+yes(run.Objective != ""))
	}
	if k.Retest {
		parts = append(parts, "retest_findings="+strconv.Itoa(len(run.RetestFindings)))
	}
	return strings.Join(parts, " ")
}

// securityAssessTypedPort is the port of the target the developer typed, 0 when
// there is none or it does not parse (the preflight then says nothing about it).
func securityAssessTypedPort(raw string) int {
	if raw == "" {
		return 0
	}
	t, err := secassess.ParseTarget(raw)
	if err != nil {
		return 0
	}
	return t.PortNumber()
}
