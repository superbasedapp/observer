package sandboxsetup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
)

// Reasons the planner writes (copy keys a surface may show as served).
const (
	reasonOrgRefused     = "Your organization does not allow this backend on this machine (allowed_backends)."
	reasonGoverned       = "Set by your organization: the components on this machine are chosen by its policy."
	reasonNotChecked     = "Not checked yet: use Check this machine."
	reasonKillSwitch     = "Guided installs are turned off on this machine ([terminal.launch].allow_install), so this is shown as steps to follow."
	reasonElevationOff   = "Steps that need your password are off: turn on [terminal.sandbox.setup].allow_elevated in Settings to run this in a setup terminal, or run the command yourself."
	reasonPinUnavailable = "No verified download is available for this machine yet (the pin is not grounded, or downloads are not allowed here), so this is shown as steps to follow."
	// reasonManagedNoMirror is a grounded pinned download on a managed node
	// with no org mirror for it: never fetched from the vendor, placed from a
	// file the person names.
	reasonManagedNoMirror = "This machine is managed by your organization, which downloads sandbox tools only from its own mirror, and that mirror has none for this yet, so Observer never fetches it from the vendor here. Name a copy of the pinned file already on this machine (from_file) and Observer checks its sha256 and size before it places it."
	reasonNoRemedy        = "Observer knows no setup step for this on this machine; see the docs."
)

// reasonCheckStopped is the reason of a step a check could not judge because
// its verdict names no step: the check's own words.
func reasonCheckStopped(probeReason string) string {
	return "The check could not judge this step; it stopped at: " + strings.TrimSuffix(strings.TrimSpace(probeReason), ".") + "."
}

// reasonArgUnset is the reason of a command step whose argument comes from a
// config key that is not set to a usable value.
func reasonArgUnset(key string) string {
	return "Set " + configKeyLabel(key) + " to the image reference pinned by digest (name@sha256:<64 hex>), then check again; Observer runs this step with that value."
}

// configKeyLabel renders a dotted key as its TOML table and key
// ("terminal.sandbox.apple_container.image" reads
// "[terminal.sandbox.apple_container].image").
func configKeyLabel(key string) string {
	i := strings.LastIndex(key, ".")
	if i < 0 {
		return key
	}
	return "[" + key[:i] + "]." + key[i+1:]
}

// digestRefRE is the rule an argument from a config key must meet: an image
// reference pinned by digest, never a tag and never a flag (the config's own
// rule for the image keys, restated so this package stays a leaf).
var digestRefRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$`)

// argValue is the usable value of remedy's ArgKey ("" when the key is unset
// or its value is not a digest-pinned reference).
func argValue(in PlanInput, r Remedy) string {
	v := strings.TrimSpace(in.ArgValues[r.ArgKey])
	if !digestRefRE.MatchString(v) {
		return ""
	}
	return v
}

// planState is the working state Build's rules share.
type planState struct {
	in         PlanInput
	plan       *Plan
	orgRefused bool
	stop       bool
}

// planRule is one row of the ordered plan rule table.
type planRule struct {
	name  string
	apply func(s *planState)
}

// planRules is THE planner (plan section 3.3, rules 1 to 7), walked top-down;
// a rule that decides the plan sets stop. One test per row.
var planRules = []planRule{
	// Rule 1: a planned row is never set up.
	{"not_offered", func(s *planState) {
		if !s.in.Row.Offered() {
			s.plan.Blocked = "Planned for " + phaseOr(s.in.Row.Phase) + "; not offered in this release."
			s.stop = true
		}
	}},
	// Rule 2: the row does not run on this host.
	{"host", func(s *planState) {
		if s.in.Row.RunsOn(s.in.Host) {
			return
		}
		for _, r := range hostRefusalRules {
			if why := r.why(s.in.Row, s.in.Host); why != "" {
				s.plan.Blocked = why
				break
			}
		}
		s.stop = true
	}},
	// Rule 3: the org floor refuses the row: every step reads not_allowed.
	{"org_floor", func(s *planState) {
		s.orgRefused = !s.in.OrgAllowed
	}},
	// Rule 4: a probe-only row in this release.
	{"not_in_release", func(s *planState) {
		if s.in.Row.SetupUnavailable != "" {
			s.plan.Blocked = "Not available in this release: " + s.in.Row.SetupUnavailable + "."
			s.stop = true
		}
	}},
	// Rules 5 and 6: each step's state, then its class.
	{"steps", func(s *planState) {
		for _, id := range stepIDs(s.in.Row) {
			s.plan.Steps = append(s.plan.Steps, buildStep(s, id))
		}
	}},
	// Rule 7: Next, CanRun, CanUndo and Ready.
	{"gate", func(s *planState) {
		gate(s.in, s.plan)
	}},
}

// hostRefusalRule is one row of the ordered table that words why a row does
// not run on this host (rule 2), walked top-down, first non-empty wins.
type hostRefusalRule struct {
	name string
	why  func(row sandboxbackend.Capability, host sandboxbackend.HostKind) string
}

// hostRefusalRules: the row's own sentence, then a Windows row seen from a
// WSL daemon, then the generic sentence.
var hostRefusalRules = []hostRefusalRule{
	{"row_refusal", func(row sandboxbackend.Capability, host sandboxbackend.HostKind) string {
		return row.HostRefusal(host)
	}},
	{"windows_row_on_wsl", func(row sandboxbackend.Capability, host sandboxbackend.HostKind) string {
		if host == sandboxbackend.HostWSL2 && row.RunsOn(sandboxbackend.HostWindows) {
			return row.Label + " runs on native Windows, not inside WSL."
		}
		return ""
	}},
	{"generic", func(row sandboxbackend.Capability, host sandboxbackend.HostKind) string {
		return row.Label + " does not run on this host (" + string(host) + ")."
	}},
}

// Build plans a backend's setup on this host. It does no I/O.
func Build(in PlanInput) Plan {
	p := Plan{Backend: in.Row.ID, Label: in.Row.Label, Beta: in.Row.SetupBeta, Next: -1}
	s := &planState{in: in, plan: &p}
	for _, r := range planRules {
		r.apply(s)
		if s.stop {
			break
		}
	}
	p.Fingerprint = Fingerprint(p.Steps)
	return p
}

// stepIDs is the row's step order: the component first, the row's own
// Setup list, the enable step last.
func stepIDs(row sandboxbackend.Capability) []string {
	out := make([]string, 0, len(row.Setup)+2)
	out = append(out, PrereqComponent)
	out = append(out, row.Setup...)
	return append(out, PrereqEnable)
}

// stepCtx is what the per-step rules read.
type stepCtx struct {
	s         *planState
	p         Prereq
	remedy    Remedy
	hasRemedy bool
	fact      Fact
	hasFact   bool
	rec       Record
	hasRec    bool
	// probeMissing: the latest probe's verdict names this prerequisite.
	probeMissing bool
	// probeRungPassed: the latest probe stopped at a later rung of its
	// ladder, so it passed this prerequisite.
	probeRungPassed bool
}

// stateRule is one row of the ordered per-step state table (rule 5).
type stateRule struct {
	name  string
	match func(c stepCtx) (StepState, string, bool)
}

// stateRules decide a step's state, top-down, first match wins.
var stateRules = []stateRule{
	{"org_refused", func(c stepCtx) (StepState, string, bool) {
		return StateNotAllowed, reasonOrgRefused, c.s.orgRefused
	}},
	{"component_not_applicable", func(c stepCtx) (StepState, string, bool) {
		return StateNotApplicable, "", c.p.Kind == KindComponent && c.s.in.ComponentID == ""
	}},
	{"in_flight", func(c stepCtx) (StepState, string, bool) {
		return StateInFlight, "", c.hasRec && toolinstall.InFlight(c.rec.Status)
	}},
	{"component", func(c stepCtx) (StepState, string, bool) {
		if c.p.Kind != KindComponent {
			return "", "", false
		}
		switch {
		case c.s.in.ComponentSelected:
			return StateDone, "", true
		case c.s.in.ComponentGoverned:
			return StateBlocked, reasonGoverned, true
		}
		return StateMissing, "", true
	}},
	{"enable", func(c stepCtx) (StepState, string, bool) {
		if c.p.Kind != KindEnable {
			return "", "", false
		}
		if c.s.in.SandboxOn && c.s.in.Listed {
			return StateDone, "", true
		}
		return StateMissing, "", true
	}},
	{"probe_missing", func(c stepCtx) (StepState, string, bool) {
		if !c.probeMissing {
			return "", "", false
		}
		why := c.s.in.Probe.Reason
		if c.hasRemedy && c.remedy.Class == ClassNever {
			return StateBlocked, why, true
		}
		return StateMissing, why, true
	}},
	{"fact_not_applicable", func(c stepCtx) (StepState, string, bool) {
		return StateNotApplicable, c.fact.Reason, c.hasFact && c.fact.NotApplicable
	}},
	{"fact_too_old", func(c stepCtx) (StepState, string, bool) {
		if !c.hasFact || !c.fact.Present {
			return "", "", false
		}
		min := minVersion(c.p, c.s.in.Row)
		if min == "" || c.fact.Version == "" || !versionBelow(c.fact.Version, min) {
			return "", "", false
		}
		return StateMissing, "Found version " + c.fact.Version + "; this needs " + min + " or newer.", true
	}},
	{"fact_present", func(c stepCtx) (StepState, string, bool) {
		if !c.hasFact || !c.fact.Present {
			return "", "", false
		}
		return StateDone, betaNote(c.p, c.s.in.Row, c.fact.Version), true
	}},
	{"fact_absent", func(c stepCtx) (StepState, string, bool) {
		if !c.hasFact {
			return "", "", false
		}
		if c.hasRemedy && c.remedy.Class == ClassNever {
			return StateBlocked, c.fact.Reason, true
		}
		return StateMissing, c.fact.Reason, true
	}},
	{"probe_rung_passed", func(c stepCtx) (StepState, string, bool) {
		return StateDone, "", c.probeRungPassed
	}},
	{"probe_passes", func(c stepCtx) (StepState, string, bool) {
		p := c.s.in.Probe
		return StateDone, "", p != nil && p.Verdict == sandboxselect.VerdictAvailable
	}},
	// A check whose verdict names no step (a shape no prerequisite owns):
	// the steps it could not judge carry the check's own reason, never "not
	// checked yet".
	{"probe_unmapped", func(c stepCtx) (StepState, string, bool) {
		p := c.s.in.Probe
		if p == nil || p.Verdict == "" || p.Verdict == sandboxselect.VerdictAvailable || strings.TrimSpace(p.Reason) == "" {
			return "", "", false
		}
		if missingFromVerdict(c.s.in.Row.ID, p.Verdict, p.Reason) != "" {
			return "", "", false
		}
		return StateUnknown, reasonCheckStopped(p.Reason), true
	}},
	{"unknown", func(stepCtx) (StepState, string, bool) {
		return StateUnknown, reasonNotChecked, true
	}},
}

// classResult is what the class rules decide.
type classResult struct {
	class   Class
	channel Channel
	note    string
}

// classRule is one row of the ordered per-step class table (rule 6).
type classRule struct {
	name  string
	match func(c stepCtx, pin *Pin) (classResult, bool)
}

// classRules degrade a remedy's class by the switches in force, top-down,
// first match wins.
var classRules = []classRule{
	{"no_remedy", func(c stepCtx, _ *Pin) (classResult, bool) {
		return classResult{ClassGuide, ChNone, reasonNoRemedy}, !c.hasRemedy
	}},
	{"never", func(c stepCtx, _ *Pin) (classResult, bool) {
		return classResult{ClassNever, ChNone, ""}, c.remedy.Class == ClassNever
	}},
	{"already_guide", func(c stepCtx, _ *Pin) (classResult, bool) {
		return classResult{ClassGuide, ChNone, ""}, c.remedy.Class == ClassGuide
	}},
	{"kill_switch", func(c stepCtx, _ *Pin) (classResult, bool) {
		return classResult{ClassGuide, ChNone, reasonKillSwitch}, !c.s.in.AllowInstall
	}},
	{"elevation_off", func(c stepCtx, _ *Pin) (classResult, bool) {
		return classResult{ClassGuide, ChNone, reasonElevationOff}, c.remedy.Class == ClassElevated && !c.s.in.AllowElevated
	}},
	// A managed node with no org mirror (DownloadSource "") never fetches
	// from the vendor, yet a grounded pin can still be placed from a file
	// the person names: the step stays runnable for that, its consent reads
	// from_file, and the runner refuses a run that names no file.
	{"managed_no_mirror", func(c stepCtx, pin *Pin) (classResult, bool) {
		hit := c.remedy.Channel == ChPinned && pin != nil && pin.Status == PinGrounded && c.s.in.Managed && c.s.in.DownloadSource == ""
		return classResult{c.remedy.Class, ChPinned, reasonManagedNoMirror}, hit
	}},
	{"pin_unavailable", func(c stepCtx, pin *Pin) (classResult, bool) {
		bad := c.remedy.Channel == ChPinned && (pin == nil || pin.Status != PinGrounded || c.s.in.DownloadSource == "")
		return classResult{ClassGuide, ChNone, reasonPinUnavailable}, bad
	}},
	// A command whose last argument is a config key's value (Apple
	// container's image pull) runs only with that key set to a digest-pinned
	// reference; otherwise it is a guide that names the key, never a step
	// that reads runnable and is then refused.
	{"arg_unset", func(c stepCtx, _ *Pin) (classResult, bool) {
		return classResult{ClassGuide, ChNone, reasonArgUnset(c.remedy.ArgKey)}, c.remedy.ArgKey != "" && argValue(c.s.in, c.remedy) == ""
	}},
	{"as_declared", func(c stepCtx, _ *Pin) (classResult, bool) {
		return classResult{c.remedy.Class, c.remedy.Channel, ""}, true
	}},
}

// buildStep plans one step.
func buildStep(s *planState, id string) Step {
	p, ok := Lookup(id)
	if !ok {
		// An id the table does not hold (the coverage test forbids it):
		// shown, never runnable.
		return Step{Prereq: id, Label: id, State: StateUnknown, Class: ClassGuide, Channel: ChNone, Reason: reasonNoRemedy}
	}
	c := stepCtx{s: s, p: p}
	c.remedy, c.hasRemedy = remedyFor(p, s.in.Host, s.in.Family)
	c.fact, c.hasFact = s.in.Facts[id]
	c.rec, c.hasRec = s.in.Records[id]
	if pr := s.in.Probe; pr != nil {
		c.probeMissing = missingFromVerdict(s.in.Row.ID, pr.Verdict, pr.Reason) == id
		c.probeRungPassed = rungPassed(s.in.Row.ID, pr.Verdict, pr.Reason, id)
	}

	st := Step{Prereq: p.ID, Kind: p.Kind, Label: p.Label}
	for _, r := range stateRules {
		if state, why, hit := r.match(c); hit {
			st.State, st.Reason = state, why
			break
		}
	}
	if c.hasRec {
		rec := c.rec
		st.Record = &rec
	}

	var pin *Pin
	if c.hasRemedy && c.remedy.Channel == ChPinned {
		if got, ok := pinMatching(c.remedy.Package, goosOf(s.in.Host), s.in.Arch); ok {
			pin = &got
		}
	}
	var cr classResult
	for _, r := range classRules {
		if res, hit := r.match(c, pin); hit {
			cr = res
			break
		}
	}
	st.Class, st.Channel = cr.class, cr.channel
	if cr.note != "" && st.State != StateDone {
		st.Reason = joinSentences(st.Reason, cr.note)
	}
	if c.hasRemedy {
		st.Display, st.Docs, st.After, st.Disclosure = c.remedy.Display, c.remedy.Docs, c.remedy.After, c.remedy.Disclosure
		st.Package, st.Value, st.Action = c.remedy.Package, c.remedy.Value, c.remedy.Action
	}
	stepNotes(s.in, &st)
	if p.Kind == KindComponent {
		st.Package = s.in.ComponentID
	}
	commandDisplay(s, c, &st)
	if st.Channel == ChPinned && pin != nil {
		source := s.in.DownloadSource
		if source == "" {
			// managed_no_mirror: the only source is a file the person names.
			source = SourceFromFile
		}
		st.Consent = &Consent{Pin: pin.ID, Version: pin.Version, SHA256: pin.SHA256, Bytes: pin.Size, Source: source}
		if s.in.DownloadSource == SourceVendorRelease {
			st.Consent.URL = pin.URL
		}
	}
	return st
}

// commandDisplay sets a pm or command step's display, argv and whether the
// display is a command (DisplayIsCommand), from its remedy.
func commandDisplay(s *planState, c stepCtx, st *Step) {
	// A pm step shows (and, when runnable, runs) its derived command, also
	// when it degraded to a guide: the command is then the copyable step.
	if c.hasRemedy && c.remedy.Channel == ChPM {
		if pm, ok := pmForFamily(s.in.Family); ok {
			if _, argv, ok := toolinstall.InstallArgvFor(pm, []string{c.remedy.Package}); ok {
				st.Display = toolinstall.DisplayArgv(argv)
				st.DisplayIsCommand = true
				if st.Channel == ChPM {
					st.Argv = argv
				}
			}
		}
		if st.Channel == ChPM && st.Argv == nil {
			st.Class, st.Channel = ClassGuide, ChNone
		}
	}
	// A command remedy without an argument key shows its constant command,
	// also when it degraded to a guide (the command is then the copyable
	// step); one with an argument key shows a command only once the planner
	// derived it from a usable value.
	if c.hasRemedy && c.remedy.Channel == ChCommand && c.remedy.ArgKey == "" && len(c.remedy.Argv) > 0 {
		st.DisplayIsCommand = true
	}
	if c.hasRemedy && st.Channel == ChCommand {
		st.Argv = append([]string(nil), c.remedy.Argv...)
		if c.remedy.ArgKey != "" {
			// arg_unset made the step a guide without a usable value, so
			// the value here is a digest-pinned reference from the config.
			st.Argv = append(st.Argv, argValue(s.in, c.remedy))
			st.Display = toolinstall.DisplayArgv(st.Argv)
			st.DisplayIsCommand = true
		}
	}
}

// stepNotes adjusts a planned step's sentences: a never step's sentence
// says what is wrong, so once the step is done or does not apply here it is
// not shown, nor what to do after it. The enable
// step names no restart: its write takes effect in the running daemon
// (cmd/observer sandbox_live_apply.go), and the one case that still needs a
// restart (a daemon that did not confirm the apply) is said by the run.
func stepNotes(_ PlanInput, st *Step) {
	if (st.State == StateDone || st.State == StateNotApplicable) && st.Class == ClassNever {
		st.Display, st.After = "", ""
	}
}

// gate applies rule 7.
func gate(in PlanInput, p *Plan) {
	blockedBefore := false
	p.Next = -1
	nc := nextCtx{passiveEnabled: in.Probe == nil && enableDone(p.Steps)}
	for i := range p.Steps {
		st := &p.Steps[i]
		if p.Next < 0 && nextCandidate(nc, *st) {
			p.Next = i
		}
		st.CanRun = !blockedBefore && st.State == StateMissing && runnableClass(st.Class) && st.Channel != ChNone
		undo, rule, refused := undoDecision(in, *st)
		st.CanUndo = undo
		st.UndoRefused = refused
		// Reason is outside the fingerprint, so these notes never change it.
		if note := undoNote(in, *st, rule); note != "" {
			st.UndoNote = note
			st.Reason = joinSentences(st.Reason, note)
		}
		st.UndoAlso = undoAlso(in, *st)
		if st.State == StateBlocked || st.State == StateNotAllowed {
			blockedBefore = true
		}
	}
	probed := in.Probe != nil
	p.Ready = p.Blocked == "" && p.Next < 0 && probed && in.Probe.Verdict == sandboxselect.VerdictAvailable
	p.Unconfirmed = p.Blocked == "" && p.Next < 0 && !probed && len(p.Steps) > 0
}

// nextCtx is what the next rules read about the whole plan.
type nextCtx struct {
	// passiveEnabled: a passive plan (no probe) whose enable step is done:
	// the row is set up as far as Observer can see.
	passiveEnabled bool
}

// enableDone reports whether the plan's enable step is done.
func enableDone(steps []Step) bool {
	for _, st := range steps {
		if st.Kind == KindEnable {
			return st.State == StateDone
		}
	}
	return false
}

// nextRule is one row of the ordered table that decides whether a step can
// be the plan's Next, walked top-down, first match wins.
type nextRule struct {
	name string
	// match reports whether the row decides this step; next is its answer.
	match func(c nextCtx, st Step) (next, hit bool)
}

// nextRules, walked top-down:
//
//   - nothing_to_do: a done or not applicable step is never Next.
//   - unknown_on_enabled_row: in a passive plan of a row whose enable step
//     is done, a step only the check can judge (state unknown, whatever its
//     class: Apple container's service and image, an oci row's image) is
//     not Next, so the row reads "set up, not checked" (unconfirmed). A row
//     whose enable step is not done is genuinely not set up and still names
//     its unknown step; a step that is missing is Next whatever this says.
//   - unknown_not_ours: a step only the check can judge that Observer would
//     not do anyway (a never or guide step) is not Next, so Next never names
//     a step Observer does not do while there is one it can do.
//   - otherwise: every other step can be Next.
var nextRules = []nextRule{
	{"nothing_to_do", func(_ nextCtx, st Step) (bool, bool) {
		return false, st.State == StateDone || st.State == StateNotApplicable
	}},
	{"unknown_on_enabled_row", func(c nextCtx, st Step) (bool, bool) {
		return false, c.passiveEnabled && st.State == StateUnknown
	}},
	{"unknown_not_ours", func(_ nextCtx, st Step) (bool, bool) {
		return false, st.State == StateUnknown && !runnableClass(st.Class)
	}},
	{"otherwise", func(nextCtx, Step) (bool, bool) { return true, true }},
}

// nextCandidate walks nextRules for st.
func nextCandidate(c nextCtx, st Step) bool {
	for _, r := range nextRules {
		if next, hit := r.match(c, st); hit {
			return next
		}
	}
	return false
}

// undoNote is the sentence a step carries when the undo rule that decided it
// has one ("" otherwise).
func undoNote(in PlanInput, st Step, rule string) string {
	switch rule {
	case undoRuleSharedInUse:
		return keptReason(in.InUseBy[st.Prereq])
	case undoRuleDefaultBackend:
		return reasonDefaultBackend
	case UndoRefusedLiveRuns:
		return fmt.Sprintf(reasonLiveRunsFormat, in.LiveRuns)
	case UndoRefusedLiveRunsUnknown:
		return reasonLiveRunsUnknown
	case UndoRefusedKillSwitch:
		return reasonUndoKillSwitch
	case UndoRefusedElevationOff:
		return reasonUndoElevationOff
	}
	return ""
}

func runnableClass(c Class) bool {
	return c == ClassAuto || c == ClassTerminal || c == ClassElevated
}

// undoRule is one row of the ordered undo table (plan sections 4.8, 4.9):
// only what Observer did, never while a live run uses the row, never with
// the kill switch off.
type undoRule struct {
	name  string
	match func(in PlanInput, st Step) (undo, hit bool)
	// lift, set on a refusal row (a live run or a switch), is the input with
	// that refusal lifted. The row refuses only a step whose undo would be
	// offered without it; on any other step the lifted decision stands (a
	// step with nothing to undo says that, not that a switch refuses it).
	lift func(in *PlanInput)
}

var undoRules = []undoRule{
	{"not_done", func(_ PlanInput, st Step) (bool, bool) { return false, st.State != StateDone }, nil},
	{UndoRefusedLiveRuns, func(in PlanInput, _ Step) (bool, bool) { return false, in.LiveRuns > 0 }, func(in *PlanInput) { in.LiveRuns = 0 }},
	{UndoRefusedLiveRunsUnknown, func(in PlanInput, _ Step) (bool, bool) { return false, in.LiveRunsUnknown }, func(in *PlanInput) { in.LiveRunsUnknown = false }},
	{UndoRefusedKillSwitch, func(in PlanInput, _ Step) (bool, bool) { return false, !in.AllowInstall }, func(in *PlanInput) { in.AllowInstall = true }},
	// A shared prerequisite another listed row also sets up is never
	// removed while that row uses it (plan section 4.9); the component and
	// enable steps are this row's own.
	{undoRuleSharedInUse, func(in PlanInput, st Step) (bool, bool) {
		return false, sharedKeptByOthers(in, st)
	}, nil},
	// Removing the default backend from an otherwise empty list changes
	// nothing (the empty list falls back to it), so that undo is not offered.
	{undoRuleDefaultBackend, func(in PlanInput, st Step) (bool, bool) {
		return false, st.Kind == KindEnable && in.UnlistRelists
	}, nil},
	// The enable step's undo removes the row from backends.
	{"enable", func(_ PlanInput, st Step) (bool, bool) { return true, st.Kind == KindEnable }, nil},
	// The component step's undo is offered only when Observer recorded
	// selecting it and the organization does not govern components.
	{"component", func(in PlanInput, st Step) (bool, bool) {
		return st.Record != nil && !in.ComponentGoverned, st.Kind == KindComponent
	}, nil},
	{"no_record", func(_ PlanInput, st Step) (bool, bool) { return false, st.Record == nil }, nil},
	{"record_settled", func(_ PlanInput, st Step) (bool, bool) {
		return false, !toolinstall.Uninstallable(st.Record.Status)
	}, nil},
	{UndoRefusedElevationOff, func(in PlanInput, st Step) (bool, bool) {
		return false, st.Record.Elevated && !in.AllowElevated
	}, func(in *PlanInput) { in.AllowElevated = true }},
	{"package", func(_ PlanInput, st Step) (bool, bool) {
		return toolinstall.HasDefinedUninstall(st.Record.Channel), toolinstall.HasDefinedUninstall(st.Record.Channel)
	}, nil},
	{"placed_file", func(_ PlanInput, st Step) (bool, bool) {
		return st.Record.PlacedPath != "", st.Record.Channel == string(ChPinned)
	}, nil},
	{"config_or_content", func(_ PlanInput, st Step) (bool, bool) {
		ch := Channel(st.Record.Channel)
		return true, ch == ChConfig || ch == ChContent
	}, nil},
	{"otherwise", func(PlanInput, Step) (bool, bool) { return false, true }, nil},
}

// sharedKeptByOthers reports whether another set-up row's use keeps st: a
// shared prerequisite other than the row's own component and enable steps,
// and not NodeWide (one value every row reads: its undo changes it for all
// of them and says so, UndoAlso).
func sharedKeptByOthers(in PlanInput, st Step) bool {
	if st.Kind == KindComponent || st.Kind == KindEnable || len(in.InUseBy[st.Prereq]) == 0 {
		return false
	}
	p, ok := Lookup(st.Prereq)
	return !ok || !p.NodeWide
}

// SharedKeptByOthers is sharedKeptByOthers for the run layer, which reads
// the rows in use again at undo time (never from the plan shown).
func SharedKeptByOthers(in PlanInput, st Step) bool { return sharedKeptByOthers(in, st) }

// undoAlso is the sentence an offered undo of a NodeWide step carries when
// other set-up rows read the same value ("" otherwise).
func undoAlso(in PlanInput, st Step) string {
	others := in.InUseBy[st.Prereq]
	if !st.CanUndo || len(others) == 0 {
		return ""
	}
	if p, ok := Lookup(st.Prereq); !ok || !p.NodeWide {
		return ""
	}
	return "Undo changes this back for " + strings.Join(rowLabels(others), ", ") + " too: they use the same setting."
}

// The undo rules that carry a sentence (undoNote).
const (
	// undoRuleSharedInUse keeps a shared prerequisite.
	undoRuleSharedInUse = "shared_in_use"
	// undoRuleDefaultBackend refuses an enable undo that would change
	// nothing.
	undoRuleDefaultBackend = "default_backend"
)

// The closed Step.UndoRefused vocabulary: the refusal rows (a live run or a
// switch) that keep an undo Observer would otherwise offer. A surface maps
// each to "refused" (the CLI's exit 4), never to "nothing to undo".
const (
	// UndoRefusedLiveRuns: a live sandboxed run uses the backend.
	UndoRefusedLiveRuns = "live_runs"
	// UndoRefusedLiveRunsUnknown: no one could say whether a run is live (a
	// CLI whose daemon did not answer).
	UndoRefusedLiveRunsUnknown = "live_runs_unknown"
	// UndoRefusedKillSwitch: [terminal.launch].allow_install is off.
	UndoRefusedKillSwitch = "kill_switch"
	// UndoRefusedElevationOff: the undo needs a password and
	// [terminal.sandbox.setup].allow_elevated is off.
	UndoRefusedElevationOff = "elevation_off"
)

// The undo refusal sentences.
const (
	reasonDefaultBackend   = "This is the default backend: with it removed, [terminal.sandbox].backends is empty, which means this backend again, so there is nothing to undo here. To stop sandboxing, turn the sandbox off in Terminals > Settings > Sandbox isolation."
	reasonLiveRunsUnknown  = "Observer could not ask the running daemon whether a sandboxed run uses this backend, so it does not undo or update it from here. Try again when the daemon answers, or use the dashboard."
	reasonLiveRunsFormat   = "%d live sandboxed run(s) use this backend, so Observer does not undo this step now; end them or wait for them to finish first."
	reasonUndoKillSwitch   = "Guided installs are turned off on this machine ([terminal.launch].allow_install), so Observer does not undo this step."
	reasonUndoElevationOff = "Undoing this step needs your password: turn on [terminal.sandbox.setup].allow_elevated in Settings to undo it in a setup terminal, or undo it yourself."
)

// undoDecision walks undoRules top-down and returns the first hit's answer,
// the name of the rule that decided it ("" when none hit) and, when that
// rule is a refusal row keeping an undo Observer would otherwise offer, its
// name again as the refusal ("" otherwise).
func undoDecision(in PlanInput, st Step) (undo bool, rule, refused string) {
	for _, r := range undoRules {
		u, hit := r.match(in, st)
		if !hit {
			continue
		}
		if r.lift == nil {
			return u, r.name, ""
		}
		lifted := in
		r.lift(&lifted)
		wouldUndo, liftedRule, deeper := undoDecision(lifted, st)
		if wouldUndo || deeper != "" {
			return false, r.name, r.name
		}
		// Nothing to undo even with the refusal lifted: that decision
		// stands, with its own sentence.
		return false, liftedRule, ""
	}
	return false, "", ""
}

// keptReason is the sentence a shared prerequisite's step carries when its
// undo is refused, naming each other row by its registry label.
func keptReason(rows []string) string {
	return "Kept: also used by " + strings.Join(rowLabels(rows), ", ") + "."
}

// rowLabels names each row id by its registry label.
func rowLabels(rows []string) []string {
	labels := make([]string, 0, len(rows))
	for _, id := range rows {
		label := id
		if c, ok := sandboxbackend.Get(id); ok && c.Label != "" {
			label = c.Label
		}
		labels = append(labels, label)
	}
	return labels
}

// Fingerprint is the sha256 over each step's prereq, state, class, display
// and consent: the value a run request names, so a run against a plan that
// changed since it was shown is refused.
func Fingerprint(steps []Step) string {
	h := sha256.New()
	for _, st := range steps {
		parts := []string{st.Prereq, string(st.State), string(st.Class), st.Display}
		if c := st.Consent; c != nil {
			parts = append(parts, c.Pin, c.Version, c.SHA256, strconv.FormatInt(c.Bytes, 10), c.Source)
		}
		h.Write([]byte(strings.Join(parts, "\x1f")))
		h.Write([]byte{0x1e})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// minVersion is the version a found program must reach: the prerequisite's
// own, else the row's required minimum for its driver binary.
func minVersion(p Prereq, row sandboxbackend.Capability) string {
	if p.Detect.MinVersion != "" {
		return p.Detect.MinVersion
	}
	if p.Detect.DriverBinary {
		return row.Control.Pins.RequiredMin
	}
	return ""
}

// betaNote is the note of a driver binary found outside the row's tested
// range (selection treats it as beta, never refused).
func betaNote(p Prereq, row sandboxbackend.Capability, version string) string {
	pins := row.Control.Pins
	if !p.Detect.DriverBinary || version == "" || pins.TestedLow == "" || pins.TestedHigh == "" {
		return ""
	}
	if versionBelow(version, pins.TestedLow) || versionBelow(pins.TestedHigh, version) {
		return "Version " + version + " is outside the tested range (" + pins.TestedLow + " to " + pins.TestedHigh + "): beta here."
	}
	return ""
}

// versionBelow reports whether a is a readable version strictly below b. An
// unreadable version is never judged below (the probe judges it).
func versionBelow(a, b string) bool {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		return false
	}
	for i := range av {
		if av[i] != bv[i] {
			return av[i] < bv[i]
		}
	}
	return false
}

// parseVersion reads the last whitespace field of s ("bubblewrap 0.9.0",
// "v54.0").
func parseVersion(s string) ([3]int, bool) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return [3]int{}, false
	}
	return toolinstall.ParseRuntimeVersion(f[len(f)-1])
}

// goosOf is the GOOS a host runs.
func goosOf(h sandboxbackend.HostKind) string {
	switch h {
	case sandboxbackend.HostMacOS:
		return "darwin"
	case sandboxbackend.HostWindows:
		return "windows"
	}
	return "linux"
}

func phaseOr(phase string) string {
	if phase == "" {
		return "a later phase"
	}
	return "phase " + phase
}

// joinSentences joins two sentences, ending the first with a full stop
// when it has no closing punctuation (a probe's reason often has none), so
// two sentences never run together.
func joinSentences(a, b string) string {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	if !strings.ContainsAny(a[len(a)-1:], ".!?") {
		a += "."
	}
	return a + " " + b
}
