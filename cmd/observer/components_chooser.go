package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/feasibility"
	"github.com/marmutapp/superbased-observer/internal/feasibility/nodefeas"
)

// components_chooser.go is the install-time component chooser (modular
// packaging plan 7.1, lane MP-DASH): the first interactive `observer init`
// on a machine with no [components] selection asks what Observer should run
// before any wiring, with the init checklist's semantics (nothing is written
// without a yes). Three steps: which AI tools (detected ones pre-selected),
// which feature groups (each with a one-line summary of what it adds), and
// a summary of every listener, outbound host and vendor file the selection
// implies, then one confirm. Declining keeps today's behaviour: the binary's
// own defaults stay active.

// chooserGroup is one step-2 feature group: the components it covers.
type chooserGroup struct {
	Label string
	IDs   []string
}

// chooserGroups is the step-2 table, in the order the plan names them
// (Capture is step 1). Table-driven: a group is a row. The system service is
// a row of its own (T-734): it is off in every distro, so without it the
// documented `observer service install --now` refused on a machine whose
// chooser never offered it. Browser chat capture is a row too (D-561): it
// was never asked, so capture.browser stayed on unless the operator ran
// `observer components remove capture.browser`; the row carries the
// browser-chat adapters the catalog bundles with it, so a "no" turns the
// listener and its five site adapters off together (step 1 leaves those
// adapters to this row).
//
// An optional module's row lists its ROOT only, never its drivers (lane
// OPTMOD; the sandbox plan's proposed `withDependents` helper is not needed
// and would be wrong here). A "no" removes the root, and componentsvc's
// removal cascade takes every active component that Requires it along
// (TestRemovingAModuleRootDeactivatesEveryDependent pins that), so one "no"
// leaves the module and every driver inactive. A "yes" adds what the row
// lists that the base leaves off, so expanding the row to every dependant
// would turn on drivers that are meant to stay off until chosen one by one.
// withBundles stays right for capture.browser: Bundles are compiled and
// chosen together by definition.
var chooserGroups = []chooserGroup{
	{"Proxy and compression", []string{"capture.proxy", "proxy.compression", "proxy.routing", "integration.proxy-route"}},
	{"Terminals", []string{"terminals", "terminals.ssh", "remote"}},
	// The sandbox module (sandbox plan v2 section 11.2): its own row, the
	// plain module root, unchecked by default. A "yes" also activates the
	// isolation engine it Requires (the resolver adds required rows); a
	// "no" leaves the module and every driver inactive.
	{"Sandboxes and VMs", []string{"terminals.sandbox"}},
	{"Code intelligence", []string{"codeintel"}},
	// The security pillar's module root only (lane OPTMOD rule above): a
	// "no" cascades to every security.* child.
	{"Code security", []string{"security"}},
	{"Browser chat capture", withBundles("capture.browser")},
	{"Org and updates", []string{"org.client", "org.update", "agentaccess.relay"}},
	{"Telemetry", []string{"ingest.otlp", "export.otel", "processobs"}},
	{"Cloud", []string{"cloud.intelligence"}},
	{"Start at login (system service)", []string{"integration.service"}},
}

// withBundles is id followed by the components the catalog bundles with it
// (one owner of that list: components.Component.Bundles).
func withBundles(id string) []string {
	out := []string{id}
	if c, ok := components.Get(id); ok {
		out = append(out, c.Bundles...)
	}
	return out
}

// chooserGroupCovered reports whether a step-2 row decides id, so step 1
// does not also turn it off.
func chooserGroupCovered(id string) bool {
	for _, g := range chooserGroups {
		for _, x := range g.IDs {
			if x == id {
				return true
			}
		}
	}
	return false
}

// chooserPlan is what the chooser starts from (T-731, D-551): the base it
// writes, the ids that base turns on, and whether the organization governs
// the node. Before T-731 the base was a hard-coded developer, so a minimal
// binary wrote `distro = "developer"` and a full one lost its own defaults.
type chooserPlan struct {
	// Base is the distro written to [components]; "" writes none (a custom
	// build keeps its manifest default, a managed node cannot change it).
	Base string
	// On is the set the base turns on.
	On map[string]bool
	// Managed reports an org-managed node: a local choice may widen it but
	// never narrow it (D-434), so every "turn off" is disabled up front
	// (T-737, D-514) instead of being refused at the summary.
	Managed bool
	// OrgRefusal is the one reason a managed node gives for a narrowing.
	OrgRefusal string
}

// chooserPlanFor resolves the plan from the unconfigured snapshot: the
// binary's own distro (the stamped one, else the prebuilt distro its
// compiled set matches; the unstamped release is full), a custom build's
// manifest default, or the governed active set on a managed node.
func chooserPlanFor(snap componentstate.Snapshot) chooserPlan {
	if snap.Governed.OrgManaged {
		return chooserPlan{
			On: toIDSet(snap.ActiveIDs()), Managed: true,
			OrgRefusal: fmt.Sprintf("managed by %s, which decides which components run; a local change cannot narrow it", snap.Governed.OrgLabel()),
		}
	}
	d := components.Distro(snap.Base)
	if !d.Valid() {
		d = components.DistroOf(snap.Compiled)
	}
	if d.Valid() {
		return chooserPlan{Base: string(d), On: toIDSet(componentstate.BaseSet(d))}
	}
	return chooserPlan{On: toIDSet(snap.ActiveIDs())}
}

func toIDSet(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// splitOn splits ids into the ones the base already turns on and the rest.
func (pl chooserPlan) splitOn(ids []string) (on, off []string) {
	for _, id := range ids {
		if pl.On[id] {
			on = append(on, id)
		} else {
			off = append(off, id)
		}
	}
	return on, off
}

// groupAdds summarises what a group adds, from the catalog: listeners,
// outbound hosts and other tools' config files.
func groupAdds(ids []string) string {
	var ports, hosts, vendor []string
	seen := map[string]bool{}
	add := func(dst *[]string, v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			*dst = append(*dst, v)
		}
	}
	for _, id := range ids {
		c, ok := components.Get(id)
		if !ok {
			continue
		}
		for _, l := range c.Surface.Listeners {
			add(&ports, l.Addr)
		}
		for _, e := range c.Surface.Egress {
			add(&hosts, e.Host)
		}
		for _, v := range c.Surface.VendorConfigs {
			add(&vendor, v)
		}
	}
	var parts []string
	if len(ports) > 0 {
		parts = append(parts, "listens on "+strings.Join(ports, ", "))
	}
	if len(hosts) > 0 {
		parts = append(parts, "talks to "+strings.Join(hosts, ", "))
	}
	if len(vendor) > 0 {
		parts = append(parts, fmt.Sprintf("edits %d other-tool config file(s)", len(vendor)))
	}
	if len(parts) == 0 {
		return "no listener, no network, no other tool's files"
	}
	return strings.Join(parts, "; ")
}

// chooserService is the part of componentsvc.Service the chooser uses.
type chooserService interface {
	State(ctx context.Context) (componentstate.Snapshot, error)
	Preview(ctx context.Context, ch componentsvc.Change) (componentsvc.Preview, error)
	Apply(ctx context.Context, ch componentsvc.Change, ao componentsvc.ApplyOptions) (componentsvc.ApplyResult, error)
}

// chooserPending reports a selection that holds only adds (no distro, no
// remove) on a node whose base the chooser can record: the shape the
// installer's service offer writes (`components add integration.service`)
// before the first `observer init` (T-745). The chooser still runs there,
// with those adds preselected, and records the base; before T-745 any block
// at all skipped it, so the documented install -> y -> init flow never showed
// the chooser and recorded no distro. A block that names a distro or a
// remove is a recorded choice; a managed node or a custom build (no base to
// record) keeps the block as it is.
func chooserPending(snap componentstate.Snapshot, plan chooserPlan) (preselected []string, pending bool) {
	if !snap.Configured || snap.BlockDistro != "" || len(snap.Remove) > 0 || len(snap.Add) == 0 || plan.Base == "" {
		return nil, false
	}
	return append([]string(nil), snap.Add...), true
}

// runComponentChooser asks the three steps and writes the selection on a
// yes. It does nothing when a selection already exists, unless that
// selection is only installer-written adds (chooserPending). detected lists
// the AI tools init found.
//
//nolint:gocyclo // the three steps read top to bottom; each branch is one question shape.
func runComponentChooser(ctx context.Context, out io.Writer, p *initPrompter, svc chooserService, detected []string) error {
	snap, err := svc.State(ctx)
	if err != nil {
		return nil
	}
	plan := chooserPlanFor(snap)
	preselected, choicePending := chooserPending(snap, plan)
	if snap.Configured && !choicePending {
		return nil
	}
	fmt.Fprintln(out, "observer init - choose what Observer runs on this machine")
	fmt.Fprintf(out, "(change this later %s; nothing is written without a yes.)\n", components.WhereToChange("`observer components select`"))
	if len(preselected) > 0 {
		// What the installer (or an earlier `components add`) turned on is
		// kept and asked as on; a "no" below still turns it off.
		fmt.Fprintf(out, "  already turned on: %s (kept unless you answer no below)\n", strings.Join(preselected, ", "))
		for _, id := range preselected {
			plan.On[id] = true
		}
	}

	// Every component's feasibility verdict (D-514): a group whose
	// components cannot be chosen here is shown disabled with the reason,
	// never asked.
	verdicts := map[string]feasibility.Verdict{}
	for _, v := range nodefeas.ComponentVerdicts(snap.Result.Decisions, snap.Selected) {
		verdicts[v.ID] = v
	}

	// The questions, in order. Each answer is kept so "b" (back) can step to
	// the previous one and the change is rebuilt from the answers at the end.
	var qs []chooserQuestion

	// Step 1: AI tools. A detected tool the base leaves off is turned on
	// (T-731: a minimal build could not capture the tool it detected), and
	// the base's other adapters go inactive when the operator says so.
	have := map[string]bool{}
	for _, t := range detected {
		have[clientwire.HookTargetBase(t)] = true
	}
	var others, turnOn []string
	for _, c := range components.ForBinary(components.BinaryNode) {
		if c.Class != components.ClassAdapter || chooserGroupCovered(c.ID) {
			continue // not a tool adapter, or a step-2 row decides it
		}
		tool := strings.TrimPrefix(c.ID, "adapter.")
		v, known := verdicts[c.ID]
		feasible := !known || v.Feasible
		switch {
		case have[tool] && !plan.On[c.ID] && feasible:
			turnOn = append(turnOn, c.ID)
		case !have[tool] && plan.On[c.ID]:
			others = append(others, c.ID)
		}
	}
	if plan.Managed {
		// D-514 / T-737: narrowing is not a choice here; say so before asking.
		others = nil
	}
	step1 := []string{"\n1. Which AI tools do you use?"}
	if len(have) > 0 {
		tools := make([]string, 0, len(have))
		for t := range have {
			tools = append(tools, t)
		}
		sort.Strings(tools)
		step1 = append(step1, fmt.Sprintf("  detected: %s", strings.Join(tools, ", ")))
	}
	if plan.Managed {
		step1 = append(step1, fmt.Sprintf("  the other adapters stay as they are (%s)", plan.OrgRefusal))
	}
	if len(others) > 0 || len(turnOn) > 0 {
		on, rest := append([]string(nil), turnOn...), append([]string(nil), others...)
		var text string
		switch {
		case len(on) > 0 && len(rest) > 0:
			text = fmt.Sprintf("Capture only the detected tools (turns on %s; the other %d adapters stay installed but inactive)?", strings.Join(on, ", "), len(rest))
		case len(on) > 0:
			text = fmt.Sprintf("Capture the detected tools (turns on %s)?", strings.Join(on, ", "))
		default:
			text = fmt.Sprintf("Capture only the detected tools (the other %d adapters stay installed but inactive)?", len(rest))
		}
		qs = append(qs, chooserQuestion{
			header: step1,
			text:   text,
			def:    len(have) > 0,
			yes: func(ch *componentsvc.Change) {
				ch.Add = append(ch.Add, on...)
				ch.Remove = append(ch.Remove, rest...)
			},
		})
	} else {
		for _, l := range step1 {
			fmt.Fprintln(out, l)
		}
	}

	// Step 2: feature groups, from the verdict rows. A group's "yes" adds
	// only what the base leaves off when the base turns none of it on, and
	// adds nothing when the base already turns some of it on (T-733: a "Y"
	// used to add every feasible id of the group, so accepting the
	// developer defaults turned on proxy.routing, remote, terminals.sandbox
	// and more, and listed already-on ids in `add`). "No" removes only what
	// the base turns on. An unavailable group's line is printed under the
	// step 2 header, never under step 1 (T-732). Step 2 is ONE checklist
	// (D-571, lane PICKERS-2): every group shown at once, [x] or [ ] from
	// the base, toggled by number, accepted with enter.
	var trailer []string
	groupStart := len(qs)
	for _, g := range chooserGroups {
		ok, notes := splitFeasible(g.IDs, verdicts)
		if len(ok) == 0 {
			trailer = append(trailer, fmt.Sprintf("  %s: unavailable here (%s)", g.Label, strings.Join(notes, "; ")))
			continue
		}
		on, off := plan.splitOn(ok)
		var yes, no func(*componentsvc.Change)
		def := len(on) > 0
		addOff := func(ch *componentsvc.Change) { ch.Add = append(ch.Add, off...) }
		switch {
		case plan.Managed:
			// Only a widening is a choice: offer what is off, never a "no"
			// that the organization would refuse.
			if len(off) > 0 {
				yes, def = addOff, false
			}
		case len(on) > 0:
			rm := on
			no = func(ch *componentsvc.Change) { ch.Remove = append(ch.Remove, rm...) }
		default:
			yes = addOff
		}
		if plan.Managed && yes == nil {
			// On, and a managed node cannot turn it off: say so, do not ask.
			trailer = append(trailer, fmt.Sprintf("  %s: on (%s)", g.Label, plan.OrgRefusal))
			continue
		}
		text := fmt.Sprintf("%s (%s)", g.Label, groupAdds(ok))
		if len(notes) > 0 {
			text = fmt.Sprintf("%s (%s; unavailable: %s)", g.Label, groupAdds(ok), strings.Join(notes, "; "))
		}
		qs = append(qs, chooserQuestion{text: text, def: def, yes: yes, no: no})
	}

	// stage walks step 1's questions, then the step 2 checklist (stage ==
	// groupStart), then the confirm; "b" steps back one stage.
	answers := make([]bool, len(qs))
	for j, q := range qs {
		answers[j] = q.def
	}
	for stage := 0; ; {
		if stage < groupStart {
			q := qs[stage]
			for _, l := range q.header {
				fmt.Fprintln(out, l)
			}
			a, back, err := p.askBack(q.text, q.def)
			if err != nil {
				return err
			}
			if back {
				if stage > 0 {
					stage--
				}
				continue
			}
			answers[stage] = a
			stage++
			continue
		}
		if stage == groupStart {
			if len(qs) > groupStart || len(trailer) > 0 {
				fmt.Fprintln(out, "\n2. Which features?")
			}
			for _, l := range trailer {
				fmt.Fprintln(out, l)
			}
			if len(qs) > groupStart {
				rows := make([]pickRow, 0, len(qs)-groupStart)
				for j := groupStart; j < len(qs); j++ {
					rows = append(rows, pickRow{Label: qs[j].text, On: answers[j]})
				}
				states, back, err := pickChecklist(p.in, out, rows, groupStart > 0)
				if err != nil {
					return err
				}
				if back {
					stage = groupStart - 1
					continue
				}
				copy(answers[groupStart:], states)
			}
			stage++
			continue
		}
		ch := chooserChange(plan.Base, qs, answers)

		// Step 3: the summary of the resulting set, then one confirm.
		pv, err := svc.Preview(ctx, ch)
		if err != nil {
			return fmt.Errorf("components: %w", err)
		}
		printChooserSummary(out, snap, pv)
		if pv.NoChange {
			fmt.Fprintln(out, "  nothing to change: the current selection already says this")
			return nil
		}
		ok, back, err := p.askBack("Write this selection?", true)
		if err != nil {
			return err
		}
		if back {
			// Back from the confirm reopens the checklist (or step 1's
			// question when there is no checklist).
			stage = groupStart
			if len(qs) == groupStart && groupStart > 0 {
				stage = groupStart - 1
			}
			continue
		}
		if !ok {
			fmt.Fprintf(out, "  kept this build's defaults; %s lists them\n", components.SettingsHint())
			return nil
		}
		if _, err := svc.Apply(ctx, ch, componentsvc.ApplyOptions{ExpectFingerprint: pv.Fingerprint, Principal: "init"}); err != nil {
			return fmt.Errorf("components: %w", err)
		}
		fmt.Fprintln(out, "  selection written to [components]; init now wires only active components")
		return nil
	}
}

// chooserChange rebuilds the change from the answers given so far. An empty
// base writes no distro (a custom build or a managed node).
func chooserChange(base string, qs []chooserQuestion, answers []bool) componentsvc.Change {
	var ch componentsvc.Change
	if base != "" {
		b := base
		ch.SetBase = &b
	}
	for j, q := range qs {
		switch {
		case answers[j] && q.yes != nil:
			q.yes(&ch)
		case !answers[j] && q.no != nil:
			q.no(&ch)
		}
	}
	return ch
}

// printChooserSummary prints step 3: the resulting active set, refusals and
// what becoming inactive undoes in other tools' config, in order (the proxy
// route first, so no tool keeps pointing at a proxy that will not start).
// The inactive count is every compiled component the result leaves off
// (T-731: it used to count only the newly deactivated ones, so a minimal
// summary said "50 active, 0 inactive").
func printChooserSummary(out io.Writer, snap componentstate.Snapshot, pv componentsvc.Preview) {
	active := toIDSet(snap.ActiveIDs())
	for _, id := range pv.Deactivated {
		delete(active, id)
	}
	for _, id := range pv.Activated {
		active[id] = true
	}
	ids := make([]string, 0, len(active))
	for id := range active {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	inactive := 0
	for _, id := range snap.Compiled {
		if !active[id] {
			inactive++
		}
	}
	fmt.Fprintln(out, "\n3. Summary")
	fmt.Fprintf(out, "  %d components active, %d inactive (they stay installed and can be turned on later)\n", len(ids), inactive)
	fmt.Fprintf(out, "  %s\n", groupAdds(ids))
	for _, r := range pv.Refused {
		fmt.Fprintf(out, "  refused: %s\n", r)
	}
	for _, st := range pv.Teardown {
		fmt.Fprintf(out, "  undo: %s\n", st.What)
	}
}

// chooserQuestion is one yes/no step of the chooser: header lines print
// before it, yes / no apply the answer to the change.
type chooserQuestion struct {
	header  []string
	text    string
	def     bool
	yes, no func(*componentsvc.Change)
}

// splitFeasible splits a group's ids into the ones that can be chosen here
// and one note per id that cannot (the feasibility seam's reason).
func splitFeasible(ids []string, verdicts map[string]feasibility.Verdict) ([]string, []string) {
	var ok, notes []string
	for _, id := range ids {
		v, known := verdicts[id]
		if known && !v.Feasible {
			notes = append(notes, v.Reason)
			continue
		}
		ok = append(ok, id)
	}
	return ok, notes
}

// askBack is ask with a way back: "b" or "back" returns back=true so the
// chooser can return to the previous question (D-514).
func (p *initPrompter) askBack(question string, def bool) (answer, back bool, err error) {
	suffix := "[Y/n, b = back]"
	if !def {
		suffix = "[y/N, b = back]"
	}
	for {
		fmt.Fprintf(p.out, "  %s %s ", question, suffix)
		line, rerr := p.in.ReadString('\n')
		a := strings.ToLower(strings.TrimSpace(line))
		if rerr != nil && a == "" {
			return false, false, fmt.Errorf("stdin closed - stopping; nothing further was written")
		}
		switch a {
		case "":
			return def, false, nil
		case "y", "yes":
			return true, false, nil
		case "n", "no":
			return false, false, nil
		case "b", "back":
			return false, true, nil
		default:
			fmt.Fprintln(p.out, "  please answer y, n or b (enter for the default)")
			if rerr != nil {
				return false, false, fmt.Errorf("stdin closed - stopping; nothing further was written")
			}
		}
	}
}

// noteComponentChoice is the one line a non-interactive init prints when no
// selection is recorded (plan 7.1): the defaults stay, and where to choose.
func noteComponentChoice(out io.Writer, configPath string) {
	snap := componentSnapshotFor(configPath)
	if _, pending := chooserPending(snap, chooserPlanFor(snap)); snap.Configured && !pending {
		return
	}
	fmt.Fprintf(out, "components: this build's defaults are active; choose what runs %s\n", components.WhereToChange("`observer components select`"))
}

// initChooserService builds the chooser's service for the config init
// writes, or nil (no chooser) when it cannot be built.
func initChooserService(configPath string) chooserService {
	svc, err := newComponentsService(configPath, nil)
	if err != nil {
		return nil
	}
	return svc
}
