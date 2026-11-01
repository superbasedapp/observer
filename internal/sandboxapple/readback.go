package sandboxapple

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// readback.go is the Apple container row's post-build re-check (sandbox
// plan v2 section 4.4): the host helper reads the run's container back with
// `container inspect` and compares it with the plan; anything weaker is
// built_below_plan and the container is removed. Inspect reports the
// configuration the CLI asked for, not what the guest got: on 1.6.0 it still
// listed a .git mount the guest never had (live 2026-10-23, D-A3), so the
// row's second witness is the in-guest check (guestcheck.go), which the box
// runs on its own mount table before the agent starts.

// VerdictBuiltBelowPlan is the re-check's refusal.
const VerdictBuiltBelowPlan = "built_below_plan"

// ReadBack compares the inspected container with the plan it was built
// from. A network other than "none", a mount the plan did not ask for (or
// a read-only mount made writable), a planned mount or read-only path
// missing, a published socket other than the plan's, other limits or other
// labels are each a refusal.
func ReadBack(c Container, p RunPlan) Verdict {
	var bad []string
	if c.Labels[LabelRun] != p.RunID || c.Labels[LabelInstall] != p.InstallID {
		bad = append(bad, "its labels are not the run's")
	}
	if c.Image != "" && !SameImage(c.Image, p.Image) {
		bad = append(bad, "its image is "+c.Image)
	}
	for _, n := range c.Networks {
		if n != "none" {
			bad = append(bad, "it is attached to the network "+n)
		}
	}
	if c.CPUs != p.CPUs {
		bad = append(bad, fmt.Sprintf("%d CPUs, not %d", c.CPUs, p.CPUs))
	}
	if want := int64(p.MemoryMiB) << 20; c.MemoryBytes != want {
		bad = append(bad, fmt.Sprintf("%d bytes of memory, not %d", c.MemoryBytes, want))
	}
	planned := map[string]Mount{}
	for _, m := range p.Mounts {
		planned[m.Target] = m
	}
	got := map[string]bool{}
	for _, m := range c.Mounts {
		got[m.Target] = true
		want, ok := planned[m.Target]
		switch {
		case !ok:
			bad = append(bad, "it mounts "+m.Target+", which the plan did not ask for")
		case want.Source != m.Source:
			bad = append(bad, "it mounts "+m.Source+" at "+m.Target)
		case want.ReadOnly && !m.ReadOnly:
			bad = append(bad, m.Target+" is writable, the plan made it read-only")
		}
	}
	for _, m := range p.Mounts {
		if !got[m.Target] {
			bad = append(bad, "the planned mount "+m.Target+" is missing")
		}
	}
	ro := map[string]bool{}
	for _, r := range c.ReadOnlyPaths {
		ro[r] = true
	}
	for _, r := range p.ReadOnlyPaths {
		if !ro[r] {
			bad = append(bad, "the planned read-only path "+r+" is missing")
		}
	}
	plannedSock := map[PublishSocket]bool{}
	for _, s := range p.PublishSockets {
		plannedSock[s] = true
	}
	gotSock := map[PublishSocket]bool{}
	for _, s := range c.PublishedSockets {
		gotSock[s] = true
		if !plannedSock[s] {
			bad = append(bad, "it publishes "+s.Guest+" at "+s.Host+", which the plan did not ask for")
		}
	}
	for _, s := range p.PublishSockets {
		if !gotSock[s] {
			bad = append(bad, "the planned published socket "+s.Guest+" is missing")
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return refuse(VerdictBuiltBelowPlan, "the container read back weaker than planned: "+strings.Join(bad, "; ")+"; it was removed")
	}
	return pass()
}

// ReadBackWindow is how long the helper waits for `container inspect` to
// answer about the run's container while it starts.
const ReadBackWindow = 20 * time.Second

// ReadBackClock is the time source AwaitReadBack polls with (injected so a
// test runs without waiting).
type ReadBackClock struct {
	Now   func() time.Time
	Sleep func(time.Duration)
}

// AwaitReadBack polls fetch (one `container inspect` of the run's
// container) until it parses to exactly one container, then judges it with
// ReadBack. It fails closed: when no answer parses to exactly one container
// within window, the verdict is built_below_plan and the caller ends the
// run, so a run never continues unverified (a JSON shape this build does
// not read included).
func AwaitReadBack(fetch func() ([]byte, error), p RunPlan, window time.Duration, clk ReadBackClock) Verdict {
	if clk.Now == nil {
		clk.Now = time.Now
	}
	if clk.Sleep == nil {
		clk.Sleep = time.Sleep
	}
	var last string
	deadline := clk.Now().Add(window)
	for {
		b, err := fetch()
		switch {
		case err != nil:
			last = "inspect failed: " + err.Error()
		default:
			list, perr := ParseList(b)
			switch {
			case perr != nil:
				last = "its answer did not parse: " + perr.Error()
			case len(list) != 1:
				last = fmt.Sprintf("it named %d containers, not 1", len(list))
			default:
				return ReadBack(list[0], p)
			}
		}
		if !clk.Now().Before(deadline) {
			return refuse(VerdictBuiltBelowPlan, fmt.Sprintf("the container could not be read back within %s (%s); the run was ended, never left unverified", window, last))
		}
		clk.Sleep(250 * time.Millisecond)
	}
}

// Orphans lists the containers of this install whose run is no longer live
// (the orphan sweep after a killed daemon, helper or CLI, MAC-17: a
// SIGKILLed `container run --rm` CLI leaves its container running, live
// 2026-10-23). A container without both labels, or another install's, is
// never touched.
func Orphans(list []Container, installID string, live func(runID string) bool) []string {
	var out []string
	for _, c := range list {
		if c.Labels[LabelInstall] != installID || installID == "" {
			continue
		}
		run := c.Labels[LabelRun]
		if run == "" || live(run) {
			continue
		}
		out = append(out, c.ID)
	}
	sort.Strings(out)
	return out
}
