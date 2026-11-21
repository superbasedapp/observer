package terminalsisolation

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// SupportedHosts are the host operating systems the remote-only lint walks.
var SupportedHosts = []sandboxbackend.HostKind{
	sandboxbackend.HostLinux, sandboxbackend.HostWSL2, sandboxbackend.HostMacOS, sandboxbackend.HostWindows,
}

// RemoteOnlyWarnings is the publish lint of section 8.1 (Opus L11): for each
// supported host OS, a warning when the floors can be met only by remote
// (hosted) rows there, which would push a developer on that OS toward
// uploading code to a provider. rows is the registry (planned rows
// included: the lint is about what the floors allow, not what this build
// ships); a test passes its own.
func RemoteOnlyWarnings(s PolicySpec, rows []sandboxbackend.Capability) []string {
	if !s.InForce() {
		return nil
	}
	var out []string
	for _, host := range SupportedHosts {
		local, remote := false, false
		for _, r := range rows {
			if !meets(s, r) {
				continue
			}
			switch {
			case r.Iso.Location == vocab.LocationRemote:
				remote = true
			case r.RunsOn(host):
				local = true
			}
		}
		if remote && !local {
			out = append(out, fmt.Sprintf("on %s these floors can be met only by a hosted (remote) sandbox, which uploads the workspace to a provider", host))
		}
	}
	return out
}

// RegistryRows is every registry row, for RemoteOnlyWarnings.
func RegistryRows() []sandboxbackend.Capability {
	var out []sandboxbackend.Capability
	for _, id := range sandboxbackend.IDs() {
		if r, ok := sandboxbackend.Get(id); ok {
			out = append(out, r)
		}
	}
	return out
}

// meets reports whether row r could satisfy the floors (its declared class;
// the lint judges intent, so a class still only claimed counts).
func meets(s PolicySpec, r sandboxbackend.Capability) bool {
	if s.MinIsolation != "" && r.Iso.Class.Rank() < s.MinIsolation.Rank() {
		return false
	}
	if s.AllowedBackends != nil {
		found := false
		for _, b := range s.AllowedBackends {
			found = found || b == r.ID
		}
		if !found {
			return false
		}
	}
	if s.ForbidRemote && r.Iso.Location == vocab.LocationRemote {
		return false
	}
	if s.RequireRefusalAudit && !r.Net.AuditsRefusals() {
		return false
	}
	if s.MinEgress != "" && r.Offered() {
		ok := false
		for _, t := range r.Net.Egress {
			ok = ok || t.Strictness() >= s.MinEgress.Strictness()
		}
		if !ok {
			return false
		}
	}
	return true
}

// floorProjections reduce the floors to one key each, so the per-host lint
// can name which floor no offered row meets (the keys meets judges). A
// closed table: a key meets learns to judge gets a row here.
var floorProjections = []struct {
	key  string
	only func(s PolicySpec) (PolicySpec, bool)
}{
	{"min_isolation", func(s PolicySpec) (PolicySpec, bool) {
		return PolicySpec{MinIsolation: s.MinIsolation}, s.MinIsolation != ""
	}},
	{"allowed_backends", func(s PolicySpec) (PolicySpec, bool) {
		return PolicySpec{AllowedBackends: s.AllowedBackends}, s.AllowedBackends != nil
	}},
	{"min_egress", func(s PolicySpec) (PolicySpec, bool) {
		return PolicySpec{MinEgress: s.MinEgress}, s.MinEgress != ""
	}},
}

// UnmetLocallyWarnings is the publish lint of section 11.5 (SBX-P2E, P1b
// audit finding 4): for each supported host OS, a warning when no row this
// release offers (planned rows left out) runs there, locally, and meets the
// floors, naming the floor (or floors) none meets. A managed node on that
// OS gets "Require a sandboxed terminal" while a floor is in force, so it
// refuses new terminals, its reason naming the floor and why it cannot run
// a sandbox. Only floors that imply a sandbox are judged; the qualifying
// floors (beta, capture, regions, provider keys) narrow the choice at
// launch and are named by the launch refusal.
func UnmetLocallyWarnings(s PolicySpec, rows []sandboxbackend.Capability) []string {
	if !s.ImpliesSandboxRequired() {
		return nil
	}
	var out []string
	for _, host := range SupportedHosts {
		if offeredLocalMeets(s, rows, host) {
			continue
		}
		var named []string
		for _, p := range floorProjections {
			one, set := p.only(s)
			if set && !offeredLocalMeets(one, rows, host) {
				named = append(named, floorLabel(p.key))
			}
		}
		if len(named) == 0 {
			// Each floor alone is met; only their combination is not.
			for _, p := range floorProjections {
				if _, set := p.only(s); set {
					named = append(named, floorLabel(p.key))
				}
			}
		}
		out = append(out, fmt.Sprintf("on %s no sandbox backend this release offers meets %s; a managed node there refuses new terminals, naming the floor and why it cannot run a sandbox",
			host, joinFloors(named)))
	}
	return out
}

// offeredLocalMeets reports whether an offered local row running on host
// meets s. An explicit-only row (process_lite, openshell and the other
// ExplicitOnly rows) never counts (tracker F-020 A14): a floor that implies
// a sandbox makes the node require one, and neither the guard's enforce
// upgrade nor an automatic choice ever picks an explicit-only row
// (sandboxselect rule S1b), so a host whose only meeting rows are
// explicit-only still refuses every terminal that does not name one.
func offeredLocalMeets(s PolicySpec, rows []sandboxbackend.Capability, host sandboxbackend.HostKind) bool {
	for _, r := range rows {
		if r.Offered() && !r.ExplicitOnly && r.Iso.Location != vocab.LocationRemote && r.RunsOn(host) && meets(s, r) {
			return true
		}
	}
	return false
}

// floorLabel is a floor's admin label with its key, as the refusals name it.
func floorLabel(key string) string { return FloorLabelWithKey(key) }

// FloorLabelWithKey is a floor's admin label, quoted, with its wire key in
// parentheses (`"Require refusal audit" (require_refusal_audit)`), read from
// the one floor table, so every refusal that names a floor names it the same
// way (lane FU10, F-050). An unknown key is returned as it is.
func FloorLabelWithKey(key string) string {
	if k, ok := LookupFloorKey(key); ok {
		return fmt.Sprintf("%q (%s)", k.Label, key)
	}
	return key
}

// joinFloors lists the named floors ("the floor X" or "the floors X and Y").
func joinFloors(named []string) string {
	switch len(named) {
	case 1:
		return "the floor " + named[0]
	case 2:
		return "the floors " + named[0] + " and " + named[1]
	}
	last := len(named) - 1
	out := "the floors "
	for i, n := range named[:last] {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out + " and " + named[last]
}
