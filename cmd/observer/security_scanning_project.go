//go:build !sbo_omit_security

package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// security_scanning_project.go is the node side of the security.scanning
// PROJECT sections (security plan 7.11 and 7.3, lane sec-p3 milestone 2).
// An org publishes a floor for one or more of its projects; the section rides
// that project's signed v3 guard envelope as a family member. This file owns
// the project-aware read seam:
//
//	securityFloorsAppliedAt(sc, root) = sc with the managed pull, then the
//	org-wide floor in force, then every matched project's sections merged
//	raise-only over it (several matched projects: the strictest).
//
// A consumer that knows its project root reads through it; every other
// consumer keeps securityFloorsApplied (the org-wide seam). The match is the
// guard project layer's (guard.OrgProjectFamilies over the process guard),
// so a linked worktree reads its main repository's sections (P-041), an
// unmatched or project_unknown directory gets the org-wide floor only, and
// the project_unknown floor of P2A keeps governing the gate. Each member is
// compiled again here with the family's linked compiler; one that does not
// compile to the bytes it carries is refused, never applied.
//
// Inert for an org that never published a project section: no envelope
// carries a member, so the seam answers exactly what the org-wide seam does.

// Per-directory section states (securityProjectSection.State).
const (
	// securitySectionApplied: the section merged into the floor in force.
	securitySectionApplied = "applied"
	// securitySectionRefused: the section is held but not applied (it does
	// not compile to its own bytes, or it cannot merge over the floor in
	// force: an allow-set that would allow nothing, or a contradiction).
	securitySectionRefused = "refused"
	// securitySectionUnknown: the node cannot say whether the section
	// applies here (the directory's project match is unknown, the directory
	// matched no project, or a matched project's envelope is unavailable).
	securitySectionUnknown = "unknown"
	// securitySectionInert: accepted but not in effect (security.scanning
	// is not in [org_client.policy] preauthorize_module_enforce).
	securitySectionInert = "inert"
	// securitySectionPartial: the section applies except on the axes named
	// in RefusedAxes, which conflict with the floor in force or another
	// matched project's section (SEC-P3 merge, finding 2).
	securitySectionPartial = "partial"
)

// securityProjectSection is one project section's outcome in one directory.
type securityProjectSection struct {
	OrgProjectID string
	// Version is the server's sequence of the section (0 when the
	// project's envelope is unavailable and its sections are not known).
	Version int64
	State   string
	Reason  string
	// Spec is the compiled section (nil when it did not compile).
	Spec *securityscanning.PolicySpec
	// RefusedAxes are the axes not applied here (partial or refused).
	RefusedAxes []string
}

// securityProjectView is the floor in force in one directory.
type securityProjectView struct {
	// Load is the guard's project read for the directory.
	Load guard.ProjectFamilyLoad
	// Spec is the merged floor (nil when neither an org-wide floor nor a
	// project section is in force).
	Spec *securityscanning.PolicySpec
	// Sections are the project sections the node holds for the matched
	// projects, sorted by project and sequence.
	Sections []securityProjectSection
}

// securityProjectFamiliesAt reads the project sections that apply at root
// through the guard's project layer. A test swaps it.
var securityProjectFamiliesAt = func(root string) guard.ProjectFamilyLoad {
	g := secScanning.projectGuard()
	if g == nil {
		return guard.ProjectFamilyLoad{}
	}
	return g.OrgProjectFamilies(root)
}

// securityProjectGuards is the guard a process without the daemon's own
// (the CLI, or a daemon whose guard is off) reads project sections through,
// one per database path, built from the node's [guard] section with the
// enrolment key pin and the bundle expectation nodeGuardPolicyInputs reads
// (the daemon's own guard is built from the same inputs).
//
// It must not go stale (SEC-P3 merge, finding 1): every section publish
// moves the composed bundle's version, and the envelopes the node then
// caches only verify against the new composed bundle. So each read stats the
// composed bundle file and, when it changed, runs the process guard's own
// reload path (guard.ReloadOrgLayer: re-verify signature and key pin, swap
// the org layer; a failed reload keeps the layer in force). A changed pin or
// bundle expectation rebuilds the guard.
var securityProjectGuards = struct {
	mu sync.Mutex
	m  map[string]*securityProjectGuardEntry
}{m: map[string]*securityProjectGuardEntry{}}

// securityProjectGuardEntry is one built guard and what it was built from.
type securityProjectGuardEntry struct {
	g        *guard.Guard
	pin      string
	expected bool
	path     string
	// fi is the composed bundle file as last loaded (nil: absent).
	fi os.FileInfo
}

// securityBundleStat stats the composed bundle file (nil when absent or
// unconfigured).
func securityBundleStat(path string) os.FileInfo {
	if path == "" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	return fi
}

// sameBundleFile reports whether two stats name the same unchanged file
// (the org client replaces the bundle by rename, so a new file is a new
// inode, and its size or modification time changes too).
func sameBundleFile(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// projectGuard is the daemon's process guard when one exists, else the
// fallback guard for this database path, reloaded when the composed bundle
// changed (its org layer verifies the cached bundle's signature and the
// enrolment key pin).
func (n *securityScanningNode) projectGuard() *guard.Guard {
	base, ok := n.baseNow()
	if !ok || base.DBPath == "" {
		return nil
	}
	if g := lookupProcessGuard(base.DBPath); g != nil {
		return g
	}
	home, _ := os.UserHomeDir()
	path := guard.OrgBundlePath(base.Guard, home)
	fi := securityBundleStat(path)
	securityProjectGuards.mu.Lock()
	defer securityProjectGuards.mu.Unlock()
	e := securityProjectGuards.m[base.DBPath]
	if e != nil && e.pin == base.OrgKeyPin && e.expected == base.BundleExpected && e.path == path {
		if !sameBundleFile(e.fi, fi) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = e.g.ReloadOrgLayer(ctx)
			cancel()
			e.fi = fi
		}
		return e.g
	}
	g, err := guard.New(guard.Options{Config: base.Guard, Home: home, OrgKeyPinHash: base.OrgKeyPin, OrgBundleExpected: base.BundleExpected})
	if err != nil {
		if e != nil {
			return e.g
		}
		return nil
	}
	securityProjectGuards.m[base.DBPath] = &securityProjectGuardEntry{g: g, pin: base.OrgKeyPin, expected: base.BundleExpected, path: path, fi: fi}
	return g
}

// securityProjectHeldSections lists the family sections the node holds in
// the envelopes of its mapped projects, through the same guard. A test swaps
// it.
var securityProjectHeldSections = func() []guard.ProjectFamilySection {
	g := secScanning.projectGuard()
	if g == nil {
		return nil
	}
	return g.OrgProjectFamilySections(time.Now(), nil)
}

// securityFloorsAppliedAt is THE project-aware read seam: sc with the managed
// pull, the org-wide floor and root's matched project sections merged over
// it. An empty root is securityFloorsApplied.
func securityFloorsAppliedAt(sc config.SecurityConfig, root string) config.SecurityConfig {
	if root == "" {
		return securityFloorsApplied(sc)
	}
	return secScanning.appliedWith(sc, secScanning.projectView(root).Spec)
}

// securityPostureFloors returns the posture writer's floor read (lane SEC-P4
// decision 9): the commit gate and launch trust floors in force at a
// project root, through the project seam (securityFloorsAppliedAt), so a
// project section raises them only there and an unmatched directory takes
// the org-wide floor. Both are managed only or component gated by the
// family's key table, so an individual node signs none for the commit gate.
func securityPostureFloors(sc config.SecurityConfig) func(root string) (string, string) {
	return func(root string) (string, string) {
		eff := securityFloorsAppliedAt(sc, root)
		return eff.CommitGateFloor, eff.PrelaunchTrustFloor
	}
}

// securityCommitGateFloorHeld reports whether this managed node holds a
// commit gate floor anywhere (audit SEC-P4 F2): the security.scanning family
// is in effect and require.commit_gate is quick_scan in the org-wide floor or
// in a project section the node holds (a section that does not compile is
// refused, as projectView refuses it). It is signed into the guard posture
// (guardposture.Posture.CommitGateFloorHeld) so the hook fails closed when a
// project's own posture file cannot answer. An individual node holds none:
// the floor is managed only.
func securityCommitGateFloorHeld() bool { return secScanning.commitGateFloorHeld() }

func (n *securityScanningNode) commitGateFloorHeld() bool {
	n.mu.Lock()
	off := n.moduleOff
	n.mu.Unlock()
	if off {
		return false
	}
	base, _ := n.baseNow()
	if !base.Managed || !base.FamilyInEffect {
		return false
	}
	if specFloorsCommitGate(n.inForceSpec()) {
		return true
	}
	for _, s := range securityProjectHeldSections() {
		if s.Member.Family != policyfam.FamilySecurityScanning {
			continue
		}
		if spec, err := securityCompileSection(s.Member.Body); err == nil && specFloorsCommitGate(spec) {
			return true
		}
	}
	return false
}

// specFloorsCommitGate reports a spec whose require.commit_gate is the
// quick-scan floor.
func specFloorsCommitGate(spec *securityscanning.PolicySpec) bool {
	return spec != nil && spec.Body.Require != nil && spec.Body.Require.CommitGate == policy.CommitGateFloorQuickScan
}

// securityCopySourceRoot maps a sandbox copy's tree to the same place in
// its source project (security_box_wire.go, lane LEFT-SEC): a copy run's
// project sections are its source project's, so a floored project's box
// work is held like its host work. nil in a build without the sandbox
// module; "" for a tree no copy run holds.
var securityCopySourceRoot func(root string) string

// securityFloorRootFor is the directory root's project sections are read
// for: the source project of a sandbox copy, else root itself.
func securityFloorRootFor(root string) string {
	if securityCopySourceRoot == nil || root == "" {
		return root
	}
	if src := securityCopySourceRoot(root); src != "" {
		return src
	}
	return root
}

// projectView resolves the floor in force at root (a sandbox copy's tree
// reads its source project's sections, securityFloorRootFor).
func (n *securityScanningNode) projectView(root string) securityProjectView {
	root = securityFloorRootFor(root)
	n.mu.Lock()
	off := n.moduleOff
	n.mu.Unlock()
	orgWide := n.inForceSpec()
	view := securityProjectView{Spec: orgWide}
	if off || root == "" || !policyfam.IsFamilyLinked(policyfam.FamilySecurityScanning) {
		return view
	}
	view.Load = securityProjectFamiliesAt(root)
	if !view.Load.InForce {
		return view
	}
	if view.Load.State == projectmatch.StateUnknown {
		// The match is unknown here: the org-wide floor applies, and every
		// section the node holds reads as unknown (never as "none"), so
		// status names what this directory may be missing.
		view.Sections = securityUnknownSections()
		return view
	}
	if view.Load.State != projectmatch.StateMatched {
		return view
	}
	base, _ := n.baseNow()
	var inputs []securityscanning.ProjectSection
	var idx []int
	for _, p := range view.Load.Projects {
		if p.Unavailable {
			view.Sections = append(view.Sections, securityProjectSection{OrgProjectID: p.OrgProjectID, State: securitySectionUnknown, Reason: "envelope_unavailable"})
			continue
		}
		for _, m := range p.Members {
			if m.Family != policyfam.FamilySecurityScanning {
				continue
			}
			sec := securityProjectSection{OrgProjectID: p.OrgProjectID, Version: m.Version}
			spec, err := securityCompileSection(m.Body)
			switch {
			case err != nil:
				sec.State, sec.Reason = securitySectionRefused, err.Error()
			case !base.FamilyInEffect:
				sec.Spec, sec.State = spec, securitySectionInert
			default:
				sec.Spec = spec
				inputs = append(inputs, securityscanning.ProjectSection{Project: p.OrgProjectID, Version: m.Version, Spec: *spec})
				idx = append(idx, len(view.Sections))
			}
			view.Sections = append(view.Sections, sec)
		}
	}
	merged, outcomes := securityscanning.MergeProjectSections(orgWide, inputs)
	for i, o := range outcomes {
		s := &view.Sections[idx[i]]
		switch {
		case o.Applied:
			s.State = securitySectionApplied
		case o.Partial:
			s.State, s.Reason, s.RefusedAxes = securitySectionPartial, o.Err.Error(), o.RefusedAxes()
		default:
			s.State, s.Reason, s.RefusedAxes = securitySectionRefused, o.Err.Error(), o.RefusedAxes()
		}
	}
	view.Spec = merged
	sortSecuritySections(view.Sections)
	return view
}

// securityUnknownSections is every security.scanning section the node holds,
// each unknown here (the directory's project match is unknown).
func securityUnknownSections() []securityProjectSection {
	var out []securityProjectSection
	seen := map[string]bool{}
	for _, h := range securityProjectHeldSections() {
		if h.Member.Family != policyfam.FamilySecurityScanning {
			continue
		}
		key := fmt.Sprintf("%s\x00%d", h.OrgProjectID, h.Member.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, securityProjectSection{OrgProjectID: h.OrgProjectID, Version: h.Member.Version, State: securitySectionUnknown, Reason: "project_unknown"})
	}
	sortSecuritySections(out)
	return out
}

// sortSecuritySections orders sections by project, then sequence.
func sortSecuritySections(s []securityProjectSection) {
	sort.SliceStable(s, func(i, j int) bool {
		a, b := s[i], s[j]
		if a.OrgProjectID != b.OrgProjectID {
			return a.OrgProjectID < b.OrgProjectID
		}
		return a.Version < b.Version
	})
}

// securityCompileSection compiles a member body with the family's linked
// compiler (the node's second compile, after the server's) and refuses one
// that does not compile to the exact bytes it carries.
func securityCompileSection(body string) (*securityscanning.PolicySpec, error) {
	raw, canon, err := policyfam.CompileFamilyBody(policyfam.FamilySecurityScanning, []byte(body), securityscanning.DefaultMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("does not compile: %w", err)
	}
	if string(canon) != body {
		return nil, fmt.Errorf("body_mismatch: the body is not in canonical form")
	}
	spec, ok := raw.(securityscanning.PolicySpec)
	if !ok {
		return nil, fmt.Errorf("not a security.scanning spec")
	}
	return &spec, nil
}

// securityProjectStatusLines are the `observer security status` lines for the
// project sections that apply in dir (the current directory).
func securityProjectStatusLines(dir string) []string {
	view := secScanning.projectView(dir)
	if !view.Load.InForce {
		return nil
	}
	switch view.Load.State {
	case projectmatch.StateUnknown:
		lines := []string{"Org project floors (security.scanning) here: unknown (the project match is unknown); the org-wide floor applies, and each project section reads as unknown"}
		for _, s := range view.Sections {
			lines = append(lines, fmt.Sprintf("  project %s section v%d: %s (%s)", s.OrgProjectID, s.Version, s.State, s.Reason))
		}
		return lines
	case projectmatch.StateUnmatched:
		return []string{"Org project floors (security.scanning) here: none (this directory matched no org project); the org-wide floor applies"}
	}
	if len(view.Sections) == 0 {
		return []string{"Org project floors (security.scanning) here: none (the matched projects carry no section)"}
	}
	facts := secScanning.facts()
	lines := []string{"Org project floors (security.scanning) here:"}
	for _, s := range view.Sections {
		line := fmt.Sprintf("  project %s", s.OrgProjectID)
		if s.Version > 0 {
			line += fmt.Sprintf(" section v%d", s.Version)
		}
		line += ": " + s.State
		if s.Reason != "" {
			line += " (" + s.Reason + ")"
		}
		lines = append(lines, line)
		if s.Spec == nil || (s.State != securitySectionApplied && s.State != securitySectionPartial) {
			continue
		}
		refused := map[string]bool{}
		for _, a := range s.RefusedAxes {
			refused[a] = true
		}
		for _, k := range securityscanning.Evaluate(*s.Spec, facts) {
			if refused[k.Key] {
				lines = append(lines, "    "+k.Key+": refused in project "+s.OrgProjectID+" (NACK): it conflicts with the floor in force here")
				continue
			}
			k = securityKeyStateOnNode(k, facts)
			kl := "    " + k.String()
			if k.Floor != "" {
				kl += " (floor " + k.Floor + ")"
			}
			if why := securityKeyNote(k, facts); why != "" {
				kl += ": " + why
			} else if why, ok := securityProjectNodeWide[k.Key]; ok && k.State == securityscanning.StateApplied {
				kl += ": " + why
			}
			lines = append(lines, kl)
		}
	}
	return lines
}

// securityProjectNodeWide names the built floor keys no consumer reads per
// project on this node (code is the truth, lanes sec-p3 and SEC-P4): a
// project section that sets one raises it only where that consumer runs for
// the whole node, which is never per project, so status says so instead of
// a bare "applied". Per-project consumers since lane SEC-P4 decision 10:
// the finding retention prune (each project at the stricter of the node's
// and its own days), and the dependency scans' advisory database check (a
// project's stricter age or narrower source set reads that project's scans
// unknown: advisory_database_not_allowed); earlier, the install gate's
// online answer and a scan's online matching through allow.online_checks.
// A key moves out of this table in the lane that gives it a per-project
// consumer.
var securityProjectNodeWide = map[string]string{
	securityscanning.AxisAllowCustomManifests: "node-wide: the custom driver policy is read for the whole node, so a project section does not change it here",
	securityscanning.AxisOnlineChecks:         "node-wide: the install gate's hook asks only while the node-wide setting is on, so a project section can turn online checks off in a project (allow.online_checks) but never on",
}

// projectFamilyStatusFrom is the gen6 per-section report of the project
// family sections the node holds (lane sec-p3), read from the daemon's live
// guard (or, when the daemon's guard is off, the fallback guard the floors
// are read through): per section, its project's status from the guard's
// table, corrected for what this node does with the section (security plan
// 7.3).
func projectFamilyStatusFrom(g *guard.Guard, now func() time.Time) func() ([]orgcontract.ProjectFamilySectionState, bool) {
	return func() ([]orgcontract.ProjectFamilySectionState, bool) {
		read := g
		if read == nil {
			// The daemon's guard is off: report what the fallback guard
			// the floors are read through holds (SEC-P3 merge, finding 1),
			// so Fleet shows what this node applies. Nothing is built
			// where no project floor can apply.
			secScanning.mu.Lock()
			off := secScanning.moduleOff
			secScanning.mu.Unlock()
			if off || !policyfam.IsFamilyLinked(policyfam.FamilySecurityScanning) {
				return nil, false
			}
			read = secScanning.projectGuard()
		}
		if read == nil {
			return nil, false
		}
		return secScanning.familyStatus(read.OrgProjectFamilySections(now(), nil))
	}
}

// familyStatus turns the guard's held sections into the wire list, capped at
// orgcontract.MaxProjectMappingProjects (truncated true beyond) and always
// valid for the server's check. A family outside the closed set is dropped
// and counts as truncated.
func (n *securityScanningNode) familyStatus(held []guard.ProjectFamilySection) ([]orgcontract.ProjectFamilySectionState, bool) {
	n.mu.Lock()
	off := n.moduleOff
	n.mu.Unlock()
	if off || len(held) == 0 {
		return nil, false
	}
	base, _ := n.baseNow()
	orgWide := n.inForceSpec()
	var out []orgcontract.ProjectFamilySectionState
	truncated := false
	for _, h := range held {
		status, axes := securityFamilySectionStatus(h, base, orgWide)
		e := orgcontract.ProjectFamilySectionState{OrgProjectID: h.OrgProjectID, Family: h.Member.Family, Version: h.Member.Version, Status: status, RefusedAxes: axes}
		if !orgcontract.ValidProjectFamilyStatus([]orgcontract.ProjectFamilySectionState{e}) {
			truncated = true
			continue
		}
		if len(out) == orgcontract.MaxProjectMappingProjects {
			truncated = true
			break
		}
		out = append(out, e)
	}
	if !orgcontract.ValidProjectFamilyStatus(out) {
		return nil, true
	}
	return out, truncated
}

// securityFamilySectionStatus is one held section's status, a table walked
// top down: a body this node cannot compile to its own bytes is refused
// anywhere; an accepted but not preauthorized family is inert; otherwise the
// project's status from the guard, except that an applied or not-matched
// section is refused on each axis that cannot merge over the org-wide floor
// in force: partial (a NACK naming the axes) when something else of it
// applies, refused when nothing does (SEC-P3 merge, finding 2).
func securityFamilySectionStatus(h guard.ProjectFamilySection, base securityScanningBase, orgWide *securityscanning.PolicySpec) (string, []string) {
	spec, err := securityCompileSection(h.Member.Body)
	switch {
	case h.Member.Family != policyfam.FamilySecurityScanning || err != nil:
		return orgcontract.ProjectFamilyRefused, nil
	case !base.FamilyInEffect:
		return orgcontract.ProjectFamilyInert, nil
	}
	if h.Status == orgcontract.ProjectSectionApplied || h.Status == orgcontract.ProjectSectionNotMatched {
		_, outcomes := securityscanning.MergeProjectSections(orgWide, []securityscanning.ProjectSection{{Project: h.OrgProjectID, Version: h.Member.Version, Spec: *spec}})
		switch o := outcomes[0]; {
		case o.Partial:
			return orgcontract.ProjectFamilyPartial, o.RefusedAxes()
		case !o.Applied:
			return orgcontract.ProjectFamilyRefused, o.RefusedAxes()
		}
	}
	return h.Status, nil
}
