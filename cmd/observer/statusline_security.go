//go:build !sbo_omit_security

package main

import (
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/statusline"
)

// statusline_security.go is the statusline's security segment (security
// pillar plan section 6.1 "Statusline", lane sec-c3): the current
// project's commit-gate state, read from the same signed posture file the
// hook reads, with no daemon call and no write (secposture.Load never
// writes). Off unless [security.statusline].segment is on and the module
// is active; a project with no posture shows nothing.

// securityStatuslineLabels maps a derived posture state to the segment's
// text; a state absent from the table shows nothing.
var securityStatuslineLabels = map[policy.SecurityPosture]func(blocking int) string{
	policy.SecurityPostureClean:    func(int) string { return "sec ok" },
	policy.SecurityPostureDirty:    func(int) string { return "sec *" },
	policy.SecurityPostureUnknown:  func(int) string { return "sec ?" },
	policy.SecurityPostureBlocking: func(n int) string { return "sec " + strconv.Itoa(n) + "!" },
}

// securityStatuslineLabel is the segment's text for one derived state, nil
// when it shows nothing.
func securityStatuslineLabel(p policy.SecurityPosture, blocking int) *string {
	f, ok := securityStatuslineLabels[p]
	if !ok {
		return nil
	}
	s := f(blocking)
	return &s
}

// statuslineSecurityProvider returns the deps.security seam for cfg: nil
// while the segment is off or the module is not active.
func statuslineSecurityProvider(cfg config.Config) func(statusline.Input) *string {
	if !cfg.Security.Statusline.Segment || !componentSnapshotForConfig(cfg).ModuleActive("security") {
		return nil
	}
	resolved, err := config.ResolveGlobalPath("")
	if err != nil {
		return nil
	}
	return func(in statusline.Input) *string {
		dir := ""
		if in.Workspace != nil {
			switch {
			case in.Workspace.ProjectDir != nil && *in.Workspace.ProjectDir != "":
				dir = *in.Workspace.ProjectDir
			case in.Workspace.CurrentDir != nil:
				dir = *in.Workspace.CurrentDir
			}
		}
		if dir == "" {
			return nil
		}
		root, ok := git.FindRoot(dir)
		if !ok {
			return nil
		}
		gp := guardposture.Load(guardposture.PosturePath(resolved), guardposture.KeyPath(resolved))
		r := secposture.Load(secposture.LayoutFor(resolved), root, secposture.ModuleSignalFrom(gp.State, gp.Posture), time.Now(), secposture.Versions{})
		return securityStatuslineLabel(r.State.Posture, r.State.Blocking)
	}
}

// withSecuritySegment adds the security segment kind to segs (the default
// list when segs is empty) unless it is already there.
func withSecuritySegment(segs []string) []string {
	if len(segs) == 0 {
		segs = statusline.DefaultSegments
	}
	for _, s := range segs {
		if s == statusline.SegmentSecurity {
			return segs
		}
	}
	return append(append([]string(nil), segs...), statusline.SegmentSecurity)
}
