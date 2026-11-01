//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secengine"
)

// security_opengrep_offer_test.go is lane SEC-G2 milestone 5: what an
// existing install (no [components] block) sees of the lane while the
// component stays opt-in, and, once offered, the one step the orchestrator
// takes (TestOpengrepOfferedByDefault in security_opengrep_cmd_test.go and
// TestOpengrepG2OfferedSurfaces below describe it).

// TestOpengrepG2InertWithNoComponentsBlock: no loop starts, the dashboard
// seam reports nothing, and nothing is planned, downloaded or written.
func TestOpengrepG2InertWithNoComponentsBlock(t *testing.T) {
	if !securityOptIn[opengrepComponent] {
		t.Skip("security.scan.opengrep is offered: TestOpengrepG2OfferedSurfaces covers it")
	}
	var out bytes.Buffer
	legacy := newGatedGroup(namedGroup{}, componentstate.Legacy(), &out)
	// namedGroup{} has no errgroup: a loop that started here would panic.
	startOpengrepDaemon(context.Background(), legacy, "", componentstate.Legacy())
	if len(legacy.skipped) != 0 || out.Len() != 0 {
		t.Fatalf("legacy: skipped %v out %q", legacy.skipped, out.String())
	}
	cfg := noBlockConfig(t)
	e, err := codeEnvForDash(cfg, nil)
	if err != nil || e != nil {
		t.Fatalf("the dashboard seam opened an env with no block: %v", err)
	}
	st, err := opengrepDash(cfg, nil).Status(context.Background())
	if err != nil || st.Selected {
		t.Fatalf("the card reads selected with no block: %+v %v", st, err)
	}
	// Selected under a block, the loop may start as its own row.
	added := componentstate.Resolve(config.ComponentsConfig{Add: []string{opengrepComponent}}, nil)
	if !loopAllowed(added, "security.scan.opengrep") {
		t.Fatal("selected: the code rules loop is not allowed to start")
	}
	removed := componentstate.Resolve(config.ComponentsConfig{Remove: []string{opengrepComponent}}, nil)
	if loopAllowed(removed, "security.scan.opengrep") {
		t.Fatal("removed: the code rules loop may still start")
	}
}

// TestOpengrepG2OfferedSurfaces states what an existing install sees once
// the orchestrator offers security.scan.opengrep (deletes its securityOptIn
// entry, flips its catalog row's distros and deletes this skip): the Code
// rules card and its install dialog with both sizes and the consent text,
// the triggers at their defaults (post-write and commit diff on, the
// schedule off, all idle until Opengrep is installed), and still nothing
// downloaded until the developer accepts once.
func TestOpengrepG2OfferedSurfaces(t *testing.T) {
	if securityOptIn[opengrepComponent] {
		t.Skip("security.scan.opengrep is opt-in until the orchestrator offers it (lane sec-g2); the offer deletes its securityOptIn entry and this skip")
	}
	cfg := noBlockConfig(t)
	e, err := codeEnvForDash(cfg, nil)
	if err != nil || e == nil {
		t.Fatalf("offered: no env: %v", err)
	}
	st := e.dashStatus(context.Background())
	if !st.Selected || st.Installed || st.Consented {
		t.Fatalf("offered status %+v", st)
	}
	if p := secengine.PlanInstall(e.installInput(context.Background())); p.Blocked == "" && (st.ConsentText == "" || !p.NeedsConsent) {
		t.Fatalf("offered: the install does not wait for the consent: %+v", p)
	}
	if !st.PostWrite || !st.CommitDiff || st.ScheduleHours != 0 {
		t.Fatalf("offered trigger defaults %+v", st)
	}
	added := componentstate.Legacy()
	if !loopAllowed(added, "security.scan.opengrep") {
		t.Fatal("offered: the code rules loop is not allowed to start")
	}
}
