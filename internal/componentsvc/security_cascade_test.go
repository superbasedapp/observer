//go:build !sbo_omit_security

package componentsvc

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestRemovingSecurityTakesItsChildrenWithIt is plans decision log P-015
// (task PT-14, lane sec-c3): a [components] block that removes only
// `security` leaves the module active while `security.secrets` or
// `security.code` stays selected, because a selected child keeps its
// parent (the resolver warns "remove security.code too"). Settings >
// Components and `observer components remove` both go through this
// service, which cascades the removal to every active child, so turning
// the parent off there turns the whole module off. A hand-edited block
// still gets the resolver's warning. The block selects the module and both
// children explicitly, and the file builds only where the module is
// compiled, so the test cannot pass by skipping (lane sec-gate2).
func TestRemovingSecurityTakesItsChildrenWithIt(t *testing.T) {
	for _, distro := range []string{"developer", "full"} {
		t.Run(distro, func(t *testing.T) {
			s, path, _, _ := newSvc(t, seedConfig+"\n[components]\ndistro = \""+distro+"\"\nadd = [\"security\", \"security.secrets\", \"security.code\"]\n")
			ctx := context.Background()
			before, err := s.State(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !before.ModuleActive("security") || !before.ModuleActive("security.secrets") || !before.ModuleActive("security.code") {
				t.Fatalf("the %s distro with the module added does not select it and both children: issues %v", distro, before.Issues)
			}
			p, err := s.Preview(ctx, Change{Remove: []string{"security"}})
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"security", "security.secrets", "security.code"} {
				if !contains(p.Deactivated, id) {
					t.Errorf("removing security leaves %s active: deactivated %v, cascade %v", id, p.Deactivated, p.Cascade)
				}
			}
			for _, id := range []string{"security.secrets", "security.code"} {
				if !contains(p.Cascade, id) {
					t.Errorf("the preview does not name %s as removed with it: cascade %v", id, p.Cascade)
				}
			}
			if _, err := s.Apply(ctx, Change{Remove: []string{"security"}}, ApplyOptions{ExpectFingerprint: p.Fingerprint, Principal: "dashboard"}); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: path, Env: func(string) string { return "" }, GovernanceSidecar: config.NoGovernanceSidecar})
			if err != nil {
				t.Fatal(err)
			}
			after := componentstate.Resolve(cfg.Components, before.ActiveIDs())
			for _, id := range []string{"security", "security.secrets", "security.code"} {
				if after.ModuleActive(id) {
					t.Errorf("%s is still active after the apply", id)
				}
			}
		})
	}
}

// TestHandRemovingOnlySecurityWarns: the same removal written by hand
// keeps the parent active (a selected child needs it) and the resolver
// says which child to remove too, so it is never silent.
func TestHandRemovingOnlySecurityWarns(t *testing.T) {
	s, _, _, _ := newSvc(t, seedConfig+"\n[components]\ndistro = \"developer\"\nadd = [\"security.secrets\"]\nremove = [\"security\"]\n")
	snap, err := s.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !snap.ModuleActive("security.secrets") {
		t.Fatalf("security.secrets added by hand is not active: issues %v", snap.Issues)
	}
	if !snap.ModuleActive("security") {
		t.Fatal("a selected child no longer keeps its parent; update this test and the Settings card copy")
	}
	warned := false
	for _, is := range snap.Issues {
		if strings.Contains(is, "security.secrets") || strings.Contains(is, "security.code") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("no resolver warning names the child to remove: %v", snap.Issues)
	}
}
