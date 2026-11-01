//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

// TestProjectFloorConsumers is lane sec-p3 milestone 2's consumer half: the
// consumers that know their project read the project-aware seam. A project
// section forbidding online checks stops the install gate's online answer
// (the daemon's per-ask check, secfeed's EnabledFor) and a scan's online
// matching in that project only; another project and the org-wide reading
// keep them on.
func TestProjectFloorConsumers(t *testing.T) {
	sc := config.DefaultSecurityConfig() // online on
	withProjectSections(t, false, true, sc, map[string]guard.ProjectFamilyLoad{
		"/strict": matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 2, `{"allow":{"online_checks":"forbidden"}}`, "X")}}),
	})
	shown := secfeed.Disclosure{Version: secfeed.DisclosureVersion, ShownAt: time.Now(), Surface: "cli", Verified: true}
	cfg := config.Config{Security: sc}

	scan := &depsScanEnv{cfg: cfg, disclose: shown}
	if got := scan.onlineBlockedAt("/strict"); got != "online_checks_off" {
		t.Fatalf("scan in the strict project: %q, want online_checks_off", got)
	}
	if got := scan.onlineBlockedAt("/relaxed"); got != "" {
		t.Fatalf("scan in another project: %q, want open", got)
	}
	if got := scan.onlineBlocked(); got != "" {
		t.Fatalf("org-wide reading: %q, want open", got)
	}

	ask := &depsEnv{cfg: cfg, disclose: shown}
	if ask.onlineReadyFor(secfeed.Scope{ProjectRoot: "/strict"}) {
		t.Fatal("the install gate would ask online in the strict project")
	}
	if !ask.onlineReadyFor(secfeed.Scope{ProjectRoot: "/relaxed"}) || !ask.onlineReady() {
		t.Fatal("the install gate stopped online checks outside the strict project")
	}

	// secfeed decides per ask's scope when EnabledFor is set.
	looked := 0
	svc := secfeed.NewService(secfeed.ServiceOptions{
		Classify: func(secfeed.Scope) secfeed.Classifier { return func(secfeed.InstallSpec) bool { return true } },
		Lookup: func(_ context.Context, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer {
			looked++
			return nil
		},
		Enabled:    func() bool { return true },
		EnabledFor: ask.onlineReadyFor,
	})
	spec := []secfeed.InstallSpec{{Eco: secfeed.EcoNpm, Name: "left-pad", Spec: "left-pad", Version: "1.0.0"}}
	svc.Answer(context.Background(), secfeed.Scope{ProjectRoot: "/strict"}, spec)
	if looked != 0 {
		t.Fatal("the strict project's ask reached the online source")
	}
}
