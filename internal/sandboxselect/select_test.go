package sandboxselect

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// okInput is a launch that bwrap satisfies: every rule passes.
func okInput() Input {
	return Input{
		Request: Request{Tier: vocab.TierInternet, Source: "live", Interactive: true, Custody: vocab.CustodyHostBound},
		Host:    sandboxbackend.HostWSL2,
		Enabled: []string{sandboxbackend.BackendBwrap},
		Probes: map[string]Probe{sandboxbackend.BackendBwrap: {
			Compiled: true, Verdict: VerdictAvailable, Version: "0.9.0", Sources: []string{"live", "clone-local"},
		}},
		Tool: Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
	}
}

func TestBwrapIsChosenWhenEveryRulePasses(t *testing.T) {
	res := Select(okInput())
	if res.Chosen == nil {
		t.Fatalf("nothing chosen: %+v", res.Drops)
	}
	c := res.Chosen
	if c.Backend != sandboxbackend.BackendBwrap || c.Class != vocab.ClassProcess || c.Capture.Level != vocab.CaptureFull || !c.Capture.ProviderBlock || c.Beta {
		t.Fatalf("choice = %+v", c)
	}
}

// remoteRow is a synthetic offered remote row for the remote-only rules.
func remoteRow() sandboxbackend.Capability {
	r := sandboxbackend.Capability{
		ID: "remote-test", Label: "remote", Maturity: sandboxbackend.MaturityPreview,
		Verification: []sandboxbackend.Verified{{Host: sandboxbackend.HostWSL2, Kind: vocab.VerifiedLive, Source: "test"}},
		Iso:          sandboxbackend.Isolation{Class: vocab.ClassHWVM, ClassSource: vocab.SourceDocumented, Location: vocab.LocationRemote, Tenancy: sandboxbackend.TenancyPerRun, Hosts: []sandboxbackend.HostKind{sandboxbackend.HostWSL2}},
		Control:      sandboxbackend.Control{Pins: sandboxbackend.DriverPins{RequiredMin: "1.0.0", TestedLow: "1.0.0", TestedHigh: "1.0.0"}},
		Term:         sandboxbackend.Terminal{PTYOwner: sandboxbackend.PTYBackendExec, Resize: sandboxbackend.ResizeBackendAPI},
		Net: sandboxbackend.Network{
			Egress: []vocab.Tier{vocab.TierProxyOnly, vocab.TierInternet}, Enforcer: sandboxbackend.EnforcerProvider,
			EgressSource: map[vocab.Tier]vocab.ClassSource{vocab.TierProxyOnly: vocab.SourceDocumented, vocab.TierInternet: vocab.SourceDocumented},
			KeyCustody:   []vocab.KeyCustody{vocab.CustodyInBoxAPIKey, vocab.CustodyProviderInjected},
		},
		Capture:            sandboxbackend.Capture{Ceiling: vocab.CaptureFull, HookPath: sandboxbackend.HookRelay},
		LifetimeCapSeconds: 1800,
	}
	return r
}

func remoteInput() Input {
	in := okInput()
	in.Request.Tier = vocab.TierProxyOnly
	in.Request.Custody = vocab.CustodyInBoxAPIKey
	in.Request.Region = "eu"
	in.Enabled = []string{"remote-test"}
	in.Probes = map[string]Probe{"remote-test": {Compiled: true, Verdict: VerdictAvailable, Version: "1.0.0", Sources: []string{"live"}, ConsentRecorded: true}}
	in.Floors.AllowRemote = true
	return in
}

// TestSelectionRules: one case per row of section 4.5's table. Each case
// starts from an input every rule passes and changes exactly what makes
// its row fire.
func TestSelectionRules(t *testing.T) {
	bw := bwrapRow(t)
	for _, tc := range []struct {
		rule, verdict string
		row           func() sandboxbackend.Capability
		base          func() Input
		mut           func(*Input, *sandboxbackend.Capability)
		auto          bool
	}{
		{"S0", VerdictNotEligibleForEnforcement, nil, nil, func(in *Input, _ *sandboxbackend.Capability) {
			in.Request.GuardEnforce = true
			in.Request.Tier = vocab.TierHost
		}, false},
		{"S1", VerdictNotInBuild, nil, nil, func(in *Input, _ *sandboxbackend.Capability) {
			p := in.Probes[sandboxbackend.BackendBwrap]
			p.Compiled = false
			in.Probes[sandboxbackend.BackendBwrap] = p
		}, false},
		{"S1b", VerdictExplicitOnly, nil, nil, func(_ *Input, r *sandboxbackend.Capability) { r.ExplicitOnly = true }, true},
		{"S2", VerdictDisabledByConfig, nil, nil, func(in *Input, _ *sandboxbackend.Capability) { in.Enabled = nil }, false},
		{"S2b", VerdictBackendVersionUntested, nil, nil, func(in *Input, _ *sandboxbackend.Capability) {
			p := in.Probes[sandboxbackend.BackendBwrap]
			p.Version = "0.3.9"
			in.Probes[sandboxbackend.BackendBwrap] = p
		}, false},
		{"S3", VerdictUnsupportedPlatform, nil, nil, func(in *Input, _ *sandboxbackend.Capability) { in.Host = sandboxbackend.HostMacOS }, false},
		// The platform rule wins over the version rule (live check macOS
		// 2026-10-22, D1): on darwin the bwrap probe reads no version.
		{"S3", VerdictUnsupportedPlatform, nil, nil, func(in *Input, _ *sandboxbackend.Capability) {
			in.Host = sandboxbackend.HostMacOS
			p := in.Probes[sandboxbackend.BackendBwrap]
			p.Version, p.Verdict = "", "unsupported_platform"
			in.Probes[sandboxbackend.BackendBwrap] = p
		}, false},
		// Absence wins over the version rule (live check InstaBox
		// 2026-10-22, D1): a missing bwrap has no version.
		{"S4", "backend_missing", nil, nil, func(in *Input, _ *sandboxbackend.Capability) {
			p := in.Probes[sandboxbackend.BackendBwrap]
			p.Version, p.Verdict = "", "backend_missing"
			in.Probes[sandboxbackend.BackendBwrap] = p
		}, false},
		// Inactivity wins over the version rule: a driver left off by its
		// opt-in rule is probed as module_inactive, with no version.
		{"S4", "module_inactive", nil, nil, func(in *Input, _ *sandboxbackend.Capability) {
			p := in.Probes[sandboxbackend.BackendBwrap]
			p.Version, p.Verdict = "", "module_inactive"
			in.Probes[sandboxbackend.BackendBwrap] = p
		}, false},
		{"S4", "userns_denied", nil, nil, func(in *Input, _ *sandboxbackend.Capability) {
			p := in.Probes[sandboxbackend.BackendBwrap]
			p.Verdict = "userns_denied"
			in.Probes[sandboxbackend.BackendBwrap] = p
		}, false},
		{"S4b", VerdictBetaBelowFloor, nil, nil, func(in *Input, _ *sandboxbackend.Capability) {
			p := in.Probes[sandboxbackend.BackendBwrap]
			p.Version = "0.14.0" // above the tested range: beta
			in.Probes[sandboxbackend.BackendBwrap] = p
			in.Floors.OrgMinClass = vocab.ClassProcess
		}, false},
		// Ruling P-062 (clarified in P-067): an automatic choice never picks
		// a row whose verification on this host is documentation only.
		{"S4c", VerdictBetaNotChosen, nil, nil, func(_ *Input, r *sandboxbackend.Capability) {
			r.Verification = []sandboxbackend.Verified{{Host: sandboxbackend.HostWSL2, Kind: vocab.VerifiedDoc, Source: "test"}}
		}, true},
		{"S5", VerdictBelowRequestedClass, nil, nil, func(in *Input, _ *sandboxbackend.Capability) { in.Request.MinClass = vocab.ClassContainer }, false},
		{"S6", VerdictBelowOrgFloor, nil, nil, func(in *Input, _ *sandboxbackend.Capability) { in.Floors.OrgMinClass = vocab.ClassHWVM }, false},
		{"S6", VerdictBelowMachineFloor, nil, nil, func(in *Input, _ *sandboxbackend.Capability) { in.Floors.MachineMinClass = vocab.ClassHWVM }, false},
		{"S6", VerdictBelowOrgFloor, nil, nil, func(in *Input, r *sandboxbackend.Capability) {
			in.Floors.OrgMinClass = vocab.ClassProcess
			r.Iso.ClassSource = vocab.SourceClaimed // a claimed class counts as none
		}, false},
		{"S6b", VerdictBelowEgressFloor, nil, nil, func(in *Input, _ *sandboxbackend.Capability) { in.Floors.MinEgress = vocab.TierProxyOnly }, false},
		{"S7", VerdictBackendNotAllowed, nil, nil, func(in *Input, _ *sandboxbackend.Capability) { in.Floors.AllowedBackends = []string{"oci-runc"} }, false},
		{"S7", VerdictBackendNotAllowed, remoteRow, remoteInput, func(in *Input, _ *sandboxbackend.Capability) { in.Floors.AllowRemote = false }, false},
		{"S7b", VerdictRegionNotAllowed, remoteRow, remoteInput, func(in *Input, _ *sandboxbackend.Capability) { in.Floors.AllowedRegions = []string{"us"} }, false},
		{"S7b", VerdictConsentRequired, remoteRow, remoteInput, func(in *Input, _ *sandboxbackend.Capability) {
			p := in.Probes["remote-test"]
			p.ConsentRecorded = false
			in.Probes["remote-test"] = p
		}, false},
		{"S7b", VerdictCustodyNotAllowed, remoteRow, remoteInput, func(in *Input, _ *sandboxbackend.Capability) {
			in.Request.Custody = vocab.CustodyProviderInjected
			in.Floors.ForbidProviderInject = true
		}, false},
		{"S7c", VerdictHostMutationRequired, nil, nil, func(_ *Input, r *sandboxbackend.Capability) { r.Iso.HostMutation = true }, false},
		{"S7d", VerdictCustodyUnsatisfiable, nil, nil, func(in *Input, _ *sandboxbackend.Capability) { in.Request.Custody = vocab.CustodyInBoxAPIKey }, false},
		{"S7d", VerdictCustodyUnsatisfiable, nil, nil, func(in *Input, _ *sandboxbackend.Capability) {
			in.Request.Custody = vocab.CustodyHomeRelay
			in.Tool.SatisfiableCustody = []vocab.KeyCustody{vocab.CustodyHostBound}
		}, false},
		{"S8", VerdictEgressUnsupported, nil, nil, func(_ *Input, r *sandboxbackend.Capability) { r.Net.Egress = []vocab.Tier{vocab.TierNone} }, false},
		{"S8", VerdictEgressUnsupported, remoteRow, remoteInput, func(in *Input, r *sandboxbackend.Capability) {
			r.Net.Egress = append(r.Net.Egress, vocab.TierHost)
			in.Request.Tier = vocab.TierHost
			in.Request.AcceptReducedCapture = true
		}, false},
		{"S9", VerdictSourceUnsupported, nil, nil, func(in *Input, _ *sandboxbackend.Capability) { in.Request.Source = "worktree" }, false},
		{"S10", VerdictToolUnmapped, nil, nil, func(in *Input, _ *sandboxbackend.Capability) { in.Tool.Mapped = false }, false},
		{"S10", VerdictToolConflict, nil, nil, func(in *Input, _ *sandboxbackend.Capability) { in.Tool.NativeConflict = true }, false},
		{"S11", VerdictToolUnavailableInImage, nil, nil, func(in *Input, _ *sandboxbackend.Capability) {
			p := in.Probes[sandboxbackend.BackendBwrap]
			p.ToolMissing = true
			in.Probes[sandboxbackend.BackendBwrap] = p
		}, false},
		{"S11b", VerdictNotInteractive, nil, nil, func(_ *Input, r *sandboxbackend.Capability) { r.Term.Resize = sandboxbackend.ResizeNone }, false},
		{"S12", VerdictReducedCaptureNotAccepted, nil, nil, func(in *Input, _ *sandboxbackend.Capability) { in.Request.Tier = vocab.TierHost }, false},
		{"S12b", VerdictReducedCaptureNotAllowed, nil, nil, func(in *Input, _ *sandboxbackend.Capability) {
			in.Request.Tier = vocab.TierHost
			in.Request.AcceptReducedCapture = true
			in.Floors.RequireFullCapture = true
		}, false},
		{"S13", VerdictLifetimeCapTooShort, remoteRow, remoteInput, func(in *Input, _ *sandboxbackend.Capability) { in.Request.MinSessionMinutes = 60 }, false},
	} {
		t.Run(tc.rule+" "+tc.verdict, func(t *testing.T) {
			row, in := bw, okInput()
			if tc.row != nil {
				row, in = tc.row(), tc.base()
			}
			if d, ok := judge(newCandidate(row, in, tc.auto)); !ok {
				t.Fatalf("the base case drops already: %+v", d)
			}
			tc.mut(&in, &row)
			d, ok := judge(newCandidate(row, in, tc.auto))
			if ok || d.Rule != tc.rule || d.Verdict != tc.verdict {
				t.Fatalf("drop = %+v (ok %v), want rule %s verdict %s", d, ok, tc.rule, tc.verdict)
			}
			if d.Reason == "" {
				t.Fatal("a drop without a reason")
			}
		})
	}
}

// Mutation proof (1): an explicit backend that probes unavailable is
// refused, never substituted.
func TestExplicitBackendIsNeverSubstituted(t *testing.T) {
	in := okInput()
	in.Request.Backend = sandboxbackend.BackendBwrap
	p := in.Probes[sandboxbackend.BackendBwrap]
	p.Verdict = "backend_missing"
	in.Probes[sandboxbackend.BackendBwrap] = p
	res := Select(in)
	if res.Chosen != nil || len(res.Drops) != 1 || res.Drops[0].Verdict != "backend_missing" {
		t.Fatalf("result = %+v", res)
	}
	in.Request.Backend = sandboxbackend.BackendCodespaces
	res = Select(in)
	if res.Chosen != nil || res.Drops[0].Verdict != VerdictNotInBuild || !strings.Contains(res.Drops[0].Reason, "planned") {
		t.Fatalf("a planned explicit backend: %+v", res)
	}
	in.Request.Backend = "made-up"
	if res := Select(in); res.Chosen != nil || res.Drops[0].Verdict != VerdictNotInBuild {
		t.Fatalf("an unknown explicit backend: %+v", res)
	}
}

// Mutation proof (2): auto never returns a stack below min_isolation or a
// floor; with nothing strong enough it fails closed listing every drop.
func TestAutoNeverPicksBelowAFloor(t *testing.T) {
	for _, mut := range []func(*Input){
		func(in *Input) { in.Request.MinClass = vocab.ClassContainer },
		func(in *Input) { in.Floors.OrgMinClass = vocab.ClassUserspaceKernel },
		func(in *Input) { in.Floors.MachineMinClass = vocab.ClassHWVM },
	} {
		in := okInput()
		mut(&in)
		res := Select(in)
		if res.Chosen != nil {
			t.Fatalf("auto chose %+v below a floor", res.Chosen)
		}
		if len(res.Drops) != len(sandboxbackend.Offered()) {
			t.Fatalf("drops %+v do not list every offered candidate", res.Drops)
		}
	}
}

// Mutation proof (4): a beta row (not live on this host, or a version
// outside the tested range) never satisfies a floor that does not accept
// beta, and does when it does.
func TestBetaNeverMeetsAFloorByDefault(t *testing.T) {
	in := okInput()
	in.Floors.OrgMinClass = vocab.ClassProcess
	p := in.Probes[sandboxbackend.BackendBwrap]
	p.Version = "0.3.99"
	in.Probes[sandboxbackend.BackendBwrap] = p
	if Select(in).Chosen != nil {
		t.Fatal("a refused version was chosen")
	}
	p.Version = "0.20.0"
	in.Probes[sandboxbackend.BackendBwrap] = p
	res := Select(in)
	if res.Chosen != nil || res.Drops[0].Verdict != VerdictBetaBelowFloor {
		t.Fatalf("beta under a floor: %+v", res)
	}
	// A floor that accepts beta: the tested row outside its tested range
	// is chosen automatically, labelled beta (S4c reads the verification
	// only, P-067).
	in.Floors.FloorAcceptsBeta = true
	if res := Select(in); res.Chosen == nil || !res.Chosen.Beta {
		t.Fatalf("an automatic choice of a tested row outside its range under an accepting floor: %+v", res)
	}
	in.Request.Backend = sandboxbackend.BackendBwrap
	if res := Select(in); res.Chosen == nil || !res.Chosen.Beta {
		t.Fatalf("beta with floor_accepts_beta: %+v", res)
	}
	// Without a floor a named beta row is usable, labelled beta.
	in.Floors = Floors{}
	if res := Select(in); res.Chosen == nil || !res.Chosen.Beta {
		t.Fatalf("beta without a floor: %+v", res)
	}
	// A host the row has no grounding on is beta too.
	row := bwrapRow(t)
	row.Verification = nil
	c := newCandidate(row, okInput(), false)
	if !c.beta {
		t.Fatal("no grounding on the host is not beta")
	}
}

// Mutation proof (5): a version below the required minimum is refused.
func TestVersionBelowMinimumIsRefused(t *testing.T) {
	for _, v := range []string{"0.3.0", "", "bubblewrap", "0.x"} {
		in := okInput()
		p := in.Probes[sandboxbackend.BackendBwrap]
		p.Version = v
		in.Probes[sandboxbackend.BackendBwrap] = p
		res := Select(in)
		if res.Chosen != nil || res.Drops[0].Verdict != VerdictBackendVersionUntested {
			t.Errorf("version %q: %+v", v, res)
		}
	}
}

// Mutation proof (6): the guard's enforce auto-upgrade never lands on a
// remote, reduced-capture or non-live row.
func TestGuardAutoUpgradeOnlyLandsOnALiveFullLocalRow(t *testing.T) {
	in := okInput()
	in.Request.GuardEnforce = true
	if res := Select(in); res.Chosen == nil || res.Chosen.Capture.Level != vocab.CaptureFull {
		t.Fatalf("the live full local row: %+v", res)
	}
	for name, mut := range map[string]func(*Input, *sandboxbackend.Capability){
		"remote":          func(_ *Input, r *sandboxbackend.Capability) { r.Iso.Location = vocab.LocationRemote },
		"reduced capture": func(in *Input, _ *sandboxbackend.Capability) { in.Request.Tier = vocab.TierHost },
		"not live":        func(_ *Input, r *sandboxbackend.Capability) { r.Verification = nil },
		"beta version": func(in *Input, _ *sandboxbackend.Capability) {
			p := in.Probes[sandboxbackend.BackendBwrap]
			p.Version = "0.99.0"
			in.Probes[sandboxbackend.BackendBwrap] = p
		},
	} {
		row, in := bwrapRow(t), okInput()
		in.Request.GuardEnforce = true
		mut(&in, &row)
		d, ok := judge(newCandidate(row, in, true))
		if ok || d.Verdict != VerdictNotEligibleForEnforcement {
			t.Errorf("%s: %+v", name, d)
		}
	}
}

func TestAutoWalksThePreferenceOrderAndShowsEveryDrop(t *testing.T) {
	in := okInput()
	in.Enabled = []string{sandboxbackend.BackendCodespaces, sandboxbackend.BackendBwrap}
	res := Select(in)
	if res.Chosen == nil || res.Chosen.Backend != sandboxbackend.BackendBwrap {
		t.Fatalf("result %+v", res)
	}
	if len(res.Drops) != 1 || res.Drops[0].Backend != sandboxbackend.BackendCodespaces {
		t.Fatalf("the planned row's drop is not shown first: %+v", res.Drops)
	}
	if res.Drops[0].Verdict != VerdictNotInBuild || !strings.Contains(res.Drops[0].Reason, "planned") {
		t.Fatalf("planned row reason: %+v", res.Drops[0])
	}
}

func TestClassifyVersion(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want versionStatus
	}{
		{"0.4.0", versionTested},
		{"bubblewrap 0.13.1", versionTested},
		{"v0.9", versionTested},
		{"0.13.2", versionBeta},
		{"1.0.0-rc1", versionBeta},
		{"0.3.9", versionRefused},
		{"", versionRefused},
		{"0.4.x", versionRefused},
		{"1.2.3.4", versionRefused},
	} {
		if got := classifyVersion(tc.v, "0.4.0", "0.4.0", "0.13.1"); got != tc.want {
			t.Errorf("%q: %d, want %d", tc.v, got, tc.want)
		}
	}
}

// TestAutoDropIsTheAutoRows: AutoDrop walks exactly the automatic-choice
// rows of the one table (ruling P-062): a beta row and an explicit-only row
// are dropped, a live tested row is not, and every auto rule is a row of
// selectRules.
func TestAutoDropIsTheAutoRows(t *testing.T) {
	bw := bwrapRow(t)
	if d, dropped := AutoDrop(bw, vocab.VerifiedDoc); !dropped || d.Rule != "S4c" || d.Verdict != VerdictBetaNotChosen || !strings.Contains(d.Reason, "--observer-sandbox bwrap") {
		t.Fatalf("doc-verified row: %+v %v", d, dropped)
	}
	if d, dropped := AutoDrop(bw, vocab.VerifiedLive); dropped {
		t.Fatalf("a live row was dropped: %+v", d)
	}
	eo := bw
	eo.ExplicitOnly = true
	if d, dropped := AutoDrop(eo, vocab.VerifiedLive); !dropped || d.Rule != "S1b" {
		t.Fatalf("explicit-only row: %+v %v", d, dropped)
	}
	ids := map[string]bool{}
	for _, r := range selectRules {
		ids[r.id] = true
	}
	for id := range autoRules {
		if !ids[id] {
			t.Errorf("auto rule %s is not a row of the table", id)
		}
	}
	// An explicit request is never judged by the auto rows.
	in := okInput()
	in.Request.Backend = sandboxbackend.BackendBwrap
	p := in.Probes[sandboxbackend.BackendBwrap]
	p.Version = "0.14.0"
	in.Probes[sandboxbackend.BackendBwrap] = p
	if res := Select(in); res.Chosen == nil || !res.Chosen.Beta {
		t.Fatalf("an explicit beta row was not chosen: %+v", res)
	}
	// An automatic choice reads the verification only (P-067): this tested
	// row outside its tested range is picked, labelled beta.
	in.Request.Backend = ""
	if res := Select(in); res.Chosen == nil || !res.Chosen.Beta {
		t.Fatalf("auto did not pick a tested row outside its range: %+v", res)
	}
}

// TestAutoSelectionReadsVerificationOnly (P-067, the P-062 clarification):
// rule S4c drops a row from automatic choice only when its verification on
// this host is documentation only. A tested row whose installed version is
// outside its tested range (bwrap 0.14.0 above the tested 0.13.1; live
// hosts run 0.11.1 and 0.12.0 today) is still picked automatically and
// keeps its beta label; the oci-runc row, documentation-verified, is not
// picked automatically; a launch that names a documentation-verified row
// still gets it.
func TestAutoSelectionReadsVerificationOnly(t *testing.T) {
	bw := bwrapRow(t)
	oci, ok := sandboxbackend.Get(sandboxbackend.BackendOCIRunc)
	if !ok {
		t.Fatal("no oci-runc row")
	}
	ociVerify, _ := oci.VerificationOn(sandboxbackend.HostLinux)
	if ociVerify.Kind != vocab.VerifiedDoc {
		t.Fatalf("oci-runc on Linux is %q; this case pins its doc verification", ociVerify.Kind)
	}
	cases := []struct {
		name     string
		version  string
		verify   vocab.Verification
		explicit bool
		chosen   bool
		beta     bool
	}{
		{"tested row above its tested high", "0.14.0", vocab.VerifiedLive, false, true, true},
		{"tested row inside its tested range", "0.11.1", vocab.VerifiedLive, false, true, false},
		{"doc-verified row, automatic", "0.11.1", vocab.VerifiedDoc, false, false, true},
		{"doc-verified row, named for the launch", "0.11.1", vocab.VerifiedDoc, true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			row := bw
			row.Verification = []sandboxbackend.Verified{{Host: sandboxbackend.HostWSL2, Kind: c.verify, Source: "test"}}
			in := okInput()
			p := in.Probes[sandboxbackend.BackendBwrap]
			p.Version = c.version
			in.Probes[sandboxbackend.BackendBwrap] = p
			cand := newCandidate(row, in, !c.explicit)
			d, ok := judge(cand)
			if ok != c.chosen {
				t.Fatalf("chosen %v (drop %+v), want %v", ok, d, c.chosen)
			}
			if cand.beta != c.beta {
				t.Fatalf("beta label %v, want %v", cand.beta, c.beta)
			}
			if !ok && (d.Rule != "S4c" || d.Verdict != VerdictBetaNotChosen) {
				t.Fatalf("drop %+v, want S4c beta_not_chosen", d)
			}
		})
	}
	// The real oci-runc row: AutoDrop (the launch path's walk) drops it
	// from an automatic choice by its verification; bwrap, live-verified,
	// is kept whatever its version.
	if d, dropped := AutoDrop(oci, ociVerify.Kind); !dropped || d.Rule != "S4c" {
		t.Fatalf("oci-runc automatic: %+v %v", d, dropped)
	}
	bwVerify, _ := bw.VerificationOn(sandboxbackend.HostLinux)
	if d, dropped := AutoDrop(bw, bwVerify.Kind); dropped {
		t.Fatalf("bwrap automatic: %+v", d)
	}
}

// TestConsentChangeIsNamed (live run 2026-10-23, finding F12): a remote row
// whose recorded consent no longer matches is refused naming what changed,
// never as no consent at all.
func TestConsentChangeIsNamed(t *testing.T) {
	row, in := remoteRow(), remoteInput()
	p := in.Probes["remote-test"]
	p.ConsentRecorded, p.ConsentChange = false, "consent_changed_cap"
	in.Probes["remote-test"] = p
	d, ok := judge(newCandidate(row, in, false))
	if ok || d.Verdict != VerdictConsentRequired || !strings.Contains(d.Reason, "consent_changed_cap") || strings.Contains(d.Reason, "no recorded consent") {
		t.Fatalf("drop %+v", d)
	}
}
