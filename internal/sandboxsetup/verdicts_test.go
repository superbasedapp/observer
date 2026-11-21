package sandboxsetup

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/openshellorg"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxapple"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxlandlock"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxsbpl"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
)

// driverConstants are, per driver package, the verdict constants the verdict
// map may name: the pin that holds every string in verdicts.go equal to the
// driver's own constant.
var driverConstants = map[string][]string{
	"sandbox":         {sandbox.VerdictBackendMissing, sandbox.VerdictBackendTooOld, sandbox.VerdictUserNSDenied, sandbox.VerdictNetNSDenied},
	"sandboxlandlock": {sandboxlandlock.VerdictLandlockUnavailable, sandboxlandlock.VerdictLandlockABITooOld},
	"sandboxoci": {
		sandboxoci.VerdictEngineUnreachable, sandboxoci.VerdictEngineIsDesktopVM, sandboxoci.VerdictEngineModeUnsupported,
		sandboxoci.VerdictImageMissing, sandboxoci.VerdictEngineCannotPull, sandboxoci.VerdictRuntimeMissing,
		sandboxoci.VerdictSocketBridgeUnavailable, sandboxoci.VerdictSocketUntrusted,
	},
	"sandboxvm": {
		sandboxvm.VerdictNoHypervisor, sandboxvm.VerdictNestedVirtUnavailable, sandboxvm.VerdictBackendMissing,
		sandboxvm.VerdictBackendUntrusted, sandboxvm.VerdictImageMissing, sandboxvm.VerdictArtifactUnverified,
	},
	"sandboxsbpl": {sandboxsbpl.VerdictOSTooOld, sandboxsbpl.VerdictBackendMissing, sandboxsbpl.VerdictBackendUntrusted},
	"sandboxapple": {
		sandboxapple.VerdictOSTooOld, sandboxapple.VerdictArchUnsupported, sandboxapple.VerdictNoHypervisor,
		sandboxapple.VerdictBackendMissing, sandboxapple.VerdictBackendUntrusted, sandboxapple.VerdictEngineUnreachable,
		sandboxapple.VerdictImageMissing,
	},
	"sandboxmxc": {sandboxmxc.VerdictPSECUnavailable, sandboxmxc.VerdictPSECBuildTooOld, sandboxmxc.VerdictArtifactMissing, sandboxmxc.VerdictArtifactUnverified},
	"sandboxopenshell": {
		sandboxopenshell.VerdictLandlockABITooOld, sandboxopenshell.VerdictMissing, sandboxopenshell.VerdictBinaryUntrusted,
		sandboxopenshell.VerdictVersionTooOld, sandboxopenshell.VerdictGatewayBinaryMissing,
		sandboxopenshell.VerdictGatewaySupervisorMissing, sandboxopenshell.VerdictGatewayNoDockerAccess,
	},
	"sandboxremote": {sandboxremote.ConsentMissing, sandboxremote.ConsentStaleVersion, sandboxremote.ConsentTampered},
	"openshellorg":  {openshellorg.VerdictSigninRequired, openshellorg.VerdictSigninExpired},
}

// cmdOnlyVerdicts are verdicts whose constant lives in cmd/observer (a main
// package a test here cannot import); lane daemon pins each there.
var cmdOnlyVerdicts = map[string]map[string]bool{
	"sandboxremote": {"credential_missing": true, "custody_unsatisfiable": true},
}

// TestVerdictStringsArePinned: every verdict string of the map is its
// driver's constant.
func TestVerdictStringsArePinned(t *testing.T) {
	for _, d := range verdictMap {
		known, ok := driverConstants[d.Driver]
		if !ok {
			t.Errorf("driver %q has no constant pin row", d.Driver)
			continue
		}
		for _, m := range d.Missing {
			if !stringIn(known, m.Verdict) && !cmdOnlyVerdicts[d.Driver][m.Verdict] {
				t.Errorf("driver %s: verdict %q is not one of its constants", d.Driver, m.Verdict)
			}
		}
	}
}

// TestVerdictMapRows is one test per verdict mapping: the verdict, asked of
// each row its driver probes, names exactly its prerequisite, which is in
// that row's Setup.
func TestVerdictMapRows(t *testing.T) {
	for _, d := range verdictMap {
		for _, m := range d.Missing {
			for _, backend := range d.Backends {
				t.Run(backend+"/"+m.Verdict, func(t *testing.T) {
					if got := missingFromVerdict(backend, m.Verdict, m.ReasonHas); got != m.Prereq {
						t.Errorf("missingFromVerdict = %q, want %q", got, m.Prereq)
					}
					row, ok := sandboxbackend.Get(backend)
					if !ok || !row.Offered() {
						t.Fatalf("backend %q is not an offered registry row", backend)
					}
					if m.Prereq == "" {
						// A shape that names no step: only a reason-split row
						// may say so.
						if m.ReasonHas == "" {
							t.Errorf("a plain row of %q names no step", m.Verdict)
						}
						return
					}
					if !stringIn(row.Setup, m.Prereq) {
						t.Errorf("%s does not list %q in its Setup %v", backend, m.Prereq, row.Setup)
					}
					p, _ := Lookup(m.Prereq)
					if !stringIn(p.Detect.Verdicts, m.Verdict) {
						t.Errorf("%s Detect.Verdicts %v lacks %q", m.Prereq, p.Detect.Verdicts, m.Verdict)
					}
				})
			}
		}
	}
}

// TestVerdictMapPrefixRows is one test per prefix row: a completed verdict
// names its prerequisite on every row the driver probes, the bare prefix
// names none, and the prerequisite is in the row's Setup (audit
// sandbox-terminal-gaps-2026-11-18, H11: consent_changed_<field> named no
// step before).
func TestVerdictMapPrefixRows(t *testing.T) {
	cases := []struct{ backend, verdict, want string }{
		{sandboxbackend.BackendDaytona, "consent_changed_custody", "hosted-consent"},
		{sandboxbackend.BackendE2B, "consent_changed_region", "hosted-consent"},
		{sandboxbackend.BackendModal, "consent_changed_box_binary", "hosted-consent"},
		{sandboxbackend.BackendDaytona, "consent_changed_", ""},
		{sandboxbackend.BackendBwrap, "consent_changed_custody", ""},
	}
	for _, c := range cases {
		if got := missingFromVerdict(c.backend, c.verdict, ""); got != c.want {
			t.Errorf("missingFromVerdict(%s, %s) = %q, want %q", c.backend, c.verdict, got, c.want)
		}
	}
	for _, d := range verdictMap {
		for _, m := range d.MissingPrefix {
			for _, backend := range d.Backends {
				row, ok := sandboxbackend.Get(backend)
				if !ok || !stringIn(row.Setup, m.Prereq) {
					t.Errorf("%s: prefix row %q names %q, not in its Setup", backend, m.Verdict, m.Prereq)
				}
				if got := missingFromVerdict(backend, m.Verdict+"x", ""); got != m.Prereq {
					t.Errorf("%s: %qx = %q, want %q", backend, m.Verdict, got, m.Prereq)
				}
			}
		}
	}
}

// TestVerdictMapShape: each backend appears in one driver row, and no
// verdict appears twice for one driver row.
func TestVerdictMapShape(t *testing.T) {
	seenBackend := map[string]string{}
	for _, d := range verdictMap {
		for _, b := range d.Backends {
			if prev, dup := seenBackend[b]; dup {
				t.Errorf("backend %s in two driver rows (%s, %s)", b, prev, d.Driver)
			}
			seenBackend[b] = d.Driver
		}
		seen := map[string]bool{}
		for _, m := range d.Missing {
			key := m.Verdict + "|" + m.ReasonHas
			if seen[key] {
				t.Errorf("driver %s %v: verdict %q (reason %q) twice", d.Driver, d.Backends, m.Verdict, m.ReasonHas)
			}
			seen[key] = true
			// A reason-split row must sit before its verdict's plain row,
			// or it would never be reached.
			if m.ReasonHas != "" && seen[m.Verdict+"|"] {
				t.Errorf("driver %s: the reason row %q of %q sits after the plain row", d.Driver, m.ReasonHas, m.Verdict)
			}
		}
		for _, id := range d.Ladder {
			for _, b := range d.Backends {
				if r, ok := sandboxbackend.Get(b); ok && !stringIn(r.Setup, id) {
					t.Errorf("driver %s ladder names %q, which %s does not list", d.Driver, id, b)
				}
			}
		}
	}
	if got := missingFromVerdict(sandboxbackend.BackendBwrap, "available", ""); got != "" {
		t.Errorf("available maps to %q", got)
	}
	if got := missingFromVerdict(sandboxbackend.BackendBwrap, "", ""); got != "" {
		t.Errorf("empty maps to %q", got)
	}
	if got := missingFromVerdict("no-such-row", "backend_missing", ""); got != "" {
		t.Errorf("unknown row maps to %q", got)
	}
}
