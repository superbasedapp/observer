package sandboxbackend

import (
	"strings"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// registry_test.go holds the coverage rules of section 4.2, one test each.

func TestRowKeysMatchIDsAndVocabulary(t *testing.T) {
	known := map[string]bool{
		BackendBwrap: true, BackendProcessLite: true, BackendOCIRunc: true, BackendOCIRunsc: true,
		BackendCloudHypervisor: true, BackendSeatbelt: true, BackendAppleContainer: true, BackendMXCProcess: true,
		BackendCodespaces: true, BackendCoder: true, BackendE2B: true, BackendK8sAgentSandbox: true, BackendAgentCore: true,
		BackendModal: true, BackendVercelSandbox: true,
		BackendMXCAppContainer: true, BackendWSLC: true, BackendHCS: true,
	}
	for key, c := range registry {
		if key != c.ID {
			t.Errorf("row key %q holds id %q", key, c.ID)
		}
		if !known[c.ID] {
			t.Errorf("row %q is not in the closed id vocabulary", c.ID)
		}
		delete(known, c.ID)
	}
	for id := range known {
		t.Errorf("id %q has no row", id)
	}
}

// TestEveryIDPassesTheSharedIDRule (LIN-1 F1): every registry id has the
// shape [terminal.sandbox].backends and the org's managed body accept.
func TestEveryIDPassesTheSharedIDRule(t *testing.T) {
	for _, id := range IDs() {
		if !vocab.ValidBackendID(id) {
			t.Errorf("registry id %q fails sandboxvocab.ValidBackendID", id)
		}
	}
}

func TestPlannedRowsAreNeverOffered(t *testing.T) {
	for _, c := range Offered() {
		if c.Maturity == MaturityPlanned {
			t.Errorf("planned row %q is offered", c.ID)
		}
	}
	// P3 (lane SBX-P3A): bwrap and oci-runc; P5 (lane SBX-P5): seatbelt and
	// apple-container (beta); P6 (lane SBX-P6): mxc-process (beta); P3 (lane
	// SBX-P3B): oci-runsc and process_lite (beta); P7 (lane SBX-P7): e2b,
	// modal and vercel-sandbox (beta); P4 (lane SBX-P4): cloud-hypervisor
	// (beta).
	var ids []string
	for _, c := range Offered() {
		ids = append(ids, c.ID)
	}
	want := []string{BackendAppleContainer, BackendBwrap, BackendCloudHypervisor, BackendE2B, BackendHCS, BackendModal, BackendMXCAppContainer, BackendMXCProcess, BackendOCIRunc, BackendOCIRunsc, BackendProcessLite, BackendSeatbelt, BackendVercelSandbox, BackendWSLC}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("offered rows = %v, want %v", ids, want)
	}
}

func TestEveryRowHasItsRequiredFields(t *testing.T) {
	for _, c := range registry {
		if c.Label == "" || c.Phase == "" {
			t.Errorf("%s: label or phase empty", c.ID)
		}
		if c.Maturity == MaturityPlanned && c.Note == "" {
			t.Errorf("%s: a planned row needs a note", c.ID)
		}
		if !c.Iso.Class.Valid() || len(c.Iso.Hosts) == 0 || c.Iso.Location == "" {
			t.Errorf("%s: class %q, hosts %v, location %q", c.ID, c.Iso.Class, c.Iso.Hosts, c.Iso.Location)
		}
		if c.Capture.Ceiling != "" && !c.Capture.Ceiling.Valid() {
			t.Errorf("%s: capture ceiling %q", c.ID, c.Capture.Ceiling)
		}
		for _, tr := range c.Net.Egress {
			if !tr.Valid() {
				t.Errorf("%s: tier %q", c.ID, tr)
			}
		}
	}
}

func TestRemoteRowsDiscloseDataLeaving(t *testing.T) {
	for _, c := range registry {
		if c.Iso.Location != vocab.LocationRemote {
			continue
		}
		found := false
		for _, d := range c.Discloses {
			found = found || d == DiscloseDataLeaves
		}
		if !found {
			t.Errorf("%s: remote without data_leaves_machine", c.ID)
		}
	}
}

func TestCrossingAKernelNeverWritesTheDatabaseDirectly(t *testing.T) {
	for _, c := range registry {
		if c.Iso.CrossesKernel && c.Capture.HookPath == HookDirectDB {
			t.Errorf("%s: crosses a kernel with a direct_db hook path (invariant I5)", c.ID)
		}
	}
}

func TestOfferedRowsAreFullyGrounded(t *testing.T) {
	for _, c := range Offered() {
		if c.Capture.Ceiling == "" || c.Capture.HookPath == "" || c.ReadBack == "" {
			t.Errorf("%s: offered without ceiling, hook path or read-back", c.ID)
		}
		if c.ReadBack == ReadBackNone && c.Iso.ClassSource == vocab.SourceMeasured {
			t.Errorf("%s: measured class with no read-back", c.ID)
		}
		if c.Capture.Ceiling == vocab.CaptureFull && !c.Capture.HookPath.ReachesHome() {
			t.Errorf("%s: full ceiling while hooks are judged in the box", c.ID)
		}
		if c.Term.Resize == "" || c.Term.PTYOwner == "" {
			t.Errorf("%s: no resize path or PTY owner", c.ID)
		}
		if (c.Term.Reattach == ReattachBackendNative || c.Term.Reattach == ReattachDetachTool) && c.Term.RelayReattach == RelayReattachNone {
			t.Errorf("%s: the PTY survives a drop but the relay cannot come back", c.ID)
		}
		if c.Term.RelayReattach == "" {
			t.Errorf("%s: RelayReattach not declared", c.ID)
		}
		for _, tr := range c.Net.Egress {
			if _, ok := c.Net.EgressSource[tr]; !ok {
				t.Errorf("%s: tier %s has no egress source", c.ID, tr)
			}
		}
		if c.Control.Pins.RequiredMin == "" || c.Control.Pins.TestedHigh == "" {
			t.Errorf("%s: no version pins", c.ID)
		}
		if c.Control.CGORequired {
			t.Errorf("%s: requires CGO", c.ID)
		}
		if c.Control.Stability == StabilityInternal || c.Control.Stability == StabilityExperimental {
			t.Errorf("%s: fail-closed guarantees on an unstable surface", c.ID)
		}
		for _, h := range c.Iso.Hosts {
			v, ok := c.VerificationOn(h)
			if !ok {
				t.Errorf("%s: no grounding on %s", c.ID, h)
				continue
			}
			if v.Kind == vocab.VerifiedLive && v.Source == "" {
				t.Errorf("%s: live on %s without a receipt", c.ID, h)
			}
			if v.Kind != vocab.VerifiedLive && v.RegisterRef == "" {
				t.Errorf("%s: beta on %s without a register row", c.ID, h)
			}
		}
	}
}

func TestSharedTenancyIsNeverAVMLayer(t *testing.T) {
	for _, c := range registry {
		if c.Iso.Tenancy == TenancyShared && c.Iso.Class == vocab.ClassHWVM {
			t.Errorf("%s: a shared VM as an hw_vm layer", c.ID)
		}
	}
}

func TestHostMutationIsDisclosed(t *testing.T) {
	for _, c := range registry {
		if !c.Iso.HostMutation {
			continue
		}
		found := false
		for _, d := range c.Discloses {
			found = found || d == DiscloseHostMutation
		}
		if !found {
			t.Errorf("%s: host mutation not disclosed", c.ID)
		}
	}
}

func TestConnectorsReachKnownRowsAndAreNotBackends(t *testing.T) {
	for _, cn := range Connectors() {
		if _, ok := registry[cn.ID]; ok {
			t.Errorf("connector %q is also a backend row", cn.ID)
		}
		for _, id := range cn.Reaches {
			c, ok := registry[id]
			if !ok || c.Iso.Location != vocab.LocationRemote {
				t.Errorf("connector %q reaches %q, not a remote backend row", cn.ID, id)
			}
		}
		if !strings.Contains(cn.Note, "planned") {
			t.Errorf("connector %q is not built in P1a; its note must say planned", cn.ID)
		}
	}
}

// TestMacOSRowsAreDocVerified (lane SBX-P5): every offered macOS row is
// doc-verified (so labelled beta) with its register rows named. The doc
// verification is what keeps it out of an automatic choice (sandboxselect
// rule S4c, ruling P-062, TestAutoDropMacOSRows) and the guard's
// auto-upgrade (S0); no row carries a second, explicit-only switch for it.
func TestMacOSRowsAreDocVerified(t *testing.T) {
	n := 0
	for _, c := range Offered() {
		if !c.RunsOn(HostMacOS) {
			continue
		}
		n++
		v, ok := c.VerificationOn(HostMacOS)
		if !ok || v.Kind != vocab.VerifiedDoc || !strings.Contains(v.RegisterRef, "MAC-") || v.Source == "" {
			t.Errorf("%s: macOS grounding %+v, want doc with a MAC register ref", c.ID, v)
		}
		if c.ExplicitOnly {
			t.Errorf("%s: a beta macOS row is kept out of auto by its verification (S4c), not by ExplicitOnly", c.ID)
		}
		if c.OffersTier(vocab.TierHost) {
			t.Errorf("%s: the host tier on macOS would leave the daemon's loopback ports reachable", c.ID)
		}
	}
	if n == 0 {
		t.Fatal("no offered macOS row")
	}
}

// TestHostedRowsAreBetaRemoteAndRelayed (lane SBX-P7): the three hosted rows
// are offered, beta on every host (so P-062 keeps auto away), remote with
// the remote disclosures, hooked through the relay over exec_stdio, never
// offer the host tier, never list provider_injected custody, and carry a
// lifetime cap (S13).
func TestHostedRowsAreBetaRemoteAndRelayed(t *testing.T) {
	for _, id := range []string{BackendE2B, BackendModal, BackendVercelSandbox} {
		c, ok := Get(id)
		if !ok || !c.Offered() || c.Maturity != MaturityPreview {
			t.Fatalf("%s: not an offered preview row", id)
		}
		if c.Iso.Location != vocab.LocationRemote || !c.Iso.CrossesKernel || c.Iso.ClassSource != vocab.SourceDocumented {
			t.Errorf("%s: isolation %+v", id, c.Iso)
		}
		for _, h := range c.Iso.Hosts {
			if v, _ := c.VerificationOn(h); v.Kind != vocab.VerifiedDoc || !strings.Contains(v.RegisterRef, "REM-") {
				t.Errorf("%s on %s: %+v, want doc with a REM register ref", id, h, v)
			}
		}
		if c.Capture.HookPath != HookRelay || c.Capture.Relay != RelayExecStdio {
			t.Errorf("%s: capture %+v", id, c.Capture)
		}
		if c.OffersTier(vocab.TierHost) || c.Net.Enforcer != EnforcerProvider {
			t.Errorf("%s: network %+v", id, c.Net)
		}
		for _, k := range c.Net.KeyCustody {
			if k == vocab.CustodyProviderInjected || k == vocab.CustodyHostBound {
				t.Errorf("%s: custody %s", id, k)
			}
		}
		if c.LifetimeCapSeconds <= 0 || c.ExplicitOnly {
			t.Errorf("%s: lifetime %d explicit-only %v", id, c.LifetimeCapSeconds, c.ExplicitOnly)
		}
		disc := map[Disclosure]bool{}
		for _, d := range c.Discloses {
			disc[d] = true
		}
		if !disc[DiscloseDataLeaves] || !disc[DiscloseAccountLogin] || !disc[DisclosePaidTier] {
			t.Errorf("%s: disclosures %v", id, c.Discloses)
		}
		if c.Term.Resize == ResizeGuest && c.Term.PTYOwner != PTYGuestHelper {
			t.Errorf("%s: a guest resize needs the guest helper to own the PTY", id)
		}
	}
}

// TestCloudHypervisorRowIsABetaMeasuredVM (lane SBX-P4): the microVM row is
// offered, beta on Linux and WSL2 with a LIN register ref (so P-062 keeps an
// automatic choice away), a measured hw_vm read back from vm.info, crossing
// a kernel with hooks through the relay over the vsock transport, the guest
// helper holding the PTY, no host tier, and no claim of nested user
// namespaces on the row itself (the driver sets that only from a verified
// image set, N13).
func TestCloudHypervisorRowIsABetaMeasuredVM(t *testing.T) {
	c, ok := Get(BackendCloudHypervisor)
	if !ok || !c.Offered() || c.Maturity != MaturityPreview || c.ExplicitOnly {
		t.Fatalf("row %+v", c)
	}
	for _, h := range []HostKind{HostLinux, HostWSL2} {
		v, ok := c.VerificationOn(h)
		if !ok || v.Kind != vocab.VerifiedDoc || !strings.Contains(v.RegisterRef, "LIN-2") {
			t.Errorf("%s: %+v", h, v)
		}
	}
	if c.Iso.Class != vocab.ClassHWVM || c.Iso.ClassSource != vocab.SourceMeasured || c.ReadBack != ReadBackVMMInfo || !c.Iso.CrossesKernel || c.Iso.Tenancy != TenancyPerRun {
		t.Errorf("isolation %+v read-back %s", c.Iso, c.ReadBack)
	}
	if c.Control.Interface != InterfaceRESTUDS || c.Control.Pins != (DriverPins{RequiredMin: "54", TestedLow: "54", TestedHigh: "54"}) {
		t.Errorf("control %+v", c.Control)
	}
	if c.Term != (Terminal{PTYOwner: PTYGuestHelper, Resize: ResizeGuest, Reattach: ReattachNone, RelayReattach: RelayNotNeeded, Transport: TransportVsockUDS}) {
		t.Errorf("terminal %+v", c.Term)
	}
	if c.Capture != (Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay, Relay: RelayVsockUDS}) {
		t.Errorf("capture %+v", c.Capture)
	}
	if c.OffersTier(vocab.TierHost) || !c.Net.ProviderHostBlock || c.Net.Enforcer != EnforcerObserverGateway {
		t.Errorf("network %+v", c.Net)
	}
	for _, tr := range c.Net.Egress {
		if c.Net.EgressSource[tr] != vocab.SourceDocumented {
			t.Errorf("tier %s: %s until a live receipt", tr, c.Net.EgressSource[tr])
		}
	}
	if c.GuestUnprivUserns || c.PassesKVM {
		t.Errorf("the row claims nested userns %v or /dev/kvm passthrough %v", c.GuestUnprivUserns, c.PassesKVM)
	}
}
