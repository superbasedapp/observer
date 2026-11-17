package sandboxbackend

import (
	"slices"
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
		BackendOpenShell: true, BackendOpenShellOrg: true,
		BackendDockerSandboxes: true,
		BackendInstaBox:        true,
		BackendDaytona:         true,
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
	want := []string{BackendAppleContainer, BackendBwrap, BackendCloudHypervisor, BackendDaytona, BackendDockerSandboxes, BackendE2B, BackendHCS, BackendInstaBox, BackendModal, BackendMXCAppContainer, BackendMXCProcess, BackendOCIRunc, BackendOCIRunsc, BackendOpenShell, BackendOpenShellOrg, BackendProcessLite, BackendSeatbelt, BackendVercelSandbox, BackendWSLC}
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

// TestHostRefusalsNameHostsTheRowDoesNotRunOn: a declared refusal reason
// is for a host outside the row's Hosts, and is never empty (an empty one
// would read as "no reason" and hide the generic text's host name).
func TestHostRefusalsNameHostsTheRowDoesNotRunOn(t *testing.T) {
	for _, c := range registry {
		for h, reason := range c.Iso.HostRefusals {
			if c.RunsOn(h) {
				t.Errorf("%s: a refusal reason for %s, a host it runs on", c.ID, h)
			}
			if strings.TrimSpace(reason) == "" || c.HostRefusal(h) != reason {
				t.Errorf("%s: refusal reason for %s is %q", c.ID, h, reason)
			}
		}
	}
	if r := (Capability{}).HostRefusal(HostWSL2); r != "" {
		t.Errorf("a row with no refusals answered %q", r)
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
	// The class source each row grounds: docker-sandboxes' cloud isolation
	// is documented nowhere, so it is claimed (dockerHostedRow).
	classSource := map[string]vocab.ClassSource{BackendDockerSandboxes: vocab.SourceClaimed}
	for _, id := range []string{BackendE2B, BackendModal, BackendVercelSandbox, BackendDockerSandboxes, BackendInstaBox, BackendDaytona} {
		c, ok := Get(id)
		if !ok || !c.Offered() || c.Maturity != MaturityPreview {
			t.Fatalf("%s: not an offered preview row", id)
		}
		want := vocab.SourceDocumented
		if s, ok := classSource[id]; ok {
			want = s
		}
		if c.Iso.Location != vocab.LocationRemote || !c.Iso.CrossesKernel || c.Iso.ClassSource != want {
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

// TestSeccompFieldIsGrounded (lane N2): a row's seccomp field is in the
// closed vocabulary or not grounded, a grounded value carries a source
// that counts, the lightweight rows Observer filters say so, and the OCI
// rows name the engine's default filter they read back.
func TestSeccompFieldIsGrounded(t *testing.T) {
	t.Parallel()
	for id, row := range registry {
		if row.Iso.Seccomp == "" {
			if row.Iso.SeccompSource != "" {
				t.Errorf("%s: a seccomp source without a seccomp value", id)
			}
			continue
		}
		if !row.Iso.Seccomp.Valid() {
			t.Errorf("%s: seccomp %q is not in the vocabulary", id, row.Iso.Seccomp)
		}
		if !row.Iso.SeccompSource.CountsForFloor() {
			t.Errorf("%s: seccomp source %q", id, row.Iso.SeccompSource)
		}
	}
	for id, want := range map[string]vocab.Seccomp{
		BackendBwrap:       vocab.SeccompObserverProfile,
		BackendProcessLite: vocab.SeccompObserverProfile,
		BackendOCIRunc:     vocab.SeccompEngineDefault,
		BackendOCIRunsc:    vocab.SeccompEngineDefault,
	} {
		row, _ := Get(id)
		if row.Iso.Seccomp != want {
			t.Errorf("%s: seccomp %q, want %q", id, row.Iso.Seccomp, want)
		}
		if row.FiltersWithObserverProfile() != (want == vocab.SeccompObserverProfile) {
			t.Errorf("%s: FiltersWithObserverProfile disagrees with the field", id)
		}
	}
}

// TestRefusalAuditIsGroundedPerRow (lane N4): one row per backend id says
// on which of its egress tiers a launch is covered by the daemon's refusal
// audit (lane N1), and why. A new backend fails here until it states its
// tiers. An audited row is local, enforced by Observer's own gateway, names
// its grounding, and audits only tiers it offers; the host tier (the shared
// host network, no gateway) is never audited (audit finding N4-A1).
func TestRefusalAuditIsGroundedPerRow(t *testing.T) {
	t.Parallel()
	private := []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone}
	// auditingEnforcers are the enforcers whose refusals reach the daemon's
	// audit: Observer's own gateway (lane N1) and OpenShell's proxy through
	// its OCSF export (lane O3). A provider or a NetworkPolicy never does.
	auditingEnforcers := []EgressEnforcer{EnforcerObserverGateway, EnforcerOpenShellProxy}
	cases := []struct {
		id   string
		want []vocab.Tier
		why  string
	}{
		{BackendBwrap, private, "hostEgressGateway reports on the relay link on internet; proxy_only and none have no way out; host has no gateway"},
		{BackendProcessLite, nil, "no egress enforcer: the host tier only, so nothing is ever refused or recorded"},
		{BackendOCIRunc, private, "hostEgressGateway in the oci host helper and the re-adopt helper"},
		{BackendOCIRunsc, private, "the same oci driver and host helper as oci-runc"},
		{BackendCloudHypervisor, private, "the microVM host helper runs startHostServices; the gateway rides the vsock mux"},
		{BackendSeatbelt, private, "the macOS helper's gateway reports"},
		{BackendAppleContainer, private, "the macOS helper's gateway reports"},
		{BackendMXCProcess, private, "mxcGatewayFor reports over the named pipe"},
		{BackendMXCAppContainer, nil, "runs are refused by name in this release"},
		{BackendWSLC, nil, "provider-enforced, and runs are refused by name"},
		{BackendHCS, nil, "runs are refused by name in this release"},
		{BackendOpenShell, private, "OpenShell's proxy denies; the loopback OCSF receiver maps each denial into the audit, and an internet launch without the export is refused (lane O3)"},
		{BackendE2B, nil, "the provider enforces egress; Observer's gateway never sees it"},
		{BackendOpenShellOrg, nil, "denials happen on the org's machine and are not carried to the node in v1 (g1-design.md section 6.4)"},
		{BackendModal, nil, "the provider enforces egress"},
		{BackendVercelSandbox, nil, "the provider enforces egress"},
		{BackendDockerSandboxes, nil, "the provider enforces egress"},
		{BackendInstaBox, nil, "the provider's own open egress; internet tier only"},
		{BackendDaytona, nil, "the provider enforces egress"},
		{BackendCodespaces, nil, "planned"},
		{BackendCoder, nil, "planned"},
		{BackendK8sAgentSandbox, nil, "planned"},
		{BackendAgentCore, nil, "planned"},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		seen[tc.id] = true
		c, ok := Get(tc.id)
		if !ok {
			t.Errorf("%s: no row", tc.id)
			continue
		}
		if !slices.Equal(c.Net.RefusalAuditTiers, tc.want) {
			t.Errorf("%s: RefusalAuditTiers %v, want %v (%s)", tc.id, c.Net.RefusalAuditTiers, tc.want, tc.why)
		}
		// One case per offered tier: the method agrees with the list, and
		// host is never audited.
		for _, tier := range c.Net.Egress {
			if got, want := c.Net.AuditsRefusalsOn(tier), slices.Contains(tc.want, tier); got != want {
				t.Errorf("%s/%s: AuditsRefusalsOn %v, want %v", tc.id, tier, got, want)
			}
			if tier == vocab.TierHost && c.Net.AuditsRefusalsOn(tier) {
				t.Errorf("%s: the host tier is audited, but it starts no gateway", tc.id)
			}
		}
		for _, tier := range c.Net.RefusalAuditTiers {
			if !c.OffersTier(tier) {
				t.Errorf("%s: audits tier %s it does not offer", tc.id, tier)
			}
		}
		if !c.Net.AuditsRefusals() {
			if c.Net.RefusalAuditSource != "" {
				t.Errorf("%s: a refusal audit source on a row that does not audit", tc.id)
			}
			continue
		}
		if c.Net.RefusalAuditSource == "" || !strings.Contains(c.Net.RefusalAuditSource, "Test") {
			t.Errorf("%s: RefusalAuditTiers without a file and a test in its source", tc.id)
		}
		if !slices.Contains(auditingEnforcers, c.Net.Enforcer) || c.Iso.Location != vocab.LocationLocal || !c.Offered() {
			t.Errorf("%s: RefusalAuditTiers on a row that is not an offered local row whose enforcer reports refusals (%v)", tc.id, auditingEnforcers)
		}
	}
	for _, id := range IDs() {
		if !seen[id] {
			t.Errorf("%s: no refusal audit case", id)
		}
	}
}

// TestOpenShellRow (lane O1A, OpenShell plan doc 04 R2.5): the openshell row
// is an offered preview container row, explicit-only, Linux only, beta with
// the O0 receipt as its grounding, the CLI as its interface, enforced by
// OpenShell's own proxy (never Observer's gateway beside it, W4) on the
// private tiers only, hooked through the relay, and disclosing the CLI
// telemetry, the gateway-wide bind-mount opt-in (D3) and the shared tmpfs
// home (F-017 A4).
func TestOpenShellRow(t *testing.T) {
	t.Parallel()
	c, ok := Get(BackendOpenShell)
	if !ok || !c.Offered() || c.Maturity != MaturityPreview || !c.ExplicitOnly {
		t.Fatalf("row %+v", c)
	}
	if !slices.Equal(c.Iso.Hosts, []HostKind{HostLinux}) || c.RunsOn(HostWSL2) {
		t.Errorf("hosts %v: Linux only (WSL2 fails closed)", c.Iso.Hosts)
	}
	// Live check O5-L2 (2026-11-01): the selector's platform rule refuses
	// WSL2 before the probe's P1 runs, so the row carries P1's reason.
	if r := c.HostRefusal(HostWSL2); r != OpenShellWSL2Refusal || !strings.Contains(r, "WSL2") || !strings.Contains(r, "ENOSYS") {
		t.Errorf("WSL2 refusal reason %q: want one naming WSL2 and ENOSYS", r)
	}
	if r := c.HostRefusal(HostMacOS); r != "" {
		t.Errorf("macOS refusal reason %q: want the selector's generic text", r)
	}
	v, ok := c.VerificationOn(HostLinux)
	if !ok || v.Kind != vocab.VerifiedDoc || !strings.Contains(v.Source, "linux-2026-10-31-f04566") || v.RegisterRef == "" {
		t.Errorf("linux grounding %+v", v)
	}
	if c.Iso.Class != vocab.ClassContainer || c.Iso.ClassSource != vocab.SourceDocumented || c.ReadBack != ReadBackNone || c.Iso.CrossesKernel || c.Iso.Location != vocab.LocationLocal {
		t.Errorf("isolation %+v read-back %s", c.Iso, c.ReadBack)
	}
	if c.Control.Interface != InterfaceCLI || c.Control.Stability != StabilityVendorPreview || c.Control.Pins.RequiredMin != "0.1.6" || !c.Control.Pins.RequireAuthenticatedVersion {
		t.Errorf("control %+v", c.Control)
	}
	// Lane O3: the internet tier is offered (the host list compiled onto
	// OpenShell's network rules); the host tier never is.
	if c.Net.Enforcer != EnforcerOpenShellProxy || c.OffersTier(vocab.TierHost) || !c.OffersTier(vocab.TierInternet) || c.Net.ProviderHostBlock {
		t.Errorf("network %+v", c.Net)
	}
	if c.Capture != (Capture{Ceiling: vocab.CaptureFull, HookPath: HookRelay}) {
		t.Errorf("capture %+v", c.Capture)
	}
	for _, want := range []Disclosure{DiscloseCLITelemetry, DiscloseGatewayBindMounts, DiscloseSharedHomeTmpfs} {
		if !slices.Contains(c.Discloses, want) {
			t.Errorf("missing disclosure %s in %v", want, c.Discloses)
		}
	}
	if c.Term.Reattach != ReattachNone || c.Term.Resize != ResizeBackendAPI {
		t.Errorf("terminal %+v", c.Term)
	}
}

// TestSetupColumn: every offered row carries a setup list or the reason it
// has none, never both and never neither; a planned row carries neither;
// no row lists an id twice. Whether each id names a real prerequisite is
// internal/sandboxsetup's coverage test (this package imports only
// internal/sandboxvocab).
func TestSetupColumn(t *testing.T) {
	for _, id := range IDs() {
		c, _ := Get(id)
		hasList, hasReason := len(c.Setup) > 0, c.SetupUnavailable != ""
		switch {
		case !c.Offered() && (hasList || hasReason):
			t.Errorf("%s: a planned row carries no setup column", id)
		case c.Offered() && hasList == hasReason:
			t.Errorf("%s: an offered row carries exactly one of Setup and SetupUnavailable (list %v, reason %q)", id, c.Setup, c.SetupUnavailable)
		}
		seen := map[string]bool{}
		for _, p := range c.Setup {
			if p == "" || seen[p] {
				t.Errorf("%s: setup id %q empty or listed twice", id, p)
			}
			seen[p] = true
		}
	}
}

// TestSetupBetaRows pins exactly which rows label their setup beta
// (operator ruling P-256): the HCS row only, with its sentence.
func TestSetupBetaRows(t *testing.T) {
	want := map[string]string{
		BackendHCS: "Setup on Windows 11 Pro is beta: it has not been checked on a live host yet.",
	}
	for _, id := range IDs() {
		c, _ := Get(id)
		if c.SetupBeta != want[id] {
			t.Errorf("%s: SetupBeta = %q, want %q", id, c.SetupBeta, want[id])
		}
	}
}
