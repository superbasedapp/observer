package sandboxopenshell

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// goodFacts is a host where every row passes (the GO receipt's host).
func goodFacts() ProbeFacts {
	return ProbeFacts{
		GatewayMode: GatewayExternal,
		Host:        sandboxbackend.HostLinux, CLIFound: true,
		GatewayStatus: "connected", Authentication: "authenticated", GatewayServer: "https://127.0.0.1:17670",
		Version: VersionFacts{CLI: "openshell 0.1.6", Gateway: "0.1.6"},
		Driver:  "docker", LandlockABI: 4, Canary: CanaryOK, BindMounts: TriYes,
		RuntimeImages: goodImages(),
		Engine:        EngineFacts{ID: testEngineID, Record: EngineRecordRead, Recorded: testEngineID, RecordPath: "/s/engine-id.json"},
		GatewayPolicy: GatewayPolicyFacts{SettingsRead: true, Settings: GatewaySettings{ApprovalMode: "manual", Proposals: "false"}, Global: GlobalPolicyAbsent},
	}
}

// goodImages are the v0.1.6 default images as an engine that pulled them
// by tag records them (the index digests).
func goodImages() []ImageFact {
	row, _ := testedRow(Version{Major: 0, Minor: 1, Patch: 6})
	d := DefaultRuntimeImages(row.Version)
	return []ImageFact{
		{Role: ImageSupervisor, Ref: d.Supervisor, Read: true, RepoDigests: []string{CanaryImageRepo + "@" + row.Supervisor.Index}},
		{Role: ImageSandbox, Ref: d.Sandbox, Read: true, RepoDigests: []string{SandboxImageRepo + "@" + row.Sandbox.Index}},
	}
}

// TestProbeTable: one case per row of the probe verdict table, each breaking
// only that row, plus the passing host.
func TestProbeTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mut     func(*ProbeFacts)
		rule    string
		verdict string
		reason  string
	}{
		{"unknown mode", func(f *ProbeFacts) { f.GatewayMode = "remote" }, "P0", VerdictGatewayModeNotBuilt, "unknown"},
		{"unresolved mode", func(f *ProbeFacts) { f.GatewayMode = "" }, "P0", VerdictGatewayModeNotBuilt, "not resolved"},
		{"managed gateway refused", func(f *ProbeFacts) {
			managedGood(f)
			f.Managed = GatewayDecision{Rule: "G4", Action: GatewayRefuse, Verdict: VerdictGatewayCustodyUnavailable, Reason: "no custody"}
		}, "PG", VerdictGatewayCustodyUnavailable, "no custody"},
		{"managed gateway waiting", func(f *ProbeFacts) {
			managedGood(f)
			f.Managed = GatewayDecision{Rule: "G14", Action: GatewayWait, Verdict: VerdictGatewayUpgradePending, Reason: "upgrade"}
		}, "PG", VerdictGatewayUpgradePending, "upgrade"},
		{"managed gateway decision not run", func(f *ProbeFacts) {
			managedGood(f)
			f.Managed = GatewayDecision{}
		}, "PG", VerdictGatewayNotReady, "not run"},
		{"managed start pending re-check", func(f *ProbeFacts) {
			managedGood(f)
			f.Managed = GatewayDecision{Rule: "G12", Action: GatewayStart}
		}, "PG", VerdictGatewayNotReady, "G12"},
		{"managed: another server answered", func(f *ProbeFacts) {
			managedGood(f)
			f.GatewayServer = "https://127.0.0.1:17670"
		}, "P4m", VerdictGatewayNotLocal, "not Observer's private gateway"},
		{"managed: nothing recorded", func(f *ProbeFacts) {
			managedGood(f)
			f.ManagedServer = ""
		}, "P4m", VerdictGatewayNotLocal, "none recorded"},
		{"managed: another name answered from the server", func(f *ProbeFacts) {
			managedGood(f)
			f.GatewayName = "openshell"
		}, "P4m", VerdictGatewayNotLocal, "named \"openshell\""},
		{"managed available", managedGood, "P10", VerdictAvailable, ""},
		{"external skips the managed rows", func(f *ProbeFacts) { f.Managed = GatewayDecision{Action: GatewayRefuse, Verdict: "x"} }, "P10", VerdictAvailable, ""},
		{"wsl2 fails closed", func(f *ProbeFacts) { f.Host = sandboxbackend.HostWSL2 }, "P1", VerdictUnsupportedPlatform, "WSL2"},
		{"macos", func(f *ProbeFacts) { f.Host = sandboxbackend.HostMacOS }, "P1", VerdictUnsupportedPlatform, "native Linux only"},
		{"no cli", func(f *ProbeFacts) { f.CLIFound = false }, "P2", VerdictMissing, "not installed"},
		{"cli only where the user can replace it", func(f *ProbeFacts) { f.CLIUntrusted = "owned by uid 1000" }, "P2", VerdictBinaryUntrusted, "uid 1000"},
		{"gateway disconnected", func(f *ProbeFacts) { f.GatewayStatus = "disconnected" }, "P3", VerdictGatewayUnreachable, `"disconnected"`},
		{"gateway not asked", func(f *ProbeFacts) { f.GatewayStatus = "" }, "P3", VerdictGatewayUnreachable, "not read"},
		{"auth not required", func(f *ProbeFacts) { f.Authentication = "not_required" }, "P4", VerdictGatewayUnauthed, `"not_required"`},
		{"auth failed", func(f *ProbeFacts) { f.Authentication = "failed" }, "P4", VerdictGatewayUnauthed, `"failed"`},
		{"remote gateway", func(f *ProbeFacts) { f.GatewayServer = "https://gateway.example.com:8080" }, "P4b", VerdictGatewayNotLocal, "loopback"},
		{"server not read", func(f *ProbeFacts) { f.GatewayServer = "" }, "P4b", VerdictGatewayNotLocal, "not read"},
		{"untested version", func(f *ProbeFacts) { f.Version = VersionFacts{CLI: "openshell 0.1.7", Gateway: "0.1.7"} }, "P5", VerdictVersionUntested, "0.1.7"},
		{"old version", func(f *ProbeFacts) { f.Version = VersionFacts{CLI: "openshell 0.1.5", Gateway: "0.1.5"} }, "P5", VerdictVersionTooOld, "floor"},
		// The P6 lift (lane FU7, F-033): the Podman driver is taken on a
		// tested version whose row names its launch receipt, and row P8e
		// (no stable engine ID on Podman) does not apply to it.
		// FU7-A1: the shipped table's v0.1.6 row carries only the PENDING
		// placeholder, so the Podman driver is refused there.
		{"podman driver, the shipped table (receipt pending)", func(f *ProbeFacts) { f.Driver = "podman"; f.Engine = EngineFacts{} }, "P6", VerdictDriverUntested, "no live receipt measured on OpenShell 0.1.6"},
		{"an unmeasured driver", func(f *ProbeFacts) { f.Driver = "lxc" }, "P6", VerdictDriverUntested, "only the Docker and Podman drivers"},
		{"landlock abi 2", func(f *ProbeFacts) { f.LandlockABI = 2 }, "P7", VerdictLandlockABITooOld, "ABI is 2"},
		{"landlock abi unread", func(f *ProbeFacts) { f.LandlockABI = 0 }, "P7", VerdictLandlockABITooOld, "could not be read"},
		{"engine replaced", func(f *ProbeFacts) { f.Engine.ID = "B" + testEngineID[1:] }, "P8e", VerdictEngineChanged, "remove \"/s/engine-id.json\""},
		{"supervisor image retagged", func(f *ProbeFacts) {
			f.RuntimeImages[0].RepoDigests = []string{CanaryImageRepo + "@sha256:" + strings.Repeat("0", 64)}
		}, "P8i", VerdictImageDigestMismatch, "supervisor image"},
		{"sandbox image missing", func(f *ProbeFacts) {
			f.RuntimeImages[1] = ImageFact{Role: ImageSandbox, Ref: SandboxImageRepo + ":0.1.6", Read: true, Missing: true}
		}, "P8i", VerdictImageMissing, "sandbox runtime image"},
		{"images not read", func(f *ProbeFacts) { f.RuntimeImages = nil }, "P8i", VerdictImageUnread, "could not read the registry digests"},
		{"canary not run, doctor ok", func(f *ProbeFacts) { f.Canary = CanaryNotRun; f.DoctorOK = true }, "P8", VerdictCanaryNotRun, "doctor check"},
		{"canary enosys, doctor ok", func(f *ProbeFacts) { f.Canary = CanaryENOSYS; f.DoctorOK = true }, "P8", VerdictRuntimeBlocksLandlock, "ENOSYS"},
		{"canary error", func(f *ProbeFacts) { f.Canary = CanaryError }, "P8", VerdictCanaryFailed, "neither an ABI nor ENOSYS"},
		{"canary error with detail", func(f *ProbeFacts) { f.Canary, f.CanaryDetail = CanaryError, "killed" }, "P8", VerdictCanaryFailed, `("killed")`},
		{"canary image missing", func(f *ProbeFacts) {
			f.Canary, f.CanaryImage = CanaryImageMissing, "ghcr.io/nvidia/openshell/supervisor:0.1.6"
		}, "P8", VerdictCanaryImageMissing, `"ghcr.io/nvidia/openshell/supervisor:0.1.6", the gateway's own supervisor image) is not on this machine`},
		{"canary image missing, no name", func(f *ProbeFacts) { f.Canary = CanaryImageMissing }, "P8", VerdictCanaryImageMissing, "never pulls"},
		{"canary timed out", func(f *ProbeFacts) { f.Canary = CanaryTimedOut }, "P8", VerdictCanaryTimedOut, "did not finish within the probe's time limit"},
		{"canary not started", func(f *ProbeFacts) {
			f.Canary, f.CanaryDetail = CanaryNotStarted, "exec /observer-canary: permission denied"
		}, "P8", VerdictCanaryNotStarted, "did not run (\"exec /observer-canary: permission denied\")"},
		{"bind mounts off", func(f *ProbeFacts) { f.BindMounts = TriNo }, "P9", VerdictBindMountsDisabled, "enable_bind_mounts"},
		{"bind mounts unknown", func(f *ProbeFacts) { f.BindMounts = TriUnknown }, "P9", VerdictBindMountsUnknown, "could not tell"},
		// Row PS (lane FU8, OSH-40), one case per row of its table.
		{"gateway global policy", func(f *ProbeFacts) { f.GatewayPolicy.Global = GlobalPolicyPresent }, "PS", VerdictGatewayGlobalPolicy, "gateway-global policy"},
		{"gateway auto approval", func(f *ProbeFacts) { f.GatewayPolicy.Settings.ApprovalMode = "auto" }, "PS", VerdictGatewayAutoApproval, "proposal_approval_mode = auto"},
		{"gateway proposals on", func(f *ProbeFacts) { f.GatewayPolicy.Settings.Proposals = "true" }, "PS", VerdictGatewayPolicyProposals, "agent_policy_proposals_enabled"},
		{"gateway settings unreadable", func(f *ProbeFacts) { f.GatewayPolicy.SettingsRead = false }, "PS", VerdictGatewaySettingsUnknown, "settings get --global"},
		{"gateway global policy unknown", func(f *ProbeFacts) { f.GatewayPolicy.Global = GlobalPolicyUnknown }, "PS", VerdictGatewaySettingsUnknown, "policy get --global"},
		{"managed: auto approval refuses", func(f *ProbeFacts) {
			managedGood(f)
			f.GatewayPolicy.Settings.ApprovalMode = "auto"
		}, "PS", VerdictGatewayAutoApproval, "auto"},
		{"managed: unreadable settings do not refuse", func(f *ProbeFacts) {
			managedGood(f)
			f.GatewayPolicy = GatewayPolicyFacts{}
		}, "P10", VerdictAvailable, ""},
		{"available", func(*ProbeFacts) {}, "P10", VerdictAvailable, ""},
		{"available without doctor", func(f *ProbeFacts) { f.DoctorOK = false }, "P10", VerdictAvailable, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			tc.mut(&f)
			r := Probe(f)
			if r.Rule != tc.rule || r.Verdict != tc.verdict || !strings.Contains(r.Reason, tc.reason) {
				t.Fatalf("got %+v, want rule %s verdict %s reason containing %q", r, tc.rule, tc.verdict, tc.reason)
			}
			if r.Available() != (tc.verdict == VerdictAvailable) {
				t.Fatalf("Available() disagrees with the verdict")
			}
		})
	}
}

// managedGood turns the passing host into a managed one whose private
// gateway is ready and answered from its recorded server.
func managedGood(f *ProbeFacts) {
	f.GatewayMode = GatewayManaged
	f.Managed = GatewayDecision{Rule: "G20", Action: GatewayNone}
	f.ManagedName, f.ManagedServer = "observer-0123456789ab", ServerFor(17701)
	f.GatewayServer, f.GatewayName = ServerFor(17701), "observer-0123456789ab"
}

// TestProbeRuleIndex pins the gathering ladder's order source.
func TestProbeRuleIndex(t *testing.T) {
	t.Parallel()
	if !(ProbeRuleIndex("P2") < ProbeRuleIndex("PG") && ProbeRuleIndex("PG") < ProbeRuleIndex("P3") &&
		ProbeRuleIndex("P4b") < ProbeRuleIndex("P4m") && ProbeRuleIndex("P9") < ProbeRuleIndex("P10")) {
		t.Fatal("probe row order")
	}
	if ProbeRuleIndex("P10") != len(probeRules) || ProbeRuleIndex("nope") != len(probeRules) {
		t.Fatal("unknown rows sort last")
	}
}

// TestProbeRowsHaveCases keeps one case per row: a new row without a case
// fails here.
func TestProbeRowsHaveCases(t *testing.T) {
	t.Parallel()
	want := []string{"P0", "P1", "P2", "PG", "P3", "P4", "P4b", "P4m", "P5", "P6", "P7", "P8e", "P8i", "P8", "P9", "PS"}
	if len(probeRules) != len(want) {
		t.Fatalf("%d probe rows, the table test covers %v", len(probeRules), want)
	}
	for i, r := range probeRules {
		if r.id != want[i] {
			t.Errorf("row %d is %s, want %s", i, r.id, want[i])
		}
	}
}

func TestParseCanary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in  string
		c   Canary
		abi int
	}{
		{"4 0", CanaryOK, 4},
		{"7 0\n", CanaryOK, 7},
		{"-1 38", CanaryENOSYS, 0},
		{"-1 1", CanaryError, 0},
		{"0 0", CanaryError, 0},
		{"", CanaryError, 0},
		{"abc def", CanaryError, 0},
		{"4", CanaryError, 0},
	}
	for _, tc := range cases {
		c, abi := ParseCanary(tc.in)
		if c != tc.c || abi != tc.abi {
			t.Errorf("%q: %s %d, want %s %d", tc.in, c, abi, tc.c, tc.abi)
		}
	}
}

func TestParseStatus(t *testing.T) {
	t.Parallel()
	got, err := ParseStatus([]byte(`{"gateway":"openshell","server":"https://127.0.0.1:17670","status":"connected","version":"0.1.6","authentication":{"status":"authenticated"}}`))
	if err != nil || got != (StatusAnswer{Gateway: "openshell", Server: "https://127.0.0.1:17670", Status: "connected", Authentication: "authenticated", Version: "0.1.6"}) {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := ParseStatus([]byte("not json")); err == nil {
		t.Fatal("garbage accepted")
	}
}

// TestLoopbackServer: the gateway server rule, one case per shape.
func TestLoopbackServer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  string
		want bool
	}{
		{"https://127.0.0.1:17670", true},
		{"https://127.0.0.2:8080", true},
		{"https://[::1]:17670", true},
		{"https://localhost:17670", true},
		{"https://localhost:17670/", true},
		{"", false},
		{"http://127.0.0.1:17670", false},
		{"https://10.0.0.5:17670", false},
		{"https://gateway.example.com", false},
		{"https://localhost.example.com", false},
		{"https://user@127.0.0.1:17670", false},
		{"https://127.0.0.1:17670/api", false},
		{"https://127.0.0.1:17670?x=1", false},
		{"https://[fe80::1%25lo]:17670", false},
		{"https://127.0.0.1:1 7670", false},
		{"https://127.0.0.1", true},
		{"https://127.0.0.1:65535", true},
		{"https://127.0.0.1:", false},
		{"https://[::1]:", false},
		{"https://localhost:", false},
		{"https://127.0.0.1:0", false},
		{"https://127.0.0.1:65536", false},
		{"https://127.0.0.1:99999", false},
	}
	for _, tc := range cases {
		if got := LoopbackServer(tc.raw); got != tc.want {
			t.Errorf("%q: %v, want %v", tc.raw, got, tc.want)
		}
	}
}
