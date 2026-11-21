package sandboxopenshell

import (
	"strings"
	"testing"
)

// readyFacts is a host where the managed gateway runs and is healthy.
func readyFacts() GatewayFacts {
	return GatewayFacts{
		Wanted: true, Custody: CustodyKeychain, CustodyPinned: CustodyKeychain, StateDirLocal: TriYes, RuntimeDirPrivate: TriYes,
		Supervisor: true, DockerAccess: TriYes, BinaryFound: true, BinaryVersion: "openshell-gateway 0.1.6", CLIVersion: "openshell 0.1.6",
		Unit:             UnitActive,
		Record:           &GatewayRecord{Name: "observer-0123456789ab", Port: 17701, Server: ServerFor(17701), Version: "0.1.6", ConfigDigest: "d1"},
		WantConfigDigest: "d1", Healthy: TriYes, Now: 10_000,
	}
}

// launching turns the facts into a gateway launched at started (unix
// seconds) that has not answered yet.
func launching(f *GatewayFacts, started int64) {
	f.Record.Starting, f.Record.StartedAt, f.Healthy = true, started, TriNo
}

// stopped turns the facts into a host whose unit does not run.
func stopped(f *GatewayFacts) { f.Unit = UnitInactive }

// TestDecideGateway is one case per lifecycle row (G1 to G23), plus the
// owner_file custody case and the ordering cases that matter (a refusal
// never starts anything; a live or recorded run is never stopped under).
func TestDecideGateway(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mod     func(f *GatewayFacts)
		rule    string
		action  GatewayAction
		verdict string
		reason  string
	}{
		{"G1 not wanted, idle", func(f *GatewayFacts) { f.Wanted = false }, "G1", GatewayStop, "", ""},
		{"G2 not wanted, a live run", func(f *GatewayFacts) { f.Wanted, f.LiveRuns, f.RecordedRuns = false, 1, 1 }, "G2", GatewayWait, "", ""},
		{"G2 not wanted, an abandoned run awaits its reap", func(f *GatewayFacts) { f.Wanted, f.RecordedRuns = false, 1 }, "G2", GatewayWait, "", ""},
		{"G3 not wanted, not running", func(f *GatewayFacts) { f.Wanted = false; stopped(f) }, "G3", GatewayNone, "", ""},
		{"G3 not wanted, nothing readable", func(f *GatewayFacts) { *f = GatewayFacts{} }, "G3", GatewayNone, "", ""},
		{"G4 foreign state dir", func(f *GatewayFacts) { f.StateDirLocal, f.StateDirFS = TriNo, "9p (DrvFs)" }, "G4", GatewayRefuse, VerdictGatewayStateForeignFS, "9p (DrvFs)"},
		{"G4 state dir unknown", func(f *GatewayFacts) { f.StateDirLocal = TriUnknown }, "G4", GatewayRefuse, VerdictGatewayStateForeignFS, "could not tell"},
		{"G5 runtime dir not RAM", func(f *GatewayFacts) { f.RuntimeDirPrivate, f.RuntimeDirDetail = TriNo, "ext4, not tmpfs" }, "G5", GatewayRefuse, VerdictGatewayRuntimeDirUnsafe, "ext4"},
		{"G6 no keystore", func(f *GatewayFacts) { f.Custody = "" }, "G6", GatewayRefuse, VerdictGatewayCustodyUnavailable, "not read"},
		{"G6 a locked keychain says so", func(f *GatewayFacts) { f.Custody, f.CustodyDetail = "", "the OS keychain is locked" }, "G6", GatewayRefuse, VerdictGatewayCustodyUnavailable, "locked"},
		{"G6 a backend name is not a custody", func(f *GatewayFacts) { f.Custody = "file" }, "G6", GatewayRefuse, VerdictGatewayCustodyUnavailable, ""},
		{"owner_file custody is accepted", func(f *GatewayFacts) { f.Custody, f.CustodyPinned = CustodyOwnerFile, CustodyOwnerFile }, "G23", GatewayNone, "", ""},
		{"first save: nothing pinned yet", func(f *GatewayFacts) { f.CustodyPinned = "" }, "G23", GatewayNone, "", ""},
		{"G7 custody changed to the keychain", func(f *GatewayFacts) { f.CustodyPinned = CustodyOwnerFile }, "G7", GatewayRefuse, VerdictGatewayCustodyChanged, GatewayKeystoreService},
		{"G7 custody changed to owner_file", func(f *GatewayFacts) { f.Custody = CustodyOwnerFile }, "G7", GatewayRefuse, VerdictGatewayCustodyChanged, "never makes a new PKI silently"},
		{"G8 no user manager", func(f *GatewayFacts) { f.Supervisor = false }, "G8", GatewayRefuse, VerdictGatewaySupervisorMissing, "enable-linger"},
		{"G9 user manager without the docker group", func(f *GatewayFacts) { f.DockerAccess, f.DockerAccessDetail = TriNo, "no docker group" }, "G9", GatewayRefuse, VerdictGatewayNoDockerAccess, "log out"},
		{"docker access unknown does not refuse", func(f *GatewayFacts) { f.DockerAccess = TriUnknown }, "G23", GatewayNone, "", ""},
		{"G10 idle gateway, binary removed: stop it", func(f *GatewayFacts) { f.BinaryFound = false }, "G10", GatewayStop, "", ""},
		{"G10 idle gateway, untested upgrade: stop it", func(f *GatewayFacts) { f.BinaryVersion, f.CLIVersion = "0.1.7", "0.1.7" }, "G10", GatewayStop, "", ""},
		{"G11 no gateway binary", func(f *GatewayFacts) { f.BinaryFound = false; stopped(f) }, "G11", GatewayRefuse, VerdictGatewayBinaryMissing, ""},
		{"G11 binary removed under a recorded run: refuse, no stop", func(f *GatewayFacts) { f.BinaryFound, f.RecordedRuns = false, 1 }, "G11", GatewayRefuse, VerdictGatewayBinaryMissing, ""},
		{"G10 idle gateway, binary now untrusted: stop it", func(f *GatewayFacts) { f.BinaryUntrusted = "owned by uid 1000" }, "G10", GatewayStop, "", ""},
		{"G11t gateway binary untrusted", func(f *GatewayFacts) { f.BinaryUntrusted = "owned by uid 1000"; stopped(f) }, "G11t", GatewayRefuse, VerdictBinaryUntrusted, "uid 1000"},
		{"G12 mixed pair", func(f *GatewayFacts) { f.CLIVersion = "openshell 0.1.7"; stopped(f) }, "G12", GatewayRefuse, VerdictGatewayBinaryMismatch, "0.1.7"},
		{"G12 version unreadable", func(f *GatewayFacts) { f.BinaryVersion = "garbage"; stopped(f) }, "G12", GatewayRefuse, VerdictGatewayBinaryMismatch, "could not read"},
		{"G13 untested pair", func(f *GatewayFacts) { f.BinaryVersion, f.CLIVersion = "0.1.5", "0.1.5"; stopped(f) }, "G13", GatewayRefuse, VerdictGatewayBinaryUntested, "0.1.5"},
		{"G13 build metadata is untested", func(f *GatewayFacts) { f.BinaryVersion, f.CLIVersion = "0.1.6+local", "0.1.6+local"; stopped(f) }, "G13", GatewayRefuse, VerdictGatewayBinaryUntested, ""},
		{"G14 unit state unknown", func(f *GatewayFacts) { f.Unit = UnitUnknown }, "G14", GatewayRefuse, VerdictGatewayUnitUnknown, ""},
		{"G14a failed unit: refuse, never restart every pass", func(f *GatewayFacts) { f.Unit = UnitFailed }, "G14a", GatewayRefuse, VerdictGatewayStartFailed, "reset-failed"},
		{"G14r failed unit, the first retry is due: start it", func(f *GatewayFacts) { f.Unit, f.FailedSince = UnitFailed, f.Now-60 }, "G14r", GatewayStart, "", "retry 1 of 3"},
		{"G14r failed unit, the third retry after four minutes", func(f *GatewayFacts) { f.Unit, f.FailedRetries, f.FailedSince = UnitFailed, 2, f.Now-240 }, "G14r", GatewayStart, "", "retry 3 of 3"},
		{"G14a failed unit, the retry wait not passed: refuse with the time", func(f *GatewayFacts) { f.Unit, f.FailedRetries, f.FailedSince = UnitFailed, 1, f.Now-30 }, "G14a", GatewayRefuse, VerdictGatewayStartFailed, "in about 90 s (automatic retry 2 of 3)"},
		{"G14a failed unit, retries spent: hold for the user", func(f *GatewayFacts) { f.Unit, f.FailedRetries, f.FailedSince = UnitFailed, 3, 1 }, "G14a", GatewayRefuse, VerdictGatewayStartFailed, "after 3 automatic retries"},
		{"G14b launched 5 min ago, not answering: finish", func(f *GatewayFacts) { launching(f, f.Now-300) }, "G14b", GatewayFinish, VerdictGatewayStarting, "300 s ago"},
		{"G14b a custom budget", func(f *GatewayFacts) { launching(f, f.Now-300); f.FirstStartBudget = 600 }, "G14b", GatewayFinish, VerdictGatewayStarting, "after 10 min"},
		{"G14c launched past the budget: stop and fail", func(f *GatewayFacts) { launching(f, f.Now-DefaultFirstStartBudget-1) }, "G14c", GatewayStop, VerdictGatewayStartFailed, "within 20 min"},
		{"G14c no launch time: over budget", func(f *GatewayFacts) { launching(f, 0) }, "G14c", GatewayStop, VerdictGatewayStartFailed, ""},
		{"a start under way after a reboot (inactive): start again", func(f *GatewayFacts) { launching(f, f.Now-60); stopped(f) }, "G15", GatewayStart, "", ""},
		{"a start under way, failed unit: G14a", func(f *GatewayFacts) { launching(f, f.Now-60); f.Unit = UnitFailed }, "G14a", GatewayRefuse, VerdictGatewayStartFailed, ""},
		{"G15 inactive: start", stopped, "G15", GatewayStart, "", ""},
		{"G15 first start, no record", func(f *GatewayFacts) { f.Unit, f.Record = UnitInactive, nil }, "G15", GatewayStart, "", ""},
		{"G16 running with no record", func(f *GatewayFacts) { f.Record = nil }, "G16", GatewayRestart, "", ""},
		{"G17 upgrade waits for a live run", func(f *GatewayFacts) { f.Record.Version, f.LiveRuns = "0.1.5", 2 }, "G17", GatewayWait, VerdictGatewayUpgradePending, "2 live run"},
		{"G18 upgrade, idle: restart", func(f *GatewayFacts) { f.Record.Version = "0.1.5" }, "G18", GatewayRestart, "", ""},
		{"G18 unreadable recorded version: restart", func(f *GatewayFacts) { f.Record.Version = "" }, "G18", GatewayRestart, "", ""},
		{"G18 config changed, idle: restart", func(f *GatewayFacts) { f.WantConfigDigest = "d2" }, "G18", GatewayRestart, "", ""},
		{"G19 activating", func(f *GatewayFacts) { f.Unit = UnitActivating }, "G19", GatewayWait, VerdictGatewayStarting, "start limit"},
		{"G20 unhealthy, idle: restart", func(f *GatewayFacts) { f.Healthy = TriNo }, "G20", GatewayRestart, "", ""},
		{"G21 unhealthy with a live run: leave it", func(f *GatewayFacts) { f.Healthy, f.LiveRuns = TriNo, 1 }, "G21", GatewayWait, VerdictGatewayUnhealthy, "1 live run"},
		{"G22 health not read", func(f *GatewayFacts) { f.Healthy = TriUnknown }, "G22", GatewayWait, VerdictGatewayNotReady, ""},
		{"G23 ready", func(*GatewayFacts) {}, "G23", GatewayNone, "", ""},
		{"G23 config changed with a live run: keep serving", func(f *GatewayFacts) { f.WantConfigDigest, f.LiveRuns = "d2", 1 }, "G23", GatewayNone, "", "once no run holds it"},
		// Ordering: filesystem refusals come before any custody read; a
		// refusal comes before a start.
		{"foreign state dir before custody", func(f *GatewayFacts) { f.StateDirLocal, f.Custody = TriNo, "" }, "G4", GatewayRefuse, VerdictGatewayStateForeignFS, ""},
		{"refusal before start", func(f *GatewayFacts) { f.Custody = ""; stopped(f) }, "G6", GatewayRefuse, VerdictGatewayCustodyUnavailable, ""},
	}
	ids := map[string]bool{}
	for _, tc := range cases {
		ids[tc.rule] = true
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := readyFacts()
			tc.mod(&f)
			d := DecideGateway(f)
			if d.Rule != tc.rule || d.Action != tc.action || d.Verdict != tc.verdict {
				t.Fatalf("DecideGateway = %+v, want rule %s action %s verdict %q", d, tc.rule, tc.action, tc.verdict)
			}
			if !strings.Contains(d.Reason, tc.reason) {
				t.Fatalf("reason %q lacks %q", d.Reason, tc.reason)
			}
			if d.Action == GatewayRefuse && d.Reason == "" {
				t.Fatalf("a refusal must say why")
			}
		})
	}
	for _, r := range gatewayRules {
		if id := r.id[:indexSpace(r.id)]; !ids[id] {
			t.Errorf("row %s has no case", id)
		}
	}
}

func TestCustodyFor(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"keychain": CustodyKeychain, "file": CustodyOwnerFile, "memory": "", "unavailable": "", "": ""} {
		if got := CustodyFor(in); got != want {
			t.Errorf("CustodyFor(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDecideGatewayNeverStopsUnderALiveRun walks every unit state with a
// live run and checks the table never stops or restarts the gateway; and
// with only an abandoned run recorded it is never stopped (audit finding
// O2-A4).
func TestDecideGatewayNeverStopsUnderALiveRun(t *testing.T) {
	t.Parallel()
	for _, wanted := range []bool{true, false} {
		for _, u := range []UnitState{UnitActive, UnitActivating} {
			for _, h := range []Tri{TriYes, TriNo, TriUnknown} {
				for _, ver := range []string{"0.1.6", "0.1.5", ""} {
					for _, rec := range []bool{true, false} {
						f := readyFacts()
						f.Wanted, f.Unit, f.Healthy, f.LiveRuns, f.RecordedRuns = wanted, u, h, 1, 1
						f.Record.Version = ver
						f.WantConfigDigest = "other"
						if !rec {
							f.Record = nil
						}
						if a := DecideGateway(f).Action; a == GatewayStop || a == GatewayRestart {
							t.Fatalf("facts %+v: action %s under a live run", f, a)
						}
					}
				}
			}
		}
	}
}

func TestDecideGatewayNeverStopsUnderARecordedRun(t *testing.T) {
	t.Parallel()
	for _, wanted := range []bool{true, false} {
		for _, bin := range []bool{true, false} {
			f := readyFacts()
			f.Wanted, f.BinaryFound, f.RecordedRuns = wanted, bin, 1
			if a := DecideGateway(f).Action; a == GatewayStop {
				t.Fatalf("wanted %v binary %v: stopped with an abandoned run recorded", wanted, bin)
			}
		}
	}
}

func TestParseUnitState(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]UnitState{
		"active\n": UnitActive, "reloading": UnitActive, "activating": UnitActivating,
		"inactive\n": UnitInactive, "deactivating": UnitInactive, "failed": UnitFailed,
		"": UnitUnknown, "unknown": UnitUnknown, "Failed to connect to bus": UnitUnknown,
	} {
		if got := ParseUnitState(in); got != want {
			t.Errorf("ParseUnitState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIdentityAndPorts(t *testing.T) {
	t.Parallel()
	id, err := IdentityFor("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "observer-0123456789ab" || id.Unit != "observer-openshell-gateway-0123456789ab.service" {
		t.Fatalf("identity %+v", id)
	}
	if id.PreferredPort < GatewayPortBase || id.PreferredPort >= GatewayPortBase+GatewayPortRange {
		t.Fatalf("port %d outside the managed block", id.PreferredPort)
	}
	if !gatewayNameRE.MatchString(id.Name) {
		t.Fatalf("name %q is not a gateway name", id.Name)
	}
	for _, bad := range []string{"", "short", "ZZZZZZZZZZZZZZ", "0123456789ab/x"} {
		if _, err := IdentityFor(bad); err == nil {
			t.Errorf("IdentityFor(%q) accepted", bad)
		}
	}
	if got := PortCandidates(id, 17799, true); len(got) != 1 || got[0] != 17799 {
		t.Fatalf("a recorded run pins the port: %v", got)
	}
	got := PortCandidates(id, 17799, false)
	if got[0] != 17799 || len(got) != GatewayPortTries+1 {
		t.Fatalf("candidates %v", got)
	}
	for _, p := range PortCandidates(GatewayIdentity{PreferredPort: GatewayPortBase + GatewayPortRange - 1}, 0, false) {
		if p < GatewayPortBase || p >= GatewayPortBase+GatewayPortRange {
			t.Fatalf("candidate %d outside the block", p)
		}
	}
	if s := ServerFor(17701); !LoopbackServer(s) {
		t.Fatalf("ServerFor %q must pass P4b", s)
	}
}

// TestDecideGatewayFailedRetry: only G14r's decision is a counted retry,
// and the wait doubles per retry.
func TestDecideGatewayFailedRetry(t *testing.T) {
	t.Parallel()
	f := readyFacts()
	f.Unit, f.FailedSince = UnitFailed, f.Now-60
	if d := DecideGateway(f); !d.FailedRetry || d.Action != GatewayStart {
		t.Fatalf("G14r %+v", d)
	}
	f.Unit = UnitInactive
	if d := DecideGateway(f); d.FailedRetry || d.Rule != "G15" {
		t.Fatalf("a plain start is not a retry: %+v", d)
	}
	for i, want := range []int64{60, 120, 240, 480} {
		if got := GatewayFailedRetryWait(i); got != want {
			t.Errorf("wait %d: %d, want %d", i, got, want)
		}
	}
}
