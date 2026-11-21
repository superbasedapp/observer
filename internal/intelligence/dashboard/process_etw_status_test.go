//go:build !sbo_omit_processobs

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/processbridge/setup"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
)

// etwStatusServer assembles a Server over a seeded config + DB and returns it
// alongside the DB DIRECTORY (where a fake daemon health record can be
// dropped) so a test can drive both halves of the endpoint.
//
// The setup Env is stubbed to a NOT-A-WINDOWS-HOST shape by default: no test
// may ever reach the real Task Scheduler (the browserhost-tests-hit-the-real-
// registry class of mistake), and a CI host that happens to have interop must
// not change the answer.
func etwStatusServer(t *testing.T, mutate func(*config.Config)) (*Server, string) {
	t.Helper()
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(tdir, "state.db")
	if mutate != nil {
		mutate(&cfg)
	}
	if err := config.WriteToml(cfgPath, cfg); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, DBPath: cfg.Observer.DBPath, ConfigPath: cfgPath})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	server.etwSetupEnvFn = func() setup.Env { return setup.Env{} } // no schtasks.exe
	return server, filepath.Dir(cfg.Observer.DBPath)
}

// fakeSchtasksEnv builds a setup.Env whose probes are entirely canned.
func fakeSchtasksEnv(queryOut string, queryErr error, observer string) setup.Env {
	return setup.Env{
		LookPath: func(string) (string, error) { return `C:\Windows\System32\schtasks.exe`, nil },
		RunSchtasks: func(context.Context, string, ...string) (string, error) {
			return queryOut, queryErr
		},
		ResolveObserver: func(string) (string, bool) { return observer, observer != "" },
		Distro:          "Ubuntu",
		WindowsUser:     func() string { return "operator" },
		// The daemon under test really runs on this host, and its DB and
		// token paths come from t.TempDir(). A Windows host must say so, or
		// the planner treats C:\... as a WSL path that is not absolute.
		HostIsWindows: runtime.GOOS == "windows",
	}
}

func getETWStatus(t *testing.T, server *Server) etwStatusResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/process/etw/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp etwStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	return resp
}

// TestProcessETWStatusStates walks every planner outcome the endpoint can
// report, through the injected probe seam.
func TestProcessETWStatusStates(t *testing.T) {
	notFound := errors.New("exit status 1")

	tests := []struct {
		name       string
		etwEnabled bool
		env        setup.Env
		wantState  string
		wantSkip   string
		wantProbe  string
		wantCmd    bool
		reasonHas  string
	}{
		{
			name:       "etw disabled is a skip that NAMES the disabled feature",
			etwEnabled: false,
			env:        fakeSchtasksEnv("", notFound, `/mnt/c/obs/observer.exe`),
			wantState:  etwStateSkip,
			wantSkip:   etwSkipDisabled,
			// Nothing probed → the tri-state must read UNKNOWN, never absent.
			wantProbe: etwProbeUnknown,
		},
		{
			name:       "no schtasks.exe is a skip that says NOT A WINDOWS HOST",
			etwEnabled: true,
			env:        setup.Env{}, // LookPath nil → no Windows Scheduled Tasks here
			wantState:  etwStateSkip,
			wantSkip:   etwSkipNoWindows,
			wantProbe:  etwProbeUnknown,
		},
		{
			name:       "an existing task is present and gets no command",
			etwEnabled: true,
			env:        fakeSchtasksEnv("TaskName: SuperBasedObserverETW", nil, `/mnt/c/obs/observer.exe`),
			wantState:  etwStatePresent,
			wantProbe:  etwProbePresent,
		},
		{
			name:       "an absent task yields the manual command",
			etwEnabled: true,
			env:        fakeSchtasksEnv("ERROR: The system cannot find the file specified.", notFound, `/mnt/c/obs/observer.exe`),
			wantState:  etwStateManual,
			wantProbe:  etwProbeAbsent,
			wantCmd:    true,
		},
		{
			name:       "a probe that could not answer is UNKNOWN and keeps the hedged command",
			etwEnabled: true,
			env:        fakeSchtasksEnv("ERROR: Access is denied.", notFound, `/mnt/c/obs/observer.exe`),
			wantState:  etwStateUnknown,
			wantProbe:  etwProbeUnknown,
			wantCmd:    true,
			reasonHas:  "Access is denied",
		},
		{
			name:       "an unresolvable Windows binary is BLOCKED with no command",
			etwEnabled: true,
			env:        fakeSchtasksEnv("ERROR: The system cannot find the file specified.", notFound, ""),
			wantState:  etwStateBlocked,
			wantProbe:  etwProbeAbsent,
			reasonHas:  "windows_binary_path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enabled := tc.etwEnabled
			server, _ := etwStatusServer(t, func(c *config.Config) {
				// BOTH switches: "the feed is on" is their conjunction (the
				// master switch gates the subsystem that builds the listener).
				// The one-off-each combinations live in
				// TestETWStatusMasterSwitchOffIsADisabledSkip and
				// setup.TestResolveInputsRequiresBothSwitches.
				c.Observer.Process.Enabled = enabled
				c.Observer.Process.ETW.Enabled = enabled
			})
			env := tc.env
			server.etwSetupEnvFn = func() setup.Env { return env }

			got := getETWStatus(t, server)
			if !got.PlanDetectable {
				t.Fatalf("plan_detectable=false (%s)", got.PlanUndetectableReason)
			}
			if got.State != tc.wantState {
				t.Errorf("state = %q, want %q", got.State, tc.wantState)
			}
			if got.SkipReason != tc.wantSkip {
				t.Errorf("skip_reason = %q, want %q", got.SkipReason, tc.wantSkip)
			}
			if got.Probe != tc.wantProbe {
				t.Errorf("probe = %q, want %q", got.Probe, tc.wantProbe)
			}
			if hasCmd := got.Command != ""; hasCmd != tc.wantCmd {
				t.Errorf("command present = %v, want %v (command=%q)", hasCmd, tc.wantCmd, got.Command)
			}
			if tc.wantCmd && !strings.Contains(got.Command, setup.TaskName) {
				t.Errorf("command does not name the frozen task: %q", got.Command)
			}
			if tc.reasonHas != "" && !strings.Contains(got.Reason, tc.reasonHas) {
				t.Errorf("reason = %q, want it to mention %q", got.Reason, tc.reasonHas)
			}
			if got.TaskName != setup.TaskName {
				t.Errorf("task_name = %q, want %q", got.TaskName, setup.TaskName)
			}
		})
	}
}

// TestProcessETWStatusProbeZeroValueIsUnknown is the §W4.6 honesty pin, one
// layer up from the planner's own.
//
// setup.ProbeUnknown is the tri-state's ZERO VALUE on purpose: "absent" is the
// state that makes the card offer to register the task, so a forgotten
// assignment must never land there. This asserts the wire mapping preserves
// that — including for a value this build does not define, which must degrade
// to unknown rather than to the actionable state.
func TestProcessETWStatusProbeZeroValueIsUnknown(t *testing.T) {
	t.Parallel()

	if got := etwProbeOf(setup.Probe(0)); got != etwProbeUnknown {
		t.Fatalf("the tri-state's ZERO value maps to %q; it must map to %q - "+
			"reporting a never-run probe as %q would tell the operator the task does not exist",
			got, etwProbeUnknown, etwProbeAbsent)
	}
	if got := etwProbeOf(setup.Probe(99)); got != etwProbeUnknown {
		t.Fatalf("an unmapped probe value degraded to %q, want %q", got, etwProbeUnknown)
	}
	if got := etwProbeOf(setup.ProbeAbsent); got != etwProbeAbsent {
		t.Fatalf("ProbeAbsent mapped to %q", got)
	}
	if got := etwProbeOf(setup.ProbePresent); got != etwProbePresent {
		t.Fatalf("ProbePresent mapped to %q", got)
	}
}

// TestProcessETWStatusHealthAbsent pins that no daemon record is reported as
// an absence with a reason, never as a zeroed transport.
func TestProcessETWStatusHealthAbsent(t *testing.T) {
	server, _ := etwStatusServer(t, nil)
	got := getETWStatus(t, server)
	if got.Health != nil {
		t.Fatalf("health reported with no daemon record: %+v", got.Health)
	}
	if got.HealthReason == "" {
		t.Fatal("a null health carries no reason - absence must be explained, not silent")
	}
}

// TestProcessETWStatusTransportHealth is the transport half: a live daemon
// record with a refusing capturer link, and the honesty rules that apply to it.
func TestProcessETWStatusTransportHealth(t *testing.T) {
	server, dbDir := etwStatusServer(t, nil)

	now := time.Now().UTC()
	if _, err := diag.WriteProcessHealth(dbDir, diag.ProcessHealth{
		PID:                         os.Getpid(),
		WrittenAt:                   now,
		Backend:                     "poll+etw",
		BackendUp:                   true,
		NetworkAccountingMode:       procmodel.NetworkAccountingUnavailable,
		TransportState:              procmodel.TransportStateConfigured,
		TransportAddr:               "127.0.0.1:8823",
		TransportAuthFailures:       3,
		TransportLastAuthError:      "processobs/bridge: malformed handshake: not a SBO-PROCESS-BRIDGE client",
		TransportLastAuthErrorClass: procmodel.TransportAuthClassMalformed,
	}); err != nil {
		t.Fatalf("WriteProcessHealth: %v", err)
	}

	got := getETWStatus(t, server)
	if got.Health == nil {
		t.Fatal("no health reported for a live record")
	}
	if got.Health.Transport == nil {
		t.Fatal("a CONFIGURED transport reported no transport object")
	}
	tr := got.Health.Transport
	if tr.AuthFailures != 3 || tr.Connections != 0 {
		t.Fatalf("counters = %+v, want 3 refusals / 0 connections", tr)
	}
	// The endpoint must surface the CLASS and the VERBATIM reason and assert
	// no cause of its own. A prior version of this surface asserted a
	// fabricated "shared-token mismatch" — and a test pinned the fabrication
	// as expected. AuthFailures counts every refusal, including an unrelated
	// Windows-host process probing a WSL loopback bind.
	if tr.LastAuthErrorClass != procmodel.TransportAuthClassMalformed {
		t.Errorf("last_auth_error_class = %q, want %q", tr.LastAuthErrorClass, procmodel.TransportAuthClassMalformed)
	}
	if !strings.Contains(tr.LastAuthError, "not a SBO-PROCESS-BRIDGE client") {
		t.Errorf("last_auth_error is not the daemon's verbatim record: %q", tr.LastAuthError)
	}
	for _, forbidden := range []string{"token mismatch", "shared-token mismatch", "the token is wrong"} {
		if strings.Contains(strings.ToLower(got.Health.TransportLine), forbidden) {
			t.Errorf("the transport line asserts %q as fact; the counter names no cause", forbidden)
		}
	}
	// Never-happened timestamps are ABSENT, not epoch 0.
	if tr.LastConnectAt != nil || tr.LastDisconnectAt != nil {
		t.Errorf("a capturer that never connected carries timestamps: %+v / %+v", tr.LastConnectAt, tr.LastDisconnectAt)
	}
	// The capturer has never reported its decoder health → absence, NOT a
	// clean zero. "0 dropped" would say the payload-length assumptions were
	// exercised and held.
	if tr.CapturerDecode != nil {
		t.Errorf("capturer_decode present with no report: %+v", tr.CapturerDecode)
	}
	if got.Health.Stale {
		t.Error("a just-written record reported as stale")
	}
}

// TestProcessETWStatusStaleQualifiesTimestamps pins that a last-known "live"
// is never rendered present-tense: an old record must come back flagged stale,
// with the age, and with diag's own staleness-qualified prose.
func TestProcessETWStatusStaleQualifiesTimestamps(t *testing.T) {
	server, dbDir := etwStatusServer(t, nil)

	old := time.Now().UTC().Add(-10 * diag.ProcessHealthStaleAfter)
	connectedAt := old.Add(-time.Minute)
	if _, err := diag.WriteProcessHealth(dbDir, diag.ProcessHealth{
		PID:                    os.Getpid(),
		WrittenAt:              old,
		Backend:                "poll+etw",
		BackendUp:              true,
		TransportState:         procmodel.TransportStateConfigured,
		TransportAddr:          "127.0.0.1:8823",
		TransportConnections:   1,
		TransportConnected:     true,
		TransportLastConnectAt: connectedAt,
	}); err != nil {
		t.Fatalf("WriteProcessHealth: %v", err)
	}

	got := getETWStatus(t, server)
	if got.Health == nil {
		t.Fatal("no health reported")
	}
	if !got.Health.Stale {
		t.Fatal("an old record is not flagged stale - the card would render a dead daemon's 'connected' present-tense")
	}
	if got.Health.AgeSeconds < diag.ProcessHealthStaleAfter.Seconds() {
		t.Fatalf("age_seconds = %v, want at least the staleness threshold", got.Health.AgeSeconds)
	}
	if !strings.Contains(got.Health.TransportLine, "STALE") {
		t.Fatalf("the transport line is not staleness-qualified: %q", got.Health.TransportLine)
	}
	if got.Health.Transport == nil || got.Health.Transport.LastConnectAt == nil {
		t.Fatal("a connect that DID happen must carry its timestamp")
	}
	if !got.Health.Transport.LastConnectAt.Equal(connectedAt) {
		t.Errorf("last_connect_at = %v, want %v", got.Health.Transport.LastConnectAt, connectedAt)
	}
	if got.Health.Transport.LastDisconnectAt != nil {
		t.Errorf("a disconnect that never happened carries a timestamp: %v", got.Health.Transport.LastDisconnectAt)
	}
}

// TestProcessETWStatusCapturerDecodeReported pins the E6 signal arriving on
// this surface — including that a reported ZERO is a real measurement, which
// is the whole point of it being distinguishable from an absent report.
func TestProcessETWStatusCapturerDecodeReported(t *testing.T) {
	tests := []struct {
		name               string
		dropped            int64
		unsupportedVersion int64
		wantHealthy        bool
		wantLine           bool
	}{
		{name: "a decoder that refused nothing is a real, healthy zero", wantHealthy: true},
		{name: "a refusing decoder is loud", dropped: 4, wantHealthy: false, wantLine: true},
		{name: "an unsupported template is its own signal", unsupportedVersion: 2, wantHealthy: false, wantLine: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, dbDir := etwStatusServer(t, nil)
			at := time.Now().UTC()
			if _, err := diag.WriteProcessHealth(dbDir, diag.ProcessHealth{
				PID:                                 os.Getpid(),
				WrittenAt:                           at,
				Backend:                             "poll+etw",
				BackendUp:                           true,
				TransportState:                      procmodel.TransportStateConfigured,
				TransportAddr:                       "127.0.0.1:8823",
				TransportConnections:                1,
				TransportConnected:                  true,
				TransportLastConnectAt:              at,
				TransportCapturerDecodeReported:     true,
				TransportCapturerDropped:            tc.dropped,
				TransportCapturerUnsupportedVersion: tc.unsupportedVersion,
				TransportCapturerDecodeAt:           at,
			}); err != nil {
				t.Fatalf("WriteProcessHealth: %v", err)
			}

			got := getETWStatus(t, server)
			if got.Health == nil || got.Health.Transport == nil || got.Health.Transport.CapturerDecode == nil {
				t.Fatalf("a REPORTED decode did not reach the wire: %+v", got.Health)
			}
			cd := got.Health.Transport.CapturerDecode
			if cd.Dropped != tc.dropped || cd.UnsupportedVersion != tc.unsupportedVersion {
				t.Errorf("counters = %+v, want %d/%d", cd, tc.dropped, tc.unsupportedVersion)
			}
			if cd.Healthy != tc.wantHealthy {
				t.Errorf("healthy = %v, want %v", cd.Healthy, tc.wantHealthy)
			}
			if hasLine := cd.Line != ""; hasLine != tc.wantLine {
				t.Errorf("line present = %v, want %v (%q)", hasLine, tc.wantLine, cd.Line)
			}
			if cd.ReportedAt.IsZero() {
				t.Error("reported_at is zero on a reported decode")
			}
		})
	}
}

// TestProcessETWStatusUndetectablePlanStillReportsHealth pins that a config we
// cannot read is reported as "no plan, and here is why" — never squeezed into
// `unknown`, which is a claim about a schtasks probe this path never ran — and
// that the daemon-published health still comes back, because whether a
// capturer is connected does not depend on whether we could compose a command.
func TestProcessETWStatusUndetectablePlanStillReportsHealth(t *testing.T) {
	server, dbDir := etwStatusServer(t, nil)
	if err := os.WriteFile(server.opts.ConfigPath, []byte("this is not = valid toml ]["), 0o600); err != nil {
		t.Fatalf("corrupt config: %v", err)
	}
	if _, err := diag.WriteProcessHealth(dbDir, diag.ProcessHealth{
		PID: os.Getpid(), WrittenAt: time.Now().UTC(), Backend: "poll", BackendUp: true,
	}); err != nil {
		t.Fatalf("WriteProcessHealth: %v", err)
	}

	got := getETWStatus(t, server)
	if got.PlanDetectable {
		t.Fatal("an unreadable config produced a plan")
	}
	if got.State != "" {
		t.Fatalf("state = %q, want empty - a config failure is not a planner outcome", got.State)
	}
	if got.Probe != etwProbeUnknown {
		t.Fatalf("probe = %q on a path that never probed, want %q", got.Probe, etwProbeUnknown)
	}
	if got.PlanUndetectableReason == "" {
		t.Fatal("no reason given for an undetectable plan")
	}
	if got.Health == nil {
		t.Fatal("health was dropped because the plan failed; the two are independent")
	}
	// A record with no transport key at all must read as "none", not as a
	// broken transport with zero connections.
	if got.Health.TransportState != procmodel.TransportStateNone {
		t.Errorf("transport_state = %q, want %q", got.Health.TransportState, procmodel.TransportStateNone)
	}
	if got.Health.Transport != nil {
		t.Errorf("a transport object for a record with no transport: %+v", got.Health.Transport)
	}
}

// TestProcessETWStatusRejectsNonGET pins the read-only posture at the method
// level: this route detects, it never registers.
func TestProcessETWStatusRejectsNonGET(t *testing.T) {
	server, _ := etwStatusServer(t, nil)
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/process/etw/status", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rr.Code)
	}
}

// TestProcessETWStatusSchtasksPresent pins the render gate the card depends on:
// schtasks_present answers "does this feature apply on this host" INDEPENDENTLY
// of state, on every path — including the ones that produce no plan.
//
// The case that matters is the last one. A default install has ETW disabled, so
// PlanTask's gate order reports skip/etw_disabled on a WINDOWS host and on a
// LINUX laptop alike; without this flag a card could only either offer a
// Windows-only feed to every Linux user or hide it from every Windows user.
func TestProcessETWStatusSchtasksPresent(t *testing.T) {
	t.Run("no schtasks on this host", func(t *testing.T) {
		server, _ := etwStatusServer(t, func(c *config.Config) { c.Observer.Process.ETW.Enabled = true })
		server.etwSetupEnvFn = func() setup.Env { return setup.Env{} }
		if got := getETWStatus(t, server); got.SchtasksPresent {
			t.Errorf("schtasks_present = true with no LookPath seam - a probe nobody ran must not invent a Windows host")
		}
	})

	t.Run("schtasks present and the feed enabled", func(t *testing.T) {
		server, _ := etwStatusServer(t, func(c *config.Config) { c.Observer.Process.ETW.Enabled = true })
		server.etwSetupEnvFn = func() setup.Env {
			return fakeSchtasksEnv("ERROR: The system cannot find the file specified.",
				errors.New("exit status 1"), `/mnt/c/obs/observer.exe`)
		}
		if got := getETWStatus(t, server); !got.SchtasksPresent {
			t.Error("schtasks_present = false on a host whose LookPath resolves schtasks.exe")
		}
	})

	t.Run("schtasks present while the feed is DISABLED", func(t *testing.T) {
		// ResolveInputs short-circuits before its own PATH lookup here, which
		// is exactly why the flag is resolved separately.
		server, _ := etwStatusServer(t, func(c *config.Config) { c.Observer.Process.ETW.Enabled = false })
		server.etwSetupEnvFn = func() setup.Env {
			return fakeSchtasksEnv("", errors.New("exit status 1"), `/mnt/c/obs/observer.exe`)
		}
		got := getETWStatus(t, server)
		if got.State != etwStateSkip || got.SkipReason != etwSkipDisabled {
			t.Fatalf("state/skip = %q/%q, want skip/etw_disabled", got.State, got.SkipReason)
		}
		if !got.SchtasksPresent {
			t.Error("schtasks_present must stay true when the feed is merely OFF - " +
				"otherwise a Windows operator can never be offered the toggle")
		}
	})

	t.Run("resolved even when no plan could be produced", func(t *testing.T) {
		server, _ := etwStatusServer(t, nil)
		server.opts.ConfigPath = "" // no plan possible
		server.etwSetupEnvFn = func() setup.Env {
			return fakeSchtasksEnv("", errors.New("exit status 1"), `/mnt/c/obs/observer.exe`)
		}
		got := getETWStatus(t, server)
		if got.PlanDetectable {
			t.Fatal("expected an undetectable plan with no config path")
		}
		if !got.SchtasksPresent {
			t.Error("schtasks_present must be answered on the no-plan path too")
		}
	})
}

// TestProcessETWStatusCapturerClassificationCounters pins E6b on the surface
// the six-step validation actually tells the operator to use.
//
// `healthy` keeps its E6 meaning — "the decoder refused nothing" — so an
// existing consumer reads the same field it always did. What is new is that
// `healthy: true` is no longer sufficient for a PASS: the renumbered-provider
// shape is healthy-and-worthless, and `nothing_classified` beside `decoded`
// is what separates it from a real one.
func TestProcessETWStatusCapturerClassificationCounters(t *testing.T) {
	tests := []struct {
		name                  string
		dropped               int64
		decoded               int64
		ignored               int64
		wantHealthy           bool
		wantNothingClassified bool
		wantLine              bool
	}{
		{
			name: "a healthy busy capture: a huge ignore count is normal and is NOT a fault",
			// A large ignored count beside real decoded events is the shape
			// of every working elevated run.
			decoded: 4321, ignored: 1_000_000,
			wantHealthy: true,
		},
		{
			name:    "the renumbered-provider shape is healthy-looking and must still not read as a pass",
			ignored: 48_211,
			// Nothing was REFUSED, so healthy stays true — and that is
			// exactly why the separate flag has to exist.
			wantHealthy: true, wantNothingClassified: true, wantLine: true,
		},
		{
			name:    "a refusing decoder is not also flagged as classifying nothing",
			dropped: 4, ignored: 900,
			wantHealthy: false, wantNothingClassified: false, wantLine: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, dbDir := etwStatusServer(t, nil)
			at := time.Now().UTC()
			if _, err := diag.WriteProcessHealth(dbDir, diag.ProcessHealth{
				PID:                             os.Getpid(),
				WrittenAt:                       at,
				Backend:                         "poll+etw",
				BackendUp:                       true,
				TransportState:                  procmodel.TransportStateConfigured,
				TransportAddr:                   "127.0.0.1:8823",
				TransportConnections:            1,
				TransportConnected:              true,
				TransportLastConnectAt:          at,
				TransportCapturerDecodeReported: true,
				TransportCapturerDropped:        tc.dropped,
				TransportCapturerDecoded:        tc.decoded,
				TransportCapturerIgnored:        tc.ignored,
				TransportCapturerDecodeAt:       at,
			}); err != nil {
				t.Fatalf("WriteProcessHealth: %v", err)
			}

			got := getETWStatus(t, server)
			if got.Health == nil || got.Health.Transport == nil || got.Health.Transport.CapturerDecode == nil {
				t.Fatalf("a REPORTED decode did not reach the wire: %+v", got.Health)
			}
			cd := got.Health.Transport.CapturerDecode
			if cd.Decoded != tc.decoded || cd.Ignored != tc.ignored {
				t.Errorf("classification counters = (decoded=%d ignored=%d), want (%d, %d)",
					cd.Decoded, cd.Ignored, tc.decoded, tc.ignored)
			}
			if cd.Healthy != tc.wantHealthy {
				t.Errorf("healthy = %v, want %v", cd.Healthy, tc.wantHealthy)
			}
			if cd.NothingClassified != tc.wantNothingClassified {
				t.Errorf("nothing_classified = %v, want %v", cd.NothingClassified, tc.wantNothingClassified)
			}
			if hasLine := cd.Line != ""; hasLine != tc.wantLine {
				t.Errorf("line present = %v, want %v (%q)", hasLine, tc.wantLine, cd.Line)
			}
		})
	}
}
