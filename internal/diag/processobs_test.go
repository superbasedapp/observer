package diag

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/procmodel"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

func TestCheckProcessObservability_DisabledIsOK(t *testing.T) {
	cfg, database, _, _ := newTestEnv(t)
	// Default config: the feature is opt-in / off.
	c := checkProcessObservability(context.Background(), database, cfg)
	if c.Status != StatusOK {
		t.Errorf("disabled feature should be OK, got %s (%q)", c.Status, c.Message)
	}
	// The opt-in is a link to Settings > Process capture.
	assertSpelled(t, c, remedy.OpenSettings)
	if c.Remediations[0].Tool != "process" {
		t.Errorf("remediation %+v, want the process section", c.Remediations)
	}
}

func TestCheckProcessObservability_EnabledNoRowsWarns(t *testing.T) {
	cfg, database, _, _ := newTestEnv(t)
	cfg.Observer.Process.Enabled = true
	cfg.Observer.Process.Backend = "linux_ebpf"
	c := checkProcessObservability(context.Background(), database, cfg)
	if c.Status != StatusWarn {
		t.Errorf("enabled-but-empty should WARN (verify backend availability), got %s (%q)", c.Status, c.Message)
	}
}

// TestCheckProcessObservability_NoDaemonHealthOffersRestart: enabled with
// no daemon health published, the fix is a restart (a daemon started before
// capture was turned on), linked to Settings > Health.
func TestCheckProcessObservability_NoDaemonHealthOffersRestart(t *testing.T) {
	cfg, database, _, _ := newTestEnv(t)
	cfg.Observer.Process.Enabled = true
	c := checkProcessObservability(context.Background(), database, cfg)
	assertSpelled(t, c, remedy.RestartDaemon)
	if !strings.Contains(strings.Join(c.Details, "\n"), "Restart daemon") {
		t.Errorf("details do not name the restart control:\n%s", strings.Join(c.Details, "\n"))
	}
}

func TestCheckProcessObservability_EnabledWithRowsOK(t *testing.T) {
	cfg, database, _, _ := newTestEnv(t)
	cfg.Observer.Process.Enabled = true
	// Minimal unattributed row (NULL session_id is FK-safe) just to make
	// the count non-zero.
	if _, err := database.ExecContext(context.Background(),
		`INSERT INTO process_runs
		   (process_key, pid, attribution_source, attribution_confidence, started_at, last_seen_at)
		 VALUES ('pk-doctor', 7, 'none', 'none', '2026-06-16T12:00:00Z', '2026-06-16T12:00:00Z')`); err != nil {
		t.Fatalf("seed process_runs: %v", err)
	}
	c := checkProcessObservability(context.Background(), database, cfg)
	if c.Status != StatusOK {
		t.Errorf("enabled with rows should be OK, got %s (%q)", c.Status, c.Message)
	}
}

// TestCheckProcessObservability_NetworkModes walks the three accounting modes
// a running daemon can report, plus the no-daemon and stale-report cases, and
// pins what the operator actually sees.
func TestCheckProcessObservability_NetworkModes(t *testing.T) {
	tests := []struct {
		name         string
		health       *ProcessHealth // nil → no daemon has published
		wantStatus   Status
		wantMessage  []string
		wantDetail   []string
		absentDetail []string
	}{
		{
			name:         "no daemon reporting says exactly that",
			health:       nil,
			wantStatus:   StatusOK,
			wantDetail:   []string{"no running daemon has published process-observability health"},
			absentDetail: []string{"network bytes:"},
		},
		{
			name: "off does not nag",
			health: &ProcessHealth{
				Backend: "poll", BackendUp: true,
				NetworkAccountingMode:   procmodel.NetworkAccountingOff,
				NetworkAccountingReason: "not enabled ([observer.process.network].process_bytes)",
			},
			wantStatus: StatusOK,
			wantDetail: []string{"network bytes: off", "process_bytes"},
		},
		{
			name: "unavailable warns and carries the reason",
			health: &ProcessHealth{
				Backend: "linux_ebpf+poll", BackendUp: true,
				NetworkAccountingMode:   procmodel.NetworkAccountingUnavailable,
				NetworkAccountingReason: "missing CAP_BPF/CAP_PERFMON",
			},
			wantStatus:  StatusWarn,
			wantMessage: []string{"network accounting UNAVAILABLE", "unmeasured, not zero"},
			wantDetail:  []string{"missing CAP_BPF/CAP_PERFMON"},
		},
		{
			name: "tcp is OK and states the TCP-only caveat",
			health: &ProcessHealth{
				Backend: "linux_ebpf+poll", BackendUp: true,
				NetworkAccountingMode: procmodel.NetworkAccountingTCP,
			},
			wantStatus: StatusOK,
			wantDetail: []string{"network bytes: live (tcp)", "UDP/QUIC"},
		},
		{
			name: "a stale report is labelled stale, not presented as current",
			health: &ProcessHealth{
				Backend: "linux_ebpf+poll", BackendUp: true,
				WrittenAt:             time.Now().UTC().Add(-30 * time.Minute),
				NetworkAccountingMode: procmodel.NetworkAccountingTCP,
			},
			wantStatus: StatusOK,
			wantDetail: []string{"STALE", "last report"},
		},
		{
			name: "a reported backend error surfaces",
			health: &ProcessHealth{
				Backend: "poll", BackendUp: false, LastError: "perf_event_open: operation not permitted",
				NetworkAccountingMode: procmodel.NetworkAccountingOff,
			},
			wantStatus: StatusOK,
			wantDetail: []string{"(down)", "perf_event_open: operation not permitted"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, database, _, _ := newTestEnv(t)
			cfg.Observer.Process.Enabled = true
			cfg.Observer.Process.Backend = "auto"
			if _, err := database.ExecContext(context.Background(),
				`INSERT INTO process_runs
				   (process_key, pid, attribution_source, attribution_confidence, started_at, last_seen_at)
				 VALUES ('pk-net', 11, 'none', 'none', '2026-07-26T12:00:00Z', '2026-07-26T12:00:00Z')`); err != nil {
				t.Fatalf("seed process_runs: %v", err)
			}
			if tc.health != nil {
				h := *tc.health
				h.PID = os.Getpid()
				if _, err := WriteProcessHealth(filepath.Dir(cfg.Observer.DBPath), h); err != nil {
					t.Fatalf("WriteProcessHealth: %v", err)
				}
			}

			c := checkProcessObservability(context.Background(), database, cfg)
			if c.Status != tc.wantStatus {
				t.Errorf("status = %s, want %s (message: %q)", c.Status, tc.wantStatus, c.Message)
			}
			for _, want := range tc.wantMessage {
				if !strings.Contains(c.Message, want) {
					t.Errorf("message %q missing %q", c.Message, want)
				}
			}
			joined := strings.Join(c.Details, "\n")
			for _, want := range tc.wantDetail {
				if !strings.Contains(joined, want) {
					t.Errorf("details missing %q:\n%s", want, joined)
				}
			}
			for _, absent := range tc.absentDetail {
				if strings.Contains(joined, absent) {
					t.Errorf("details unexpectedly contain %q:\n%s", absent, joined)
				}
			}
		})
	}
}

// TestCheckProcessObservability_TransportStates walks what `observer doctor`
// shows for the cross-OS capturer link. The failure modes this surface exists
// for: an elevated capturer that was never set up (silent forever by design),
// one whose connections are all refused (which must ESCALATE, because
// something is dialling and every event it captures is being discarded), and
// a transport the operator asked for that never came up (which must NOT be
// silence, or it reads exactly like a feature nobody enabled). An install
// without the feed must gain no line at all.
//
// The refused case reports the daemon's VERBATIM reason and names no cause.
// The counter behind it conflates a bad token, a protocol version this daemon
// does not speak, and an unrelated local process probing the port — this
// listener is a WSL loopback bind, so the whole Windows host can reach it and
// a port scanner would otherwise get to author the operator's diagnosis.
func TestCheckProcessObservability_TransportStates(t *testing.T) {
	tests := []struct {
		name          string
		health        ProcessHealth
		wantStatus    Status
		wantMessage   []string
		absentMessage []string
		wantDetail    []string
		absentDetail  []string
	}{
		{
			name: "no transport configured adds no line",
			health: ProcessHealth{
				Backend: "poll", BackendUp: true,
				NetworkAccountingMode: procmodel.NetworkAccountingOff,
			},
			wantStatus:   StatusOK,
			absentDetail: []string{"capturer link:"},
		},
		{
			name: "configured but never connected is reported, not escalated",
			health: ProcessHealth{
				Backend: "composite[poll+bridge-listen]", BackendUp: true,
				NetworkAccountingMode: procmodel.NetworkAccountingOff,
				TransportState:        procmodel.TransportStateConfigured, TransportAddr: "127.0.0.1:8823",
			},
			wantStatus: StatusOK,
			wantDetail: []string{"capturer link: waiting", "127.0.0.1:8823", "Scheduled Task"},
		},
		{
			// The H2 regression guard. This exact input (an upgraded WSL
			// daemon, a Windows observer.exe left behind) used to produce
			// "(shared-token mismatch)" in the headline, sending the operator
			// to fix a token that was already correct.
			name: "a refused capturer WARNs with the daemon's verbatim reason, not a guessed cause",
			health: ProcessHealth{
				Backend: "composite[poll+bridge-listen]", BackendUp: true,
				NetworkAccountingMode: procmodel.NetworkAccountingOff,
				TransportState:        procmodel.TransportStateConfigured, TransportAddr: "127.0.0.1:8823",
				TransportAuthFailures:  12,
				TransportLastAuthError: "processobs/bridge: malformed handshake: capturer speaks protocol v2, this daemon speaks v1",
			},
			wantStatus: StatusWarn,
			wantMessage: []string{
				"REFUSING every connection", "12 refused at the handshake",
				"capturer speaks protocol v2, this daemon speaks v1",
			},
			absentMessage: []string{"shared-token mismatch", "token mismatch"},
			wantDetail:    []string{"capturer link: AUTH FAILURE", "[observer.process.etw].token", "cause is NOT assumed"},
		},
		{
			name: "a refusal with no recorded reason admits the gap",
			health: ProcessHealth{
				Backend: "composite[poll+bridge-listen]", BackendUp: true,
				NetworkAccountingMode: procmodel.NetworkAccountingOff,
				TransportState:        procmodel.TransportStateConfigured, TransportAddr: "127.0.0.1:8823",
				TransportAuthFailures: 3,
			},
			wantStatus:    StatusWarn,
			wantMessage:   []string{"REFUSING every connection", "no refusal reason was recorded"},
			absentMessage: []string{"shared-token mismatch", "token mismatch"},
		},
		{
			// M3: without this branch the whole surface prints NOTHING, which
			// is exactly what an install that never enabled ETW prints.
			name: "a requested transport that never started WARNs instead of going silent",
			health: ProcessHealth{
				Backend: "composite[poll+bridge]", BackendUp: true,
				NetworkAccountingMode:      procmodel.NetworkAccountingOff,
				TransportState:             procmodel.TransportStateUnavailable,
				TransportUnavailableReason: "processobs/bridge: listen 127.0.0.1:8823: bind: address already in use",
			},
			wantStatus: StatusWarn,
			wantMessage: []string{
				"REQUESTED but is NOT running", "bind: address already in use",
			},
			wantDetail: []string{"capturer link: UNAVAILABLE"},
		},
		{
			name: "a live capturer is OK",
			health: ProcessHealth{
				Backend: "composite[poll+bridge-listen]", BackendUp: true,
				NetworkAccountingMode: procmodel.NetworkAccountingTCP,
				TransportState:        procmodel.TransportStateConfigured, TransportAddr: "127.0.0.1:8823",
				TransportConnected: true, TransportConnections: 1,
				TransportLastConnectAt: time.Now().UTC().Add(-time.Minute),
			},
			wantStatus: StatusOK,
			wantDetail: []string{"capturer link: live"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, database, _, _ := newTestEnv(t)
			cfg.Observer.Process.Enabled = true
			cfg.Observer.Process.Backend = "etw"
			if _, err := database.ExecContext(context.Background(),
				`INSERT INTO process_runs
				   (process_key, pid, attribution_source, attribution_confidence, started_at, last_seen_at)
				 VALUES ('pk-transport', 12, 'none', 'none', '2026-07-26T12:00:00Z', '2026-07-26T12:00:00Z')`); err != nil {
				t.Fatalf("seed process_runs: %v", err)
			}
			h := tc.health
			h.PID = os.Getpid()
			if _, err := WriteProcessHealth(filepath.Dir(cfg.Observer.DBPath), h); err != nil {
				t.Fatalf("WriteProcessHealth: %v", err)
			}

			c := checkProcessObservability(context.Background(), database, cfg)
			if c.Status != tc.wantStatus {
				t.Errorf("status = %s, want %s (message: %q)", c.Status, tc.wantStatus, c.Message)
			}
			for _, want := range tc.wantMessage {
				if !strings.Contains(c.Message, want) {
					t.Errorf("message %q missing %q", c.Message, want)
				}
			}
			for _, absent := range tc.absentMessage {
				if strings.Contains(c.Message, absent) {
					t.Errorf("message %q asserts a cause the record cannot support: %q", c.Message, absent)
				}
			}
			joined := strings.Join(c.Details, "\n")
			for _, want := range tc.wantDetail {
				if !strings.Contains(joined, want) {
					t.Errorf("details missing %q:\n%s", want, joined)
				}
			}
			for _, absent := range tc.absentDetail {
				if strings.Contains(joined, absent) {
					t.Errorf("details unexpectedly contain %q:\n%s", absent, joined)
				}
			}
		})
	}
}
