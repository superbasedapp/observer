package diag

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/procmodel"
)

func TestWriteProcessHealth_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := ProcessHealth{
		PID:                     os.Getpid(),
		WrittenAt:               time.Now().UTC(),
		Backend:                 "linux_ebpf+poll",
		BackendUp:               true,
		QueueDepth:              3,
		NetworkAccountingMode:   procmodel.NetworkAccountingUnavailable,
		NetworkAccountingReason: "missing CAP_BPF/CAP_PERFMON",
	}
	path, err := WriteProcessHealth(dir, want)
	if err != nil {
		t.Fatalf("WriteProcessHealth: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("record not written: %v", err)
	}
	// The temp file used for the atomic write must not survive.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file left behind: err=%v", err)
	}

	got, ok := LatestProcessHealth(dir)
	if !ok {
		t.Fatal("LatestProcessHealth: no live record")
	}
	if got.Backend != want.Backend || got.PID != want.PID || got.QueueDepth != want.QueueDepth {
		t.Errorf("round trip mismatch: got %+v want %+v", got, want)
	}
	if got.NetworkAccountingMode != want.NetworkAccountingMode {
		t.Errorf("mode: got %q want %q", got.NetworkAccountingMode, want.NetworkAccountingMode)
	}
	// The reason is the actionable half — it must survive verbatim.
	if got.NetworkAccountingReason != want.NetworkAccountingReason {
		t.Errorf("reason: got %q want %q", got.NetworkAccountingReason, want.NetworkAccountingReason)
	}

	if err := RemoveProcessHealth(path); err != nil {
		t.Errorf("RemoveProcessHealth: %v", err)
	}
	if _, ok := LatestProcessHealth(dir); ok {
		t.Error("record still live after removal")
	}
	// Removing a missing path is a no-op.
	if err := RemoveProcessHealth(path); err != nil {
		t.Errorf("RemoveProcessHealth on missing path: %v", err)
	}
}

func TestWriteProcessHealth_DefaultsPIDAndTimestamp(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteProcessHealth(dir, ProcessHealth{Backend: "poll"}); err != nil {
		t.Fatalf("WriteProcessHealth: %v", err)
	}
	got, ok := LatestProcessHealth(dir)
	if !ok {
		t.Fatal("no live record")
	}
	if got.PID != os.Getpid() {
		t.Errorf("pid: got %d want %d", got.PID, os.Getpid())
	}
	if got.WrittenAt.IsZero() {
		t.Error("written_at not defaulted")
	}
}

func TestWriteProcessHealth_RequiresDir(t *testing.T) {
	if _, err := WriteProcessHealth("", ProcessHealth{}); err == nil {
		t.Fatal("want error for empty dbDir")
	}
}

// TestLiveProcessHealth_DropsDeadDaemons pins the honesty rule: a record left
// behind by a daemon that is gone is NOT the current state, so it is dropped
// rather than reported as stale. Uses the same virtually-never-live PID as
// the lockfile tests.
func TestLiveProcessHealth_DropsDeadDaemons(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteProcessHealth(dir, ProcessHealth{
		PID: 2147483646, WrittenAt: time.Now().UTC(), Backend: "poll",
		NetworkAccountingMode: procmodel.NetworkAccountingTCP,
	}); err != nil {
		t.Fatalf("WriteProcessHealth: %v", err)
	}
	live, err := LiveProcessHealth(dir)
	if err != nil {
		t.Fatalf("LiveProcessHealth: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("got %d live records, want 0: %+v", len(live), live)
	}
	if _, ok := LatestProcessHealth(dir); ok {
		t.Error("LatestProcessHealth reported a dead daemon's record")
	}
}

// TestWriteProcessHealth_SweepsDeadRecords confirms the write path cleans up
// after daemons that exited without removing their record (a kill -9), so the
// directory does not accumulate one file per crashed daemon.
func TestWriteProcessHealth_SweepsDeadRecords(t *testing.T) {
	dir := t.TempDir()
	dead := ProcessHealthPath(dir, 2147483646)
	if err := os.WriteFile(dead, []byte(`{"pid":2147483646}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteProcessHealth(dir, ProcessHealth{Backend: "poll"}); err != nil {
		t.Fatalf("WriteProcessHealth: %v", err)
	}
	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Errorf("dead record not swept: err=%v", err)
	}
}

// TestLiveProcessHealth_SkipsGarbage confirms an unparseable file neither
// crashes the reader nor gets deleted (it may not be ours).
func TestLiveProcessHealth_SkipsGarbage(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "observer-processobs-777.health.json")
	if err := os.WriteFile(garbage, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	live, err := LiveProcessHealth(dir)
	if err != nil {
		t.Fatalf("LiveProcessHealth: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("got %d records, want 0", len(live))
	}
	if _, err := os.Stat(garbage); err != nil {
		t.Errorf("unparseable file was deleted: %v", err)
	}
}

func TestLiveProcessHealth_EmptyDir(t *testing.T) {
	live, err := LiveProcessHealth("")
	if err != nil || live != nil {
		t.Fatalf("empty dir: got (%v, %v), want (nil, nil)", live, err)
	}
	if _, ok := LatestProcessHealth(t.TempDir()); ok {
		t.Error("empty directory reported a live record")
	}
}

func TestProcessHealthDir(t *testing.T) {
	if got := ProcessHealthDir(""); got != "" {
		t.Errorf("empty path: got %q, want %q", got, "")
	}
	// filepath.Dir answers in the host's separator.
	if got := ProcessHealthDir("/var/lib/observer/observer.db"); got != filepath.FromSlash("/var/lib/observer") {
		t.Errorf("got %q", got)
	}
	if got := ProcessHealthDir("~/.observer/observer.db"); strings.HasPrefix(got, "~") {
		t.Errorf("tilde not expanded: %q", got)
	}
}

func TestProcessHealth_AgeAndStale(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		writtenAt time.Time
		wantAge   time.Duration
		wantStale bool
	}{
		{"fresh", now.Add(-5 * time.Second), 5 * time.Second, false},
		{"one missed refresh", now.Add(-45 * time.Second), 45 * time.Second, false},
		{"exactly at the threshold", now.Add(-ProcessHealthStaleAfter), ProcessHealthStaleAfter, false},
		{"past the threshold", now.Add(-ProcessHealthStaleAfter - time.Second), ProcessHealthStaleAfter + time.Second, true},
		{"zero timestamp", time.Time{}, 0, false},
		{"clock skew into the future", now.Add(time.Minute), 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := ProcessHealth{WrittenAt: tc.writtenAt}
			if got := h.Age(now); got != tc.wantAge {
				t.Errorf("Age = %v, want %v", got, tc.wantAge)
			}
			if got := h.Stale(now); got != tc.wantStale {
				t.Errorf("Stale = %v, want %v", got, tc.wantStale)
			}
		})
	}
}

// TestNetworkAccountingLine pins the operator-visible wording for each mode:
// "off" must not nag, "unavailable" must carry the reason verbatim, and "tcp"
// must state the TCP-only caveat so a QUIC-heavy workload's near-zero chart
// is not read as breakage.
func TestNetworkAccountingLine(t *testing.T) {
	tests := []struct {
		name        string
		mode        string
		reason      string
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:        "off is stated, not nagged",
			mode:        procmodel.NetworkAccountingOff,
			reason:      "not enabled ([observer.process.network].process_bytes)",
			wantContain: []string{"off", "process_bytes"},
			wantAbsent:  []string{"UNAVAILABLE", "NOT measured"},
		},
		{
			name:        "unavailable carries the reason verbatim",
			mode:        procmodel.NetworkAccountingUnavailable,
			reason:      "missing CAP_BPF/CAP_PERFMON",
			wantContain: []string{"UNAVAILABLE", "NOT measured", "missing CAP_BPF/CAP_PERFMON"},
		},
		{
			name:        "unavailable without a reason says so",
			mode:        procmodel.NetworkAccountingUnavailable,
			wantContain: []string{"UNAVAILABLE", "no reason reported"},
		},
		{
			name:        "etw elevation reason survives",
			mode:        procmodel.NetworkAccountingUnavailable,
			reason:      "ETW session needs elevation (ERROR_ACCESS_DENIED)",
			wantContain: []string{"UNAVAILABLE", "needs elevation", "ERROR_ACCESS_DENIED"},
		},
		{
			name:        "tcp states the TCP-only caveat",
			mode:        procmodel.NetworkAccountingTCP,
			wantContain: []string{"live (tcp)", "TCP payload bytes only", "UDP/QUIC"},
			wantAbsent:  []string{"UNAVAILABLE"},
		},
		{
			name:        "empty mode is unknown, not guessed",
			mode:        "",
			wantContain: []string{"unknown"},
			wantAbsent:  []string{"off -"},
		},
		{
			name:        "unrecognised mode is reported as itself",
			mode:        "tcp+udp",
			wantContain: []string{"tcp+udp", "unrecognised"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ProcessHealth{
				NetworkAccountingMode:   tc.mode,
				NetworkAccountingReason: tc.reason,
			}.NetworkAccountingLine()
			for _, want := range tc.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("line %q missing %q", got, want)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("line %q unexpectedly contains %q", got, absent)
				}
			}
		})
	}
}

// transportNow anchors the "… ago" phrasing in the transport-line tests.
func transportNow() time.Time { return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC) }

// TestTransportLine pins the operator-visible wording for every cross-OS
// capturer-link state. The states are NOT interchangeable phrasings of one
// fact: "no transport configured" must render nothing at all, "never
// connected" is a WAITING state and not an error, and auth failures with zero
// successful connections is the one actionable case (a token mismatch) and
// must name the config keys.
func TestTransportLine(t *testing.T) {
	tests := []struct {
		name        string
		health      ProcessHealth
		wantEmpty   bool
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:      "no transport configured renders nothing",
			health:    ProcessHealth{Backend: "poll"},
			wantEmpty: true,
		},
		{
			name: "counters without the configured flag still render nothing",
			// The back-compat shape: a record from an older daemon decodes
			// with no transport_state key. Zero counters must never be
			// dressed up as a broken transport.
			health:    ProcessHealth{Backend: "poll", TransportConnections: 0},
			wantEmpty: true,
		},
		{
			name: "never connected is waiting, not an error",
			health: ProcessHealth{
				TransportState: procmodel.TransportStateConfigured, TransportAddr: "127.0.0.1:8823",
			},
			wantContain: []string{"waiting", "no capturer has ever connected", "127.0.0.1:8823", "Scheduled Task"},
			wantAbsent:  []string{"AUTH FAILURE", "DISCONNECTED", "live -"},
		},
		{
			// The defect this row now guards: the counter conflates EVERY
			// handshake failure, so a wire-version skew used to render as
			// "the capturer is presenting the wrong shared token" and sent
			// the operator to fix a token that was already correct. The
			// daemon's verbatim reason must lead, and the token may appear
			// only as one candidate among several.
			name: "a non-token refusal is not diagnosed as a token problem",
			health: ProcessHealth{
				TransportState: procmodel.TransportStateConfigured, TransportAddr: "127.0.0.1:8823",
				TransportAuthFailures:  6,
				TransportLastAuthError: "processobs/bridge: malformed handshake: capturer speaks protocol v2, this daemon speaks v1",
			},
			wantContain: []string{
				"AUTH FAILURE", "REFUSED", "6",
				"capturer speaks protocol v2, this daemon speaks v1",
				"cause is NOT assumed", "candidates",
				"[observer.process.etw].token", "token_path",
			},
			wantAbsent: []string{
				"waiting", "DISCONNECTED",
				// The three assertions of a cause the record cannot support.
				"is presenting the wrong", "shared-token mismatch", "on a bad token",
			},
		},
		{
			name: "a token refusal reports the token reason verbatim, still as a candidate",
			health: ProcessHealth{
				TransportState: procmodel.TransportStateConfigured, TransportAddr: "127.0.0.1:8823",
				TransportAuthFailures:  2,
				TransportLastAuthError: "processobs/bridge: invalid token",
			},
			wantContain: []string{"AUTH FAILURE", `"processobs/bridge: invalid token"`, "candidates"},
			wantAbsent:  []string{"is presenting the wrong", "shared-token mismatch"},
		},
		{
			name: "a refusal with no recorded reason says so rather than guessing",
			health: ProcessHealth{
				TransportState: procmodel.TransportStateConfigured, TransportAddr: "127.0.0.1:8823",
				TransportAuthFailures: 6,
			},
			wantContain: []string{"AUTH FAILURE", "no refusal reason was recorded"},
			wantAbsent:  []string{"is presenting the wrong", "shared-token mismatch", "most recent reason"},
		},
		{
			// M3: requested and broken must not read like never requested.
			name: "a requested transport that never started is reported, not silent",
			health: ProcessHealth{
				TransportState:             procmodel.TransportStateUnavailable,
				TransportUnavailableReason: "processobs/bridge: listen 127.0.0.1:8823: bind: address already in use",
			},
			wantContain: []string{
				"UNAVAILABLE", "was requested", "NOT running",
				"bind: address already in use", "[observer.process.etw].enabled",
			},
			wantAbsent: []string{"waiting", "AUTH FAILURE", "live"},
		},
		{
			name: "an unavailable transport with no reason states the gap",
			health: ProcessHealth{
				TransportState: procmodel.TransportStateUnavailable,
			},
			wantContain: []string{"UNAVAILABLE", "no reason reported by the daemon"},
		},
		{
			name: "connected reports since-when",
			health: ProcessHealth{
				TransportState: procmodel.TransportStateConfigured, TransportAddr: "127.0.0.1:8823",
				TransportConnected: true, TransportConnections: 1,
				TransportLastConnectAt: transportNow().Add(-90 * time.Second),
			},
			wantContain: []string{"live", "connected 1m30s ago", "127.0.0.1:8823"},
			wantAbsent:  []string{"AUTH FAILURE", "waiting", "DISCONNECTED"},
		},
		{
			name: "connected after an earlier refusal still mentions it",
			health: ProcessHealth{
				TransportState: procmodel.TransportStateConfigured, TransportConnected: true,
				TransportConnections: 2, TransportAuthFailures: 3,
				TransportLastConnectAt: transportNow().Add(-10 * time.Second),
			},
			wantContain: []string{"live", "3 earlier connection(s) were refused"},
		},
		{
			name: "a capturer that came and went shows both timestamps",
			health: ProcessHealth{
				TransportState: procmodel.TransportStateConfigured, TransportAddr: "127.0.0.1:8823",
				TransportConnections:      4,
				TransportLastConnectAt:    transportNow().Add(-5 * time.Minute),
				TransportLastDisconnectAt: transportNow().Add(-2 * time.Minute),
			},
			wantContain: []string{"DISCONNECTED", "last connected 5m0s ago", "disconnected 2m0s ago", "4 connection(s)"},
			wantAbsent:  []string{"waiting", "AUTH FAILURE"},
		},
		{
			// L7: every state below is present-tense. A record the daemon
			// stopped refreshing cannot support "is connected", so the line
			// says up front that it is reading history.
			name: "a stale record does not claim the capturer is connected NOW",
			health: ProcessHealth{
				WrittenAt:      transportNow().Add(-10 * time.Minute),
				TransportState: procmodel.TransportStateConfigured, TransportAddr: "127.0.0.1:8823",
				TransportConnected: true, TransportConnections: 1,
				TransportLastConnectAt: transportNow().Add(-11 * time.Minute),
			},
			wantContain: []string{"last report 10m0s ago", "STALE", "live"},
		},
		{
			name: "a fresh record carries no staleness qualifier",
			health: ProcessHealth{
				WrittenAt:      transportNow().Add(-5 * time.Second),
				TransportState: procmodel.TransportStateConfigured, TransportAddr: "127.0.0.1:8823",
				TransportConnected: true, TransportConnections: 1,
				TransportLastConnectAt: transportNow().Add(-time.Minute),
			},
			wantContain: []string{"live"},
			wantAbsent:  []string{"STALE", "last report"},
		},
		{
			name: "a missing timestamp is stated, not printed as epoch zero",
			health: ProcessHealth{
				TransportState: procmodel.TransportStateConfigured, TransportConnections: 1,
			},
			wantContain: []string{"DISCONNECTED", "unrecorded time"},
			wantAbsent:  []string{"1970", "0001"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.health.TransportLine(transportNow())
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("want an empty line (caller skips it), got %q", got)
				}
				return
			}
			if got == "" {
				t.Fatal("want a rendered line, got empty")
			}
			for _, want := range tc.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("line %q missing %q", got, want)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("line %q unexpectedly contains %q", got, absent)
				}
			}
		})
	}
}

// TestProcessHealthTransportBackCompat pins the wire back-compat rule: a
// record written by a daemon that predates these fields must decode as "no
// transport" and render silence — never as a transport with zero connections
// — and a new record must round-trip its transport half intact.
func TestProcessHealthTransportBackCompat(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"pid":` + strconv.Itoa(os.Getpid()) + `,"written_at":"2026-07-26T11:59:00Z",` +
		`"backend":"poll","backend_up":true,"queue_depth":0,"network_accounting_mode":"off"}`
	if err := os.WriteFile(ProcessHealthPath(dir, os.Getpid()), []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy record: %v", err)
	}
	h, ok := LatestProcessHealth(dir)
	if !ok {
		t.Fatal("a legacy record must still be readable")
	}
	if h.TransportConfigured() || h.TransportState != "" {
		t.Errorf("a record with no transport keys must decode as no transport, got state %q", h.TransportState)
	}
	if line := h.TransportLine(transportNow()); line != "" {
		t.Errorf("a legacy record must render no capturer-link line, got %q", line)
	}
	// The refusal CLASS is the same shape of additive key: an older daemon
	// never wrote it, so it decodes empty and readers normalise it to
	// "unknown" rather than inventing one of the named causes.
	if h.TransportLastAuthErrorClass != "" {
		t.Errorf("a legacy record cannot carry a refusal class, got %q", h.TransportLastAuthErrorClass)
	}
	if got := procmodel.NormalizeTransportAuthClass(h.TransportLastAuthErrorClass); got != procmodel.TransportAuthClassUnknown {
		t.Errorf("an absent class must read as %q, got %q", procmodel.TransportAuthClassUnknown, got)
	}

	dir2 := t.TempDir()
	want := ProcessHealth{
		PID: os.Getpid(), WrittenAt: transportNow(), Backend: "composite[poll+bridge-listen]",
		TransportState: procmodel.TransportStateConfigured, TransportAddr: "127.0.0.1:8823",
		TransportConnections: 2, TransportAuthFailures: 1, TransportConnected: true,
		TransportLastAuthError:      "processobs/bridge: malformed handshake: capturer speaks protocol v2, this daemon speaks v1",
		TransportLastAuthErrorClass: procmodel.TransportAuthClassProtocolVersion,
		TransportLastConnectAt:      transportNow().Add(-time.Minute),
		TransportLastDisconnectAt:   transportNow().Add(-2 * time.Minute),
	}
	if _, err := WriteProcessHealth(dir2, want); err != nil {
		t.Fatalf("WriteProcessHealth: %v", err)
	}
	got, ok := LatestProcessHealth(dir2)
	if !ok {
		t.Fatal("record not readable")
	}
	if !got.TransportConfigured() || got.TransportAddr != want.TransportAddr ||
		got.TransportConnections != 2 || got.TransportAuthFailures != 1 || !got.TransportConnected ||
		got.TransportLastAuthError != want.TransportLastAuthError ||
		got.TransportLastAuthErrorClass != want.TransportLastAuthErrorClass ||
		!got.TransportLastConnectAt.Equal(want.TransportLastConnectAt) ||
		!got.TransportLastDisconnectAt.Equal(want.TransportLastDisconnectAt) {
		t.Errorf("transport half did not round-trip: %+v", got)
	}
}

// TestCapturerDecodeLineNothingClassified pins the E6b prose surface: the one
// decode state that used to be indistinguishable from a pass now says so, and
// the states that were correctly quiet stay quiet.
//
// The quiet rows are as load-bearing as the loud one. A large ignore count is
// NORMAL on every healthy elevated run — it counts control-plane events,
// connect/disconnect/retransmit and UDP — so a line that fired on it would
// scream on exactly the hosts where the feature is working.
func TestCapturerDecodeLineNothingClassified(t *testing.T) {
	tests := []struct {
		name        string
		health      ProcessHealth
		wantEmpty   bool
		wantContain []string
		wantAbsent  []string
	}{
		{
			name: "everything ignored, nothing decoded, nothing refused",
			health: ProcessHealth{
				TransportCapturerDecodeReported: true,
				TransportCapturerIgnored:        48211,
			},
			wantContain: []string{"NO DATA EVENTS CLASSIFIED", "48211", "flat zero", "event ids no longer"},
			wantAbsent:  []string{"DECODE FAILURES"},
		},
		{
			name: "a healthy busy capture stays silent however large the ignore count",
			health: ProcessHealth{
				TransportCapturerDecodeReported: true,
				TransportCapturerIgnored:        1_000_000,
				TransportCapturerDecoded:        4321,
			},
			wantEmpty: true,
		},
		{
			name: "a capturer that never reported stays silent - absence is not a suspicion",
			health: ProcessHealth{
				TransportCapturerDecodeReported: false,
				TransportCapturerIgnored:        48211,
			},
			wantEmpty: true,
		},
		{
			name: "a refusing decoder keeps its own louder line",
			health: ProcessHealth{
				TransportCapturerDecodeReported: true,
				TransportCapturerDropped:        4,
				TransportCapturerIgnored:        900,
			},
			wantContain: []string{"DECODE FAILURES"},
			wantAbsent:  []string{"NO DATA EVENTS CLASSIFIED"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.health.CapturerDecodeLine()
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("want silence, got %q", got)
				}
				return
			}
			for _, want := range tc.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("line %q missing %q", got, want)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("line %q unexpectedly contains %q", got, absent)
				}
			}
		})
	}
}

// TestCapturerDecodeClassificationBackCompat pins design constraint 5 at the
// on-disk layer: a health record written by a daemon that predates the two
// classification counters decodes with them absent, which must read as "not
// proven" — never as the renumbered-provider suspicion, and never as a pass.
func TestCapturerDecodeClassificationBackCompat(t *testing.T) {
	dir := t.TempDir()
	// A pre-E6b record: reported, both refusal counters omitted (a reported
	// zero), and no classification keys at all.
	legacy := `{"pid":` + strconv.Itoa(os.Getpid()) + `,"written_at":"2026-07-26T11:59:00Z",` +
		`"backend":"bridge-listen","backend_up":true,"network_accounting_mode":"tcp",` +
		`"transport_state":"configured","transport_addr":"127.0.0.1:8823","transport_connections":1,` +
		`"transport_capturer_decode_reported":true}`
	if err := os.WriteFile(ProcessHealthPath(dir, os.Getpid()), []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy record: %v", err)
	}
	h, ok := LatestProcessHealth(dir)
	if !ok {
		t.Fatal("a legacy record must still be readable")
	}
	if h.TransportCapturerIgnored != 0 || h.TransportCapturerDecoded != 0 {
		t.Errorf("absent classification keys must decode as zero, got %+v", h)
	}
	if h.CapturerDecodeNothingClassified() {
		t.Error("an older daemon's record must not raise a suspicion it carries no evidence for")
	}
	if line := h.CapturerDecodeLine(); line != "" {
		t.Errorf("a legacy record must render no decode clause, got %q", line)
	}
}
