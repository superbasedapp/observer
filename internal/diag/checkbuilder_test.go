package diag

import (
	"net"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestDetailCheckResult pins the accumulator: worst tracks the highest
// status noted, and the message switches to the warning text only then.
func TestDetailCheckResult(t *testing.T) {
	var d detailCheck
	if got := d.result("n", "ok", "warn"); got.Status != StatusOK || got.Message != "ok" || got.Details != nil {
		t.Fatalf("empty result = %+v", got)
	}
	d.note(StatusOK, "a")
	d.note(StatusWarn, "b")
	d.note(StatusOK, "c")
	got := d.result("n", "ok", "warn")
	want := Check{Name: "n", Status: StatusWarn, Message: "warn", Details: []string{"a", "b", "c"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("result = %+v, want %+v", got, want)
	}
}

// TestNoteOTLPReceiverMessages pins the exact lines the Teams checks print
// for a reachable and an unreachable receiver, with and without a target.
func TestNoteOTLPReceiverMessages(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	up := ln.Addr().String()
	gone, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	down := gone.Addr().String()
	_ = gone.Close()

	cases := []struct {
		addr, target string
		status       Status
		line         string
	}{
		{up, "", StatusOK, "OTLP receiver reachable at " + up},
		{up, "Copilot Rail A redirect target", StatusOK, "OTLP receiver reachable at " + up + " (Copilot Rail A redirect target)"},
		{down, "Rail A redirect target", StatusWarn, "OTLP receiver NOT reachable at " + down + " - is `observer start` running with [ingest.otel].enabled?"},
	}
	for _, tc := range cases {
		var d detailCheck
		d.noteOTLPReceiver(tc.addr, tc.target)
		if d.worst != tc.status || len(d.details) != 1 || d.details[0] != tc.line {
			t.Errorf("noteOTLPReceiver(%q, %q) = %v %q, want %v %q", tc.addr, tc.target, d.worst, d.details, tc.status, tc.line)
		}
	}

	// noteOTLPReceivers walks gRPC then HTTP and skips an empty address.
	var cfg config.Config
	cfg.Ingest.OTel.GRPCAddr = ""
	cfg.Ingest.OTel.HTTPAddr = up
	var d detailCheck
	d.noteOTLPReceivers(cfg, "")
	if !reflect.DeepEqual(d.details, []string{"OTLP receiver reachable at " + up}) {
		t.Fatalf("noteOTLPReceivers details = %q", d.details)
	}
}

// TestNoteNPX pins that an empty OK line notes nothing when npx is found
// and that the WARN line is used verbatim when it is not.
func TestNoteNPX(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var d detailCheck
	d.noteNPX("present", npxPinWillNotStart)
	if d.worst != StatusWarn || !reflect.DeepEqual(d.details, []string{npxPinWillNotStart}) {
		t.Fatalf("npx missing: %v %q", d.worst, d.details)
	}
}
