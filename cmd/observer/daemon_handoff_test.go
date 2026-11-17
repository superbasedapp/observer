package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// fakeHandoffDaemon is a dashboard of one of four kinds: "same" and "other"
// speak the identity protocol (db_identity_guard.go) for this database or
// another one, "old" predates it (names nothing, refuses nothing), and
// "swapped" names this database on the probe but another one afterwards
// (the address changed hands between the probe and the work).
type fakeHandoffDaemon struct {
	srv      *httptest.Server
	pushes   atomic.Int32
	ends     atomic.Int32
	identity atomic.Int32 // requests that named this database
}

func newFakeHandoffDaemon(t *testing.T, kind, own, other string) *fakeHandoffDaemon {
	t.Helper()
	d := &fakeHandoffDaemon{}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := r.Header.Get(dashapi.DBIdentityRequestHeader)
		if want == own && own != "" {
			d.identity.Add(1)
		}
		served := ""
		switch kind {
		case "same":
			served = own
		case "other":
			served = other
		case "swapped":
			served = own
			if r.Method != http.MethodHead {
				served = other
			}
		}
		if served != "" && want != "" {
			w.Header().Set(dashapi.DBIdentityHeader, served)
			if want != served {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": dashapi.DBMismatchCode})
				return
			}
		}
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
		case "/api/enrolment/manage":
			_ = json.NewEncoder(w).Encode(map[string]any{"confirm_token": "tok"})
		case "/api/enrolment/push-now":
			d.pushes.Add(1)
			_ = json.NewEncoder(w).Encode(dashapi.PushNowReport{RowCount: 54, Message: "Pushed 54 rows"})
		case "/api/admin/restart":
			w.Header().Set(dashapi.LiveRunsHeader, "1")
			if r.Method == http.MethodPost {
				d.ends.Add(1)
				_ = json.NewEncoder(w).Encode(map[string]int{"ended_sandboxed_runs": 1})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"live_sandboxed_runs": []dashapi.LiveSandboxRun{{RunID: "r1", Tool: "claude-code", Backend: "bwrap"}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *fakeHandoffDaemon) addr() string { return strings.TrimPrefix(d.srv.URL, "http://") }

// closedHandoffAddr is a loopback address nothing listens on.
func closedHandoffAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// stubRecordEvidence sets the listen-record evidence for the test.
func stubRecordEvidence(t *testing.T, present bool) {
	t.Helper()
	saved := daemonRecordEvidence
	daemonRecordEvidence = func(string) bool { return present }
	t.Cleanup(func() { daemonRecordEvidence = saved })
}

// TestDaemonHandoffPushNow pins L-125 end to end on the CLI side: `org
// push-now` hands the push to a daemon only when it serves this database,
// over listen-record evidence present/absent x the daemon's identity
// (same / other / unknown (older daemon) / none listening / swapped after the
// probe). Every row that does not hand off pushes in this process instead.
func TestDaemonHandoffPushNow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "throwaway", "observer.db")
	own := dashapi.DBIdentity(dbPath)
	other := dashapi.DBIdentity(filepath.Join(t.TempDir(), "live", "observer.db"))
	cases := []struct {
		name       string
		record     bool
		kind       string // "same", "other", "old", "swapped", "none"
		wantUse    bool
		wantPushed bool
	}{
		{"record absent, same database", false, "same", true, true},
		{"record present, same database", true, "same", true, true},
		{"record absent, other database (the L-125 case on a new daemon)", false, "other", false, false},
		{"record present, other database", true, "other", false, false},
		{"record absent, older daemon names nothing (the L-125 case)", false, "old", false, false},
		{"record present, older daemon names nothing", true, "old", true, true},
		{"record absent, nothing listens", false, "none", false, false},
		{"record present, nothing listens", true, "none", false, false},
		{"record absent, address changed hands after the probe", false, "swapped", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubRecordEvidence(t, tc.record)
			var d *fakeHandoffDaemon
			addr := ""
			if tc.kind == "none" {
				addr = closedHandoffAddr(t)
			} else {
				d = newFakeHandoffDaemon(t, tc.kind, own, other)
				addr = d.addr()
			}
			target := daemonHandoffFor(context.Background(), dbPath, addr)
			if target.Use != tc.wantUse {
				t.Fatalf("Use = %v (%s), want %v", target.Use, target.Reason, tc.wantUse)
			}
			if target.Listening != (tc.kind != "none") {
				t.Fatalf("Listening = %v for kind %q", target.Listening, tc.kind)
			}
			answered := false
			if target.Use {
				answered = daemonPushNow(context.Background(), target.Base, target.DBIdentity).Answered
			}
			pushed := d != nil && d.pushes.Load() > 0
			if pushed != tc.wantPushed || answered != tc.wantPushed {
				t.Fatalf("daemon pushed = %v answered = %v, want %v", pushed, answered, tc.wantPushed)
			}
			if d != nil && tc.kind != "old" && target.Use && d.identity.Load() == 0 {
				t.Fatal("the CLI never named its database to the daemon")
			}
		})
	}
}

// TestDaemonHandoffLiveRuns pins the live-run question and its end through
// the same table: a daemon serving another database is never asked, so its
// runs are neither reported nor ended.
func TestDaemonHandoffLiveRuns(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "throwaway", "observer.db")
	own := dashapi.DBIdentity(dbPath)
	other := dashapi.DBIdentity(filepath.Join(t.TempDir(), "live", "observer.db"))
	cases := []struct {
		name         string
		record       bool
		kind         string
		wantAnswered bool
		wantEnded    bool
	}{
		{"same database: asked and ended", false, "same", true, true},
		{"other database: not asked, not ended", true, "other", false, false},
		{"older daemon, no record: not asked, not ended", false, "old", false, false},
		{"older daemon, record present: asked and ended", true, "old", true, true},
		{"swapped after the probe: refused, not ended", false, "swapped", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubRecordEvidence(t, tc.record)
			d := newFakeHandoffDaemon(t, tc.kind, own, other)
			c := handoffLiveRunsClient(func(ctx context.Context) daemonTarget {
				return daemonHandoffFor(ctx, dbPath, d.addr())
			})
			rep, err := c.query(context.Background())
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if rep.Answered != tc.wantAnswered {
				t.Fatalf("answered = %v, want %v", rep.Answered, tc.wantAnswered)
			}
			n, err := c.end(context.Background())
			if tc.wantEnded {
				if err != nil || n != 1 {
					t.Fatalf("end = %d, %v; want 1 ended", n, err)
				}
			} else if err == nil {
				t.Fatalf("end on a daemon of another database reported success (%d)", n)
			}
			if ended := d.ends.Load() > 0; ended != tc.wantEnded {
				t.Fatalf("daemon ended runs = %v, want %v", ended, tc.wantEnded)
			}
		})
	}
}
