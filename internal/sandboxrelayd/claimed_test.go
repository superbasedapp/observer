package sandboxrelayd

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
)

// claim claims ids for runID the way the bind's claim row does, including
// persisting the new fresh ids.
func claim(t *testing.T, d *Daemon, runID string, ids ...string) {
	t.Helper()
	r, fresh := d.claimSessions(&RunState{}, runID, ids, d.freshEligible(context.Background(), runID, ids, nil))
	if r != "" {
		t.Fatalf("claim refused: %s", r)
	}
	if len(fresh) > 0 && d.FreshStore != nil {
		d.FreshStore.AddFresh(runID, fresh)
	}
}

// memFresh is an in-memory FreshSessions (it outlives a Daemon, as the
// node's file does).
type memFresh struct {
	mu  sync.Mutex
	ids map[string][]string
}

func (m *memFresh) Fresh(runID string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.ids[runID]...)
}

func (m *memFresh) AddFresh(runID string, ids []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ids == nil {
		m.ids = map[string][]string{}
	}
	for _, id := range ids {
		if !slices.Contains(m.ids[runID], id) {
			m.ids[runID] = append(m.ids[runID], id)
		}
	}
}

// TestSessionClaim: only the run whose hooks claimed a session reads it as
// claimed; a claim is fresh only when the node recorded no such session at
// the first claim (a failed lookup or no lookup is never fresh); the check
// claims nothing itself; ending the run clears both.
func TestSessionClaim(t *testing.T) {
	t.Parallel()
	recorded := map[string]string{"host-s": "/w"}
	d := &Daemon{SessionOwner: func(_ context.Context, id string) (string, error) {
		if id == "lookup-fails" {
			return "", errors.New("db down")
		}
		return recorded[id], nil
	}}
	claim(t, d, "run-a", "s1", "host-s", "lookup-fails")
	// A session first seen by the run, then recorded by its own hook, is
	// still fresh: freshness is fixed at the first claim.
	recorded["s1"] = "/w"
	claim(t, d, "run-a", "s1")
	for _, tc := range []struct {
		run, id        string
		claimed, fresh bool
	}{
		{"run-a", "s1", true, true},
		{"run-a", "host-s", true, false},
		{"run-a", "lookup-fails", true, false},
		{"run-b", "s1", false, false},
		{"run-a", "s2", false, false},
		{"", "s1", false, false},
		{"run-a", "", false, false},
	} {
		if c, f := d.SessionClaim(tc.run, tc.id); c != tc.claimed || f != tc.fresh {
			t.Errorf("SessionClaim(%q, %q) = %v %v, want %v %v", tc.run, tc.id, c, f, tc.claimed, tc.fresh)
		}
	}
	if len(d.sessions) != 3 {
		t.Fatalf("the check claimed a session: %v", d.sessions)
	}
	d.EndRun("run-a")
	if c, _ := d.SessionClaim("run-a", "s1"); c || len(d.fresh) != 0 {
		t.Fatalf("the run's claims outlived it: %v %v", d.sessions, d.fresh)
	}
	// No SessionOwner: nothing can be shown fresh.
	bare := &Daemon{}
	claim(t, bare, "run-c", "s9")
	if c, f := bare.SessionClaim("run-c", "s9"); !c || f {
		t.Fatalf("no lookup: claimed %v fresh %v, want claimed and not fresh", c, f)
	}
	var nilD *Daemon
	if c, _ := nilD.SessionClaim("run-a", "s1"); c {
		t.Fatal("a nil daemon claims nothing")
	}
}

// TestSessionFreshnessOutlivesTheClaims (audit FU3-R1), one case per way a
// run's claims are dropped while the run goes on: the run's own session,
// fresh at its first claim and recorded by the node since, is fresh again
// when the run re-claims it, while a session the node recorded before the
// run's first claim (the developer's own session the box resumed) never
// is; with no FreshStore the re-claim is not fresh (memory only, fail
// safe).
func TestSessionFreshnessOutlivesTheClaims(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		store bool
		drop  func(d *Daemon) *Daemon
		fresh bool
	}{
		{"re-adoption: claims dropped by the run's end, same run id", true, func(d *Daemon) *Daemon { d.EndRun("run-a"); return d }, true},
		{"daemon restart: a new daemon, the same store", true, func(d *Daemon) *Daemon {
			return &Daemon{SessionOwner: d.SessionOwner, FreshStore: d.FreshStore}
		}, true},
		{"no store: memory only", false, func(d *Daemon) *Daemon { d.EndRun("run-a"); return d }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			recorded := map[string]string{"host-own": "/w"}
			var mu sync.Mutex
			owner := func(_ context.Context, id string) (string, error) {
				mu.Lock()
				defer mu.Unlock()
				return recorded[id], nil
			}
			d := &Daemon{SessionOwner: owner}
			if tc.store {
				d.FreshStore = &memFresh{}
			}
			claim(t, d, "run-a", "box-own", "host-own")
			mu.Lock()
			recorded["box-own"] = "/w" // the run's own hook recorded it
			mu.Unlock()
			d = tc.drop(d)
			if c, _ := d.SessionClaim("run-a", "box-own"); c {
				t.Fatal("the claims were not dropped")
			}
			claim(t, d, "run-a", "box-own", "host-own")
			if c, f := d.SessionClaim("run-a", "box-own"); !c || f != tc.fresh {
				t.Fatalf("the run's own session after the drop: claimed %v fresh %v, want fresh %v", c, f, tc.fresh)
			}
			if c, f := d.SessionClaim("run-a", "host-own"); !c || f {
				t.Fatalf("a session recorded before the run: claimed %v fresh %v, want claimed and not fresh", c, f)
			}
			// Another run never inherits the kept list.
			d.EndRun("run-a")
			claim(t, d, "run-b", "box-own")
			if _, f := d.SessionClaim("run-b", "box-own"); f {
				t.Fatal("another run read run-a's kept freshness")
			}
		})
	}
}
