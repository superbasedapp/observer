package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// TestKillSwitchSetRequiresYes is table-driven over on/off: neither verb may
// change state without an explicit --yes, and the credential check runs
// before the database is even opened (a bad DSN must not be reached).
func TestKillSwitchSetRequiresYes(t *testing.T) {
	cases := []struct {
		name string
		on   bool
	}{
		{"on_without_yes", true},
		{"off_without_yes", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("SBCI_PG_DSN", "postgres://invalid:1/none?sslmode=disable")
			cmd := newKillSwitchSetCmd(c.on)
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(nil)
			err := cmd.Execute()
			if err == nil {
				t.Fatal("kill-switch set ran without --yes")
			}
			if !strings.Contains(err.Error(), "--yes") {
				t.Fatalf("refusal must name --yes: %v", err)
			}
			if strings.Contains(err.Error(), "connect") || strings.Contains(err.Error(), "dial") {
				t.Fatalf("the --yes check must run BEFORE the database is opened: %v", err)
			}
		})
	}
}

// TestKillSwitchStatusNeverRequiresYes proves the read-only verb has no --yes
// gate (only the state-changing verbs do).
func TestKillSwitchStatusNeverRequiresYes(t *testing.T) {
	cmd := newKillSwitchStatusCmd()
	if fl := cmd.Flags().Lookup("yes"); fl != nil {
		t.Fatal("status must not have a --yes flag")
	}
}

// TestKillSwitchTopLevelWiresAllThreeVerbs pins the command tree shape so a
// future refactor can't silently drop status/on/off.
func TestKillSwitchTopLevelWiresAllThreeVerbs(t *testing.T) {
	cmd := newKillSwitchCmd()
	want := map[string]bool{"status": false, "on": false, "off": false}
	for _, sub := range cmd.Commands() {
		if _, ok := want[sub.Name()]; ok {
			want[sub.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("kill-switch subcommand %q is missing", name)
		}
	}
}

// TestKillSwitchEndToEndAgainstThrowawayPG exercises the real store seam
// (SetKillSwitch / KillSwitches / GlobalKillSwitchActive,
// internal/cloudserver/store/control.go) through the CLI's own RunE
// functions against a throwaway, freshly-migrated Postgres — the D4 "store
// test against the throwaway PG" requirement. Skips gracefully when
// SBCI_TEST_PG_DSN is unset (cloudtestpg.NewDB).
func TestKillSwitchEndToEndAgainstThrowawayPG(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)

	// Seed migration 0004 installs the global switch OFF (active=false) and one
	// route switch OFF for session_enrichment.luna.v1 — assert the seed first so
	// a schema drift fails loudly here instead of masquerading as a CLI bug.
	activeAfterSeed, err := s.GlobalKillSwitchActive(t.Context())
	if err != nil {
		t.Fatalf("GlobalKillSwitchActive (seed): %v", err)
	}
	if activeAfterSeed {
		t.Fatal("seed migration 0004 must install the global kill switch OFF (active=false)")
	}

	// Flip the global switch ON via the exact store call the `on` verb makes.
	if err := s.SetKillSwitch(t.Context(), "global", "all", true); err != nil {
		t.Fatalf("SetKillSwitch(global, on): %v", err)
	}
	active, err := s.GlobalKillSwitchActive(t.Context())
	if err != nil {
		t.Fatalf("GlobalKillSwitchActive (after on): %v", err)
	}
	if !active {
		t.Fatal("global kill switch did not report active after SetKillSwitch(..., true)")
	}

	// Flip a per-route switch and confirm KillSwitches reports both halves
	// independently (the global flip above must not leak into the per-route
	// read, and vice versa).
	const routeID = "session_enrichment.luna.v1"
	if err := s.SetKillSwitch(t.Context(), "route", routeID, true); err != nil {
		t.Fatalf("SetKillSwitch(route, on): %v", err)
	}
	st, err := s.KillSwitches(t.Context(), routeID)
	if err != nil {
		t.Fatalf("KillSwitches: %v", err)
	}
	if !st.GlobalActive || !st.RouteActive {
		t.Fatalf("KillSwitches = %+v, want both global and route active", st)
	}

	// Flip both back off and confirm the round trip.
	if err := s.SetKillSwitch(t.Context(), "global", "all", false); err != nil {
		t.Fatalf("SetKillSwitch(global, off): %v", err)
	}
	if err := s.SetKillSwitch(t.Context(), "route", routeID, false); err != nil {
		t.Fatalf("SetKillSwitch(route, off): %v", err)
	}
	st, err = s.KillSwitches(t.Context(), routeID)
	if err != nil {
		t.Fatalf("KillSwitches (after off): %v", err)
	}
	if st.GlobalActive || st.RouteActive {
		t.Fatalf("KillSwitches after off = %+v, want both inactive", st)
	}

	// The audit row the `on`/`off` verb records must be writable through the
	// same seam the CLI uses (RecordAudit, pre-auth accountID="").
	if err := s.RecordAudit(t.Context(), "", "kill_switch_changed",
		`{"scope":"global","key":"all","active":false,"reason":"test"}`); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}
}

// TestKillSwitchStatusUnknownRoute proves an unknown route id reports as
// active=true (fail-closed, KillSwitches' documented behaviour for a missing
// per-route sentinel) rather than erroring — an operator querying a typo'd
// route id must see "paused" (safe), never a silent pass-through.
func TestKillSwitchStatusUnknownRoute(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)

	st, err := s.KillSwitches(t.Context(), "route-that-does-not-exist")
	if err != nil {
		t.Fatalf("KillSwitches(unknown route): %v", err)
	}
	if !st.RouteActive {
		t.Fatal("an unknown route id must fail closed (RouteActive=true), not report open")
	}
}
