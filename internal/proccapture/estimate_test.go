package proccapture

import (
	"fmt"
	"testing"
	"time"
)

// TestEstimate pins the shape and direction of the volume projection.
func TestEstimate(t *testing.T) {
	var h []RunFacts
	h = append(h, RunFacts{ProcessKey: "root", SessionID: "s", AttributionSource: "bridge", ExeBasename: "claude", Time: t0})
	h = append(h, RunFacts{ProcessKey: "sh", ParentKey: "root", SessionID: "s", AttributionSource: "inherited", ExeBasename: "bash", Time: t0.Add(time.Second)})
	for i := range 1000 {
		h = append(h, RunFacts{
			ProcessKey: fmt.Sprint("c", i), ParentKey: "sh", SessionID: "s", AttributionSource: "inherited",
			ExeBasename: "compile", Argv: "compile -p x", Time: t0.Add(time.Duration(i) * time.Second).Add(24 * time.Hour * time.Duration(i%2)),
			Ended: true, AliveFor: time.Second, MetricBytes: 200,
		})
	}
	h = append(h, RunFacts{ProcessKey: "u1", ExeBasename: "x", AttributionSource: "none", HeldForCorrelation: true, Time: t0})

	off := DefaultConfig()
	off.Enabled = false
	proposed := DefaultConfig()
	est := Estimate(h, off, proposed)
	if est.Basis.Days != 2 || est.Basis.Sessions != 1 || est.Basis.ObservedRows != len(h) {
		t.Fatalf("basis %+v", est.Basis)
	}
	if est.Current.RowsPerDay != int64(len(h))/2 && est.Current.RowsPerDay != (int64(len(h))+1)/2 {
		t.Fatalf("current rows/day %d", est.Current.RowsPerDay)
	}
	if est.Projected.RowsPerDay >= est.Current.RowsPerDay || est.Projected.BytesPerDay >= est.Current.BytesPerDay {
		t.Fatalf("budget did not reduce volume: %+v vs %+v", est.Projected, est.Current)
	}
	if est.Projected.RollupRowsPerDay == 0 || est.Projected.OrgRowsPerDay == 0 {
		t.Fatalf("projection %+v", est.Projected)
	}
	if len(est.BySetting) != 1 || est.BySetting[0].Key != "enabled" || est.BySetting[0].RowsPerDay != est.Projected.RowsPerDay {
		t.Fatalf("by_setting %+v", est.BySetting)
	}

	// One key changed: the breakdown names exactly that key.
	tighter := DefaultConfig()
	tighter.PerToolCall = 10
	est2 := Estimate(h, DefaultConfig(), tighter)
	if len(est2.BySetting) != 1 || est2.BySetting[0].Key != "budget.per_tool_call" || est2.BySetting[0].RowsPerDay >= est2.Current.RowsPerDay {
		t.Fatalf("by_setting %+v current %+v", est2.BySetting, est2.Current)
	}
	// No change: no breakdown rows, current == projected.
	est3 := Estimate(h, DefaultConfig(), DefaultConfig())
	if len(est3.BySetting) != 0 || est3.Current.RowsPerDay != est3.Projected.RowsPerDay {
		t.Fatalf("no-change estimate %+v", est3)
	}
	// The ring threshold drops metric bytes from short runs.
	f := RunFacts{MetricBytes: 200, AliveFor: time.Second}
	if RowBytes(f, DefaultConfig()) >= RowBytes(f, off) {
		t.Fatal("ring threshold did not shrink a short run")
	}
}

// TestConfigKeysRoundTrip pins that every ConfigKeys key Gets and Sets, and
// that an unknown key or a bad mode is refused.
func TestConfigKeysRoundTrip(t *testing.T) {
	c := DefaultConfig()
	for _, k := range ConfigKeys {
		v, ok := c.Get(k)
		if !ok {
			t.Fatalf("Get(%s) unknown", k)
		}
		var d Config
		if err := d.Set(k, v); err != nil {
			t.Fatalf("Set(%s, %q): %v", k, v, err)
		}
		if got, _ := d.Get(k); got != v {
			t.Fatalf("round trip %s: %q != %q", k, got, v)
		}
	}
	if err := c.Set("nope", "1"); err == nil {
		t.Fatal("unknown key accepted")
	}
	if err := c.Set("unattributed.mode", "keep"); err == nil {
		t.Fatal("bad mode accepted")
	}
	if err := c.Set("services.extra_basenames", " a.exe, ,b "); err != nil || len(c.ExtraServiceBasenames) != 2 {
		t.Fatalf("list parse: %v %v", err, c.ExtraServiceBasenames)
	}
}

// TestRollupUnattributed pins the machine-rollup grouping.
func TestRollupUnattributed(t *testing.T) {
	rows := []RunFacts{
		{ProcessKey: "a", ExeBasename: "git", Argv: "git status", Time: t0},
		{ProcessKey: "b", ExeBasename: "git", Argv: "git status", Time: t0.Add(10 * time.Second)},
		{ProcessKey: "c", ExeBasename: "git", Argv: "git status", Time: t0.Add(2 * time.Minute)},
	}
	rs := RollupUnattributed(rows, DefaultConfig())
	if len(rs) != 2 || rs[0].Count != 2 || rs[0].Key.Kind != GroupUnattributed || rs[0].Key.SessionID != "" {
		t.Fatalf("rollups %+v", rs)
	}
}
