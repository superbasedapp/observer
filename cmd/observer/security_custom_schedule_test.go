//go:build !sbo_omit_security && !sbo_omit_security_scan_custom

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestCustomScheduleLoopIsOptIn: an install with no [components] block
// starts no schedule loop (the component is opt-in), and a selected one
// starts it as its own moduleGates row.
func TestCustomScheduleLoopIsOptIn(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	legacy := newGatedGroup(namedGroup{}, componentstate.Legacy(), &out)
	// namedGroup{} has no errgroup: a loop that started here would panic.
	startCustomScanSchedule(context.Background(), legacy, "", componentstate.Legacy())
	if len(legacy.skipped) != 0 || out.Len() != 0 {
		t.Fatalf("legacy: skipped %v out %q", legacy.skipped, out.String())
	}
	added := componentstate.Resolve(config.ComponentsConfig{Add: []string{customScanComponent}}, nil)
	if !loopAllowed(added, "security.custom.schedule") {
		t.Fatal("selected: the schedule loop is not allowed to start")
	}
	removed := componentstate.Resolve(config.ComponentsConfig{Remove: []string{customScanComponent}}, nil)
	if loopAllowed(removed, "security.custom.schedule") {
		t.Fatal("removed: the schedule loop may still start")
	}
}

// TestCustomSchedulePassOffOpensNothing: with schedule_hours at its
// default 0 a pass reads the config and stops: no database, no service,
// no run.
func TestCustomSchedulePassOffOpensNothing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[security.custom]\nschedule_hours = 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.Custom.ScheduleHours != 0 || !cfg.Security.Custom.PauseOnBattery {
		t.Fatalf("defaults: %+v", cfg.Security.Custom)
	}
	l := &customScheduleLoop{configPath: cfgPath, snap: componentstate.Resolve(config.ComponentsConfig{Add: []string{customScanComponent}}, nil)}
	defer l.close()
	l.pass(context.Background())
	if l.svc != nil || l.db != nil {
		t.Fatal("a pass with the schedule off opened the database")
	}
}
