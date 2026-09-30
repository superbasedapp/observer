package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestNewSkillScanAfterScanGate pins the [projects].skill_history gate: off
// means the commit scanner gets a nil AfterScan (its pre-arc behaviour),
// on means a live callback.
func TestNewSkillScanAfterScanGate(t *testing.T) {
	st, _ := openTestStore(t)
	if cb := newSkillScanAfterScan(st, config.ProjectsConfig{SkillHistory: false}, nil); cb != nil {
		t.Error("skill_history=false still produced an AfterScan callback")
	}
	if cb := newSkillScanAfterScan(st, config.ProjectsConfig{SkillHistory: true}, nil); cb == nil {
		t.Error("skill_history=true produced no AfterScan callback")
	}
}
