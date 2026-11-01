package invariant

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

// workflow_schedule_test.go pins the operator ruling of 2026-10-20: no
// GitHub Actions workflow runs on a schedule.
//
// "We can't have daily or weekly scheduled workflows using GitHub Actions.
// That's probably why we're losing money." CI runs are paid for, so they
// happen only for a public version release (re-enabled by hand for it, see
// docs/release-runbook.md step 3e); demos and other work build locally or
// in cloud sessions. The nightly ci / ci-private runs, the weekly
// perf-smoke run and the daily website-deploy re-render were removed on
// that date. A `schedule:` trigger in any .github/workflows file is red
// here, naming the file, so one cannot quietly come back.

// workflowSchedule reports whether a workflow document declares a schedule
// trigger under its top-level `on:` key, in any of the three shapes GitHub
// accepts: a scalar (`on: schedule`), a sequence (`on: [push, schedule]`)
// or a mapping (`on: {schedule: [...]}`). Only the top-level `on:` counts;
// a `schedule` string anywhere else (an expression, a comment, a job key)
// is not a trigger.
func workflowSchedule(src []byte) (bool, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return false, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return false, nil
	}
	top := doc.Content[0]
	if top.Kind != yaml.MappingNode {
		return false, nil
	}
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value != "on" {
			continue
		}
		on := top.Content[i+1]
		switch on.Kind {
		case yaml.ScalarNode:
			if on.Value == "schedule" {
				return true, nil
			}
		case yaml.SequenceNode:
			for _, ev := range on.Content {
				if ev.Kind == yaml.ScalarNode && ev.Value == "schedule" {
					return true, nil
				}
			}
		case yaml.MappingNode:
			for j := 0; j+1 < len(on.Content); j += 2 {
				if on.Content[j].Value == "schedule" {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// TestWorkflowScheduleDetector pins workflowSchedule itself, one row per
// trigger shape, so the repo-wide check below cannot pass by not looking.
func TestWorkflowScheduleDetector(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"mapping with schedule", "on:\n  push: {}\n  schedule:\n    - cron: '17 3 * * *'\n", true},
		{"mapping schedule only", "on:\n  schedule:\n    - cron: '0 0 * * 1'\njobs: {}\n", true},
		{"sequence with schedule", "on: [push, schedule]\n", true},
		{"scalar schedule", "on: schedule\n", true},
		{"quoted on key", "\"on\":\n  schedule:\n    - cron: '0 0 * * *'\n", true},
		{"push and dispatch only", "on:\n  push:\n    branches: [main]\n  workflow_dispatch: {}\n", false},
		{"sequence without schedule", "on: [push, pull_request]\n", false},
		{"schedule only in an expression", "on:\n  workflow_dispatch: {}\njobs:\n  a:\n    if: github.event_name != 'schedule'\n", false},
		{"schedule as a job name", "on:\n  push: {}\njobs:\n  schedule:\n    runs-on: ubuntu-latest\n", false},
		{"schedule only in a comment", "on:\n  # schedule: removed\n  workflow_dispatch: {}\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := workflowSchedule([]byte(tc.src))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got != tc.want {
				t.Fatalf("workflowSchedule = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWorkflowScheduleNone fails, naming the file, when any workflow under
// .github/workflows declares a schedule trigger.
func TestWorkflowScheduleNone(t *testing.T) {
	dir := filepath.Join(repoRoot(t), ".github", "workflows")
	var files []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			t.Fatalf("glob %s: %v", pat, err)
		}
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Skipf("no workflows under %s (public tree without .github?)", dir)
	}
	sort.Strings(files)
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		scheduled, err := workflowSchedule(src)
		if err != nil {
			t.Errorf("%s: not valid YAML: %v", filepath.Base(f), err)
			continue
		}
		if scheduled {
			t.Errorf("%s declares a schedule trigger: no GitHub Actions workflow may run on a schedule (operator ruling 2026-10-20); remove it and refresh by hand", filepath.Base(f))
		}
	}
}
