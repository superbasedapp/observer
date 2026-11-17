package integration

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestTaskSeedCoversSeededLaunchers pins the task-seed table to the registry:
// every row of the table names a launchable tool; a tool whose launcher
// seeds a handover (LaunchSeeded) has a row, either a seed or a Note saying
// why it has none; a doc-assisted tool (its TUI takes no first prompt) has
// no seed.
func TestTaskSeedCoversSeededLaunchers(t *testing.T) {
	for tool, seed := range taskSeeds {
		c, ok := For(tool)
		if !ok || !c.Handoff.Launchable() {
			t.Errorf("task seed for %q, which is not a launchable registry row", tool)
			continue
		}
		if c.Handoff.Launch.Mode == LaunchDocAssisted && seed.Seeds() {
			t.Errorf("%s: doc-assisted launcher (no first-prompt seed) declares task seed %q", tool, seed.Kind)
		}
		if seed.Seeds() && seed.Note != "" {
			t.Errorf("%s: a seeded row carries a Note (%q); a Note explains a missing seed", tool, seed.Note)
		}
		if seed.Kind == TaskSeedFlag && !strings.HasPrefix(seed.Flag, "-") {
			t.Errorf("%s: flag seed %q is not a flag", tool, seed.Flag)
		}
		if seed.Kind != TaskSeedFlag && seed.Flag != "" {
			t.Errorf("%s: Flag %q set on a %q seed", tool, seed.Flag, seed.Kind)
		}
	}
	for _, c := range Capabilities() {
		if !c.Handoff.Launchable() || c.Handoff.Launch.Mode != LaunchSeeded {
			continue
		}
		seed, ok := taskSeeds[c.Tool]
		if !ok {
			t.Errorf("%s: seeded launcher with no task-seed row (add its seed, or a Note saying why it has none)", c.Tool)
			continue
		}
		if !seed.Seeds() && seed.Note == "" {
			t.Errorf("%s: seeded launcher with an empty task-seed row (no seed and no Note)", c.Tool)
		}
	}
}

// TestTaskSeedArgs is one case per kind and per refusal.
func TestTaskSeedArgs(t *testing.T) {
	model := []string{"--model", "m"}
	cases := []struct {
		name   string
		seed   TaskSeed
		args   []string
		prompt string
		want   []string
		err    bool
	}{
		{"leading", TaskSeed{Kind: TaskSeedLeadingPositional}, model, "Fix it", []string{"Fix it", "--model", "m"}, false},
		{"trailing", TaskSeed{Kind: TaskSeedTrailingPositional}, model, "Fix it", []string{"--model", "m", "Fix it"}, false},
		{"flag", TaskSeed{Kind: TaskSeedFlag, Flag: "-i"}, model, "Fix it", []string{"--model", "m", "-i", "Fix it"}, false},
		{"no args", TaskSeed{Kind: TaskSeedTrailingPositional}, nil, "Fix it", []string{"Fix it"}, false},
		{"multi-line", TaskSeed{Kind: TaskSeedTrailingPositional}, nil, "Fix\nit", []string{"Fix\nit"}, false},
		{"none", TaskSeed{}, model, "Fix it", nil, true},
		{"note only", TaskSeed{Note: "why"}, model, "Fix it", nil, true},
		{"flag without flag", TaskSeed{Kind: TaskSeedFlag}, model, "Fix it", nil, true},
		{"empty", TaskSeed{Kind: TaskSeedTrailingPositional}, model, "  \n", nil, true},
		{"dash", TaskSeed{Kind: TaskSeedTrailingPositional}, model, "--yolo", nil, true},
		{"nul", TaskSeed{Kind: TaskSeedTrailingPositional}, model, "a\x00b", nil, true},
		{"too long", TaskSeed{Kind: TaskSeedTrailingPositional}, model, strings.Repeat("a", MaxTaskPromptBytes+1), nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]string(nil), tc.args...)
			got, err := TaskSeedArgs(tc.seed, tc.args, tc.prompt)
			if tc.err {
				if !errors.Is(err, ErrTaskSeed) {
					t.Fatalf("err = %v, want ErrTaskSeed", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if !reflect.DeepEqual(tc.args, before) {
				t.Fatalf("args modified: %q", tc.args)
			}
		})
	}
}

// TestTaskSeedWire is the wire value per kind.
func TestTaskSeedWire(t *testing.T) {
	for seed, want := range map[TaskSeed]string{
		{}:                                 "none",
		{Note: "x"}:                        "none",
		{Kind: TaskSeedLeadingPositional}:  "leading_positional",
		{Kind: TaskSeedTrailingPositional}: "trailing_positional",
		{Kind: TaskSeedFlag, Flag: "-i"}:   "flag",
	} {
		if got := seed.Wire(); got != want {
			t.Errorf("%+v.Wire() = %q, want %q", seed, got, want)
		}
	}
}
