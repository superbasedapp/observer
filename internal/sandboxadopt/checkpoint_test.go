package sandboxadopt

import "testing"

func goodCP() CheckpointFacts {
	return CheckpointFacts{
		UserAction: true, Engine: EngineFacts{Engine: EnginePodman, Mode: ModeRootful, Conmon: true},
		Runtime: "crun", CRIUVersion: "3.17.1", Running: true, StateDirPerm: 0o700, StateDirOwned: true,
	}
}

// TestCheckpointRefusals has one case per refusal row and engine mode.
func TestCheckpointRefusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		edit func(*CheckpointFacts)
	}{
		{"automatic", func(f *CheckpointFacts) { f.UserAction = false }},
		{"docker rootful", func(f *CheckpointFacts) {
			f.Engine = EngineFacts{Engine: EngineDocker, Mode: ModeRootful, LiveRestore: true}
		}},
		{"docker rootless", func(f *CheckpointFacts) { f.Engine = EngineFacts{Engine: EngineDocker, Mode: ModeRootless} }},
		{"unknown engine", func(f *CheckpointFacts) { f.Engine = EngineFacts{Engine: "other", Mode: ModeRootful} }},
		{"rootless podman", func(f *CheckpointFacts) { f.Engine.Mode = ModeRootless }},
		{"runsc", func(f *CheckpointFacts) { f.Runtime = "runsc" }},
		{"no criu", func(f *CheckpointFacts) { f.CRIUVersion = "" }},
		{"old criu", func(f *CheckpointFacts) { f.CRIUVersion = "3.10" }},
		{"not running", func(f *CheckpointFacts) { f.Running = false }},
		{"state dir group readable", func(f *CheckpointFacts) { f.StateDirPerm = 0o750 }},
		{"state dir not owned", func(f *CheckpointFacts) { f.StateDirOwned = false }},
	}
	if len(cases) < len(checkpointRules) {
		t.Fatalf("%d cases for %d rows", len(cases), len(checkpointRules))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := goodCP()
			c.edit(&f)
			_, r := PlanCheckpoint("run1", f)
			if r == nil || r.Code != CodeCheckpointUnsupported || r.Reason == "" {
				t.Fatalf("PlanCheckpoint = %+v, want checkpoint_unsupported with why", r)
			}
		})
	}
}

func TestCheckpointPlan(t *testing.T) {
	t.Parallel()
	p, r := PlanCheckpoint("run1", goodCP())
	if r != nil || p.ExportName != "run1"+ExportSuffix || p.CapBytes != DefaultExportCapBytes {
		t.Fatalf("PlanCheckpoint = %+v %v", p, r)
	}
	f := goodCP()
	f.CapBytes = 10
	if p, _ := PlanCheckpoint("run1", f); p.CapBytes != 10 {
		t.Fatalf("cap = %d", p.CapBytes)
	}
}

func TestExportVerdict(t *testing.T) {
	t.Parallel()
	if ExportVerdict(5, 10) != nil {
		t.Fatal("an export under the cap was refused")
	}
	if ExportVerdict(11, 10) == nil || ExportVerdict(0, 10) == nil {
		t.Fatal("an export over the cap or empty was accepted")
	}
}

func TestRestore(t *testing.T) {
	t.Parallel()
	ok := RestoreFacts{Checkpoint: goodCP(), ExportOwned: true, SocketDirIntact: true, ReadBackOK: true}
	if PlanRestore(ok) != nil || RestoredVerdict(ok) != nil {
		t.Fatal("a sound restore was refused")
	}
	rootless := ok
	rootless.Checkpoint.Engine.Mode = ModeRootless
	if r := PlanRestore(rootless); r == nil || r.Code != CodeCheckpointUnsupported {
		t.Fatalf("rootless restore = %v", r)
	}
	notOwned := ok
	notOwned.ExportOwned = false
	if PlanRestore(notOwned) == nil {
		t.Fatal("a restore from a foreign export was accepted")
	}
	lost := ok
	lost.SocketDirIntact = false
	if r := RestoredVerdict(lost); r == nil || r.Code != CodeRestoreLostCapture {
		t.Fatalf("lost relay = %v", r)
	}
	below := ok
	below.ReadBackOK = false
	if r := RestoredVerdict(below); r == nil || r.Code != CodeBuiltBelowPlan {
		t.Fatalf("below plan = %v", r)
	}
}

func TestParseCRIUVersion(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"Version: 3.17.1\n":           "3.17.1",
		"Version: 4.0\nGitID: v4.0\n": "4.0",
		"criu: command not found":     "",
		"":                            "",
		"Version: banana\n":           "",
	}
	for in, want := range cases {
		if got := ParseCRIUVersion(in); got != want {
			t.Fatalf("ParseCRIUVersion(%q) = %q, want %q", in, got, want)
		}
	}
	if !versionAtLeast("3.11", MinCRIU) || versionAtLeast("3.10.9", MinCRIU) || !versionAtLeast("4", MinCRIU) {
		t.Fatal("versionAtLeast")
	}
}
