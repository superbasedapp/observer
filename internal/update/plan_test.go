package update

import (
	"strings"
	"testing"
	"time"
)

// selfApplyDetection is the only detection that permits an apply.
func selfApplyDetection() Detection {
	return Detection{Method: MethodBinary, SelfApply: true, Rule: "standalone-writable"}
}

// planInput is the happy-path input every row mutates.
func planInput() PlanInput {
	return PlanInput{
		Installed: Installed{
			Version:       "v1.32.0",
			SchemaVersion: 104,
			ExecPath:      "/home/dev/.local/bin/observer",
			Detection:     selfApplyDetection(),
		},
		Manifest:            baseManifest(),
		Artifact:            linuxArtifact(),
		TargetSchemaVersion: 105,
		StateDir:            "/home/dev/.observer/updates",
		Now:                 time.Date(2026, 9, 15, 3, 0, 0, 0, time.UTC),
	}
}

// TestBuildApplyPlan is the plan table: paths, the snapshot decision,
// and every gate-0 defer.
func TestBuildApplyPlan(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*PlanInput)
		wantErr bool
		check   func(t *testing.T, p ApplyPlan)
	}{
		{
			name:   "a migrating apply plans a DB snapshot",
			mutate: func(*PlanInput) {},
			check: func(t *testing.T, p ApplyPlan) {
				if !p.AdvancesSchema || !p.NeedsDBSnapshot {
					t.Error("104 -> 105 must advance the schema and require a snapshot")
				}
				if p.DBBackupPath == "" {
					t.Error("no snapshot path was planned")
				}
				if p.Blocked {
					t.Error("plan is blocked on the happy path")
				}
			},
		},
		{
			name: "a non-migrating apply plans NO snapshot",
			mutate: func(in *PlanInput) {
				in.TargetSchemaVersion = 104
			},
			check: func(t *testing.T, p ApplyPlan) {
				if p.AdvancesSchema || p.NeedsDBSnapshot {
					t.Error("104 -> 104 must not require a snapshot")
				}
				if p.DBBackupPath != "" {
					t.Errorf("snapshot path %q planned for a non-migrating apply", p.DBBackupPath)
				}
			},
		},
		{
			name: "an UNKNOWN target schema is treated as migrating (the conservative direction)",
			mutate: func(in *PlanInput) {
				in.TargetSchemaVersion = 0
			},
			check: func(t *testing.T, p ApplyPlan) {
				if !p.NeedsDBSnapshot {
					t.Error("an unknown target schema must still snapshot: a missing snapshot is a brick, a spare one is disk")
				}
			},
		},
		{
			// The staged binary is the ONE path that is NOT under state_dir:
			// the swap is os.Rename(staged, exePath) and rename cannot cross a
			// filesystem, so a node whose binary lives on another device than
			// $HOME would fail every apply with EXDEV. Staging beside the
			// target removes the question.
			name:   "the archive and rollback paths are under state_dir; the staged binary sits beside the executable",
			mutate: func(*PlanInput) {},
			check: func(t *testing.T, p ApplyPlan) {
				want := map[string]string{
					"download": "/home/dev/.observer/updates/v1.33.0/observer-v1.33.0-linux-x64.tar.gz",
					"partial":  "/home/dev/.observer/updates/v1.33.0/observer-v1.33.0-linux-x64.tar.gz.part",
					"staged":   "/home/dev/.local/bin/.observer-staged-v1.33.0",
					"rollback": "/home/dev/.observer/updates/rollback/observer-v1.32.0",
					"backup":   "/home/dev/.observer/updates/preupgrade-v1.32.0.db",
				}
				got := map[string]string{
					"download": p.DownloadPath, "partial": p.PartialPath, "staged": p.StagedBinaryPath,
					"rollback": p.RollbackBinaryPath, "backup": p.DBBackupPath,
				}
				for k, w := range want {
					if got[k] != w {
						t.Errorf("%s path = %q, want %q", k, got[k], w)
					}
				}
			},
		},
		{
			name: "a windows target stages observer.exe",
			mutate: func(in *PlanInput) {
				in.Artifact = windowsArtifact()
			},
			check: func(t *testing.T, p ApplyPlan) {
				if !strings.HasSuffix(p.StagedBinaryPath, ".exe") {
					t.Errorf("staged binary = %q, want an .exe", p.StagedBinaryPath)
				}
				if p.ArchiveType != ArchiveZip {
					t.Errorf("archive type = %q", p.ArchiveType)
				}
			},
		},
		{
			name:   "expected hashes come from the manifest, never from anywhere else",
			mutate: func(*PlanInput) {},
			check: func(t *testing.T, p ApplyPlan) {
				if p.ExpectedArchiveSHA256 != linuxArtifact().SHA256 ||
					p.ExpectedMemberSHA256 != linuxArtifact().MemberSHA256 {
					t.Error("plan hashes drifted from the manifest")
				}
				if p.MaxBytes != linuxArtifact().SizeBytes {
					t.Errorf("download ceiling = %d, want the declared size", p.MaxBytes)
				}
			},
		},
		{
			name: "an npm-owned binary is BLOCKED with advice, not failed",
			mutate: func(in *PlanInput) {
				in.Installed.Detection = Detection{
					Method: MethodNPM, Rule: "npm-package-path",
					Advice: "npm i -g @superbased/observer@<version>",
				}
			},
			check: func(t *testing.T, p ApplyPlan) {
				if !p.Blocked || p.State != StateBlocked || p.Reason != ReasonInstallMethod {
					t.Errorf("plan = %+v, want blocked{install_method}", p)
				}
				if !strings.Contains(p.Advice, "npm i -g @superbased/observer@1.33.0") {
					t.Errorf("advice = %q, want the expanded npm command", p.Advice)
				}
			},
		},
		{
			name: "a read-only binary blocks with the narrower reason",
			mutate: func(in *PlanInput) {
				in.Installed.Detection = Detection{
					Method: MethodBinaryReadOnly, Rule: "standalone-readonly",
					Advice: "the binary at /usr/local/bin/observer is not writable by this user",
				}
			},
			check: func(t *testing.T, p ApplyPlan) {
				if p.Reason != ReasonNotWritable {
					t.Errorf("reason = %q, want %q", p.Reason, ReasonNotWritable)
				}
			},
		},
		{
			name: "outside the maintenance window the apply DEFERS and stays available",
			mutate: func(in *PlanInput) {
				w, err := ParseWindow("02:00-05:00")
				if err != nil {
					t.Fatalf("ParseWindow: %v", err)
				}
				in.Window = w
				in.Now = time.Date(2026, 9, 15, 13, 0, 0, 0, time.UTC)
			},
			check: func(t *testing.T, p ApplyPlan) {
				if !p.Blocked || p.Reason != ReasonWindow {
					t.Errorf("plan = %+v, want a window defer", p)
				}
				if p.State != StateAvailable {
					t.Errorf("state = %q — a closed window is a defer, not a block on the node", p.State)
				}
				if !strings.Contains(p.Advice, "next open") {
					t.Errorf("advice = %q, want the next window opening", p.Advice)
				}
			},
		},
		{
			name: "inside the maintenance window the apply proceeds",
			mutate: func(in *PlanInput) {
				w, _ := ParseWindow("02:00-05:00")
				in.Window = w
				in.Now = time.Date(2026, 9, 15, 3, 30, 0, 0, time.UTC)
			},
			check: func(t *testing.T, p ApplyPlan) {
				if p.Blocked {
					t.Errorf("plan = %+v, want an unblocked apply", p)
				}
			},
		},
		{
			name: "--force ignores the window but not the install method",
			mutate: func(in *PlanInput) {
				w, _ := ParseWindow("02:00-05:00")
				in.Window = w
				in.Now = time.Date(2026, 9, 15, 13, 0, 0, 0, time.UTC)
				in.Force = true
			},
			check: func(t *testing.T, p ApplyPlan) {
				if p.Blocked {
					t.Error("--force should carry the plan past a closed window")
				}
			},
		},
		{
			name: "an artifact that is not part of the manifest is a programming error, not a plan",
			mutate: func(in *PlanInput) {
				a := linuxArtifact()
				a.Arch = "riscv64"
				in.Artifact = a
			},
			wantErr: true,
		},
		{
			name: "an empty state_dir is refused",
			mutate: func(in *PlanInput) {
				in.StateDir = ""
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := planInput()
			tc.mutate(&in)
			p, err := BuildApplyPlan(in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildApplyPlan: %v", err)
			}
			if len(p.Steps) == 0 {
				t.Error("plan carries no steps to print for --dry-run")
			}
			tc.check(t, p)
		})
	}
}

// TestPlanStepsNameTheSnapshotHonestly checks the --dry-run text says
// which of the two migration cases the operator is in — the plan
// requires --dry-run to print "whether a migration, and therefore a DB
// snapshot, is involved".
func TestPlanStepsNameTheSnapshotHonestly(t *testing.T) {
	in := planInput()
	p, err := BuildApplyPlan(in)
	if err != nil {
		t.Fatalf("BuildApplyPlan: %v", err)
	}
	joined := strings.Join(p.Steps, "\n")
	if !strings.Contains(joined, "snapshot the database") {
		t.Errorf("migrating plan does not mention the snapshot:\n%s", joined)
	}
	in.TargetSchemaVersion = 104
	p, err = BuildApplyPlan(in)
	if err != nil {
		t.Fatalf("BuildApplyPlan: %v", err)
	}
	joined = strings.Join(p.Steps, "\n")
	if !strings.Contains(joined, "no database snapshot") {
		t.Errorf("non-migrating plan does not say so:\n%s", joined)
	}
}

// TestDecideRollback is the §3.7 step 8 decision table.
func TestDecideRollback(t *testing.T) {
	cases := []struct {
		name string
		in   RollbackInput
		want RollbackDecision
	}{
		{
			name: "no previous binary: refuse, leave it for an operator",
			in:   RollbackInput{State: StateApplying, HasPreviousBinary: false},
			want: RollbackDecision{Refuse: true, State: StateFailed, ErrorClass: ErrorSwap},
		},
		{
			name: "schema advanced with a snapshot: restore both, and say what is discarded",
			in: RollbackInput{
				State: StateApplying, HasPreviousBinary: true,
				PreviousSchemaVersion: 104, CurrentSchemaVersion: 105, HasDBBackup: true,
			},
			want: RollbackDecision{
				RestoreBinary: true, RestoreDB: true, DiscardsDataWindow: true,
				State: StateRolledBack, ErrorClass: ErrorHealthcheck,
			},
		},
		{
			name: "schema advanced with NO snapshot: refuse rather than corrupt",
			in: RollbackInput{
				State: StateApplying, HasPreviousBinary: true,
				PreviousSchemaVersion: 104, CurrentSchemaVersion: 105, HasDBBackup: false,
			},
			want: RollbackDecision{Refuse: true, State: StateFailed, ErrorClass: ErrorHealthcheck},
		},
		{
			name: "same schema: restore the binary only, database untouched",
			in: RollbackInput{
				State: StateApplying, HasPreviousBinary: true,
				PreviousSchemaVersion: 105, CurrentSchemaVersion: 105, HasDBBackup: true,
			},
			want: RollbackDecision{RestoreBinary: true, State: StateRolledBack, ErrorClass: ErrorHealthcheck},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DecideRollback(tc.in)
			if got.RestoreBinary != tc.want.RestoreBinary ||
				got.RestoreDB != tc.want.RestoreDB ||
				got.Refuse != tc.want.Refuse ||
				got.State != tc.want.State ||
				got.ErrorClass != tc.want.ErrorClass ||
				got.DiscardsDataWindow != tc.want.DiscardsDataWindow {
				t.Fatalf("DecideRollback = %+v, want %+v", got, tc.want)
			}
			if got.Reason == "" {
				t.Error("every rollback decision must carry a reason an operator can read")
			}
		})
	}
}

// TestWindow covers the maintenance-window helper, including the
// midnight wrap a fleet across timezones will hit.
func TestWindow(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 9, 15, h, m, 0, 0, time.UTC) }

	if _, err := ParseWindow("bad"); err == nil {
		t.Error("ParseWindow accepted a malformed window")
	}
	for _, bad := range []string{"25:00-02:00", "02:60-03:00", "02:00-02:00", "0200-0300"} {
		if _, err := ParseWindow(bad); err == nil {
			t.Errorf("ParseWindow(%q) accepted an invalid window", bad)
		}
	}
	empty, err := ParseWindow("")
	if err != nil {
		t.Fatalf("ParseWindow(\"\"): %v", err)
	}
	if empty.IsSet() || !empty.Permits(at(13, 0)) || empty.String() != "any time" {
		t.Error("an empty window must permit any time")
	}

	w, err := ParseWindow("02:00-05:00")
	if err != nil {
		t.Fatalf("ParseWindow: %v", err)
	}
	cases := []struct {
		h, m int
		want bool
	}{{1, 59, false}, {2, 0, true}, {4, 59, true}, {5, 0, false}, {13, 0, false}}
	for _, c := range cases {
		if got := w.Permits(at(c.h, c.m)); got != c.want {
			t.Errorf("02:00-05:00 permits %02d:%02d = %v, want %v", c.h, c.m, got, c.want)
		}
	}
	if next := w.NextOpen(at(13, 0)); next.Day() != 16 || next.Hour() != 2 {
		t.Errorf("NextOpen after the window = %s, want tomorrow 02:00", next)
	}
	if next := w.NextOpen(at(1, 0)); next.Day() != 15 || next.Hour() != 2 {
		t.Errorf("NextOpen before the window = %s, want today 02:00", next)
	}
	if next := w.NextOpen(at(3, 0)); !next.Equal(at(3, 0)) {
		t.Errorf("NextOpen inside the window = %s, want the given time", next)
	}

	wrap, err := ParseWindow("22:00-02:00")
	if err != nil {
		t.Fatalf("ParseWindow: %v", err)
	}
	for _, c := range []struct {
		h    int
		want bool
	}{{21, false}, {22, true}, {23, true}, {0, true}, {1, true}, {2, false}, {12, false}} {
		if got := wrap.Permits(at(c.h, 0)); got != c.want {
			t.Errorf("22:00-02:00 permits %02d:00 = %v, want %v", c.h, got, c.want)
		}
	}
}
