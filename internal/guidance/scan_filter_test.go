package guidance

import "testing"

// TestScanKindToolFiltersAndBlobIDs pins the S10-SKILLS additive options:
// Kinds/Tools restrict the pass to matching discovery rows (the Claude
// Code hook snapshots skills only), GitBlobIDs adds git blob ids for bodies
// the scan read, and the zero value of all three is the pre-arc scan.
func TestScanKindToolFiltersAndBlobIDs(t *testing.T) {
	t.Parallel()
	all := scanFixture(t, testOptions())
	var wantSkills int
	for _, f := range all.Files {
		if f.GitBlobOID != "" || f.GitBlobOIDLF != "" {
			t.Fatalf("default scan computed a blob id for %s", f.RelPath)
		}
		if f.Kind == KindSkill && f.Tool == "claude-code" {
			wantSkills++
		}
	}
	if wantSkills == 0 {
		t.Fatal("fixture has no claude-code skills; the filter test would be vacuous")
	}

	opts := testOptions()
	opts.Kinds = []Kind{KindSkill}
	opts.Tools = []string{"claude-code"}
	opts.GitBlobIDs = true
	got := scanFixture(t, opts)
	if len(got.Files) != wantSkills {
		t.Fatalf("filtered scan = %d files, want %d claude-code skills", len(got.Files), wantSkills)
	}
	for _, f := range got.Files {
		if f.Kind != KindSkill || f.Tool != "claude-code" {
			t.Errorf("filter leaked %s/%s %s", f.Tool, f.Kind, f.RelPath)
		}
		if f.ParseErr == "" && len(f.GitBlobOID) != 40 {
			t.Errorf("%s: GitBlobOID = %q, want a 40-hex blob id", f.RelPath, f.GitBlobOID)
		}
	}
}
