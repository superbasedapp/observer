package codex

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// updateTargetGolden rewrites testdata/target_golden.json. The committed
// file was captured before the checkout path seam (lane shr-worktree2,
// PT-39), so it pins that every fixture's targets stay byte-identical.
var updateTargetGolden = flag.Bool("update-target-golden", false, "rewrite testdata/target_golden.json")

// nondeterministicTargets lists the fixture rows whose target is a
// map-order pick, keyed "<fixture>\t<source event id>".
var nondeterministicTargets = map[string]string{
	"rollout-patch-apply-exec-namespace.jsonl\texec-13ec0715-713d-4942-9fe1-e4541968b8ab": "main.go|notes.txt",
}

// TestTargetGolden parses every codex rollout fixture and pins each tool
// event's Target.
func TestTargetGolden(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "testdata", "codex", "rollout-*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	sort.Strings(files)
	got := map[string][]string{}
	for _, f := range files {
		res, err := New().ParseSessionFile(context.Background(), f, 0)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var rows []string
		for _, ev := range res.ToolEvents {
			rows = append(rows, ev.SourceEventID+"\t"+ev.Target)
		}
		got[filepath.Base(f)] = rows
	}
	// patchApplyTargetFromChanges picks a map key, so a multi-file
	// patch_apply_end row's target varies between runs (pre-existing). Its
	// golden row lists the possible targets joined by "|"; a run matches
	// when it names one of them.
	for name, rows := range got {
		for i, r := range rows {
			id, target, _ := strings.Cut(r, "\t")
			if alts, ok := nondeterministicTargets[name+"\t"+id]; ok {
				for _, a := range strings.Split(alts, "|") {
					if a == target {
						rows[i] = id + "\t" + alts
					}
				}
			}
		}
	}
	compareTargetGolden(t, got)
}

func compareTargetGolden(t *testing.T, got map[string][]string) {
	t.Helper()
	// A relative fixture target resolves against the test's working
	// directory; spell it $CWD so the golden is host-independent.
	if wd, err := os.Getwd(); err == nil {
		wd = filepath.ToSlash(wd)
		for k, rows := range got {
			for i, r := range rows {
				rows[i] = strings.ReplaceAll(r, wd, "$CWD")
			}
			got[k] = rows
		}
	}
	body, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	path := filepath.Join("testdata", "target_golden.json")
	if *updateTargetGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (run with -update-target-golden)", err)
	}
	if strings.ReplaceAll(string(want), "\r\n", "\n") != string(body) {
		t.Errorf("targets drifted from the golden captured before the checkout path seam\n got: %s\nwant: %s", body, want)
	}
}
