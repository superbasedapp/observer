package secassess

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Tests of the retest scorer (scoreretest_test.go): the score of labels against
// the fixture's truth, the earlier run's match of its findings, and reading a
// live run directory.

// retestEarlier is the earlier run's score in the tests below: F-1 and F-2 took
// the seeded flaws F01 and F02, F-3 reported a decoy, F-4 was near no anchor.
func retestEarlier() scPenScore {
	return scPenScore{
		Taken:      map[string]string{"F-1": "F01", "F-2": "F02"},
		DecoyHits:  []scPenHit{{Finding: "F-3", Key: "D01", Why: "reported a near miss as a weakness"}},
		Unscored:   []scPenHit{{Finding: "F-4", Why: "near no anchor of the key"}},
		Incidental: nil,
	}
}

// rtResultOf is a validated retest holding the given labels (finding, result,
// evidence state).
func rtResultOf(rs ...[3]string) Result {
	doc := &RetestDoc{}
	for _, r := range rs {
		doc.Results = append(doc.Results, RTResult{Finding: r[0], Result: r[1], EvidenceState: EvidenceState(r[2])})
	}
	return Result{RT: doc, Report: Report{State: ValidationValid}}
}

func TestScoreRetestRows(t *testing.T) {
	cases := []struct {
		name  string
		asked []string
		res   Result
		want  scRetestScore
	}{
		{
			name: "every seeded weakness read as reproduced, one of them backed", asked: []string{"F-1", "F-2"},
			res:  rtResultOf([3]string{"F-1", RetestReproduced, "logged"}, [3]string{"F-2", RetestReproduced, "unlogged"}),
			want: scRetestScore{Asked: 2, Labelled: 2, Seeded: 2, Reproduced: []string{"F01", "F02"}, Backed: 1, Recall: 1},
		},
		{
			name: "a not reproduced on a seeded weakness is a miss", asked: []string{"F-1", "F-2"},
			res:  rtResultOf([3]string{"F-1", RetestReproduced, ""}, [3]string{"F-2", RetestNotReproduced, "logged"}),
			want: scRetestScore{Asked: 2, Labelled: 2, Seeded: 2, Reproduced: []string{"F01"}, NotReproduced: []string{"F02"}, Recall: 0.5},
		},
		{
			name: "inconclusive is no answer, not a miss", asked: []string{"F-1", "F-2"},
			res:  rtResultOf([3]string{"F-1", RetestInconclusive, ""}, [3]string{"F-2", RetestReproduced, ""}),
			want: scRetestScore{Asked: 2, Labelled: 2, Seeded: 2, Reproduced: []string{"F02"}, Inconclusive: []string{"F01"}, Recall: 0.5},
		},
		{
			name: "a finding the earlier run took for a decoy or no flaw is listed, never scored", asked: []string{"F-1", "F-3", "F-4"},
			res: rtResultOf([3]string{"F-1", RetestReproduced, ""}, [3]string{"F-3", RetestReproduced, ""}, [3]string{"F-4", RetestNotReproduced, ""}),
			want: scRetestScore{
				Asked: 3, Labelled: 3, Seeded: 1, Reproduced: []string{"F01"}, Recall: 1,
				Unscored: []scPenHit{
					{Finding: "F-3", Key: "D01", Why: "reported a near miss as a weakness; the retest labelled it reproduced"},
					{Finding: "F-4", Why: "near no anchor of the key; the retest labelled it not_reproduced"},
				},
			},
		},
		{
			name: "a finding asked for with no result is named", asked: []string{"F-2", "F-1"},
			res:  rtResultOf([3]string{"F-1", RetestReproduced, ""}),
			want: scRetestScore{Asked: 2, Labelled: 1, Seeded: 1, Reproduced: []string{"F01"}, Unlabelled: []string{"F-2"}, Recall: 1},
		},
		{
			name: "a finding the earlier score does not list is still listed", asked: []string{"F-9"},
			res: rtResultOf([3]string{"F-9", RetestReproduced, ""}),
			want: scRetestScore{
				Asked: 1, Labelled: 1,
				Unscored: []scPenHit{{Finding: "F-9", Why: "the earlier run's score does not list it; the retest labelled it reproduced"}},
			},
		},
		{
			name: "a file the validator refused scores nothing and names every finding unlabelled", asked: []string{"F-1", "F-2"},
			res:  Result{Report: Report{State: ValidationInvalid, Fatal: "bad_shape"}},
			want: scRetestScore{Asked: 2, Unlabelled: []string{"F-1", "F-2"}, Validator: scValidator{State: ValidationInvalid, Fatal: "bad_shape"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scoreRetest(retestEarlier(), c.asked, c.res)
			if c.want.Validator.State == "" {
				c.want.Validator = scValidator{State: ValidationValid}
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
			lines := strings.Join(got.Lines(), "\n")
			for _, must := range []string{"retest:", "reproduced:", "not reproduced (a miss", "inconclusive (no answer)", "asked for with no result", "validator:"} {
				if !strings.Contains(lines, must) {
					t.Errorf("the account lacks %q:\n%s", must, lines)
				}
			}
		})
	}
}

// ---- reading a live run directory ----

const retestRunID = "0123456789abcdef"

// retestProject builds a project on disk holding the fixture's application at
// its root and the earlier run (the golden file of variant) in its run folder.
func retestProject(t *testing.T, fixture, variant string) (project, earlierDir string) {
	t.Helper()
	project = t.TempDir()
	app := filepath.Join(fixture, "app")
	err := filepath.WalkDir(app, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(app, p)
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		dst := filepath.Join(project, rel)
		if merr := os.MkdirAll(filepath.Dir(dst), 0o755); merr != nil {
			return merr
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	earlierDir = filepath.Join(project, ".observer", "assessments", "GOLDEN")
	if err := os.MkdirAll(earlierDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(earlierDir, "assessment.json"), scGolden(t, fixture, "pentest", variant), 0o644); err != nil {
		t.Fatal(err)
	}
	return project, earlierDir
}

// writeRetestRun writes a retest run folder next to the earlier run: the
// retest's file labelling each finding with the given result, the helper's
// settings naming the findings it replayed, and optionally a log.
func writeRetestRun(t *testing.T, project string, labels map[string]string, replay []string) string {
	t.Helper()
	dir := filepath.Join(project, ".observer", "assessments", retestRunID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var results []any
	for _, id := range replay {
		if l, ok := labels[id]; ok {
			results = append(results, map[string]any{"finding": id, "result": l})
		}
	}
	doc, err := json.Marshal(map[string]any{
		"schema": SchemaRetest, "run_id": retestRunID, "prompt_version": "re.2", "generator": map[string]any{"tool": "t", "model": "m"},
		"summary": "Replayed.", "started": true, "results": results,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assessment.json"), doc, 0o644); err != nil {
		t.Fatal(err)
	}
	set := map[string]any{}
	for _, id := range replay {
		set[id] = map[string]any{"steps": []any{}}
	}
	cfg, _ := json.Marshal(map[string]any{"schema": ProbeConfigSchema, "run_id": retestRunID, "replay": set})
	if err := os.WriteFile(filepath.Join(dir, FileProbeConfig), cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestScoreLiveRetest: a retest of the fixture's golden pen test, found beside
// it, scored through the earlier run's match of its findings.
func TestScoreLiveRetest(t *testing.T) {
	fixture, m, _, _ := scFixture(t)
	project, earlier := retestProject(t, fixture, "perfect")
	earlierRes := scValidateGolden(t, ContractPentest, scGolden(t, fixture, "pentest", "perfect"), scDir{project})
	if earlierRes.PT == nil {
		t.Fatal("no earlier model")
	}
	var replayable []string
	for _, f := range RetestRequestable(earlierRes.PT) {
		replayable = append(replayable, f.ID)
	}
	if len(replayable) < MaxRetestFindings {
		t.Fatalf("the golden pen test has %d replayable findings, want at least %d", len(replayable), MaxRetestFindings)
	}
	asked := replayable[:MaxRetestFindings]
	labels := map[string]string{}
	for _, id := range asked {
		labels[id] = RetestReproduced
	}
	labels[asked[1]] = RetestNotReproduced
	labels[asked[2]] = RetestInconclusive
	delete(labels, asked[3]) // asked for, no result
	run := writeRetestRun(t, project, labels, asked)
	data, err := os.ReadFile(filepath.Join(run, "assessment.json"))
	if err != nil {
		t.Fatal(err)
	}

	s, err := scLiveRetest(m, run, "", data) // the earlier run is found beside it
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + strings.Join(s.Lines(), "\n"))
	if s.Asked != MaxRetestFindings || s.Labelled != MaxRetestFindings-1 || len(s.Unlabelled) != 1 || s.Unlabelled[0] != asked[3] {
		t.Errorf("asked %d, labelled %d, unlabelled %v", s.Asked, s.Labelled, s.Unlabelled)
	}
	if len(s.NotReproduced) != 1 || len(s.Inconclusive) != 1 || len(s.Reproduced) != MaxRetestFindings-3 || s.Seeded != s.Labelled {
		t.Errorf("reproduced %v, not reproduced %v, inconclusive %v, seeded %d", s.Reproduced, s.NotReproduced, s.Inconclusive, s.Seeded)
	}
	if s.LogRead || s.Backed != 0 {
		t.Errorf("a run folder with no log read as backed: %+v", s)
	}
	if s.Validator.State == ValidationInvalid || s.Validator.Fatal != "" {
		t.Errorf("validator: %s", s.Validator.line())
	}
	// Naming the earlier run gives the same score.
	again, err := scLiveRetest(m, run, earlier, data)
	if err != nil || !reflect.DeepEqual(again, s) {
		t.Errorf("explicit earlier run: %v\n%+v\nwant %+v", err, again, s)
	}
}

// TestScoreEarlierRun: how the run a retest replayed is found.
func TestScoreEarlierRun(t *testing.T) {
	assessments := filepath.Join(t.TempDir(), ".observer", "assessments")
	mk := func(name, schema string, findings ...string) string {
		dir := filepath.Join(assessments, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		var fs []any
		for _, id := range findings {
			fs = append(fs, map[string]any{"id": id})
		}
		b, _ := json.Marshal(map[string]any{"schema": schema, "findings": fs})
		if err := os.WriteFile(filepath.Join(dir, "assessment.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	retest := mk(retestRunID, SchemaRetest)
	mk("tm", SchemaThreatModel, "F-1", "F-2")
	t.Run("none beside it", func(t *testing.T) {
		if _, err := scEarlierRun(retest, "", []string{"F-1"}); err == nil || !strings.Contains(err.Error(), "pass the earlier run's folder") {
			t.Errorf("err = %v", err)
		}
	})
	one := mk("aaaaaaaaaaaaaaaa", SchemaPentest, "F-1", "F-2", "F-3")
	mk("bbbbbbbbbbbbbbbb", SchemaPentest, "F-1") // names only one of the two
	t.Run("the one that names every finding", func(t *testing.T) {
		got, err := scEarlierRun(retest, "", []string{"F-1", "F-2"})
		if err != nil || got != one {
			t.Errorf("got %q, %v, want %q", got, err, one)
		}
	})
	two := mk("cccccccccccccccc", SchemaPentest, "F-2", "F-1")
	t.Run("two do", func(t *testing.T) {
		_, err := scEarlierRun(retest, "", []string{"F-1", "F-2"})
		if err == nil || !strings.Contains(err.Error(), "2 run folders") || !strings.Contains(err.Error(), "aaaaaaaaaaaaaaaa") || !strings.Contains(err.Error(), "cccccccccccccccc") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("naming one settles it", func(t *testing.T) {
		got, err := scEarlierRun(retest, two, []string{"F-1", "F-2"})
		if err != nil || got != two {
			t.Errorf("got %q, %v", got, err)
		}
	})
	t.Run("a folder that is not a pen test is no earlier run", func(t *testing.T) {
		if _, err := scEarlierRun(retest, filepath.Join(assessments, "tm"), nil); err == nil || !strings.Contains(err.Error(), "holds no penetration test result") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("no findings named means nothing to find it by", func(t *testing.T) {
		if _, err := scEarlierRun(retest, "", nil); err == nil {
			t.Error("a retest naming no finding found an earlier run")
		}
	})
}

// TestScoreProbeFacts: the helper's files of a run folder as facts.
func TestScoreProbeFacts(t *testing.T) {
	dir := t.TempDir()
	if _, ok := scProbeFacts(dir); ok {
		t.Error("a folder with no log read as a run with a helper")
	}
	if err := os.WriteFile(filepath.Join(dir, FileProbeLog), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	f, ok := scProbeFacts(dir)
	if !ok || f.Mode != HelperOn || f.LogState != LogFileOK || f.HelperState() != HelperMissing {
		t.Errorf("a log with no helper files: %+v ok %v state %q", f, ok, f.HelperState())
	}
	for _, name := range []string{FileProbeHelper, FileProbeConfig} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(fmt.Sprintf("%s body", name)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if f, _ := scProbeFacts(dir); f.HelperState() != HelperIntact {
		t.Errorf("helper state %q, want intact", f.HelperState())
	}
}
