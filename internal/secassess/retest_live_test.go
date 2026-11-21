package secassess

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The retest file of the first live run (2026-11-16, run re.1): six findings of
// an earlier pen test, all labelled reproduced with an attack and a control
// probe, and on ONE result (index 3) an optional field written as one text where
// the prompt's text asks for a list: "evidence": "p3". The typed decode refused
// the whole file (V2 bad_shape, "results.3.evidence ... expected slice, got
// string"), so all six labels were lost. These tests hold the file's own shape.

// liveRetestBasis is six findings, each with one stored request and a stored
// condition the replay's logged answer holds.
func liveRetestBasis() *RetestBasis {
	b := &RetestBasis{Of: "0123456789abcdef"}
	for i := 1; i <= 6; i++ {
		b.Findings = append(b.Findings, RetestFinding{
			ID: fmt.Sprintf("F-%d", i), Title: fmt.Sprintf("Seeded weakness %d", i), Category: "ATHN",
			Steps: []PTRepro{{Step: "Send it", Request: &PTRequest{Method: "GET", Path: fmt.Sprintf("/a%d", i)}}},
			When:  &PTMatch{Status: 200, BodyContains: []string{"secret-row"}},
		})
	}
	return b
}

// liveRetestRecs is the helper's log of that retest: for finding n a control
// (p<2n-1>, an ordinary answer) and the replay of the finding (p<2n>, the answer
// that shows the weakness).
func liveRetestRecs() []ProbeRecord {
	var recs []ProbeRecord
	for n := 1; n <= 6; n++ {
		recs = append(recs, evRec(2*n-1, `{"rows":[]}`, nil))
		finding := fmt.Sprintf("F-%d", n)
		recs = append(recs, evRec(2*n, `{"rows":[1],"leak":"secret-row"}`, func(r *ProbeRecord) { r.Replay = finding }))
	}
	return recs
}

// liveRetestFile is the file the agent wrote: six reproduced labels with their
// two probe ids each, and the one result that names a lone probe id as its
// evidence. mut edits the generic JSON before it is written.
func liveRetestFile(t *testing.T, mut func(results []any)) []byte {
	t.Helper()
	var results []any
	for n := 1; n <= 6; n++ {
		r := map[string]any{
			"finding": fmt.Sprintf("F-%d", n), "result": "reproduced",
			"attack": fmt.Sprintf("p%d", 2*n), "control": fmt.Sprintf("p%d", 2*n-1), "note": "Still answers with the row.",
		}
		if n == 4 { // results.3
			r["evidence"] = "p3"
		}
		results = append(results, r)
	}
	if mut != nil {
		mut(results)
	}
	b, err := json.Marshal(map[string]any{
		"schema": SchemaRetest, "run_id": modelRun, "prompt_version": "re.1",
		"generator": map[string]any{"tool": "claude-code", "model": "m"}, "summary": "Replayed six findings.", "started": true,
		"results": results, "limits": []any{"Dev server only."},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func liveRetestValidate(t *testing.T, doc []byte) Result {
	t.Helper()
	o := optsFor(ContractRetest)
	o.Retest, o.Probe = liveRetestBasis(), evFacts(t, evLog(t, liveRetestRecs()...))
	return Validate(doc, o)
}

// TestRetestLiveFileKeepsEveryLabel: the live file, byte for byte in shape, is
// read; every label is kept and backed by the helper's log, the lone text is a
// one-item list and nothing is refused.
func TestRetestLiveFileKeepsEveryLabel(t *testing.T) {
	r := liveRetestValidate(t, liveRetestFile(t, nil))
	if r.Report.State == ValidationInvalid || r.RT == nil {
		t.Fatalf("the file is refused: fatal %q, issues %s", r.Report.Fatal, issueCodes(r.Report))
	}
	if r.Report.State != ValidationValid || len(r.Report.Issues) != 0 {
		t.Errorf("state %s, issues %s: a lone text for a list is a spelling, not a defect", r.Report.State, issueCodes(r.Report))
	}
	if len(r.RT.Results) != 6 || r.Report.RT == nil || r.Report.RT.Reproduced != 6 || r.Report.RT.Missing != 0 {
		t.Fatalf("results %d, summary %+v", len(r.RT.Results), r.Report.RT)
	}
	for i, got := range r.RT.Results {
		if got.Result != RetestReproduced || got.EvidenceState != EvidenceLogged {
			t.Errorf("result %d: %+v", i, got)
		}
		if i == 3 {
			if strings.Join(got.Evidence, ",") != "p3" {
				t.Errorf("result 3 evidence = %v, want [p3]", got.Evidence)
			}
		} else if len(got.Evidence) != 0 {
			t.Errorf("result %d evidence = %v, want none", i, got.Evidence)
		}
	}
}

// TestRetestLiveFileEvidenceIsBackedByTheLog: the lone text is read as the list
// it names, so a result that cites a probe the log does not hold is still
// unbacked (E11): the tolerance is for the spelling, not for the claim.
func TestRetestLiveFileEvidenceIsBackedByTheLog(t *testing.T) {
	r := liveRetestValidate(t, liveRetestFile(t, func(results []any) { obj(results[3])["evidence"] = "p99" }))
	if r.RT == nil || len(r.RT.Results) != 6 {
		t.Fatalf("results: %+v", r.Report)
	}
	// Result 3 cites p99 (a lone text), which the log does not hold, beside its own attack and control.
	got := r.RT.Results[3]
	if got.Result != RetestReproduced || got.EvidenceState != EvidenceUnlogged || got.EvidenceReason != ReasonProbeNotInLog {
		t.Errorf("result 3 = %+v, want a kept label read as unlogged (probe not in the log)", got)
	}
}

// TestReplayShowsHeaderNamesWhole: the retest task and the plan's list of
// findings cut a stored header name at the longest name the check admits, no
// sooner. The live run showed "Access-Control-Allow-Ori" for the 27-byte name.
func TestReplayShowsHeaderNamesWhole(t *testing.T) {
	names := []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Strict-Transport-Security", strings.Repeat("A", maxHeaderName)}
	for _, n := range names {
		if !ValidHeaderName(n) {
			t.Fatalf("%q is not a valid header name", n)
		}
	}
	b := testReplayBasis()
	b.Findings[0].Steps[0].Request.Headers = []PTHeader{{Name: names[0]}, {Name: names[1]}}
	b.Findings[0].When = &PTMatch{HeaderPresent: []string{names[2]}, HeaderAbsent: []string{names[1]}, HeaderContains: []PTHeader{{Name: names[0], Value: "*"}}}
	task := RenderReplay(*b)
	for _, want := range []string{"headers: " + names[0] + ", " + names[1], "header " + names[2] + " present", "header " + names[1] + " absent", "header " + names[0] + " contains"} {
		if !strings.Contains(task, want) {
			t.Errorf("the task lacks %q:\n%s", want, task)
		}
	}
	plan := MatchWords(b.Findings[0].When)
	for _, want := range []string{"header " + names[2] + " present", "header " + names[1] + " absent", "header " + names[0] + " contains"} {
		if !strings.Contains(plan, want) {
			t.Errorf("the plan's line lacks %q: %s", want, plan)
		}
	}
	// The longest valid name is shown whole; a longer one (the check refuses it,
	// so it cannot be stored) is cut at the bound if one is shown anyway.
	b.Findings[0].Steps[0].Request.Headers = []PTHeader{{Name: names[3]}, {Name: names[3] + "BBBB"}}
	task = RenderReplay(*b)
	if !strings.Contains(task, "headers: "+names[3]+", "+names[3]+" | ") && !strings.Contains(task, "headers: "+names[3]+", "+names[3]+"\n") {
		t.Errorf("a name of %d bytes was not shown whole, or a longer one not cut at it:\n%s", maxHeaderName, task)
	}
}

// replayBasisOf is a basis of n findings whose ids are idLen bytes long, each with
// stored requests (path and body of the given lengths, eight headers named nameLen
// bytes long) and a stored condition.
func replayBasisOf(n, idLen, nameLen, stored, pathLen, bodyLen int) *RetestBasis {
	b := &RetestBasis{Of: "x"}
	for i := 0; i < n; i++ {
		id := strings.Repeat("i", idLen-1) + string(rune('a'+i))
		f := RetestFinding{ID: id, Category: "ATHN", When: &PTMatch{Status: 200, BodyContains: []string{strings.Repeat("c", capMatchText)}, HeaderPresent: []string{strings.Repeat("h", nameLen)}}}
		for j := 0; j < stored; j++ {
			r := &PTRequest{Method: "POST", Path: "/" + strings.Repeat("p", pathLen-1), Body: strings.Repeat("b", bodyLen)}
			for k := 0; k < maxPerItemList; k++ {
				r.Headers = append(r.Headers, PTHeader{Name: strings.Repeat("H", nameLen), Value: "v"})
			}
			f.Steps = append(f.Steps, PTRepro{Step: "s", Request: r})
		}
		b.Findings = append(b.Findings, f)
	}
	return b
}

// TestRenderReplayNeverPassesItsBound: whatever the number of findings, the
// length of their ids, of the header names, of the path and of the body, the
// replay section is never over its bound, and every finding is either shown or
// named. The sweep over the path and body lengths walks the block size past every
// alignment with the bound (header names at the full 64 bytes put the old fixed
// 160-byte margin 8 bytes over, at one such alignment).
func TestRenderReplayNeverPassesItsBound(t *testing.T) {
	check := func(t *testing.T, b *RetestBasis, what string) {
		t.Helper()
		out := RenderReplay(*b)
		if len(out) > maxReplayPromptBytes {
			t.Errorf("%s: %d bytes, over %d", what, len(out), maxReplayPromptBytes)
		}
		for _, f := range b.Findings {
			if !strings.Contains(out, f.ID) {
				t.Errorf("%s: %s is neither shown nor named", what, f.ID)
			}
		}
	}
	for n := 1; n <= MaxRetestFindings; n++ {
		for _, idLen := range []int{3, 12, 48} {
			for _, nameLen := range []int{4, 27, maxHeaderName} {
				for _, stored := range []int{1, maxPerItemList} {
					check(t, replayBasisOf(n, idLen, nameLen, stored, capRequestPath, capRequestBody),
						fmt.Sprintf("%d findings, ids of %d, header names of %d, %d stored requests", n, idLen, nameLen, stored))
				}
			}
		}
	}
	// The fixture's own worst basis (every part at its cap), with the header names
	// walked through every length, so the section's size passes each alignment.
	for nameLen := 1; nameLen <= maxHeaderName; nameLen++ {
		b := worstReplayBasis()
		for i := range b.Findings {
			f := &b.Findings[i]
			f.When.HeaderPresent[0] = strings.Repeat("h", nameLen)
			f.When.HeaderAbsent[0] = strings.Repeat("g", nameLen)
			f.When.HeaderContains[0].Name = strings.Repeat("n", nameLen)
			for _, s := range f.Steps {
				for k := range s.Request.Headers {
					s.Request.Headers[k].Name = strings.Repeat("H", nameLen)
				}
			}
		}
		check(t, b, fmt.Sprintf("the worst basis with header names of %d", nameLen))
	}
	for pathLen := maxReplayPathShown - 12; pathLen <= maxReplayPathShown+2; pathLen++ {
		for bodyLen := maxReplayBodyShown - 12; bodyLen <= maxReplayBodyShown+2; bodyLen++ {
			check(t, replayBasisOf(MaxRetestFindings, 48, maxHeaderName, maxPerItemList, pathLen, bodyLen), fmt.Sprintf("a path of %d and a body of %d", pathLen, bodyLen))
		}
	}
}
