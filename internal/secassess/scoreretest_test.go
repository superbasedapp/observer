package secassess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The retest scorer (depth plan W7.2, the live-check kit's `score` for a retest
// run). A retest replays the stored requests of findings an EARLIER pen test or
// red team run reported and labels each finding reproduced, not_reproduced or
// inconclusive. The fixture is a static copy of a deliberately vulnerable
// application, so the truth is the same for every seeded flaw: it is still
// there, and the label that matches is "reproduced". A "not reproduced" on a
// seeded flaw is a miss (the retest said a real weakness was gone); an
// "inconclusive" is no answer.
//
// A retest names the earlier run's finding ids ("F-3" there), not the answer
// key's ("F03"), so the scorer needs the earlier run's own match of its findings
// to flaws (scPenScore.Taken): it scores the earlier run first, with the same
// rules as a pen test, and reads the retest through that mapping. A labelled
// finding the earlier run did not match to a seeded flaw (a near miss it
// reported as a weakness, a real property that was not seeded, a finding near no
// anchor) has no truth here: it is listed, never scored and never dropped.
//
// What it scores is what Observer would keep: the retest's file is validated
// against the findings it was asked to replay (the ids in the run folder's
// probe.json, as the node holds them to the earlier run's stored model) and
// against the helper's own log, so each label carries Observer's reading of
// whether the log backs it. The scorer cannot tell what Observer wrote into
// probe.py and probe.json at launch, so it takes their bytes as they are and
// does not judge whether they were changed.

// scRetestScore is the account of one retest against the key.
type scRetestScore struct {
	// Asked is the findings the retest was asked to replay.
	Asked int
	// Labelled is the results the validator kept; Seeded the ones of them that the
	// earlier run matched to a seeded flaw (the ones scored).
	Labelled, Seeded int
	// Reproduced, NotReproduced and Inconclusive are the seeded flaws by label, as
	// the key's ids, sorted. NotReproduced is the misses.
	Reproduced, NotReproduced, Inconclusive []string
	// Backed counts the reproduced labels of seeded flaws that the helper's log
	// backs (Observer's evidence state "logged").
	Backed int
	// Unscored lists the labelled findings the earlier run did not match to a
	// seeded flaw, with what it made of each.
	Unscored []scPenHit
	// Unlabelled lists the findings the retest was asked to replay and gave no
	// result for.
	Unlabelled []string
	// LogRead says the run folder held the helper's log (so a label could be
	// backed); without it every label reads unlogged.
	LogRead   bool
	Recall    float64 // reproduced over seeded
	Validator scValidator
}

// scoreRetest scores a validated retest. earlier is the earlier run's score
// (Taken, and the lists its unmatched findings went to) and asked the finding
// ids the retest was asked to replay.
func scoreRetest(earlier scPenScore, asked []string, res Result) scRetestScore {
	s := scRetestScore{Asked: len(asked), Validator: scTally(res.Report)}
	if res.RT == nil {
		s.Unlabelled = append(s.Unlabelled, asked...)
		return s
	}
	labelled := map[string]bool{}
	for _, r := range res.RT.Results {
		labelled[r.Finding] = true
		s.Labelled++
		flaw, seeded := earlier.Taken[r.Finding]
		if !seeded {
			s.Unscored = append(s.Unscored, earlier.hitOf(r.Finding, r.Result))
			continue
		}
		s.Seeded++
		switch r.Result {
		case RetestReproduced:
			s.Reproduced = append(s.Reproduced, flaw)
			if r.EvidenceState == EvidenceLogged {
				s.Backed++
			}
		case RetestNotReproduced:
			s.NotReproduced = append(s.NotReproduced, flaw)
		default:
			s.Inconclusive = append(s.Inconclusive, flaw)
		}
	}
	for _, id := range asked {
		if !labelled[id] {
			s.Unlabelled = append(s.Unlabelled, id)
		}
	}
	for _, l := range [][]string{s.Reproduced, s.NotReproduced, s.Inconclusive} {
		sort.Strings(l)
	}
	sort.Strings(s.Unlabelled)
	if s.Seeded > 0 {
		s.Recall = float64(len(s.Reproduced)) / float64(s.Seeded)
	}
	return s
}

// hitOf says what the earlier run made of a finding it did not match to a seeded
// flaw: the bucket it went to and why, with the retest's label beside it.
func (s scPenScore) hitOf(finding, label string) scPenHit {
	for _, list := range [][]scPenHit{s.DecoyHits, s.Incidental, s.Duplicates, s.Unscored} {
		for _, h := range list {
			if h.Finding == finding {
				h.Why += "; the retest labelled it " + label
				return h
			}
		}
	}
	return scPenHit{Finding: finding, Why: "the earlier run's score does not list it; the retest labelled it " + label}
}

// Lines renders the score for a person (the live check pastes this).
func (s scRetestScore) Lines() []string {
	pct := func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) }
	out := []string{
		fmt.Sprintf("retest: %d of %d seeded weaknesses it replayed read as reproduced (%s); %d findings labelled, %d asked for",
			len(s.Reproduced), s.Seeded, pct(s.Recall), s.Labelled, s.Asked),
		"  reproduced: " + scList(s.Reproduced),
		"  not reproduced (a miss: the seeded weakness is still there): " + scList(s.NotReproduced),
		"  inconclusive (no answer): " + scList(s.Inconclusive),
		fmt.Sprintf("  reproduced labels the helper's log backs: %d of %d%s", s.Backed, len(s.Reproduced), scLogNote(s.LogRead)),
		fmt.Sprintf("  labelled findings the earlier run did not match to a seeded weakness (not scored, listed): %d%s", len(s.Unscored), scHits(s.Unscored)),
		"  asked for with no result: " + scList(s.Unlabelled),
		s.Validator.line(),
	}
	return out
}

func scLogNote(read bool) string {
	if read {
		return ""
	}
	return " (the run folder holds no helper log, so nothing can be backed)"
}

// ---- reading a live retest run ----

// scReplayIDs reads the finding ids a retest run's probe.json holds stored
// requests for (nil: no settings or no replay set).
func scReplayIDs(runDir string) []string {
	b, err := os.ReadFile(filepath.Join(runDir, FileProbeConfig))
	if err != nil {
		return nil
	}
	var cfg struct {
		Replay map[string]json.RawMessage `json:"replay"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return nil
	}
	ids := make([]string, 0, len(cfg.Replay))
	for id := range cfg.Replay {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// scProbeFacts reads the helper's files of a run folder as ProbeFacts: the log
// parsed, and each file's hash as both the one Observer wrote and the one found
// (the scorer cannot know what was written at launch, so a changed helper is not
// judged here). A folder with no log reads as a run with no helper.
func scProbeFacts(runDir string) (ProbeFacts, bool) {
	log, err := os.ReadFile(filepath.Join(runDir, FileProbeLog))
	if err != nil {
		return ProbeFacts{}, false
	}
	hash := func(name string) string {
		b, err := os.ReadFile(filepath.Join(runDir, name))
		if err != nil {
			return ""
		}
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:])
	}
	h, c := hash(FileProbeHelper), hash(FileProbeConfig)
	return ProbeFacts{Mode: HelperOn, HelperWant: h, HelperHave: h, ConfigWant: c, ConfigHave: c, LogState: LogFileOK, Log: ParseProbeLog(log)}, true
}

// scRunHoldsPentest reports whether a run directory holds a pen test (or red
// team) result and returns its finding ids.
func scRunHoldsPentest(dir string) ([]string, bool) {
	b, err := os.ReadFile(filepath.Join(dir, "assessment.json"))
	if err != nil {
		return nil, false
	}
	var doc struct {
		Schema   string `json:"schema"`
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	if json.Unmarshal(b, &doc) != nil || doc.Schema != SchemaPentest {
		return nil, false
	}
	ids := make([]string, len(doc.Findings))
	for i, f := range doc.Findings {
		ids[i] = f.ID
	}
	return ids, true
}

// scEarlierRun finds the run a retest replayed. An explicit directory (the
// kit's second argument, OBSERVER_SECASSESS_LIVE_OF) is taken as it is. Without
// one, the run folders beside the retest's are looked at: the one pen test or
// red team run that names every finding the retest was asked about is the
// earlier run; none, or more than one, is an error that says to name it (the
// retest's own record holds the id, in the node, and the run folder does not).
func scEarlierRun(runDir, explicit string, asked []string) (string, error) {
	if explicit != "" {
		abs, err := filepath.Abs(explicit)
		if err != nil {
			return "", err
		}
		if _, ok := scRunHoldsPentest(abs); !ok {
			return "", fmt.Errorf("%s holds no penetration test result (assessment.json with schema %s)", explicit, SchemaPentest)
		}
		return abs, nil
	}
	entries, err := os.ReadDir(filepath.Dir(runDir))
	if err != nil {
		return "", err
	}
	var found []string
	for _, e := range entries {
		dir := filepath.Join(filepath.Dir(runDir), e.Name())
		if !e.IsDir() || dir == runDir {
			continue
		}
		ids, ok := scRunHoldsPentest(dir)
		if !ok {
			continue
		}
		have := map[string]bool{}
		for _, id := range ids {
			have[id] = true
		}
		covers := len(asked) > 0
		for _, id := range asked {
			covers = covers && have[id]
		}
		if covers {
			found = append(found, dir)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", errors.New("no other run folder holds a penetration test result that names the findings this retest replayed: pass the earlier run's folder (OBSERVER_SECASSESS_LIVE_OF, or the second argument of collect.sh score)")
	}
	names := make([]string, len(found))
	for i, f := range found {
		names[i] = filepath.Base(f)
	}
	return "", fmt.Errorf("%d run folders hold a penetration test result that names the findings this retest replayed (%s): pass the one it replayed (OBSERVER_SECASSESS_LIVE_OF, or the second argument of collect.sh score)", len(found), strings.Join(names, ", "))
}

// scLiveRetest scores a live retest run: the earlier run first (as a pen test,
// in its own project copy), then the retest through the earlier run's match of
// its findings. runDir holds the retest's assessment.json (data).
func scLiveRetest(m *scManifest, runDir, explicitEarlier string, data []byte) (scRetestScore, error) {
	var head struct {
		Results []struct {
			Finding string `json:"finding"`
		} `json:"results"`
	}
	_ = json.Unmarshal(data, &head)
	asked := scReplayIDs(runDir)
	if len(asked) == 0 { // no settings in the folder: the findings the file itself names
		for _, r := range head.Results {
			asked = append(asked, r.Finding)
		}
	}
	earlierDir, err := scEarlierRun(runDir, explicitEarlier, asked)
	if err != nil {
		return scRetestScore{}, err
	}
	earlierData, err := os.ReadFile(filepath.Join(earlierDir, "assessment.json"))
	if err != nil {
		return scRetestScore{}, err
	}
	project := scDir{filepath.Join(earlierDir, "..", "..", "..")}
	eo := DefaultValidateOptions(ContractPentest, filepath.Base(earlierDir))
	eo.Refs = project
	earlierRes := Validate(earlierData, eo)
	earlier, err := scorePentest(m, project, earlierRes)
	if err != nil {
		return scRetestScore{}, fmt.Errorf("the earlier run's project does not carry the fixture's anchors (it was changed, or it is not the fixture): %w", err)
	}
	basis, refused := BuildRetestBasis(filepath.Base(earlierDir), earlierRes.PT, asked)
	if len(basis.Findings) == 0 {
		return scRetestScore{}, fmt.Errorf("the earlier run's model holds no replayable finding among the ones this retest names (%d refused)", len(refused))
	}
	ro := DefaultValidateOptions(ContractRetest, filepath.Base(runDir))
	ro.Retest = &basis
	facts, logRead := scProbeFacts(runDir)
	ro.Probe = facts
	s := scoreRetest(earlier, basis.IDs(), Validate(data, ro))
	s.LogRead = logRead
	return s, nil
}
