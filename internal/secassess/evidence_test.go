package secassess

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Tests of row V14 (evidence from the request helper's log), one case per row of
// the evidence table, the structure check of the log, the forged-log cases and
// the reproduction request and indicator rules the evidence reads.

// evTime is the time of the first log line; each next line is a second later.
var evTime = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

// evRec builds the nth record (1-based) of a helper log: a request that was
// sent and got a 200 with the given body.
func evRec(n int, body string, mut func(*ProbeRecord)) ProbeRecord {
	r := ProbeRecord{
		V: ProbeRecordVersion, ID: fmt.Sprintf("p%d", n), TS: evTime.Add(time.Duration(n) * time.Second).Format("2006-01-02T15:04:05.000Z"),
		Method: "GET", Path: fmt.Sprintf("/r%d", n), ReqHeaders: []ProbeHeader{}, Sent: true, Status: 200,
		RespHeaders: []ProbeHeader{{N: "Content-Type", V: "application/json"}}, BodyBytes: len(body), BodyExcerpt: body, Cost: 1, MS: 3,
	}
	if mut != nil {
		mut(&r)
	}
	return r
}

// evLog is the bytes of a helper log of the records.
func evLog(t testing.TB, recs ...ProbeRecord) []byte {
	t.Helper()
	var b strings.Builder
	for _, r := range recs {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// evFacts is an intact helper with a readable log of data.
func evFacts(t testing.TB, data []byte) ProbeFacts {
	t.Helper()
	return ProbeFacts{
		Mode: HelperOn, HelperWant: "aa", HelperHave: "aa", ConfigWant: "bb", ConfigHave: "bb",
		LogState: LogFileOK, Log: ParseProbeLog(data),
	}
}

// evGoodLog is two requests: p1 the control (a plain answer), p2 the attack (an
// answer that shows the weakness).
func evGoodLog(t testing.TB) []byte {
	return evLog(t, evRec(1, `{"rows":[]}`, nil), evRec(2, `{"rows":[1],"leak":"secret-row"}`, nil))
}

// evDoc is a pen test whose one finding cites p1 and p2 with an indicator.
func evDoc(t *testing.T, mut func(m map[string]any)) []byte {
	return edit(t, basePentest, func(m map[string]any) {
		f := obj(arr(m["findings"])[0])
		f["evidence"] = []any{"p1", "p2"}
		f["indicator"] = map[string]any{"attack": "p2", "control": "p1", "when": map[string]any{"status": 200, "body_contains": []any{"secret-row"}}}
		if mut != nil {
			mut(m)
		}
	})
}

func evValidate(t testing.TB, doc []byte, pf ProbeFacts) Result {
	t.Helper()
	o := optsFor(ContractPentest)
	o.Probe = pf
	return Validate(doc, o)
}

// finding0 returns the first finding of the result.
func finding0(t testing.TB, r Result) PTFinding {
	t.Helper()
	if r.PT == nil || len(r.PT.Findings) == 0 {
		t.Fatalf("no finding kept: %+v", r.Report)
	}
	return r.PT.Findings[0]
}

// TestEvidenceRows: every row of the V14 table is reached by a case that names
// the state and the reason it must give, and the table's reasons are the closed
// list.
func TestEvidenceRows(t *testing.T) {
	good := func() ProbeFacts { return evFacts(t, evGoodLog(t)) }
	cases := []struct {
		row    string
		facts  func() ProbeFacts
		doc    func(m map[string]any)
		state  EvidenceState
		reason string
	}{
		{"E1", good, func(m map[string]any) { obj(obj(m["target"])["start"])["started"] = false }, EvidenceNotStarted, ReasonTargetNotStarted},
		{"E2", func() ProbeFacts { f := good(); f.Mode = HelperOff; return f }, nil, EvidenceUnlogged, ReasonHelperOff},
		{"E2", func() ProbeFacts { f := good(); f.Mode = ""; return f }, nil, EvidenceUnlogged, ReasonHelperOff},
		{"E3", func() ProbeFacts { f := good(); f.Mode = HelperWithheld; return f }, nil, EvidenceUnlogged, ReasonHelperWithheld},
		{"E4", func() ProbeFacts { f := good(); f.HelperHave = "cc"; return f }, nil, EvidenceUnlogged, ReasonHelperChanged},
		{"E4", func() ProbeFacts { f := good(); f.ConfigHave = "cc"; return f }, nil, EvidenceUnlogged, ReasonHelperChanged},
		{"E5", func() ProbeFacts { f := good(); f.HelperHave = ""; return f }, nil, EvidenceUnlogged, ReasonHelperMissing},
		{"E5", func() ProbeFacts { f := good(); f.ConfigHave = ""; return f }, nil, EvidenceUnlogged, ReasonHelperMissing},
		{"E5", func() ProbeFacts { f := good(); f.HelperWant = ""; return f }, nil, EvidenceUnlogged, ReasonHelperMissing},
		{"E6", func() ProbeFacts { f := good(); f.LogState, f.Log = LogFileAbsent, ProbeLog{}; return f }, nil, EvidenceUnlogged, ReasonLogAbsent},
		{"E6", func() ProbeFacts { f := good(); f.LogState = ""; return f }, nil, EvidenceUnlogged, ReasonLogAbsent},
		{"E7", func() ProbeFacts { f := good(); f.LogState = LogFileUnreadable; return f }, nil, EvidenceUnlogged, ReasonLogUnreadable},
		{"E8", func() ProbeFacts { f := good(); f.LogState = LogFileTooLarge; return f }, nil, EvidenceUnlogged, ReasonLogTooLarge},
		{"E9", func() ProbeFacts {
			// A line was removed: p1, then p3.
			return evFacts(t, evLog(t, evRec(1, "a", nil), evRec(3, "b", nil)))
		}, nil, EvidenceUnlogged, ReasonLogInconsistent},
		{"E10", good, func(m map[string]any) {
			f := obj(arr(m["findings"])[0])
			delete(f, "evidence")
			delete(f, "indicator")
		}, EvidenceUnlogged, ReasonNoProbe},
		{"E11", good, func(m map[string]any) { obj(arr(m["findings"])[0])["evidence"] = []any{"p1", "p2", "p9"} }, EvidenceUnlogged, ReasonProbeNotInLog},
		{"E11", good, func(m map[string]any) { obj(obj(arr(m["findings"])[0])["indicator"])["attack"] = "p7" }, EvidenceUnlogged, ReasonProbeNotInLog},
		{"E12", func() ProbeFacts {
			return evFacts(t, evLog(t, evRec(1, "a", nil), evRec(2, "", func(r *ProbeRecord) { r.Sent, r.Refused, r.Status, r.Cost = false, "off_target", 0, 0 })))
		}, nil, EvidenceUnlogged, ReasonProbeNotSent},
		{"E13", func() ProbeFacts {
			return evFacts(t, evLog(t, evRec(1, "a", nil), evRec(2, "", func(r *ProbeRecord) { r.Status, r.Error = 0, "connection refused" })))
		}, nil, EvidenceUnlogged, ReasonProbeNoResponse},
		{"E14", good, func(m map[string]any) { delete(obj(arr(m["findings"])[0]), "indicator") }, EvidenceUnlogged, ReasonNoIndicator},
		{"E14", good, func(m map[string]any) { delete(obj(obj(arr(m["findings"])[0])["indicator"]), "attack") }, EvidenceUnlogged, ReasonNoIndicator},
		{"E15", good, func(m map[string]any) { delete(obj(obj(arr(m["findings"])[0])["indicator"]), "control") }, EvidenceUnlogged, ReasonNoControl},
		{"E15", good, func(m map[string]any) { obj(obj(arr(m["findings"])[0])["indicator"])["control"] = "p2" }, EvidenceUnlogged, ReasonNoControl},
		{"E16", good, func(m map[string]any) { delete(obj(obj(arr(m["findings"])[0])["indicator"]), "when") }, EvidenceUnlogged, ReasonNoCondition},
		{"E16", good, func(m map[string]any) { obj(obj(arr(m["findings"])[0])["indicator"])["when"] = map[string]any{} }, EvidenceUnlogged, ReasonNoCondition},
		{"E17", good, func(m map[string]any) {
			obj(obj(obj(arr(m["findings"])[0])["indicator"])["when"])["body_contains"] = []any{"not in the response"}
		}, EvidenceUnlogged, ReasonConditionNotMet},
		{"E17", good, func(m map[string]any) { obj(obj(obj(arr(m["findings"])[0])["indicator"])["when"])["status"] = 500 }, EvidenceUnlogged, ReasonConditionNotMet},
		{"E18", func() ProbeFacts {
			// The control answers like the attack: the condition tells nothing apart.
			return evFacts(t, evLog(t, evRec(1, `{"leak":"secret-row"}`, nil), evRec(2, `{"leak":"secret-row"}`, nil)))
		}, nil, EvidenceUnlogged, ReasonNotDifferential},
		{"E19", good, nil, EvidenceLogged, ""},
	}
	seen := map[string]bool{}
	for i, c := range cases {
		t.Run(fmt.Sprintf("%s#%d", c.row, i), func(t *testing.T) {
			seen[c.row] = true
			f := finding0(t, evValidate(t, evDoc(t, c.doc), c.facts()))
			if f.EvidenceState != c.state || f.EvidenceReason != c.reason {
				t.Fatalf("row %s: evidence %q/%q, want %q/%q", c.row, f.EvidenceState, f.EvidenceReason, c.state, c.reason)
			}
		})
	}
	// Every row of the table has a case, and the reasons are the closed list, one
	// row each.
	reasons := map[string]bool{}
	for _, r := range evidenceRows {
		if !seen[r.ID] {
			t.Errorf("row %s has no case", r.ID)
		}
		if r.Reason != "" {
			if reasons[r.Reason] {
				t.Errorf("reason %s is raised by two rows", r.Reason)
			}
			reasons[r.Reason] = true
		}
	}
	// A retest result is read through the same table with rows of its own
	// (retest_test.go has a case for each).
	for _, r := range retestOnlyRows {
		if r.Reason != "" {
			if reasons[r.Reason] {
				t.Errorf("reason %s is raised by two rows", r.Reason)
			}
			reasons[r.Reason] = true
		}
	}
	if len(reasons) != len(EvidenceReasons) {
		t.Errorf("the table raises %d reasons, the list names %d", len(reasons), len(EvidenceReasons))
	}
	for _, code := range EvidenceReasons {
		if !reasons[code] {
			t.Errorf("reason %s is listed and no row raises it", code)
		}
	}
	if len(cases) < len(evidenceRows) {
		t.Errorf("%d cases for %d rows", len(cases), len(evidenceRows))
	}
}

// TestEvidenceTableOrder: an earlier row wins over a later one when both hold.
func TestEvidenceTableOrder(t *testing.T) {
	// The target did not start AND the helper changed: not started wins.
	pf := evFacts(t, evGoodLog(t))
	pf.HelperHave = "cc"
	f := finding0(t, evValidate(t, evDoc(t, func(m map[string]any) { obj(obj(m["target"])["start"])["started"] = false }), pf))
	if f.EvidenceState != EvidenceNotStarted {
		t.Fatalf("state %q", f.EvidenceState)
	}
	// The helper is off AND the finding cites nothing: off wins over no_probe.
	pf = evFacts(t, evGoodLog(t))
	pf.Mode = HelperOff
	f = finding0(t, evValidate(t, evDoc(t, func(m map[string]any) { delete(obj(arr(m["findings"])[0]), "evidence") }), pf))
	if f.EvidenceReason != ReasonHelperOff {
		t.Fatalf("reason %q", f.EvidenceReason)
	}
	// No facts at all (a caller that passes none, or a run before the helper):
	// every finding reads off.
	f = finding0(t, Validate(evDoc(t, nil), optsFor(ContractPentest)))
	if f.EvidenceState != EvidenceUnlogged || f.EvidenceReason != ReasonHelperOff {
		t.Fatalf("zero facts: %q/%q", f.EvidenceState, f.EvidenceReason)
	}
}

// TestEvidenceIsComputedNotRead: a state written in the agent's file is ignored
// and counted, never believed.
func TestEvidenceIsComputedNotRead(t *testing.T) {
	doc := evDoc(t, func(m map[string]any) {
		f := obj(arr(m["findings"])[0])
		f["evidence_state"], f["evidence_reason"] = "logged", ""
	})
	r := evValidate(t, doc, ProbeFacts{})
	f := finding0(t, r)
	if f.EvidenceState != EvidenceUnlogged {
		t.Fatalf("the agent's own state was believed: %q", f.EvidenceState)
	}
	if r.Report.Ignored == 0 {
		t.Error("the written state was not counted among the ignored fields")
	}
}

// TestEvidenceReport: the report counts the log and the findings by evidence.
func TestEvidenceReport(t *testing.T) {
	log := evLog(t, evRec(1, `{"rows":[]}`, nil), evRec(2, `{"rows":[1],"leak":"secret-row"}`, nil),
		evRec(3, "", func(r *ProbeRecord) { r.Sent, r.Refused, r.Status, r.Cost = false, "budget", 0, 0 }))
	r := evValidate(t, evDoc(t, nil), evFacts(t, log))
	e := r.Report.Evidence
	if e == nil {
		t.Fatal("no evidence report")
	}
	want := EvidenceReport{Mode: HelperOn, Helper: HelperIntact, Log: LogFileOK, Records: 3, Sent: 2, Refused: 1, Requests: 2, Logged: 1}
	if e.Mode != want.Mode || e.Helper != want.Helper || e.Log != want.Log || e.Records != want.Records || e.Sent != want.Sent ||
		e.Refused != want.Refused || e.Requests != want.Requests || e.Logged != 1 || e.Unlogged != 0 || e.NotStarted != 0 {
		t.Fatalf("report = %+v", *e)
	}
	// A run with no helper reads off, and counts nothing of a log it never read.
	r = evValidate(t, evDoc(t, nil), ProbeFacts{Mode: HelperOff, LogState: LogFileOK, Log: ParseProbeLog(evGoodLog(t))})
	e = r.Report.Evidence
	if e.Mode != HelperOff || e.Helper != HelperNotChecked || e.Log != LogFileNotRead || e.Records != 0 || e.Unlogged != 1 || e.ByReason[ReasonHelperOff] != 1 {
		t.Fatalf("report for a run without a helper = %+v", *e)
	}
	// A threat model has none.
	tm := Validate([]byte(baseThreatModel), optsFor(ContractThreatModel))
	if tm.Report.Evidence != nil {
		t.Error("a threat model carries an evidence report")
	}
}

// TestEvidenceForgedLog: what the check catches of a log the agent wrote itself,
// and what it cannot, said in the cases.
func TestEvidenceForgedLog(t *testing.T) {
	// A log written by hand with exactly the helper's structure, beside the
	// helper as Observer wrote it. Nothing in the log tells it from a real one:
	// Observer reads it as "Helper log matches", and the words around that label
	// say the log is a file the agent can write. This is the stated limit.
	forged := evLog(t, evRec(1, `{"rows":[]}`, nil), evRec(2, `{"leak":"secret-row"}`, nil))
	t.Run("hand-written with the helper intact reads as matching (the stated limit)", func(t *testing.T) {
		f := finding0(t, evValidate(t, evDoc(t, nil), evFacts(t, forged)))
		if f.EvidenceState != EvidenceLogged {
			t.Fatalf("state %q: a well-formed forged log is not detectable and the limit changed", f.EvidenceState)
		}
	})
	t.Run("a forged log beside an edited helper is not used", func(t *testing.T) {
		pf := evFacts(t, forged)
		pf.HelperHave = "edited"
		f := finding0(t, evValidate(t, evDoc(t, nil), pf))
		if f.EvidenceState != EvidenceUnlogged || f.EvidenceReason != ReasonHelperChanged {
			t.Fatalf("%q/%q", f.EvidenceState, f.EvidenceReason)
		}
	})
	t.Run("a forged log beside an edited settings file is not used", func(t *testing.T) {
		pf := evFacts(t, forged)
		pf.ConfigHave = "points elsewhere"
		f := finding0(t, evValidate(t, evDoc(t, nil), pf))
		if f.EvidenceReason != ReasonHelperChanged {
			t.Fatalf("reason %q", f.EvidenceReason)
		}
	})
	t.Run("a probe the finding cites and the log does not hold", func(t *testing.T) {
		doc := evDoc(t, func(m map[string]any) { obj(obj(arr(m["findings"])[0])["indicator"])["attack"] = "p40" })
		f := finding0(t, evValidate(t, doc, evFacts(t, forged)))
		if f.EvidenceReason != ReasonProbeNotInLog {
			t.Fatalf("reason %q", f.EvidenceReason)
		}
	})
	// Careless forgeries: each breaks a property the helper keeps.
	broken := map[string][]byte{
		"a line deleted from the middle":  evLog(t, evRec(1, "a", nil), evRec(3, "b", nil)),
		"ids that do not count lines":     evLog(t, evRec(1, "a", nil), evRec(7, "b", nil)),
		"times that go backwards":         evLog(t, evRec(1, "a", nil), evRec(2, "b", func(r *ProbeRecord) { r.TS = evTime.Add(-time.Hour).Format(time.RFC3339Nano) })),
		"a blank line":                    []byte(string(evLog(t, evRec(1, "a", nil))) + "\n" + string(evLog(t, evRec(3, "b", nil)))),
		"a line that is not a record":     []byte(string(evLog(t, evRec(1, "a", nil))) + "not json\n"),
		"a key the helper never writes":   []byte(strings.Replace(string(evGoodLog(t)), `"v":1,`, `"v":1,"verified":true,`, 1)),
		"a refusal code it never gives":   evLog(t, evRec(1, "", func(r *ProbeRecord) { r.Sent, r.Refused, r.Status, r.Cost = false, "because", 0, 0 })),
		"a refused request that was sent": evLog(t, evRec(1, "", func(r *ProbeRecord) { r.Refused = "budget" })),
		"a version it does not write":     evLog(t, evRec(1, "a", func(r *ProbeRecord) { r.V = 2 })),
	}
	for name, data := range broken {
		t.Run(name, func(t *testing.T) {
			f := finding0(t, evValidate(t, evDoc(t, nil), evFacts(t, data)))
			if f.EvidenceState != EvidenceUnlogged || f.EvidenceReason != ReasonLogInconsistent {
				t.Fatalf("%q/%q for a log that does not read like the helper's", f.EvidenceState, f.EvidenceReason)
			}
		})
	}
}

func TestParseProbeLog(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		problem string
		records int
	}{
		{"empty", nil, "", 0},
		{"two lines", evGoodLog(t), "", 2},
		{"no trailing newline", []byte(strings.TrimSuffix(string(evGoodLog(t)), "\n")), "", 2},
		{"carriage returns", []byte(strings.ReplaceAll(string(evGoodLog(t)), "\n", "\r\n")), "", 2},
		{"too long a line", []byte(strings.Repeat("x", maxProbeLine+1) + "\n"), LogBadLine, 0},
		{"two records on a line", []byte(strings.TrimSuffix(string(evLog(t, evRec(1, "a", nil))), "\n") + " " + string(evLog(t, evRec(1, "a", nil)))), LogBadLine, 0},
		{"a bad time", evLog(t, evRec(1, "a", func(r *ProbeRecord) { r.TS = "yesterday" })), LogBadTime, 0},
		{"equal times are fine", evLog(t, evRec(1, "a", nil), evRec(2, "b", func(r *ProbeRecord) { r.TS = evRec(1, "", nil).TS })), "", 2},
		{"an unknown role", evLog(t, evRec(1, "a", func(r *ProbeRecord) { r.Role = "boss" })), LogBadField, 0},
		{"an unknown category", evLog(t, evRec(1, "a", func(r *ProbeRecord) { r.WSTG = "ZZZZ" })), LogBadField, 0},
		{"an unsent record with no refusal", evLog(t, evRec(1, "a", func(r *ProbeRecord) { r.Sent = false })), LogBadField, 0},
		{"a status out of range", evLog(t, evRec(1, "a", func(r *ProbeRecord) { r.Status = 1200 })), LogBadField, 0},
		{"a role of control", evLog(t, evRec(1, "a", func(r *ProbeRecord) { r.Role, r.WSTG = "control", "ATHN" })), "", 1},
		// The excerpt is at most what the body's bytes can give plus nine characters
		// for each marker that replaced a value (excerptTooLong).
		{"an excerpt as long as its body", evLog(t, evRec(1, `{"a":"b"}`, nil)), "", 1},
		{"an excerpt longer than its body", evLog(t, evRec(1, `{"a":"b"}`, func(r *ProbeRecord) { r.BodyBytes = 4 })), LogBadField, 0},
		{"a request excerpt longer than its body", evLog(t, evRec(1, "a", func(r *ProbeRecord) { r.ReqBodyExcerpt, r.ReqBodyBytes = `{"pw":"xxxxxxxx"}`, 3 })), LogBadField, 0},
		{"an excerpt that grew by one marker", evLog(t, evRec(1, `{"token":"[REDACTED]"}`, func(r *ProbeRecord) { r.BodyBytes = len(`{"token":"x"}`) })), "", 1},
		{"an excerpt that grew past its marker", evLog(t, evRec(1, `{"token":"[REDACTED]"}`, func(r *ProbeRecord) { r.BodyBytes = len(`{"token":"x"}`) - 1 })), LogBadField, 0},
		{"an excerpt cut at the helper's limit is not measured", evLog(t, evRec(1, strings.Repeat("x", probeExcerptChars), func(r *ProbeRecord) { r.BodyBytes = 2000 })), "", 1},
		{"an excerpt just under the limit is measured", evLog(t, evRec(1, strings.Repeat("x", probeExcerptChars-1), func(r *ProbeRecord) { r.BodyBytes = 5 })), LogBadField, 0},
		{"characters, not bytes", evLog(t, evRec(1, strings.Repeat("é", 5), func(r *ProbeRecord) { r.BodyBytes = 5 })), "", 1},
		{"an empty excerpt of an empty body", evLog(t, evRec(1, "", nil)), "", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := ParseProbeLog(c.data)
			if l.Problem != c.problem || len(l.Records) != c.records {
				t.Fatalf("problem %q with %d records, want %q with %d", l.Problem, len(l.Records), c.problem, c.records)
			}
		})
	}
	t.Run("more lines than are looked at", func(t *testing.T) {
		line := evLog(t, evRec(1, "", nil))
		_ = line
		var b strings.Builder
		for i := 0; i <= maxProbeLines; i++ {
			b.WriteString("{}\n")
		}
		// The first line already fails, so build the case on the limit directly.
		if got := ParseProbeLog([]byte(b.String())).Problem; got == "" {
			t.Fatal("a log of empty objects was accepted")
		}
	})
	t.Run("summary", func(t *testing.T) {
		l := ParseProbeLog(evLog(t, evRec(1, "a", func(r *ProbeRecord) { r.Cost = 2 }), evRec(2, "", func(r *ProbeRecord) { r.Sent, r.Refused, r.Status, r.Cost = false, "budget", 0, 0 })))
		s := l.Summary()
		if s != (ProbeLogSummary{Records: 2, Sent: 1, Refused: 1, Requests: 2}) {
			t.Fatalf("summary %+v", s)
		}
	})
	t.Run("Backs", func(t *testing.T) {
		if !evRec(1, "", nil).Backs() {
			t.Error("a sent request with a response does not back")
		}
		for _, mut := range []func(*ProbeRecord){
			func(r *ProbeRecord) { r.Sent, r.Refused, r.Status, r.Cost = false, "budget", 0, 0 },
			func(r *ProbeRecord) { r.Status, r.Error = 0, "refused" },
		} {
			if evRec(1, "", mut).Backs() {
				t.Error("a request with no response backs")
			}
		}
	})
}

func TestHelperState(t *testing.T) {
	on := ProbeFacts{Mode: HelperOn, HelperWant: "AA", HelperHave: "aa", ConfigWant: "bb", ConfigHave: "bb"}
	cases := []struct {
		name string
		f    ProbeFacts
		want string
	}{
		{"intact, hex case ignored", on, HelperIntact},
		{"helper changed", func() ProbeFacts { f := on; f.HelperHave = "cc"; return f }(), HelperChanged},
		{"settings changed", func() ProbeFacts { f := on; f.ConfigHave = "cc"; return f }(), HelperChanged},
		{"helper unreadable", func() ProbeFacts { f := on; f.HelperHave = ""; return f }(), HelperMissing},
		{"nothing to compare with", func() ProbeFacts { f := on; f.ConfigWant = ""; return f }(), HelperMissing},
		{"off", ProbeFacts{Mode: HelperOff}, HelperNotChecked},
		{"withheld", ProbeFacts{Mode: HelperWithheld}, HelperNotChecked},
		{"none", ProbeFacts{}, HelperNotChecked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.f.HelperState(); got != c.want {
				t.Fatalf("%q, want %q", got, c.want)
			}
		})
	}
}

// TestEvidenceCoverage: a category the agent marked tested becomes "tested, with a
// logged request" only when the log backs it and the helper is intact.
func TestEvidenceCoverage(t *testing.T) {
	logWithTag := evLog(t, evRec(1, "a", func(r *ProbeRecord) { r.WSTG = "INPV" }), evRec(2, "b", nil))
	cases := []struct {
		name  string
		facts func() ProbeFacts
		doc   func(m map[string]any)
		want  map[string]string // category -> effective word
	}{
		{
			"a cited request that reached the target", func() ProbeFacts { return evFacts(t, evGoodLog(t)) }, nil,
			map[string]string{"ATHN": CovTestedLogged, "INPV": CovTestedClaimed},
		},
		{
			"a request tagged with the category", func() ProbeFacts { return evFacts(t, logWithTag) }, nil,
			map[string]string{"ATHN": CovTestedLogged, "INPV": CovTestedLogged},
		},
		{"a cited request the helper refused", func() ProbeFacts {
			return evFacts(t, evLog(t, evRec(1, "", func(r *ProbeRecord) { r.Sent, r.Refused, r.Status, r.Cost = false, "off_target", 0, 0 })))
		}, nil, map[string]string{"ATHN": CovTestedClaimed}},
		{
			"a cited request that is not in the log", func() ProbeFacts { return evFacts(t, evLog(t, evRec(1, "a", nil))) },
			func(m map[string]any) { obj(arr(m["coverage"])[0])["probes"] = []any{"p5"} },
			map[string]string{"ATHN": CovTestedClaimed},
		},
		{"the helper changed", func() ProbeFacts { f := evFacts(t, evGoodLog(t)); f.HelperHave = "x"; return f }, nil, map[string]string{"ATHN": CovTestedClaimed}},
		{"the log does not read like the helper's", func() ProbeFacts { return evFacts(t, evLog(t, evRec(2, "a", nil))) }, nil, map[string]string{"ATHN": CovTestedClaimed}},
		{"the helper was off", func() ProbeFacts { f := evFacts(t, evGoodLog(t)); f.Mode = HelperOff; return f }, nil, map[string]string{"ATHN": CovTestedClaimed}},
		{
			"the target did not start", func() ProbeFacts { return evFacts(t, evGoodLog(t)) },
			func(m map[string]any) { obj(obj(m["target"])["start"])["started"] = false },
			map[string]string{"ATHN": CovNotStarted},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := evValidate(t, evDoc(t, c.doc), c.facts())
			if r.Report.PT == nil {
				t.Fatal("no coverage report")
			}
			got := map[string]string{}
			for _, row := range r.Report.PT.Rows {
				got[row.Category] = row.Effective
			}
			for cat, w := range c.want {
				if got[cat] != w {
					t.Errorf("%s reads %q, want %q (rows %v)", cat, got[cat], w, got)
				}
			}
			// The counts agree with the rows.
			tally := map[string]int{}
			for _, row := range r.Report.PT.Rows {
				tally[row.Effective]++
			}
			for w, n := range tally {
				if r.Report.PT.Counts[w] != n {
					t.Errorf("count of %s is %d, rows say %d", w, r.Report.PT.Counts[w], n)
				}
			}
			for w, n := range r.Report.PT.Counts {
				if n == 0 {
					t.Errorf("a zero count of %s is kept", w)
				}
			}
		})
	}
}

func TestPTMatchHolds(t *testing.T) {
	hs := []ProbeHeader{{"Content-Type", "application/json"}, {"Set-Cookie", "sid=[REDACTED]; HttpOnly"}}
	cases := []struct {
		name string
		m    PTMatch
		want bool
	}{
		{"empty holds for nothing", PTMatch{}, false},
		{"status", PTMatch{Status: 200}, true},
		{"status differs", PTMatch{Status: 404}, false},
		{"body contains", PTMatch{BodyContains: []string{"leak"}}, true},
		{"body contains is case sensitive", PTMatch{BodyContains: []string{"LEAK"}}, false},
		{"every body text", PTMatch{BodyContains: []string{"leak", "rows"}}, true},
		{"one missing body text", PTMatch{BodyContains: []string{"leak", "absent"}}, false},
		{"body not contains", PTMatch{BodyNotContains: []string{"absent"}}, true},
		{"body not contains fails", PTMatch{BodyNotContains: []string{"leak"}}, false},
		{"header present, case ignored", PTMatch{HeaderPresent: []string{"content-type"}}, true},
		{"header present fails", PTMatch{HeaderPresent: []string{"X-Request-Id"}}, false},
		{"header absent", PTMatch{HeaderAbsent: []string{"X-Request-Id"}}, true},
		{"header absent fails", PTMatch{HeaderAbsent: []string{"set-cookie"}}, false},
		{"header contains, case ignored", PTMatch{HeaderContains: []PTHeader{{Name: "set-cookie", Value: "httponly"}}}, true},
		{"header contains fails", PTMatch{HeaderContains: []PTHeader{{Name: "set-cookie", Value: "samesite"}}}, false},
		{"all parts together", PTMatch{Status: 200, BodyContains: []string{"leak"}, HeaderPresent: []string{"Content-Type"}, HeaderAbsent: []string{"X-Nope"}}, true},
		{"all parts but one", PTMatch{Status: 200, BodyContains: []string{"leak"}, HeaderAbsent: []string{"Content-Type"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.m.Holds(200, `{"leak":"x","rows":[]}`, hs); got != c.want {
				t.Fatalf("Holds = %v, want %v", got, c.want)
			}
		})
	}
}

// TestIndicatorCleaning: the condition's texts are cleaned and capped, a header name
// must be a plain header name, and a condition with nothing left is dropped.
func TestIndicatorCleaning(t *testing.T) {
	cases := []struct {
		name string
		when map[string]any
		want func(t *testing.T, w *PTMatch, r Result)
	}{
		{"texts cleaned, a long one dropped whole", map[string]any{"body_contains": []any{"  two   words\n", strings.Repeat("a", 200), "```", strings.Repeat("b", capMatchText)}}, func(t *testing.T, w *PTMatch, r Result) {
			if len(w.BodyContains) != 2 || w.BodyContains[0] != "two words" || w.BodyContains[1] != strings.Repeat("b", capMatchText) || !hasIssue(r.Report, "V5", "indicator_text_dropped") {
				t.Fatalf("texts = %q, issues %s", w.BodyContains, issueCodes(r.Report))
			}
		}},
		{"a long must-not-contain text is dropped, not shortened", map[string]any{"status": 200, "body_not_contains": []any{strings.Repeat("c", capMatchText+1)}}, func(t *testing.T, w *PTMatch, r Result) {
			if len(w.BodyNotContains) != 0 || !hasIssue(r.Report, "V5", "indicator_text_dropped") {
				t.Fatalf("texts = %q, issues %s", w.BodyNotContains, issueCodes(r.Report))
			}
		}},
		{"a long header text is dropped", map[string]any{"status": 200, "header_contains": []any{map[string]any{"name": "Set-Cookie", "value": strings.Repeat("d", capMatchText+1)}}}, func(t *testing.T, w *PTMatch, r Result) {
			if len(w.HeaderContains) != 0 || !hasIssue(r.Report, "V5", "indicator_text_dropped") || hasIssue(r.Report, "V5", "indicator_header_dropped") {
				t.Fatalf("headers = %+v, issues %s", w.HeaderContains, issueCodes(r.Report))
			}
		}},
		{"a bad header name is dropped", map[string]any{"header_present": []any{"X-Good", "bad name", "x:y"}, "status": 200}, func(t *testing.T, w *PTMatch, r Result) {
			if len(w.HeaderPresent) != 1 || w.HeaderPresent[0] != "X-Good" || !hasIssue(r.Report, "V5", "indicator_header_dropped") {
				t.Fatalf("names = %q, issues %s", w.HeaderPresent, issueCodes(r.Report))
			}
		}},
		{"a header condition needs a name and a text", map[string]any{"header_contains": []any{map[string]any{"name": "Set-Cookie", "value": "httponly"}, map[string]any{"name": "Set-Cookie"}, map[string]any{"value": "x"}}, "status": 200}, func(t *testing.T, w *PTMatch, _ Result) {
			if len(w.HeaderContains) != 1 {
				t.Fatalf("header conditions = %+v", w.HeaderContains)
			}
		}},
		{"a status that is not a status", map[string]any{"status": 99, "body_contains": []any{"x"}}, func(t *testing.T, w *PTMatch, r Result) {
			if w.Status != 0 || !hasIssue(r.Report, "V5", "indicator_status_dropped") {
				t.Fatalf("status %d, issues %s", w.Status, issueCodes(r.Report))
			}
		}},
		{"at most five texts of a kind", map[string]any{"body_contains": []any{"a", "b", "c", "d", "e", "f", "g"}}, func(t *testing.T, w *PTMatch, r Result) {
			if len(w.BodyContains) != maxSmallList || !hasIssue(r.Report, "V3", "cap_exceeded") {
				t.Fatalf("%d texts, issues %s", len(w.BodyContains), issueCodes(r.Report))
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := edit(t, basePentest, func(m map[string]any) {
				obj(arr(m["findings"])[0])["indicator"] = map[string]any{"attack": "p2", "control": "p1", "when": c.when}
			})
			r := Validate(doc, optsFor(ContractPentest))
			f := finding0(t, r)
			if f.Indicator == nil || f.Indicator.When == nil {
				t.Fatalf("no condition kept; issues %s", issueCodes(r.Report))
			}
			c.want(t, f.Indicator.When, r)
		})
	}
	t.Run("a condition with nothing left is dropped", func(t *testing.T) {
		doc := edit(t, basePentest, func(m map[string]any) {
			obj(arr(m["findings"])[0])["indicator"] = map[string]any{"attack": "p2", "control": "p1", "when": map[string]any{"body_contains": []any{"```"}}}
		})
		r := Validate(doc, optsFor(ContractPentest))
		f := finding0(t, r)
		if f.Indicator == nil || f.Indicator.When != nil || !hasIssue(r.Report, "V6", "indicator_condition_empty") {
			t.Fatalf("indicator %+v, issues %s", f.Indicator, issueCodes(r.Report))
		}
	})
	t.Run("an indicator with no id and no condition is dropped", func(t *testing.T) {
		doc := edit(t, basePentest, func(m map[string]any) {
			obj(arr(m["findings"])[0])["indicator"] = map[string]any{"attack": "bad id!"}
		})
		if f := finding0(t, Validate(doc, optsFor(ContractPentest))); f.Indicator != nil {
			t.Fatalf("indicator %+v", f.Indicator)
		}
	})
}

// TestReproductionRequests: a reproduction request is structured and held to a closed
// method list, a restricted path, an allow-list of headers and a short body; a
// plain one-line request from an older file or an agent is read as the same
// structure.
func TestReproductionRequests(t *testing.T) {
	long := strings.Repeat("a", capRequestBody+10)
	cases := []struct {
		name string
		req  any
		want *PTRequest
		code string
	}{
		{
			"structured",
			map[string]any{"method": "post", "path": "/login", "body": `{"u":"a"}`, "headers": []any{map[string]any{"name": "Content-Type", "value": "application/json"}}},
			&PTRequest{Method: "POST", Path: "/login", Body: `{"u":"a"}`, Headers: []PTHeader{{"Content-Type", "application/json"}}}, "",
		},
		{"one line", "GET /notes?q=a%27", &PTRequest{Method: "GET", Path: "/notes?q=a%27"}, ""},
		{"one line with a body", `POST /api/login {"username": "bob"}`, &PTRequest{Method: "POST", Path: "/api/login", Body: `{"username": "bob"}`}, ""},
		{"one line that is no request", "send fifty bad logins", nil, ""},
		{"method not allowed", map[string]any{"method": "TRACE", "path": "/x"}, nil, "request_dropped"},
		{"a path with a space", map[string]any{"method": "GET", "path": "/a b"}, nil, "request_dropped"},
		{"a path with two slashes first", map[string]any{"method": "GET", "path": "//evil.example/x"}, nil, "request_dropped"},
		{"an absolute url", map[string]any{"method": "GET", "path": "http://localhost:3000/x"}, nil, "request_dropped"},
		{"a path that is too long", map[string]any{"method": "GET", "path": "/" + strings.Repeat("a", capRequestPath+1)}, nil, "request_dropped"},
		{"an angle bracket", map[string]any{"method": "GET", "path": "/s?q=<script>"}, nil, "request_dropped"},
		{
			"a header that is not on the list",
			map[string]any{"method": "GET", "path": "/x", "headers": []any{map[string]any{"name": "X-Custom", "value": "v"}}},
			&PTRequest{Method: "GET", Path: "/x"}, "request_header_dropped",
		},
		{
			"a bad header name",
			map[string]any{"method": "GET", "path": "/x", "headers": []any{map[string]any{"name": "Bad Name", "value": "v"}}},
			&PTRequest{Method: "GET", Path: "/x"}, "request_header_dropped",
		},
		{
			"a credential header keeps no value",
			map[string]any{"method": "GET", "path": "/x", "headers": []any{
				map[string]any{"name": "Authorization", "value": "Bearer abc.def.ghi"}, map[string]any{"name": "Cookie", "value": "sid=123"}, map[string]any{"name": "X-Api-Key", "value": "k"},
			}},
			&PTRequest{Method: "GET", Path: "/x", Headers: []PTHeader{{"Authorization", "Bearer [REDACTED]"}, {"Cookie", "[REDACTED]"}, {"X-Api-Key", "[REDACTED]"}}}, "",
		},
		{
			"an authorization value with no scheme",
			map[string]any{"method": "GET", "path": "/x", "headers": []any{map[string]any{"name": "Authorization", "value": "abc"}}},
			&PTRequest{Method: "GET", Path: "/x", Headers: []PTHeader{{"Authorization", "[REDACTED]"}}}, "",
		},
		{"a body over its cap is cut", map[string]any{"method": "POST", "path": "/x", "body": long}, &PTRequest{Method: "POST", Path: "/x", Body: long[:capRequestBody]}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := edit(t, basePentest, func(m map[string]any) {
				obj(arr(m["findings"])[0])["reproduction"] = []any{map[string]any{"step": "Send it", "request": c.req}}
			})
			r := Validate(doc, optsFor(ContractPentest))
			f := finding0(t, r)
			if len(f.Reproduction) != 1 || f.Reproduction[0].Step != "Send it" {
				t.Fatalf("the step was lost: %+v", f.Reproduction)
			}
			got := f.Reproduction[0].Request
			switch {
			case c.want == nil && got != nil:
				t.Fatalf("request kept: %+v", *got)
			case c.want != nil && (got == nil || !equalRequest(*got, *c.want)):
				t.Fatalf("request = %+v, want %+v", got, *c.want)
			}
			if c.code != "" && !hasIssue(r.Report, "V5", c.code) {
				t.Errorf("missing V5:%s; got %s", c.code, issueCodes(r.Report))
			}
		})
	}
	t.Run("at most eight headers", func(t *testing.T) {
		var hs []any
		for i := 0; i < 12; i++ {
			hs = append(hs, map[string]any{"name": "Accept", "value": fmt.Sprint(i)})
		}
		doc := edit(t, basePentest, func(m map[string]any) {
			obj(arr(m["findings"])[0])["reproduction"] = []any{map[string]any{"step": "s", "request": map[string]any{"method": "GET", "path": "/x", "headers": hs}}}
		})
		f := finding0(t, Validate(doc, optsFor(ContractPentest)))
		if n := len(f.Reproduction[0].Request.Headers); n != maxPerItemList {
			t.Fatalf("%d headers kept", n)
		}
	})
}

func equalRequest(a, b PTRequest) bool {
	if a.Method != b.Method || a.Path != b.Path || a.Body != b.Body || len(a.Headers) != len(b.Headers) {
		return false
	}
	for i := range a.Headers {
		if a.Headers[i] != b.Headers[i] {
			return false
		}
	}
	return true
}

// TestRequestPathCharset pins the path rule on its edges.
func TestRequestPathCharset(t *testing.T) {
	for p, want := range map[string]bool{
		"/": true, "/a/b?c=d&e=f#g": true, "/a%20b": true, "/s?q=a'--": true, "/x[0]": true,
		"": false, "a": false, "//a": false, "/a b": false, "/a\"b": false, "/a<b": false, "/a{b}": false, "/a|b": false, "/é": false, "/a\nb": false,
	} {
		if got := ValidRequestPath(p); got != want {
			t.Errorf("ValidRequestPath(%q) = %v", p, got)
		}
	}
	if ValidRequestPath("/" + strings.Repeat("a", capRequestPath)) {
		t.Error("a path over its cap is valid")
	}
}

func TestCitedProbes(t *testing.T) {
	doc := Validate(evDoc(t, func(m map[string]any) {
		obj(arr(m["coverage"])[0])["probes"] = []any{"p11", "p3"}
	}), optsFor(ContractPentest))
	got := CitedProbes(doc.PT)
	if strings.Join(got, ",") != "p1,p2,p3,p11" {
		t.Fatalf("cited = %v", got)
	}
	for id, want := range map[string]int{"p1": 1, "p25": 25, "p": 1 << 30, "x1": 1 << 30, "p1x": 1 << 30} {
		if probeNumber(id) != want {
			t.Errorf("probeNumber(%q) = %d", id, probeNumber(id))
		}
	}
}
