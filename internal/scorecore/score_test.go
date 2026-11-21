package scorecore

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/genaiattr"
)

const tid = "4bf92f3577b34da6a3ce929d0e0e4736"

func fixedNow() time.Time { return time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC) }

func TestDecodeValueKindTable(t *testing.T) {
	cases := []struct {
		raw     string
		want    Kind
		kind    Kind
		text    string
		num     *float64
		errCode string
	}{
		{raw: `0.8`, kind: KindNumeric, text: "0.8", num: f(0.8)},
		{raw: `3`, want: KindNumeric, kind: KindNumeric, text: "3", num: f(3)},
		{raw: `true`, kind: KindBoolean, text: "true", num: f(1)},
		{raw: `false`, want: KindBoolean, kind: KindBoolean, text: "false", num: f(0)},
		{raw: `" good "`, kind: KindCategorical, text: "good"},
		{raw: `"a\nb"`, errCode: CodeInvalidValue},
		{raw: `""`, errCode: CodeInvalidValue},
		{raw: `null`, errCode: CodeInvalidValue},
		{raw: `[1]`, errCode: CodeInvalidValue},
		{raw: `1e999`, errCode: CodeInvalidValue},
		{raw: `"x"`, want: KindNumeric, errCode: CodeKindMismatch},
		{raw: `1`, want: "weird", errCode: CodeInvalidValue},
	}
	for _, c := range cases {
		k, text, num, err := DecodeValue(json.RawMessage(c.raw), c.want)
		if c.errCode != "" {
			if err == nil || err.Code != c.errCode {
				t.Errorf("%s: want %s, got %v", c.raw, c.errCode, err)
			}
			continue
		}
		if err != nil || k != c.kind || text != c.text || !sameNum(num, c.num) {
			t.Errorf("%s: got %s %q %v %v", c.raw, k, text, num, err)
		}
	}
}

func TestSourceTable(t *testing.T) {
	for _, r := range sourceTable {
		if !ValidSource(r.Source) || ClientSource(r.Source) != r.Client {
			t.Errorf("row %+v", r)
		}
	}
	if ClientSource("nope") || ValidSource("nope") {
		t.Error("unknown source accepted")
	}
}

func TestAuthorTable(t *testing.T) {
	p := AuthorParts{ID: "abc", EventDigest: "dd", Member: "m1", Run: "r1", Version: "v2"}
	want := map[Source]string{
		SourceSDK: "id:abc", SourceFeedback: "id:abc", SourceOTel: "id:abc",
		SourceUser: "user:m1", SourceReview: "user:m1", SourceEval: "run:r1@v2",
		SourceLLM: "run:r1", SourceRule: "run:r1",
	}
	for _, r := range authorTable {
		if got := AuthorKey(r.Source, p); got != want[r.Source] {
			t.Errorf("%s: %q want %q", r.Source, got, want[r.Source])
		}
	}
	if got := AuthorKey(SourceOTel, AuthorParts{EventDigest: "dd"}); got != "ev:dd" {
		t.Errorf("otel digest: %q", got)
	}
	if AuthorKey(SourceUser, AuthorParts{}) != "" || AuthorKey(SourceLLM, AuthorParts{}) != "" {
		t.Error("empty parts must keep the legacy empty author")
	}
}

func TestNormalize(t *testing.T) {
	opt := Options{DefaultSource: SourceSDK, NewID: func() string { return "minted" }, Now: fixedNow}
	s, err := Normalize(Input{
		ID: "c1", TraceID: "4BF92F3577B34DA6A3CE929D0E0E4736", SpanID: "00F067AA0BA902B7",
		Name: "Helpfulness", Value: json.RawMessage(`0.25`), Comment: " ok ", Scorer: &Scorer{Name: "j", Version: "3"},
	}, opt)
	if err != nil {
		t.Fatal(err)
	}
	if s.TraceID != tid || s.SpanID != "00f067aa0ba902b7" || s.Key != "helpfulness" || s.Author != "id:c1" ||
		s.ClientID != "c1" || s.Comment != "ok" || s.Source != SourceSDK || !s.At.Equal(fixedNow()) {
		t.Fatalf("%+v", s)
	}
	s2, err := Normalize(Input{TraceID: tid, Name: "x", Value: json.RawMessage(`true`), Source: SourceFeedback}, opt)
	if err != nil || s2.Author != "id:minted" || s2.ClientID != "" || s2.Source != SourceFeedback {
		t.Fatalf("%+v %v", s2, err)
	}
	bad := []struct {
		in   Input
		code string
	}{
		{Input{TraceID: "xyz", Name: "a", Value: json.RawMessage(`1`)}, CodeInvalidTraceID},
		{Input{TraceID: "00000000000000000000000000000000", Name: "a", Value: json.RawMessage(`1`)}, CodeInvalidTraceID},
		{Input{TraceID: tid, SpanID: "12", Name: "a", Value: json.RawMessage(`1`)}, CodeInvalidSpanID},
		{Input{TraceID: tid, Name: "a b", Value: json.RawMessage(`1`)}, CodeInvalidName},
		{Input{TraceID: tid, Name: "a", Value: json.RawMessage(`1`), Source: SourceEval}, CodeInvalidSource},
		{Input{TraceID: tid, Name: "a", Value: json.RawMessage(`1`), ID: "a b"}, CodeInvalidID},
		{Input{TraceID: tid, Name: "a", Value: json.RawMessage(`1`), Timestamp: "yesterday"}, CodeInvalidTime},
		{Input{TraceID: tid, Name: "a", Value: json.RawMessage(`1`), Scorer: &Scorer{Version: "1"}}, CodeInvalidScorer},
		{Input{TraceID: tid, Name: "a", Value: json.RawMessage(`1`), Comment: string(make([]byte, MaxCommentBytes+1))}, CodeCommentTooLong},
	}
	for _, b := range bad {
		if _, err := Normalize(b.in, opt); err == nil || err.Code != b.code {
			t.Errorf("%+v: want %s got %v", b.in, b.code, err)
		}
	}
}

func TestDecodeBatch(t *testing.T) {
	one, err := DecodeBatch([]byte(`{"trace_id":"x","name":"a","value":1}`))
	if err != nil || len(one) != 1 {
		t.Fatal(one, err)
	}
	many, err := DecodeBatch([]byte(`{"scores":[{"name":"a"},{"name":"b"}]}`))
	if err != nil || len(many) != 2 {
		t.Fatal(many, err)
	}
	for body, code := range map[string]string{
		`[]`: CodeBadRequest, `{"scores":[]}`: CodeBadRequest, `{"scores":3}`: CodeBadRequest, `{`: CodeBadRequest,
	} {
		if _, err := DecodeBatch([]byte(body)); err == nil || err.Code != code {
			t.Errorf("%s: %v", body, err)
		}
	}
	big := `{"scores":[` + repeat(`{},`, MaxBatch) + `{}]}`
	if _, err := DecodeBatch([]byte(big)); err == nil || err.Code != CodeTooMany {
		t.Errorf("too many: %v", err)
	}
}

// TestScoreIDGolden pins ScoreID against the shared fixture the SDK lanes use.
func TestScoreIDGolden(t *testing.T) {
	b, err := os.ReadFile("testdata/score_ids.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		TraceID, SpanID, Key, Source, Author, ID string
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no golden cases")
	}
	for _, c := range cases {
		if got := ScoreID(c.TraceID, c.SpanID, c.Key, c.Source, c.Author); got != c.ID {
			t.Errorf("%+v: got %s", c, got)
		}
	}
}

func TestFromEvaluation(t *testing.T) {
	at := fixedNow()
	s, err := FromEvaluation(genaiattr.Evaluation{Name: "Relevance", ScoreValue: f(0.9), Label: "relevant", Explanation: "why"}, tid, "00f067aa0ba902b7", at)
	if err != nil || s.Kind != KindNumeric || s.Value != "relevant" || *s.ValueNum != 0.9 || s.Source != SourceOTel || s.Comment != "why" {
		t.Fatalf("%+v %v", s, err)
	}
	again, _ := FromEvaluation(genaiattr.Evaluation{Name: "relevance", ScoreValue: f(0.1)}, tid, "00f067aa0ba902b7", at)
	if again.Author != s.Author || again.ID() != s.ID() {
		t.Fatal("a re-delivered event must land on the same row")
	}
	c, err := FromEvaluation(genaiattr.Evaluation{Name: "tone", Label: "polite", Source: "feedback", ScoreID: "fb-1"}, tid, "", at)
	if err != nil || c.Kind != KindCategorical || c.Source != SourceFeedback || c.Author != "id:fb-1" {
		t.Fatalf("%+v %v", c, err)
	}
	for _, ev := range []genaiattr.Evaluation{{Name: "x", ScoreValue: f(1), ErrorType: "timeout"}, {Name: "x"}} {
		if _, err := FromEvaluation(ev, tid, "", at); err == nil {
			t.Errorf("%+v accepted", ev)
		}
	}
}

func TestPassed(t *testing.T) {
	cases := []struct {
		k    Kind
		v    string
		n    *float64
		want bool
	}{
		{KindBoolean, "true", f(1), true},
		{KindBoolean, "false", f(0), false},
		{KindNumeric, "0.5", f(0.5), true},
		{KindNumeric, "0.49", f(0.49), false},
		{KindCategorical, "good", nil, true},
		{KindCategorical, "FAIL", nil, false},
	}
	for _, c := range cases {
		if Passed(c.k, c.v, c.n) != c.want {
			t.Errorf("%+v", c)
		}
	}
}

func f(v float64) *float64 { return &v }

func sameNum(a, b *float64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
