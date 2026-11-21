package explorerview

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeAndValidate(t *testing.T) {
	base := View{Name: " errors ", Filters: map[string]string{"service": " api ", "status": ""}, Columns: []string{"model", "model", " "}}
	v := Normalize(base)
	if v.Name != "errors" || v.Page != PageTraces || v.Scope != ScopePrivate || len(v.Filters) != 1 || v.Filters["service"] != "api" || len(v.Columns) != 1 {
		t.Fatalf("normalize: %+v", v)
	}
	if err := Validate(v, false); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mut    func(*View)
		shared bool
		want   string
	}{
		{"no name", func(v *View) { v.Name = "" }, true, "name"},
		{"long name", func(v *View) { v.Name = strings.Repeat("n", MaxNameLen+1) }, true, "name"},
		{"bad page", func(v *View) { v.Page = "spans" }, true, "page"},
		{"bad scope", func(v *View) { v.Scope = "world" }, true, "scope"},
		{"machine shared", func(v *View) { v.Scope = ScopeOrg }, false, "private"},
		{"team without id", func(v *View) { v.Scope = ScopeTeam }, true, "team_id"},
		{"unknown filter", func(v *View) { v.Filters["tag"] = "x" }, true, "not an explorer filter"},
		{"long value", func(v *View) { v.Filters["user"] = strings.Repeat("u", MaxValueLen+1) }, true, "filter user"},
		{"control", func(v *View) { v.Filters["user"] = "a\nb" }, true, "filter user"},
		{"content no q", func(v *View) { v.Filters["content"] = "1" }, true, "needs q"},
		{"content bad", func(v *View) { v.Filters["content"] = "yes" }, true, "0 or 1"},
		{"bad column", func(v *View) { v.Columns = []string{"secret"} }, true, "column"},
		{"bad group", func(v *View) { v.GroupBy = "weather" }, true, "group_by"},
		{"empty prefix group", func(v *View) { v.GroupBy = "metadata:" }, true, "group_by"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := Normalize(View{Name: "v", Filters: map[string]string{"service": "api"}})
			c.mut(&w)
			err := Validate(w, c.shared)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if strings.Contains(err.Error(), "a\nb") {
				t.Fatal("error leaks a filter value")
			}
		})
	}
	ok := Normalize(View{
		Name: "g", Page: PageGroups, GroupBy: "metadata:plan", Scope: ScopeTeam, TeamID: "t1",
		Filters: map[string]string{"q": "refund", "content": "1"},
	})
	if err := Validate(ok, true); err != nil {
		t.Fatal(err)
	}
	if Normalize(View{Name: "x", Scope: ScopeOrg, TeamID: "t1"}).TeamID != "" {
		t.Fatal("team id kept on an org view")
	}
}

func TestRedactAndNeedsContent(t *testing.T) {
	plain := View{Name: "p", Filters: map[string]string{"service": "api"}, GroupBy: "service"}
	if NeedsContentRead(plain) || Redact(plain).Redacted {
		t.Fatal("an ungated view needs no content read")
	}
	gated := View{Name: "g", Filters: map[string]string{"service": "api", "user": "alice", "trace_tag": "vip"}, GroupBy: "metadata:plan"}
	if !NeedsContentRead(gated) {
		t.Fatal("gated view")
	}
	r := Redact(gated)
	if !r.Redacted || r.Filters["user"] != "" || r.Filters["trace_tag"] != "" || r.Filters["service"] != "api" || r.GroupBy != "" {
		t.Fatalf("redact: %+v", r)
	}
	if gated.Filters["user"] != "alice" {
		t.Fatal("redact mutated its input")
	}
	if !NeedsContentRead(View{GroupBy: "tag"}) || NeedsContentRead(View{GroupBy: "annotation:x"}) {
		t.Fatal("group gating")
	}
}

func TestQueryAndVisible(t *testing.T) {
	v := View{Page: PageGroups, GroupBy: "user", Filters: map[string]string{"service": "api"}}
	q := Query(v)
	if q.Get("by") != "user" || q.Get("service") != "api" {
		t.Fatalf("query: %v", q)
	}
	if Query(View{Page: PageTraces, GroupBy: "user"}).Get("by") != "" {
		t.Fatal("trace page has no by")
	}
	teams := map[string]bool{"t1": true}
	for _, c := range []struct {
		v    View
		want bool
	}{
		{View{Scope: ScopePrivate, Owner: "me"}, true},
		{View{Scope: ScopePrivate, Owner: "other"}, false},
		{View{Scope: ScopeOrg, Owner: "other"}, true},
		{View{Scope: ScopeTeam, Owner: "other", TeamID: "t1"}, true},
		{View{Scope: ScopeTeam, Owner: "other", TeamID: "t2"}, false},
		{View{Scope: ScopeTeam, Owner: "me", TeamID: "t2"}, true},
	} {
		if got := Visible(c.v, "me", teams); got != c.want {
			t.Errorf("%+v: %v", c.v, got)
		}
	}
}

func TestTimeCursorAndSelect(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	c, err := DecodeTimeCursor("", now)
	if err != nil || !c.At.Equal(now.Add(-TailFirstLookback)) {
		t.Fatalf("empty cursor: %+v %v", c, err)
	}
	c = TimeCursor{At: now.Add(123 * time.Millisecond), ID: "b"}
	back, err := DecodeTimeCursor(c.Encode(), now)
	if err != nil || !back.At.Equal(c.At) || back.ID != "b" {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	for _, bad := range []string{"!!", "eA", c.Encode()[:3]} {
		if _, err := DecodeTimeCursor(bad, now); err == nil {
			t.Errorf("%q decoded", bad)
		}
	}
	if c.SecondFloor() != "2026-11-20T10:00:00" {
		t.Fatalf("floor %q", c.SecondFloor())
	}
	cands := []Candidate{
		{"2026-11-20T10:00:00.5Z", "z"},   // after the cursor (later in the second)
		{"2026-11-20T10:00:00.123Z", "a"}, // same stamp, id before cursor
		{"2026-11-20T10:00:00.123Z", "c"}, // same stamp, id after cursor
		{"2026-11-20T10:00:00.1Z", "q"},   // before the cursor
		{"2026-11-20T10:00:01Z", "y"},
		{"not a time", "x"},
	}
	sel := Select(cands, c, 10, false)
	if sel.Unparsed != 1 || sel.More || len(sel.Keep) != 3 {
		t.Fatalf("select: %+v", sel)
	}
	if cands[sel.Keep[0]].ID != "c" || cands[sel.Keep[1]].ID != "z" || cands[sel.Keep[2]].ID != "y" {
		t.Fatalf("order: %+v", sel.Keep)
	}
	if sel.Next.ID != "y" {
		t.Fatalf("next %+v", sel.Next)
	}
	sel = Select(cands, c, 2, false)
	if !sel.More || len(sel.Keep) != 2 || sel.Next.ID != "z" {
		t.Fatalf("limited: %+v", sel)
	}
	sel = Select(nil, c, 5, true)
	if !sel.More || sel.Next != c {
		t.Fatalf("empty full scan: %+v", sel)
	}
}

func TestSeqCursorAndClamp(t *testing.T) {
	if n, ok, err := DecodeSeqCursor(EncodeSeqCursor(42)); err != nil || !ok || n != 42 {
		t.Fatalf("%d %v %v", n, ok, err)
	}
	if _, ok, err := DecodeSeqCursor(""); ok || err != nil {
		t.Fatal("empty")
	}
	for _, bad := range []string{"s", "x1", "s-1", "sabc"} {
		if _, _, err := DecodeSeqCursor(bad); err == nil {
			t.Errorf("%q", bad)
		}
	}
	if ClampPage(0) != TailDefaultPage || ClampPage(999) != TailMaxPage || ClampPage(7) != 7 {
		t.Fatal("clamp")
	}
}

func TestLimiter(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	l := NewLimiter(2*time.Second, 2)
	if ok, _ := l.Allow("a", now); !ok {
		t.Fatal("first poll")
	}
	ok, retry := l.Allow("a", now.Add(500*time.Millisecond))
	if ok || retry != 1500*time.Millisecond {
		t.Fatalf("fast poll: %v %v", ok, retry)
	}
	if ok, _ := l.Allow("a", now.Add(2*time.Second)); !ok {
		t.Fatal("poll after interval")
	}
	l.Allow("b", now.Add(2*time.Second))
	l.Allow("c", now.Add(2500*time.Millisecond)) // evicts the stalest
	if len(l.last) > 2 {
		t.Fatalf("limiter holds %d keys", len(l.last))
	}
}

func TestArrivalKeyAndCompleteSeconds(t *testing.T) {
	c := TimeCursor{At: time.Date(2026, 5, 26, 6, 0, 5, 500_000_000, time.UTC)}
	if got := c.ArrivalKey(); got != "2026-05-26T06:00:05.500000000" {
		t.Fatalf("key %q", got)
	}
	if n, ok := NextSecondFloor("2026-05-26T06:00:59"); !ok || n != "2026-05-26T06:01:00" {
		t.Fatalf("next %q %v", n, ok)
	}
	if _, ok := NextSecondFloor("junk"); ok {
		t.Fatal("junk second parsed")
	}
	for _, tc := range []struct {
		ats  []string
		want int
	}{
		{nil, 0},
		{[]string{"2026-05-26T06:00:05Z", "2026-05-26T06:00:05.5Z"}, 0},
		{[]string{"2026-05-26T06:00:04.9Z", "2026-05-26T06:00:05Z", "2026-05-26T06:00:05.1Z"}, 1},
		{[]string{"2026-05-26T06:00:03Z", "2026-05-26T06:00:04Z", "2026-05-26T06:00:05Z"}, 2},
	} {
		cands := make([]Candidate, len(tc.ats))
		for i, at := range tc.ats {
			cands[i] = Candidate{At: at, ID: "x"}
		}
		if got := CompleteSeconds(cands); got != tc.want {
			t.Errorf("%v: %d, want %d", tc.ats, got, tc.want)
		}
	}
}

// R-C22: a content search's term is content; a plain name search's is not.
func TestRedactDropsTheContentSearchTerm(t *testing.T) {
	r := Redact(View{Filters: map[string]string{"q": "refund policy", "content": "1", "service": "api"}})
	if !r.Redacted || r.Filters["q"] != "" || r.Filters["content"] != "" || r.Filters["service"] != "api" {
		t.Fatalf("content search kept: %+v", r.Filters)
	}
	plain := Redact(View{Filters: map[string]string{"q": "checkout", "user": "u@x"}})
	if plain.Filters["q"] != "checkout" || plain.Filters["user"] != "" {
		t.Fatalf("name search: %+v", plain.Filters)
	}
}

func TestTailLimiterKey(t *testing.T) {
	for _, tc := range []struct{ host, client, want string }{
		{"127.0.0.1", "", "127.0.0.1"},
		{"127.0.0.1", "tab_1-a", "127.0.0.1|tab_1-a"},
		{"127.0.0.1", "bad id", "127.0.0.1"},
		{"127.0.0.1", "a|b", "127.0.0.1"},
		{"127.0.0.1", strings.Repeat("x", MaxTailClientLen+1), "127.0.0.1"},
	} {
		if got := TailLimiterKey(tc.host, tc.client); got != tc.want {
			t.Errorf("TailLimiterKey(%q, %q) = %q, want %q", tc.host, tc.client, got, tc.want)
		}
	}
}
