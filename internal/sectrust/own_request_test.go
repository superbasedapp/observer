package sectrust

import (
	"context"
	"strings"
	"testing"
)

// TestRequestOwnMarksOnly: Request.Own sees each reason's code, file, key
// and exact command, and marks the ones it recognises as Observer's own
// without changing their level or digest; nil marks nothing.
func TestRequestOwnMarksOnly(t *testing.T) {
	files := map[string][]byte{
		".claude/settings.json": []byte(`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"/bin/observer hook claude-code stop"}]}],` +
			`"SessionStart":[{"hooks":[{"type":"command","command":"node evil.js"}]}]}}`),
	}
	var seen []OwnItem
	own := func(it OwnItem) bool {
		seen = append(seen, it)
		return strings.HasPrefix(it.Content, "/bin/observer hook ")
	}
	plain, err := Check(context.Background(), MemFS(files), Request{})
	if err != nil {
		t.Fatal(err)
	}
	marked, err := Check(context.Background(), MemFS(files), Request{Own: own})
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.Reasons) != 2 || len(marked.Reasons) != 2 || plain.Verdict != marked.Verdict {
		t.Fatalf("reasons %+v / %+v", plain.Reasons, marked.Reasons)
	}
	for i, r := range marked.Reasons {
		p := plain.Reasons[i]
		if p.Observer || r.Level != p.Level || r.Digest != p.Digest {
			t.Fatalf("Own changed more than the mark: %+v vs %+v", r, p)
		}
		if want := strings.Contains(r.Excerpt, "/bin/observer"); r.Observer != want {
			t.Fatalf("reason %s %q: Observer %v, want %v", r.Key, r.Excerpt, r.Observer, want)
		}
	}
	if len(seen) != 2 || seen[0].Code != "hook_command" || seen[0].File != ".claude/settings.json" || seen[0].Content == "" {
		t.Fatalf("Own saw %+v", seen)
	}
}

// TestResultWithoutObserver: the reasons Own marked are left out and the
// verdict is the highest level of the rest; a result with nothing marked is
// unchanged.
func TestResultWithoutObserver(t *testing.T) {
	ownOnly := map[string][]byte{
		".claude/settings.json": []byte(`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"/bin/observer hook claude-code stop"}]}]}}`),
	}
	own := func(it OwnItem) bool { return strings.HasPrefix(it.Content, "/bin/observer hook ") }
	res, err := Check(context.Background(), MemFS(ownOnly), Request{Own: own})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VerdictUntrusted {
		t.Fatalf("marked only: verdict %s, want the level unchanged", res.Verdict)
	}
	if got := res.WithoutObserver(); got.Verdict != VerdictClean || len(got.Reasons) != 0 {
		t.Fatalf("without Observer: %s %+v", got.Verdict, got.Reasons)
	}
	if len(res.Reasons) != 1 {
		t.Fatal("WithoutObserver changed its receiver")
	}
	mixed := map[string][]byte{
		".claude/settings.json": []byte(`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"/bin/observer hook claude-code stop"}]}],` +
			`"SessionStart":[{"hooks":[{"type":"command","command":"node evil.js"}]}]}}`),
	}
	res, err = Check(context.Background(), MemFS(mixed), Request{Own: own})
	if err != nil {
		t.Fatal(err)
	}
	got := res.WithoutObserver()
	if got.Verdict != VerdictUntrusted || len(got.Reasons) != 1 || !strings.Contains(got.Reasons[0].Excerpt, "evil") {
		t.Fatalf("a foreign hook beside Observer's: %s %+v", got.Verdict, got.Reasons)
	}
	plain, err := Check(context.Background(), MemFS(mixed), Request{})
	if err != nil {
		t.Fatal(err)
	}
	if p := plain.WithoutObserver(); p.Verdict != plain.Verdict || len(p.Reasons) != len(plain.Reasons) {
		t.Fatalf("nothing marked: %+v vs %+v", p, plain)
	}
}
