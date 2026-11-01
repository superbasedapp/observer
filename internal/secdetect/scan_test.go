package secdetect

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Fake credentials shaped like real ones; none is a live key. The AWS id is
// visibly fake but not an ...EXAMPLE value: knownExample never fires on one
// (the "aws documentation key never fires" case below pins that).
const (
	fakeAWSKeyID = "AKIA" + "FAKEFIXTURE0TEST" // split: GitHub push protection on the public mirror
	fakeGitHub   = "ghp_" + "Zx9Kq2Lm8Np4Rt6Vw1Yb3Cd5Ef7Gh0Jk2Ln4"
)

func TestScanTable(t *testing.T) {
	cases := []struct {
		name    string
		text    string
		path    string
		status  Status
		types   []string
		fixture bool
	}{
		{"clean code", "package main\n\nfunc main() {}\n", "main.go", StatusClean, nil, false},
		{"aws key id", "package cfg\n\nconst id = \"" + fakeAWSKeyID + "\"\n", "config/prod.go", StatusHits, []string{"aws_access_key"}, false},
		{"github token line", "a\nb\ntoken := \"" + fakeGitHub + "\"\n", "x.go", StatusHits, []string{"github_pat"}, false},
		{"fixture path", "k = \"" + fakeAWSKeyID + "\"\n", "internal/x/testdata/k.txt", StatusHits, []string{"aws_access_key"}, true},
		{"aws documentation key never fires", "id = \"AKIAIOSFODNN7EXAMPLE\"\n", "README.md", StatusClean, nil, false},
		{"empty", "", "", StatusClean, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ScanHook(tc.text, tc.path)
			if r.Status != tc.status {
				t.Fatalf("status = %s, want %s (hits %+v)", r.Status, tc.status, r.Hits)
			}
			var got []string
			for _, h := range r.Hits {
				if h.Blocking() {
					got = append(got, h.Type)
				}
				if h.Fixture != tc.fixture {
					t.Errorf("fixture = %v, want %v", h.Fixture, tc.fixture)
				}
			}
			if strings.Join(got, ",") != strings.Join(tc.types, ",") {
				t.Fatalf("types = %v, want %v", got, tc.types)
			}
		})
	}
}

func TestScanLineNumber(t *testing.T) {
	r := ScanHook("one\ntwo\nthree\nk = \""+fakeAWSKeyID+"\"\n", "a.py")
	if len(r.Hits) != 1 || r.Hits[0].Line != 4 {
		t.Fatalf("hits = %+v, want one on line 4", r.Hits)
	}
}

// TestScanOverCap: content past the fixed 16 KiB cap is not scanned and the
// result is scan_incomplete, with hits before the cut still listed.
func TestScanOverCap(t *testing.T) {
	head := "k = \"" + fakeAWSKeyID + "\"\n"
	filler := strings.Repeat("x = 1 # filler line for the cap test\n", (HookMaxBytes/38)+50)
	tail := "t = \"" + fakeGitHub + "\"\n"
	r := ScanHook(head+filler+tail, "a.py")
	if r.Status != StatusIncomplete || r.Reason != ReasonOverCap {
		t.Fatalf("status %s reason %s, want scan_incomplete over_cap", r.Status, r.Reason)
	}
	if r.Scanned > HookMaxBytes {
		t.Fatalf("scanned %d > cap %d", r.Scanned, HookMaxBytes)
	}
	if len(r.Hits) != 1 || r.Hits[0].Type != "aws_access_key" {
		t.Fatalf("hits = %+v, want only the head key", r.Hits)
	}
}

// TestScanDeadline: a clock past the deadline after the first slice ends
// the scan scan_incomplete with reason deadline.
func TestScanDeadline(t *testing.T) {
	base := time.Unix(1000, 0)
	calls := 0
	clock := func() time.Time {
		calls++
		if calls == 1 {
			return base
		}
		return base.Add(time.Second)
	}
	text := strings.Repeat("line of ordinary code here\n", 600) // > one slice
	r := Scanner{Now: clock}.Scan(text, "a.go", HookLimits)
	if r.Status != StatusIncomplete || r.Reason != ReasonDeadline {
		t.Fatalf("status %s reason %s, want scan_incomplete deadline", r.Status, r.Reason)
	}
	if r.Scanned >= len(text) {
		t.Fatalf("scanned everything despite the deadline")
	}
}

// TestScanSliceBoundary: a secret on a slice boundary is found once.
func TestScanSliceBoundary(t *testing.T) {
	for off := chunkBytes - 40; off < chunkBytes+10; off += 7 {
		pad := strings.Repeat("a", off)
		text := pad + " k=\"" + fakeAWSKeyID + "\" \n" + strings.Repeat("b\n", 2000)
		r := Scanner{}.Scan(text, "", Limits{MaxBytes: 1 << 20})
		n := 0
		for _, h := range r.Hits {
			if h.Type == "aws_access_key" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("offset %d: %d aws hits, want 1 (%+v)", off, n, r.Hits)
		}
	}
}

// TestScanEntropyNeverBlocks: an uncertain detection is low confidence.
func TestScanEntropyNeverBlocks(t *testing.T) {
	det := func(string) []scrub.TypedFinding {
		return []scrub.TypedFinding{{Type: "entropy", Certain: false, Start: 0, End: 3}}
	}
	r := Scanner{Detect: det}.Scan("abc", "a", Limits{MaxBytes: 100})
	if r.Status != StatusClean || len(r.Hits) != 1 || r.Hits[0].Blocking() {
		t.Fatalf("entropy result = %+v", r)
	}
}

func TestPostWriteLimits(t *testing.T) {
	if PostWriteLimits(64).MaxBytes != 64<<10 || PostWriteLimits(256).MaxBytes != 256<<10 || PostWriteLimits(0).MaxBytes != 256<<10 {
		t.Fatal("post-write caps")
	}
	if HookLimits.MaxBytes != 16<<10 {
		t.Fatal("hook cap must stay 16 KiB")
	}
}

func TestIsFixturePath(t *testing.T) {
	cases := map[string]bool{
		"internal/x/testdata/a.json":    true,
		"src/__fixtures__/k.txt":        true,
		"pkg/a_test.go":                 true,
		`C:\repo\tests\conf.py`:         true,
		"web/src/app.spec.ts":           true,
		"config/.env.example":           true,
		"config/prod.py":                false,
		"latest/main.go":                false,
		"":                              false,
		"contest/x.go":                  false,
		"docs/examples/aws-config.toml": true,
	}
	for p, want := range cases {
		if got := IsFixturePath(p); got != want {
			t.Errorf("IsFixturePath(%q) = %v, want %v", p, got, want)
		}
	}
}

// BenchmarkScanHookWorst16KiB is the in-hook worst case the JSP-2 budget
// names: 16 KiB dense with detector gate words.
func BenchmarkScanHookWorst16KiB(b *testing.B) {
	line := "password = token secret api_key bearer AKIA ghp_ -----BEGIN x=1\n"
	text := strings.Repeat(line, HookMaxBytes/len(line))
	b.SetBytes(int64(len(text)))
	for i := 0; i < b.N; i++ {
		_ = Scanner{}.Scan(text, "a.go", Limits{MaxBytes: HookMaxBytes})
	}
}

// TestIdentifyAndSecretFinding: a hit carries the keyed identity, never the
// value, and SecretFinding keys the same secret the same way on any line.
func TestIdentifyAndSecretFinding(t *testing.T) {
	const key = fakeAWSKeyID // shaped like an AWS key id; not a live key
	var seen []string
	s := Scanner{Identify: func(typ, value string) string { seen = append(seen, value); return "id-" + typ }}
	r := s.Scan("x = 1\nk = \""+key+"\"\n", "cfg.py", PostWriteLimits(0))
	if len(r.Hits) != 1 || r.Hits[0].Identity != "id-aws_access_key" || len(seen) != 1 || seen[0] != key {
		t.Fatalf("hits %+v, identify saw %v", r.Hits, seen)
	}
	a, ok := SecretFinding(FindingInput{ProjectRootHash: "p", Path: "cfg.py", Line: 2, Hit: r.Hits[0], Scope: "post_write"})
	b, _ := SecretFinding(FindingInput{ProjectRootHash: "p", Path: "other.py", Line: 9, Hit: r.Hits[0], Scope: "post_write"})
	if !ok || a.LocalKey == "" || a.LocalKey != b.LocalKey || a.Rule.ID != "secret.aws_access_key" {
		t.Fatalf("findings %+v / %+v", a, b)
	}
	if strings.Contains(a.Message+a.FixHint+a.EvidenceRedacted, key) {
		t.Fatal("the finding carries the value")
	}
	low := r.Hits[0]
	low.Confidence = ConfidenceLow
	if _, ok := SecretFinding(FindingInput{ProjectRootHash: "p", Hit: low}); ok {
		t.Fatal("a non-blocking hit was stored")
	}
	if _, ok := SecretFinding(FindingInput{ProjectRootHash: "p", Hit: Hit{Type: "x", Confidence: ConfidenceHigh}}); ok {
		t.Fatal("a hit with no identity was stored")
	}
}
