package main

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

const mod = "github.com/x/y"

func day(s string) time.Time {
	d, err := time.Parse(dateLayout, s)
	if err != nil {
		panic(err)
	}
	return d
}

func TestParse(t *testing.T) {
	good := "# header\n\nTestA\tcmd/observer\tlane X\t2026-11-15\tflaky\tP-1\n"
	cases := []struct {
		name, body string
		wantErr    string
		wantN      int
	}{
		{"good entry", good, "", 1},
		{"five fields", "TestA\tcmd/observer\tlane X\t2026-11-15\tflaky\n", "want 6", 0},
		{"empty field", "TestA\tcmd/observer\t \t2026-11-15\tflaky\tP-1\n", "is empty", 0},
		{"bad date", "TestA\tcmd/observer\tlane X\t15/11/2026\tflaky\tP-1\n", "expiry", 0},
		{"subtest name", "TestA/sub\tcmd/observer\tlane X\t2026-11-15\tflaky\tP-1\n", "top-level", 0},
		{"not a test", "BenchmarkA\tcmd/observer\tlane X\t2026-11-15\tflaky\tP-1\n", "top-level", 0},
		{"dot slash package", "TestA\t./cmd/observer\tlane X\t2026-11-15\tflaky\tP-1\n", "module-relative", 0},
		{"trailing slash package", "TestA\tcmd/observer/\tlane X\t2026-11-15\tflaky\tP-1\n", "module-relative", 0},
		{"with a signature", "TestA\tcmd/observer\tlane X\t2026-11-15\tflaky\tP-1\tdirect \\d+ rows\n", "", 1},
		{"bad signature", "TestA\tcmd/observer\tlane X\t2026-11-15\tflaky\tP-1\tdirect (\n", "signature", 0},
		{"empty signature", "TestA\tcmd/observer\tlane X\t2026-11-15\tflaky\tP-1\t \n", "is empty", 0},
		{"eight fields", "TestA\tcmd/observer\tlane X\t2026-11-15\tflaky\tP-1\tx\ty\n", "want 6", 0},
	}
	for _, c := range cases {
		got, err := Parse(strings.NewReader(c.body))
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: err = %v, want it to contain %q", c.name, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if len(got) != c.wantN {
			t.Errorf("%s: %d entries, want %d", c.name, len(got), c.wantN)
		}
	}
}

func TestActive(t *testing.T) {
	e := Entry{Expiry: day("2026-11-15")}
	cases := []struct {
		today string
		want  bool
	}{
		{"2026-11-14", true},
		{"2026-11-15", true}, // the expiry day is the last day it holds
		{"2026-11-16", false},
	}
	for _, c := range cases {
		if got := Active(e, day(c.today)); got != c.want {
			t.Errorf("Active on %s = %v, want %v", c.today, got, c.want)
		}
	}
	if n := len(Expired([]Entry{e, {Expiry: day("2026-12-01")}}, day("2026-11-20"))); n != 1 {
		t.Errorf("Expired = %d, want 1", n)
	}
}

func TestFilter(t *testing.T) {
	entries := []Entry{
		{Test: "TestKnown", Package: "cmd/observer", Owner: "lane X", Expiry: day("2026-11-15"), Line: 1},
		{Test: "TestOld", Package: "cmd/observer", Owner: "lane X", Expiry: day("2026-10-01"), Line: 2},
		{Test: "TestRoot", Package: ".", Owner: "lane Y", Expiry: day("2026-11-15"), Line: 3},
	}
	today := day("2026-11-01")
	cases := []struct {
		name, log   string
		wantKnown   int
		wantUnknown []string
	}{
		{
			"only a known red",
			"=== RUN   TestKnown\n--- FAIL: TestKnown (1.00s)\n    x_test.go:1: boom\nFAIL\nFAIL\t" + mod + "/cmd/observer\t2.0s\nok  \t" + mod + "/internal/a\t0.1s\n",
			1, nil,
		},
		{
			"known red with a failing subtest counted once",
			"--- FAIL: TestKnown (1.00s)\n    --- FAIL: TestKnown/case_1 (0.00s)\nFAIL\t" + mod + "/cmd/observer\t2.0s\n",
			1, nil,
		},
		{
			"a new red still fails",
			"--- FAIL: TestKnown (1.00s)\n--- FAIL: TestNew (0.10s)\nFAIL\t" + mod + "/cmd/observer\t2.0s\n",
			1, []string{"TestNew (cmd/observer)"},
		},
		{
			"same name in another package is not known",
			"--- FAIL: TestKnown (1.00s)\nFAIL\t" + mod + "/internal/store\t2.0s\n",
			0, []string{"TestKnown (internal/store)"},
		},
		{
			"expired entry is not known",
			"--- FAIL: TestOld (1.00s)\nFAIL\t" + mod + "/cmd/observer\t2.0s\n",
			0, []string{"TestOld (cmd/observer)"},
		},
		{
			"build failure is not known",
			"# " + mod + "/internal/a\ninternal/a/a.go:1: syntax error\nFAIL\t" + mod + "/internal/a [build failed]\n",
			0, []string{"internal/a: [build failed]"},
		},
		{
			"timeout with no failing test is not known",
			"panic: test timed out after 10m0s\nFAIL\t" + mod + "/cmd/observer\t600.0s\n",
			0, []string{"cmd/observer: 600.0s"},
		},
		{
			"root package",
			"--- FAIL: TestRoot (0.00s)\nFAIL\t" + mod + "\t0.1s\n",
			1, nil,
		},
		{
			"truncated log",
			"--- FAIL: TestKnown (1.00s)\n",
			0, []string{"TestKnown (package not named in the log)"},
		},
		{
			"other module lines ignored",
			"--- FAIL: TestKnown (1.00s)\nFAIL\tgithub.com/other/mod\t0.1s\n--- FAIL: TestKnown (1.00s)\nFAIL\t" + mod + "/cmd/observer\t0.1s\n",
			1, nil,
		},
	}
	for _, c := range cases {
		res, err := Filter(strings.NewReader(c.log), mod, entries, today)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(res.Known) != c.wantKnown {
			t.Errorf("%s: known = %v, want %d", c.name, res.Known, c.wantKnown)
		}
		if strings.Join(res.Unknown, "|") != strings.Join(c.wantUnknown, "|") {
			t.Errorf("%s: unknown = %q, want %q", c.name, res.Unknown, c.wantUnknown)
		}
	}
}

func TestFilterSignature(t *testing.T) {
	entries := []Entry{
		{Test: "TestSig", Package: "cmd/observer", Owner: "lane X", Expiry: day("2026-11-15"), Line: 1,
			Signature: regexp.MustCompile(`table \S+: direct \d+ rows, relayed \d+`)},
		{Test: "TestNoSig", Package: "cmd/observer", Owner: "lane X", Expiry: day("2026-11-15"), Line: 2},
	}
	today := day("2026-11-01")
	pkgLine := "FAIL\t" + mod + "/cmd/observer\t2.0s\n"
	cases := []struct {
		name, log   string
		wantKnown   int
		wantUnknown string
		wantOutput  string
	}{
		{
			"the known failure matches",
			"--- FAIL: TestSig (1.00s)\n    relay_test.go:230: table actions: direct 4 rows, relayed 3\nFAIL\n" + pkgLine,
			1, "", "direct 4 rows, relayed 3",
		},
		{
			"verbose output before the FAIL line matches too",
			"=== RUN   TestSig\n    relay_test.go:230: table actions: direct 4 rows, relayed 3\n--- FAIL: TestSig (1.00s)\nFAIL\n" + pkgLine,
			1, "", "direct 4 rows, relayed 3",
		},
		{
			"a panic in a listed test is new",
			"--- FAIL: TestSig (1.00s)\npanic: runtime error: invalid memory address [recovered]\nFAIL\n" + pkgLine,
			0, "TestSig (cmd/observer): listed, but the failure does not match its signature", "",
		},
		{
			"another test's matching output does not count",
			"=== RUN   TestOther\n    x_test.go:1: table actions: direct 4 rows, relayed 3\n--- PASS: TestOther (0.00s)\n=== RUN   TestSig\n    relay_test.go:9: new assertion\n--- FAIL: TestSig (1.00s)\nFAIL\n" + pkgLine,
			0, "TestSig (cmd/observer): listed, but the failure does not match its signature", "",
		},
		{
			"an entry with no signature is known whatever the failure",
			"--- FAIL: TestNoSig (1.00s)\n    x_test.go:1: anything\nFAIL\n" + pkgLine,
			1, "", "anything",
		},
	}
	for _, c := range cases {
		res, err := Filter(strings.NewReader(c.log), mod, entries, today)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(res.Known) != c.wantKnown || len(res.Output) != c.wantKnown {
			t.Errorf("%s: known = %v (output %d), want %d", c.name, res.Known, len(res.Output), c.wantKnown)
		}
		got := strings.Join(res.Unknown, "|")
		if (c.wantUnknown == "") != (got == "") || !strings.Contains(got, c.wantUnknown) {
			t.Errorf("%s: unknown = %q, want it to contain %q", c.name, got, c.wantUnknown)
		}
		if c.wantOutput != "" && (len(res.Output) == 0 || !strings.Contains(strings.Join(res.Output[0], "\n"), c.wantOutput)) {
			t.Errorf("%s: output = %q, want it to contain %q", c.name, res.Output, c.wantOutput)
		}
	}
}

func TestTail(t *testing.T) {
	lines := []string{"a", "b", "c"}
	if got := strings.Join(tail(lines, 2), ""); got != "bc" {
		t.Errorf("tail 2 = %q", got)
	}
	if got := strings.Join(tail(lines, 5), ""); got != "abc" {
		t.Errorf("tail 5 = %q", got)
	}
}
