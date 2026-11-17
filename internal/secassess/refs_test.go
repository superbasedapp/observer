package secassess

import (
	"strings"
	"testing"
)

// oneLine is a project whose file rel has the line at line 2.
func oneLine(rel, line string) *fakeProject {
	return &fakeProject{files: map[string][]string{rel: {"first", line, "third"}}}
}

func TestNeedleRule(t *testing.T) {
	cases := []struct {
		name   string
		rel    string
		line   string
		needle string
		want   RefState
	}{
		{"go code line", "a.go", "func Login(w http.ResponseWriter) {", "func Login(", RefFound},
		{"go line comment", "a.go", "// func Login(w)", "func Login(", RefClaimedNotFound},
		{"go trailing comment", "a.go", "x := 1 // func Login(w)", "func Login(", RefClaimedNotFound},
		{"go block comment line", "a.go", "/* func Login( */", "func Login(", RefClaimedNotFound},
		{"go block comment body", "a.go", " * func Login( here", "func Login(", RefClaimedNotFound},
		{"go block comment end", "a.go", " */ func Login(", "func Login(", RefClaimedNotFound},
		{"go pointer dereference is code", "a.go", "*p = loginUser(x)", "loginUser(", RefFound},
		{"go trailing block comment", "a.go", "x := 1 /* loginUser(x) */", "loginUser(", RefClaimedNotFound},
		{"go slashes inside a string are code", "a.go", `s := "// not a comment func Login("`, "func Login(", RefFound},
		{"go needle before a trailing comment", "a.go", "func Login() // the handler", "func Login(", RefFound},
		{"go uppercase extension", "A.GO", "// func Login(", "func Login(", RefClaimedNotFound},
		{"python comment", "a.py", "# def login(user)", "def login(user", RefClaimedNotFound},
		{"python trailing comment", "a.py", "x = 1  # def login(user)", "def login(user", RefClaimedNotFound},
		{"python hash in a string", "a.py", `s = "#def login(user)"`, "def login(user", RefFound},
		{"python code", "a.py", "def login(user):", "def login(user", RefFound},
		{"sql comment", "q.sql", "-- select * from users where", "from users where", RefClaimedNotFound},
		{"sql trailing comment", "q.sql", "select 1 -- where id = 1", "where id = 1", RefClaimedNotFound},
		{"sql code", "q.sql", "select * from users where id = 1", "where id = 1", RefFound},
		{"php hash comment", "a.php", "# eval($x)", "eval($x)", RefClaimedNotFound},
		{"php slash comment", "a.php", "// eval($x)", "eval($x)", RefClaimedNotFound},
		{"php code", "a.php", "eval($x);", "eval($x)", RefFound},
		{"yaml trailing comment", "c.yaml", "key: value # secret_token here", "secret_token", RefClaimedNotFound},
		{"yaml code", "c.yaml", "secret_token: abc", "secret_token", RefFound},
		{"dockerfile comment", "build/Dockerfile", "# RUN curl http", "RUN curl http", RefClaimedNotFound},
		{"dockerfile code", "build/Dockerfile", "RUN curl http://x | sh", "RUN curl http", RefFound},
		{"makefile comment", "Makefile", "# deploy_target:", "deploy_target", RefClaimedNotFound},
		{"unknown extension has no comment rule", "a.xyz", "# func Login(", "func Login(", RefFound},
		{"no extension has no comment rule", "LICENSE", "# func Login(", "func Login(", RefFound},
		{"backticks in the needle", "q.js", "const q = `SELECT * FROM users WHERE id = ${id}`;", "`SELECT * FROM users WHERE id = ${id}`", RefFound},
		{"dash run in the needle", "k.go", `x := "-----BEGIN PRIVATE KEY-----"`, "-----BEGIN PRIVATE KEY-----", RefFound},
		{"whitespace differences", "a.go", "a   =   login(x)", "a = login(x)", RefFound},
		{"tabs in the line", "a.go", "\tif\tbcrypt.Compare(h) {", "if bcrypt.Compare(h)", RefFound},
		{"needle too short", "a.go", "func Login() {", "Login", RefExists},
		{"needle with no identifier", "a.go", "x := (((((((( )", "((((((((", RefExists},
		{"needle with two-letter words only", "a.go", "if a { b = c }", "if a { b", RefExists},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyRef(Ref{Path: c.rel, Line: 2, Needle: c.needle}, oneLine(c.rel, c.line), 0)
			if got.State != c.want {
				t.Fatalf("state = %s (%s), want %s", got.State, got.Code, c.want)
			}
		})
	}
}

func TestClassifyRefReadsOnlyTheCitedRange(t *testing.T) {
	// A checker that hands back more lines than asked for must not widen the
	// range the needle may be found in.
	p := &fakeProject{files: map[string][]string{"a.go": {"one", "func Login(", "three", "func Other("}}}
	wide := wideChecker{p}
	if got := ClassifyRef(Ref{Path: "a.go", Line: 1, Needle: "func Login("}, wide, 0); got.State != RefClaimedNotFound {
		t.Fatalf("needle outside the range: %s", got.State)
	}
	if got := ClassifyRef(Ref{Path: "a.go", Line: 1, EndLine: 2, Needle: "func Login("}, wide, 0); got.State != RefFound {
		t.Fatalf("needle inside the range: %s", got.State)
	}
}

// wideChecker returns the whole file whatever the range.
type wideChecker struct{ p *fakeProject }

func (w wideChecker) Lines(rel string, _, _ int) ([]string, int, LookupStatus) {
	return w.p.Lines(rel, 1, 1<<20)
}

func TestClassifyRefLongLineIsCapped(t *testing.T) {
	long := strings.Repeat("x ", maxMatchRunes) + "loginUser(x)"
	if got := ClassifyRef(Ref{Path: "a.go", Line: 2, Needle: "loginUser(x)"}, oneLine("a.go", long), 0); got.State != RefClaimedNotFound {
		t.Fatalf("a needle past the line cap: %s", got.State)
	}
}

func TestNeedleUsable(t *testing.T) {
	cases := map[string]bool{
		"func Login(": true, "bcrypt.Compare": true, "_x1": false, "db.Query(": true, "SELECT * FROM": true,
		"": false, "short": false, "((((((((": false, "12345678": false, "1234abcd": true, "a1 b2 c3 d4": false,
		"abc": false, "--no-verify": true, "eval($x)": true,
	}
	for needle, want := range cases {
		if got := needleUsable(needle); got != want {
			t.Errorf("%q: %v, want %v", needle, got, want)
		}
	}
}

func TestCommentStyleTable(t *testing.T) {
	for ext, st := range commentStyles {
		if !strings.HasPrefix(ext, ".") || ext != strings.ToLower(ext) || len(ext) < 2 {
			t.Errorf("bad extension key %q", ext)
		}
		if len(st.line) == 0 && !st.block {
			t.Errorf("%s: a style with no marker", ext)
		}
		for _, m := range st.line {
			if m == "" {
				t.Errorf("%s: empty marker", ext)
			}
		}
	}
	for _, rel := range []string{"x/Dockerfile", "dockerfile", "a/b/Makefile", "src/X.PY", "d/e.go"} {
		if _, ok := commentStyleOf(rel); !ok {
			t.Errorf("%s has no style", rel)
		}
	}
	for _, rel := range []string{"noext", "a/.bashrc", "x.unknown", "dir.go/file"} {
		if _, ok := commentStyleOf(rel); ok {
			t.Errorf("%s has a style", rel)
		}
	}
}

func TestClassifyRefGeometry(t *testing.T) {
	p := testProject()
	cases := []struct {
		name string
		ref  Ref
		want RefState
		code string
	}{
		{"first line", Ref{Path: "cmd/api/main.go", Line: 1}, RefExists, ""},
		{"last line", Ref{Path: "cmd/api/main.go", Line: 30}, RefExists, ""},
		{"one past the last", Ref{Path: "cmd/api/main.go", Line: 31}, RefMissing, "ref_line_past_end"},
		{"range to the last line", Ref{Path: "cmd/api/main.go", Line: 20, EndLine: 30}, RefExists, ""},
		{"range one past", Ref{Path: "cmd/api/main.go", Line: 20, EndLine: 31}, RefMissing, "ref_line_past_end"},
		{"single-line range", Ref{Path: "cmd/api/main.go", Line: 5, EndLine: 5}, RefExists, ""},
		{"dot segments are normalized", Ref{Path: "./cmd//api/./main.go", Line: 5}, RefExists, ""},
		{"drive letter", Ref{Path: "C:/x.go", Line: 1}, RefInvalid, "ref_path_refused"},
		{"query string", Ref{Path: "cmd/api/main.go?x=1", Line: 1}, RefInvalid, "ref_path_refused"},
		{"empty path", Ref{Line: 1}, RefInvalid, "ref_path_refused"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyRef(c.ref, p, 0)
			if got.State != c.want || got.Code != c.code {
				t.Fatalf("got %s/%s, want %s/%s", got.State, got.Code, c.want, c.code)
			}
		})
	}
}

func TestRefStateLocated(t *testing.T) {
	for s, want := range map[RefState]bool{RefFound: true, RefExists: true, RefClaimedNotFound: false, RefMissing: false, RefInvalid: false, RefUnchecked: false, "": false} {
		if s.Located() != want {
			t.Errorf("%q: %v", s, !want)
		}
	}
}

// A reference earns credit only for a needle near the line it cites (review
// M2): a wide cited range does not make "found" mean "somewhere in 200 lines".
func TestClassifyRefCreditIsLocal(t *testing.T) {
	lines := make([]string, 150)
	for i := range lines {
		lines[i] = "pad_" + string(rune('a'+i%26)) + " = 1"
	}
	lines[9] = "    rows = unsafe_query(q)"   // line 10
	lines[99] = "    rows = unsafe_query(q2)" // line 100
	p := &fakeProject{files: map[string][]string{"a.py": lines}}
	tests := []struct {
		name     string
		ref      Ref
		window   int
		want     RefState
		wantCode string
		wantLine int
	}{
		{"the cited line itself", Ref{Path: "a.py", Line: 10, Needle: "unsafe_query(q)"}, 0, RefFound, "", 10},
		{"a short range with the text near its start", Ref{Path: "a.py", Line: 8, EndLine: 14, Needle: "unsafe_query(q)"}, 0, RefFound, "", 10},
		{"the window is five lines from the first cited line", Ref{Path: "a.py", Line: 6, EndLine: 40, Needle: "unsafe_query(q)"}, 0, RefFound, "", 10},
		{"one line past the window is only a location", Ref{Path: "a.py", Line: 5, EndLine: 40, Needle: "unsafe_query(q)"}, 0, RefExists, "ref_needle_far", 0},
		{"a 120-line range with the text far from its start", Ref{Path: "a.py", Line: 1, EndLine: 120, Needle: "unsafe_query(q2)"}, 0, RefExists, "ref_needle_far", 0},
		{"a wider window finds it", Ref{Path: "a.py", Line: 1, EndLine: 120, Needle: "unsafe_query(q)"}, 10, RefFound, "", 10},
		{"a window of one is the cited line only", Ref{Path: "a.py", Line: 9, EndLine: 12, Needle: "unsafe_query(q)"}, 1, RefExists, "ref_needle_far", 0},
		{"a window of one still finds the cited line", Ref{Path: "a.py", Line: 10, EndLine: 12, Needle: "unsafe_query(q)"}, 1, RefFound, "", 10},
		{"text nowhere in the range is claimed but not found", Ref{Path: "a.py", Line: 1, EndLine: 120, Needle: "no_such_call(x)"}, 0, RefClaimedNotFound, "", 0},
		{"a single-line cite is exact", Ref{Path: "a.py", Line: 9, Needle: "unsafe_query(q)"}, 0, RefClaimedNotFound, "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyRef(tc.ref, p, tc.window)
			if got.State != tc.want || got.Code != tc.wantCode || got.Line != tc.wantLine {
				t.Fatalf("got %s %q line %d, want %s %q line %d", got.State, got.Code, got.Line, tc.want, tc.wantCode, tc.wantLine)
			}
		})
	}
}

// The validator carries the match line onto the reference and counts a far
// needle as a location only; a model whose references were never looked at is
// partly checked.
func TestValidateRefWindowAndUnchecked(t *testing.T) {
	doc := edit(t, basePentest, func(m map[string]any) {
		r := obj(arr(obj(finding(m, 0)["where"])["refs"])[0])
		r["line"], r["end_line"], r["needle"] = 1, 20, "bcrypt.CompareHashAndPassword"
	})
	o := optsFor(ContractPentest)
	res := Validate(doc, o)
	ref := res.PT.Findings[0].Where.Refs[0]
	if ref.State != RefExists || ref.MatchLine != 0 || !hasIssue(res.Report, "V8", "ref_needle_far") {
		t.Fatalf("a far needle: %+v %s", ref, issueCodes(res.Report))
	}
	o.RefWindow = 25
	res = Validate(doc, o)
	if ref = res.PT.Findings[0].Where.Refs[0]; ref.State != RefFound || ref.MatchLine != 20 {
		t.Fatalf("a wide window: %+v", ref)
	}
	// A match line written by the agent is computed, not read.
	forged := edit(t, basePentest, func(m map[string]any) {
		obj(arr(obj(finding(m, 0)["where"])["refs"])[0])["match_line"] = 99
	})
	if got := Validate(forged, optsFor(ContractPentest)).PT.Findings[0].Where.Refs[0].MatchLine; got != 12 {
		t.Fatalf("match line %d: the agent's value must be dropped and the computed one kept", got)
	}
	// Never looked at: not "nothing was refused".
	o = optsFor(ContractPentest)
	o.Refs = nil
	if got := Validate([]byte(basePentest), o); got.Report.State != ValidationPartial || got.Report.Refs.Unchecked == 0 {
		t.Fatalf("unchecked references left the state %s", got.Report.State)
	}
}
