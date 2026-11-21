package secassess

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Tests of four small validator fixes: redaction that an invisible character
// cannot defeat (m2), ignored keys that are cleaned, redacted and bounded (m3),
// whole numbers written as floats (n1) and an attack tree without a root that
// is refused in the open (n2).

// tokenRedactor is a redactor with two patterns: a GitHub-style token and a
// private key block that needs its five-dash header.
func tokenRedactor() func(string) string {
	token := regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`)
	block := regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*`)
	return func(s string) string {
		return token.ReplaceAllString(block.ReplaceAllString(s, "[REDACTED]"), "[REDACTED]")
	}
}

// tokenCore is the part of a token every variant carries; the tests look for
// its tail in what is stored.
const tokenCore = "0123456789abcdefghijABCDEFGHIJ0123"

// splitTokens are one token written several ways, each with something the
// cleaner drops in it, so the redactor cannot match until after cleaning.
func splitTokens() []struct{ name, text string } {
	return []struct{ name, text string }{
		{"plain", "ghp_" + tokenCore},
		{"zero-width space", "ghp_" + cp(0x200b) + tokenCore},
		{"zero-width joiner in the prefix", "gh" + cp(0x200d) + "p_" + tokenCore},
		{"bidi override", "ghp_" + cp(0x202e) + tokenCore},
		{"soft hyphen", "ghp_" + cp(0x00ad) + tokenCore},
		{"all of them", "ghp_" + cp(0x200b) + "0123456789" + cp(0x202e) + "abcdefghij" + cp(0x00ad) + "ABCDEFGHIJ" + cp(0x2060) + "0123"},
		{"backtick", "ghp_`" + tokenCore},
		{"replacement character", "ghp_" + cp(0xFFFD) + tokenCore},
	}
}

func TestValidateRedactionSurvivesInvisibleCharacters(t *testing.T) {
	for _, tok := range splitTokens() {
		t.Run(tok.name, func(t *testing.T) {
			data := edit(t, baseThreatModel, func(m map[string]any) {
				threat(m, 0)["title"] = "Leaked " + tok.text + " in config"
				obj(arr(threat(m, 0)["missing"])[0])["text"] = "Rotate " + tok.text + " now"
				obj(arr(m["no_threat"])[0])["reason"] = "Holds " + tok.text + " only"
			})
			o := optsFor(ContractThreatModel)
			o.Redact = tokenRedactor()
			r := Validate(data, o)
			if r.Report.State != ValidationValid {
				t.Fatalf("state = %s: %s", r.Report.State, issueCodes(r.Report))
			}
			th := r.TM.Threats[0]
			got := []string{th.Title, th.Missing[0].Text, r.TM.NoThreat[0].Reason}
			want := []string{"Leaked [REDACTED] in config", "Rotate [REDACTED] now", "Holds [REDACTED] only"}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("stored text %d = %q, want %q", i, got[i], want[i])
				}
			}
			b, _ := json.Marshal(r)
			if bytes.Contains(b, []byte("ABCDEFGHIJ")) {
				t.Fatalf("a piece of the token survived in %s", b)
			}
		})
	}
}

// A redactor that needs the text as written must still see it: the key block
// pattern needs its five-dash header, which the cleaner shrinks.
func TestValidateRedactorSeesTheTextAsWritten(t *testing.T) {
	data := edit(t, baseThreatModel, func(m map[string]any) {
		threat(m, 0)["title"] = "Key -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
	})
	o := optsFor(ContractThreatModel)
	o.Redact = tokenRedactor()
	r := Validate(data, o)
	if got := r.TM.Threats[0].Title; got != "Key [REDACTED]" {
		t.Fatalf("title = %q", got)
	}
}

func TestValidateTruncationIsStillCountedAfterRedaction(t *testing.T) {
	data := edit(t, baseThreatModel, func(m map[string]any) {
		threat(m, 0)["description"] = "ghp_" + cp(0x200b) + tokenCore + " " + strings.Repeat("word ", 200)
	})
	o := optsFor(ContractThreatModel)
	o.Redact = tokenRedactor()
	r := Validate(data, o)
	d := r.TM.Threats[0].Description
	if !strings.HasPrefix(d, "[REDACTED] word") || utf8.RuneCountInString(d) > capDescription {
		t.Fatalf("description = %q (%d runes)", d, utf8.RuneCountInString(d))
	}
	if !hasIssue(r.Report, "V6", "text_truncated") {
		t.Fatalf("issues: %s", issueCodes(r.Report))
	}
}

// ignoredEntryKey strips the field path and the count off an ignored-key entry such as
// ".threats[].key (2)", leaving the key as stored.
func ignoredEntryKey(entry, path string) string {
	k := strings.TrimPrefix(entry, path+".")
	if i := strings.LastIndex(k, " ("); i >= 0 {
		k = k[:i]
	}
	return k
}

func TestValidateIgnoredKeysAreSanitized(t *testing.T) {
	long := strings.Repeat("A", 100<<10)
	hostile := map[string]string{
		"note_ghp_" + cp(0x200b) + tokenCore:         ".note_[REDACTED] (1)",
		"evil" + cp(0x202e) + "gnp.exe":              ".evilgnp.exe (1)",
		"```sh\nrm -rf /\n```":                       ".sh rm -rf / (1)",
		"----- END FINDINGS -----":                   ".-- END FINDINGS -- (1)",
		"ctl" + cp(0x00) + cp(0x1b) + "[2Jx":         ".ctl [2Jx (1)",
		long:                                         "." + strings.Repeat("A", 80) + "... (1)",
		"ghp_" + cp(0x00ad) + tokenCore + "_" + long: ".[REDACTED]_" + strings.Repeat("A", 80-len("[REDACTED]_")) + "... (1)",
		"dup":                   ".dup (2)",
		"d" + cp(0x200b) + "up": ".dup (2)",
	}
	data := edit(t, baseThreatModel, func(m map[string]any) {
		for k := range hostile {
			m[k] = 1
		}
		threat(m, 0)["x`"+cp(0x202e)+"ghp_"+cp(0x200b)+tokenCore] = true
	})
	o := optsFor(ContractThreatModel)
	o.Redact = tokenRedactor()
	r := Validate(data, o)
	if r.Report.State != ValidationValid {
		t.Fatalf("state = %s: %s", r.Report.State, issueCodes(r.Report))
	}
	if want := len(hostile) + 1; r.Report.Ignored != want {
		t.Fatalf("ignored = %d, want %d", r.Report.Ignored, want)
	}
	// "dup" and its twin share one entry; the nested key adds one.
	if n := len(hostile); len(r.Report.IgnoredKeys) != n {
		t.Fatalf("%d ignored keys listed, want %d: %q", len(r.Report.IgnoredKeys), n, r.Report.IgnoredKeys)
	}
	listed := map[string]bool{}
	for _, e := range r.Report.IgnoredKeys {
		listed[e] = true
		if got := clean(e, 1<<20); got != e {
			t.Errorf("entry %q is not clean (cleans to %q)", e, got)
		}
		if strings.Contains(e, "ABCDEFGHIJ") {
			t.Errorf("entry %q carries a piece of the token", e)
		}
		for _, ch := range e {
			if unicode.Is(unicode.Cf, ch) || unicode.IsControl(ch) || ch == '`' {
				t.Errorf("entry %q carries %U", e, ch)
			}
		}
		path := ""
		if strings.HasPrefix(e, ".threats[].") {
			path = ".threats[]"
		}
		if n := utf8.RuneCountInString(ignoredEntryKey(e, path)); n > 83 {
			t.Errorf("entry key %q has %d runes", ignoredEntryKey(e, path), n)
		}
	}
	for _, want := range hostile {
		if !listed[want] {
			t.Errorf("no entry %q in %q", want, r.Report.IgnoredKeys)
		}
	}
	if want := ".threats[].x[REDACTED] (1)"; !listed[want] {
		t.Errorf("no entry %q in %q", want, r.Report.IgnoredKeys)
	}
}

func TestValidateIgnoredKeysAreBounded(t *testing.T) {
	const total = maxIgnoredKeys + 500
	data := edit(t, baseThreatModel, func(m map[string]any) {
		for i := 0; i < total; i++ {
			m[fmt.Sprintf("k%04d", i)] = i
		}
	})
	o := optsFor(ContractThreatModel)
	first := Validate(data, o)
	if first.Report.Ignored != total {
		t.Fatalf("ignored = %d, want %d (keys past the bound still count)", first.Report.Ignored, total)
	}
	if n := len(first.Report.IgnoredKeys); n != maxListedIgnoredKeys {
		t.Fatalf("%d keys listed, want %d", n, maxListedIgnoredKeys)
	}
	// The tracked keys are the first ones in sorted order, so a rerun lists the
	// same keys.
	if first.Report.IgnoredKeys[0] != ".k0000 (1)" || first.Report.IgnoredKeys[maxListedIgnoredKeys-1] != fmt.Sprintf(".k%04d (1)", maxListedIgnoredKeys-1) {
		t.Fatalf("keys = %q", first.Report.IgnoredKeys)
	}
	for i := 0; i < 3; i++ {
		if again := Validate(data, o); !reflect.DeepEqual(again.Report, first.Report) {
			t.Fatalf("run %d differs from the first", i)
		}
	}
	// The map itself stays at the bound; the rest is a counter.
	generic := map[string]any{}
	for i := 0; i < total; i++ {
		generic[fmt.Sprintf("k%04d", i)] = i
	}
	v := newValidator(nil, o)
	v.prune(generic, reflect.TypeOf(ThreatModelDoc{}), "")
	if len(v.ignore) != maxIgnoredKeys || v.ignoreMore != total-maxIgnoredKeys {
		t.Fatalf("tracked %d keys and %d more, want %d and %d", len(v.ignore), v.ignoreMore, maxIgnoredKeys, total-maxIgnoredKeys)
	}
}

func TestValidateIgnoredKeyBoundKeepsCountingTrackedKeys(t *testing.T) {
	// The threats are visited before the "z" keys, so the nested key is tracked
	// first and the bound is reached inside the z keys: the tracked key keeps its
	// own count, and the keys past the bound still reach the total.
	data := edit(t, baseThreatModel, func(m map[string]any) {
		for i := 0; i < maxIgnoredKeys+5; i++ {
			m[fmt.Sprintf("z%04d", i)] = i
		}
		for _, th := range arr(m["threats"]) {
			obj(th)["aa"] = true
		}
	})
	r := Validate(data, optsFor(ContractThreatModel))
	if want := maxIgnoredKeys + 5 + 2; r.Report.Ignored != want {
		t.Fatalf("ignored = %d, want %d", r.Report.Ignored, want)
	}
	if got := r.Report.IgnoredKeys[0]; got != ".threats[].aa (2)" {
		t.Fatalf("first key = %q", got)
	}
}

// numProbe is a struct with the field shapes a number can land in.
type numProbe struct {
	I   int       `json:"i"`
	U   uint8     `json:"u"`
	P   *int      `json:"p"`
	L   []int     `json:"l"`
	F   float64   `json:"f"`
	FL  []float64 `json:"fl"`
	S   string    `json:"s"`
	Sub struct {
		N int `json:"n"`
	} `json:"sub"`
}

// probe prunes a document against numProbe the way the validator does, then
// decodes it the way the validator does.
func probe(t *testing.T, doc string) (numProbe, error) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		t.Fatalf("fixture %s: %v", doc, err)
	}
	v := newValidator(nil, ValidateOptions{})
	v.prune(generic, reflect.TypeOf(numProbe{}), "")
	b, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("marshal %s: %v", doc, err)
	}
	var out numProbe
	err = json.Unmarshal(b, &out)
	return out, err
}

func TestWholeNumbersWrittenAsFloats(t *testing.T) {
	ip := func(n int) *int { return &n }
	cases := []struct {
		name string
		doc  string
		want numProbe
		bad  bool
	}{
		{name: "an integer spelled as an integer", doc: `{"i":3}`, want: numProbe{I: 3}},
		{name: "3.0", doc: `{"i":3.0}`, want: numProbe{I: 3}},
		{name: "12.0", doc: `{"i":12.0}`, want: numProbe{I: 12}},
		{name: "1e1", doc: `{"i":1e1}`, want: numProbe{I: 10}},
		{name: "1E+1", doc: `{"i":1E+1}`, want: numProbe{I: 10}},
		{name: "30e-1", doc: `{"i":30e-1}`, want: numProbe{I: 3}},
		{name: "-0.0", doc: `{"i":-0.0}`, want: numProbe{I: 0}},
		{name: "0e5", doc: `{"i":0e5}`, want: numProbe{I: 0}},
		{name: "negative", doc: `{"i":-3.0}`, want: numProbe{I: -3}},
		{name: "2^53 exactly", doc: `{"i":9007199254740992.0}`, want: numProbe{I: 1 << 53}},
		{name: "past 2^53", doc: `{"i":9007199254740994.0}`, bad: true},
		{name: "a fraction", doc: `{"i":3.5}`, bad: true},
		{name: "a fraction hidden past the float's precision", doc: `{"i":3.0000000000000000001}`, bad: true},
		{name: "a huge exponent", doc: `{"i":1e30}`, bad: true},
		{name: "an exponent that overflows a float", doc: `{"i":1e400}`, bad: true},
		{name: "an exponent that overflows an int", doc: `{"i":1e99999999999999999999}`, bad: true},
		{name: "a negative exponent that makes a fraction", doc: `{"i":1e-1}`, bad: true},
		{name: "a number spelled past the length cap", doc: `{"i":1.00000000000000000000000000000000000000000}`, bad: true},
		{name: "a string is left alone", doc: `{"i":"3.0"}`, bad: true},
		{name: "a float into a string field is left alone", doc: `{"s":3.0}`, bad: true},
		{name: "uint8 in range", doc: `{"u":200.0}`, want: numProbe{U: 200}},
		{name: "uint8 negative", doc: `{"u":-1.0}`, bad: true},
		{name: "uint8 overflow", doc: `{"u":300.0}`, bad: true},
		{name: "a pointer to an integer", doc: `{"p":2.0}`, want: numProbe{P: ip(2)}},
		{name: "a float inside an integer slice", doc: `{"l":[1.0,2e0,3]}`, want: numProbe{L: []int{1, 2, 3}}},
		{name: "a fraction inside an integer slice", doc: `{"l":[1.0,2.5]}`, bad: true},
		{name: "a nested integer field", doc: `{"sub":{"n":7.0}}`, want: numProbe{Sub: struct {
			N int `json:"n"`
		}{N: 7}}},
		{name: "a float field still decodes", doc: `{"f":3.0}`, want: numProbe{F: 3}},
		{name: "a float field keeps its fraction", doc: `{"f":3.5}`, want: numProbe{F: 3.5}},
		{name: "a float slice keeps its fractions", doc: `{"fl":[1.0,2.5]}`, want: numProbe{FL: []float64{1, 2.5}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := probe(t, c.doc)
			if c.bad {
				if err == nil {
					t.Fatalf("decoded %s into %+v, want an error", c.doc, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: %v", c.doc, err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("%s decoded to %+v, want %+v", c.doc, got, c.want)
			}
		})
	}
}

func TestValidateWholeNumbersWrittenAsFloats(t *testing.T) {
	num := func(s string) json.Number { return json.Number(s) }
	cases := []vcase{
		{name: "likelihood and impact as floats", mut: func(m map[string]any) {
			threat(m, 0)["rating"] = map[string]any{"likelihood": num("3.0"), "impact": num("4.0")}
		}, check: func(t *testing.T, r Result) {
			if g := r.TM.Threats[0].Rating; g.Likelihood != 3 || g.Impact != 4 {
				t.Fatalf("rating = %+v", g)
			}
		}},
		{name: "an exponent form of an integer", mut: func(m map[string]any) {
			threat(m, 0)["rating"] = map[string]any{"likelihood": num("5e0"), "impact": num("2.0e0")}
		}, check: func(t *testing.T, r Result) {
			if g := r.TM.Threats[0].Rating; g.Likelihood != 5 || g.Impact != 2 {
				t.Fatalf("rating = %+v", g)
			}
		}},
		{name: "a ref line as a float", mut: func(m map[string]any) {
			obj(arr(obj(arr(sys(m)["components"])[0])["paths"])[0])["line"] = num("12.0")
		}, check: func(t *testing.T, r Result) {
			if g := r.TM.System.Components[0].Paths[0]; g.Line != 12 || g.State != RefFound {
				t.Fatalf("path = %+v", g)
			}
		}},
		{name: "a fraction still refuses the file", mut: func(m map[string]any) {
			threat(m, 0)["rating"] = map[string]any{"likelihood": num("3.5"), "impact": 4}
		}, state: ValidationInvalid, fatal: "bad_shape", want: []string{"V2:bad_shape"}},
		{name: "a huge value still refuses the file", mut: func(m map[string]any) {
			threat(m, 0)["rating"] = map[string]any{"likelihood": num("1e30"), "impact": 4}
		}, state: ValidationInvalid, fatal: "bad_shape", want: []string{"V2:bad_shape"}},
		{name: "pen test numbers as floats", contract: ContractPentest, mut: func(m map[string]any) {
			start := obj(obj(m["target"])["start"])
			start["startup_seconds"] = num("1e1")
			obj(start["health"])["status"] = num("200.0")
			finding(m, 0)["rating"] = map[string]any{"likelihood": num("4.0"), "impact": num("3.0")}
		}, check: func(t *testing.T, r Result) {
			s := r.PT.Target.Start
			if s.StartupSeconds != 10 || s.Health.Status != 200 || r.PT.Findings[0].Rating.Likelihood != 4 {
				t.Fatalf("start = %+v, rating = %+v", s, r.PT.Findings[0].Rating)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func TestValidateEmptyAttackTreeRootIsRefused(t *testing.T) {
	tree := func(root string) map[string]any {
		return map[string]any{"root": root, "nodes": []any{map[string]any{"id": "n1", "label": "Guess", "op": "or", "leaf": true}}}
	}
	invisible := cp(0x200b, 0x202e, 0x00ad)
	cases := []struct {
		name    string
		roots   []string
		refused []int  // original indexes that must carry the issue
		kept    string // the first kept root
	}{
		{name: "the second tree", roots: []string{"Take over an account", invisible}, refused: []int{1}, kept: "Take over an account"},
		{name: "the first and the third, not the compacted index", roots: []string{invisible, "Read the data", "   "}, refused: []int{0, 2}, kept: "Read the data"},
		{name: "an empty string", roots: []string{"Keep this", ""}, refused: []int{1}, kept: "Keep this"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := edit(t, baseThreatModel, func(m map[string]any) {
				var trees []any
				for _, root := range c.roots {
					trees = append(trees, tree(root))
				}
				m["attack_trees"] = trees
			})
			r := Validate(data, optsFor(ContractThreatModel))
			if r.Report.State != ValidationPartial {
				t.Fatalf("state = %s: %s", r.Report.State, issueCodes(r.Report))
			}
			for _, i := range c.refused {
				found := false
				for _, is := range r.Report.Issues {
					if is.Row == "V6" && is.Code == "empty_root" && is.Path == fmt.Sprintf("attack_trees[%d]", i) && is.Severity == SevRefused {
						found = true
						if is.Message != "The attack tree has no root text, so it was left out." {
							t.Errorf("message = %q", is.Message)
						}
					}
				}
				if !found {
					t.Errorf("no empty_root issue at attack_trees[%d]: %v", i, r.Report.Issues)
				}
			}
			wantKept := len(c.roots) - len(c.refused)
			if got := r.Report.Counts["attack_trees"]; got != (Count{Read: len(c.roots), Refused: len(c.refused), Kept: wantKept}) {
				t.Errorf("attack_trees count = %+v", got)
			}
			if len(r.TM.AttackTrees) != wantKept || r.TM.AttackTrees[0].Root != c.kept {
				t.Errorf("trees = %+v", r.TM.AttackTrees)
			}
		})
	}
}
