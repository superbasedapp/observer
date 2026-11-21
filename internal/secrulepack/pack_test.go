package secrulepack

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// floorFiles returns a mutable copy of the embedded floor's files.
func floorFiles(t *testing.T) map[string][]byte {
	t.Helper()
	p, err := Floor()
	if err != nil {
		t.Fatalf("Floor: %v", err)
	}
	return p.Files()
}

func TestFloorValidates(t *testing.T) {
	p, err := Floor()
	if err != nil {
		t.Fatalf("the embedded floor does not validate: %v", err)
	}
	if p.Manifest.ID != PackID || len(p.Manifest.Rules) < 12 {
		t.Fatalf("floor %s with %d rules", p.Manifest.ID, len(p.Manifest.Rules))
	}
	langs := map[string]bool{}
	for _, r := range p.Manifest.Rules {
		for _, l := range r.Languages {
			langs[l] = true
		}
	}
	for _, l := range []string{"python", "javascript", "typescript", "go", "java", "csharp", "ruby", "php", "kotlin"} {
		if !langs[l] {
			t.Errorf("no rule for %s", l)
		}
	}
	if len(p.Digest()) != 64 {
		t.Errorf("digest %q", p.Digest())
	}
}

func TestDigestIsCanonical(t *testing.T) {
	a := map[string][]byte{"pack.json": []byte("a"), "rules/x.yaml": []byte("b")}
	b := map[string][]byte{"rules/x.yaml": []byte("b"), "pack.json": []byte("a")}
	if CanonicalDigest(a) != CanonicalDigest(b) {
		t.Fatal("digest depends on map order")
	}
	b["rules/x.yaml"] = []byte("c")
	if CanonicalDigest(a) == CanonicalDigest(b) {
		t.Fatal("digest ignores a content change")
	}
	c := map[string][]byte{"pack.json": []byte("a"), "rules/y.yaml": []byte("b")}
	if CanonicalDigest(a) == CanonicalDigest(c) {
		t.Fatal("digest ignores a rename")
	}
}

// TestParseRefuses is the validator's table: one mutation of the floor per
// row, each a rule the validator must hold.
func TestParseRefuses(t *testing.T) {
	sql := "rules/python.sql-string-concat.yaml"
	replace := func(file, old, new string) func(map[string][]byte) {
		return func(f map[string][]byte) {
			s := string(f[file])
			if !strings.Contains(s, old) {
				t.Fatalf("%s has no %q", file, old)
			}
			f[file] = []byte(strings.Replace(s, old, new, 1))
		}
	}
	cases := []struct {
		name   string
		mutate func(map[string][]byte)
		want   string
	}{
		{"no manifest", func(f map[string][]byte) { delete(f, ManifestFile) }, "no pack.json"},
		{"unknown manifest key", replace(ManifestFile, `"licence"`, `"remote": "https://example.com", "licence"`), "unknown field"},
		{"wrong pack id", replace(ManifestFile, `"id": "observer-code"`, `"id": "observer-rules"`), "pack id"},
		{"bad version", replace(ManifestFile, `"version": "`+floorVersion(t)+`"`, `"version": "latest"`), "MAJOR.MINOR.PATCH"},
		{"duplicate rule id", replace(ManifestFile, `"id": "go.sql-string-concat"`, `"id": "go.shell-interpolation"`), "used twice"},
		{"rule id of another file", replace(sql, "id: python.sql-string-concat", "id: python.sql-other"), "not the manifest's"},
		{"severity disagrees", replace(sql, "severity: ERROR", "severity: WARNING"), "severity"},
		{"languages disagree", replace(sql, "languages: [python]", "languages: [python, go]"), "languages"},
		{"unsupported language", replace(sql, "languages: [python]", "languages: [cobol]"), "not supported"},
		{"unknown rule key (a fix)", replace(sql, "    metadata:", "    fix: cur.execute(\"x\")\n    metadata:"), "not found in type"},
		{"a path filter", replace(sql, "    metadata:", "    paths:\n      include: [\"*\"]\n    metadata:"), "not found in type"},
		{"two operators in one entry", replace(sql, "          - pattern: $CUR.$EXEC($SQL, ...)", "          - pattern: $CUR.$EXEC($SQL, ...)\n            pattern-regex: x"), "exactly one operator"},
		{"a regex Go cannot compile", replace(sql, "regex: ^(execute|", "regex: ^((execute|"), "regex"},
		{"two rules in one file", replace(sql, "rules:\n", "rules:\n  - id: python.sql-string-concat\n    languages: [python]\n    severity: ERROR\n    message: m\n    metadata: {cwe: CWE-89}\n    pattern: x\n"), "exactly one"},
		{"a URL in the message", replace(sql, "message: Web request input", "message: see https://example.com Web request input"), "URL"},
		{"wrong CWE", replace(sql, "cwe: CWE-89", "cwe: CWE-78"), "CWE-89"},
		{"an unlisted file", func(f map[string][]byte) { f["rules/extra.yaml"] = f[sql] }, "not named by the manifest"},
		{"a file outside the pack layout", func(f map[string][]byte) { f["../x.yaml"] = []byte("x") }, "only pack.json"},
		{"a nested rules path", func(f map[string][]byte) { f["rules/a/b.yaml"] = []byte("x") }, "only pack.json"},
		{"a hidden file", func(f map[string][]byte) { f["rules/.x.yaml"] = []byte("x") }, "bad file name"},
		{"a missing rule file", func(f map[string][]byte) { delete(f, sql) }, "missing"},
		{"a missing canary target", func(f map[string][]byte) { delete(f, "canary/observer_code_canary.py") }, "canary target"},
		{"an oversized rule file", func(f map[string][]byte) { f[sql] = append(f[sql], []byte("\n#"+strings.Repeat("x", MaxRuleBytes))...) }, "byte cap"},
		{"non UTF-8 bytes", func(f map[string][]byte) { f[sql] = append(f[sql], 0xff) }, "UTF-8"},
		{"a precision figure with no denominator", replace(ManifestFile, `"cwe": "CWE-942"`, `"cwe": "CWE-942", "precision": {"figure": 0.95, "wilson_lower": 0.9, "denominator": 0, "corpus": "c", "method": "m"}`), "denominator"},
		{"a hand-raised lower bound", replace(ManifestFile, `"cwe": "CWE-942"`, `"cwe": "CWE-942", "precision": {"figure": 0.9, "wilson_lower": 0.89, "denominator": 10, "corpus": "c", "method": "m"}`), "Wilson bound"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := floorFiles(t)
			c.mutate(f)
			_, err := Parse(f)
			if err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Parse = %v, want an ErrInvalid naming %q", err, c.want)
			}
		})
	}
}

// spot is a spot-check of p by an independent agent.
func spot(p *Precision, size, overturnedTrue int) *Spotcheck {
	s := &Spotcheck{Date: "2026-10-22", Reviewer: "agent:independent-1", SampleSize: size, Disagreements: overturnedTrue, OverturnedTrue: overturnedTrue}
	if p != nil {
		s.FiguresDigest = PrecisionDigest(*p)
	}
	return s
}

func TestBlockingBar(t *testing.T) {
	cleared := &Precision{Figure: 1, WilsonLower: WilsonLower(30, 30), Denominator: 30, Results: 30}
	under := &Precision{Figure: 0.9, WilsonLower: WilsonLower(27, 30), Denominator: 30, Results: 30}
	// P-077: a capped figure (60 labelled of 765) or one whose results were
	// not recorded never blocks, whatever its bound.
	capped := &Precision{Figure: 1, WilsonLower: WilsonLower(60, 60), Denominator: 60, Results: 765}
	unrecorded := &Precision{Figure: 1, WilsonLower: WilsonLower(30, 30), Denominator: 30}
	noDenominator := &Precision{Figure: 1, WilsonLower: 0.9}
	// 23 of 24: the true bound is 0.7976; stated as 0.80 it must not pass.
	stated := &Precision{Figure: 23.0 / 24, WilsonLower: 0.80, Denominator: 24}
	operator := spot(cleared, 10, 0)
	operator.Reviewer = SpotcheckerOperator
	// Lane SEC-G4 audit finding 1: two passes agreeing on every verdict and
	// reason code over 20 or more results are one effective pass, and never
	// block unless the second pass is attested isolated.
	withPasses := func(ps Passes) *Precision {
		c := *cleared
		c.Passes = &ps
		return &c
	}
	onePass := withPasses(Passes{Results: 97, VerdictAgreements: 97, ReasonAgreements: 97})
	onePass20 := withPasses(Passes{Results: 20, VerdictAgreements: 20, ReasonAgreements: 20})
	attested := withPasses(Passes{Results: 97, VerdictAgreements: 97, ReasonAgreements: 97, SecondPassAttestedIsolated: true})
	reasonDiffers := withPasses(Passes{Results: 97, VerdictAgreements: 97, ReasonAgreements: 96})
	verdictDiffers := withPasses(Passes{Results: 97, VerdictAgreements: 96, ReasonAgreements: 96})
	small := withPasses(Passes{Results: 19, VerdictAgreements: 19, ReasonAgreements: 19})
	pendingB := withPasses(Passes{Results: 10, VerdictAgreements: 8, ReasonAgreements: 7, SecondPassAttestedIsolated: true, SecondPassPending: 1})
	unnamed := spot(cleared, 10, 0)
	unnamed.Reviewer = ""
	cases := []struct {
		name     string
		r        Rule
		mayBlock bool
		blocks   bool
	}{
		{"no figure", Rule{Blocking: true}, false, false},
		{"no figure, a spot-check", Rule{Blocking: true, OperatorSpotcheck: spot(nil, 10, 0)}, false, false},
		{"lower bound under the bar", Rule{Blocking: true, OperatorSpotcheck: spot(under, 10, 0), Precision: under}, false, false},
		{"no denominator", Rule{Blocking: true, OperatorSpotcheck: spot(noDenominator, 10, 0), Precision: noDenominator}, false, false},
		{"23 of 24 stated as 0.80", Rule{Blocking: true, OperatorSpotcheck: spot(stated, 10, 0), Precision: stated}, false, false},
		{"cleared, no spot-check", Rule{Blocking: true, Precision: cleared}, false, false},
		{"capped (60 of 765), spot-checked", Rule{Blocking: true, Precision: capped, OperatorSpotcheck: spot(capped, 10, 0)}, false, false},
		{"results not recorded, spot-checked", Rule{Blocking: true, Precision: unrecorded, OperatorSpotcheck: spot(unrecorded, 10, 0)}, false, false},
		{"cleared, the operator overturned a true positive", Rule{Blocking: true, Precision: cleared, OperatorSpotcheck: spot(cleared, 10, 1)}, false, false},
		{"cleared, a spot-check of 9 (under 10)", Rule{Blocking: true, Precision: cleared, OperatorSpotcheck: spot(cleared, 9, 0)}, false, false},
		{"cleared, a spot-check of other figures (void)", Rule{Blocking: true, Precision: cleared, OperatorSpotcheck: spot(under, 10, 0)}, false, false},
		{"cleared, a spot-check with no reviewer", Rule{Blocking: true, Precision: cleared, OperatorSpotcheck: unnamed}, false, false},
		{"cleared and spot-checked, blocking off", Rule{Precision: cleared, OperatorSpotcheck: spot(cleared, 10, 0)}, true, false},
		{"cleared, spot-checked, blocking on", Rule{Blocking: true, Precision: cleared, OperatorSpotcheck: spot(cleared, 10, 0)}, true, true},
		{"cleared, spot-checked by the operator", Rule{Blocking: true, Precision: cleared, OperatorSpotcheck: operator}, true, true},
		{"one effective pass (97 of 97 verdicts and reasons)", Rule{Blocking: true, Precision: onePass, OperatorSpotcheck: spot(onePass, 10, 0)}, false, false},
		{"one effective pass at exactly 20", Rule{Blocking: true, Precision: onePass20, OperatorSpotcheck: spot(onePass20, 10, 0)}, false, false},
		{"unanimous, second pass attested isolated", Rule{Blocking: true, Precision: attested, OperatorSpotcheck: spot(attested, 10, 0)}, true, true},
		{"one reason code differs", Rule{Blocking: true, Precision: reasonDiffers, OperatorSpotcheck: spot(reasonDiffers, 10, 0)}, true, true},
		{"one verdict differs", Rule{Blocking: true, Precision: verdictDiffers, OperatorSpotcheck: spot(verdictDiffers, 10, 0)}, true, true},
		{"unanimous under 20 results", Rule{Blocking: true, Precision: small, OperatorSpotcheck: spot(small, 10, 0)}, true, true},
		{"a second-pass label pending (lane SEC-G5)", Rule{Blocking: true, Precision: pendingB, OperatorSpotcheck: spot(pendingB, 10, 0)}, false, false},
	}
	if l := WilsonLower(23, 24); l >= BlockingLowerBound || l < 0.797 || l > 0.798 {
		t.Errorf("WilsonLower(23, 24) = %.4f, want about 0.7976", l)
	}
	for _, c := range []struct {
		p    Precision
		want bool
	}{{*cleared, true}, {*capped, false}, {*unrecorded, false}, {Precision{}, false}, {Precision{Denominator: 5, Results: 6}, false}} {
		if got := c.p.FullyLabelled(); got != c.want {
			t.Errorf("FullyLabelled(%+v) = %v, want %v", c.p, got, c.want)
		}
	}
	// The minimum spot-check: 10, or every true positive when fewer.
	for _, c := range []struct {
		p    Precision
		want int
	}{{*cleared, 10}, {Precision{Figure: 0.1, Denominator: 30}, 3}, {Precision{Denominator: 5}, 1}} {
		if got := c.p.MinSpotcheck(); got != c.want {
			t.Errorf("MinSpotcheck(%+v) = %d, want %d", c.p, got, c.want)
		}
	}
	for _, c := range cases {
		if got := c.r.MayBlock(); got != c.mayBlock {
			t.Errorf("%s: MayBlock = %v, want %v", c.name, got, c.mayBlock)
		}
		if got := c.r.BlockingEligible(); got != c.blocks {
			t.Errorf("%s: BlockingEligible = %v, want %v", c.name, got, c.blocks)
		}
	}
	// 30 of 30 labelled true clears the bar; 27 of 30 does not.
	if l := WilsonLower(30, 30); l < BlockingLowerBound {
		t.Errorf("WilsonLower(30, 30) = %.3f", l)
	}
	if l := WilsonLower(27, 30); l >= BlockingLowerBound || l < 0.74 || l > 0.75 {
		t.Errorf("WilsonLower(27, 30) = %.4f, want about 0.744", l)
	}
}

func TestNoisy(t *testing.T) {
	cases := []struct {
		p    *Precision
		want bool
	}{
		{nil, false},
		{&Precision{Figure: 0.49}, true},
		{&Precision{Figure: 0.5}, false},
	}
	for _, c := range cases {
		if got := (Rule{Precision: c.p}).Noisy(); got != c.want {
			t.Errorf("Noisy(%+v) = %v", c.p, got)
		}
	}
}

// measured returns the floor with csharp.cors-credentials-any-origin (a rule with no
// result on the corpus, so no figure of its own) carrying extra
// manifest keys (a JSON fragment after its file).
// measured injects extra into the manifest row of a rule the committed
// pack has not measured (no results on the corpus), so the injected figure
// is the rule's only one.
func measured(t *testing.T, extra string) (*Pack, error) {
	t.Helper()
	f := floorFiles(t)
	row := `"file": "rules/csharp.cors-credentials-any-origin.yaml",`
	if !strings.Contains(string(f[ManifestFile]), row) {
		t.Fatal("the manifest has no csharp.cors-credentials-any-origin row")
	}
	f[ManifestFile] = []byte(strings.Replace(string(f[ManifestFile]), row, row+" "+extra+",", 1))
	return Parse(f)
}

func TestAMeasuredPrecisionValidates(t *testing.T) {
	lower := WilsonLower(29, 30)
	prec := `"precision": {"figure": 0.9667, "wilson_lower": ` + formatFloat(lower) + `, "denominator": 30, "results": 30, "reviewer_disagreements": 1, "kappa": 0.65, "corpus": "jsp7-50+observer@c0ffee", "method": "two reviewers, every result"}`
	p, err := measured(t, prec)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r, _ := p.Rule("csharp.cors-credentials-any-origin")
	if r.MayBlock() || r.BlockingEligible() {
		t.Fatalf("29 of 30 with no spot-check: MayBlock %v, blocks %v (want neither)", r.MayBlock(), r.BlockingEligible())
	}
	for _, reviewer := range []string{"agent:independent-1", SpotcheckerOperator} {
		spot := spotJSON(t, prec, reviewer, 10, 0)
		p, err = measured(t, prec+", "+spot+`, "blocking": true`)
		if err != nil {
			t.Fatalf("Parse with the spot-check by %s: %v", reviewer, err)
		}
		r, _ = p.Rule("csharp.cors-credentials-any-origin")
		if !r.BlockingEligible() {
			t.Fatalf("29 of 30 (lower %.3f) with a clean spot-check by %s should block", lower, reviewer)
		}
	}
}

// spotJSON is an operator_spotcheck fragment checking the figures of the
// precision fragment prec.
func spotJSON(t *testing.T, prec, reviewer string, size, overturnedTrue int) string {
	t.Helper()
	var x struct {
		Precision Precision `json:"precision"`
	}
	if err := json.Unmarshal([]byte("{"+prec+"}"), &x); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`"operator_spotcheck": {"date": "2026-10-22", "reviewer": %q, "figures_digest": %q, "sample_size": %d, "disagreements": %d, "overturned_true": %d}`,
		reviewer, PrecisionDigest(x.Precision), size, overturnedTrue, overturnedTrue)
}

// TestValidatorRefusesBlocking is the bar's table: blocking turned on in a
// manifest that does not clear it is refused, never silently ignored.
func TestValidatorRefusesBlocking(t *testing.T) {
	cleared := `"precision": {"figure": 1, "wilson_lower": ` + formatFloat(WilsonLower(30, 30)) + `, "denominator": 30, "results": 30, "corpus": "c", "method": "m"}`
	under := `"precision": {"figure": 0.9, "wilson_lower": ` + formatFloat(WilsonLower(27, 30)) + `, "denominator": 30, "results": 30, "corpus": "c", "method": "m"}`
	noisy := `"precision": {"figure": 0.4, "wilson_lower": ` + formatFloat(WilsonLower(4, 10)) + `, "denominator": 10, "results": 10, "corpus": "c", "method": "m"}`
	capped := `"precision": {"figure": 1, "wilson_lower": ` + formatFloat(WilsonLower(60, 60)) + `, "denominator": 60, "results": 765, "corpus": "c", "method": "m"}`
	unrecorded := `"precision": {"figure": 1, "wilson_lower": ` + formatFloat(WilsonLower(30, 30)) + `, "denominator": 30, "corpus": "c", "method": "m"}`
	const ind = "agent:independent-1"
	clean := func(prec string) string { return spotJSON(t, prec, ind, 10, 0) }
	// edit replaces one key of a clean spot-check of the cleared figures.
	edit := func(from, to string) string {
		return cleared + ", " + strings.Replace(clean(cleared), from, to, 1)
	}
	stated := `"precision": {"figure": 0.958333, "wilson_lower": 0.8, "denominator": 24, "corpus": "c", "method": "m"}`
	cases := []struct{ name, extra, want string }{
		{"blocking with no figure", `"blocking": true`, "blocking needs"},
		{"blocking with no spot-check", cleared + `, "blocking": true`, "blocking needs"},
		{"blocking a capped figure (60 of 765), P-077", capped + ", " + clean(capped) + `, "blocking": true`, "every result labelled"},
		{"blocking with results not recorded", unrecorded + ", " + clean(unrecorded) + `, "blocking": true`, "every result labelled"},
		{"blocking under the bar", under + ", " + clean(under) + `, "blocking": true`, "blocking needs"},
		{"blocking a noisy rule", noisy + ", " + clean(noisy) + `, "blocking": true`, "blocking needs"},
		{"blocking after an overturned true positive", cleared + ", " + spotJSON(t, cleared, ind, 10, 1) + `, "blocking": true`, "blocking needs"},
		{"blocking on a spot-check too small (5 of the needed 10)", cleared + ", " + spotJSON(t, cleared, ind, 5, 0) + `, "blocking": true`, "blocking needs"},
		{"a stated bound above the recomputed one (23 of 24 as 0.80)", stated, "above the Wilson bound"},
		{"a spot-check with no figure", clean(cleared), "no precision figure"},
		{"a spot-check of other figures (void)", cleared + ", " + clean(under), "figures_digest"},
		{"a spot-check with no reviewer", edit(`"reviewer": "`+ind+`"`, `"reviewer": ""`), "reviewer"},
		{"a spot-check by someone unnamed", edit(`"reviewer": "`+ind+`"`, `"reviewer": "bob"`), "reviewer"},
		{"a spot-check with a bad date", edit(`"date": "2026-10-22"`, `"date": "22/10/2026"`), "YYYY-MM-DD"},
		{"a spot-check with no sample", edit(`"sample_size": 10`, `"sample_size": 0`), "sample_size"},
		{"more overturned true than overturned", edit(`"overturned_true": 0`, `"overturned_true": 1`), "overturned_true"},
		{"results under the denominator", `"precision": {"figure": 1, "wilson_lower": ` + formatFloat(WilsonLower(30, 30)) + `, "denominator": 30, "results": 20, "corpus": "c", "method": "m"}`, "results"},
		{"a figure that is no count", `"precision": {"figure": 0.95, "wilson_lower": ` + formatFloat(WilsonLower(10, 10)) + `, "denominator": 10, "corpus": "c", "method": "m"}`, "not a count"},
		{"blocking on one effective pass (97 of 97)", strings.TrimSuffix(cleared, "}") + `, "passes": {"results": 97, "verdict_agreements": 97, "reason_agreements": 97}}, ` + clean(strings.TrimSuffix(cleared, "}")+`, "passes": {"results": 97, "verdict_agreements": 97, "reason_agreements": 97}}`) + `, "blocking": true`, "one effective pass"},
		{"passes with more reason than verdict agreements", strings.TrimSuffix(cleared, "}") + `, "passes": {"results": 97, "verdict_agreements": 90, "reason_agreements": 91}}`, "passes"},
		{"passes with no results", strings.TrimSuffix(cleared, "}") + `, "passes": {"results": 0, "verdict_agreements": 0, "reason_agreements": 0}}`, "passes"},
		{"kappa out of range", `"precision": {"figure": 1, "wilson_lower": ` + formatFloat(WilsonLower(30, 30)) + `, "denominator": 30, "kappa": 1.5, "corpus": "c", "method": "m"}`, "kappa"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := measured(t, c.extra)
			if err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Parse = %v, want an ErrInvalid naming %q", err, c.want)
			}
		})
	}
}

func TestChoose(t *testing.T) {
	floor, _ := Floor()
	v := ParseVersion(floorVersion(t))
	newer := withVersion(t, fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]+1))
	older := withVersion(t, "1.1.0")
	same := withVersion(t, floorVersion(t))
	cases := []struct {
		name     string
		imported *Pack
		want     *Pack
		src      Source
	}{
		{"nothing imported", nil, floor, SourceFloor},
		{"a newer pack wins", newer, newer, SourceImported},
		{"an older pack never displaces the floor", older, floor, SourceFloor},
		{"an equal version keeps the floor", same, floor, SourceFloor},
	}
	for _, c := range cases {
		got, src := Choose(floor, c.imported)
		if got != c.want || src != c.src {
			t.Errorf("%s: Choose = %s %s", c.name, got.Version(), src)
		}
	}
}

// floorVersion is the embedded floor's version, so no test moves with a
// pack revision.
func floorVersion(t *testing.T) string {
	t.Helper()
	p, err := Floor()
	if err != nil {
		t.Fatal(err)
	}
	return p.Version()
}

func withVersion(t *testing.T, v string) *Pack {
	t.Helper()
	f := floorFiles(t)
	f[ManifestFile] = []byte(strings.Replace(string(f[ManifestFile]), `"version": "`+floorVersion(t)+`"`, `"version": "`+v+`"`, 1))
	p, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBundleRoundTrip(t *testing.T) {
	p := withVersion(t, floorVersion(t))
	b, err := EncodeBundle(p)
	if err != nil {
		t.Fatal(err)
	}
	q, err := DecodeBundle(b)
	if err != nil {
		t.Fatalf("DecodeBundle: %v", err)
	}
	if q.Digest() != p.Digest() || q.Version() != floorVersion(t) {
		t.Fatalf("round trip changed the pack: %s %s", q.Digest(), q.Version())
	}
	if _, err := DecodeBundle([]byte(`{"schema":"x","files":{}}`)); err == nil {
		t.Fatal("a bundle of another schema decoded")
	}
	if _, err := DecodeBundle([]byte(`{"schema":"` + BundleSchema + `","files":{},"url":"https://x"}`)); err == nil {
		t.Fatal("a bundle with an unknown key decoded")
	}
}

func TestRulePrefix(t *testing.T) {
	cases := map[string]string{
		"/tmp/claude-0/og/pack/rules":              "tmp.claude-0.og.pack.rules",
		"/home/u/.cache/sbo/packs/1.0.0-ab/rules/": "home.u..cache.sbo.packs.1.0.0-ab.rules",
		`C:\Users\u\AppData\Local\sbo\rules`:       "Users.u.AppData.Local.sbo.rules",
	}
	for in, want := range cases {
		if got := RulePrefix(in); got != want {
			t.Errorf("RulePrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"1.0.0", "1.0.1", -1}, {"1.10.0", "1.9.9", 1}, {"1.0.0", "1.0.0", 0}, {"x", "1.0.0", -1}, {"01.0.0", "1.0.0", -1}} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%s, %s) = %d", c.a, c.b, got)
		}
	}
}

// TestShippedPackBar is milestone 5's floor check: in the embedded pack a
// rule under the 0.8 bar never blocks, a noisy rule (precision under 0.5)
// never blocks, and no rule blocks without the operator's spot-check.
func TestShippedPackBar(t *testing.T) {
	p, err := Floor()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Manifest.Rules {
		under := r.Precision == nil || r.Precision.WilsonLower < BlockingLowerBound
		switch {
		case r.Blocking && under:
			t.Errorf("%s blocks under the bar", r.ID)
		case r.Blocking && r.Noisy():
			t.Errorf("%s blocks while noisy", r.ID)
		case r.Blocking && r.OperatorSpotcheck == nil:
			t.Errorf("%s blocks without the operator's spot-check", r.ID)
		case r.BlockingEligible() != r.Blocking:
			t.Errorf("%s: blocking %v but eligible %v", r.ID, r.Blocking, r.BlockingEligible())
		}
	}
}

// TestPassesOneEffectivePass is the rule's own table (lane SEC-G4 audit
// finding 1).
func TestPassesOneEffectivePass(t *testing.T) {
	cases := []struct {
		name string
		p    Passes
		one  bool
	}{
		{"97 of 97 on both", Passes{Results: 97, VerdictAgreements: 97, ReasonAgreements: 97}, true},
		{"20 of 20 on both", Passes{Results: 20, VerdictAgreements: 20, ReasonAgreements: 20}, true},
		{"19 of 19 on both (too few to judge)", Passes{Results: 19, VerdictAgreements: 19, ReasonAgreements: 19}, false},
		{"every verdict, 483 of 529 reasons (SEC-G3)", Passes{Results: 529, VerdictAgreements: 529, ReasonAgreements: 483}, false},
		{"a verdict differs", Passes{Results: 97, VerdictAgreements: 96, ReasonAgreements: 96}, false},
		{"unanimous, attested isolated", Passes{Results: 97, VerdictAgreements: 97, ReasonAgreements: 97, SecondPassAttestedIsolated: true}, false},
	}
	for _, c := range cases {
		if got := c.p.OneEffectivePass(); got != c.one {
			t.Errorf("%s: OneEffectivePass = %v, want %v", c.name, got, c.one)
		}
		if got := (Precision{Passes: &c.p}).OneEffectivePass(); got != c.one {
			t.Errorf("%s: Precision.OneEffectivePass = %v, want %v", c.name, got, c.one)
		}
	}
	if (Precision{}).OneEffectivePass() {
		t.Error("a figure with no passes recorded is not one effective pass")
	}
}
