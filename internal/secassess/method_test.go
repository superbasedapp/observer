package secassess

import (
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// mBannedWords are words Observer never says as a claim about an agent's
// result (depth plan section 13): none of the text this lane renders may carry
// one. A claim of enforcement is in the list too: the rules of a prompt are
// prompt rules, and the words must not say otherwise. The match is on whole
// words, case insensitive, so a technical word such as "authenticated" (a flow
// property the agent records) is not the claim "authentic".
var mBannedWords = regexp.MustCompile(`(?i)\b(confirmed|verified|vulnerable|clean|secure|authentic|guaranteed|enforced|prevented|blocked)\b`)

// mCheckWords fails the test for every banned word in text.
func mCheckWords(t *testing.T, label, text string) {
	t.Helper()
	for _, w := range mBannedWords.FindAllString(text, -1) {
		t.Errorf("%s says %q: %q", label, w, text)
	}
}

// mStepIDs maps rendered step lines back to their ids.
func mStepIDs(t *testing.T, lines []string) []string {
	t.Helper()
	var ids []string
	for _, l := range lines {
		found := ""
		for _, s := range tmMethod {
			if s.Text == l {
				found = s.ID
			}
		}
		if found == "" {
			t.Fatalf("line %q is not a step text", l)
		}
		ids = append(ids, found)
	}
	return ids
}

func TestTMMethodTableShape(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range tmMethod {
		t.Run(s.ID, func(t *testing.T) {
			if s.ID == "" || seen[s.ID] {
				t.Fatalf("step id %q is empty or repeated", s.ID)
			}
			seen[s.ID] = true
			if _, ok := tmMethodConditions[s.When]; !ok {
				t.Fatalf("step %s has the unknown condition %q", s.ID, s.When)
			}
			if strings.TrimSpace(s.Text) == "" || strings.ContainsAny(s.Text, "\r\n") {
				t.Fatalf("step %s text is empty or has a line break: %q", s.ID, s.Text)
			}
			if r := []rune(s.Text)[0]; unicode.IsDigit(r) || !unicode.IsUpper(r) {
				t.Errorf("step %s text must start with a capital and carry no number: %q", s.ID, s.Text)
			}
			if clean(s.Text, 4096) != s.Text {
				t.Errorf("step %s text is changed by clean (a backtick, a space run or a dash run)", s.ID)
			}
		})
	}
	// Every condition in the table is used by at least one step.
	for cond := range tmMethodConditions {
		used := false
		for _, s := range tmMethod {
			used = used || s.When == cond
		}
		if !used {
			t.Errorf("condition %q is used by no step", cond)
		}
	}
}

func TestTMMethodLinesSelection(t *testing.T) {
	all := []string{FrameworkSTRIDE, FrameworkLINDDUN, FrameworkOWASPLLM, FrameworkOWASPAgentic}
	both := []string{ExtraAbuseCases, ExtraAttackTrees}
	base := []string{"decompose", "enumerate", "rate", "mitigations", "report"}
	cases := []struct {
		name string
		in   TMMethodInput
		want []string
	}{
		{
			"every optional step on",
			TMMethodInput{Frameworks: all, MethodExtras: both, AIApp: true, Scoped: true},
			[]string{"scope", "decompose", "enumerate", "linddun", "ai", "rate", "abuse_cases", "attack_trees", "mitigations", "report"},
		},
		{"nothing optional", TMMethodInput{Frameworks: []string{FrameworkSTRIDE}}, base},
		{"nil frameworks take all, but not an AI step without an AI app", TMMethodInput{}, []string{"decompose", "enumerate", "linddun", "rate", "mitigations", "report"}},
		{"nil frameworks and an AI app", TMMethodInput{AIApp: true}, []string{"decompose", "enumerate", "linddun", "ai", "rate", "mitigations", "report"}},
		{"AI frameworks but not an AI app", TMMethodInput{Frameworks: all}, []string{"decompose", "enumerate", "linddun", "rate", "mitigations", "report"}},
		{"an AI app but only STRIDE in force", TMMethodInput{Frameworks: []string{FrameworkSTRIDE}, AIApp: true}, base},
		{
			"an AI app, one AI framework",
			TMMethodInput{Frameworks: []string{FrameworkSTRIDE, FrameworkOWASPLLM}, AIApp: true},
			[]string{"decompose", "enumerate", "ai", "rate", "mitigations", "report"},
		},
		{
			"an AI app, the other AI framework",
			TMMethodInput{Frameworks: []string{FrameworkSTRIDE, FrameworkOWASPAgentic}, AIApp: true},
			[]string{"decompose", "enumerate", "ai", "rate", "mitigations", "report"},
		},
		{
			"LINDDUN only",
			TMMethodInput{Frameworks: []string{FrameworkSTRIDE, FrameworkLINDDUN}},
			[]string{"decompose", "enumerate", "linddun", "rate", "mitigations", "report"},
		},
		{
			"abuse cases only",
			TMMethodInput{Frameworks: []string{FrameworkSTRIDE}, MethodExtras: []string{ExtraAbuseCases}},
			[]string{"decompose", "enumerate", "rate", "abuse_cases", "mitigations", "report"},
		},
		{
			"attack trees only",
			TMMethodInput{Frameworks: []string{FrameworkSTRIDE}, MethodExtras: []string{ExtraAttackTrees}},
			[]string{"decompose", "enumerate", "rate", "attack_trees", "mitigations", "report"},
		},
		{
			"scoped",
			TMMethodInput{Frameworks: []string{FrameworkSTRIDE}, Scoped: true},
			[]string{"scope", "decompose", "enumerate", "rate", "mitigations", "report"},
		},
		{"an empty, non-nil framework list is STRIDE alone", TMMethodInput{Frameworks: []string{}, AIApp: true}, base},
		{"an unknown framework word adds nothing", TMMethodInput{Frameworks: []string{"nope"}}, base},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mStepIDs(t, TMMethodLines(tc.in))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("steps = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTMMethodPresetsAgree walks the framework and extras presets the
// settings offer and checks each yields the steps its words promise.
func TestTMMethodPresetsAgree(t *testing.T) {
	for _, p := range FrameworkPresets {
		for _, ai := range []bool{false, true} {
			ids := mStepIDs(t, TMMethodLines(TMMethodInput{Frameworks: p.Members, AIApp: ai}))
			gotL, gotAI := has(ids, "linddun"), has(ids, "ai")
			wantL := has(p.Members, FrameworkLINDDUN)
			wantAI := ai && (has(p.Members, FrameworkOWASPLLM) || has(p.Members, FrameworkOWASPAgentic))
			if gotL != wantL || gotAI != wantAI {
				t.Errorf("preset %s ai=%v: linddun=%v ai=%v, want %v %v", p.ID, ai, gotL, gotAI, wantL, wantAI)
			}
		}
	}
	for _, p := range MethodExtraPresets {
		ids := mStepIDs(t, TMMethodLines(TMMethodInput{Frameworks: []string{FrameworkSTRIDE}, MethodExtras: p.Members}))
		if has(ids, "abuse_cases") != has(p.Members, ExtraAbuseCases) || has(ids, "attack_trees") != has(p.Members, ExtraAttackTrees) {
			t.Errorf("extras preset %s gives steps %v", p.ID, ids)
		}
	}
}

func TestTMMethodEnumerateFollowsTheChart(t *testing.T) {
	var enumerate string
	for _, s := range tmMethod {
		if s.ID == "enumerate" {
			enumerate = s.Text
		}
	}
	for _, c := range []struct {
		class DFDClass
		logs  bool
	}{{ClassExternalEntity, false}, {ClassProcess, false}, {ClassDataStore, false}, {ClassDataFlow, false}} {
		want := strideApplies(c.class, c.logs)
		if !strings.Contains(enumerate, want) {
			t.Errorf("enumerate step lacks the %s categories %q", c.class, want)
		}
	}
	if want := "and " + strideLogStoreExtra() + " for a log or audit store"; !strings.Contains(enumerate, want) {
		t.Errorf("enumerate step lacks %q", want)
	}
	if strideLogStoreExtra() != "repudiation" {
		t.Errorf("a log store adds %q, want repudiation", strideLogStoreExtra())
	}
	if strideApplies(ClassProcess, false) != "all six" {
		t.Errorf("a process takes %q", strideApplies(ClassProcess, false))
	}
	// Every STRIDE category the chart gives a class is a real category id.
	for _, c := range []DFDClass{ClassExternalEntity, ClassProcess, ClassDataStore, ClassDataFlow} {
		for _, id := range ApplicableStride(c, true) {
			if _, ok := StrideCategoryByID(id); !ok {
				t.Errorf("chart category %q is not a STRIDE category", id)
			}
		}
	}
}

// TestTMMethodNamesSchemaWords pins the field names and closed words the
// steps tell the agent to use: each must be a word the model reads.
func TestTMMethodNamesSchemaWords(t *testing.T) {
	text := map[string]string{}
	for _, s := range tmMethod {
		text[s.ID] = s.Text
	}
	rows := []struct{ step, word string }{
		{"scope", "scope.in_scope"},
		{"scope", "scope.out_of_scope"},
		{"scope", "scope.assumptions"},
		{"decompose", "open_questions"},
		{"enumerate", "no_threat"},
		{"enumerate", "STRIDE"},
		{"enumerate", "do not skip a cell"},
		{"linddun", "personal_data"},
		{"linddun", "no_threat"},
		{"linddun", "framework linddun"},
		{"ai", "owasp_llm (LLM01 to LLM10)"},
		{"ai", "owasp_agentic (ASI01 to ASI10)"},
		{"rate", "1 to 5"},
		{"abuse_cases", "abuse_case"},
		{"attack_trees", "attack tree"},
		{"mitigations", "existing"},
		{"mitigations", "missing"},
		{"mitigations", "needle"},
		{"mitigations", "8 or more characters"},
		{"mitigations", "not a mitigation"},
		{"report", "report.md"},
	}
	for _, r := range rows {
		if !strings.Contains(text[r.step], r.word) {
			t.Errorf("step %s lacks %q", r.step, r.word)
		}
	}
	// The effort words and the framework ids are the schema's own.
	for _, e := range EnumEffort {
		if !strings.Contains(text["mitigations"], e) {
			t.Errorf("mitigations step lacks effort %q", e)
		}
	}
	for _, f := range AIFrameworks {
		if !strings.Contains(text["ai"], f.ID) {
			t.Errorf("ai step lacks framework %q", f.ID)
		}
	}
	if !strings.Contains(text["linddun"], FrameworkLINDDUN) || len(LinddunCategories) != 7 {
		t.Errorf("linddun step says seven categories; the table has %d", len(LinddunCategories))
	}
	if len(StrideCategories) != 6 {
		t.Errorf("the enumerate step says all six; the table has %d", len(StrideCategories))
	}
	// The step on mitigations repeats the needle floor the reference rule uses.
	if minNeedleRunes != 8 {
		t.Errorf("the mitigations step says 8 characters; minNeedleRunes is %d", minNeedleRunes)
	}
}

func TestTMMethodSizes(t *testing.T) {
	everything := TMMethodInput{
		Frameworks:   []string{FrameworkSTRIDE, FrameworkLINDDUN, FrameworkOWASPLLM, FrameworkOWASPAgentic},
		MethodExtras: []string{ExtraAbuseCases, ExtraAttackTrees}, AIApp: true, Scoped: true,
	}
	lines := TMMethodLines(everything)
	if len(lines) != len(tmMethod) {
		t.Fatalf("every optional step on gives %d of %d steps", len(lines), len(tmMethod))
	}
	total := 0
	for _, l := range lines {
		total += len(l) + 1
	}
	const cap = 4 << 10
	if total >= cap {
		t.Errorf("the method steps are %d bytes, over the %d plan cap", total, cap)
	}
	if band := total + len(BandMethodText) + 1; band >= cap {
		t.Errorf("steps and the band text are %d bytes together, over the %d plan cap", band, cap)
	}
	if len(BandMethodText) >= 600 {
		t.Errorf("BandMethodText is %d bytes, cap 600", len(BandMethodText))
	}
	t.Logf("tm method %d bytes, band text %d bytes", total, len(BandMethodText))
}

// mReachable are the likelihood-times-impact products a rating of 1 to 5 by
// 1 to 5 can reach.
func mReachable() []int {
	seen := map[int]bool{}
	var out []int
	for l := 1; l <= 5; l++ {
		for i := 1; i <= 5; i++ {
			if p := l * i; !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Ints(out)
	return out
}

// mRatingOf finds a rating with the given product.
func mRatingOf(t *testing.T, product int) Rating {
	t.Helper()
	for l := 1; l <= 5; l++ {
		for i := 1; i <= 5; i++ {
			if l*i == product {
				return Rating{Likelihood: l, Impact: i}
			}
		}
	}
	t.Fatalf("no rating has product %d", product)
	return Rating{}
}

func TestBandMethodText(t *testing.T) {
	if got := renderBandMethod(); got != BandMethodText {
		t.Fatalf("BandMethodText drifted from the band table:\n have %q\n want %q", BandMethodText, got)
	}
	// The ranges are contiguous, cover 1 to 25 and follow the band order.
	if len(riskBandEdges) != len(Bands) {
		t.Fatalf("%d band rows for %d bands", len(riskBandEdges), len(Bands))
	}
	prev := 0
	for i, e := range riskBandEdges {
		if e.Band != Bands[i] || e.Min != prev+1 || e.Max < e.Min {
			t.Errorf("band row %d = %+v breaks the order or contiguity (previous max %d)", i, e, prev)
		}
		prev = e.Max
	}
	if prev != 25 {
		t.Errorf("the ranges end at %d, not 25", prev)
	}
	reach := mReachable()
	// Every reachable product falls in the band the table says BandOf gives.
	for _, p := range reach {
		want := Band("")
		for _, e := range riskBandEdges {
			if p >= e.Min && p <= e.Max {
				want = e.Band
			}
		}
		if got := BandOf(mRatingOf(t, p)); got != want {
			t.Errorf("product %d: BandOf says %q, the table says %q", p, got, want)
		}
	}
	// At each edge, the nearest reachable product on the inside is in the band
	// (a range edge that no rating reaches, such as 7 or 13, is held by the
	// nearest one that does).
	for _, e := range riskBandEdges {
		lo, hi := 0, 0
		for _, p := range reach {
			if p >= e.Min && lo == 0 {
				lo = p
			}
			if p <= e.Max {
				hi = p
			}
		}
		for _, p := range []int{lo, hi} {
			if got := BandOf(mRatingOf(t, p)); got != e.Band {
				t.Errorf("band %s edge product %d: BandOf says %q", e.Band, p, got)
			}
		}
	}
	// The one-past-the-edge neighbours belong to the next band, by BandOf.
	for i := 0; i+1 < len(riskBandEdges); i++ {
		next := 0
		for _, p := range reach {
			if p > riskBandEdges[i].Max {
				next = p
				break
			}
		}
		if got := BandOf(mRatingOf(t, next)); got != riskBandEdges[i+1].Band {
			t.Errorf("first product past %s is %d: BandOf says %q, want %s", riskBandEdges[i].Band, next, got, riskBandEdges[i+1].Band)
		}
	}
	for _, e := range riskBandEdges {
		want := string(e.Band) + " " + strconv.Itoa(e.Min) + "-" + strconv.Itoa(e.Max)
		if !strings.Contains(BandMethodText, want) {
			t.Errorf("BandMethodText lacks %q", want)
		}
	}
	for _, w := range []string{"ordinal heuristic", "not a probability", "not a loss figure", "No residual score is computed", "never subtracted from it", "1 to 5"} {
		if !strings.Contains(BandMethodText, w) {
			t.Errorf("BandMethodText lacks %q", w)
		}
	}
}

func TestTMMethodWordsAreHonest(t *testing.T) {
	for _, s := range tmMethod {
		mCheckWords(t, "step "+s.ID, s.Text)
	}
	mCheckWords(t, "BandMethodText", BandMethodText)
}

// TestBannedWordsCheckerCatches proves the checker used by this lane's tests
// sees each banned word and leaves technical words alone.
func TestBannedWordsCheckerCatches(t *testing.T) {
	for _, w := range []string{"confirmed", "Verified", "VULNERABLE", "clean", "secure", "authentic", "guaranteed", "enforced", "prevented", "blocked"} {
		if !mBannedWords.MatchString("a result is " + w + ".") {
			t.Errorf("the checker misses %q", w)
		}
	}
	for _, ok := range []string{"authenticated", "unauthenticated flows", "a cleaner", "security", "insecure transport", "vulnerability", "a secret value"} {
		if mBannedWords.MatchString(ok) {
			t.Errorf("the checker flags %q", ok)
		}
	}
}
