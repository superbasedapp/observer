package secassess

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// tsLimit is one { id, applies, text } entry read out of the TypeScript.
type tsLimit struct{ id, applies, text string }

// limitsTSSource reads web/src/lib/secAssessModel.ts, or skips when the web
// sources are not in this tree (the public tree), as the secassesssvc pins do.
func limitsTSSource(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "lib", "secAssessModel.ts"))
	if err != nil {
		t.Skipf("the web sources are not in this tree: %v", err)
	}
	return string(src)
}

// limitsEntryRE matches one entry of the table: the three keys in order and a
// double-quoted string for the text (the texts hold plain ASCII and no quote
// of their own). The text may sit on the next line after its key.
var limitsEntryRE = regexp.MustCompile(`\{\s*id:\s*("[^"\\]*"),\s*applies:\s*("[^"\\]*"),\s*text:\s*("(?:[^"\\\n]|\\.)*"),?\s*\}`)

// tsHonestLimits extracts every entry of HONEST_LIMITS. A string literal is
// decoded with strconv.Unquote, which refuses an escape the two languages do
// not share, so a TypeScript text that needs a richer decoder fails here
// instead of being misread.
func tsHonestLimits(t *testing.T, src string) []tsLimit {
	t.Helper()
	block := regexp.MustCompile(`(?s)export const HONEST_LIMITS[^=]*=\s*\[(.*?)\n\];`).FindStringSubmatch(src)
	if block == nil {
		t.Fatal("HONEST_LIMITS was not found in secAssessModel.ts")
	}
	var out []tsLimit
	for _, m := range limitsEntryRE.FindAllStringSubmatch(block[1], -1) {
		var l tsLimit
		for i, dst := range []*string{&l.id, &l.applies, &l.text} {
			s, err := strconv.Unquote(m[i+1])
			if err != nil {
				t.Fatalf("a string literal of HONEST_LIMITS cannot be decoded (%v): %s", err, m[i+1])
			}
			*dst = s
		}
		out = append(out, l)
	}
	// Every entry must have been read: count the ids the block holds.
	if want := strings.Count(block[1], "id: \""); want != len(out) {
		t.Fatalf("HONEST_LIMITS holds %d entries and %d were read: the entry shape changed, extend limitsEntryRE", want, len(out))
	}
	return out
}

// TestLimitsMatchTheWeb pins the Go table to the TypeScript one: order, id,
// group and text. The web is the wording owner today.
func TestLimitsMatchTheWeb(t *testing.T) {
	web := tsHonestLimits(t, limitsTSSource(t))
	if len(web) != len(HonestLimits) {
		t.Fatalf("the web has %d limits and the Go table %d", len(web), len(HonestLimits))
	}
	for i, w := range web {
		g := HonestLimits[i]
		if g.ID != w.id || g.Applies != w.applies || g.Text != w.text {
			t.Errorf("limit %d differs:\n web: %q %q %q\n  go: %q %q %q", i+1, w.id, w.applies, w.text, g.ID, g.Applies, g.Text)
		}
	}
}

// TestLimitsContractGroupsMatchTheWeb pins the table that says which group a
// contract reads: CONTRACT_LIMIT_GROUP in the TypeScript.
func TestLimitsContractGroupsMatchTheWeb(t *testing.T) {
	src := limitsTSSource(t)
	block := regexp.MustCompile(`(?s)const CONTRACT_LIMIT_GROUP[^=]*=\s*new Map\(\[(.*?)\]\);`).FindStringSubmatch(src)
	if block == nil {
		t.Fatal("CONTRACT_LIMIT_GROUP was not found in secAssessModel.ts")
	}
	web := map[string]string{}
	for _, m := range regexp.MustCompile(`\["([^"]+)",\s*"([^"]+)"\]`).FindAllStringSubmatch(block[1], -1) {
		web[m[1]] = m[2]
	}
	if len(web) != len(limitGroupOfContract) {
		t.Fatalf("the web maps %d contracts and Go %d: %v vs %v", len(web), len(limitGroupOfContract), web, limitGroupOfContract)
	}
	for c, g := range limitGroupOfContract {
		if web[string(c)] != g {
			t.Errorf("contract %q: web group %q, Go group %q", c, web[string(c)], g)
		}
	}
}

// TestLimitsTable pins the shape of the table on its own: 20 limits, ids l1 to
// l20 in order, a closed group word, and a text that is one plain line.
func TestLimitsTable(t *testing.T) {
	if len(HonestLimits) != 20 {
		t.Fatalf("%d limits, want 20", len(HonestLimits))
	}
	groups := map[string]bool{LimitsBoth: true, LimitsThreatModel: true, LimitsPentest: true}
	for i, l := range HonestLimits {
		if want := "l" + strconv.Itoa(i+1); l.ID != want {
			t.Errorf("limit %d has the id %q, want %q", i+1, l.ID, want)
		}
		if !groups[l.Applies] {
			t.Errorf("%s has the group %q", l.ID, l.Applies)
		}
		if l.Text == "" || strings.ContainsAny(l.Text, "\n\r\t") || l.Text != strings.TrimSpace(l.Text) {
			t.Errorf("%s has a text that is not one trimmed line: %q", l.ID, l.Text)
		}
	}
}

// TestLimitsFor is a table of contracts and the ids each reads, in order.
func TestLimitsFor(t *testing.T) {
	both := []string{"l1", "l2", "l3", "l4", "l5", "l6", "l7"}
	tm := append(append([]string(nil), both...), "l8", "l9", "l10", "l11")
	pt := append(append([]string(nil), both...), "l12", "l13", "l14", "l15", "l16", "l17", "l18", "l19", "l20")
	tests := []struct {
		name string
		c    Contract
		want []string
	}{
		{"threat model", ContractThreatModel, tm},
		{"pen test", ContractPentest, pt},
		{"retest", ContractRetest, pt},
		{"sarif reads only the shared rows", ContractSARIF, both},
		{"an empty contract reads only the shared rows", "", both},
		{"a contract this build does not know", "future.v9", both},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, l := range LimitsFor(tc.c) {
				got = append(got, l.ID)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("LimitsFor(%q) = %v, want %v", tc.c, got, tc.want)
			}
		})
	}
}

// TestLimitsForReturnsACopy: a caller that edits the returned slice does not
// change the table.
func TestLimitsForReturnsACopy(t *testing.T) {
	got := LimitsFor(ContractThreatModel)
	got[0].Text = "changed"
	if HonestLimits[0].Text == "changed" || LimitsFor(ContractThreatModel)[0].Text == "changed" {
		t.Fatal("LimitsFor shares the table")
	}
}

// TestLimitsWording applies the shared clearance list (testdata/
// clearance_words.json) to every limit: the sentences say what the check did
// not do, and never that a result is clean, safe or passed.
func TestLimitsWording(t *testing.T) {
	banned := rdBannedPattern(t)
	for _, l := range HonestLimits {
		if m := banned.FindString(l.Text); m != "" {
			t.Errorf("%s uses the word %q: %q", l.ID, m, l.Text)
		}
	}
}

// TestLimitText: the lookup the exports use for the sentence about what the
// check covered.
func TestLimitText(t *testing.T) {
	if limitText("l1") != HonestLimits[0].Text || limitText("l1") == "" {
		t.Errorf("limitText(l1) = %q", limitText("l1"))
	}
	if limitText("l99") != "" || limitText("") != "" {
		t.Error("an id that is not in the table must read as empty")
	}
}
