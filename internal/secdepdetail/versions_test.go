package secdepdetail

import (
	"reflect"
	"testing"
)

// TestComparators: one block per comparatorRows row plus the default.
func TestComparators(t *testing.T) {
	type pair struct {
		a, b string
		want int
		ok   bool
	}
	cases := []struct {
		eco   string
		pairs []pair
	}{
		{"npm", []pair{ // the default (dotted, semver pre-release rules)
			{"4.17.20", "4.17.21", -1, true},
			{"4.17.21", "4.17.21", 0, true},
			{"1.0", "1.0.0", 0, true},
			{"10.0.0", "9.9.9", 1, true},
			{"1.0.0-rc.1", "1.0.0", -1, true},
			{"1.0.0-alpha", "1.0.0-alpha.1", -1, true},
			{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1, true},
			{"1.0.0-beta.2", "1.0.0-beta.11", -1, true},
			{"1.0.0+build.5", "1.0.0", 0, true},
			{"1.0.0.Final", "1.0.0", 0, false},
			{"latest", "1.0.0", 0, false},
		}},
		{"Go", []pair{
			{"v0.3.5", "0.3.8", -1, true},
			{"v0.0.0-20210101000000-abcdef123456", "v0.0.1", -1, true},
			{"v2.0.0+incompatible", "v2.0.0", 0, true},
		}},
		{"PyPI", []pair{
			{"2.19.0", "2.20", -1, true},
			{"1.0", "1.0.0", 0, true},
			{"1.0a1", "1.0", -1, true},
			{"1.0rc1", "1.0b2", 1, true},
			{"1.0.dev1", "1.0a1", -1, true},
			{"1.0.post1", "1.0", 1, true},
			{"1.0", "1.0.post1.dev1", -1, true},
			{"1!1.0", "2.0", 1, true},
			{"1.0+local.7", "1.0", 0, true},
			{"not-a-version", "1.0", 0, false},
		}},
		{"Packagist", []pair{
			{"v4.0.0", "4.1.0", -1, true},
			{"V4.1.0", "v4.1.0", 0, true},
		}},
	}
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.eco] = true
		cmp := ComparatorFor(c.eco)
		for _, p := range c.pairs {
			got, ok := cmp(p.a, p.b)
			if ok != p.ok || (ok && got != p.want) {
				t.Errorf("%s: cmp(%q,%q) = %d,%v want %d,%v", c.eco, p.a, p.b, got, ok, p.want, p.ok)
			}
			if ok {
				if back, _ := cmp(p.b, p.a); back != -p.want {
					t.Errorf("%s: cmp not antisymmetric on %q,%q", c.eco, p.a, p.b)
				}
			}
		}
	}
	for _, r := range comparatorRows {
		if !covered[r.ecosystem] {
			t.Errorf("comparator row %q has no test case", r.ecosystem)
		}
	}
}

// TestNormalizeName: one case per nameNormalizers row plus the exact default.
func TestNormalizeName(t *testing.T) {
	cases := []struct{ eco, in, want string }{
		{"PyPI", "Zope.Interface__x", "zope-interface-x"},
		{"NuGet", "Newtonsoft.Json", "newtonsoft.json"},
		{"Packagist", "Symfony/Http-Kernel", "symfony/http-kernel"},
		{"npm", "Lodash", "Lodash"},
	}
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.eco] = true
		if got := NormalizeName(c.eco, c.in); got != c.want {
			t.Errorf("%s %q -> %q, want %q", c.eco, c.in, got, c.want)
		}
	}
	for _, r := range nameNormalizers {
		if !covered[r.ecosystem] {
			t.Errorf("normalizer row %q has no test case", r.ecosystem)
		}
	}
}

// TestSuggestFix: the smallest fixed version above the current one that
// no range marks affected, and nothing whenever the answer is not clear.
func TestSuggestFix(t *testing.T) {
	adv := func(rs ...Range) []Advisory { return []Advisory{{ID: "GHSA-x", Ranges: rs}} }
	cases := []struct {
		name      string
		eco, cur  string
		advs      []Advisory
		suggested string
		fixed     []string
	}{
		{"one range", "npm", "4.17.20", adv(Range{Introduced: "0", Fixed: "4.17.21"}), "4.17.21", []string{"4.17.21"}},
		{
			"two lines, the current one's fix", "npm", "4.5.0",
			adv(Range{Introduced: "0", Fixed: "4.17.21"}, Range{Introduced: "5.0.0", Fixed: "5.0.1"}), "4.17.21",
			[]string{"4.17.21", "5.0.1"},
		},
		{
			"a fix that is itself affected is skipped", "npm", "1.0.0",
			adv(Range{Introduced: "0", Fixed: "1.1.0"}, Range{Introduced: "1.1.0", Fixed: "1.2.0"}), "1.2.0",
			[]string{"1.1.0", "1.2.0"},
		},
		{
			"no fix for the current range", "npm", "2.0.0",
			adv(Range{Introduced: "0", Fixed: "1.0.0"}, Range{Introduced: "2.0.0"}), "",
			[]string{"1.0.0"},
		},
		{"last_affected only", "npm", "1.0.0", adv(Range{Introduced: "0", LastAffected: "1.5.0"}), "", nil},
		{"current outside every range", "npm", "9.0.0", adv(Range{Introduced: "0", Fixed: "1.0.0"}), "", []string{"1.0.0"}},
		{"unparsable version", "Maven", "1.0.0.Final", adv(Range{Introduced: "0", Fixed: "1.0.1.Final"}), "", []string{"1.0.1.Final"}},
		{"go v prefix", "Go", "v0.3.5", adv(Range{Introduced: "0", Fixed: "0.3.8"}), "0.3.8", []string{"0.3.8"}},
		{"pypi", "PyPI", "2.19.0", adv(Range{Introduced: "0", Fixed: "2.20"}), "2.20", []string{"2.20"}},
		{"no ranges", "npm", "1.0.0", []Advisory{{ID: "GHSA-y", ExplicitVersions: 3}}, "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := SuggestFix(c.eco, c.cur, c.advs)
			if f.Suggested != c.suggested || !reflect.DeepEqual(f.FixedVersions, c.fixed) {
				t.Fatalf("got %+v, want suggested %q fixed %v", f, c.suggested, c.fixed)
			}
		})
	}
}
