package secreach

import "strings"

// matchCrateRecord decides a crates.io finding: the approximate call level
// when the record lists functions and call sites were read (3c), else, and
// whenever it is stronger, the crate import level. It never decides "not
// called", and never "not imported directly": the index holds a Rust
// file's use declarations only, so a crate written as a path elsewhere (a
// type, a macro, a fully qualified call) is invisible to the import list.
func matchCrateRecord(adv Advisory, rec Record, set ImportSet, _ []string) Tier {
	crate := CrateKey(adv.Package)
	imp := crateImportTier(crate, set)
	if call, ok := rustCallTier(crate, rec, set); ok && call.SortRank() > imp.SortRank() {
		return call
	}
	return imp
}

// crateImportTier is the import level of a crate: Imported when a use
// declaration names it, else Unknown (ReasonUseOnly, or ReasonIncomplete
// for an incomplete list).
func crateImportTier(crate string, set ImportSet) Tier {
	if u, ok := set.Uses[crate]; ok {
		return Tier{Level: Imported, Source: set.Source, TestsOnly: !u.NonTest, Match: crate}
	}
	if set.Complete {
		return UnknownTier(ReasonUseOnly)
	}
	return UnknownTier(ReasonIncomplete)
}

// rustFunction is one listed function split: the crate key, the path
// before the function ("smallvec", "SmallVec") and its name.
type rustFunction struct {
	Full   string
	Crate  string
	Parent []string
	Name   string
}

// parseRustFunction splits "crate::path::name"; ok false for anything
// with fewer than two elements or a non-identifier element.
func parseRustFunction(fn string) (rustFunction, bool) {
	segs := strings.Split(fn, "::")
	if len(segs) < 2 {
		return rustFunction{}, false
	}
	for _, s := range segs {
		if !identifier(s) {
			return rustFunction{}, false
		}
	}
	return rustFunction{Full: fn, Crate: CrateKey(segs[0]), Parent: segs[:len(segs)-1], Name: segs[len(segs)-1]}, true
}

// rustCallRule is one row of the call-site table: the first row whose
// When holds for a call whose callee name is the function's name makes the
// call a match. Both rows are name matches, so the tier is approximate.
type rustCallRule struct {
	Name string
	When func(fn rustFunction, path []string, fileUsesCrate bool) bool
}

// rustCallRules is walked top-down per call (one test case per row).
var rustCallRules = []rustCallRule{
	{
		// "smallvec::SmallVec::insert_many(..)" or "SmallVec::insert_many(..)":
		// the written path is a tail of the function's path, and the crate
		// is named by the path itself or by a use declaration of the file.
		Name: "qualified path",
		When: func(fn rustFunction, path []string, fileUsesCrate bool) bool {
			if len(path) == 0 || !pathTailOf(path, fn) {
				return false
			}
			return fileUsesCrate || (len(path) == len(fn.Parent) && CrateKey(path[0]) == fn.Crate)
		},
	},
	{
		// "v.insert_many(..)" or "insert_many(..)": a method or bare call
		// of that name in a file whose use declarations name the crate.
		Name: "callee name in a file that uses the crate",
		When: func(_ rustFunction, path []string, fileUsesCrate bool) bool {
			return len(path) == 0 && fileUsesCrate
		},
	},
}

// pathTailOf reports whether path is a tail of fn's parent path (the
// crate element compared as a crate key).
func pathTailOf(path []string, fn rustFunction) bool {
	if len(path) > len(fn.Parent) {
		return false
	}
	off := len(fn.Parent) - len(path)
	for i, seg := range path {
		want := fn.Parent[off+i]
		if off+i == 0 {
			if CrateKey(seg) != fn.Crate {
				return false
			}
			continue
		}
		if seg != want {
			return false
		}
	}
	return true
}

// rustCallTier is the approximate call level of one record, ok false when
// it cannot be checked (no listed function, no call sites read) or no
// call matched: the import level then decides, never "not called".
func rustCallTier(crate string, rec Record, set ImportSet) (Tier, bool) {
	if !set.CallsRead || len(rec.Functions) == 0 {
		return Tier{}, false
	}
	var fns []rustFunction
	for _, f := range rec.Functions {
		if fn, ok := parseRustFunction(f); ok && fn.Crate == crate {
			fns = append(fns, fn)
		}
	}
	found := false
	best := Tier{}
	for _, c := range set.Calls {
		path := RustCallPath(c.Text, c.Name)
		uses := fileImports(set, c.File, crate)
		for _, fn := range fns {
			if c.Name != fn.Name || !rustCallMatches(fn, path, uses) {
				continue
			}
			t := Tier{Level: Called, Source: SourceRustCallSite, Approximate: true, TestsOnly: c.Test, Match: fn.Full}
			if !found || (!t.TestsOnly && best.TestsOnly) {
				found, best = true, t
			}
			if !t.TestsOnly {
				return best, true
			}
		}
	}
	return best, found
}

func rustCallMatches(fn rustFunction, path []string, fileUsesCrate bool) bool {
	for _, r := range rustCallRules {
		if r.When(fn, path, fileUsesCrate) {
			return true
		}
	}
	return false
}

func fileImports(set ImportSet, file, key string) bool {
	for _, k := range set.FileImports[file] {
		if k == key {
			return true
		}
	}
	return false
}

// RustCallPath reads the qualified path written before a call's callee
// name from the call excerpt ("smallvec::SmallVec::insert_many(x)" gives
// ["smallvec", "SmallVec"]; "Vec::<u8>::new()" gives ["Vec"]); nil for a
// method call ("v.insert_many(x)"), a bare call, or an excerpt it cannot
// read.
func RustCallPath(text, name string) []string {
	if name == "" {
		return nil
	}
	for from := 0; from < len(text); {
		i := strings.Index(text[from:], name)
		if i < 0 {
			return nil
		}
		i += from
		end := i + len(name)
		from = end
		if i > 0 && identByte(text[i-1]) || end < len(text) && identByte(text[end]) {
			continue
		}
		rest := strings.TrimLeft(text[end:], " ")
		if !strings.HasPrefix(rest, "(") && !strings.HasPrefix(rest, "::<") {
			continue
		}
		prefix := strings.TrimRight(text[:i], " ")
		if !strings.HasSuffix(prefix, "::") {
			return nil
		}
		return pathSegments(stripGenerics(strings.TrimSuffix(prefix, "::")))
	}
	return nil
}

// stripGenerics drops balanced "<...>" groups and the "::" before each.
func stripGenerics(s string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '<':
			depth++
		case c == '>' && depth > 0:
			depth--
		case depth == 0:
			b.WriteByte(c)
		}
	}
	return strings.ReplaceAll(b.String(), "::::", "::")
}

// pathSegments reads the trailing "a::b::c" path of s; nil when s does not
// end in one (a method receiver, an expression).
func pathSegments(s string) []string {
	s = strings.TrimSuffix(strings.TrimSpace(s), "::")
	start := len(s)
	for start > 0 && (identByte(s[start-1]) || s[start-1] == ':') {
		start--
	}
	if start > 0 && s[start-1] == '.' {
		return nil
	}
	p := strings.TrimPrefix(s[start:], "::")
	if p == "" {
		return nil
	}
	segs := strings.Split(p, "::")
	for _, seg := range segs {
		if !identifier(seg) {
			return nil
		}
	}
	return segs
}

func identByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// CallNames returns the callee names (each listed function's last
// element) of the records of a finding, deduplicated in order, for the
// call-site read; empty when the records list no functions.
func CallNames(adv Advisory) []string {
	crate := CrateKey(adv.Package)
	seen := map[string]bool{}
	var out []string
	for _, rec := range adv.Records {
		for _, f := range rec.Functions {
			fn, ok := parseRustFunction(f)
			if ok && fn.Crate == crate && !seen[fn.Name] {
				seen[fn.Name] = true
				out = append(out, fn.Name)
			}
		}
	}
	return out
}
