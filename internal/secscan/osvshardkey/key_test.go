package osvshardkey

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestBase(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"npm", "npm"},
		{"GitHub Actions", "GitHub Actions"},
		{"Debian:12", "Debian"},
		{"Ubuntu:24.04:LTS", "Ubuntu"},
		{"Red Hat:enterprise_linux:9::baseos", "Red Hat"},
		{"Maven:https://repo.maven.apache.org/maven2/", "Maven"},
		{"", ""},
	} {
		if got := Base(tc.in); got != tc.want {
			t.Errorf("Base(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanon(t *testing.T) {
	for _, tc := range []struct{ base, in, want string }{
		{"npm", "Rambox", "rambox"},
		{"npm", "@Scope/Name", "@scope/name"},
		{"PyPI", "Zope.Interface", "zope-interface"},
		{"PyPI", "zope__interface", "zope-interface"},
		{"PyPI", "a-_.-b", "a-b"},
		{"PyPI", "requests", "requests"},
		// PEP 503 is PyPI's alone: an npm name keeps its dots.
		{"npm", "lodash.merge", "lodash.merge"},
		{"Go", "github.com/Azure/azure-sdk-for-go/sdk/azidentity", "github.com/azure/azure-sdk-for-go/sdk/azidentity"},
		{"GitHub Actions", "Azure/setup-kubectl", "azure/setup-kubectl"},
		{"NuGet", "Magick.NET-Q8-AnyCPU", "magick.net-q8-anycpu"},
		{"Maven", "org.Apache:Commons", "org.apache:commons"},
		{"Debian", "linux", "linux"},
	} {
		if got := Canon(tc.base, tc.in); got != tc.want {
			t.Errorf("Canon(%q, %q) = %q, want %q", tc.base, tc.in, got, tc.want)
		}
	}
}

// TestKeyGolden pins the key bytes (sha256 of base, NUL, canon name) so a
// change of the hash input is loud: the publisher and every node must agree.
func TestKeyGolden(t *testing.T) {
	for _, tc := range []struct {
		base, name, want string
		bits             int
		prefix           uint32
	}{
		{"npm", "lodash", "78e080abcc5bd58318a2482851d33375a0f75e06eb3dc02ccf91f3bd988ae2cb", 13, 3868},
		{"npm", "LoDash", "78e080abcc5bd58318a2482851d33375a0f75e06eb3dc02ccf91f3bd988ae2cb", 8, 0x78},
		{"PyPI", "Zope.Interface", "58ef90e1a6f4af57702b8f392f987ce10422b40ca424c264f8f4764230a95860", 10, 0x58ef >> 6},
		{"GitHub Actions", "Azure/setup-kubectl", "3381e4cc8b23d5870a6df229efe902feeb302ee3ae6f97662674e2dc7c87811d", 8, 0x33},
		{"Debian", "linux", "8078d8ee711309a7ab924e150dcf64a02c56ea3f18fad8cb0a27538c6f79e887", 9, 0x8078 >> 7},
	} {
		k := KeyOf(tc.base, tc.name)
		if got := hex.EncodeToString(k[:]); got != tc.want {
			t.Errorf("KeyOf(%q, %q) = %s, want %s", tc.base, tc.name, got, tc.want)
		}
		if got := k.Prefix(tc.bits); got != tc.prefix {
			t.Errorf("%s/%s prefix at %d bits = %d, want %d", tc.base, tc.name, tc.bits, got, tc.prefix)
		}
		if got := FirstByte(k.Prefix(tc.bits), tc.bits); got != int(k[0]) {
			t.Errorf("%s/%s first byte = %d, want %d", tc.base, tc.name, got, k[0])
		}
	}
}

// TestBaseIsPartOfTheKey: one name in two ecosystems lands in two keys, so
// a set never answers for another ecosystem's names.
func TestBaseIsPartOfTheKey(t *testing.T) {
	if KeyOf("npm", "requests") == KeyOf("PyPI", "requests") {
		t.Fatal("npm and PyPI requests share a key")
	}
	if KeyOf("Debian", "openssl") == KeyOf("Ubuntu", "openssl") {
		t.Fatal("Debian and Ubuntu openssl share a key")
	}
}

func TestPrefixesUnion(t *testing.T) {
	// The Go rule: hash the raw module path and ParsePackage's rebuild, fetch
	// the union. Two spellings that canonicalise alike cost one prefix.
	raw := "github.com/BurntSushi/toml"
	got := Prefixes("Go", 9, raw, "github.com/burntsushi/toml", "", raw)
	if len(got) != 1 {
		t.Fatalf("case variants gave %d prefixes, want 1", len(got))
	}
	two := Prefixes("Go", 9, "golang.org/x/text", "golang.org/x/net")
	want := []uint32{PrefixOf("Go", "golang.org/x/text", 9), PrefixOf("Go", "golang.org/x/net", 9)}
	if want[0] > want[1] {
		want[0], want[1] = want[1], want[0]
	}
	if want[0] == want[1] {
		want = want[:1]
	}
	if !reflect.DeepEqual(two, want) {
		t.Fatalf("Prefixes = %v, want %v", two, want)
	}
	if len(Prefixes("Go", 9)) != 0 {
		t.Fatal("no names gave a prefix")
	}
}

func TestBitsBounds(t *testing.T) {
	k := KeyOf("npm", "lodash")
	for bits := MinBits; bits <= MaxBits; bits++ {
		p := k.Prefix(bits)
		if p >= 1<<uint(bits) {
			t.Fatalf("prefix %d does not fit %d bits", p, bits)
		}
		if FirstByte(p, bits) != int(k[0]) {
			t.Fatalf("first byte at %d bits", bits)
		}
	}
	if ValidBits(MinBits-1) || ValidBits(MaxBits+1) || !ValidBits(13) {
		t.Fatal("ValidBits bounds")
	}
}

func TestNameRules(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range NameRules {
		if seen[r.Base] {
			t.Errorf("base %q repeats", r.Base)
		}
		seen[r.Base] = true
		if !ValidBits(r.DefaultBits) || r.NodeName == "" || Base(r.Base) != r.Base {
			t.Errorf("row %+v", r)
		}
		if got, ok := RuleFor(r.Base); !ok || got != r {
			t.Errorf("RuleFor(%q)", r.Base)
		}
	}
	// RM-0's recommendation, plan section 13.11 item 2, and the six
	// ecosystems mirrored since 2026-11-06, sized by the same rule from
	// their record counts (every one far under crates.io's 3,036 records at
	// the floor).
	want := map[string]int{
		"npm": 13, "PyPI": 10, "Go": 9, "Maven": 9, "crates.io": 8, "RubyGems": 8, "Packagist": 9, "NuGet": 9, "GitHub Actions": 8,
		"Debian": 9, "Ubuntu": 11, "Alpine": 8, "Red Hat": 11, "Rocky Linux": 8,
		"Pub": 8, "SwiftURL": 8, "Hex": 8, "Hackage": 8, "Julia": 8, "CRAN": 8,
	}
	for base, bits := range want {
		if r, ok := RuleFor(base); !ok || r.DefaultBits != bits {
			t.Errorf("%s: bits %d, want %d", base, r.DefaultBits, bits)
		}
	}
	if len(NameRules) != len(want) {
		t.Errorf("%d rows, want %d", len(NameRules), len(want))
	}
	for _, unlisted := range []string{"opam", "GIT", "ConanCenter", "hex"} {
		if _, ok := RuleFor(unlisted); ok {
			t.Errorf("the unlisted ecosystem %q has a row (a base is spelled exactly as OSV spells it)", unlisted)
		}
	}
}

// TestNewEcosystemKeys pins the six ecosystems mirrored since 2026-11-06:
// a name keys alike in either case (the publisher hashes the record's
// spelling, the node the extractor's), and the key is the base's own, so a
// name shared by two ecosystems never lands in the other's shard.
func TestNewEcosystemKeys(t *testing.T) {
	cases := []struct {
		base, record, node string
	}{
		{"Pub", "dio", "dio"},
		{"SwiftURL", "github.com/Alamofire/Alamofire", "github.com/alamofire/alamofire"},
		{"Hex", "plug", "Plug"},
		{"Hackage", "Cabal", "cabal"},
		{"Julia", "HTTP", "HTTP"},
		{"CRAN", "readxl", "readxl"},
	}
	for _, c := range cases {
		r, ok := RuleFor(c.base)
		if !ok {
			t.Fatalf("%s: no row", c.base)
		}
		// The set is named by the ecosystem itself (no space to spell).
		if !ValidSetName(c.base) {
			t.Errorf("%s is not a set name", c.base)
		}
		if KeyOf(c.base, c.record) != KeyOf(c.base, c.node) {
			t.Errorf("%s: %q and %q key apart", c.base, c.record, c.node)
		}
		if KeyOf(c.base, c.record).Prefix(r.DefaultBits) != KeyOf(c.base, c.node).Prefix(r.DefaultBits) {
			t.Errorf("%s: %q and %q fall in different shards", c.base, c.record, c.node)
		}
		if KeyOf(c.base, c.record) == KeyOf("npm", c.record) {
			t.Errorf("%s: %q keys like npm's", c.base, c.record)
		}
	}
}

func TestNameHelpers(t *testing.T) {
	if got := MavenName("org.apache.commons", "commons-text"); got != "org.apache.commons:commons-text" {
		t.Errorf("MavenName = %q", got)
	}
	if got := MavenName("", "x"); got != "x" {
		t.Errorf("MavenName no group = %q", got)
	}
	for _, tc := range []struct {
		f                    PackageFormat
		binary, source, want string
	}{
		{FormatDpkg, "libssl3", "openssl", "openssl"},
		{FormatDpkg, "bash", "", "bash"},
		{FormatApk, "libcrypto3", "openssl", "openssl"},
		{FormatRPM, "openssl-libs", "openssl", "openssl-libs"},
		{"", "x", "y", "x"},
	} {
		if got := OSPackageName(tc.f, tc.binary, tc.source); got != tc.want {
			t.Errorf("OSPackageName(%s, %q, %q) = %q, want %q", tc.f, tc.binary, tc.source, got, tc.want)
		}
	}
}
