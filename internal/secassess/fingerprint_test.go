package secassess

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestShortFingerprint(t *testing.T) {
	sha1 := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	sha256 := strings.Repeat("AbCdEf0123456789", 4)
	cases := []struct {
		name, in, want string
	}{
		{"sha1 hash", sha1, "da39a3ee5e6b4b0d3255"},
		{"sha256 hash is lower-cased and cut", sha256, "abcdef0123456789abcd"},
		{"exactly the stored length", "0123456789abcdef0123", "0123456789abcdef0123"},
		{"too short", "abc123", ""},
		{"empty", "", ""},
		{"not hex", "da39a3ee5e6b4b0d3255bfef9560189zafd80709", ""},
		{"an error line", "fatal: could not open 'x' for reading: No such file or directory", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ShortFingerprint(c.in)
			if got != c.want || (got != "" && len(got) != FpLen) {
				t.Fatalf("ShortFingerprint(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestLinkFingerprint(t *testing.T) {
	a, b := LinkFingerprint("../shared/config"), LinkFingerprint("/etc/passwd")
	if len(a) != FpLen || a == b || a != LinkFingerprint("../shared/config") {
		t.Fatalf("a = %q, b = %q", a, b)
	}
	// A link never collides with the fingerprint of a file of the same text.
	if ShortFingerprint(a) == "" {
		t.Fatalf("%q is not a stored fingerprint", a)
	}
}

func TestEntryDeleted(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		{" D", true},
		{"D ", true},
		{"AD", true},
		{"MD", true},
		{"DD", true},
		{"UD", true},
		{" M", false},
		{"M ", false},
		{"MM", false},
		{"??", false},
		{"R ", false},
		{"A ", false},
		{"", false},
	}
	for _, c := range cases {
		if got := (TreeEntry{Status: c.status}).Deleted(); got != c.want {
			t.Errorf("Deleted(%q) = %v, want %v", c.status, got, c.want)
		}
	}
}

// TestFingerprintAction: one row of the action table per case.
func TestFingerprintAction(t *testing.T) {
	mod, del, untr := TreeEntry{Status: " M"}, TreeEntry{Status: " D"}, TreeEntry{Status: "??"}
	cases := []struct {
		name string
		e    TreeEntry
		kind FileKind
		size int64
		want FpAction
	}{
		{"modified regular file", mod, FileRegular, 10, FpHash},
		{"untracked regular file", untr, FileRegular, 0, FpHash},
		{"empty regular file", mod, FileRegular, 0, FpHash},
		{"file at the size cap", mod, FileRegular, FpMaxFileBytes, FpHash},
		{"file over the size cap", mod, FileRegular, FpMaxFileBytes + 1, FpSkip},
		{"deleted and gone", del, FileAbsent, 0, FpSetAbsent},
		{"staged delete and gone", TreeEntry{Status: "D "}, FileAbsent, 0, FpSetAbsent},
		{"modified but missing (a race or an unresolved path)", mod, FileAbsent, 0, FpSkip},
		{"untracked but missing", untr, FileAbsent, 0, FpSkip},
		{"deleted but a file is there", del, FileRegular, 5, FpHash},
		{"symbolic link", mod, FileSymlink, 0, FpSetLink},
		{"untracked symbolic link", untr, FileSymlink, 0, FpSetLink},
		{"directory (nested repository or submodule)", mod, FileOther, 0, FpSkip},
		{"unreadable", untr, FileOther, 0, FpSkip},
		{"unknown kind", mod, FileKind("weird"), 0, FpSkip},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FingerprintAction(c.e, c.kind, c.size); got != c.want {
				t.Fatalf("FingerprintAction = %s, want %s", got, c.want)
			}
		})
	}
}

func TestPlanHashBatches(t *testing.T) {
	items := func(n int, path string, size int64) []HashItem {
		out := make([]HashItem, n)
		for i := range out {
			out[i] = HashItem{Path: path + strconv.Itoa(i), Size: size}
		}
		return out
	}
	lens := func(bs [][]int) []int {
		var l []int
		for _, b := range bs {
			l = append(l, len(b))
		}
		return l
	}
	cases := []struct {
		name  string
		items []HashItem
		want  []int // batch sizes
	}{
		{"nothing", nil, nil},
		{"one", items(1, "a", 1), []int{1}},
		{"under every limit", items(10, "a", 1), []int{10}},
		{"the path count splits", items(HashBatchPaths*2+5, "a", 1), []int{HashBatchPaths, HashBatchPaths, 5}},
		{"the command line length splits", items(10, strings.Repeat("p", HashBatchArgBytes/3), 1), []int{2, 2, 2, 2, 2}},
		{"the content size splits", items(5, "a", HashBatchContentBytes/2), []int{2, 2, 1}},
		{"one file over the content limit has a batch of its own", []HashItem{{"a", 1}, {"b", HashBatchContentBytes + 1}, {"c", 1}}, []int{1, 1, 1}},
		{"one path over the line limit has a batch of its own", []HashItem{{"a", 1}, {strings.Repeat("p", HashBatchArgBytes+5), 1}, {"c", 1}}, []int{1, 1, 1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bs := PlanHashBatches(c.items)
			if got := lens(bs); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("batch sizes = %v, want %v", got, c.want)
			}
			// Every item is in exactly one batch, in order.
			next := 0
			for _, b := range bs {
				for _, idx := range b {
					if idx != next {
						t.Fatalf("batches %v are not in order", bs)
					}
					next++
				}
			}
			if next != len(c.items) {
				t.Fatalf("%d of %d items planned", next, len(c.items))
			}
		})
	}
	// Every batch of a 400-entry snapshot stays under the Windows command line.
	long := items(MaxTreeEntries, strings.Repeat("some/long/path/", 5), 1)
	for _, b := range PlanHashBatches(long) {
		n := 0
		for _, idx := range b {
			n += len(long[idx].Path) + 1
		}
		if n > HashBatchArgBytes && len(b) > 1 {
			t.Fatalf("a batch of %d paths is %d bytes of arguments", len(b), n)
		}
	}
}

func TestHashObjectArgs(t *testing.T) {
	got := HashObjectArgs([]string{"-dash.go", "a b.go"})
	want := []string{"hash-object", "--no-filters", "--", "-dash.go", "a b.go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
	// Read-only: the write flag is never present, and the filters are off.
	for _, a := range got[:3] {
		if a == "-w" || a == "--stdin" {
			t.Fatalf("args carry %q", a)
		}
	}
}

func TestParseHashOutput(t *testing.T) {
	h1, h2 := "da39a3ee5e6b4b0d3255bfef95601890afd80709", "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
	cases := []struct {
		name string
		out  string
		want int
		fps  []string
		ok   bool
	}{
		{"two hashes", h1 + "\n" + h2 + "\n", 2, []string{h1[:FpLen], h2[:FpLen]}, true},
		{"crlf line ends", h1 + "\r\n" + h2 + "\r\n", 2, []string{h1[:FpLen], h2[:FpLen]}, true},
		{"no final newline", h1, 1, []string{h1[:FpLen]}, true},
		{"too few lines", h1 + "\n", 2, nil, false},
		{"too many lines", h1 + "\n" + h2 + "\n", 1, nil, false},
		{"an error line", "fatal: could not open 'x'\n", 1, nil, false},
		{"empty output", "", 1, nil, false},
		{"zero wanted, empty output", "", 0, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fps, ok := ParseHashOutput([]byte(c.out), c.want)
			if ok != c.ok || !reflect.DeepEqual(fps, c.fps) {
				t.Fatalf("ParseHashOutput = %v, %v; want %v, %v", fps, ok, c.fps, c.ok)
			}
		})
	}
}
