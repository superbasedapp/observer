package sandbox

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestMatchWorkspaceSecret is the rule table, one row per pattern and per
// exclusion (plus the shapes that must NOT match). The want column is the ID
// of the rule that must claim the name, "" for a name no rule claims.
func TestMatchWorkspaceSecret(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want string
	}{
		// .env, exact
		{".env", "dotenv"},
		{".ENV", "dotenv"}, // matched case-insensitively: a mask errs wide
		// .env.*, with the three committed examples excluded
		{".env.local", "dotenv-variant"},
		{".env.production", "dotenv-variant"},
		{".env.development.local", "dotenv-variant"},
		{".Env.Staging", "dotenv-variant"},
		{".env.example", ""},
		{".env.sample", ""},
		{".env.template", ""},
		{".ENV.EXAMPLE", ""},
		{".env.example.local", "dotenv-variant"}, // only the exact example names are excluded
		{".env.", "dotenv-variant"},
		// *.pem
		{"server.pem", "pem"},
		{"CERT.PEM", "pem"},
		{"a.b.pem", "pem"},
		// *.key
		{"tls.key", "key"},
		{"signing.KEY", "key"},
		// id_rsa*
		{"id_rsa", "ssh-rsa"},
		{"id_rsa.pub", "ssh-rsa"}, // the public half is hidden with the pair
		{"id_rsa_work", "ssh-rsa"},
		{"id_rsa_test.go", "ssh-rsa"}, // accepted over-match: the brief's id_rsa* shape
		// id_ed25519*
		{"id_ed25519", "ssh-ed25519"},
		{"id_ed25519.pub", "ssh-ed25519"},
		{"id_ed25519_ci", "ssh-ed25519"},
		// the credential files
		{".npmrc", "npmrc"},
		{".pypirc", "pypirc"},
		{".netrc", "netrc"},
		// names that are not secret files
		{".envrc", ""}, // direnv's file: a different name, not in the table
		{".environment", ""},
		{"env", ""},
		{"environment.ts", ""},
		{"key.go", ""},
		{"monkey", ""},
		{"pem", ""},
		{"keys.json", ""},
		{"id_dsa", ""},
		{"id_ecdsa", ""},
		{"my_id_rsa", ""},
		{".npmrc.bak", ""},
		{"npmrc", ""},
		{".netrc.d", ""},
		{"README.md", ""},
		// not one path component
		{"", ""},
		{"sub/.env", ""},
		{"a\x00.env", ""},
	}
	for _, tc := range tests {
		got, ok := MatchWorkspaceSecret(tc.name)
		if ok != (tc.want != "") || got != tc.want {
			t.Errorf("MatchWorkspaceSecret(%q) = (%q, %v), want rule %q", tc.name, got, ok, tc.want)
		}
	}
}

// TestWorkspaceSecretRulesAreWellFormed: the table is data, so its shape is
// pinned: unique IDs, a known match kind, lower-case patterns, and every
// exclusion is a name its own rule would otherwise claim (an exclusion that
// the rule never matched is dead weight and a typo hiding behind a pass).
func TestWorkspaceSecretRulesAreWellFormed(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, r := range WorkspaceSecretRules {
		if r.ID == "" || seen[r.ID] {
			t.Errorf("rule ID %q is empty or repeated", r.ID)
		}
		seen[r.ID] = true
		switch r.Match {
		case SecretMatchExact, SecretMatchPrefix, SecretMatchSuffix:
		default:
			t.Errorf("rule %s: unknown match kind %q", r.ID, r.Match)
		}
		if r.Pattern == "" || r.Pattern != strings.ToLower(r.Pattern) {
			t.Errorf("rule %s: pattern %q must be non-empty and lower-case", r.ID, r.Pattern)
		}
		for _, e := range r.Except {
			if e != strings.ToLower(e) {
				t.Errorf("rule %s: exception %q must be lower-case", r.ID, e)
			}
			probe := r
			probe.Except = nil
			if !probe.matches(e) {
				t.Errorf("rule %s: exception %q is not a name the rule would claim", r.ID, e)
			}
		}
	}
	// The brief's nine patterns, none dropped.
	for _, id := range []string{"dotenv", "dotenv-variant", "pem", "key", "ssh-rsa", "ssh-ed25519", "npmrc", "pypirc", "netrc"} {
		if !seen[id] {
			t.Errorf("rule %s is missing from WorkspaceSecretRules", id)
		}
	}
	if !reflect.DeepEqual(SecretMaskSkipDirs, []string{".git", "node_modules"}) {
		t.Errorf("SecretMaskSkipDirs = %v, want [.git node_modules]", SecretMaskSkipDirs)
	}
}

// ---- the injected walk ------------------------------------------------------

// maskRoot is an absolute workspace root on the host running the test (the
// planner validates paths with filepath.IsAbs, so a bare /ws is relative on
// Windows).
func maskRoot() string {
	if runtime.GOOS == "windows" {
		return `C:\ws`
	}
	return "/ws"
}

// fakeDirs is an in-memory folder tree behind a MaskDirReader; it records
// every folder it was asked to list.
type fakeDirs struct {
	entries map[string][]MaskDirEntry
	errs    map[string]error
	reads   []string
}

func (f *fakeDirs) read(dir string, max int) ([]MaskDirEntry, bool, error) {
	f.reads = append(f.reads, dir)
	if err, ok := f.errs[dir]; ok {
		return nil, false, err
	}
	es := f.entries[dir]
	if len(es) > max {
		return append([]MaskDirEntry(nil), es[:max]...), true, nil
	}
	return append([]MaskDirEntry(nil), es...), false, nil
}

func file(n string) MaskDirEntry { return MaskDirEntry{Name: n, Kind: MaskEntryFile} }
func dir(n string) MaskDirEntry  { return MaskDirEntry{Name: n, Kind: MaskEntryDir} }
func link(n string) MaskDirEntry { return MaskDirEntry{Name: n, Kind: MaskEntrySymlink} }
func other(n string) MaskDirEntry {
	return MaskDirEntry{Name: n, Kind: MaskEntryOther}
}

func gapSet(r SecretMaskReport) map[string]SecretMaskGapReason {
	out := map[string]SecretMaskGapReason{}
	for _, g := range r.Gaps {
		out[g.Path] = g.Reason
	}
	return out
}

func TestDiscoverFindsSecretsBreadthFirstAndSkipsWhatItShould(t *testing.T) {
	t.Parallel()
	root := maskRoot()
	j := func(p ...string) string { return filepath.Join(append([]string{root}, p...)...) }
	fs := &fakeDirs{entries: map[string][]MaskDirEntry{
		root:             {file("main.go"), dir("app"), file(".env"), dir(".git"), file(".env.example"), dir("node_modules"), file("id_rsa.pub"), dir("observer")},
		j("app"):         {file("config.json"), file("server.key"), dir("deep")},
		j("app", "deep"): {file(".npmrc"), file("tls.pem")},
		// Never read: skipped folders and the excluded one.
		j(".git"):         {file("secret.pem")},
		j("node_modules"): {file(".env")},
		j("observer"):     {file(".env")},
	}}
	rep := DiscoverWorkspaceSecrets(root, fs.read, SecretMaskLimits{}, []string{j("observer")})
	want := []string{j(".env"), j("id_rsa.pub"), j("app", "server.key"), j("app", "deep", ".npmrc"), j("app", "deep", "tls.pem")}
	if !reflect.DeepEqual(rep.Masked, want) {
		t.Fatalf("Masked = %v\n want %v", rep.Masked, want)
	}
	if !rep.Enabled || !rep.Complete() || rep.Root != root {
		t.Fatalf("report = %+v, want enabled and complete over %s", rep, root)
	}
	for _, skipped := range []string{j(".git"), j("node_modules"), j("observer")} {
		if slices.Contains(fs.reads, skipped) {
			t.Errorf("the walk read %s, which it must not enter", skipped)
		}
	}
	if rep.DirsRead != 3 {
		t.Errorf("DirsRead = %d, want 3 (root, app, app/deep)", rep.DirsRead)
	}
}

func TestDiscoverIsDeterministicWhateverTheReaderOrder(t *testing.T) {
	t.Parallel()
	root := maskRoot()
	a := &fakeDirs{entries: map[string][]MaskDirEntry{root: {file(".env"), file("b.key"), file("a.key"), dir("z"), dir("m")}, filepath.Join(root, "m"): {file(".npmrc")}, filepath.Join(root, "z"): {file(".netrc")}}}
	b := &fakeDirs{entries: map[string][]MaskDirEntry{root: {dir("m"), dir("z"), file("a.key"), file("b.key"), file(".env")}, filepath.Join(root, "m"): {file(".npmrc")}, filepath.Join(root, "z"): {file(".netrc")}}}
	ra := DiscoverWorkspaceSecrets(root, a.read, SecretMaskLimits{}, nil)
	rb := DiscoverWorkspaceSecrets(root, b.read, SecretMaskLimits{}, nil)
	if !reflect.DeepEqual(ra.Masked, rb.Masked) {
		t.Fatalf("order depends on the reader: %v vs %v", ra.Masked, rb.Masked)
	}
	// Breadth first, names sorted within a folder.
	j := func(p ...string) string { return filepath.Join(append([]string{root}, p...)...) }
	want := []string{j(".env"), j("a.key"), j("b.key"), j("m", ".npmrc"), j("z", ".netrc")}
	if !reflect.DeepEqual(ra.Masked, want) {
		t.Fatalf("Masked = %v, want %v", ra.Masked, want)
	}
}

func TestDiscoverBounds(t *testing.T) {
	t.Parallel()
	root := maskRoot()
	j := func(p ...string) string { return filepath.Join(append([]string{root}, p...)...) }

	t.Run("depth", func(t *testing.T) {
		t.Parallel()
		fs := &fakeDirs{entries: map[string][]MaskDirEntry{
			root:                {file(".env"), dir("l2")},
			j("l2"):             {file(".npmrc"), dir("l3")},
			j("l2", "l3"):       {file("hidden.key")},
			j("l2", "l3", "l4"): {file("deeper.key")},
		}}
		rep := DiscoverWorkspaceSecrets(root, fs.read, SecretMaskLimits{MaxDepth: 2}, nil)
		if want := []string{j(".env"), j("l2", ".npmrc")}; !reflect.DeepEqual(rep.Masked, want) {
			t.Fatalf("Masked = %v, want %v", rep.Masked, want)
		}
		if got := gapSet(rep); !reflect.DeepEqual(got, map[string]SecretMaskGapReason{j("l2", "l3"): MaskGapDepth}) {
			t.Fatalf("gaps = %v, want the level-3 folder reported as depth_limit", got)
		}
		if rep.Complete() {
			t.Fatal("a tree deeper than MaxDepth must not be Complete")
		}
		if slices.Contains(fs.reads, j("l2", "l3")) {
			t.Fatal("the walk entered a folder below MaxDepth")
		}
		// MaxDepth 1 reads the root only.
		fs2 := &fakeDirs{entries: map[string][]MaskDirEntry{root: {file(".env"), dir("sub")}, j("sub"): {file(".netrc")}}}
		rep2 := DiscoverWorkspaceSecrets(root, fs2.read, SecretMaskLimits{MaxDepth: 1}, nil)
		if !reflect.DeepEqual(rep2.Masked, []string{j(".env")}) || rep2.DirsRead != 1 || rep2.Complete() {
			t.Fatalf("MaxDepth 1: %+v", rep2)
		}
	})

	t.Run("dirs", func(t *testing.T) {
		t.Parallel()
		fs := &fakeDirs{entries: map[string][]MaskDirEntry{
			root:   {dir("a"), dir("b"), dir("c")},
			j("a"): {file("a.key")},
			j("b"): {file("b.key")},
			j("c"): {file("c.key")},
		}}
		rep := DiscoverWorkspaceSecrets(root, fs.read, SecretMaskLimits{MaxDirs: 2}, nil)
		if rep.DirsRead != 2 {
			t.Fatalf("DirsRead = %d, want 2", rep.DirsRead)
		}
		if want := []string{j("a", "a.key")}; !reflect.DeepEqual(rep.Masked, want) {
			t.Fatalf("Masked = %v, want %v", rep.Masked, want)
		}
		if got := gapSet(rep); !reflect.DeepEqual(got, map[string]SecretMaskGapReason{j("b"): MaskGapDirs}) {
			t.Fatalf("gaps = %v, want b reported as dir_limit", got)
		}
	})

	t.Run("dir entries", func(t *testing.T) {
		t.Parallel()
		fs := &fakeDirs{entries: map[string][]MaskDirEntry{
			root: {file(".env"), file("a"), file("b"), file("c.key")},
		}}
		rep := DiscoverWorkspaceSecrets(root, fs.read, SecretMaskLimits{MaxDirEntries: 2}, nil)
		if got := gapSet(rep); !reflect.DeepEqual(got, map[string]SecretMaskGapReason{root: MaskGapDirEntries}) {
			t.Fatalf("gaps = %v, want the root reported as dir_entries_limit", got)
		}
		if rep.Complete() {
			t.Fatal("a folder cut at MaxDirEntries must not be Complete")
		}
	})

	t.Run("masked", func(t *testing.T) {
		t.Parallel()
		fs := &fakeDirs{entries: map[string][]MaskDirEntry{
			root:     {file(".env"), file(".netrc"), file(".npmrc"), dir("sub")},
			j("sub"): {file("late.key")},
		}}
		rep := DiscoverWorkspaceSecrets(root, fs.read, SecretMaskLimits{MaxMasked: 2}, nil)
		if want := []string{j(".env"), j(".netrc")}; !reflect.DeepEqual(rep.Masked, want) {
			t.Fatalf("Masked = %v, want %v", rep.Masked, want)
		}
		if got := gapSet(rep); !reflect.DeepEqual(got, map[string]SecretMaskGapReason{j(".npmrc"): MaskGapMasked}) {
			t.Fatalf("gaps = %v, want the first unmasked file reported as mask_limit", got)
		}
		if slices.Contains(fs.reads, j("sub")) {
			t.Fatal("the walk went on after MaxMasked")
		}
	})

	t.Run("zero limits take the defaults", func(t *testing.T) {
		t.Parallel()
		if got := (SecretMaskLimits{}).withDefaults(); got != DefaultSecretMaskLimits() {
			t.Fatalf("zero limits = %+v, want %+v", got, DefaultSecretMaskLimits())
		}
		d := DefaultSecretMaskLimits()
		if d.MaxDepth != 12 || d.MaxDirs != 10000 || d.MaxDirEntries != 4096 || d.MaxMasked != 256 {
			t.Fatalf("defaults moved: %+v (docs/sandboxed-terminals.md states them)", d)
		}
		if got := (SecretMaskLimits{MaxDepth: 3, MaxDirs: -1}).withDefaults(); got.MaxDepth != 3 || got.MaxDirs != d.MaxDirs {
			t.Fatalf("partial limits = %+v", got)
		}
	})

	t.Run("gap list is bounded", func(t *testing.T) {
		t.Parallel()
		// 150 folders at the limit, each a depth gap.
		es := []MaskDirEntry{}
		for i := 0; i < 150; i++ {
			es = append(es, dir(fmt.Sprintf("d%03d", i)))
		}
		fs := &fakeDirs{entries: map[string][]MaskDirEntry{root: es}}
		rep := DiscoverWorkspaceSecrets(root, fs.read, SecretMaskLimits{MaxDepth: 1}, nil)
		if len(rep.Gaps) != maxListedGaps || rep.GapsDropped != 50 {
			t.Fatalf("gaps %d dropped %d, want %d listed and 50 counted", len(rep.Gaps), rep.GapsDropped, maxListedGaps)
		}
		if rep.Complete() {
			t.Fatal("a report with dropped gaps must not be Complete")
		}
	})
}

func TestDiscoverReportsWhatItCannotCover(t *testing.T) {
	t.Parallel()
	root := maskRoot()
	j := func(p ...string) string { return filepath.Join(append([]string{root}, p...)...) }

	fs := &fakeDirs{
		entries: map[string][]MaskDirEntry{
			root: {
				link(".env"),          // a secret-named link: never followed, never mounted over
				link("linkdir"),       // a link to a folder: never entered
				other(".netrc"),       // a FIFO or socket: cannot be hidden with /dev/null
				file("bad\tname.pem"), // a tab: the plan cannot pass it to bwrap
				file("my key.pem"),    // a plain space is fine
				dir("denied"),         // cannot be listed
				link("README.md"),     // a link that is not secret-named: ignored
				{Name: "..", Kind: MaskEntryFile},
			},
		},
		errs: map[string]error{j("denied"): errors.New("permission denied")},
	}
	rep := DiscoverWorkspaceSecrets(root, fs.read, SecretMaskLimits{}, nil)
	if want := []string{j("my key.pem")}; !reflect.DeepEqual(rep.Masked, want) {
		t.Fatalf("Masked = %v, want %v", rep.Masked, want)
	}
	want := map[string]SecretMaskGapReason{
		j(".env"):                                MaskGapSymlink,
		j(".netrc"):                              MaskGapNotRegular,
		j("bad\tname.pem"):                       MaskGapUnsafeName,
		j("denied"):                              MaskGapUnreadable,
		root + string(filepath.Separator) + "..": MaskGapUnsafeName,
	}
	if got := gapSet(rep); !reflect.DeepEqual(got, want) {
		t.Fatalf("gaps = %v\n want %v", got, want)
	}
	if rep.Complete() {
		t.Fatal("a report with gaps must not be Complete")
	}
	if slices.Contains(fs.reads, j("linkdir")) {
		t.Fatal("the walk followed a symbolic link")
	}
}

func TestDiscoverWithoutAReaderSaysSo(t *testing.T) {
	t.Parallel()
	root := maskRoot()
	rep := DiscoverWorkspaceSecrets(root, nil, SecretMaskLimits{}, nil)
	if len(rep.Masked) != 0 || rep.Complete() || gapSet(rep)[root] != MaskGapUnreadable {
		t.Fatalf("a nil reader must report the root unreadable, got %+v", rep)
	}
}

func TestDisabledReportIsNeverComplete(t *testing.T) {
	t.Parallel()
	if (SecretMaskReport{}).Complete() {
		t.Fatal("a plan that did not ask for the mask must not read as a complete mask")
	}
}
