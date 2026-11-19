package sandboxremote

import (
	"errors"
	"strings"
	"testing"
)

// TestDefaultUploadIgnoreRows (SBXD-8): every default ignore row is one
// non-empty gitignore line with its reason, and none repeats.
func TestDefaultUploadIgnoreRows(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range DefaultUploadIgnore {
		if strings.TrimSpace(r.Pattern) == "" || strings.ContainsAny(r.Pattern, "\r\n\x00") || strings.HasPrefix(r.Pattern, "#") || strings.HasPrefix(r.Pattern, "!") {
			t.Errorf("bad pattern %q", r.Pattern)
		}
		if strings.TrimSpace(r.Why) == "" {
			t.Errorf("%s has no reason", r.Pattern)
		}
		if seen[r.Pattern] {
			t.Errorf("%s repeats", r.Pattern)
		}
		seen[r.Pattern] = true
	}
	// The ruled set: dependency, build and virtual-environment folders,
	// VCS dirs, .env files, OS junk.
	for _, want := range []string{"node_modules/", ".venv/", "venv/", "__pycache__/", "target/", "dist/", ".git/", ".hg/", ".svn/", ".env*", ".DS_Store", "Thumbs.db"} {
		if !seen[want] {
			t.Errorf("the default set lacks %s", want)
		}
	}
	// Names that are also common source folders stay out (an extra pattern
	// adds them).
	for _, never := range []string{"build/", "vendor/", "env/", "lib/", "src/"} {
		if seen[never] {
			t.Errorf("the default set ignores %s, a common source folder", never)
		}
	}
}

// TestUploadIgnoreFile: the extra patterns follow the defaults (so a negated
// extra wins), and a pattern holding a line break is dropped.
func TestUploadIgnoreFile(t *testing.T) {
	got := string(UploadIgnoreFile([]string{"  *.log ", "!dist/", "bad\nline", ""}))
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if lines[len(lines)-2] != "*.log" || lines[len(lines)-1] != "!dist/" {
		t.Fatalf("extras not last: %q", got)
	}
	if strings.Contains(got, "bad") {
		t.Fatalf("a broken pattern was written: %q", got)
	}
	if strings.Index(got, "node_modules/") > strings.Index(got, "!dist/") {
		t.Fatal("a default follows the extras")
	}
}

// nonRepoInput is a plain folder's listing.
func nonRepoInput(cands ...Candidate) ManifestInput {
	return ManifestInput{Root: "/w/plain", Home: "/home/u", NonRepository: true, Candidates: cands}
}

// TestPlanManifestNonRepository (SBXD-8): a folder that is not a repository
// is planned only through the non-repository listing; the credential-shaped
// rule and the caps still apply; the scope key names the listed paths.
func TestPlanManifestNonRepository(t *testing.T) {
	if _, err := PlanManifest(ManifestInput{Root: "/w/plain", Home: "/home/u"}); !errors.Is(err, ErrScopeNotRepository) {
		t.Fatalf("a plain folder without the listing: %v", err)
	}
	a := Candidate{Path: "a.go", Kind: KindRegular, Size: 3}
	env := Candidate{Path: "config/.env.local", Kind: KindRegular, Size: 4}
	key := Candidate{Path: "deploy.pem", Kind: KindRegular, Size: 4}
	m, err := PlanManifest(nonRepoInput(a, env, key))
	if err != nil {
		t.Fatal(err)
	}
	if !m.NonRepository || m.Count != 1 || m.Files[0].Path != "a.go" || len(m.Excluded) != 2 {
		t.Fatalf("plan %+v", m)
	}
	if !strings.HasPrefix(m.ScopeKey, "nongit:") || m.ScopeKey == ScopeKey("/w/plain", false, DefaultManifestLimits) {
		t.Fatalf("scope key %q", m.ScopeKey)
	}
	// An edit (a new size) does not re-ask; a file added does; another
	// ignore list does.
	edited, _ := PlanManifest(nonRepoInput(Candidate{Path: "a.go", Kind: KindRegular, Size: 300}, env, key))
	added, _ := PlanManifest(nonRepoInput(a, Candidate{Path: "b.go", Kind: KindRegular, Size: 1}, env, key))
	in := nonRepoInput(a, env, key)
	in.Ignore = []string{"*.log"}
	ignored, _ := PlanManifest(in)
	if edited.ScopeKey != m.ScopeKey {
		t.Error("editing a file re-asks")
	}
	if added.ScopeKey == m.ScopeKey {
		t.Error("adding a file does not re-ask")
	}
	if ignored.ScopeKey == m.ScopeKey {
		t.Error("another ignore list does not re-ask")
	}
	// The caps refuse, never a silent partial upload.
	lim := ManifestLimits{MaxFiles: 1, MaxBytes: 1 << 20, MaxFileBytes: 1 << 20}
	in = nonRepoInput(a, Candidate{Path: "b.go", Kind: KindRegular, Size: 1})
	in.Limits = lim
	if _, err := PlanManifest(in); !errors.Is(err, ErrScopeTooLarge) {
		t.Fatalf("over the file cap: %v", err)
	}
	// The home folder and / stay refused.
	for _, root := range []string{"/home/u", "/home", "/"} {
		in := nonRepoInput()
		in.Root = root
		if _, err := PlanManifest(in); err == nil {
			t.Errorf("%s planned", root)
		}
	}
	// A repository's key is unchanged by the new mode (no re-consent).
	r, _ := PlanManifest(ManifestInput{Root: "/w/plain", Home: "/home/u", Repository: true, NonRepository: true, Candidates: []Candidate{a}})
	if r.NonRepository || r.ScopeKey != ScopeKey("/w/plain", true, DefaultManifestLimits) {
		t.Fatalf("a repository planned as a plain folder: %+v", r)
	}
}

// TestConsentScreenSaysNotARepository: the consent screen says the folder
// is not a repository and how its files were chosen, and lists them.
func TestConsentScreenSaysNotARepository(t *testing.T) {
	v, _ := VendorFor(VendorE2B)
	m, err := PlanManifest(nonRepoInput(Candidate{Path: "a.go", Kind: KindRegular, Size: 3}))
	if err != nil {
		t.Fatal(err)
	}
	scr := BuildConsentScreen(v, ConsentFacts{Provider: v.ID, ScopeKey: m.ScopeKey}, m, Estimate{})
	var line string
	for _, l := range scr.Lines {
		if l.Label == "What is uploaded" {
			line = l.Value
		}
	}
	if !strings.Contains(line, "not a git repository") || !strings.Contains(line, ".gitignore") || !strings.Contains(line, "diff file") {
		t.Fatalf("line %q", line)
	}
	if len(scr.Uploaded) != 1 || scr.Uploaded[0] != "a.go" {
		t.Fatalf("listed %v", scr.Uploaded)
	}
	rm, _ := PlanManifest(ManifestInput{Root: "/w/r", Home: "/home/u", Repository: true})
	for _, l := range BuildConsentScreen(v, ConsentFacts{}, rm, Estimate{}).Lines {
		if l.Label == "What is uploaded" && strings.Contains(l.Value, "not a git repository") {
			t.Fatal("a repository's screen says it is not one")
		}
	}
}
