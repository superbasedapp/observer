package agentconfigsvc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// TestProjectLinkEscapingTheRootIsRefused pins AGENTCFG-READ-1's project
// rule (audit follow-up 7): a repository can commit .claude/settings.json as
// a symlink to any file the developer can read. A project-scope link that
// resolves outside the project root is refused by the snapshot (so neither
// the editor view nor the effective layers decode its target) and by every
// raw / preview / save target. A link that stays inside the project root,
// and a user-scope link outside the home (a dotfile manager's), are still
// followed.
func TestProjectLinkEscapingTheRootIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	outside := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(outside, []byte(`{"model":"outside-model"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(h.project, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	ctx := context.Background()

	snap := snapshotOf(t, h, "claude-code/project-settings")
	if snap.State != agentconfig.FileUnreadable || !strings.Contains(snap.Reason, "outside the project root") || len(snap.Bytes) != 0 {
		t.Fatalf("escaping project link: state %s reason %q bytes %d", snap.State, snap.Reason, len(snap.Bytes))
	}
	if _, err := h.svc.Raw(ctx, Target{Tool: "claude-code", FileID: "claude-code/project-settings", Project: h.project}); !errors.Is(err, ErrNotEditable) {
		t.Fatalf("raw view of an escaping link: %v, want ErrNotEditable", err)
	}
	req := SaveRequest{
		Target: Target{Tool: "claude-code", FileID: "claude-code/project-settings", Project: h.project},
		Edits:  []agentconfig.Edit{{Path: agentconfig.KeyPath{"model"}, Op: agentconfig.OpSet, Value: "opus"}},
	}
	if _, err := h.svc.Preview(ctx, req); !errors.Is(err, ErrNotEditable) {
		t.Fatalf("preview through an escaping link: %v, want ErrNotEditable", err)
	}
	if b, _ := os.ReadFile(outside); string(b) != `{"model":"outside-model"}` {
		t.Fatalf("the outside file changed: %s", b)
	}

	// A link inside the project root is followed.
	inside := filepath.Join(h.project, "shared", "claude.json")
	if err := os.MkdirAll(filepath.Dir(inside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inside, []byte(`{"model":"inside-model"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inside, link); err != nil {
		t.Fatal(err)
	}
	if snap := snapshotOf(t, h, "claude-code/project-settings"); snap.State != agentconfig.FilePresent {
		t.Fatalf("in-project link: state %s reason %q", snap.State, snap.Reason)
	}

	// A user-scope link outside the home (a dotfile manager's) is followed.
	userLink := filepath.Join(h.home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(userLink), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, userLink); err != nil {
		t.Fatal(err)
	}
	if snap := snapshotOf(t, h, "claude-code/user-settings"); snap.State != agentconfig.FilePresent {
		t.Fatalf("user-scope dotfile link: state %s reason %q", snap.State, snap.Reason)
	}
}

// TestProjectLinkedDirFirstSaveIsRefused pins orchestrator follow-up H1: a
// repository that commits .claude as a link to a directory outside the
// project, with no settings.json there yet, cannot have Observer's first
// project-scope save create that file outside the project.
func TestProjectLinkedDirFirstSaveIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(h.project, ".claude")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	ctx := context.Background()
	if snap := snapshotOf(t, h, "claude-code/project-settings"); snap.State != agentconfig.FileUnreadable || !strings.Contains(snap.Reason, "outside the project root") {
		t.Fatalf("missing file under an escaping dir link: state %s reason %q", snap.State, snap.Reason)
	}
	req := SaveRequest{
		Target: Target{Tool: "claude-code", FileID: "claude-code/project-settings", Project: h.project},
		Edits:  []agentconfig.Edit{{Path: agentconfig.KeyPath{"model"}, Op: agentconfig.OpSet, Value: "opus"}},
	}
	if _, err := h.svc.Preview(ctx, req); !errors.Is(err, ErrNotEditable) {
		t.Fatalf("preview of a first save through an escaping dir link: %v, want ErrNotEditable", err)
	}
	if _, err := h.svc.Save(ctx, req); !errors.Is(err, ErrNotEditable) {
		t.Fatalf("first save through an escaping dir link: %v, want ErrNotEditable", err)
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("the outside directory changed: %v %v", entries, err)
	}
}

// snapshotOf returns the claude-code snapshot of one file row.
func snapshotOf(t *testing.T, h *harness, id string) agentconfig.FileSnapshot {
	t.Helper()
	for _, s := range h.svc.snapshots("claude-code", h.project) {
		if s.Row.ID == id {
			return s
		}
	}
	t.Fatalf("no snapshot for %s", id)
	return agentconfig.FileSnapshot{}
}

// TestProjectLinkEscapes: one case per rule of the containment check.
func TestProjectLinkEscapes(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	mk := func(p string) string {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	plain := mk(filepath.Join(root, ".claude", "settings.json"))
	target := mk(filepath.Join(out, "x.json"))
	escLink := filepath.Join(root, ".github", "copilot", "settings.json")
	if err := os.MkdirAll(filepath.Dir(escLink), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, escLink); err != nil {
		t.Skipf("symlink: %v", err)
	}
	dirLink := filepath.Join(root, ".vscode")
	if err := os.Symlink(out, dirLink); err != nil {
		t.Fatal(err)
	}
	link := func(target, at string) string {
		if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	// A directory link that stays inside the project.
	inDirLink := link(filepath.Dir(plain), filepath.Join(root, ".cursor"))
	// Dangling links: their targets do not exist yet, so a write through
	// them would create the target.
	danglingOut := link(filepath.Join(out, "later.json"), filepath.Join(root, ".claude", "settings.local.json"))
	danglingDirOut := link(filepath.Join(out, "notyet"), filepath.Join(root, ".gemini"))
	danglingIn := link(filepath.Join(root, "later.json"), filepath.Join(root, ".claude", "in.json"))
	relTarget, err := filepath.Rel(filepath.Join(root, ".claude"), filepath.Join(out, "rel.json"))
	if err != nil {
		t.Fatal(err)
	}
	danglingRel := link(relTarget, filepath.Join(root, ".claude", "rel.json"))
	// A chain of maxLinkHops+1 dangling links ending outside: too deep to
	// judge, so it escapes.
	chainDir := filepath.Join(root, ".chain")
	for i := 0; i <= maxLinkHops; i++ {
		target := filepath.Join(chainDir, fmt.Sprintf("l%d", i+1))
		if i == maxLinkHops {
			target = filepath.Join(out, "far.json")
		}
		link(target, filepath.Join(chainDir, fmt.Sprintf("l%d", i)))
	}
	longChain := filepath.Join(chainDir, "l0")
	// A relative dangling target whose ".." follows a linked component: dl
	// points at out/a/b, so dl/../missing.json lands at out/a/missing.json,
	// not (lexically) at .claude/missing.json inside the project.
	if err := os.MkdirAll(filepath.Join(out, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	link(filepath.Join(out, "a", "b"), filepath.Join(root, ".claude", "dl"))
	// Built by hand: filepath.Join would clean the ".." away lexically.
	sep := string(filepath.Separator)
	viaLinkedDotDot := link("dl"+sep+".."+sep+"missing.json", filepath.Join(root, ".claude", "viadl.json"))
	for _, tc := range []struct {
		name, path, project string
		want                bool
	}{
		{"plain file", plain, root, false},
		{"link to a file outside", escLink, root, true},
		{"file under a linked directory outside", filepath.Join(dirLink, "x.json"), root, true},
		{"missing file", filepath.Join(root, "nope.json"), root, false},
		{"missing nested dir in the project", filepath.Join(root, "a", "b", "nope.json"), root, false},
		{"missing file under a linked directory outside", filepath.Join(dirLink, "settings.json"), root, true},
		{"missing nested dir under a linked directory outside", filepath.Join(dirLink, "a", "b", "settings.json"), root, true},
		{"missing file under a linked directory inside", filepath.Join(inDirLink, "new.json"), root, false},
		{"dangling link to a file outside", danglingOut, root, true},
		{"missing file under a dangling directory link outside", filepath.Join(danglingDirOut, "settings.json"), root, true},
		{"dangling link inside", danglingIn, root, false},
		{"relative dangling link outside", danglingRel, root, true},
		{"dangling link chain past maxLinkHops", longChain, root, true},
		{"relative dangling target climbing through a linked component", viaLinkedDotDot, root, true},
		{"no project", escLink, "", false},
	} {
		if got := projectLinkEscapes(tc.path, tc.project); got != tc.want {
			t.Errorf("%s: projectLinkEscapes = %v, want %v", tc.name, got, tc.want)
		}
		// The edit-target check refuses exactly the escaping rows (none of
		// these is unresolvable).
		if err := projectLinkCheck(tc.path, tc.project); (err != nil) != tc.want || (err != nil && !errors.Is(err, errProjectLinkEscapes)) {
			t.Errorf("%s: projectLinkCheck = %v, want refusal %v", tc.name, err, tc.want)
		}
	}
}

// TestProjectPathUnresolvedRefusesTheSave pins FU-182 (ruling AW-98): a
// project-scope edit target whose path cannot be resolved (here a
// committed .claude that is a regular file, so .claude/settings.json is a
// file used as a directory) cannot be proven inside the project root, so
// the raw view, the preview and the save refuse it with an error naming the
// path, and nothing is written. A read keeps reporting its own error
// (projectLinkEscapes still answers false for it).
func TestProjectPathUnresolvedRefusesTheSave(t *testing.T) {
	h := newHarness(t, nil)
	blocker := filepath.Join(h.project, ".claude")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "settings.json")
	if _, st := resolveWritePath(path); st != resolveFailed {
		t.Skipf("this OS resolves a file used as a directory (status %v)", st)
	}
	if projectLinkEscapes(path, h.project) {
		t.Error("projectLinkEscapes now answers true for an unresolvable path; the read side was to stay unchanged")
	}
	if err := projectLinkCheck(path, h.project); !errors.Is(err, errProjectPathUnresolved) || !strings.Contains(err.Error(), path) {
		t.Fatalf("projectLinkCheck = %v, want errProjectPathUnresolved naming %s", err, path)
	}
	ctx := context.Background()
	target := Target{Tool: "claude-code", FileID: "claude-code/project-settings", Project: h.project}
	req := SaveRequest{Target: target, Edits: []agentconfig.Edit{{Path: agentconfig.KeyPath{"model"}, Op: agentconfig.OpSet, Value: "opus"}}}
	for name, call := range map[string]func() error{
		"raw":     func() error { _, err := h.svc.Raw(ctx, target); return err },
		"preview": func() error { _, err := h.svc.Preview(ctx, req); return err },
		"save":    func() error { _, err := h.svc.Save(ctx, req); return err },
	} {
		err := call()
		if !errors.Is(err, ErrNotEditable) || !errors.Is(err, errProjectPathUnresolved) || !strings.Contains(err.Error(), path) {
			t.Errorf("%s: %v, want ErrNotEditable for the unresolvable path %s", name, err, path)
		}
	}
	if b, _ := os.ReadFile(blocker); string(b) != "not a directory" {
		t.Errorf("the blocking file changed: %q", b)
	}
}
