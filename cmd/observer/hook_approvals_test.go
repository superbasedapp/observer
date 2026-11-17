package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// approvalHookNode is an individual node in enforce mode with a migrated
// database, returning the config path and the database path.
func approvalHookNode(t *testing.T) (cfgPath, dbPath string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath, dbPath = filepath.Join(dir, "config.toml"), filepath.Join(dir, "observer.db")
	// org_bundle names an absent file in the node's own directory: no
	// bundle, so no org lock (the test HOME's default path is unreadable).
	writeFileT(t, cfgPath, "[observer]\ndb_path = "+strconv.Quote(filepath.ToSlash(dbPath))+
		"\n[guard]\nenabled = true\nmode = \"enforce\"\n[guard.rules]\norg_bundle = "+
		strconv.Quote(filepath.ToSlash(filepath.Join(dir, "org-policy-bundle.json")))+"\n")
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	return cfgPath, dbPath
}

// grantApproval writes one grant through the store seam.
func grantApproval(t *testing.T, dbPath string, row store.GuardApprovalRow) {
	t.Helper()
	d, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if row.TS.IsZero() {
		row.TS = time.Now().UTC()
	}
	if _, err := store.New(d).InsertGuardApproval(context.Background(), row); err != nil {
		t.Fatal(err)
	}
}

// TestHookProjectGrantAppliesOnCwdOnlyPayload is P-232 cause 1 through the
// real Claude Code PreToolUse receiver: the payload carries only cwd (a
// subdirectory of a git tree), and a project grant hashed from the tree's
// root (the spelling projects.root_path holds) downgrades the block. A grant
// for another project, or none, still blocks.
func TestHookProjectGrantAppliesOnCwdOnlyPayload(t *testing.T) {
	root, cwd := projectHookRepo(t, "https://github.com/acme/widget.git")
	cases := []struct {
		name      string
		grantRoot string
		wantBlock bool
	}{
		{"project grant for this repository", root, false},
		{"project grant for another repository", filepath.Join(t.TempDir(), "other"), true},
		{"no grant", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp, dbPath := approvalHookNode(t)
			if tc.grantRoot != "" {
				for _, info := range policy.Catalog() {
					grantApproval(t, dbPath, store.GuardApprovalRow{
						RuleID: info.ID, Scope: "project", ProjectRootHash: guard.HashProjectRoot(tc.grantRoot), GrantedBy: "test",
					})
				}
			}
			body := `{"session_id":"s1","cwd":` + strconv.Quote(filepath.ToSlash(cwd)) + `,"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf ~/"}}`
			h := newFailureHarness(t, hookFailurePlan{})
			var errBuf strings.Builder
			handleClaudeCodePreTool(strings.NewReader(body), &h.stdout, &errBuf, "claude-code:pre-tool", cp)
			out := h.stdout.String()
			if blocked := toolGateBlockWords.MatchString(out); blocked != tc.wantBlock {
				t.Fatalf("reply %q (stderr %s): blocked=%v, want %v", out, errBuf.String(), blocked, tc.wantBlock)
			}
		})
	}
}

// TestHookProjectRootWindowsCwdThroughWSL: a Windows Claude Code whose hook
// runs inside WSL (the wsl.exe bridge) sends a drive-letter cwd. The hook's
// derived root must be the root the watcher records for the same cwd
// (crossmount.TranslateForeignPath, then git.ResolveIdentity), so the hash
// equals the one the dashboard anchored the project grant with.
func TestHookProjectRootWindowsCwdThroughWSL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the drive-letter cwd is foreign only on a POSIX host")
	}
	for _, cwd := range []string{`C:\programsx\superbased-observer`, `c:\programsx\superbased-observer\`, `C:/programsx/superbased-observer`} {
		t.Run(cwd, func(t *testing.T) {
			got := hookProjectRoot(&policy.Event{Cwd: cwd})
			id, err := git.ResolveIdentity(crossmount.TranslateForeignPath(cwd), git.IdentityOptions{})
			if err != nil {
				t.Fatal(err)
			}
			const stored = "/mnt/c/programsx/superbased-observer"
			if got != id.Root || got != stored {
				t.Fatalf("hook root %q, watcher root %q, want both %q", got, id.Root, stored)
			}
			if guard.HashProjectRoot(got) != guard.HashProjectRoot(stored) {
				t.Fatal("hashes differ")
			}
		})
	}
}

// TestHookApprovalLookup pins the hook's read-only approval read (P-232
// fix 2): a grant is found on a migrated (closed, WAL) database, no grant is
// (false, nil), a missing or not yet migrated database is (false, nil), and
// an unreadable one is an error rather than a silent "no grant". The read
// never migrates.
func TestHookApprovalLookup(t *testing.T) {
	_, dbPath := approvalHookNode(t)
	grantApproval(t, dbPath, store.GuardApprovalRow{RuleID: "S-793", Scope: "session", SessionID: "s1", GrantedBy: "test"})
	garbage := filepath.Join(t.TempDir(), "garbage.db")
	writeFileT(t, garbage, strings.Repeat("not a database ", 100))
	empty := filepath.Join(t.TempDir(), "empty.db")
	writeFileT(t, empty, "")
	cases := []struct {
		name    string
		path    string
		rule    string
		session string
		want    bool
		wantErr bool
	}{
		{"grant found", dbPath, "S-793", "s1", true, false},
		{"no grant for this session", dbPath, "S-793", "s2", false, false},
		{"no grant for this rule", dbPath, "S-794", "s1", false, false},
		{"missing database: no grants, no error", filepath.Join(t.TempDir(), "absent.db"), "S-793", "s1", false, false},
		{"not a database: an error", garbage, "S-793", "s1", false, true},
		{"unmigrated database: no grants, no error, and it stays unmigrated", empty, "S-793", "s1", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := hookApprovalLookup(tc.path, 500*time.Millisecond)(tc.rule, tc.session, "")
			if ok != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("lookup = (%v, %v), want (%v, err=%v)", ok, err, tc.want, tc.wantErr)
			}
		})
	}
	if fi, err := os.Stat(empty); err != nil || fi.Size() != 0 {
		t.Fatalf("the read wrote to an unmigrated database (size %v, %v)", fi.Size(), err)
	}
}

// TestHookApprovalBusy: the busy wait stays inside the hook budget.
func TestHookApprovalBusy(t *testing.T) {
	cases := []struct {
		budget, want time.Duration
	}{
		{500 * time.Millisecond, 250 * time.Millisecond},
		{0, 250 * time.Millisecond},
		{10 * time.Millisecond, 20 * time.Millisecond},
		{2 * time.Second, time.Second},
	}
	for _, tc := range cases {
		if got := hookApprovalBusy(tc.budget); got != tc.want {
			t.Errorf("hookApprovalBusy(%v) = %v, want %v", tc.budget, got, tc.want)
		}
	}
}

// mustApprovalActive is store.ApprovalActiveFor for a test: a lookup error
// fails the test instead of reading as "no grant".
func mustApprovalActive(t *testing.T, st *store.Store, ctx context.Context, ruleID, sessionID, rootHash string, now time.Time) bool {
	t.Helper()
	ok, err := st.ApprovalActiveFor(ctx, ruleID, sessionID, rootHash, now)
	if err != nil {
		t.Fatalf("ApprovalActiveFor(%s): %v", ruleID, err)
	}
	return ok
}

// TestHookApprovalCoverLookup: the hook's richer lookup answers exactly as the
// plain one does (grant, no grant, missing, unreadable and unmigrated
// databases) and names the covering approval and its grantor (plan section
// 13.7).
func TestHookApprovalCoverLookup(t *testing.T) {
	_, dbPath := approvalHookNode(t)
	grantApproval(t, dbPath, store.GuardApprovalRow{RuleID: "R-179", Scope: "session", SessionID: "s1", GrantedBy: "assessment:3fa9c2d17b0e4a56"})
	garbage := filepath.Join(t.TempDir(), "garbage.db")
	writeFileT(t, garbage, strings.Repeat("not a database ", 100))
	empty := filepath.Join(t.TempDir(), "empty.db")
	writeFileT(t, empty, "")
	cases := []struct {
		name    string
		path    string
		rule    string
		session string
		want    guard.ApprovalCover
		wantErr bool
	}{
		{"grant found names the grantor", dbPath, "R-179", "s1", guard.ApprovalCover{Found: true, ID: 1, GrantedBy: "assessment:3fa9c2d17b0e4a56"}, false},
		{"no grant for this session", dbPath, "R-179", "s2", guard.ApprovalCover{}, false},
		{"no grant for this rule", dbPath, "R-170", "s1", guard.ApprovalCover{}, false},
		{"missing database: no grants, no error", filepath.Join(t.TempDir(), "absent.db"), "R-179", "s1", guard.ApprovalCover{}, false},
		{"not a database: an error", garbage, "R-179", "s1", guard.ApprovalCover{}, true},
		{"unmigrated database: no grants, no error", empty, "R-179", "s1", guard.ApprovalCover{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := hookApprovalCoverLookup(tc.path, 500*time.Millisecond)(tc.rule, tc.session, "")
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("lookup = (%+v, %v), want (%+v, err=%v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}
