package arena

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestPermissionLaneTable pins which permission lane each role may run in
// (OSH-R-005): permissions are skipped only for a candidate or a merge keep
// whose drive is allowed to skip them, never for the judge, and a harness
// that has no other unattended mode is refused with the policy's reason.
func TestPermissionLaneTable(t *testing.T) {
	allowed := BypassDecision{Allowed: true}
	denied := BypassDecision{Why: "the test says no"}
	cases := []struct {
		tool    string
		role    driveRole
		bypass  BypassDecision
		lane    integration.HeadlessPermLane
		wantErr string
	}{
		{"claude-code", roleCandidate, allowed, integration.HeadlessPermBypass, ""},
		{"claude-code", roleCandidate, denied, integration.HeadlessPermEdit, ""},
		// audit F3: the merge keep runs git, which only the skip lane allows.
		{"claude-code", roleMerge, denied, "", "arena_allow_skip_permissions = true, or keep the candidate with squash"},
		{"claude-code", roleMerge, allowed, integration.HeadlessPermBypass, ""},
		{"codex", roleMerge, allowed, "", "no grounded unattended mode a judge_merge keep may run in"},
		{"claude-code", roleJudge, allowed, integration.HeadlessPermReadOnly, ""},
		{"codex", roleCandidate, allowed, integration.HeadlessPermEdit, ""},
		{"codex", roleJudge, denied, integration.HeadlessPermReadOnly, ""},
		{"opencode", roleCandidate, allowed, integration.HeadlessPermBypass, ""},
		{"opencode", roleCandidate, denied, "", "not allowed here: the test says no"},
		{"grok", roleCandidate, denied, "", "not allowed here: the test says no"},
		{"aider", roleMerge, denied, "", "not allowed here"},
		{"grok", roleJudge, allowed, "", "no grounded unattended mode"},
	}
	for _, c := range cases {
		ic, ok := integration.For(c.tool)
		if !ok || ic.Headless == nil {
			t.Fatalf("%s: no headless row", c.tool)
		}
		lane, _, err := permissionArgs(ic.Headless, c.tool, c.role, c.bypass)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s role %d: err %v, want %q", c.tool, c.role, err, c.wantErr)
			}
			continue
		}
		if err != nil || lane != c.lane {
			t.Errorf("%s role %d bypass %v: lane %q err %v, want %q", c.tool, c.role, c.bypass.Allowed, lane, err, c.lane)
		}
	}
}

// TestExecuteDriveSkipsPermissionsOnlyWhenAllowed drives the claude-code
// shape three ways: a candidate with no policy answer keeps claude's own
// checks on (acceptEdits), the same candidate with the skip allowed gets
// the old --dangerously-skip-permissions, and a judge never does.
func TestExecuteDriveSkipsPermissionsOnlyWhenAllowed(t *testing.T) {
	binDir := t.TempDir()
	argsFile := filepath.Join(binDir, "args.txt")
	bin := fakeBin(t, binDir, "claude-perm", strings.ReplaceAll(claudeFakeBody, "$ARENA_ARGS_FILE", argsFile))
	ic, _ := integration.For("claude-code")
	cases := []struct {
		name    string
		role    driveRole
		bypass  BypassDecision
		want    string
		notWant string
	}{
		{"candidate, no policy", roleCandidate, BypassDecision{}, "--permission-mode acceptEdits", "--dangerously-skip-permissions"},
		{"candidate, allowed", roleCandidate, BypassDecision{Allowed: true}, "--dangerously-skip-permissions", "--permission-mode"},
		{"judge, allowed", roleJudge, BypassDecision{Allowed: true}, "--permission-mode default", "--dangerously-skip-permissions"},
	}
	for _, c := range cases {
		if _, err := executeDrive(context.Background(), bin, ic.Headless, driveRequest{
			Tool: "claude-code", WorktreePath: t.TempDir(), Prompt: "p", Timeout: 30 * time.Second,
			Role: c.role, Bypass: c.bypass,
		}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		raw, _ := os.ReadFile(argsFile)
		if argv := string(raw); !strings.Contains(argv, c.want) || strings.Contains(argv, c.notWant) {
			t.Errorf("%s: argv %q, want %q and not %q", c.name, argv, c.want, c.notWant)
		}
	}
}

// TestStartRunRefusesSkipOnlyCandidateWithoutPolicy: a candidate harness
// that can only run with its checks skipped is refused before any worktree
// exists when the runner's policy does not allow the skip, and the policy
// is asked about that exact tool.
func TestStartRunRefusesSkipOnlyCandidateWithoutPolicy(t *testing.T) {
	repo := initArenaRepo(t)
	bin := fakeBin(t, t.TempDir(), "grok-perm", "exit 0\n")
	claude := fakeBin(t, t.TempDir(), "claude-perm-judge", "exit 0\n")
	oldG, oldC := driveBinOverrides["grok"], driveBinOverrides["claude-code"]
	driveBinOverrides["grok"], driveBinOverrides["claude-code"] = bin, claude
	t.Cleanup(func() { driveBinOverrides["grok"], driveBinOverrides["claude-code"] = oldG, oldC })
	workspace := t.TempDir()
	var asked []string
	r, err := NewRunner(Options{
		Store: arenaTestStore(t), WorkspaceDir: workspace, MaxParallel: 1,
		PermissionBypass: func(_ context.Context, tool string) BypassDecision {
			asked = append(asked, tool)
			return BypassDecision{Why: "[benchmark] arena_allow_skip_permissions is off (the default)"}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.StartRun(context.Background(), RunSpec{
		ID: "run-perm", ProjectRoot: repo, Prompt: "p",
		Candidates: []CandidateSpec{{Tool: "grok"}}, JudgeTool: "claude-code",
	})
	if err == nil || !strings.Contains(err.Error(), "arena_allow_skip_permissions is off") {
		t.Fatalf("StartRun = %v, want the skip refusal naming the setting", err)
	}
	if len(asked) != 1 || asked[0] != "grok" {
		t.Fatalf("policy asked about %v, want [grok]", asked)
	}
	if _, serr := os.Stat(filepath.Join(workspace, "run-perm")); !os.IsNotExist(serr) {
		t.Fatalf("a refused run left a workspace: %v", serr)
	}
}

// allowSkip makes r's permission policy allow the skip lane, the only lane a
// judge_merge keep may run in (audit F3).
func allowSkip(r *Runner) *Runner {
	r.opts.PermissionBypass = func(context.Context, string) BypassDecision { return BypassDecision{Allowed: true} }
	return r
}

// TestJudgeMergeRefusedUpFrontWithoutSkip (audit F3): with skipping not
// allowed the judge_merge keep is refused before any keep worktree exists,
// naming the setting, instead of driving an agent that cannot run git.
func TestJudgeMergeRefusedUpFrontWithoutSkip(t *testing.T) {
	repo := initArenaRepo(t)
	r := startTestRunner(t, repo)
	marker := filepath.Join(t.TempDir(), "judge-started")
	prev := driveBinOverrides["claude-code"]
	driveBinOverrides["claude-code"] = fakeBin(t, t.TempDir(), "noskip-judge", `echo started > "`+marker+`"`+"\n")
	t.Cleanup(func() { driveBinOverrides["claude-code"] = prev })
	row := &models.ArenaCandidate{RunID: "noskip", Tool: "codex", BranchName: "arena/noskip/codex"}
	_, err := r.judgeMergeKeep(context.Background(), row, repo, JudgeSpec{Tool: "claude-code"}, "usd")
	if err == nil || !strings.Contains(err.Error(), "arena_allow_skip_permissions") {
		t.Fatalf("judgeMergeKeep = %v, want an up-front refusal naming the setting", err)
	}
	if _, serr := os.Stat(marker); !os.IsNotExist(serr) {
		t.Fatal("the merge agent was started")
	}
	keepDir, _ := r.keepWorktreeFor(row)
	if _, serr := os.Stat(keepDir); !os.IsNotExist(serr) {
		t.Fatalf("a keep worktree was made: %v", serr)
	}
}

// TestCandidateRowRecordsPermissionLane (audit F4): the candidate row
// records the permission lane its drive ran in, through the store.
func TestCandidateRowRecordsPermissionLane(t *testing.T) {
	for _, c := range []struct {
		name  string
		allow bool
		want  string
	}{
		{"no policy", false, string(integration.HeadlessPermEdit)},
		{"skip allowed", true, string(integration.HeadlessPermBypass)},
	} {
		t.Run(c.name, func(t *testing.T) {
			repo := initArenaRepo(t)
			r := startTestRunner(t, repo)
			if c.allow {
				allowSkip(r)
			}
			ctx := context.Background()
			prep, err := r.StartRun(ctx, validRunSpec("lane-"+strings.ReplaceAll(c.name, " ", "-"), repo))
			if err != nil {
				t.Fatal(err)
			}
			if err := r.DriveCandidates(ctx, prep); err != nil {
				t.Fatal(err)
			}
			rows, err := r.opts.Store.ArenaCandidates(ctx, prep.Spec.ID)
			if err != nil || len(rows) != 1 {
				t.Fatalf("candidates: %v %v", rows, err)
			}
			if rows[0].PermissionLane != c.want {
				t.Fatalf("permission lane = %q, want %q", rows[0].PermissionLane, c.want)
			}
		})
	}
}

// TestCodexMergeJudgeRefusedWithTheRealWayOut: codex has no skip lane, so a
// judge_merge keep with codex as the merge judge is refused up front even
// where skipping is allowed, and the refusal names what helps (another
// judge, or squash) instead of the setting, which cannot help.
func TestCodexMergeJudgeRefusedWithTheRealWayOut(t *testing.T) {
	repo := initArenaRepo(t)
	r := allowSkip(startTestRunner(t, repo))
	marker := filepath.Join(t.TempDir(), "judge-started")
	prev := driveBinOverrides["codex"]
	driveBinOverrides["codex"] = fakeBin(t, t.TempDir(), "codex-merge-judge", `echo started > "`+marker+`"`+"\n")
	t.Cleanup(func() { driveBinOverrides["codex"] = prev })
	row := &models.ArenaCandidate{RunID: "codexmerge", Tool: "claude-code", BranchName: "arena/codexmerge/claude-code"}
	_, err := r.judgeMergeKeep(context.Background(), row, repo, JudgeSpec{Tool: "codex"}, "usd")
	if err == nil || !strings.Contains(err.Error(), "pick a merge judge that has one") || strings.Contains(err.Error(), "arena_allow_skip_permissions") {
		t.Fatalf("judgeMergeKeep = %v, want the up-front refusal naming another judge or squash, not the setting", err)
	}
	if _, serr := os.Stat(marker); !os.IsNotExist(serr) {
		t.Fatal("the merge agent was started")
	}
	keepDir, _ := r.keepWorktreeFor(row)
	if _, serr := os.Stat(keepDir); !os.IsNotExist(serr) {
		t.Fatalf("a keep worktree was made: %v", serr)
	}
}
