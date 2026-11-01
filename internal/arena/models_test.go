package arena

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestModelDelivery pins how a selected model reaches each Arena harness: the
// registry ModelSpec through integration.ModelLaunch, never a silent drop.
func TestModelDelivery(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		tool     string
		model    string
		wantArgs []string
		wantEnv  []string
		wantErr  string
	}{
		{name: "claude-code alias", tool: "claude-code", model: "opus", wantArgs: []string{"--model", "opus"}},
		{name: "claude-code full id", tool: "claude-code", model: "claude-opus-5-5", wantArgs: []string{"--model", "claude-opus-5-5"}},
		{name: "codex", tool: "codex", model: "gpt-5.5", wantArgs: []string{"--model", "gpt-5.5"}},
		{name: "grok", tool: "grok", model: "grok-code-fast-1", wantArgs: []string{"--model", "grok-code-fast-1"}},
		{name: "opencode provider path", tool: "opencode", model: "openrouter/anthropic/claude-sonnet-4.6", wantArgs: []string{"--model", "openrouter/anthropic/claude-sonnet-4.6"}},
		{name: "aider", tool: "aider", model: "gpt-4o-mini", wantArgs: []string{"--model", "gpt-4o-mini"}},
		{name: "empty is the harness default", tool: "claude-code", model: "  "},
		{name: "flag injection refused", tool: "claude-code", model: "--dangerously", wantErr: "must not begin with '-'"},
		{name: "whitespace refused", tool: "codex", model: "gpt 5", wantErr: "whitespace"},
		{name: "no model mechanism", tool: "not-a-tool", model: "x", wantErr: "no grounded model override"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, env, err := modelDelivery(tc.tool, tc.model)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("modelDelivery: %v", err)
			}
			if !reflect.DeepEqual(args, tc.wantArgs) || !reflect.DeepEqual(env, tc.wantEnv) {
				t.Fatalf("args=%v env=%v, want args=%v env=%v", args, env, tc.wantArgs, tc.wantEnv)
			}
		})
	}
}

// TestResolveModel pins the StartRun-time resolution: the routed lane's
// grounded default fills an empty selection, an unroutable or unsafe one is
// refused before any worktree exists, and a direct drive lifts the prefix.
func TestResolveModel(t *testing.T) {
	t.Parallel()
	const proxy = "http://127.0.0.1:8820"
	cases := []struct {
		name, tool, model, proxy string
		want                     string
		wantErr                  string
	}{
		{name: "claude default stays default", tool: "claude-code", proxy: proxy, want: ""},
		{name: "claude trimmed", tool: "claude-code", model: " sonnet ", proxy: proxy, want: "sonnet"},
		{name: "opencode routed default", tool: "opencode", proxy: proxy, want: "openrouter/stealth/ox-alpha"},
		{name: "opencode routed explicit", tool: "opencode", model: "openrouter/anthropic/claude-sonnet-4.6", proxy: proxy, want: "openrouter/anthropic/claude-sonnet-4.6"},
		{name: "opencode routed wrong provider", tool: "opencode", model: "gpt-5.5", proxy: proxy, wantErr: `expected prefix "openrouter/"`},
		{name: "opencode direct", tool: "opencode", model: "gpt-5.5", want: "gpt-5.5"},
		{name: "aider model", tool: "aider", model: "gpt-4o-mini", proxy: proxy, want: "gpt-4o-mini"},
		{name: "unsafe value", tool: "codex", model: "-c", proxy: proxy, wantErr: "must not begin"},
		{name: "not an arena harness", tool: "cursor", model: "x", wantErr: "no grounded headless contract"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveModel(tc.tool, tc.model, tc.proxy)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ResolveModel = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// TestExecuteDrive_ModelOverrideArgvPerHarness drives every Arena harness's
// real HeadlessSpec through a fake binary and checks the selected model lands
// on argv exactly once, and that the default selection adds no model flag.
func TestExecuteDrive_ModelOverrideArgvPerHarness(t *testing.T) {
	t.Parallel()
	for _, tool := range Harnesses() {
		for _, model := range []string{"", "picked-model/x-1"} {
			t.Run(tool+"/"+model, func(t *testing.T) {
				t.Parallel()
				binDir := t.TempDir()
				argsFile := filepath.Join(binDir, "args.txt")
				bin := fakeBin(t, binDir, "harness-fake", `printf '%s\n' "$@" > "`+argsFile+`"`)
				ic, _ := integration.For(tool)
				if _, err := executeDrive(context.Background(), bin, ic.Headless, driveRequest{
					Bypass: BypassDecision{Allowed: true}, // argv shape of the skip lane (OSH-R-005)
					Tool:   tool, Model: model, WorktreePath: t.TempDir(), Prompt: "p", Timeout: 30 * time.Second,
				}); err != nil {
					t.Fatalf("executeDrive: %v", err)
				}
				raw, err := os.ReadFile(argsFile)
				if err != nil {
					t.Fatal(err)
				}
				argv := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
				flags := 0
				for i, a := range argv {
					if a != "--model" {
						continue
					}
					flags++
					if i+1 >= len(argv) || argv[i+1] != model {
						t.Fatalf("--model not followed by %q: %v", model, argv)
					}
				}
				want := 0
				if model != "" {
					want = 1
				}
				if flags != want {
					t.Fatalf("%d --model flags, want %d: %v", flags, want, argv)
				}
			})
		}
	}
}

// TestStartRun_RecordsResolvedModelsAndJudgeModelReachesJudge pins that the
// run record names the judge model, candidate rows name theirs, and the judge
// drive actually receives its model on argv.
func TestStartRun_RecordsResolvedModelsAndJudgeModelReachesJudge(t *testing.T) {
	repo := initArenaRepo(t)
	binDir := t.TempDir()
	argsLog := filepath.Join(binDir, "claude-args.log")
	rubricDoc := `{"type":"result","result":"{\"correctness\":8,\"completeness\":7,\"code_quality\":9,\"performance\":6,\"risk\":3,\"overall\":8,\"verdict_rationale\":\"ok\"}"}`
	claude := fakeBin(t, binDir, "claude-fake",
		// One log line per drive: the judge prompt is multi-line, so fold
		// newlines before appending.
		`printf '%s ' "$@" | tr '\n' ' ' >> "`+argsLog+`"; echo >> "`+argsLog+`"`+"\ncat <<'JSON'\n"+rubricDoc+"\nJSON\necho edited > candidate.txt\n")
	prev := driveBinOverrides["claude-code"]
	driveBinOverrides["claude-code"] = claude
	t.Cleanup(func() {
		if prev == "" {
			delete(driveBinOverrides, "claude-code")
		} else {
			driveBinOverrides["claude-code"] = prev
		}
	})
	r, err := NewRunner(Options{Store: arenaTestStore(t), WorkspaceDir: t.TempDir(), MaxParallel: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := r.StartRun(ctx, RunSpec{
		ID: "models-bad", ProjectRoot: repo, Prompt: "p",
		Candidates: []CandidateSpec{{Tool: "claude-code", Model: "-x"}},
		JudgeTool:  "claude-code",
	}); err == nil || !strings.Contains(err.Error(), `candidate "claude-code"`) {
		t.Fatalf("unsafe candidate model must fail the start, got %v", err)
	}
	if rn, _ := r.opts.Store.ArenaRun(ctx, "models-bad"); rn != nil {
		t.Fatalf("a refused start must leave no run row: %+v", rn)
	}

	prep, err := r.StartRun(ctx, RunSpec{
		ID: "models-ok", ProjectRoot: repo, Prompt: "p",
		Candidates: []CandidateSpec{{Tool: "claude-code", Model: " cand-model "}},
		JudgeTool:  "claude-code", JudgeModel: "judge-model",
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	rn, err := r.opts.Store.ArenaRun(ctx, "models-ok")
	if err != nil || rn == nil || rn.JudgeModel != "judge-model" {
		t.Fatalf("run row judge model = %+v, %v", rn, err)
	}
	rows, _ := r.opts.Store.ArenaCandidates(ctx, "models-ok")
	if len(rows) != 1 || rows[0].Model != "cand-model" {
		t.Fatalf("candidate rows = %+v", rows)
	}
	if err := r.DriveCandidates(ctx, prep); err != nil {
		t.Fatalf("DriveCandidates: %v", err)
	}
	if err := r.JudgeRun(ctx, prep); err != nil {
		t.Fatalf("JudgeRun: %v", err)
	}
	raw, _ := os.ReadFile(argsLog)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want one candidate + one judge drive, got %d:\n%s", len(lines), raw)
	}
	if !strings.Contains(lines[0], "--model cand-model") {
		t.Errorf("candidate argv missing its model: %s", lines[0])
	}
	if !strings.Contains(lines[1], "--model judge-model") || !strings.Contains(lines[1], "strict code-review judge") {
		t.Errorf("judge argv missing its model: %s", lines[1])
	}
}
