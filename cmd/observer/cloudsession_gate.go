package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// cloudsession_gate.go is `observer cloud-session gate` (lane CA-C2): what
// the committed gate hooks run inside a vendor's cloud sandbox. It evaluates
// the repository's committed policy file LOCALLY, with no network call
// (decision CA-D9; pinned by TestCloudSessionGateMakesNoNetworkCall and by
// TestCloudSessionGateImportsNoEgress, which keeps every network package and
// the org client out of this file):
//
//  1. verify the policy file against the key pin and file digest the
//     committed command carries (cloudsession.VerifyPolicy);
//  2. a tool gate runs the ordinary guard engine with the verified policy as
//     its org layer (the guard re-verifies it under the same pin) and answers
//     in the vendor's own reply dialect (internal/hook.HandleToolGate);
//  3. a prompt gate applies the soft budget stop over the org's signed budget
//     document; prompt-content intervention stays with the capture hook on
//     the same event, which already runs the guard's prompt lane.
//
// When it cannot evaluate, the failure table (cloudsession.GateFailureFor)
// decides: under enforce on a dialect that honors a block it blocks with a
// reason (docs/guard.md "Hook failure semantics"), otherwise it lets the call
// through and says so on stderr.

// cloudSessionGateOptions are runCloudSessionGate's inputs.
type cloudSessionGateOptions struct {
	Agent, Event string
	Mode         cloudsession.GuardMode
	KeyPin       string
	Policy       string
	Repo         string
	ConfigPath   string
	Env          cloudsession.LookupEnv
	// Now is the clock (tests); nil is time.Now.
	Now func() time.Time
}

func newCloudSessionGateCmd() *cobra.Command {
	var o cloudSessionGateOptions
	var mode string
	cmd := &cobra.Command{
		Use:   "gate",
		Short: "Evaluate the committed guard policy for one hook event in a cloud sandbox (what the gate hooks run)",
		Long: "Run by the gate hooks `observer cloud-session init --guard` commits. Outside\n" +
			"the vendor's cloud it allows at once. Inside it verifies " + cloudsession.PolicyPath + "\n" +
			"against the committed key pin and digest, evaluates the guard locally with\n" +
			"no network call, and answers in the vendor's hook dialect. Under enforce a\n" +
			"gate that cannot evaluate blocks with a reason where the vendor honors a block.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o.Mode, o.Env = cloudsession.GuardMode(mode), os.LookupEnv
			if code := runCloudSessionGate(cmd.Context(), o, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()); code != 0 {
				return exitErr(code)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&o.Agent, "agent", "", agentFlagHelp())
	cmd.Flags().StringVar(&o.Event, "event", "", "the vendor hook event this gate serves (PreToolUse, UserPromptSubmit, preToolUse, userPromptSubmitted)")
	cmd.Flags().StringVar(&mode, "mode", string(cloudsession.GuardEnforce), "enforce or observe (baked in by init)")
	cmd.Flags().StringVar(&o.KeyPin, "key-pin", "", "sha256 hex of the distribution key the policy must be signed by (baked in by init)")
	cmd.Flags().StringVar(&o.Policy, "policy", "", "sha256:<hex> of the committed policy file (baked in by init)")
	cmd.Flags().StringVar(&o.Repo, "repo", "", "repository holding the policy file (default: the git repository of the working directory)")
	cmd.Flags().StringVar(&o.ConfigPath, "config", "", "Path to observer config.toml")
	return cmd
}

// runCloudSessionGate is the gate. It returns the process exit code; every
// reply is already written to stdout.
func runCloudSessionGate(_ context.Context, o cloudSessionGateOptions, stdin io.Reader, stdout, stderr io.Writer) int {
	agent, err := cloudsession.AgentByID(o.Agent)
	if err != nil {
		fmt.Fprintf(stderr, "observer cloud-session gate: %v; allowing (no dialect to block in)\n", err)
		return 0
	}
	b, err := cloudsession.GateBinding(agent, o.Event)
	if err != nil {
		fmt.Fprintf(stderr, "observer cloud-session gate: %v; allowing (no dialect to block in)\n", err)
		return 0
	}
	if o.Env == nil {
		o.Env = func(string) (string, bool) { return "", false }
	}
	body, truncated := readHookBodyDetectTruncation(stdin, promptSubmitBodyLimit)
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	g := &cloudSessionGate{o: o, agent: agent, b: b, body: body, stdout: stdout, stderr: stderr}
	if !cloudsession.Detect(agent, o.Env).InCloud {
		return g.allow()
	}
	if !cloudsession.ValidGuardMode(o.Mode) {
		// The mode is unknown, so the failure table reads it as not
		// enforcing; say so rather than guess.
		return g.fail(fmt.Sprintf("unknown guard mode %q in the committed gate", o.Mode))
	}
	root := cloudSessionRepoRoot(o.Repo)
	g.root = root
	raw, exists, err := readCloudSessionPolicy(root)
	if err != nil {
		return g.fail("cannot read " + cloudsession.PolicyPath + ": " + err.Error())
	}
	v, err := cloudsession.VerifyPolicy(raw, exists, cloudsession.PolicyPin{KeyPin: o.KeyPin, Digest: o.Policy})
	if err != nil {
		if pe, ok := cloudsession.AsPolicyError(err); ok {
			return g.fail(pe.Reason())
		}
		return g.fail(err.Error())
	}
	switch b.Gate {
	case cloudsession.GateTool:
		return g.tool(v, truncated)
	case cloudsession.GatePrompt:
		return g.prompt(v)
	}
	return g.fail("unknown gate kind " + string(b.Gate))
}

// readCloudSessionPolicy reads the committed policy file from the repository.
func readCloudSessionPolicy(root string) ([]byte, bool, error) {
	if root == "" {
		return nil, false, nil
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(cloudsession.PolicyPath)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

// cloudSessionGate carries one gate invocation.
type cloudSessionGate struct {
	o      cloudSessionGateOptions
	agent  cloudsession.Agent
	b      cloudsession.HookBinding
	body   []byte
	stdout io.Writer
	stderr io.Writer
	// root is the repository the committed policy was read from ("" when
	// none was found).
	root string
}

func (g *cloudSessionGate) label() string { return g.agent.HookTool + ":" + g.b.Event }

// allow writes the dialect's neutral allow.
func (g *cloudSessionGate) allow() int {
	hook.HandleDialectAllow(g.b.Dialect, g.b.Event, bytes.NewReader(g.body), g.stdout, io.Discard)
	return 0
}

// block writes the dialect's block carrying reason and returns its exit code.
func (g *cloudSessionGate) block(reason string) int {
	reply, ok := hook.BuildFailClosedReply(g.b.Dialect, reason)
	if !ok {
		fmt.Fprintf(g.stderr, "observer cloud-session gate: %s: the %s dialect cannot block; allowing: %s\n", g.label(), g.b.Dialect, reason)
		return g.allow()
	}
	if len(reply.Stdout) > 0 {
		_, _ = g.stdout.Write(reply.Stdout)
	}
	if reply.StderrReason {
		hook.WriteStderrBlockReason(g.stderr, reason)
	} else {
		fmt.Fprintf(g.stderr, "observer cloud-session gate: %s blocked: %s\n", g.label(), reason)
	}
	return reply.ExitCode
}

// fail answers a gate that cannot evaluate, per the failure table.
func (g *cloudSessionGate) fail(reason string) int {
	if cloudsession.GateFailureFor(g.b, g.o.Mode) == cloudsession.FailClosed {
		return g.block(reason)
	}
	fmt.Fprintf(g.stderr, "observer cloud-session gate: %s fails open (%s mode): %s\n", g.label(), g.o.Mode, reason)
	return g.allow()
}

// tool evaluates one tool call with the verified policy.
func (g *cloudSessionGate) tool(v cloudsession.VerifiedPolicy, truncated bool) int {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: g.o.ConfigPath})
	if err != nil {
		return g.fail(hook.FailClosedErrorReason)
	}
	home, _ := os.UserHomeDir()
	gd, err := buildSandboxGuard(v, g.o.KeyPin, g.o.Mode, home)
	if err != nil {
		fmt.Fprintf(g.stderr, "observer cloud-session gate: %v\n", err)
		return g.fail(hook.FailClosedErrorReason)
	}
	res := hook.HandleToolGate(hook.ToolGateRequest{
		Tool: g.agent.HookTool, Dialect: g.b.Dialect, NativeEvent: g.b.Event, Label: g.label(),
		Body: g.body, Truncated: truncated, Enforcing: g.o.Mode == cloudsession.GuardEnforce,
		Enrich: cloudSessionRootEnrich(g.projectDirFallback()),
	}, gd, makeGuardPersist(cfg, gd, g.label(), g.stderr), g.stdout, g.stderr)
	if res.Replied {
		return res.ExitCode
	}
	if res.Undecodable {
		return g.fail(hook.FailClosedErrorReason)
	}
	hook.WriteToolGateAllowWarn(g.b.Dialect, res.WarnField, res.Warn, g.stdout)
	if res.RecordAfterReply != nil {
		res.RecordAfterReply()
	}
	return 0
}

// projectDirFallback is the directory the gate judges a tool call's project
// against when the payload names no usable working directory: the agent
// row's project directory variable (Agent.ProjectDirEnv, CLAUDE_PROJECT_DIR
// for Claude Code), else the repository the committed policy was read from.
func (g *cloudSessionGate) projectDirFallback() string {
	if g.agent.ProjectDirEnv != "" {
		if dir, ok := g.o.Env(g.agent.ProjectDirEnv); ok && dir != "" {
			return dir
		}
	}
	return g.root
}

// cloudSessionRootEnrich is the gate's Enrich step: it stamps the project
// root the ordinary tool gate stamps (withProjectLookupRoot: the git tree of
// the payload's cwd), and when the payload carried no cwd it resolves the
// same roots from fallback, so R-101 and the project rules judge the call
// against the repository the session runs in instead of reporting an
// unknown project root. File reads only, no git process.
func cloudSessionRootEnrich(fallback string) func(*policy.Event) {
	stamp := withProjectLookupRoot(nil)
	return func(pe *policy.Event) {
		stamp(pe)
		if fallback == "" {
			return
		}
		if pe.ProjectLookupRoot == "" {
			pe.ProjectLookupRoot = hookRootOf(fallback)
		}
		if pe.ProjectRoot == "" && pe.RepoRoot == "" {
			if root, ok := git.FindCheckoutRoot(fallback); ok {
				pe.RepoRoot = root
			}
		}
	}
}

// prompt applies the soft budget stop.
func (g *cloudSessionGate) prompt(v cloudsession.VerifiedPolicy) int {
	now := time.Now
	if g.o.Now != nil {
		now = g.o.Now
	}
	d := cloudsession.SoftBudgetStop(v.Budget, now().UTC(), time.LoadLocation)
	for _, s := range d.Skipped {
		fmt.Fprintf(g.stderr, "observer cloud-session gate: budget cap not evaluated: %s\n", s)
	}
	if !d.Stop() {
		return g.allow()
	}
	if g.o.Mode != cloudsession.GuardEnforce {
		fmt.Fprintf(g.stderr, "observer cloud-session gate: observe mode, not stopping: %s\n", d.Reason)
		return g.allow()
	}
	return g.block(d.Reason)
}

// sandboxGuardDefaults is the [guard] configuration the gate starts from: the
// built-in defaults only. No config file (the sandbox's ~/.observer/config.toml
// is a file the agent can write as root), no OBSERVER_* environment override
// and no governance sidecar is read, so nothing written in the sandbox can
// disable a rule, widen [guard.boundary] allow_paths, drop a protected
// branch, or relax the taint, MCP or dialect settings the committed policy
// is judged with (ledger CLOUDSESS-10).
func sandboxGuardDefaults() (config.GuardConfig, error) {
	cfg, err := config.Load(config.LoadOptions{
		NoGlobal:          true,
		Env:               func(string) string { return "" },
		GovernanceSidecar: config.NoGovernanceSidecar,
	})
	if err != nil {
		return config.GuardConfig{}, fmt.Errorf("guard defaults: %w", err)
	}
	return cfg.Guard, nil
}

// sandboxBlockNotices maps the committed policy's origin to the guard's
// block notice, so a blocked call's reason names whose policy it is and how
// to change it from outside the sandbox (guard/blocknotice.go), never the
// node-local org-lock, approval or request-access wording, none of which
// works inside the sandbox.
var sandboxBlockNotices = map[cloudsession.PolicyOrigin]guard.BlockNotice{
	cloudsession.OriginNode: guard.BlockNoticeSandboxNode,
	cloudsession.OriginOrg:  guard.BlockNoticeSandboxOrg,
}

// buildSandboxGuard builds the guard the gate evaluates with: the default
// guard configuration (sandboxGuardDefaults, never the sandbox's own config
// file), the verified policy as its ONLY non-repository layer (served from
// memory and re-verified by the guard under keyPin), the user and
// trusted-project layers off (a file the agent could write in the sandbox
// must never weaken the committed policy; the in-repository project layer
// stays, it is escalate-only). It fails when the policy does not load, so a
// gate never runs on less than what was committed.
func buildSandboxGuard(v cloudsession.VerifiedPolicy, keyPin string, mode cloudsession.GuardMode, home string) (*guard.Guard, error) {
	gcfg, err := sandboxGuardDefaults()
	if err != nil {
		return nil, err
	}
	gcfg.Enabled = true
	gcfg.Mode = string(mode)
	gcfg.Strict = mode == cloudsession.GuardEnforce
	gcfg.Rules.UserPolicy = ""
	gcfg.Rules.TrustedProjectDir = ""
	// A path the guard reads through ReadFile only; nothing is read from or
	// written to it on disk.
	virtual := filepath.Join(home, ".observer", "cloud-session", "committed-policy-guard.json")
	gcfg.Rules.OrgBundle = virtual
	env := v.GuardEnvelope
	notice, ok := sandboxBlockNotices[v.Policy.Origin]
	if !ok {
		return nil, fmt.Errorf("no block notice for policy origin %q", v.Policy.Origin)
	}
	g, err := hookGuardNew(guard.Options{
		Config: gcfg, Home: home, OrgKeyPinHash: keyPin, BlockNotice: notice,
		ReadFile: func(p string) ([]byte, error) {
			if p == virtual {
				return env, nil
			}
			return os.ReadFile(p) //nolint:gosec // G304: the guard's own policy paths
		},
	})
	if err != nil {
		return nil, fmt.Errorf("build the sandbox guard: %w", err)
	}
	for _, st := range g.PolicyStates() {
		if st.Layer == "org" && st.Path == virtual {
			return g, nil
		}
	}
	return nil, fmt.Errorf("the committed policy did not load as the guard's policy layer: %v", g.LoadIssues())
}
