package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/cloudsessionnet"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudsession.go is `observer cloud-session` (Rail S of the cloud-agents
// arc, docs/cloud-sessions.md): init/remove write the repository files the
// internal/cloudsession planner renders; flush runs inside a vendor's cloud
// sandbox, scans the agent's own store with the existing adapters and ships
// the existing org push envelope through internal/cloudsessionnet, the
// feature's only egress.

// Environment variables the flush reads. Only names are documented; a token
// value is never printed.
const (
	envCloudSessionURL       = "SBO_CLOUD_SESSION_URL"
	envCloudSessionToken     = "SBO_CLOUD_SESSION_TOKEN"      //nolint:gosec // G101: env var NAME to read at run time, not a secret
	envCloudSessionTokenFile = "SBO_CLOUD_SESSION_TOKEN_FILE" //nolint:gosec // G101: env var NAME to read at run time, not a secret
)

// Flush bounds.
const (
	// cloudSessionMaxBatches bounds the envelopes one flush sends; what is
	// left waits in the local database for the next flush.
	cloudSessionMaxBatches = 20
	// cloudSessionBatchBytes is the envelope budget passed to
	// SelectUnpushedSince, under cloudsessionnet.MaxEnvelopeBytes.
	cloudSessionBatchBytes = 4 << 20
)

func newCloudSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud-session",
		Short: "Run Observer inside a managed cloud agent's sandbox (Rail S)",
		Long: "Set a repository up so a managed cloud coding agent (Claude Code on the\n" +
			"web, the GitHub Copilot cloud agent) captures its session with Observer\n" +
			"inside its own sandbox, and ships the rows when the agent stops.\n\n" +
			"init and remove write repository files you review and commit; flush is\n" +
			"what the committed hooks run in the sandbox. Every committed hook is a\n" +
			"no-op outside the vendor's cloud. See docs/cloud-sessions.md.",
	}
	cmd.AddCommand(newCloudSessionInitCmd(), newCloudSessionRemoveCmd(), newCloudSessionFlushCmd(), newCloudSessionStatusCmd(), newCloudSessionTokenCmd(),
		newCloudSessionGateCmd(), newCloudSessionSetupCmd())
	// Lane CA-C4: the customer-compute proxy (cloudsession_worker.go).
	cmd.AddCommand(newCloudSessionWorkerCmd())
	return cmd
}

// agentFlagHelp lists the agent ids for flag help.
func agentFlagHelp() string {
	return "cloud agent: " + strings.Join(cloudsession.AgentIDs(), ", ")
}

// repoRoot returns dir's repository root: the nearest ancestor holding .git.
func repoRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for d := abs; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil { //nolint:gosec // G703: false positive; the operator's own working directory, only stat'd for a .git entry
			return d, nil
		}
		if filepath.Dir(d) == d {
			return "", fmt.Errorf("%s is not inside a git repository (pass --repo)", abs)
		}
	}
}

// repoReader adapts a repository directory to the planner's ReadFile. Like
// applyRepoPlan it refuses a path that reaches through a symbolic link.
func repoReader(root string) cloudsession.ReadFile {
	return func(path string) (string, bool, error) {
		p, err := repoFilePath(root, path)
		if err != nil {
			return "", false, err
		}
		b, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		return string(b), true, nil
	}
}

// repoFilePath resolves rel (slash-separated, relative to root) to the path
// init writes, reads or removes, refusing one that would leave the
// repository: rel must be relative with no ".." component, and no component
// below root that exists may be a symbolic link or anything but a directory
// (the last one: anything but a regular file). A hostile repository could
// otherwise commit .claude as a link to ~/.ssh and have init write through
// it on the developer's machine. Components that do not exist yet are fine;
// init creates them as plain directories. root itself is the developer's
// choice and is not checked.
func repoFilePath(root, rel string) (string, error) {
	parts := strings.Split(rel, "/")
	if rel == "" || filepath.IsAbs(filepath.FromSlash(rel)) || filepath.VolumeName(filepath.FromSlash(rel)) != "" {
		return "", fmt.Errorf("%s: not a path inside the repository", rel)
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.ContainsRune(p, '\\') {
			return "", fmt.Errorf("%s: not a path inside the repository", rel)
		}
	}
	cur := root
	for i, p := range parts {
		cur = filepath.Join(cur, p)
		fi, err := os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			return filepath.Join(root, filepath.FromSlash(rel)), nil
		}
		if err != nil {
			return "", fmt.Errorf("%s: %w", rel, err)
		}
		at := strings.Join(parts[:i+1], "/")
		last := i == len(parts)-1
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			return "", fmt.Errorf("%s: refusing to go through the symbolic link %s in the repository", rel, at)
		case !last && !fi.IsDir():
			return "", fmt.Errorf("%s: %s is not a plain directory", rel, at)
		case last && !fi.Mode().IsRegular():
			return "", fmt.Errorf("%s: not a regular file", rel)
		}
	}
	return cur, nil
}

// applyRepoPlan writes a plan into root. Every target goes through
// repoFilePath first, so no write, chmod or remove follows a symbolic link
// committed in the repository.
func applyRepoPlan(root string, plan cloudsession.RepoPlan) error {
	for _, c := range plan.Changes {
		if !c.Changed() {
			continue
		}
		dst, err := repoFilePath(root, c.Path)
		if err != nil {
			return fmt.Errorf("refusing to write %s: %w", c.Path, err)
		}
		if c.Delete {
			if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", c.Path, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return fmt.Errorf("mkdir for %s: %w", c.Path, err)
		}
		mode := os.FileMode(0o644)
		if c.Executable {
			mode = 0o755
		}
		if err := os.WriteFile(dst, []byte(c.After), mode); err != nil {
			return fmt.Errorf("write %s: %w", c.Path, err)
		}
		if err := os.Chmod(dst, mode); err != nil {
			return fmt.Errorf("chmod %s: %w", c.Path, err)
		}
	}
	return nil
}

// printRepoPlan prints the diff, per-file notes and manual steps.
func printRepoPlan(out io.Writer, root string, plan cloudsession.RepoPlan, dryRun bool) {
	if d := plan.Diff(); d != "" {
		fmt.Fprint(out, d)
	}
	for _, c := range plan.Changes {
		if c.Note != "" {
			fmt.Fprintf(out, "note: %s: %s\n", c.Path, c.Note)
		}
	}
	switch {
	case !plan.Changed():
		fmt.Fprintln(out, "no repository changes")
	case dryRun:
		fmt.Fprintf(out, "dry run: nothing written in %s\n", root)
	default:
		fmt.Fprintf(out, "written in %s; review with `git diff` and commit\n", root)
	}
	for _, m := range plan.Manual {
		fmt.Fprintf(out, "to do: %s\n", m)
	}
}

func newCloudSessionInitCmd() *cobra.Command {
	var (
		agent, destination, url, observerVersion, releaseBase, installDir, repo string
		installSource, npmRegistry, share, guardMode, configPath                string
		npmIntegrity                                                            []string
		every                                                                   int
		reformat, dryRun, withGuard, withMCP, withCodeIntel                     bool
		otelLoopback                                                            bool
		otelLoopbackAddr                                                        string
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write the repository files that run Observer in a cloud agent's sandbox",
		Long: "Writes the agent's hook configuration, a setup script that installs a\n" +
			"pinned, verified observer, and the agent's setup step, then prints the\n" +
			"diff to review and commit. Idempotent; undo with remove. No token is ever\n" +
			"written into the repository.\n\n" +
			"The default install source is npm: init reads the registry's\n" +
			"dist.integrity (sha512) of each Linux platform package of the pinned\n" +
			"version and writes it into the setup script (one GET per architecture\n" +
			"to the registry; pass --npm-integrity to pin by hand without it).\n" +
			"--install-source release keeps the release archive path (sha256 plus\n" +
			"the vendor signature) for sandboxes that can reach release assets.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			root, err := resolveRepo(repo)
			if err != nil {
				return err
			}
			if observerVersion == "" {
				observerVersion = releaseTagOf(version)
			}
			src := cloudsession.InstallSource(installSource)
			pins, err := parseNpmIntegrityFlags(npmIntegrity)
			if err != nil {
				return err
			}
			// Read the pins from the registry only when they are needed and
			// the planner would otherwise refuse: the npm source, a release
			// tag, nothing pinned by hand.
			if src == cloudsession.InstallNpm && len(pins) == 0 && observerVersion != "" {
				ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
				pins, err = cloudsessionnet.LookupNpmPins(ctx, npmRegistry, observerVersion, cloudsession.NpmArches, cloudsessionnet.NpmOptions{})
				cancel()
				if err != nil {
					return fmt.Errorf("pin the npm packages: %w (pass --npm-integrity x64=sha512-... to pin by hand, or --install-source release)", err)
				}
			}
			// --guard (lane CA-C2): fetch the signed policy from the
			// destination and verify it against the pinned key; it must also
			// load as the guard's policy layer, exactly as the sandbox gate
			// will load it, before anything is committed.
			var guardSetup *cloudsession.GuardSetup
			var guardNotes []string
			if withGuard {
				gs, notes, err := cloudSessionInitGuard(cmd.Context(), root, cloudsession.DestinationKind(destination), configPath, cloudsession.GuardMode(guardMode))
				if err != nil {
					return err
				}
				guardSetup, guardNotes = gs, notes
			}
			plan, err := cloudsession.PlanInit(cloudsession.PlanOptions{
				Agent:           agent,
				Destination:     cloudsession.DestinationKind(destination),
				DestinationURL:  url,
				Share:           cloudsession.SharePosture(share),
				ObserverVersion: observerVersion,
				VendorKeys:      cloudSessionVendorKeys(),
				InstallSource:   src,
				NpmRegistry:     npmRegistry,
				NpmPins:         pins,
				ReleaseBaseURL:  releaseBase,
				InstallDir:      installDir,
				FlushEvery:      every,
				Reformat:        reformat,
				Guard:           guardSetup,
				MCP:             withMCP,
				CodeIntel:       withCodeIntel,
			}, repoReader(root))
			if err != nil {
				return err
			}
			// Lane CA-C7: the opt-in in-sandbox loopback OTLP receiver.
			if plan, err = applyOTelLoopback(plan, cloudsession.PlanOptions{InstallDir: installDir}, otelLoopback, otelLoopbackAddr); err != nil {
				return err
			}
			if !dryRun {
				if err := applyRepoPlan(root, plan); err != nil {
					return err
				}
			}
			printRepoPlan(out, root, plan, dryRun)
			printCloudSessionFeatures(out, plan.Agent, guardSetup, guardNotes, withMCP)
			return nil
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", agentFlagHelp())
	_ = cmd.MarkFlagRequired("agent")
	cmd.Flags().StringVar(&destination, "destination", string(cloudsession.DestOrg), "where the sandbox ships: org (your org server) or node (your own reachable node)")
	cmd.Flags().StringVar(&url, "url", "", "destination base URL baked into the hooks (not a secret); otherwise the sandbox reads "+envCloudSessionURL)
	cmd.Flags().StringVar(&share, "share", "", "what the sandbox ships, baked into the hooks: "+string(cloudsession.ShareFullContent)+" or "+string(cloudsession.ShareMetadataOnly)+". For --destination org pass the posture the ship token's mint response names (managed enrolment = "+string(cloudsession.ShareFullContent)+"; the org refuses content otherwise). Default: "+string(cloudsession.ShareFullContent)+" for node, "+string(cloudsession.ShareMetadataOnly)+" for org")
	cmd.Flags().StringVar(&observerVersion, "observer-version", "", "release tag the setup script pins (default: this binary's version)")
	cmd.Flags().StringVar(&installSource, "install-source", string(cloudsession.InstallNpm), "where the setup script fetches observer: npm (registry tarball, sha512 pinned from dist.integrity) or release (archive, sha256 and vendor signature)")
	cmd.Flags().StringVar(&npmRegistry, "npm-registry", "", "https npm registry mirror (default "+cloudsession.DefaultNpmRegistry+")")
	cmd.Flags().StringSliceVar(&npmIntegrity, "npm-integrity", nil, "pin a platform package by hand instead of reading the registry: arch=sha512-<base64> (x64, arm64), repeatable")
	cmd.Flags().StringVar(&releaseBase, "release-base-url", "", "https mirror laid out like GitHub releases, for --install-source release (default "+cloudsession.DefaultReleaseBaseURL+")")
	cmd.Flags().StringVar(&installDir, "install-dir", "", "where the setup script installs observer (default "+cloudsession.DefaultInstallDir+")")
	cmd.Flags().IntVar(&every, "every", 0, "periodic flush cadence in tool calls (default "+strconv.Itoa(cloudsession.DefaultFlushEvery)+")")
	cmd.Flags().BoolVar(&reformat, "reformat", false, "allow rewriting a shared JSON settings file that is not in two-space layout")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the diff, write nothing")
	cmd.Flags().StringVar(&repo, "repo", "", "repository root (default: the git repository of the working directory)")
	cmd.Flags().BoolVar(&withGuard, "guard", false, "commit the destination's signed guard policy and gate hooks that evaluate it in the sandbox with no network call (org: needs this node enrolled; node: signed by this node)")
	cmd.Flags().StringVar(&guardMode, "guard-mode", string(cloudsession.GuardEnforce), "with --guard: enforce (deny, and block when the gate cannot evaluate, where the vendor honors a block) or observe (record only)")
	cmd.Flags().BoolVar(&withMCP, "mcp", false, "register Observer's MCP server (observer serve) for the agent and build its database during setup")
	cmd.Flags().BoolVar(&withCodeIntel, "codeintel", false, "with --mcp: index the repository for code intelligence during setup (off by default)")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to observer config.toml (for --guard)")
	cmd.Flags().BoolVar(&otelLoopback, "otel-loopback", false, "also start a loopback OTLP receiver in the sandbox for the agent's own telemetry export (Claude Code; see docs/cloud-agents.md)")
	cmd.Flags().StringVar(&otelLoopbackAddr, "otel-loopback-addr", "", "loopback host:port of that receiver (default "+cloudsession.DefaultOTelLoopbackAddr+")")
	return cmd
}

// cloudSessionInitGuard fetches, verifies and load-checks the policy for
// init --guard.
func cloudSessionInitGuard(ctx context.Context, root string, dest cloudsession.DestinationKind, configPath string, mode cloudsession.GuardMode) (*cloudsession.GuardSetup, []string, error) {
	if !cloudsession.ValidGuardMode(mode) {
		return nil, nil, fmt.Errorf("--guard-mode must be one of %v, got %q", cloudsession.GuardModes(), mode)
	}
	fctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	res, err := fetchSandboxPolicy(fctx, dest, configPath, time.Now())
	if err != nil {
		return nil, nil, err
	}
	v, err := cloudsession.VerifyPolicy(res.Policy, true, cloudsession.PolicyPin{KeyPin: res.KeyPin, Digest: cloudsession.PolicyDigest(res.Policy)})
	if err != nil {
		return nil, nil, err
	}
	home, _ := os.UserHomeDir()
	if _, err := buildSandboxGuard(v, res.KeyPin, mode, home); err != nil {
		return nil, nil, fmt.Errorf("the fetched policy would not load in the sandbox: %w", err)
	}
	policy := res.Policy
	if committed, ok := committedSamePolicy(root, v.Policy, res.KeyPin); ok {
		// Nothing signed changed: keep the committed bytes, so a re-run
		// of init is a no-op instead of a new signature and timestamp.
		policy = committed
	}
	return &cloudsession.GuardSetup{Mode: mode, KeyPin: res.KeyPin, Policy: policy}, res.Notes, nil
}

// committedSamePolicy returns the repository's committed policy file when it
// verifies under keyPin and signs the same content as fresh: the same origin
// and guard policy (for the org, the same bundle version) and no budget on
// either side. A budget document is re-minted by the org on every fetch, so a
// policy that carries one is always refreshed (a newer spend figure).
func committedSamePolicy(root string, fresh cloudsession.SandboxPolicy, keyPin string) ([]byte, bool) {
	raw, exists, err := readCloudSessionPolicy(root)
	if err != nil || !exists {
		return nil, false
	}
	v, err := cloudsession.VerifyPolicy(raw, true, cloudsession.PolicyPin{KeyPin: keyPin, Digest: cloudsession.PolicyDigest(raw)})
	if err != nil {
		return nil, false
	}
	old := v.Policy
	same := old.Origin == fresh.Origin && old.Guard.BundleTOML == fresh.Guard.BundleTOML &&
		old.Budget == nil && fresh.Budget == nil &&
		(fresh.Origin == cloudsession.OriginNode || old.Guard.Version == fresh.Guard.Version)
	return raw, same
}

// printCloudSessionFeatures prints what the opt-in features do, honestly per
// gate (cloudsession.GateCoverageFor).
func printCloudSessionFeatures(out io.Writer, a cloudsession.Agent, g *cloudsession.GuardSetup, notes []string, mcp bool) {
	if g != nil {
		fmt.Fprintf(out, "guard: %s mode, policy key %s…, policy %s\n", g.Mode, g.KeyPin[:12], cloudsession.PolicyDigest(g.Policy))
		for _, c := range cloudsession.GateCoverageFor(a, g.Mode) {
			fmt.Fprintf(out, "guard: %s\n", c.Line())
		}
		for _, n := range notes {
			fmt.Fprintf(out, "guard: %s\n", n)
		}
		fmt.Fprintln(out, "guard: re-run init --guard to pick up a new policy or budget figure; the committed file is a snapshot")
	}
	if mcp && a.MCPSettings == "" {
		fmt.Fprintf(out, "mcp: if the cloud session does not start the %q server, approve it in the session or add it to \"enabledMcpjsonServers\" in %s (not live-checked yet)\n", cloudsession.MCPServerName, cloudsession.ClaudeSettingsPath)
	}
}

func newCloudSessionRemoveCmd() *cobra.Command {
	var (
		agent, repo string
		dryRun      bool
	)
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Take out the repository files init wrote for an agent",
		Long: "Removes exactly what init added: Observer's hook entries (the rest of\n" +
			"a shared settings file is restored byte-for-byte) and the generated\n" +
			"files, unless they were edited since. A setup script another agent still\n" +
			"uses is kept.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := resolveRepo(repo)
			if err != nil {
				return err
			}
			plan, err := cloudsession.PlanRemove(agent, repoReader(root))
			if err != nil {
				return err
			}
			if !dryRun {
				if err := applyRepoPlan(root, plan); err != nil {
					return err
				}
			}
			printRepoPlan(cmd.OutOrStdout(), root, plan, dryRun)
			return nil
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", agentFlagHelp())
	_ = cmd.MarkFlagRequired("agent")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the diff, write nothing")
	cmd.Flags().StringVar(&repo, "repo", "", "repository root (default: the git repository of the working directory)")
	return cmd
}

func resolveRepo(repo string) (string, error) {
	if repo != "" {
		return filepath.Abs(repo)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return repoRoot(wd)
}

// parseNpmIntegrityFlags parses --npm-integrity arch=sha512-... values.
func parseNpmIntegrityFlags(vals []string) ([]cloudsession.NpmPin, error) {
	var pins []cloudsession.NpmPin
	for _, v := range vals {
		arch, integrity, ok := strings.Cut(v, "=")
		if !ok || arch == "" || integrity == "" {
			return nil, fmt.Errorf("--npm-integrity %q: want arch=sha512-<base64>", v)
		}
		pins = append(pins, cloudsession.NpmPin{Arch: strings.TrimSpace(arch), Integrity: strings.TrimSpace(integrity)})
	}
	return pins, nil
}

// releaseTagOf turns this binary's version ("1.37.0", "v1.37.0" or "dev")
// into a release tag; "" when it is not a release build.
func releaseTagOf(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "dev" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

func newCloudSessionStatusCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Say whether this process runs inside a supported cloud agent's sandbox, and what the last flush recorded",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			det, ok := cloudsession.DetectAny(os.LookupEnv)
			if !ok {
				fmt.Fprintln(out, "not in a supported cloud agent sandbox: cloud-session hooks and flush are no-ops here")
				return nil
			}
			fmt.Fprintf(out, "in the %s sandbox (marker %s), execution location %s\n", det.Agent, det.MarkerEnv, det.Location)
			if det.VendorRef != "" {
				fmt.Fprintf(out, "vendor session reference: %s\n", det.VendorRef)
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			stateDir := filepath.Join(filepath.Dir(cfg.Observer.DBPath), "cloud-session")
			if c := loadCloudSessionCoverage(stateDir, det.Agent); c != nil {
				fmt.Fprintf(out, "coverage: %s (%s, %s flush at %s)\n", c.Message(), c.State, c.Trigger, c.At.Format(time.RFC3339))
			} else {
				fmt.Fprintln(out, "coverage: no flush has recorded any yet")
			}
			var b cloudsession.HookBaseline
			if readCloudSessionJSON(cloudSessionBaselinePath(stateDir, det.Agent), &b) {
				fmt.Fprintf(out, "hook block baseline: %s from %s (session %s)\n", b.Digest, b.Source, b.VendorRef)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to observer config.toml")
	return cmd
}

// cloudSessionFlushResult is what one flush did, printed on stderr so a
// hook's stdout stays clean for the vendor.
type cloudSessionFlushResult struct {
	Skipped     string   `json:"skipped,omitempty"`
	Agent       string   `json:"agent"`
	Trigger     string   `json:"trigger,omitempty"`
	Location    string   `json:"execution_location,omitempty"`
	Destination string   `json:"destination,omitempty"`
	Scanned     int      `json:"files_scanned"`
	Envelopes   int      `json:"envelopes"`
	Rows        int      `json:"rows"`
	Bytes       int      `json:"bytes"`
	Stamped     string   `json:"stamp"`
	Pending     bool     `json:"pending,omitempty"`
	Error       string   `json:"error,omitempty"`
	Locations   []string `json:"locations,omitempty"`
	// Guard is the self-modification guard's verdict (verified, changed,
	// uncommitted); Held reports that it kept this flush from delivering.
	Guard string `json:"hook_block,omitempty"`
	Held  bool   `json:"held,omitempty"`
	// Coverage is the coverage state this flush recorded, with its reason
	// and sentence (empty when the flush learned nothing new).
	Coverage        string `json:"coverage,omitempty"`
	CoverageReason  string `json:"coverage_reason,omitempty"`
	CoverageMessage string `json:"coverage_message,omitempty"`
}

func newCloudSessionFlushCmd() *cobra.Command {
	var (
		agent, trigger, destination, url, tokenFile, configPath, repo, share string
		every                                                                int
		timeout                                                              time.Duration
		jsonOut, trustUncommitted                                            bool
	)
	cmd := &cobra.Command{
		Use:   "flush",
		Short: "Scan the agent's store in this sandbox and ship the captured rows",
		Long: "Run by the committed hooks inside the vendor's sandbox. Outside a cloud\n" +
			"sandbox (no vendor marker) it does nothing. It scans the agent's own\n" +
			"store with the existing adapters, builds the org push envelope from the\n" +
			"local database (the same seam and privacy strip as `observer org`), and\n" +
			"delivers it. A failed delivery keeps the rows for the next flush. Before\n" +
			"delivering it checks that the committed hook block is unchanged since\n" +
			"the session started (the agent can rewrite its own hooks mid-session).\n" +
			"The ship token comes from " + envCloudSessionToken + " or the file named by\n" +
			envCloudSessionTokenFile + ".",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := runCloudSessionFlush(cmd.Context(), cloudSessionFlushOptions{
				Agent: agent, Trigger: cloudsession.Trigger(trigger), Destination: cloudsession.DestinationKind(destination),
				Share: cloudsession.SharePosture(share),
				URL:   url, TokenFile: tokenFile, ConfigPath: configPath, Every: every, Timeout: timeout,
				Repo: repo, TrustUncommittedHooks: trustUncommitted, Env: os.LookupEnv,
			})
			if err != nil {
				return err // cobra prints it; a hook shows it as a non-blocking error
			}
			errOut := cmd.ErrOrStderr()
			if jsonOut {
				enc := json.NewEncoder(errOut)
				_ = enc.Encode(res)
			} else {
				printCloudSessionFlush(errOut, res)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", agentFlagHelp())
	_ = cmd.MarkFlagRequired("agent")
	cmd.Flags().StringVar(&trigger, "trigger", string(cloudsession.TriggerFinal), "start (SessionStart), prompt (UserPromptSubmit), periodic (every --every tool calls) or final (Stop/SessionEnd)")
	cmd.Flags().StringVar(&destination, "destination", string(cloudsession.DestOrg), "org, node, or file (a local directory: tests, and a look at what would ship)")
	cmd.Flags().StringVar(&url, "url", "", "destination base URL (or directory for file); default "+envCloudSessionURL)
	cmd.Flags().StringVar(&share, "share", "", "what ships: "+string(cloudsession.ShareFullContent)+" or "+string(cloudsession.ShareMetadataOnly)+" (default: "+string(cloudsession.ShareFullContent)+" for node, "+string(cloudsession.ShareMetadataOnly)+" otherwise; init bakes it into the hooks)")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "file holding the ship token (default "+envCloudSessionTokenFile+", then "+envCloudSessionToken+")")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to observer config.toml")
	cmd.Flags().IntVar(&every, "every", 0, "periodic cadence in calls (default "+strconv.Itoa(cloudsession.DefaultFlushEvery)+")")
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "bound on the whole flush (default: the trigger's budget, 20s to 45s)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print the result as JSON on stderr")
	cmd.Flags().StringVar(&repo, "repo", "", "repository whose committed hook block is verified (default: the git repository of the working directory, which is where the vendor runs hooks)")
	cmd.Flags().BoolVar(&trustUncommitted, "trust-uncommitted-hooks", false, "accept a hook block that is not committed at HEAD as the session baseline (a manual test before commit; never written into the committed hooks)")
	return cmd
}

func printCloudSessionFlush(w io.Writer, r cloudSessionFlushResult) {
	if r.Skipped != "" {
		fmt.Fprintf(w, "cloud-session flush: skipped: %s\n", r.Skipped)
		if r.CoverageMessage != "" {
			fmt.Fprintf(w, "cloud-session flush: coverage: %s\n", r.CoverageMessage)
		}
		return
	}
	fmt.Fprintf(w, "cloud-session flush: %s (%s) -> %s: scanned %d file(s), sent %d envelope(s), %d row(s), %d byte(s); stamp %s\n",
		r.Agent, r.Location, r.Destination, r.Scanned, r.Envelopes, r.Rows, r.Bytes, r.Stamped)
	for _, l := range r.Locations {
		fmt.Fprintf(w, "cloud-session flush: wrote %s\n", l)
	}
	if r.Pending {
		fmt.Fprintln(w, "cloud-session flush: rows remain in the local database for the next flush (partial history until then)")
	}
	if r.Error != "" {
		fmt.Fprintf(w, "cloud-session flush: %s\n", r.Error)
	}
	if r.CoverageMessage != "" {
		fmt.Fprintf(w, "cloud-session flush: coverage: %s\n", r.CoverageMessage)
	}
}

// cloudSessionFlushOptions are runCloudSessionFlush's inputs.
type cloudSessionFlushOptions struct {
	Agent       string
	Trigger     cloudsession.Trigger
	Destination cloudsession.DestinationKind
	// Share is the share posture (decision CA-D19); "" takes the
	// destination's default (cloudsession.ResolveShare).
	Share      cloudsession.SharePosture
	URL        string
	TokenFile  string
	ConfigPath string
	Every      int
	Timeout    time.Duration
	// Repo is the repository whose hook block the guard verifies ("" =
	// the git repository of the working directory).
	Repo string
	// TrustUncommittedHooks accepts an uncommitted hook block as baseline.
	TrustUncommittedHooks bool
	Env                   cloudsession.LookupEnv
	// HTTP overrides the delivery options (tests).
	HTTP cloudsessionnet.HTTPOptions
}

// readShipToken resolves the ship token: --token-file, then
// SBO_CLOUD_SESSION_TOKEN_FILE, then SBO_CLOUD_SESSION_TOKEN.
func readShipToken(tokenFile string, env cloudsession.LookupEnv) (string, error) {
	if tokenFile == "" {
		tokenFile, _ = env(envCloudSessionTokenFile)
	}
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read ship token file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	v, _ := env(envCloudSessionToken)
	return strings.TrimSpace(v), nil
}

// errCloudSessionEnrolled refuses a flush on an org-enrolled database: the
// flush advances the same push cursor as the org push loop, so on an
// enrolled node it would hide rows from the org.
var errCloudSessionEnrolled = errors.New("this Observer database is enrolled with an org; cloud-session flush runs only on a daemonless sandbox node")

// runCloudSessionFlush is the flush. A delivery failure is reported in the
// result and the recorded coverage and leaves the rows for the next flush; it
// is not an error, so a hook never fails the agent over a network blip. A
// misconfiguration is an error only on the trigger that reports one (start,
// once per session); the others record it in the coverage and exit 0, so a
// broken setup does not raise a hook error on every prompt.
func runCloudSessionFlush(ctx context.Context, o cloudSessionFlushOptions) (cloudSessionFlushResult, error) {
	res := cloudSessionFlushResult{Agent: o.Agent, Trigger: string(o.Trigger), Stamped: "pending CA-A1"}
	agent, err := cloudsession.AgentByID(o.Agent)
	if err != nil {
		return res, err
	}
	if !agent.Supported() {
		return res, fmt.Errorf("%s is not supported yet: %s", agent.DisplayName, agent.Unsupported)
	}
	if o.Env == nil {
		o.Env = func(string) (string, bool) { return "", false }
	}
	det := cloudsession.Detect(agent, o.Env)
	if !det.InCloud {
		res.Skipped = "not in the " + agent.DisplayName + " cloud sandbox (no vendor marker)"
		return res, nil
	}
	res.Location = string(det.Location)
	spec, err := cloudsession.TriggerSpecFor(o.Trigger)
	if err != nil {
		return res, err
	}

	timeout := o.Timeout
	if timeout <= 0 {
		timeout = spec.Budget
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stateDir, cfg, err := openCloudSessionState(ctx, o.ConfigPath)
	if err != nil {
		return res, err
	}
	fl := &cloudSessionFlush{o: o, agent: agent, det: det, spec: spec, stateDir: stateDir, res: &res}

	// The destination. Misconfiguration is recorded as coverage; only the
	// trigger that reports misconfiguration fails the hook.
	if err := fl.resolveDelivery(); err != nil {
		recordCloudSessionCoverage(stateDir, &res, cloudsession.ReasonNotConfigured, "", det.VendorRef, spec.Trigger)
		if spec.ReportsMisconfig {
			return res, err
		}
		res.Skipped = "not configured: " + err.Error()
		return res, nil
	}
	if run, err := fl.cadence(); err != nil || !run {
		return res, err
	}

	// One flush at a time: hooks of one event run in parallel, and Stop and
	// SessionEnd can fire together.
	release, acquired, lerr := cloudSessionLock(stateDir)
	if lerr == nil && !acquired {
		res.Skipped = "another flush is running"
		return res, nil
	}
	defer release()

	// The self-modification guard: is the owned hook block the one the
	// session started with?
	guard, err := checkCloudSessionHooks(ctx, stateDir, cloudSessionRepoRoot(o.Repo), agent, det, spec, o.TrustUncommittedHooks)
	if err != nil {
		return res, err
	}
	res.Guard = string(guard.Verdict)

	// Capture stays local whatever the guard says; only delivery is held.
	if err := fl.scan(ctx); err != nil {
		return res, err
	}
	if guard.Verdict != cloudsession.GuardVerified {
		res.Held, res.Pending = true, true
		recordCloudSessionCoverage(stateDir, &res, guard.Reason, fl.host, det.VendorRef, spec.Trigger)
		if guard.Verdict == cloudsession.GuardUncommitted && spec.ReportsMisconfig {
			return res, errors.New(res.CoverageMessage + " (commit the files `observer cloud-session init` wrote)")
		}
		return res, nil
	}
	if cloudsession.SkipDelivery(spec, loadCloudSessionCoverage(stateDir, agent.ID), fl.host, det.VendorRef) {
		res.Pending = true
		res.Skipped = "delivery skipped: the environment's network level blocks " + fl.host + " (recorded by an earlier flush of this session; the start and final flushes try again)"
		return res, nil
	}
	return res, fl.deliver(ctx, cfg)
}

// cloudSessionFlush carries one flush's resolved inputs between its phases.
type cloudSessionFlush struct {
	o         cloudSessionFlushOptions
	agent     cloudsession.Agent
	det       cloudsession.Detection
	spec      cloudsession.TriggerSpec
	stateDir  string
	res       *cloudSessionFlushResult
	deliverer cloudsession.Deliverer
	host      string
}

// cloudSessionShareOptions is the push seam's share options for a flush
// (decision CA-D19). The posture resolves through cloudsession.ResolveShare
// (an explicit --share, else the destination's default: full content to the
// owner's own node, metadata only otherwise). Full content sets
// FullContent, the same switch a managed node's enrolment writes, so the
// strip is still the one shipsRawContent() seam; metadata only clears every
// raw-content switch whatever the sandbox config says, so the committed
// posture is what ships.
func cloudSessionShareOptions(cfg config.Config, dest cloudsession.DestinationKind, requested cloudsession.SharePosture) (store.ShareOptions, error) {
	posture, err := cloudsession.ResolveShare(dest, requested)
	if err != nil {
		return store.ShareOptions{}, err
	}
	share := orgclient.ShareOptionsFromConfig(cfg.OrgClient)
	switch posture {
	case cloudsession.ShareFullContent:
		share.FullContent = true
	default:
		share.FullContent, share.AdminManaged, share.EnterpriseGranted = false, false, false
	}
	return share, nil
}

// openCloudSessionState opens the local database once to refuse an
// org-enrolled node and returns the flush's state directory and config.
func openCloudSessionState(ctx context.Context, configPath string) (string, config.Config, error) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return "", cfg, err
	}
	defer cleanup()
	enr, err := store.New(database).LoadEnrolment(ctx)
	if err != nil {
		return "", cfg, fmt.Errorf("load enrolment: %w", err)
	}
	if enr != nil {
		return "", cfg, errCloudSessionEnrolled
	}
	stateDir := filepath.Join(filepath.Dir(cfg.Observer.DBPath), "cloud-session")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", cfg, fmt.Errorf("state dir: %w", err)
	}
	return stateDir, cfg, nil
}

// resolveDelivery resolves the destination, the ship token and the
// deliverer. Every error it returns is a misconfiguration.
func (f *cloudSessionFlush) resolveDelivery() error {
	target := f.o.URL
	if target == "" {
		target, _ = f.o.Env(envCloudSessionURL)
	}
	dest, err := cloudsession.ResolveDestination(f.o.Destination, target)
	if err != nil {
		return err
	}
	if _, err := cloudsession.ResolveShare(dest.Kind, f.o.Share); err != nil {
		return err
	}
	f.res.Destination = string(dest.Kind)
	token := ""
	if dest.NeedsToken {
		if token, err = readShipToken(f.o.TokenFile, f.o.Env); err != nil {
			return err
		}
	}
	httpOpts := f.o.HTTP
	if httpOpts.AgentVersion == "" {
		httpOpts.AgentVersion = version
	}
	if f.deliverer, err = cloudsessionnet.New(dest, token, httpOpts); err != nil {
		return err
	}
	if hd, ok := f.deliverer.(*cloudsessionnet.HTTPDeliverer); ok {
		f.host = hd.Host()
	}
	return nil
}

// cadence advances the periodic counter and reports whether this call
// flushes.
func (f *cloudSessionFlush) cadence() (bool, error) {
	counterPath := filepath.Join(f.stateDir, "flush-count-"+f.agent.ID)
	prev := 0
	if b, err := os.ReadFile(counterPath); err == nil {
		prev, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	dec, err := cloudsession.ShouldFlush(f.o.Trigger, prev, f.o.Every)
	if err != nil {
		return false, err
	}
	if dec.Counted {
		_ = os.WriteFile(counterPath, []byte(strconv.Itoa(dec.Count)), 0o600)
	}
	if !dec.Run {
		f.res.Skipped = fmt.Sprintf("periodic flush %d of every %d", dec.Count, everyOrDefault(f.o.Every))
	}
	return dec.Run, nil
}

// scan runs the agent's adapters over its own store in this sandbox.
func (f *cloudSessionFlush) scan(ctx context.Context) error {
	for _, ad := range f.agent.ScanAdapters {
		w, wcleanup, err := buildWatcherWithOverride(ctx, f.o.ConfigPath, ad)
		if err != nil {
			return fmt.Errorf("scan %s: %w", ad, err)
		}
		sr, err := w.Scan(ctx)
		wcleanup()
		if err != nil {
			return fmt.Errorf("scan %s: %w", ad, err)
		}
		f.res.Scanned += sr.FilesProcessed
	}
	return nil
}

// deliver sends up to cloudSessionMaxBatches envelopes and records the
// coverage the deliveries showed.
func (f *cloudSessionFlush) deliver(ctx context.Context, cfg config.Config) error {
	_, database, cleanup, err := loadConfigAndDB(ctx, f.o.ConfigPath)
	if err != nil {
		return err
	}
	defer cleanup()
	st := store.New(database)
	// Price $0-stored token_usage rows at push time, the same seam and the
	// same process cost engine the daemon's org push wires in buildOrgBundle
	// (G1-COST(b)). Without it a transcript-only turn (an adapter that
	// stores no cost) shipped from the sandbox as $0. No network: the engine
	// reads the compiled seed, the local overrides and any persisted org
	// rows (a sandbox has none).
	st.SetOrgPushPricer(orgPushPricer(acquireProcessCostEngine(ctx, cfg, database, newLogger("warn"))))
	share, err := cloudSessionShareOptions(cfg, f.o.Destination, f.o.Share)
	if err != nil {
		return err
	}
	stamper := executionStamperFor(st)
	if stamper != nil {
		f.res.Stamped = "applied"
	}
	var outcome cloudsession.DeliveryOutcome
	capped := true
	for i := 0; i < cloudSessionMaxBatches; i++ {
		sent, err := flushOneEnvelope(ctx, st, share, f.det, stamper, f.deliverer, f.res, &outcome)
		if err != nil {
			return err
		}
		if !sent {
			capped = false
			break
		}
	}
	if capped {
		f.res.Pending = true
		outcome.Pending = true
	}
	if reason, ok := cloudsession.ClassifyDelivery(outcome); ok {
		recordCloudSessionCoverage(f.stateDir, f.res, reason, f.host, f.det.VendorRef, f.spec.Trigger)
	}
	return nil
}

// cloudSessionRepoRoot resolves --repo, defaulting to the git repository of
// the working directory ("" when there is none: the guard then finds no
// committed block).
func cloudSessionRepoRoot(repo string) string {
	if repo != "" {
		if abs, err := filepath.Abs(repo); err == nil {
			return abs
		}
		return repo
	}
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	root, _ := repoRoot(wd)
	return root
}

func everyOrDefault(n int) int {
	if n <= 0 {
		return cloudsession.DefaultFlushEvery
	}
	return n
}

// flushOneEnvelope selects, stamps, encodes and delivers one envelope.
// sent=false when there was nothing to send or the delivery failed (the
// failure is recorded in res and the cursor is left where it was).
func flushOneEnvelope(
	ctx context.Context, st *store.Store, share store.ShareOptions, det cloudsession.Detection,
	stamper cloudsession.ExecutionStamper, deliverer cloudsession.Deliverer, res *cloudSessionFlushResult,
	outcome *cloudsession.DeliveryOutcome,
) (sent bool, err error) {
	cur, err := st.LoadPushCursor(ctx)
	if err != nil {
		return false, fmt.Errorf("load cursor: %w", err)
	}
	// No identity is stamped here: the destination binds the rows to the
	// member the ship token was minted for (CA-D8). No settle holdback: the
	// sandbox may be gone before a held-back row would become eligible.
	sel := func() (store.PushBatch, error) {
		return st.SelectUnpushedSince(ctx, cur, cloudSessionBatchBytes, "", "", share, store.ScopeOptions{})
	}
	batch, err := sel()
	if err != nil {
		return false, fmt.Errorf("select: %w", err)
	}
	if batch.Empty() {
		st.CommitPushedSnapshots()
		if batch.Cursor != cur {
			_, _ = st.SavePushCursorIfUnchanged(ctx, cur, batch.Cursor)
		}
		return false, nil
	}
	ids := make([]string, 0, len(batch.Sessions))
	for _, s := range batch.Sessions {
		ids = append(ids, s.ID)
	}
	if n, err := cloudsession.ApplyStamps(ctx, stamper, cloudsession.PlanStamps(det, ids)); err != nil {
		return false, err
	} else if n > 0 {
		// The stamp changed rows this batch already read: select again so
		// the envelope carries it.
		if batch, err = sel(); err != nil {
			return false, fmt.Errorf("select: %w", err)
		}
	}
	env := orgclient.EnvelopeFromBatch(batch, cur, orgclient.EnvelopeMeta{AgentVersion: version})
	raw, err := json.Marshal(env)
	if err != nil {
		return false, fmt.Errorf("encode envelope: %w", err)
	}
	receipt, derr := deliverer.Deliver(ctx, raw)
	deliveryOutcome(outcome, derr)
	if derr != nil {
		res.Error = "delivery failed, rows kept for the next flush: " + derr.Error()
		res.Pending = true
		outcome.Pending = true
		return false, nil
	}
	if receipt.Location != "" {
		res.Locations = append(res.Locations, receipt.Location)
	}
	if _, err := st.SavePushCursorIfUnchanged(ctx, cur, batch.Cursor); err != nil {
		return false, fmt.Errorf("save cursor: %w", err)
	}
	if err := st.AckPushedChanges(ctx, batch.Acks); err != nil {
		res.Error = "acknowledging re-sent rows failed; they will re-send"
	}
	st.CommitPushedSnapshots()
	res.Envelopes++
	res.Rows += batch.RowCount()
	res.Bytes += len(raw)
	return true, nil
}
