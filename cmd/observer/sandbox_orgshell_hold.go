//go:build !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// sandbox_orgshell_hold.go is the node half of held boxes (g1-design.md
// sections 3.6 and 4.6, lane G4): `observer sandbox org-shell hold | resume |
// discard | fetch | held | hold-on-end`. The org server and its worker own
// every held box (stop, start, collect, delete); these verbs only ask, from
// any of the member's managed nodes.
//
// Resume (design 3.6) is a new launch: a new node run id and terminal_run
// row, a resume-purpose mint naming the held box (the server moves it to
// resuming and starts it), fresh relay secrets written into the box run dir
// by the relay's own start, and the agent continued through its native
// resume when its registry row has ResumeSpec.Kind == ResumeNative and the
// box's sessions.json names a session (otherwise a fresh session in the kept
// workspace, said so).

func init() {
	orgShellHoldSubcommands = append(orgShellHoldSubcommands,
		newOrgShellHoldCmd, newOrgShellResumeCmd, newOrgShellDiscardCmd, newOrgShellFetchCmd, newOrgShellHeldCmd, newOrgShellHoldOnEndCmd)
}

// orgShellResumeBox is the held box a resume launch in this process takes
// over ("" for a fresh box); the hosted Create reads it through the row's
// resumeBox hook.
var orgShellResumeBox atomic.Value

// orgShellResumeTarget is the resumeBox hook.
func orgShellResumeTarget() string {
	s, _ := orgShellResumeBox.Load().(string)
	return s
}

// orgShellRunArg is the one run-id argument of a verb (a safe id only).
func orgShellRunArg(args []string) (string, error) {
	if len(args) != 1 || args[0] == "" || len(args[0]) > 128 || strings.ContainsAny(args[0], "/ \t\r\n|") || strings.HasPrefix(args[0], "-") {
		return "", errors.New("name the run id (see `observer sandbox org-shell held`)")
	}
	return args[0], nil
}

// orgShellClientDo opens the org client for one verb.
func orgShellClientDo(ctx context.Context, f func(*orgclient.Client, config.Config) error) error {
	c, _, cfg, done, err := orgShellOrgClient(ctx)
	if err != nil {
		return err
	}
	defer done()
	return f(c, cfg)
}

func newOrgShellHoldCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hold <run>",
		Short: "Hold a live org sandbox run's box (stopped, kept) to resume it later from any of your managed machines",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			run, err := orgShellRunArg(args)
			if err != nil {
				return err
			}
			return orgShellClientDo(cmd.Context(), func(c *orgclient.Client, _ config.Config) error {
				held, err := c.OpenShellHoldBox(cmd.Context(), run)
				if err != nil {
					return err
				}
				id := orgShellHeldAs(run, held)
				fmt.Fprintf(cmd.OutOrStdout(), "Holding %s: your organization stops the box and keeps it; resume it with `observer sandbox org-shell resume %s`.\n", id, id)
				return nil
			})
		},
	}
}

// orgShellHeldAs is the id a hold's answer names the box under (lane FX6,
// F-P7-3): the organization's ledger key when it answered a well-formed
// one, else the id the member typed. Every hint names it, and every verb
// (hold, resume, discard, fetch) accepts it.
func orgShellHeldAs(asked, answered string) string {
	if id, err := orgShellRunArg([]string{answered}); err == nil {
		return id
	}
	return asked
}

func newOrgShellDiscardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "discard <run>",
		Short: "Delete a held box now (your organization collects its work first when it never came back)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			run, err := orgShellRunArg(args)
			if err != nil {
				return err
			}
			return orgShellClientDo(cmd.Context(), func(c *orgclient.Client, _ config.Config) error {
				if err := c.OpenShellDiscard(cmd.Context(), run); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Discard of %s requested.\n", run)
				return nil
			})
		},
	}
}

func newOrgShellHeldCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "held",
		Short: "List your own held org sandbox boxes (from any of your managed machines)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return orgShellClientDo(cmd.Context(), func(c *orgclient.Client, _ config.Config) error {
				held, err := c.OpenShellHeld(cmd.Context())
				if err != nil {
					return err
				}
				fmt.Fprint(cmd.OutOrStdout(), orgShellHeldText(held))
				return nil
			})
		},
	}
}

// orgShellHeldText renders the held list.
func orgShellHeldText(held []orgclient.OpenShellHeldBox) string {
	if len(held) == 0 {
		return "No held boxes.\n"
	}
	var b strings.Builder
	for _, h := range held {
		line := h.RunID + "  " + h.State
		if h.HeldSince != nil {
			line += "  held since " + h.HeldSince.Local().Format(time.RFC1123)
		}
		if h.ExpiresAt != nil {
			line += "  expires " + h.ExpiresAt.Local().Format(time.RFC1123)
		}
		line += fmt.Sprintf("  reason %s  resumed %d times  tier %s  source %s\n", h.Reason, h.ResumeCount, h.Tier, h.Source)
		b.WriteString(line)
	}
	return b.String()
}

func newOrgShellHoldOnEndCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hold-on-end on|off",
		Short: "Hold your org sandbox boxes when a run ends normally (honoured where your organization holds on end)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			on := args[0] == "on"
			if !on && args[0] != "off" {
				return errors.New("say on or off")
			}
			if err := orgShellSetKey("", func(o *config.TerminalSandboxHostedOrgShellConfig) { o.HoldOnEnd = on }); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "hold on end: %v\n", on)
			return nil
		},
	}
}

func newOrgShellFetchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fetch <run>",
		Short: "Fetch your own collected work of an org sandbox run (a diff and a bundle, saved here, never applied)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			run, err := orgShellRunArg(args)
			if err != nil {
				return err
			}
			return orgShellClientDo(cmd.Context(), func(c *orgclient.Client, cfg config.Config) error {
				col, err := c.OpenShellFetch(cmd.Context(), run)
				if errors.Is(err, orgclient.ErrOpenShellNothingCollected) {
					fmt.Fprintf(cmd.OutOrStdout(), "nothing was collected for run %s: its box had no changes to return\n", run)
					return nil
				}
				if err != nil {
					return err
				}
				paths, err := orgShellSaveCollect(filepath.Dir(cfg.Observer.DBPath), run, col)
				if err != nil {
					return err
				}
				for _, p := range paths {
					fmt.Fprintf(cmd.OutOrStdout(), "saved %s (not applied)\n", p)
				}
				return nil
			})
		},
	}
}

// orgShellSaveCollect checks a fetched collect's sizes and saves it under
// the hosted returns directory, owner-only (untrusted input, never applied).
func orgShellSaveCollect(observerDir, run string, col orgclient.OpenShellCollect) ([]string, error) {
	if err := workspace.CheckReturnSize(int64(len(col.Diff))); err != nil {
		return nil, fmt.Errorf("the collected diff: %w", err)
	}
	if err := workspace.CheckReturnSize(int64(len(col.Bundle))); err != nil {
		return nil, fmt.Errorf("the collected bundle: %w", err)
	}
	dir := filepath.Join(hostedStateDir(observerDir), "returns")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var out []string
	for _, f := range []struct {
		ext  string
		data []byte
	}{{".collected.diff", col.Diff}, {".collected.bundle", col.Bundle}} {
		if len(f.data) == 0 {
			continue
		}
		p := filepath.Join(dir, run+f.ext)
		if err := os.WriteFile(p, f.data, 0o600); err != nil {
			return out, err
		}
		out = append(out, p)
	}
	return out, nil
}

func newOrgShellResumeCmd() *cobra.Command {
	var tool string
	cmd := &cobra.Command{
		Use:   "resume <run>",
		Short: "Resume a held org sandbox box in this terminal, from any of your managed machines",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			run, err := orgShellRunArg(args)
			if err != nil {
				return err
			}
			verb, err := orgShellLaunchVerb(tool)
			if err != nil {
				return err
			}
			orgShellResumeBox.Store(run)
			defer orgShellResumeBox.Store("")
			code := runSandboxCLI(cmd.Context(), sandboxCLIRequest{Verb: verb, Tool: tool, Profile: sandboxbackend.BackendOpenShellOrg}, cmd.ErrOrStderr())
			if code != 0 {
				return fmt.Errorf("the resume launch exited %d", code)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&tool, "tool", "claude-code", "the agent tool the held run ran")
	return cmd
}

// orgShellLaunchVerb is a tool's observer launcher verb (the registry's
// handoff launch subcommand).
func orgShellLaunchVerb(tool string) (string, error) {
	spec, ok := integration.For(tool)
	if !ok || spec.Handoff.Launch == nil || spec.Handoff.Launch.Subcommand == "" {
		return "", fmt.Errorf("%s has no observer launcher", tool)
	}
	return spec.Handoff.Launch.Subcommand, nil
}

// orgShellResumeArgs is the agent's native resume tail for a held run
// (design 3.6 step 5): chosen by the tool's ResumeSpec capability, never by
// its name; nil means a fresh session in the kept workspace.
func orgShellResumeArgs(tool, sessionID string) []string {
	spec, ok := integration.For(tool)
	if !ok || spec.Resume.Kind != integration.ResumeNative || sessionID == "" {
		return nil
	}
	args, err := integration.ResumeArgs(spec.Resume, sessionID)
	if err != nil {
		return nil
	}
	return args
}
