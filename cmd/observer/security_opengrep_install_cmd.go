//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/secengine"
)

// security_opengrep_install_cmd.go is the CLI half of the guided install
// and the content refresh: `observer security code install` (the plan, the
// size consent, then the install, through installEngine, the seam the
// dashboard dialog also calls) and `observer security code refresh`.

func newCodeGuidedInstallCmd() *cobra.Command {
	var yes, planOnly bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install the pinned Opengrep for the code rules (individual node: after your one-time size consent; managed node: from the org mirror only)",
		Long: "Shows what the install fetches (the pinned version, its sha256, the download and the\n" +
			"unpacked tree's size, the host) and, on an individual node, asks once before anything is\n" +
			"downloaded; a new pin asks again. A managed node installs only from its org mirror and asks\n" +
			"nothing. The download is checked against the pin, then secengine's decision table, before it\n" +
			"is renamed into place. --plan prints the plan and writes nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			e, err := openCodeEnv(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer e.cleanup()
			return runCodeInstall(cmd.Context(), cmd.OutOrStdout(), cmd.InOrStdin(), e, yes, planOnly, term.IsTerminal(int(os.Stdin.Fd())))
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "give the size consent without asking (you read the plan above)")
	cmd.Flags().BoolVar(&planOnly, "plan", false, "print the plan only; download and write nothing")
	return cmd
}

// writeCodePlan prints a plan.
func writeCodePlan(w io.Writer, p secengine.InstallPlan, managed bool) {
	if p.Blocked != "" {
		fmt.Fprintln(w, "install: blocked:", codeBlockedWords(p.Blocked))
		return
	}
	fmt.Fprintf(w, "engine: Opengrep %s for %s/%s (pin from %s)\n", p.Pin.Version, p.Pin.OS, p.Pin.Arch, p.PinFrom)
	fmt.Fprintf(w, "sha256: %s\n", p.Pin.SHA256)
	fmt.Fprintf(w, "download: %s from %s\n", secengine.MB(p.DownloadBytes), map[bool]string{true: "the org mirror", false: p.URL}[managed])
	tree := secengine.MB(p.TreeBytes)
	if p.TreeFiles > 0 {
		tree += fmt.Sprintf(", %d files", p.TreeFiles)
	}
	fmt.Fprintf(w, "unpacked on first run: %s\n", tree)
	if p.Installed {
		fmt.Fprintln(w, "installed: yes, this pin is already at", codeInstalledPath())
	}
}

func runCodeInstall(ctx context.Context, w io.Writer, in io.Reader, e *codeEnv, yes, planOnly, isTerminal bool) error {
	p := secengine.PlanInstall(e.installInput(ctx))
	writeCodePlan(w, p, e.managed)
	if planOnly || p.Installed {
		return nil
	}
	if e.managed {
		fmt.Fprintln(w, "Managed node: installing from the org mirror (never the public release).")
		got, err := e.installEngine(ctx, codeSurfaceCLI, false)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "Installed Opengrep %s at %s.\n", got.Pin.Version, codeInstalledPath())
		return nil
	}
	if p.Blocked != "" {
		return errors.New("nothing was installed")
	}
	consent := readCodeInstallConsent(e.secDir).Covers(p)
	if !consent {
		fmt.Fprintln(w)
		fmt.Fprintln(w, secengine.ConsentText(p))
		if !yes && isTerminal {
			fmt.Fprintf(w, "\nDownload %s now and install it? [y/N] ", secengine.MB(p.DownloadBytes))
			yes = readYes(in)
		}
		if !yes {
			fmt.Fprintln(w, "\nNothing downloaded. Install from the dashboard's Code security page (Code rules card), or re-run with --yes.")
			return nil
		}
	}
	got, err := e.installEngine(ctx, codeSurfaceCLI, true)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "\nInstalled Opengrep %s at %s (sha256 checked against the pin, then verified).\n", got.Pin.Version, codeInstalledPath())
	return nil
}

// readYes reads one y or yes line.
func readYes(r io.Reader) bool {
	line, _ := bufio.NewReader(io.LimitReader(r, 64)).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func newCodeRefreshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "Fetch the signed rule pack and engine pins now (the vendor feed on an individual node, the org mirror on a managed one)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			e, err := openCodeEnv(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer e.cleanup()
			rep := e.refreshCodeContent(cmd.Context())
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "source: %s\nrule pack: %s\nengine: %s\n", rep.Source, rep.Pack, rep.Engine)
			fmt.Fprintf(w, "in use: %s %s (%s)\n", e.pack.Pack.Manifest.ID, e.pack.Pack.Version(), e.pack.Source)
			if e.pack.Note != "" {
				fmt.Fprintln(w, "note:", e.pack.Note)
			}
			return rep.Err
		},
	}
}
