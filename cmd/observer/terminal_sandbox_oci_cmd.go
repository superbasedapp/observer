//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// terminal_sandbox_oci_cmd.go is `observer sandbox oci`: the two user
// commands of the container driver. `pull` asks the engine to fetch the
// configured image (the ENGINE fetches it; this process only talks to the
// local socket, and only on this explicit command); `forget-engine` drops
// the engine identity recorded at first use, after the user checked a
// daemon that changed (section 4.6, A9).

func init() { sandboxSubcommands = append(sandboxSubcommands, newSandboxOCICmd) }

func newSandboxOCICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oci",
		Short: "Container sandboxes (Docker, Podman): pull the image, forget a recorded engine",
	}
	cmd.AddCommand(newSandboxOCIPullCmd(), newSandboxOCIForgetCmd(), newSandboxOCIDevcontainerCmd(), newSandboxOCIImageCmd())
	return cmd
}

// ociCLIConfig loads the config and refuses when the driver is not
// selected; it returns the effective [terminal.sandbox] block.
func ociCLIConfig(ctx context.Context, cfgPath string) (config.Config, config.TerminalSandboxConfig, error) {
	cfg, gov, err := config.LoadGovernance(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		return cfg, config.TerminalSandboxConfig{}, fmt.Errorf("load config: %w", err)
	}
	if !sandboxDriverSelected(componentSnapshotForConfig(cfg), ociComponent) {
		return cfg, config.TerminalSandboxConfig{}, fmt.Errorf("the %s component is not selected on this node; add it in Settings > Components (or [components] add = [%q])", ociComponent, ociComponent)
	}
	return cfg, cliEffectiveSandboxConfig(ctx, cfg, gov.PinsInForce), nil
}

func newSandboxOCIPullCmd() *cobra.Command {
	var (
		cfgPath      string
		devcontainer bool
	)
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Ask the local engine to pull [terminal.sandbox.oci].image, or Observer's verified default image (the engine fetches it)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, sb, err := ociCLIConfig(ctx, cfgPath)
			if err != nil {
				return fmt.Errorf("sandbox oci pull: %w", err)
			}
			observerDir := sandboxObserverDirFor(cfg)
			res := sandboxoci.Probe(ociProbeEnvFn(ctx, sb.OCI, observerDir))
			if !res.Verdict.OK() && res.Rule != "P11 image present" {
				return fmt.Errorf("sandbox oci pull: %s", res.Verdict.Error())
			}
			if res.FirstUse {
				if err := recordOCIIdentity(observerDir, res.Socket, res.Identity); err != nil {
					return fmt.Errorf("sandbox oci pull: record the engine identity: %w", err)
				}
			}
			c, err := sandboxengine.New(res.Socket)
			if err == nil {
				err = c.SetAPIVersion(res.Identity.APIVersion)
			}
			if err != nil {
				return fmt.Errorf("sandbox oci pull: %w", err)
			}
			trust := ociResolveImageFn(sb.OCI, observerDir)
			image := trust.image
			if trust.desc != nil && !devcontainer {
				// Observer's default image: by digest, read back and
				// recorded, as `observer sandbox oci image pull` does.
				if _, _, err := ociPullDefault(ctx, c, trust, observerDir, func(l string) { fmt.Fprintln(cmd.OutOrStdout(), l) }); err != nil {
					return fmt.Errorf("sandbox oci pull: %w", err)
				}
				return nil
			}
			if devcontainer {
				repo, err := ociRepoRoot("")
				if err != nil {
					return fmt.Errorf("sandbox oci pull: %w", err)
				}
				dc, ok, err := readDevcontainer(repo)
				if err != nil || !ok || dc.Image == "" {
					return fmt.Errorf("sandbox oci pull: %s has no .devcontainer image pinned by digest (%s): %w", repo, dc.ImageRefused, err)
				}
				if devcontainerConsents(observerDir)[repo] != dc.Image {
					return fmt.Errorf("sandbox oci pull: accept the .devcontainer image first: observer sandbox oci devcontainer accept")
				}
				image = dc.Image
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Asking the %s %s engine on %s to pull %s ...\n", res.Identity.Mode, res.Identity.Engine, res.Socket, image)
			pctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
			defer cancel()
			if err := c.ImagePull(pctx, image); err != nil {
				v := sandboxoci.PullFailure(ociHost(), res.Identity.Mode, err.Error())
				return fmt.Errorf("sandbox oci pull: %s", v.Error())
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Pulled.")
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "path to config.toml")
	cmd.Flags().BoolVar(&devcontainer, "devcontainer", false, "pull this repository's consented .devcontainer image instead")
	return cmd
}

// ociRepoRoot is the repository a devcontainer command acts on: --repo, or
// the git root of the working directory, symlinks resolved.
func ociRepoRoot(flag string) (string, error) {
	dir := flag
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = wd
	}
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil { //nolint:gosec // G703: a metadata read of the user's own local path; no privilege boundary is crossed
			return d, nil
		}
		if filepath.Dir(d) == d {
			return dir, nil
		}
	}
}

func newSandboxOCIDevcontainerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "devcontainer",
		Short: "Consent to (or revoke) a repository's .devcontainer image for container sandboxes",
	}
	var cfgPath, repoFlag string
	show := func(w io.Writer, repo string, dc sandboxoci.Devcontainer) {
		fmt.Fprintf(w, "Repository: %s\nImage: %s\n", repo, dc.Image)
		if len(dc.Env) > 0 {
			fmt.Fprintf(w, "Environment it sets: %s\n", strings.Join(dc.Env, " "))
		}
		if len(dc.DroppedEnv) > 0 {
			fmt.Fprintf(w, "Environment refused (Observer-owned or unsafe names): %s\n", strings.Join(dc.DroppedEnv, ", "))
		}
		if len(dc.Ignored) > 0 {
			fmt.Fprintf(w, "Ignored (never run, never honoured): %s\n", strings.Join(dc.Ignored, ", "))
		}
		fmt.Fprintln(w, "A sandboxed run of this repository then starts from this image, with your tool's own settings and sign-in bound into it.")
	}
	accept := &cobra.Command{
		Use:   "accept",
		Short: "Use this repository's .devcontainer image (by digest) for its container sandboxes",
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, sb, err := ociCLIConfig(c.Context(), cfgPath)
			if err != nil {
				return fmt.Errorf("sandbox oci devcontainer accept: %w", err)
			}
			if !sb.OCI.AllowDevcontainerImage {
				return fmt.Errorf("sandbox oci devcontainer accept: [terminal.sandbox.oci].allow_devcontainer_image is false")
			}
			repo, err := ociRepoRoot(repoFlag)
			if err != nil {
				return fmt.Errorf("sandbox oci devcontainer accept: %w", err)
			}
			dc, ok, err := readDevcontainer(repo)
			if err != nil || !ok {
				return fmt.Errorf("sandbox oci devcontainer accept: no readable .devcontainer/devcontainer.json in %s: %w", repo, err)
			}
			if dc.Image == "" {
				return fmt.Errorf("sandbox oci devcontainer accept: %s", dc.ImageRefused)
			}
			show(c.OutOrStdout(), repo, dc)
			if err := setDevcontainerConsent(sandboxObserverDirFor(cfg), repo, dc.Image); err != nil {
				return fmt.Errorf("sandbox oci devcontainer accept: %w", err)
			}
			fmt.Fprintln(c.OutOrStdout(), "Accepted for this repository and this digest only; a changed image asks again.")
			return nil
		},
	}
	revoke := &cobra.Command{
		Use:   "revoke",
		Short: "Stop using this repository's .devcontainer image",
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, _, err := ociCLIConfig(c.Context(), cfgPath)
			if err != nil {
				return fmt.Errorf("sandbox oci devcontainer revoke: %w", err)
			}
			repo, err := ociRepoRoot(repoFlag)
			if err != nil {
				return fmt.Errorf("sandbox oci devcontainer revoke: %w", err)
			}
			if err := setDevcontainerConsent(sandboxObserverDirFor(cfg), repo, ""); err != nil {
				return fmt.Errorf("sandbox oci devcontainer revoke: %w", err)
			}
			fmt.Fprintf(c.OutOrStdout(), "Revoked for %s.\n", repo)
			return nil
		},
	}
	for _, sub := range []*cobra.Command{accept, revoke} {
		sub.Flags().StringVar(&cfgPath, "config", "", "path to config.toml")
		sub.Flags().StringVar(&repoFlag, "repo", "", "the repository (default: the git root of the working directory)")
	}
	cmd.AddCommand(accept, revoke)
	return cmd
}

func newSandboxOCIForgetCmd() *cobra.Command {
	var (
		cfgPath string
		socket  string
	)
	cmd := &cobra.Command{
		Use:   "forget-engine",
		Short: "Forget the engine identity recorded for a socket (after checking a daemon that changed)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, sb, err := ociCLIConfig(cmd.Context(), cfgPath)
			if err != nil {
				return fmt.Errorf("sandbox oci forget-engine: %w", err)
			}
			if socket == "" {
				env := ociProbeEnvFn(cmd.Context(), sb.OCI, sandboxObserverDirFor(cfg))
				p, v := sandboxoci.ResolveEndpoint(sb.OCI.Socket, env.Endpoint)
				if !v.OK() {
					return fmt.Errorf("sandbox oci forget-engine: %s", v.Error())
				}
				socket = p
			}
			if err := forgetOCIIdentity(sandboxObserverDirFor(cfg), socket); err != nil {
				return fmt.Errorf("sandbox oci forget-engine: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Forgot the engine recorded for %s; the next probe records the daemon it finds there.\n", socket)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&socket, "socket", "", "the socket path (default: the one the driver would use)")
	return cmd
}

// ociCLIEngine probes the engine for the image verbs and returns a client
// and the install id.
func ociCLIEngine(ctx context.Context, cfgPath string) (*sandboxengine.Client, string, config.TerminalSandboxOCIConfig, string, error) {
	cfg, sb, err := ociCLIConfig(ctx, cfgPath)
	if err != nil {
		return nil, "", sb.OCI, "", err
	}
	observerDir := sandboxObserverDirFor(cfg)
	res := sandboxoci.Probe(ociProbeEnvFn(ctx, sb.OCI, observerDir))
	if !res.Verdict.OK() && res.Rule != "P11 image present" {
		return nil, "", sb.OCI, "", fmt.Errorf("%s", res.Verdict.Error())
	}
	if res.FirstUse {
		if err := recordOCIIdentity(observerDir, res.Socket, res.Identity); err != nil {
			return nil, "", sb.OCI, "", fmt.Errorf("record the engine identity: %w", err)
		}
	}
	c, err := ociEngineClient(res.Socket, res.Identity.APIVersion)
	if err != nil {
		return nil, "", sb.OCI, "", err
	}
	id, err := ociInstallID(observerDir)
	return c, observerDir, sb.OCI, id, err
}

// newSandboxOCIImageCmd is `observer sandbox oci image pull|prune`:
// Observer's default image on this machine (lane SBX-P3C). Both verbs act
// only under a signed sandbox.image manifest.
func newSandboxOCIImageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Observer's default container image: pull it by digest, remove a revoked one",
	}
	var cfgPath string
	pull := &cobra.Command{
		Use:   "pull",
		Short: "Pull Observer's default image by its signed digest (the engine fetches it), read it back and record it",
		RunE: func(c *cobra.Command, _ []string) error {
			cl, observerDir, oci, _, err := ociCLIEngine(c.Context(), cfgPath)
			if err != nil {
				return fmt.Errorf("sandbox oci image pull: %w", err)
			}
			if oci.Image != "" {
				return fmt.Errorf("sandbox oci image pull: [terminal.sandbox.oci].image is set to your own image %s; Observer's default image is used only when it is empty", oci.Image)
			}
			if _, _, err := ociPullDefault(c.Context(), cl, ociResolveImageFn(oci, observerDir), observerDir, func(l string) { fmt.Fprintln(c.OutOrStdout(), l) }); err != nil {
				return fmt.Errorf("sandbox oci image pull: %w", err)
			}
			return nil
		},
	}
	prune := &cobra.Command{
		Use:   "prune",
		Short: "Remove the images Observer pulled that the signed manifest revokes, and their tool caches",
		RunE: func(c *cobra.Command, _ []string) error {
			cl, observerDir, oci, installID, err := ociCLIEngine(c.Context(), cfgPath)
			if err != nil {
				return fmt.Errorf("sandbox oci image prune: %w", err)
			}
			trust := ociResolveImageFn(oci, observerDir)
			if trust.revoked == nil {
				fmt.Fprintln(c.OutOrStdout(), "No signed sandbox.image manifest is installed; nothing is revoked.")
				return nil
			}
			res, err := ociPruneRevoked(c.Context(), cl, observerDir, installID, trust.revoked)
			w := c.OutOrStdout()
			for _, r := range res.Removed {
				fmt.Fprintf(w, "Removed the revoked image %s.\n", r)
			}
			for _, v := range res.Caches {
				fmt.Fprintf(w, "Removed the tool cache %s of a revoked image.\n", v)
			}
			for _, r := range res.Refused {
				fmt.Fprintf(w, "Not removed: %s\n", r)
			}
			if len(res.Removed)+len(res.Caches)+len(res.Refused) == 0 {
				fmt.Fprintln(w, "Nothing Observer pulled is revoked.")
			}
			if err != nil {
				return fmt.Errorf("sandbox oci image prune: %w", err)
			}
			return nil
		},
	}
	for _, sub := range []*cobra.Command{pull, prune} {
		sub.Flags().StringVar(&cfgPath, "config", "", "path to config.toml")
	}
	cmd.AddCommand(pull, prune)
	return cmd
}
