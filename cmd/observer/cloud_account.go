//go:build !sbo_omit_cloud_intelligence

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// --- logout ----------------------------------------------------------------

func newCloudLogoutCmd() *cobra.Command {
	var (
		configPath string
		baseURL    string
		allHosts   bool
	)
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Revoke this device's server token and clear stored credentials",
		Long: "Signs this device out. It first asks the hosted service to revoke this\n" +
			"device's API token (D17) so a copy of the bearer stops working, then clears\n" +
			"the local credentials. The server call is BEST-EFFORT: if the base URL is\n" +
			"unset, no credential is stored, or the request fails, the local credentials\n" +
			"are still cleared and the command still succeeds. Local enrichment results\n" +
			"are always kept.\n\n" +
			"Credentials are stored per cloud host (the API token and the sign-in\n" +
			"material; one device key is shared): a plain logout signs out of the host\n" +
			"the base URL resolves to, and --all-hosts wipes every host's credentials\n" +
			"on this device (the device key included, so every host needs a fresh sign-in).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			gw, err := openCloudGateway(cfg, resolveCloudBaseURL(baseURL, cfg), "", nil, nil)
			if err != nil {
				return err
			}
			cloudLogoutBestEffort(cmd, gw)
			if allHosts {
				// The host-less gateway opens the legacy-shaped store, whose Clear is
				// the full local wipe (cloudcred: every host's scoped records, the
				// legacy records and the device key).
				all, aerr := openCloudGateway(cfg, "", "", nil, nil)
				if aerr != nil {
					return aerr
				}
				if err := all.ClearCredentials(); err != nil {
					return fmt.Errorf("clear credentials (all hosts): %w", err)
				}
				cloudResetResultCursor(cmd.Context(), cmd.OutOrStdout(), configPath, "", true)
				fmt.Fprintln(cmd.OutOrStdout(), "Logged out - credentials for every cloud host cleared. Local enrichment results are kept.")
				return nil
			}
			if err := gw.ClearCredentials(); err != nil {
				return fmt.Errorf("clear credentials: %w", err)
			}
			cloudResetResultCursor(cmd.Context(), cmd.OutOrStdout(), configPath, resolveCloudBaseURL(baseURL, cfg), false)
			fmt.Fprintln(cmd.OutOrStdout(), "Logged out - credentials cleared. Local enrichment results are kept.")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", cloudBaseURLFlagUsage("Cloud base URL for the server-side token revocation"))
	cmd.Flags().BoolVar(&allHosts, "all-hosts", false, "Also clear the credentials stored for every OTHER cloud host on this device (full local wipe)")
	return cmd
}

// cloudLogoutBestEffort attempts the server-side token revocation for `observer
// cloud logout` (D17). It NEVER returns an error and never blocks: signing out
// of your own machine must work offline, on a decommissioned endpoint, and after
// the token has already expired. Every outcome that isn't a clean revocation
// prints exactly one line and the caller proceeds to clear local state.
//
// Two preconditions decide whether a request is attempted at all — a resolvable
// base URL and a stored API token — so a node that was never signed in makes no
// network call (the manual-only/zero-egress posture: nothing outbound without
// something to revoke).
func cloudLogoutBestEffort(cmd *cobra.Command, gw *cloudgateway.Gateway) {
	w := cmd.OutOrStdout()
	if !gw.Configured() {
		return // never signed in against a known endpoint; nothing to revoke
	}
	if !gw.APITokenPresent() {
		return // no stored token ⇒ nothing to revoke, and no request to make
	}
	// BOOTSTRAP lane: revoking your own device token is an account/device
	// operation, authorized by the same sign-in action that minted it.
	if err := gw.BootstrapLogout(cmd.Context()); err != nil {
		fmt.Fprintf(w, "Warning: server-side token revocation failed (%v). Clearing local credentials anyway; the token expires on its own.\n", err)
		return
	}
	fmt.Fprintln(w, "Server-side device token revoked.")
}

// --- delete-account --------------------------------------------------------

func newCloudDeleteAccountCmd() *cobra.Command {
	var (
		configPath string
		baseURL    string
		localOnly  bool
		yes        bool
	)
	cmd := &cobra.Command{
		Use:   "delete-account",
		Short: "Request hosted account deletion (or --local-only to clear just this device)",
		Long: "Requests server-side deletion of the signed-in account via the hosted\n" +
			"deletion endpoint (authenticated by the stored device token - run\n" +
			"`observer cloud login` first). Requires explicit confirmation unless\n" +
			"--yes. Use --local-only to skip the server and only clear this device's\n" +
			"local credentials.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			if localOnly {
				gw, gerr := openCloudGateway(cfg, "", "", nil, nil)
				if gerr != nil {
					return gerr
				}
				if err := gw.ClearCredentials(); err != nil {
					return fmt.Errorf("clear credentials: %w", err)
				}
				// The host-less gateway's Clear is the full local wipe, so every
				// host's results cursor goes with it (T-962).
				cloudResetResultCursor(cmd.Context(), w, configPath, "", true)
				fmt.Fprintln(w, "Local credentials cleared. No server request was made (--local-only).")
				return nil
			}

			resolved := resolveCloudBaseURL(baseURL, cfg)
			if resolved == "" {
				return fmt.Errorf("no cloud base URL - pass --base-url, set %s, or set [cloud].base_url in config.toml (or --local-only to clear just this device)", cloudBaseURLEnv)
			}
			if !yes {
				ok, cerr := cloudConfirm(cmd.InOrStdin(), w,
					"Request PERMANENT server-side deletion of your cloud account and all its evidence/results?")
				if cerr != nil {
					return cerr
				}
				if !ok {
					fmt.Fprintln(w, "Aborted - no deletion requested.")
					return nil
				}
			}
			gw, err := openCloudGateway(cfg, resolved, "", nil, nil)
			if err != nil {
				return err
			}
			// BOOTSTRAP lane: deleting the account you signed into is an
			// account/device operation and sends no session-derived data.
			resp, err := gw.BootstrapRequestDeletion(cmd.Context())
			if err != nil {
				return fmt.Errorf("request account deletion: %w", err)
			}
			// The deleted account's sequence will never be pulled again; a later
			// account on this host starts its own from the beginning (T-962).
			cloudResetResultCursor(cmd.Context(), w, configPath, resolved, false)
			fmt.Fprintf(w, "Server-side deletion requested (request %s, state %q).\n", resp.ID, resp.State)
			fmt.Fprintln(w, "Run `observer cloud delete-account --local-only` to also clear this device's credentials.")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", cloudBaseURLFlagUsage("Cloud base URL"))
	cmd.Flags().BoolVar(&localOnly, "local-only", false, "Clear only this device's local credentials (no server call)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the interactive confirmation")
	return cmd
}
