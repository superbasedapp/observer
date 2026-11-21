package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/shiptoken"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudsession_token.go is `observer cloud-session token mint|list|revoke`:
// the node-minted, per-cloud-environment ship tokens (decision CA-D18) from
// the terminal, beside the dashboard's owner-local routes. One token serves
// one cloud environment for both of the node's cloud destinations: the Rail
// S flush (POST /api/cloud-session/ingest) and the Rail T OTLP exporter
// (the receiver accepts it in the receiver token header, CLOUDTEL-1). The
// rules are the store's MintCloudSessionShipToken, shared with the
// dashboard, so the two surfaces cannot drift.
//
// The secret is printed exactly once, by mint, and only to stdout; list and
// revoke never print it.

func newCloudSessionTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Mint, list or revoke this node's per-environment cloud-session ship tokens",
		Long: "A ship token lets ONE cloud environment send its sandbox capture\n" +
			"(observer cloud-session flush --destination node) and its OTLP telemetry\n" +
			"to this node, and nothing else. It is labelled with the environment,\n" +
			"expires on its own (8 hours by default, a week at most) and can be revoked\n" +
			"alone. Store it as that environment's secret, never in the repository.",
	}
	cmd.AddCommand(newCloudSessionTokenMintCmd(), newCloudSessionTokenListCmd(), newCloudSessionTokenRevokeCmd())
	return cmd
}

func newCloudSessionTokenMintCmd() *cobra.Command {
	var configPath string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "mint <environment label>",
		Short: "Mint a ship token for one cloud environment (the secret is shown once)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			m, err := store.New(database).MintCloudSessionShipToken(cmd.Context(), rand.Reader, args[0], ttl, time.Now().UTC())
			var held store.ShipTokenEnvironmentHeldError
			switch {
			case errors.Is(err, store.ErrShipTokenBadLabel), errors.As(err, &held), errors.Is(err, store.ErrShipTokenTooMany):
				return err
			case err != nil:
				return fmt.Errorf("mint: %w", err)
			}
			printMintedShipToken(cmd.OutOrStdout(), m)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to observer config.toml")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, fmt.Sprintf("lifetime (default %s, %s to %s)", shiptoken.DefaultLifetime, shiptoken.MinLifetime, shiptoken.MaxLifetime))
	return cmd
}

// printMintedShipToken prints the one-time secret and where it goes.
func printMintedShipToken(out io.Writer, m store.MintedCloudSessionShipToken) {
	fmt.Fprintf(out, "ship token for cloud environment %q (%s), expires %s:\n\n", m.Token.Label, m.Token.TokenID, m.Token.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintln(out, "  "+m.Secret)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Shown once. Store it as a secret of that one cloud environment, never in the repository:")
	fmt.Fprintln(out, "  Rail S (sandbox capture): "+envCloudSessionToken+" for `observer cloud-session flush --destination node`; the node receives full content by default (`init --destination node` bakes --share "+string(cloudsession.ShareFullContent)+")")
	fmt.Fprintln(out, "  Rail T (telemetry): the receiver token header value in OTEL_EXPORTER_OTLP_HEADERS (observer init --otlp-cloud-endpoint)")
	fmt.Fprintln(out, "Revoke it alone with `observer cloud-session token revoke "+m.Token.TokenID+"`.")
}

func newCloudSessionTokenListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List this node's ship tokens (never the secrets)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			ts, err := store.New(database).ListCloudSessionShipTokens(cmd.Context())
			if err != nil {
				return err
			}
			printShipTokenList(cmd.OutOrStdout(), ts, time.Now().UTC())
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to observer config.toml")
	return cmd
}

// printShipTokenList prints one row per token with its visible expiry.
func printShipTokenList(out io.Writer, ts []store.CloudSessionShipToken, now time.Time) {
	if len(ts) == 0 {
		fmt.Fprintln(out, "no ship tokens; mint one per cloud environment with `observer cloud-session token mint <environment>`")
		return
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TOKEN\tENVIRONMENT\tSTATUS\tEXPIRES\tLEFT\tUSES")
	for _, t := range ts {
		left := "-"
		if t.Status(now) == shiptoken.StatusActive {
			left = t.ExpiresAt.Sub(now).Truncate(time.Minute).String()
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n", t.TokenID, t.Label, t.Status(now), t.ExpiresAt.Format(time.RFC3339), left, t.UseCount)
	}
	_ = tw.Flush()
}

func newCloudSessionTokenRevokeCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "revoke <token-id>",
		Short: "Revoke one ship token (its environment stops reaching this node)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !shiptoken.ValidID(args[0]) {
				return fmt.Errorf("%q is not a ship token id (cst_...)", args[0])
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			ok, err := store.New(database).RevokeCloudSessionShipToken(cmd.Context(), args[0], time.Now().UTC())
			if errors.Is(err, store.ErrShipTokenNotFound) {
				return fmt.Errorf("no ship token %s on this node", args[0])
			}
			if err != nil {
				return err
			}
			if !ok {
				fmt.Fprintf(cmd.OutOrStdout(), "%s was already revoked\n", args[0])
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "revoked %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to observer config.toml")
	return cmd
}
