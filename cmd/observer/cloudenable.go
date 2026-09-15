package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudenable.go is the value-upgrade plan's W2 one-shot on/off surface
// (docs/plans/cloud-intelligence-value-upgrade-plan-2026-09-14.md §2/§W2):
// `observer cloud enable` records the structural standing grant (through the
// same cloudRecordStandingGrant path `observer cloud consent grant` uses) and
// the developer's own recorded enrichment LEVEL/background choice
// (internal/store.CloudEnrichPolicy, migration 115); `observer cloud disable`
// reverses it, cancelling anything queued and never touching results already
// received or the sign-in itself.
//
// Neither command signs in or syncs — enable still requires a base URL (the
// standing grant binds it) exactly like `consent grant` does, but it makes no
// network call itself.

// newCloudEnableCmd builds `observer cloud enable`.
func newCloudEnableCmd() *cobra.Command {
	var (
		configPath           string
		evidenceSettingsJSON string
		baseURL              string
		timezone             string
		withExcerpts         bool
		noBackground         bool
		yes                  bool
		source               string
	)
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Turn on Cloud Intelligence: name and tag finished sessions in the background",
		Long: "Records the standing consent that lets background enrichment name and tag your\n" +
			"finished sessions automatically, plus your own choice of level (titles only, or\n" +
			"titles and short excerpts) and whether it runs unattended. Every send is still\n" +
			"listed in `observer cloud consent list` and the dashboard's What we sent ledger.\n" +
			"Turn it off any time with `observer cloud disable`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			resolved := resolveCloudBaseURL(baseURL, cfg)
			if resolved == "" {
				return fmt.Errorf("no cloud base URL — pass --base-url, set %s, or set [cloud].base_url in config.toml (the grant binds the upload endpoint)", cloudBaseURLEnv)
			}

			level := store.CloudEnrichTitles
			if withExcerpts {
				level = store.CloudEnrichExcerpts
			}
			background := !noBackground

			var evidenceSettings *store.CloudEvidenceSettings
			if cmd.Flags().Changed("evidence-settings") {
				evidenceSettings, err = store.ParseCloudEvidenceSettings(evidenceSettingsJSON)
				if err != nil {
					return fmt.Errorf("invalid evidence settings: %w", err)
				}
				if evidenceSettings == nil {
					return fmt.Errorf("invalid evidence settings: complete settings JSON is required")
				}
			} else {
				prior, _, err := st.GetCloudEnrichPolicy(cmd.Context())
				if err != nil {
					return err
				}
				evidenceSettings = prior.EvidenceSettings
			}
			if evidenceSettings != nil {
				effective := evidenceSettings.ForLevel(level)
				evidenceSettings = &effective
			}
			if evidenceSettings == nil {
				cloudPrintEnableExplanation(w, background, level)
			} else {
				cloudPrintConfiguredEnableExplanation(w, background, level, *evidenceSettings)
			}

			// The standing grant only ever authorizes the structural purpose —
			// bounded_context_enrichment (the excerpts level) is by design never
			// standing-grantable (shared facts: it always implies structural, but
			// excerpt content stays a per-session, explicitly-confirmed upload).
			live, err := cloudLiveStandingReceipts(cmd.Context(), st, cloudcontract.PurposeStructuralInsights)
			if err != nil {
				return err
			}
			if len(live) > 0 {
				fmt.Fprintf(w, "Standing consent for the daily activity summary is already recorded (receipt %s).\n",
					cloudShortReceiptID(live[0].ID))
				if !yes {
					accepted, err := cloudConfirm(cmd.InOrStdin(), w, "Turn on Cloud Intelligence with these settings?")
					if err != nil {
						return err
					}
					if !accepted {
						fmt.Fprintln(w, "Aborted — nothing changed.")
						return nil
					}
				}
			} else {
				accepted, err := cloudRecordStandingGrant(cmd.Context(), st, cfg, cloudcontract.PurposeStructuralInsights,
					baseURL, timezone, yes, cmd.InOrStdin(), w)
				if err != nil || !accepted {
					return err
				}
			}

			src := strings.TrimSpace(source)
			if src == "" {
				src = "cli"
			}
			if err := st.SetCloudEnrichPolicy(cmd.Context(), store.CloudEnrichPolicy{
				Level:            level,
				EvidenceSettings: evidenceSettings,
				Background:       background,
				PolicyVersion:    cloudcontract.ProviderPosturePolicyVersion,
				Source:           src,
			}); err != nil {
				return fmt.Errorf("record enrichment policy: %w", err)
			}

			bg := "off"
			if background {
				bg = "on"
			}
			fmt.Fprintf(w, "Cloud Intelligence is on: %s (background %s).\n", level, bg)
			return nil
		},
	}
	cmd.Flags().StringVar(&evidenceSettingsJSON, "evidence-settings", "", "Versioned JSON evidence limits (also editable in dashboard Settings)")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Cloud base URL (else $"+cloudBaseURLEnv+", else [cloud].base_url)")
	cmd.Flags().StringVar(&timezone, "timezone", "", "IANA timezone the day windows are defined in (default: this host's zone)")
	cmd.Flags().BoolVar(&withExcerpts, "with-excerpts", false, "Also send short scrubbed excerpts of your task and final summary per session")
	cmd.Flags().BoolVar(&noBackground, "no-background", false, "Do not enrich in the background — use `observer cloud consent` yourself per session")
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the interactive confirmation")
	cmd.Flags().StringVar(&source, "source", "cli", "Who is recording this (cli, dashboard, ...)")
	return cmd
}

// cloudPrintEnableExplanation prints the "Turning on Cloud Intelligence
// means:" disclosure block, in order: what runs in the background, what is
// sent per session at this level, the provider-retention disclosure, and
// where every send is listed.
func cloudPrintEnableExplanation(w io.Writer, background bool, level store.CloudEnrichLevel) {
	fmt.Fprintln(w, "Turning on Cloud Intelligence means:")
	bg := "off"
	if background {
		bg = "on"
	}
	fmt.Fprintf(w, "- after a session ends, it is named and tagged for you in the background (when background enrichment is on - it is %s here)\n", bg)
	if level == store.CloudEnrichExcerpts {
		fmt.Fprintln(w, "- what is sent per session: a structural summary, your first prompt, and short scrubbed excerpts of your task and final summary; plus a daily zero-content activity summary")
	} else {
		fmt.Fprintln(w, "- what is sent per session: a structural summary and your first prompt, nothing else; plus a daily zero-content activity summary")
	}
	fmt.Fprintf(w, "- %s (privacy policy v%s)\n", cloudcontract.ProviderPostureDisclosure, cloudcontract.ProviderPosturePolicyVersion)
	fmt.Fprintln(w, "Every send is listed in `observer cloud consent list` and on the dashboard's What we sent ledger; turn off any time with `observer cloud disable`.")
}

// newCloudDisableCmd builds `observer cloud disable`.
func newCloudDisableCmd() *cobra.Command {
	var (
		configPath string
		yes        bool
		source     string
	)
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Turn off Cloud Intelligence",
		Long: "Revokes the structural standing grant and cancels anything already queued for\n" +
			"background enrichment. Results already received stay on this device (and on\n" +
			"the server) until you delete your account with `observer cloud delete-account`.\n" +
			"Never signs you out.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			if !yes {
				ok, cerr := cloudConfirm(cmd.InOrStdin(), w,
					"Turn off Cloud Intelligence? Queued sessions are cancelled; results already received stay on this device and on the server until you delete your account.")
				if cerr != nil {
					return cerr
				}
				if !ok {
					fmt.Fprintln(w, "Aborted — nothing changed.")
					return nil
				}
			}

			existing, ok, gerr := st.GetCloudEnrichPolicy(cmd.Context())
			if gerr != nil {
				return fmt.Errorf("read enrichment policy: %w", gerr)
			}
			background := true
			if ok {
				background = existing.Background
			}
			src := strings.TrimSpace(source)
			if src == "" {
				src = "cli"
			}
			if err := st.SetCloudEnrichPolicy(cmd.Context(), store.CloudEnrichPolicy{
				Level:            store.CloudEnrichOff,
				EvidenceSettings: existing.EvidenceSettings,
				Background:       background,
				PolicyVersion:    cloudcontract.ProviderPosturePolicyVersion,
				Source:           src,
			}); err != nil {
				return fmt.Errorf("record enrichment policy: %w", err)
			}

			if err := cloudRevokeStanding(cmd.Context(), st, cloudcontract.PurposeStructuralInsights, w); err != nil {
				return err
			}

			n, err := st.CancelPendingCloudSessionEvidence(cmd.Context())
			if err != nil {
				return fmt.Errorf("cancel queued session enrichment: %w", err)
			}
			fmt.Fprintf(w, "Cancelled %d queued session enrichment job(s).\n", n)

			fmt.Fprintln(w, "Cloud Intelligence is off.")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the interactive confirmation")
	cmd.Flags().StringVar(&source, "source", "cli", "Who is recording this (cli, dashboard, ...)")
	return cmd
}
