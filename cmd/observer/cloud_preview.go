//go:build !sbo_omit_cloud_intelligence

package main

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// --- preview ---------------------------------------------------------------

func newCloudPreviewCmd() *cobra.Command {
	var (
		configPath string
		receiptID  string
		sessionID  string
		purpose    string
	)
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Show the LITERAL bytes and digests that would upload for a session",
		Long: "Builds the evidence envelope for a session and prints the exact bytes\n" +
			"that would upload (what you see is what uploads), both digests, and a\n" +
			"content-free summary. No network. Refuses org / unknown sessions.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if sessionID == "" {
				return errors.New("--session is required")
			}
			p, err := parseCloudPurpose(purpose)
			if err != nil {
				return err
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			var res cloudEnvelopeResult
			pricer := acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default())
			if receiptID != "" {
				res, err = cloudReceiptPreview(cmd.Context(), st, receiptID, sessionID, p, pricer)
			} else {
				res, err = buildCloudEnvelope(cmd.Context(), st, sessionID, p, pricer)
			}
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s\n", res.Bytes)
			fmt.Fprintln(w, "----")
			fmt.Fprintf(w, "purpose:                %s\n", res.Purpose)
			fmt.Fprintf(w, "evidence-content digest: %s\n", res.Digests.EvidenceContent)
			fmt.Fprintf(w, "upload digest:           %s\n", res.Digests.Upload)
			fmt.Fprintf(w, "actions:                 %d\n", res.Actions)
			fmt.Fprintf(w, "context excerpts:        %d\n", res.Excerpts)
			fmt.Fprintf(w, "upload size:             %d bytes\n", len(res.Bytes))
			cloudPrintEnvelopeSummary(w, res)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&receiptID, "receipt-id", "", "Use the selection settings frozen on this receipt")
	cmd.Flags().StringVar(&sessionID, "session", "", "Local session id to preview")
	cmd.Flags().StringVar(&purpose, "purpose", string(cloudcontract.PurposeStructuralInsights), "Consent purpose to build under")
	return cmd
}

// --- consent ---------------------------------------------------------------

func newCloudConsentCmd() *cobra.Command {
	var (
		configPath           string
		baseURL              string
		sessionID            string
		purpose              string
		yes                  bool
		backgroundGeneration int64
		expectedUploadDigest string
	)
	cmd := &cobra.Command{
		Use:   "consent",
		Short: "Confirm a preview, record a consent receipt, and enqueue for sync",
		Long: "Per-session consent: builds the envelope for one session, shows its digests,\n" +
			"records a receipt binding those exact bytes, and enqueues it.\n\n" +
			"Standing grants - which authorize a SCHEMA rather than one upload - are managed\n" +
			"by the subcommands: `grant`, `revoke`, and `list`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if sessionID == "" {
				return errors.New("--session is required")
			}
			p, err := parseCloudPurpose(purpose)
			if err != nil {
				return err
			}
			// The same table the egress seam gates on decides this, so the CLI
			// can never record a receipt whose upload the gateway would refuse:
			// the refusal happens HERE, with honest copy, instead of at the far
			// end of a sync the developer thought they had authorized.
			if ok, reason := cloudgateway.EvidenceUploadable(p); !ok {
				return fmt.Errorf("%q cannot authorize a session upload: %s", string(p), reason)
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			if cmd.Flags().Changed("background-generation") {
				if err := st.CheckCloudBackgroundPolicy(cmd.Context(), backgroundGeneration, string(p)); err != nil {
					return err
				}
			}

			resolved := resolveCloudBaseURL(baseURL, cfg)
			if resolved == "" {
				return fmt.Errorf("no cloud base URL - pass --base-url, set %s, or set [cloud].base_url in config.toml (the receipt binds the upload endpoint)", cloudBaseURLEnv)
			}

			// Device thumbprint is the node-local account pseudonym bound on the
			// receipt (no cloud account exists until exchange). No network call.
			gw, err := openCloudGateway(cfg, resolved, "", st, nil)
			if err != nil {
				return err
			}
			thumbprint, err := gw.DeviceThumbprint()
			if err != nil {
				return err
			}

			res, err := buildCloudEnvelopeConfigured(cmd.Context(), st, sessionID, p, acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default()), backgroundGeneration)
			if err != nil {
				return err
			}
			if expectedUploadDigest != "" && expectedUploadDigest != res.Digests.Upload {
				return errors.New("the evidence or settings changed since preview; preview again before confirming")
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Session %s - purpose %s\n", sessionID, p)
			fmt.Fprintf(w, "  evidence-content digest: %s\n", res.Digests.EvidenceContent)
			fmt.Fprintf(w, "  upload digest:           %s\n", res.Digests.Upload)
			fmt.Fprintf(w, "  upload size:             %d bytes (%d actions)\n", len(res.Bytes), res.Actions)
			// Consent is the moment the developer authorizes these exact bytes,
			// so it shows the same excerpt-by-excerpt disclosure preview does.
			cloudPrintEnvelopeSummary(w, res)

			// Idempotency (review 2026-09-15): the auto-enrich sweep and a
			// manual "Enrich now" can both reach here for one session. If these
			// exact bytes are already in flight, report that job and mint
			// nothing - one enrichment must never cost two quota units or show
			// twice on the ledger.
			if existing, found, ferr := st.FindLiveCloudOutboxForUpload(cmd.Context(), sessionID, res.Digests.Upload); ferr != nil {
				return ferr
			} else if found {
				fmt.Fprintf(w, "Already queued as job %s (identical bytes, state %s); nothing new recorded. Run `observer cloud sync` to send.\n", existing.ID, existing.State)
				return nil
			}

			if !yes {
				ok, cerr := cloudConfirm(cmd.InOrStdin(), w, "Record consent and enqueue this session for sync?")
				if cerr != nil {
					return cerr
				}
				if !ok {
					fmt.Fprintln(w, "Aborted - nothing recorded.")
					return nil
				}
			}

			receiptID, err := st.InsertCloudConsentReceipt(cmd.Context(), store.CloudConsentReceipt{
				AccountPseudonym:       thumbprint,
				BackgroundGeneration:   backgroundGeneration,
				DeviceLabelRef:         thumbprint,
				Purpose:                string(p),
				FieldClassesJSON:       cloudFieldClassesJSON(p),
				EvidenceSettingsJSON:   res.EvidenceSettingsJSON,
				EnvelopeSchemaVersion:  cloudcontract.EnvelopeSchemaVersion,
				ScrubberVersion:        cloudScrubberVersion,
				Endpoint:               resolved + "/v1/jobs",
				RetentionPolicyVersion: cloudRetentionPolicyVersion,
				UploadDigest:           res.Digests.Upload,
			})
			if err != nil {
				return fmt.Errorf("record consent receipt: %w", err)
			}
			jobID, err := st.EnqueueCloudOutbox(cmd.Context(), store.CloudOutboxItem{
				SessionID:             sessionID,
				FeatureSetJSON:        cloudFeatureSetJSON(),
				EvidenceContentDigest: res.Digests.EvidenceContent,
				UploadDigest:          res.Digests.Upload,
				ReceiptID:             receiptID,
			})
			if errors.Is(err, store.ErrCloudOutboxDuplicate) {
				// Lost the race to a concurrent consent for the same bytes:
				// the receipt just minted binds nothing, so retire it and
				// point at the job that carries the upload.
				if ierr := st.InvalidateCloudConsentReceipt(cmd.Context(), receiptID); ierr != nil {
					return fmt.Errorf("enqueue: %w (and retiring the unused receipt failed: %w)", err, ierr)
				}
				if existing, found, ferr := st.FindLiveCloudOutboxForUpload(cmd.Context(), sessionID, res.Digests.Upload); ferr == nil && found {
					fmt.Fprintf(w, "Already queued as job %s (identical bytes, state %s); nothing new recorded. Run `observer cloud sync` to send.\n", existing.ID, existing.State)
					return nil
				}
				fmt.Fprintln(w, "Already queued (identical bytes); nothing new recorded. Run `observer cloud sync` to send.")
				return nil
			}
			if err != nil {
				return fmt.Errorf("enqueue: %w", err)
			}
			fmt.Fprintf(w, "Recorded receipt %s and enqueued job %s. Run `observer cloud sync` to send.\n", receiptID, jobID)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", cloudBaseURLFlagUsage("Cloud base URL"))
	cmd.Flags().StringVar(&sessionID, "session", "", "Local session id to consent")
	cmd.Flags().StringVar(&purpose, "purpose", "", "Consent purpose (required)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the interactive confirmation")
	cmd.Flags().StringVar(&expectedUploadDigest, "expected-upload-digest", "", "Refuse if these bytes differ from the displayed preview")
	cmd.Flags().Int64Var(&backgroundGeneration, "background-generation", 0, "Expected policy generation for daemon-scheduled consent")
	_ = cmd.Flags().MarkHidden("background-generation")
	// Standing-grant management lives alongside the per-session flow above: the
	// parent's own RunE still handles `consent --session ...` unchanged.
	cmd.AddCommand(
		newCloudConsentGrantCmd(),
		newCloudConsentRevokeCmd(),
		newCloudConsentListCmd(),
	)
	return cmd
}
