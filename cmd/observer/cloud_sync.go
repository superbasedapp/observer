//go:build !sbo_omit_cloud_intelligence

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// --- sync ------------------------------------------------------------------

func newCloudSyncCmd() *cobra.Command {
	var (
		configPath string
		baseURL    string
		devToken   string
		sessionID  string
	)
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Drain the outbox (upload) and pull enrichment results by cursor",
		Long: "Manually drains the outbox: each sendable job is rebuilt once and its\n" +
			"digests re-checked against the consent receipt before upload (a mismatch\n" +
			"moves it to reconfirmation_required, never auto-sent). Under a standing\n" +
			"structural grant it first captures any completed day windows that have not\n" +
			"been snapshotted yet, then drains them in revision order. Finally it pulls\n" +
			"results by cursor.\n\n" +
			"EVERY outbound call goes through the consent-gated egress seam: with no live\n" +
			"grant, nothing is sent and nothing is fetched.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			if cmd.Flags().Changed("session") && strings.TrimSpace(sessionID) == "" {
				return errors.New("--session must name a session")
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			// W3 (value-upgrade plan §4, 2026-09-15): record the outcome of
			// THIS run into cloud_sync_last — content-free counts and a
			// closed error class only — so `observer cloud status` and the
			// dashboard's GET /api/cloud/status can say "did the last sync
			// work" without re-running one. Written on BOTH the success and
			// failure paths via this defer, which reads the counters below by
			// reference: they are declared here, before any return in the
			// function body, precisely so the defer sees their final values
			// no matter which return statement fires (a named return `err`
			// is what lets `return someErr` still populate the value this
			// defer reads).
			syncStarted := time.Now().UTC()
			var sent, reconf, waiting, failed, associated, unassociated, digests int
			var signInExpired bool
			// W5 (value-upgrade plan §4, 2026-09-15): the account plan GET
			// /v1/usage reported on this run, if the fetch succeeded. Stays at
			// its zero value ("" / nil) when it did not — RecordCloudSyncLast
			// then correctly writes "unknown" rather than repeating a stale
			// number from a prior run.
			var planName, planLabel string
			var planDigestWeekly, planRetentionDays, planDailyCap, planMonthlyCap *int
			// R-AI1: the usage view this run read, nil when it read none. Its
			// token budgets (and the evidence budget the builder fits to) are
			// recorded beside the plan; nil keeps the last-known evidence
			// budget (store.RecordCloudSyncLast).
			var usageRead *cloudgateway.UsageView
			defer func() {
				err = cloudScopedSyncError(sessionID, err, failed, reconf)
				errClass := ""
				if err != nil {
					errClass = cloudErrClass(err)
				}
				rec := store.CloudSyncLast{
					StartedAt: syncStarted, FinishedAt: time.Now().UTC(), OK: err == nil,
					Sent: sent, WaitingProvider: waiting, Reconfirm: reconf, Failed: failed,
					Results: associated, SignInExpired: signInExpired, ErrorClass: errClass,
					PlanName: planName, PlanLabel: planLabel,
					DigestWeekly: planDigestWeekly, ResultsRetentionDays: planRetentionDays,
					DailyCap: planDailyCap, MonthlyCap: planMonthlyCap,
				}
				cloudApplyUsageTokens(&rec, usageRead)
				_ = st.RecordCloudSyncLast(cmd.Context(), rec)
			}()

			// The same pricer preview and consent used, so a rebuild at send
			// time reproduces the exact bytes the receipt bound.
			pricer := acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default())
			resolved := resolveCloudBaseURL(baseURL, cfg)
			if err := requireCloudBaseURL(resolved); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			gw, err := openCloudGateway(cfg, resolved, devToken, st, func() {
				fmt.Fprintln(w, "Note: the API token had expired; it was re-exchanged through the persisted sign-in.")
			})
			if err != nil {
				return err
			}
			// signInExpired records that the token self-heal failed somewhere in
			// this run. The network client latches that state, so once any rail
			// hits it every later authenticated call (the results pull included)
			// fails fast with the same error — which is how a failure on the
			// structural/community rails (reported inline, never fatal) still
			// reaches this flag through the results pull below.

			// FD4: reclaim outbox items stranded in `sending` by a prior crash/
			// kill (a sync that transitioned to sending but never marked the
			// outcome) so they retry. The idempotency key makes an ambiguous
			// prior delivery safe.
			if n, rerr := st.ReclaimStaleCloudSending(cmd.Context(), time.Now().Add(-cloudSendingLeaseTTL)); rerr != nil {
				return fmt.Errorf("reclaim stale sending: %w", rerr)
			} else if n > 0 {
				fmt.Fprintf(w, "Reclaimed %d stranded 'sending' item(s) from a prior interrupted sync.\n", n)
			}

			// Structural-insights rail: capture then drain, both under the
			// standing grant. Reported separately and never fatal — a structural
			// problem must not cost the developer their session-evidence sync.
			if sessionID == "" {
				cloudSyncStructural(cmd.Context(), st, gw, time.Now(), w)

				// Community cohort-benchmarking rail: compute the current month's own
				// value and upload it under the standing grant. Also separate + never
				// fatal, and a no-op unless the developer granted the purpose.
				cloudSyncCommunity(cmd.Context(), st, gw, time.Now(), w)
			}

			items, err := st.ListSendableCloudOutbox(cmd.Context())
			if err != nil {
				return fmt.Errorf("list outbox: %w", err)
			}
			items = cloudScopeSyncItems(items, sessionID, w)
			for _, it := range items {
				if err := cloudDrainOneGated(cmd.Context(), st, gw, it, w, pricer); err != nil {
					signInExpired = signInExpired || errors.Is(err, cloudgateway.ErrSignInExpired)
					switch {
					case errors.Is(err, errCloudProviderNotReady):
						waiting++
					case errors.Is(err, store.ErrCloudReconfirmationRequired),
						errors.Is(err, store.ErrCloudEndpointMismatch),
						errors.Is(err, store.ErrCloudSendUnauthorized),
						errors.Is(err, cloudgateway.ErrNoLiveGrant),
						errors.Is(err, cloudgateway.ErrGrantRevoked):
						reconf++
					default:
						failed++
					}
					continue
				}
				sent++
			}
			if waiting > 0 {
				fmt.Fprintf(w, "Outbox: %d sent, %d waiting on provider, %d need reconfirmation, %d failed (of %d sendable).\n", sent, waiting, reconf, failed, len(items))
			} else {
				fmt.Fprintf(w, "Outbox: %d sent, %d need reconfirmation, %d failed (of %d sendable).\n", sent, reconf, failed, len(items))
			}

			// Pull results by cursor and associate each back to its local
			// session via the reverse pseudonym lookup (CI-P5b), or its local
			// project via the project pseudonym for a weekly digest (W5). It is
			// a FEATURE fetch: with no live grant at all there is nothing on the
			// service that belongs to this device, and no request is made.
			err = gw.FeatureFetch(cmd.Context(), func(sess cloudgateway.ReadSession) error {
				var perr error
				associated, unassociated, digests, perr = cloudPullResultsAndDigests(cmd.Context(), st, cloudHostKey(resolved), sess, w)
				return perr
			})
			if errors.Is(err, cloudgateway.ErrNoLiveGrant) {
				fmt.Fprintln(w, "Results: skipped - no live consent grant, so nothing was fetched.")
				return nil
			}
			if err != nil {
				fmt.Fprintf(w, "Results: pull incomplete: %v\n", err)
				if signInExpired || errors.Is(err, cloudgateway.ErrSignInExpired) {
					// Exit non-zero so the R2a auto-sync subprocess surfaces the
					// state in the daemon log instead of silently failing forever.
					return errors.New(cloudSignInExpiredHint + " (the persisted sign-in could not be refreshed; nothing syncs until then)")
				}
				return nil
			}
			if signInExpired {
				return errors.New(cloudSignInExpiredHint + " (the persisted sign-in could not be refreshed; nothing syncs until then)")
			}
			resultsLine := fmt.Sprintf("Results: %d associated", associated)
			if unassociated > 0 {
				resultsLine += fmt.Sprintf(", %d for sessions not on this device", unassociated)
			}
			if digests > 0 {
				resultsLine += fmt.Sprintf(", %d digest(s)", digests)
			}
			fmt.Fprintln(w, resultsLine+".")

			// W5: read the account's resolved plan through the SAME
			// consent-gated read lane, straight after the results pull — no new
			// egress path. A failed usage fetch is a WARN, never a sync
			// failure: the sync already did its job (outbox drained, results
			// pulled), and the plan fields simply stay unknown.
			var usage cloudgateway.UsageView
			switch uerr := gw.FeatureFetch(cmd.Context(), func(sess cloudgateway.ReadSession) error {
				var perr error
				usage, perr = sess.Usage(cmd.Context())
				return perr
			}); {
			case uerr == nil:
				usageRead = &usage
				planName, planLabel = usage.Plan, usage.PlanLabel
				dailyCap, monthlyCap := usage.DailyCap, usage.MonthlyCap
				planDailyCap, planMonthlyCap = &dailyCap, &monthlyCap
				if usage.DigestWeekly != nil {
					v := 0
					if *usage.DigestWeekly {
						v = 1
					}
					planDigestWeekly = &v
				}
				if usage.ResultsRetentionDays != nil {
					v := *usage.ResultsRetentionDays
					planRetentionDays = &v
				}
			case errors.Is(uerr, cloudgateway.ErrNoLiveGrant):
				// Routine: no live grant at all, same as the results pull above;
				// the plan simply stays unknown, silently.
			default:
				fmt.Fprintf(w, "Warning: could not read the account plan from the hosted service: %v\n", uerr)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", cloudBaseURLFlagUsage("Cloud base URL"))
	cmd.Flags().StringVar(&devToken, "dev-token", "", "Dev access token for local testing (never stored)")
	cmd.Flags().StringVar(&sessionID, "session", "", "Upload only this session; skip structural/community uploads and still pull available results")
	return cmd
}

// cloudLocalOutboxIDPrefix is the prefix `store.EnqueueCloudOutbox` mints for a
// LOCAL outbox row id (see store.cloudRandomID("job_")). It is entirely
// distinct from the CLOUD job id the hosted service assigns at submit time
// (UploadResult.JobID, printed by `observer cloud sync` as "cloud job <id>")
// — observer does not persist a mapping from one to the other, so
// newCloudJobCmd refuses a local-shaped argument with an explanation instead
// of guessing.
const cloudLocalOutboxIDPrefix = "job_"

// newCloudJobCmd looks up one hosted enrichment job's status by its CLOUD job
// id (GET /v1/jobs/{id} through the consent-gated read lane — the same lane
// `sync` already uses for Results/Usage, no new egress path).
func newCloudJobCmd() *cobra.Command {
	var (
		configPath string
		baseURL    string
		devToken   string
		asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "job <cloud-job-id>",
		Short: "Show a hosted enrichment job's status",
		Long: "Looks up one hosted enrichment job by its CLOUD job id - the id\n" +
			"`observer cloud sync` prints as \"cloud job <id>\" once an item sends.\n\n" +
			"This is NOT the same as the LOCAL outbox id (job_<hex>) `observer cloud\n" +
			"consent` prints when it enqueues a session: observer does not store a\n" +
			"mapping from the local id back to the cloud id, so a job_<hex> argument\n" +
			"is refused with an explanation rather than looked up wrong.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := strings.TrimSpace(args[0])
			if strings.HasPrefix(id, cloudLocalOutboxIDPrefix) {
				return fmt.Errorf(
					"%q looks like a LOCAL outbox id (printed by `observer cloud consent`); "+
						"observer does not store a mapping from it to the hosted job id - "+
						"pass the id `observer cloud sync` printed as \"cloud job <id>\" instead",
					id)
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			resolved := resolveCloudBaseURL(baseURL, cfg)
			if err := requireCloudBaseURL(resolved); err != nil {
				return err
			}
			gw, err := openCloudGateway(cfg, resolved, devToken, st, nil)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			var status cloudgateway.JobStatus
			ferr := gw.FeatureFetch(cmd.Context(), func(sess cloudgateway.ReadSession) error {
				var perr error
				status, perr = sess.Job(cmd.Context(), id)
				return perr
			})
			switch {
			case errors.Is(ferr, cloudgateway.ErrNoLiveGrant):
				return errors.New("no live consent grant - nothing can be fetched (run `observer cloud consent` first)")
			case errors.Is(ferr, cloudgateway.ErrJobNotFound):
				fmt.Fprintln(w, "job not found for this device's account")
				return nil
			case ferr != nil:
				return fmt.Errorf("fetch job status: %w", ferr)
			}
			if asJSON {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(status)
			}
			fmt.Fprintf(w, "job:             %s\n", status.ID)
			fmt.Fprintf(w, "state:           %s\n", status.State)
			if status.TerminalReason != "" {
				fmt.Fprintf(w, "terminal reason: %s\n", status.TerminalReason)
			}
			fmt.Fprintf(w, "feature:         %s\n", status.Feature)
			fmt.Fprintf(w, "attempts:        %d\n", status.Attempts)
			fmt.Fprintf(w, "created:         %s\n", status.CreatedAt.Format(time.RFC3339))
			fmt.Fprintf(w, "updated:         %s\n", status.UpdatedAt.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", cloudBaseURLFlagUsage("Cloud base URL"))
	cmd.Flags().StringVar(&devToken, "dev-token", "", "Dev access token for local testing (never stored)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the job status as JSON")
	return cmd
}

// cloudDrainOneGated is the CONSENT GATE around one session-evidence item: it
// resolves the item's bound purpose and routes the actual drain through the
// gateway's feature lane, so the network client is only reachable once a live
// grant for that purpose has been confirmed.
//
// It is deliberately a BELT over machinery that already works: the per-item
// receipt binding, digest re-check, endpoint binding (FD1) and pre-dispatch
// re-verification (FD3) inside cloudDrainOne are untouched. What the gate adds
// is that a node with no live consent at all makes NO network attempt, rather
// than relying on every per-item path to refuse.
func cloudDrainOneGated(ctx context.Context, st *store.Store, gw *cloudgateway.Gateway, it store.CloudOutboxItem, w io.Writer, pricer *cost.Engine) error {
	rcpt, ok, err := st.GetCloudConsentReceipt(ctx, it.ReceiptID)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION - its consent receipt no longer exists; not sent\n", it.ID)
		return fmt.Errorf("job %s: %w", it.ID, store.ErrCloudReceiptNotFound)
	}
	purpose, perr := parseCloudPurpose(rcpt.Purpose)
	if perr != nil {
		fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION - its receipt names an unknown purpose %q; not sent\n", it.ID, rcpt.Purpose)
		return perr
	}
	// A bounded upload needs BOTH purposes to actually authorize an evidence
	// body — the structural purpose it implies, not just the one the developer
	// typed — before the single receipt-bound purpose below gates the live
	// grant + dispatches. cloudPurposeSet is the same table buildCloudEnvelope
	// uses to decide what the envelope discloses under, so this check can never
	// drift from what is about to be sent.
	set, serr := cloudPurposeSet(purpose)
	if serr != nil {
		fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION - its receipt names a purpose this build no longer supports (%v); not sent\n", it.ID, serr)
		return serr
	}
	if uerr := cloudPurposeSetUploadable(set); uerr != nil {
		fmt.Fprintf(w, "  job %s: NOT SENT - %v\n", it.ID, uerr)
		return uerr
	}
	err = gw.FeatureSend(ctx, purpose, func(sess cloudgateway.UploadSession) error {
		return cloudDrainOne(ctx, st, sess, it, w, pricer)
	})
	switch {
	case errors.Is(err, cloudgateway.ErrNoLiveGrant), errors.Is(err, cloudgateway.ErrGrantRevoked):
		fmt.Fprintf(w, "  job %s: NOT SENT - no live consent grant for purpose %q; nothing left this machine\n", it.ID, purpose)
	case errors.Is(err, cloudgateway.ErrPurposeNotUploadable):
		fmt.Fprintf(w, "  job %s: NOT SENT - purpose %q does not authorize an evidence upload (%v)\n", it.ID, purpose, err)
	}
	return err
}

// cloudDrainOne prepares (rebuild + digest re-check), uploads, and marks one
// outbox item. Its error is returned so the caller can bucket the outcome. It
// is only ever reached from inside an authorized gateway send — the Session it
// takes cannot be obtained any other way.
// errCloudProviderNotReady is a node-local sentinel: the hosted enrichment
// provider returned provider_policy_unverified (it is not accepting jobs yet —
// a server-side credential/attestation gate, nothing the developer did). The
// outbox item stays retryable; a later sync sends it once the provider is
// enabled. The sync summary counts it as "waiting on provider", not "failed".
var errCloudProviderNotReady = errors.New("cloud: hosted enrichment provider is not accepting jobs yet")

func cloudDrainOne(ctx context.Context, st *store.Store, sess cloudgateway.UploadSession, it store.CloudOutboxItem, w io.Writer, pricer *cost.Engine) error {
	rebuild := func(ctx context.Context) ([]byte, string, string, error) {
		rcpt, ok, err := st.GetCloudConsentReceipt(ctx, it.ReceiptID)
		if err != nil {
			return nil, "", "", err
		}
		if !ok {
			return nil, "", "", store.ErrCloudReceiptNotFound
		}
		p, perr := parseCloudPurpose(rcpt.Purpose)
		if perr != nil {
			return nil, "", "", perr
		}
		// The receipt's OWN classes, not today's table: an item consented
		// before the first-prompt class existed must rebuild to the bytes the
		// developer saw.
		settings, serr := store.ParseCloudEvidenceSettings(rcpt.EvidenceSettingsJSON)
		if serr != nil {
			return nil, "", "", serr
		}
		res, berr := buildCloudEnvelopeWithSettings(ctx, st, it.SessionID, p, cloudReceiptFieldClasses(rcpt.FieldClassesJSON), pricer, settings)
		if berr != nil {
			return nil, "", "", berr
		}
		return res.Bytes, res.Digests.EvidenceContent, res.Digests.Upload, nil
	}

	// FD1: bind the send target to the receipt's approved endpoint. The store
	// refuses the send (reconfirmation) if the client's immutable upload URL is
	// not the origin+path the developer consented to.
	bytesOut, lease, err := st.PrepareCloudOutboxSend(ctx, it.ID, sess.UploadEndpoint(), rebuild)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrCloudEndpointMismatch):
			fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION - the sync endpoint does not match the one you consented to\n", it.ID)
			fmt.Fprintf(w, "    (%v). Re-run `observer cloud consent --session %s --base-url <approved>` to confirm.\n", err, it.SessionID)
		case errors.Is(err, store.ErrCloudReconfirmationRequired):
			fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION - the rebuilt envelope no longer matches the receipt\n", it.ID)
			fmt.Fprintf(w, "    (a local edit, scrubber upgrade, schema bump, or an authorization change). Re-preview and\n")
			fmt.Fprintf(w, "    re-run `observer cloud consent --session %s` to confirm the new bytes.\n", it.SessionID)
		}
		return err
	}

	// FD3: cheap pre-flight — if the receipt was already invalidated or the
	// session upgraded to org before we even mint a pseudonym, abort here (moving
	// the item to reconfirmation_required) before doing any further work.
	if verr := st.VerifyCloudSendAuthorization(ctx, lease); verr != nil {
		fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION - authorization changed before dispatch; not sent (%v)\n", it.ID, verr)
		return verr
	}

	cloudSession, err := st.GetOrCreateCloudSessionPseudonym(ctx, it.SessionID)
	if err != nil {
		_ = st.MarkCloudOutboxRetryable(ctx, it.ID, "pseudonym_error")
		return err
	}

	// Two-digest preview truth: register the exact (upload, content) digests
	// these bytes carry BEFORE the upload, or the server refuses the upload with
	// reconfirmation_required. The receipt supplies the disclosure metadata; the
	// outbox row carries the digests of the bytes about to be sent.
	if pcErr := cloudPreviewConfirm(ctx, st, sess, it); pcErr != nil {
		_ = st.MarkCloudOutboxRetryable(ctx, it.ID, cloudErrClass(pcErr))
		fmt.Fprintf(w, "  job %s: failed (retryable): preview-confirmation: %v\n", it.ID, pcErr)
		return pcErr
	}

	receipt, found, rerr := st.GetCloudConsentReceipt(ctx, it.ReceiptID)
	if rerr != nil || !found {
		return fmt.Errorf("cloudDrainOne: %w", store.ErrCloudReceiptNotFound)
	}
	resp, upErr := sess.Upload(ctx, cloudgateway.UploadRequest{
		CloudSessionID: cloudSession,
		Feature:        cloudFeatureSessionEnrichment,
		Envelope:       bytesOut,
		UploadDigest:   it.UploadDigest,
		SchemaVersion:  cloudcontract.EnvelopeSchemaVersion,
		// FD3: re-verify authorization inside the client, immediately before each
		// physical POST (after the pseudonym mint above, and before every retry).
		// This closes the prepare→dispatch window (a revocation during the
		// pseudonym mint) and the retry window (a revocation between attempts) —
		// the confirmed body never leaves once the receipt is gone or the session
		// has flipped to org authority.
		PreAttempt:    func() error { return st.VerifyCloudSendAuthorization(ctx, lease) },
		DispatchLease: cloudDispatchLeaseForMode(st, receipt.ID, cloudcontract.Purpose(receipt.Purpose), receipt.ConsentGeneration, store.CloudGrantPerUpload),
	})
	if upErr != nil {
		// A server 409 reconfirmation_required means the exact bytes were not
		// preview-confirmed (two-digest preview truth). That is a re-preview/
		// re-consent situation, NOT a terminal failure: park the item in
		// reconfirmation_required and surface the store sentinel so the sync loop
		// counts it as reconfirmation rather than a burned failure.
		if d, ok := cloudgateway.HTTPError(upErr); ok && d.StatusCode == http.StatusConflict && d.Code == "reconfirmation_required" {
			_ = st.MarkCloudOutboxReconfirmation(ctx, it.ID, "reconfirmation_required")
			fmt.Fprintf(w, "  job %s: NEEDS RECONFIRMATION - the server did not accept these exact bytes; re-preview and re-run `observer cloud consent --session %s`\n", it.ID, it.SessionID)
			return fmt.Errorf("cloudDrainOne: %w", store.ErrCloudReconfirmationRequired)
		}
		// The hosted enrichment provider is not accepting jobs yet
		// (provider_policy_unverified — the provider credential/attestation gate
		// on the server, not anything the developer did). Keep the item retryable
		// and say so honestly: nothing to do, a later sync sends it once the
		// provider is enabled — never a scary "failed".
		if d, ok := cloudgateway.HTTPError(upErr); ok && d.Code == "provider_policy_unverified" {
			_ = st.MarkCloudOutboxRetryable(ctx, it.ID, "provider_policy_unverified")
			fmt.Fprintf(w, "  job %s: QUEUED - the hosted enrichment provider is not accepting jobs yet; your job is kept and will send automatically on a later `observer cloud sync` (nothing to do)\n", it.ID)
			return fmt.Errorf("cloudDrainOne: %w", errCloudProviderNotReady)
		}
		if cloudUploadTerminal(upErr) {
			_ = st.MarkCloudOutboxTerminal(ctx, it.ID, cloudErrClass(upErr))
			fmt.Fprintf(w, "  job %s: FAILED (terminal): %v\n", it.ID, upErr)
			// A 422 digest_mismatch stays TERMINAL — the server recomputed a
			// different digest over these exact bytes, and no retry of the same
			// bytes can change that. But the most likely CAUSE is not a corrupt
			// node: the envelope is versioned additively (`activity_mix` was
			// added under an unchanged schema version), so a server that predates
			// this node DROPS the unknown field and digests something else. That
			// is a deployment-order problem — servers roll before nodes — and the
			// operator can only act on it if we say so.
			if d, ok := cloudgateway.HTTPError(upErr); ok && d.Code == cloudErrCodeDigestMismatch {
				fmt.Fprintf(w, "    %s\n", cloudDigestMismatchHint)
			}
			// A 403 out_of_purpose means the server needed a purpose this receipt
			// did not disclose under. Name the missing purpose (the server's
			// message embeds it) and the exact command that grants it, instead of
			// leaving the operator to grep an error code.
			if d, ok := cloudgateway.HTTPError(upErr); ok && d.Code == cloudErrCodeOutOfPurpose {
				fmt.Fprintf(w, "    %s\n", cloudOutOfPurposeHint(d.Message, it.SessionID))
			}
		} else {
			_ = st.MarkCloudOutboxRetryable(ctx, it.ID, cloudErrClass(upErr))
			fmt.Fprintf(w, "  job %s: failed (retryable): %v\n", it.ID, upErr)
		}
		return upErr
	}
	if err := st.MarkCloudOutboxSent(ctx, it.ID); err != nil {
		return err
	}
	fmt.Fprintf(w, "  job %s: sent (cloud job %s)\n", it.ID, resp.JobID)
	return nil
}

// cloudPreviewConfirm registers the two digests of the exact bytes the following
// upload will carry (the outbox row's EvidenceContentDigest + UploadDigest) with
// the disclosure metadata bound on the receipt, so the server admits the upload
// instead of refusing it with reconfirmation_required. It runs immediately
// before the upload — the receipt binds (account, upload_digest), and those are
// the bytes about to be POSTed.
func cloudPreviewConfirm(ctx context.Context, st *store.Store, sess cloudgateway.UploadSession, it store.CloudOutboxItem) error {
	rcpt, ok, err := st.GetCloudConsentReceipt(ctx, it.ReceiptID)
	if err != nil {
		return err
	}
	if !ok {
		return store.ErrCloudReceiptNotFound
	}
	// The receipt names the ONE purpose the developer typed at consent time,
	// but the server's out-of-purpose check requires the FULL disclosure set a
	// bounded envelope carries (structural_activity_insights is the base every
	// session-evidence upload rides on; bounded_context_enrichment is additive
	// on top of it). cloudPurposeSet is the same table buildCloudEnvelope used
	// to decide the envelope's own DisclosurePurposes, so the two can never
	// disagree about what this upload discloses under.
	purpose, perr := parseCloudPurpose(rcpt.Purpose)
	if perr != nil {
		return fmt.Errorf("cloudPreviewConfirm: %w", perr)
	}
	purposeSet, serr := cloudPurposeSet(purpose)
	if serr != nil {
		return fmt.Errorf("cloudPreviewConfirm: %w", serr)
	}
	var fieldClasses []string
	if strings.TrimSpace(rcpt.FieldClassesJSON) != "" {
		if jerr := json.Unmarshal([]byte(rcpt.FieldClassesJSON), &fieldClasses); jerr != nil {
			return fmt.Errorf("cloudPreviewConfirm: decode field classes: %w", jerr)
		}
	}
	endpoint := rcpt.Endpoint
	if endpoint == "" {
		endpoint = sess.UploadEndpoint()
	}
	return sess.PreviewConfirm(ctx, cloudgateway.PreviewConfirmRequest{
		Purposes:        cloudPurposeStrings(purposeSet),
		FieldClasses:    fieldClasses,
		EvidenceSchema:  rcpt.EnvelopeSchemaVersion,
		ScrubberVersion: rcpt.ScrubberVersion,
		RetentionPolicy: rcpt.RetentionPolicyVersion,
		Endpoint:        endpoint,
		UploadDigest:    it.UploadDigest,
		ContentDigest:   it.EvidenceContentDigest,
	})
}

// cloudUploadTerminal classifies a client error as terminal (a 4xx client
// error other than 429) vs retryable (transport / 5xx / 429). An expired
// sign-in is a CREDENTIAL state, not a rejection of the item — it wraps the
// 401 that revealed it, but the item must stay queued for the sync after the
// user's next `observer cloud login`.
func cloudUploadTerminal(err error) bool {
	if errors.Is(err, cloudgateway.ErrSignInExpired) {
		return false
	}
	if status, ok := cloudgateway.HTTPStatus(err); ok {
		return status >= 400 && status < 500 && status != http.StatusTooManyRequests
	}
	return false
}

// cloudErrClass returns a content-free error class for the outbox row.
func cloudErrClass(err error) string {
	if errors.Is(err, cloudgateway.ErrSignInExpired) {
		return cloudErrClassSignInExpired
	}
	if status, ok := cloudgateway.HTTPStatus(err); ok {
		return fmt.Sprintf("http_%d", status)
	}
	return "transport"
}

// cloudErrClassSignInExpired is the content-free outbox error class for a send
// that failed because the sign-in expired (retryable after `observer cloud
// login`).
const cloudErrClassSignInExpired = "sign_in_expired"

// cloudErrCodeDigestMismatch is the server's error code when it recomputes a
// different digest over the uploaded bytes (HTTP 422).
const cloudErrCodeDigestMismatch = "digest_mismatch"

// cloudDigestMismatchHint is the ONE user-facing explanation for a 422
// digest_mismatch. It is a hint, not a state change: the item stays terminal
// (re-sending identical bytes to the same server cannot succeed), but the
// operator is told the likeliest cause and what to do about it.
const cloudDigestMismatchHint = "the server computed a different digest over these exact bytes - most often it PREDATES this " +
	"node's envelope version (fields are added additively, and a server that does not know a field drops it and " +
	"digests something else). The hosted service rolls BEFORE nodes: update it, then re-run `observer cloud preview` " +
	"and `observer cloud consent` for this session."

// cloudErrCodeOutOfPurpose is the server's error code (HTTP 403) when the
// envelope's disclosure needs a consent purpose the confirmed receipt did not
// grant (internal/cloudserver/api/jobs.go's requiredPurposes /
// DisclosurePurposes checks).
const cloudErrCodeOutOfPurpose = "out_of_purpose"

// The two message prefixes internal/cloudserver/api/jobs.go embeds the
// missing purpose after. Matched literally so cloudOutOfPurposeHint can name
// the exact purpose in its own remedy instead of repeating the server's raw
// message.
const (
	cloudOutOfPurposeRequiredPrefix = "required purpose not granted: "
	cloudOutOfPurposeDeclaredPrefix = "declared disclosure purpose not granted: "
)

// cloudOutOfPurposeHint turns a 403 out_of_purpose body into an actionable
// remedy: which purpose is missing, and the exact command that grants it. A
// bounded_context_enrichment consent grants BOTH purposes a session-evidence
// upload needs (cloudPurposeSet), so re-consenting under it is always the fix
// once this node carries that behavior - this is the live-bug remedy itself,
// not just documentation of it.
func cloudOutOfPurposeHint(serverMessage, sessionID string) string {
	missing := strings.TrimPrefix(serverMessage, cloudOutOfPurposeRequiredPrefix)
	if missing == serverMessage {
		missing = strings.TrimPrefix(serverMessage, cloudOutOfPurposeDeclaredPrefix)
	}
	if missing == serverMessage {
		missing = ""
	}
	if missing == "" {
		return fmt.Sprintf(
			"the server rejected this upload because a required consent purpose was not granted (%s). "+
				"Re-run `observer cloud consent --session %s --purpose %s` (it grants the structural purpose "+
				"too) then retry `observer cloud sync`.",
			serverMessage, sessionID, string(cloudcontract.PurposeContextEnrichment),
		)
	}
	return fmt.Sprintf(
		"the server needs purpose %q granted for this upload and it is not on the confirmed receipt. "+
			"Re-run `observer cloud consent --session %s --purpose %s` (bounded_context_enrichment grants both "+
			"the structural and bounded purposes together) then retry `observer cloud sync`.",
		missing, sessionID, string(cloudcontract.PurposeContextEnrichment),
	)
}
