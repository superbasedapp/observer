package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudmetrics"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/orgdeletion"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/seatbilling"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/seatbilling/paddleapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// This file wires org deletion and account deletion with orgs (managed-SaaS
// plan 07 M6.9 and the control-plane half of M7a.1) into `worker`, and the
// operator's `deletions` verbs.
//
// Environment (worker):
//
//	SBCI_DELETION_DRIVER     "off" stops the deletion driver (default on: it
//	                         acts only on requests that exist, and writes host
//	                         intents to the outbox, which only the host-API
//	                         client sends)
//	WORKOS_API_KEY[_FILE]    when set, the identity seam deletes the WorkOS
//	                         user at the end of an account deletion; unset,
//	                         that step blocks as identity_seam_unwired
//	SBCI_PADDLE_API_KEY_FILE when set (with SBCI_PADDLE_ENV), the billing
//	                         seam cancels an org's live Paddle subscription
//	                         at cancel_billing (POST /subscriptions/{id}/cancel,
//	                         effective immediately; FR-1); unset, that step
//	                         blocks as billing_seam_unwired. The console
//	                         refuses to open such a deletion when serve has no
//	                         key (billing_cancel_unavailable), so the block is
//	                         the rare case of a worker without the key.
//
// ALERTS (FR-1). A blocked request leaves the driver's due queue, so it is
// logged at ERROR with alert=deletion_blocked when the pass blocks it (kind,
// request id, org id, step, reason, class; ids and enum words only), and
// every deletionAlertEvery while any request stays blocked the worker logs
// alert=deletion_blocked_open with the counts. The ops lane alerts on both
// keys; staff clear the cause and run `observer-cloud deletions resume`.

// envDeletionDriver switches the deletion driver.
const envDeletionDriver = "SBCI_DELETION_DRIVER"

// deletionPassEvery is the driver's cadence; deletionPassLimit bounds one
// pass per table; deletionAlertEvery is how often the still-blocked count is
// logged.
const (
	deletionPassEvery  = time.Minute
	deletionPassLimit  = 100
	deletionAlertEvery = time.Hour
)

// The alert keys of the deletion driver's log lines (the "alert" attribute).
const (
	alertDeletionBlocked     = "deletion_blocked"
	alertDeletionBlockedOpen = "deletion_blocked_open"
)

// paddleSubscriptions is the part of the Paddle API client the billing seam
// uses (paddleapi.Client).
type paddleSubscriptions interface {
	GetSubscription(ctx context.Context, id string) (seatbilling.Subscription, error)
	CancelSubscription(ctx context.Context, id string) (seatbilling.Subscription, error)
}

// deletionBilling is orgdeletion.Billing over the Paddle API (FR-1): the
// worker's org deletion uses it at cancel_billing, and serve's account
// deletion before it purges the account's live subscriptions (ORGDEL-7,
// paddleServeConfigFromEnv). It is idempotent by reading first: a subscription Paddle already reports
// canceled is done (the request's retry, or a cancel the customer made in
// Paddle's portal), and a refused cancel is read again before it counts as
// a refusal. Paddle keeps no idempotency key; the read stands in for it.
type deletionBilling struct{ api paddleSubscriptions }

// CancelOrgSubscription implements orgdeletion.Billing.
func (b deletionBilling) CancelOrgSubscription(ctx context.Context, req orgdeletion.CancelRequest) error {
	id := req.SubscriptionID
	if !paddleapi.ValidSubscriptionID(id) {
		return orgdeletion.Classed("billing:bad_subscription_id",
			fmt.Errorf("%w: the stored subscription id is not a Paddle subscription id", orgdeletion.ErrBillingRefused))
	}
	sub, err := b.api.GetSubscription(ctx, id)
	if err != nil {
		return billingError("get", err)
	}
	if sub.Status == paddleapi.StatusCanceled {
		return nil
	}
	if _, err := b.api.CancelSubscription(ctx, id); err != nil {
		var ae *paddleapi.APIError
		if errors.As(err, &ae) && !ae.Retryable() {
			if again, gerr := b.api.GetSubscription(ctx, id); gerr == nil && again.Status == paddleapi.StatusCanceled {
				return nil
			}
		}
		return billingError("cancel", err)
	}
	return nil
}

// billingClassPattern is the last_error_class column's CHECK.
var billingClassPattern = regexp.MustCompile(`^[a-z0-9_:.-]{1,80}$`)

// billingError classes a Paddle failure: a rate limit or a server error is
// retried; any other HTTP answer is a refusal a retry cannot fix (the step
// blocks as billing_cancel_refused, with Paddle's error code in the class);
// a transport failure is retried.
func billingError(op string, err error) error {
	var ae *paddleapi.APIError
	if !errors.As(err, &ae) {
		return orgdeletion.Classed("billing:"+op+":transport", err)
	}
	class := fmt.Sprintf("billing:%s:http_%d", op, ae.HTTPStatus)
	if c := class + ":" + ae.Code; ae.Code != "" && billingClassPattern.MatchString(c) {
		class = c
	}
	if ae.Retryable() {
		return orgdeletion.Classed(class, err)
	}
	return orgdeletion.Classed(class, fmt.Errorf("%w: %w", orgdeletion.ErrBillingRefused, err))
}

// deletionBillingFromEnv returns the billing seam from the worker's Paddle
// settings (nil: no API key, the step blocks as billing_seam_unwired).
func deletionBillingFromEnv(log *slog.Logger, getenv func(string) string, readFile func(string) ([]byte, error)) (orgdeletion.Billing, error) {
	sec, err := readPaddleSecrets(getenv, readFile)
	if err != nil {
		return nil, fmt.Errorf("deletion billing: Paddle secrets: %w", err)
	}
	if sec.apiKey == "" {
		log.Warn("observer-cloud: deletion driver: no Paddle API key; a team deletion with a live subscription blocks at cancel_billing (billing_seam_unwired)")
		return nil, nil
	}
	client, err := newPaddleAPIClient(paddleEnvironment(getenv), sec)
	if err != nil {
		return nil, fmt.Errorf("deletion billing: Paddle API: %w", err)
	}
	return deletionBilling{api: client}, nil
}

// logDeletionBlocks raises one alert line per request the pass blocked and
// counts it in sbci_deletion_blocked_total (reg nil: not counted).
func logDeletionBlocks(log *slog.Logger, reg *cloudmetrics.Registry, rep orgdeletion.PassReport) {
	for _, b := range rep.Blocks {
		reg.DeletionBlocked(b.Kind, b.Reason)
		log.Error("observer-cloud: deletion blocked; staff must clear the cause and resume it",
			"alert", alertDeletionBlocked, "kind", b.Kind, "request_id", b.RequestID, "org_id", b.OrgID,
			"step", string(b.Step), "reason", b.Reason, "class", b.Class)
	}
}

// blockedCounter is the store's count of blocked deletions.
type blockedCounter interface {
	BlockedDeletions(ctx context.Context) (orgs, followups int, err error)
}

// readBlockedOpen reads the blocked counts into the
// sbci_deletion_blocked_open gauges (every pass, when reg is wired) and
// returns them; ok=false when the read failed (logged, gauges kept).
func readBlockedOpen(ctx context.Context, log *slog.Logger, reg *cloudmetrics.Registry, s blockedCounter) (orgs, fus int, ok bool) {
	orgs, fus, err := s.BlockedDeletions(ctx)
	if err != nil {
		reg.DeletionsBlockedOpenReadFailed()
		log.Warn("observer-cloud: deletion blocked count failed", "err", err)
		return 0, 0, false
	}
	reg.SetDeletionsBlockedOpen(orgs, fus)
	return orgs, fus, true
}

// logStillBlocked raises the standing alert while any deletion is blocked.
func logStillBlocked(ctx context.Context, log *slog.Logger, reg *cloudmetrics.Registry, s blockedCounter) {
	if orgs, fus, ok := readBlockedOpen(ctx, log, reg, s); ok && orgs+fus > 0 {
		log.Error("observer-cloud: deletion requests are still blocked",
			"alert", alertDeletionBlockedOpen, "org_requests", orgs, "account_followups", fus)
	}
}

// identityDeleter adapts identity.WorkOSUsers to the driver's seam, classing
// its errors for the request's last_error_class.
type identityDeleter struct{ w *identity.WorkOSUsers }

func (d identityDeleter) DeleteUser(ctx context.Context, sub string) error {
	err := d.w.DeleteUser(ctx, sub)
	var se *identity.WorkOSStatusError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, identity.ErrNotWorkOSUser):
		// A subject of another provider has no WorkOS user to delete.
		return nil
	case errors.As(err, &se):
		return orgdeletion.Classed(fmt.Sprintf("identity:http_%d", se.Status), err)
	}
	return orgdeletion.Classed("identity:transport", err)
}

// deletionIdentity returns the identity seam from the worker's environment
// (nil: unwired).
func deletionIdentity(log *slog.Logger) (orgdeletion.Identity, error) {
	key, err := readExclusiveSecret(os.Getenv, os.ReadFile, envWorkOSAPIKey, envWorkOSAPIKeyFile)
	if err != nil {
		return nil, err
	}
	if key == "" {
		log.Info("observer-cloud: deletion driver: no WorkOS API key; account deletions stop before deleting the WorkOS user (identity_seam_unwired)")
		return nil, nil
	}
	w, err := identity.NewWorkOSUsers("", key, nil)
	if err != nil {
		return nil, err
	}
	return identityDeleter{w: w}, nil
}

// newDeletionDriver builds the driver over the store (the worker's role).
func newDeletionDriver(s *store.Store, id orgdeletion.Identity, billing orgdeletion.Billing) (*orgdeletion.Driver, error) {
	j := s.DeletionJournal()
	if j == nil {
		return nil, errors.New("deletion driver: no deletion journal configured")
	}
	return orgdeletion.New(orgdeletion.Deps{Orgs: s, Accounts: s, Journal: j, Identity: id, Billing: billing})
}

// startOrgDeletionDriver runs the driver every minute until ctx ends, unless
// SBCI_DELETION_DRIVER=off.
//
// reg (nil: not wired) counts each block and holds the blocked gauges, read
// every pass so a resumed request clears within a minute; the
// alert=deletion_blocked_open log line stays hourly.
func startOrgDeletionDriver(ctx context.Context, log *slog.Logger, s *store.Store, reg *cloudmetrics.Registry) error {
	if strings.EqualFold(strings.TrimSpace(os.Getenv(envDeletionDriver)), "off") {
		log.Info("observer-cloud: deletion driver off (" + envDeletionDriver + "=off)")
		return nil
	}
	id, err := deletionIdentity(log)
	if err != nil {
		return fmt.Errorf("deletion driver: %w", err)
	}
	billing, err := deletionBillingFromEnv(log, os.Getenv, os.ReadFile)
	if err != nil {
		return fmt.Errorf("deletion driver: %w", err)
	}
	d, err := newDeletionDriver(s, id, billing)
	if err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(deletionPassEvery)
		defer t.Stop()
		var lastAlert time.Time
		for {
			rep, err := d.Pass(ctx, deletionPassLimit)
			switch {
			case err != nil && ctx.Err() == nil:
				log.Warn("observer-cloud: deletion pass failed", "err", err)
			case rep.Orgs+rep.Followups > 0:
				log.Info("observer-cloud: deletion pass", "orgs", rep.Orgs, "followups", rep.Followups,
					"advanced", rep.Advanced, "waiting", rep.Waiting, "blocked", rep.Blocked, "failed", rep.Failed)
			}
			logDeletionBlocks(log, reg, rep)
			if now := time.Now(); now.Sub(lastAlert) >= deletionAlertEvery && ctx.Err() == nil {
				lastAlert = now
				logStillBlocked(ctx, log, reg, s)
			} else if reg != nil && ctx.Err() == nil {
				readBlockedOpen(ctx, log, reg, s)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	log.Info("observer-cloud: deletion driver running", "every", deletionPassEvery.String(), "identity_wired", id != nil, "billing_wired", billing != nil)
	return nil
}

// newDeletionsCmd is the operator's view of deletions: the staff status, a
// dry run of one org's deletion, and resuming a blocked request.
func newDeletionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deletions",
		Short: "org and account deletions: status, dry run, resume",
	}
	var limit int
	status := &cobra.Command{
		Use:   "status",
		Short: "list org deletions and account follow-ups (ids, steps, enum reasons only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			rows, err := s.ListDeletions(cmd.Context(), limit)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(rows)
		},
	}
	status.Flags().IntVar(&limit, "limit", 100, "at most this many of each kind")

	var org string
	dry := &cobra.Command{
		Use:   "dry-run",
		Short: "show what the driver would do with one org now; writes nothing",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(org) == "" {
				return errors.New("dry-run: --org is required")
			}
			s, err := openStoreForRole(cmd.Context(), store.RoleWorker, mustWorkerDSN())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			billing, err := deletionBillingFromEnv(slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil)), os.Getenv, os.ReadFile)
			if err != nil {
				return err
			}
			d, err := newDeletionDriver(s, nil, billing)
			if err != nil {
				return err
			}
			p, err := d.PreviewOrg(cmd.Context(), org, time.Time{})
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(p)
		},
	}
	dry.Flags().StringVar(&org, "org", "", "the org id")

	var skipWait, yes bool
	resume := &cobra.Command{
		Use:   "resume <request-id>",
		Short: "clear a block once its reason is fixed (--skip-deactivation-wait moves a follow-up past await_deactivate)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				return errors.New("resume requires --yes (the driver acts on the request at its next pass)")
			}
			s, err := openStoreForRole(cmd.Context(), store.RoleWorker, mustWorkerDSN())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			ok, err := s.ResumeDeletion(cmd.Context(), args[0], skipWait, time.Now())
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("resume: no blocked deletion with id %s", args[0])
			}
			detail := fmt.Sprintf(`{"request_id":%q,"skip_deactivation_wait":%t}`, args[0], skipWait)
			if err := s.RecordAudit(cmd.Context(), "", "deletion_resumed", detail); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "observer-cloud: resumed, but recording the audit row failed: %v\n", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "observer-cloud: deletion %s resumed\n", args[0])
			return nil
		},
	}
	resume.Flags().BoolVar(&skipWait, "skip-deactivation-wait", false, "the operator's decision that the remaining members_deactivate intents will not be acked")
	resume.Flags().BoolVar(&yes, "yes", false, "required to confirm")

	cmd.AddCommand(status, dry, resume)
	return cmd
}

// mustWorkerDSN is the worker login's DSN, or the shared one.
func mustWorkerDSN() string {
	dsn, err := workerDSN()
	if err != nil {
		dsn, _ = envDSN()
	}
	return dsn
}
