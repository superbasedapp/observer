package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// newRestoreSuppressCmd is the operator verb for the restore-runbook
// suppression step (gap owed by docs/cloud-intelligence-staging-launch-runbook.md
// §14.3's PITR restore drill): after a point-in-time restore resurrects
// accounts that had been deleted, this replays the deletion journal (which
// lives OUTSIDE the Postgres restore domain — see
// internal/cloudserver/store/deletion.go::SuppressFromJournal) and re-applies
// deletion to every account the restore brought back, BEFORE the restored
// service reopens to traffic. It is idempotent: an account still tombstoned
// is skipped, so a re-run after a partial failure is safe.
//
// It uses the existing store seam only (SuppressFromJournal); it adds no new
// SQL, mirroring newKillSwitchCmd's "existing seam, new CLI surface" shape.
func newRestoreSuppressCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "restore-suppress",
		Short: "re-apply deletion to accounts a point-in-time restore resurrected",
		Long: "Reads the deletion journal (SBCI_DELETION_JOURNAL_PATH) and, for every\n" +
			"account it records as deleted that is NOT currently tombstoned in the\n" +
			"connected database, re-runs the complete deletion. Run this against the\n" +
			"restored database BEFORE it reopens to traffic — see\n" +
			"docs/cloud-intelligence-staging-launch-runbook.md §14.3. Idempotent: an\n" +
			"account still tombstoned is skipped, so re-running after a partial\n" +
			"failure is safe. Requires --yes (this writes to the restored database).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !yes {
				return fmt.Errorf("restore-suppress requires --yes to confirm (this re-applies deletion against the restored database)")
			}
			ctx := cmd.Context()
			s, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer s.Pool().Close()

			n, err := s.SuppressFromJournal(ctx, time.Now())
			if err != nil {
				return fmt.Errorf("restore-suppress: %w", err)
			}

			detail := fmt.Sprintf(`{"suppressed":%d}`, n)
			if auditErr := s.RecordAudit(ctx, "", "restore_suppress_run", detail); auditErr != nil {
				// The suppression already ran — real accounts are already
				// re-tombstoned. Surface the audit failure loudly instead of
				// silently dropping the trail, but don't pretend the run
				// itself didn't happen.
				fmt.Fprintf(cmd.ErrOrStderr(),
					"observer-cloud: restore-suppress applied, but recording the audit row failed: %v\n", auditErr)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "observer-cloud: restore-suppress: %d account(s) re-suppressed\n", n)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "required to confirm this writes to the restored database")
	return cmd
}
