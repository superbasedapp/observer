package main

import (
	"fmt"

	"github.com/spf13/cobra"

	clouddb "github.com/marmutapp/superbased-observer/internal/cloudserver/db"
)

// Exit codes for `observer-cloud schema-check` (gap 4.3). scripts/roll-cloud.sh's
// pre-roll gate (D3) shells out to this command and reads the exit code rather
// than parsing stdout, so the contract is a stable, tested set of integers —
// not the printed text.
const (
	// schemaCheckExitMatch: deployed == embedded. Nothing owed.
	schemaCheckExitMatch = 0
	// schemaCheckExitBehind: deployed < embedded — a migration is owed before
	// (or immediately after) this image is rolled. `roll-cloud.sh` refuses to
	// proceed on this code unless --allow-schema-ahead is passed (D3's naming is
	// symmetric with schemaCheckExitAhead; the flag name in the roll script
	// covers both directions of mismatch, see scripts/roll-cloud.sh).
	schemaCheckExitBehind = 2
	// schemaCheckExitAhead: deployed > embedded — this image's embedded
	// migration lineage is OLDER than what's already applied to the database.
	// Rolling it would run stale code against a newer schema.
	schemaCheckExitAhead = 3
)

// schemaCheckOutcome is the pure decision function (D5): given the embedded
// migration head and the deployed schema version, it returns the human-
// readable verdict line and the process exit code. Kept separate from
// newSchemaCheckCmd so it is unit-testable without a database or os.Exit.
func schemaCheckOutcome(embedded, deployed int) (message string, exitCode int) {
	switch {
	case deployed == embedded:
		return fmt.Sprintf("observer-cloud: schema OK — embedded head=%d deployed=%d", embedded, deployed), schemaCheckExitMatch
	case deployed < embedded:
		return fmt.Sprintf(
			"observer-cloud: schema-check: deployed schema (%d) is BEHIND the embedded migration head (%d) — "+
				"a migration is owed (run `observer-cloud migrate` against this database before, or immediately "+
				"after, rolling this image)", deployed, embedded), schemaCheckExitBehind
	default:
		return fmt.Sprintf(
			"observer-cloud: schema-check: deployed schema (%d) is AHEAD of the embedded migration head (%d) — "+
				"this image is older than the database; roll a newer image instead", deployed, embedded), schemaCheckExitAhead
	}
}

// newSchemaCheckCmd prints the embedded migration head, the deployed schema
// version, and exits 0/2/3 per schemaCheckOutcome (gap 4.3). It never mutates
// anything — this is `migrate`'s read-only sibling, meant to be run by
// scripts/roll-cloud.sh's pre-roll gate (D3) or an operator diagnosing a
// "roll shipped a migration but nobody ran migrate" incident
// (docs/cloud-intelligence-staging-launch-runbook.md §12f).
func newSchemaCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema-check",
		Short: "compare the embedded migration head against the deployed schema version",
		Long: "Exit codes: 0 = match (nothing owed), 2 = deployed is BEHIND the embedded\n" +
			"head (a migration is owed), 3 = deployed is AHEAD of the embedded head\n" +
			"(this image is too old for the database). Reads SBCI_PG_DSN; never writes.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			dsn, err := envDSN()
			if err != nil {
				return err
			}
			pool, err := clouddb.Open(ctx, dsn)
			if err != nil {
				return err
			}
			defer pool.Close()

			embedded, err := clouddb.MaxEmbeddedVersion()
			if err != nil {
				return err
			}
			deployed, err := clouddb.Version(ctx, pool)
			if err != nil {
				return err
			}

			message, code := schemaCheckOutcome(embedded, deployed)
			if code == schemaCheckExitMatch {
				fmt.Fprintln(cmd.OutOrStdout(), message)
				return nil
			}
			// A non-zero, non-1 exit code is the whole point of this command (D3's
			// pre-roll gate branches on it); main() maps an exitCodeError onto the
			// process exit status, so no os.Exit is needed here.
			return &exitCodeError{code: code, msg: message}
		},
	}
}
