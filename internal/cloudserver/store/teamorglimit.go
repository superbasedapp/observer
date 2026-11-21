package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// teamorglimit.go is the cap on how many team orgs one account may hold
// (managed-SaaS plan 07 wave 15, lead decisions W15-D12 and L-113
// C2.front-door-3; cloud 0094; docs/security.md PORTALORG-1 and PORTALORG-10).
//
// The default is DefaultMaxTeamOrgs. An operator raises (or lowers) one
// account's cap with `observer-cloud grant-plan team-orgs`, which appends a
// row to account_team_org_limits; the newest row wins. The console reads the
// caller's own cap through the 0094 definer sbci_team_org_limit(), which
// takes no argument and answers only for the caller's account context.
//
// ProvisionOrg checks the cap inside its own transaction, after taking a
// transaction-scoped advisory lock on the account: two concurrent creates by
// one account serialise on that lock, and the second one counts the first
// one's org once the first commits (READ COMMITTED takes a fresh snapshot per
// statement, and the count runs after the lock is granted). So the cap holds
// under concurrency without a table lock and without a constraint.

// DefaultMaxTeamOrgs is how many team orgs an account may hold when no
// operator raise names it (W15-D12).
const DefaultMaxTeamOrgs = 3

// MaxTeamOrgsCeiling bounds an operator raise (the 0094 CHECK holds the same).
const MaxTeamOrgsCeiling = 1000

// ErrTeamOrgLimit is the sentinel a create past the cap wraps; the error is a
// *TeamOrgLimitError carrying the cap.
var ErrTeamOrgLimit = errors.New("cloudserver/store: team org limit reached")

// TeamOrgLimitError is a refused team create: the account already holds
// Limit counted team orgs.
type TeamOrgLimitError struct {
	Limit int
}

func (e *TeamOrgLimitError) Error() string {
	return fmt.Sprintf("cloudserver/store: an account may hold at most %d team orgs", e.Limit)
}

// Unwrap makes errors.Is(err, ErrTeamOrgLimit) true.
func (e *TeamOrgLimitError) Unwrap() error { return ErrTeamOrgLimit }

// teamOrgCountedStatuses are the org states that count against the cap: an
// org being created, running, suspended, or scheduled for deletion (it can
// still be restored). An org being purged or purged frees its place.
const teamOrgCountedStatuses = `('provisioning', 'active', 'suspended', 'pending_deletion')`

// countTeamOrgsSQL counts the caller's team orgs: those it created or owns,
// read through the caller's membership (RLS, 0048), so it needs the account
// context WithAccount sets.
const countTeamOrgsSQL = `SELECT count(*)
	   FROM orgs o
	   JOIN org_members m ON m.org_id = o.org_id AND m.account_id = sbci_current_account()
	  WHERE o.kind = 'team'
	    AND (m.console_role = 'owner' OR o.created_by = sbci_current_account())
	    AND o.status IN ` + teamOrgCountedStatuses

// TeamOrgAllowance is how many team orgs an account holds against its cap.
type TeamOrgAllowance struct {
	// Used is the number of counted team orgs.
	Used int
	// Limit is the account's cap (DefaultMaxTeamOrgs unless raised).
	Limit int
	// Raised is true when an operator row sets Limit.
	Raised bool
}

// Remaining is how many more team orgs the account may create (never
// negative).
func (a TeamOrgAllowance) Remaining() int {
	if a.Used >= a.Limit {
		return 0
	}
	return a.Limit - a.Used
}

// teamOrgAllowanceTx reads the caller's cap and count inside the caller's
// account transaction.
func teamOrgAllowanceTx(ctx context.Context, tx pgx.Tx) (TeamOrgAllowance, error) {
	var a TeamOrgAllowance
	var limit *int32
	if err := tx.QueryRow(ctx, `SELECT sbci_team_org_limit()`).Scan(&limit); err != nil {
		return a, fmt.Errorf("read team org limit: %w", err)
	}
	a.Limit = DefaultMaxTeamOrgs
	if limit != nil {
		a.Limit, a.Raised = int(*limit), true
	}
	var n int64
	if err := tx.QueryRow(ctx, countTeamOrgsSQL).Scan(&n); err != nil {
		return a, fmt.Errorf("count team orgs: %w", err)
	}
	a.Used = int(n)
	return a, nil
}

// teamOrgCapLockTx takes the account's team-create advisory lock for the rest
// of the transaction.
func teamOrgCapLockTx(ctx context.Context, tx pgx.Tx, accountID string) error {
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('sbci_team_org_cap:' || $1::uuid::text, 0))`, accountID); err != nil {
		return fmt.Errorf("team org cap lock: %w", err)
	}
	return nil
}

// enforceTeamOrgCapTx refuses a team create when the account already holds
// its cap. It takes the account's advisory lock first (see the file comment).
func enforceTeamOrgCapTx(ctx context.Context, tx pgx.Tx, accountID string) error {
	if err := teamOrgCapLockTx(ctx, tx, accountID); err != nil {
		return err
	}
	a, err := teamOrgAllowanceTx(ctx, tx)
	if err != nil {
		return err
	}
	if a.Used >= a.Limit {
		return &TeamOrgLimitError{Limit: a.Limit}
	}
	return nil
}

// TeamOrgAllowance returns accountID's team org count and cap, as the
// console shows it before a create.
func (s *Store) TeamOrgAllowance(ctx context.Context, accountID string) (TeamOrgAllowance, error) {
	var out TeamOrgAllowance
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		a, err := teamOrgAllowanceTx(ctx, tx)
		out = a
		return err
	})
	if err != nil {
		return TeamOrgAllowance{}, fmt.Errorf("cloudserver/store.TeamOrgAllowance: %w", err)
	}
	return out, nil
}

// TeamOrgLimitRecord is one operator change of an account's cap.
type TeamOrgLimitRecord struct {
	AccountID   string
	MaxTeamOrgs int
	Actor       string
	Reason      string
	At          time.Time
}

// ErrTeamOrgLimitInput is a SetTeamOrgLimit refusal for bad input.
var ErrTeamOrgLimitInput = errors.New("cloudserver/store: team org limit input is invalid")

// SetTeamOrgLimit is the operator's raise (or lowering) of accountID's team
// org cap: it appends a row to account_team_org_limits (cloud 0094) with the
// actor "operator" and reason, and returns the account's previous cap. It
// runs as the store's role under WithSystem: only the operator role
// (sbci_app) holds INSERT. Lowering a cap below the account's current count
// is allowed; it blocks only further creates.
func (s *Store) SetTeamOrgLimit(ctx context.Context, accountID string, maxTeamOrgs int, reason string, now time.Time) (previous TeamOrgAllowance, err error) {
	reason = strings.TrimSpace(reason)
	if maxTeamOrgs < 0 || maxTeamOrgs > MaxTeamOrgsCeiling {
		return previous, fmt.Errorf("cloudserver/store.SetTeamOrgLimit: max must be 0 to %d: %w", MaxTeamOrgsCeiling, ErrTeamOrgLimitInput)
	}
	if reason == "" || len([]rune(reason)) > 1000 {
		return previous, fmt.Errorf("cloudserver/store.SetTeamOrgLimit: a reason of 1 to 1000 characters is required: %w", ErrTeamOrgLimitInput)
	}
	if _, err := uuid.Parse(accountID); err != nil {
		return previous, fmt.Errorf("cloudserver/store.SetTeamOrgLimit: %w", ErrNotFound)
	}
	now = nowOr(now).UTC()
	err = s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := teamOrgCapLockTx(ctx, tx, accountID); err != nil {
			return err
		}
		prev, err := latestTeamOrgLimitTx(ctx, tx, accountID)
		if err != nil {
			return err
		}
		previous = prev
		if _, err := tx.Exec(ctx,
			`INSERT INTO account_team_org_limits (account_id, max_team_orgs, actor, reason, at)
			 VALUES ($1::uuid, $2, 'operator', $3, $4)`, accountID, maxTeamOrgs, reason, now); err != nil {
			if isForeignKeyViolation(err) {
				return ErrNotFound
			}
			return fmt.Errorf("insert limit: %w", err)
		}
		return nil
	})
	if err != nil {
		return TeamOrgAllowance{}, fmt.Errorf("cloudserver/store.SetTeamOrgLimit: %w", err)
	}
	return previous, nil
}

// TeamOrgLimitHistory returns every operator change of accountID's cap,
// newest first (the CLI's show). Operator role only.
func (s *Store) TeamOrgLimitHistory(ctx context.Context, accountID string) ([]TeamOrgLimitRecord, error) {
	var out []TeamOrgLimitRecord
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT account_id::text, max_team_orgs, actor, reason, at
			   FROM account_team_org_limits WHERE account_id = $1::uuid ORDER BY seq DESC`, accountID)
		if err != nil {
			if isInvalidUUIDErr(err) {
				return ErrNotFound
			}
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r TeamOrgLimitRecord
			if err := rows.Scan(&r.AccountID, &r.MaxTeamOrgs, &r.Actor, &r.Reason, &r.At); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.TeamOrgLimitHistory: %w", err)
	}
	return out, nil
}

// latestTeamOrgLimitTx reads accountID's cap from the table directly (the
// operator role's path; the console uses the definer).
func latestTeamOrgLimitTx(ctx context.Context, tx pgx.Tx, accountID string) (TeamOrgAllowance, error) {
	a := TeamOrgAllowance{Limit: DefaultMaxTeamOrgs}
	var limit int
	err := tx.QueryRow(ctx,
		`SELECT max_team_orgs FROM account_team_org_limits WHERE account_id = $1::uuid ORDER BY seq DESC LIMIT 1`,
		accountID).Scan(&limit)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return a, nil
	case err != nil:
		return a, fmt.Errorf("read limit: %w", err)
	}
	a.Limit, a.Raised = limit, true
	return a, nil
}

// isForeignKeyViolation reports whether err is a foreign key violation (an
// operator row naming an account or org that does not exist).
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}
