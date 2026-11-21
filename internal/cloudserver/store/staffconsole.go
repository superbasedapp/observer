package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// staffconsole.go is the staff console's read seam over the org registry
// (managed-SaaS plan 07 M6.8, the staff UI window; cloud migration 0133). The
// staff role (sbci_staff) holds no grant on any org, billing or usage table,
// so every read here goes through a 0133 SECURITY DEFINER function that only
// sbci_staff may execute, and returns registry and control-plane facts only:
// no member id, account, email, payload or tenant data. Nothing here writes.

// staffOrgDetailUsageDays is how many usage days an org's detail carries.
const staffOrgDetailUsageDays = 30

// StaffOrgGrantState is an org's newest plan grant row (the row that decides).
type StaffOrgGrantState struct {
	Action         string     `json:"action"`
	PlanName       string     `json:"plan_name,omitempty"`
	PlanVersion    int        `json:"plan_version,omitempty"`
	EffectiveUntil *time.Time `json:"effective_until,omitempty"`
}

// StaffOrgSubscription is the org's most relevant subscription (live first).
type StaffOrgSubscription struct {
	Status      string     `json:"status"`
	PlanName    string     `json:"plan_name,omitempty"`
	PlanVersion int        `json:"plan_version,omitempty"`
	PeriodEnd   *time.Time `json:"period_end,omitempty"`
}

// StaffOrgUsageDay is one daily usage report's counts.
type StaffOrgUsageDay struct {
	// Day is the report day, YYYY-MM-DD.
	Day               string `json:"day"`
	Seats             int    `json:"seats"`
	Members           int64  `json:"members"`
	Sessions          int64  `json:"sessions,omitempty"`
	MachineIdentities int64  `json:"machine_identities,omitempty"`
}

// StaffDocRef is a signed document's version and issue time.
type StaffDocRef struct {
	Version  int64     `json:"version"`
	IssuedAt time.Time `json:"issued_at"`
}

// StaffOrg is one org as the staff console lists it.
type StaffOrg struct {
	OrgID               string                `json:"org_id"`
	Kind                string                `json:"kind"`
	Slug                string                `json:"slug"`
	DisplayName         string                `json:"display_name"`
	Status              string                `json:"status"`
	Tenancy             string                `json:"tenancy"`
	HostID              string                `json:"host_id,omitempty"`
	PlatformRailEnabled bool                  `json:"platform_rail_enabled"`
	LifecycleGen        int64                 `json:"lifecycle_gen"`
	CreatedAt           time.Time             `json:"created_at"`
	UpdatedAt           time.Time             `json:"updated_at"`
	Members             int64                 `json:"members"`
	Grant               *StaffOrgGrantState   `json:"grant,omitempty"`
	Subscription        *StaffOrgSubscription `json:"subscription,omitempty"`
	Usage               *StaffOrgUsageDay     `json:"usage,omitempty"`
	Entitlements        *StaffDocRef          `json:"entitlements,omitempty"`
}

// StaffOrgGrantRow is one org_plan_grants history row, with its actor and
// reason.
type StaffOrgGrantRow struct {
	Seq            int64      `json:"seq"`
	Action         string     `json:"action"`
	PlanName       string     `json:"plan_name,omitempty"`
	PlanVersion    int        `json:"plan_version,omitempty"`
	EffectiveUntil *time.Time `json:"effective_until,omitempty"`
	Actor          string     `json:"actor"`
	Reason         string     `json:"reason"`
	At             time.Time  `json:"at"`
}

// StaffSignedDoc is a signed document as issued: its body is the signed bytes
// as JSON (Body), or, when the bytes are not JSON, only their length.
type StaffSignedDoc struct {
	Version   int64           `json:"version"`
	KeyID     string          `json:"key_id"`
	IssuedAt  time.Time       `json:"issued_at"`
	IssuedBy  string          `json:"issued_by"`
	Body      json.RawMessage `json:"body,omitempty"`
	BodyBytes int             `json:"body_bytes"`
}

// StaffOrgIntent is one org_outbox intent, without payload or key.
type StaffOrgIntent struct {
	Verb           string     `json:"verb"`
	State          string     `json:"state"`
	Attempts       int        `json:"attempts"`
	LastErrorClass string     `json:"last_error_class,omitempty"`
	NextAttemptAt  time.Time  `json:"next_attempt_at"`
	CreatedAt      time.Time  `json:"created_at"`
	DoneAt         *time.Time `json:"done_at,omitempty"`
}

// StaffOrgDeletion is an org's newest deletion request, without its
// requesting account.
type StaffOrgDeletion struct {
	State         string     `json:"state"`
	BlockedReason string     `json:"blocked_reason,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DoneAt        *time.Time `json:"done_at,omitempty"`
}

// StaffOrgDetail is one org with its history.
type StaffOrgDetail struct {
	Org          StaffOrg           `json:"org"`
	Grants       []StaffOrgGrantRow `json:"grants"`
	Usage        []StaffOrgUsageDay `json:"usage"`
	Entitlements *StaffSignedDoc    `json:"entitlements,omitempty"`
	Intents      []StaffOrgIntent   `json:"intents"`
	Deletion     *StaffOrgDeletion  `json:"deletion,omitempty"`
}

// ListStaffOrgs returns every org (newest first, at most 2000) as the staff
// console lists it.
func (s *Store) ListStaffOrgs(ctx context.Context) ([]StaffOrg, error) {
	out := []StaffOrg{}
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = staffOrgsTx(ctx, tx, nil)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListStaffOrgs: %w", err)
	}
	return out, nil
}

// StaffOrgDetail returns one org with its plan grant history, its last 30
// usage days, its newest entitlements document, its newest 50 lifecycle
// intents and its newest deletion request. ErrNotFound when there is no such
// org (or orgID is not a UUID).
func (s *Store) StaffOrgDetail(ctx context.Context, orgID string) (StaffOrgDetail, error) {
	id, err := uuid.Parse(strings.TrimSpace(orgID))
	if err != nil {
		return StaffOrgDetail{}, ErrNotFound
	}
	var out StaffOrgDetail
	err = s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		orgs, err := staffOrgsTx(ctx, tx, &id)
		if err != nil {
			return err
		}
		if len(orgs) == 0 {
			return ErrNotFound
		}
		out.Org = orgs[0]
		steps := []func(context.Context, pgx.Tx, uuid.UUID, *StaffOrgDetail) error{
			staffOrgGrantsTx, staffOrgUsageTx, staffOrgEntitlementsTx, staffOrgIntentsTx, staffOrgDeletionTx,
		}
		for _, step := range steps {
			if err := step(ctx, tx, id, &out); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		return StaffOrgDetail{}, ErrNotFound
	}
	if err != nil {
		return StaffOrgDetail{}, fmt.Errorf("cloudserver/store.StaffOrgDetail: %w", err)
	}
	return out, nil
}

// StaffAvailabilityDocument returns the newest issued availability envelope,
// or ErrNotFound when none has been issued.
func (s *Store) StaffAvailabilityDocument(ctx context.Context) (StaffSignedDoc, error) {
	var out StaffSignedDoc
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		doc, err := scanStaffSignedDoc(tx.QueryRow(ctx,
			`SELECT version, key_id, issued_at, issued_by, body FROM sbci_staff_availability_doc()`))
		out = doc
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return StaffSignedDoc{}, ErrNotFound
	}
	if err != nil {
		return StaffSignedDoc{}, fmt.Errorf("cloudserver/store.StaffAvailabilityDocument: %w", err)
	}
	return out, nil
}

func staffOrgsTx(ctx context.Context, tx pgx.Tx, id *uuid.UUID) ([]StaffOrg, error) {
	var arg any
	if id != nil {
		arg = id.String()
	}
	rows, err := tx.Query(ctx,
		`SELECT org_id::text, kind, slug, display_name, status, tenancy, coalesce(host_id, ''),
		        platform_rail_enabled, lifecycle_gen, created_at, updated_at, members,
		        grant_action, grant_plan, grant_version, grant_until,
		        sub_status, sub_plan, sub_version, sub_period_end,
		        usage_day, usage_seats, usage_members,
		        entitlements_version, entitlements_issued
		   FROM sbci_staff_orgs($1::uuid)`, arg)
	if err != nil {
		return nil, fmt.Errorf("list orgs: %w", err)
	}
	defer rows.Close()
	out := []StaffOrg{}
	for rows.Next() {
		var o StaffOrg
		var (
			gAction, gPlan, sStatus, sPlan *string
			gVersion, sVersion, uSeats     *int32
			gUntil, sEnd, eIssued          *time.Time
			uDay                           *time.Time
			uMembers, eVersion             *int64
		)
		if err := rows.Scan(&o.OrgID, &o.Kind, &o.Slug, &o.DisplayName, &o.Status, &o.Tenancy, &o.HostID,
			&o.PlatformRailEnabled, &o.LifecycleGen, &o.CreatedAt, &o.UpdatedAt, &o.Members,
			&gAction, &gPlan, &gVersion, &gUntil,
			&sStatus, &sPlan, &sVersion, &sEnd,
			&uDay, &uSeats, &uMembers,
			&eVersion, &eIssued); err != nil {
			return nil, fmt.Errorf("scan org: %w", err)
		}
		if gAction != nil {
			o.Grant = &StaffOrgGrantState{Action: *gAction, PlanName: derefString(gPlan), PlanVersion: int(derefInt32(gVersion)), EffectiveUntil: gUntil}
		}
		if sStatus != nil {
			o.Subscription = &StaffOrgSubscription{Status: *sStatus, PlanName: derefString(sPlan), PlanVersion: int(derefInt32(sVersion)), PeriodEnd: sEnd}
		}
		if uDay != nil {
			o.Usage = &StaffOrgUsageDay{Day: uDay.Format(time.DateOnly), Seats: int(derefInt32(uSeats)), Members: derefInt64(uMembers)}
		}
		if eVersion != nil && eIssued != nil {
			o.Entitlements = &StaffDocRef{Version: *eVersion, IssuedAt: *eIssued}
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func staffOrgGrantsTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, d *StaffOrgDetail) error {
	rows, err := tx.Query(ctx,
		`SELECT seq, action, coalesce(plan_name, ''), coalesce(plan_version, 0), effective_until, actor, reason, at
		   FROM sbci_staff_org_plan_grants($1::uuid)`, id.String())
	if err != nil {
		return fmt.Errorf("list plan grants: %w", err)
	}
	defer rows.Close()
	d.Grants = []StaffOrgGrantRow{}
	for rows.Next() {
		var g StaffOrgGrantRow
		if err := rows.Scan(&g.Seq, &g.Action, &g.PlanName, &g.PlanVersion, &g.EffectiveUntil, &g.Actor, &g.Reason, &g.At); err != nil {
			return fmt.Errorf("scan plan grant: %w", err)
		}
		d.Grants = append(d.Grants, g)
	}
	return rows.Err()
}

func staffOrgUsageTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, d *StaffOrgDetail) error {
	rows, err := tx.Query(ctx,
		`SELECT day, seats, members, sessions, machine_identities FROM sbci_staff_org_usage($1::uuid, $2)`,
		id.String(), staffOrgDetailUsageDays)
	if err != nil {
		return fmt.Errorf("list usage: %w", err)
	}
	defer rows.Close()
	d.Usage = []StaffOrgUsageDay{}
	for rows.Next() {
		var u StaffOrgUsageDay
		var day time.Time
		var seats int32
		if err := rows.Scan(&day, &seats, &u.Members, &u.Sessions, &u.MachineIdentities); err != nil {
			return fmt.Errorf("scan usage: %w", err)
		}
		u.Day, u.Seats = day.Format(time.DateOnly), int(seats)
		d.Usage = append(d.Usage, u)
	}
	return rows.Err()
}

func staffOrgEntitlementsTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, d *StaffOrgDetail) error {
	doc, err := scanStaffSignedDoc(tx.QueryRow(ctx,
		`SELECT version, key_id, issued_at, issued_by, body FROM sbci_staff_org_entitlements($1::uuid)`, id.String()))
	switch {
	case errors.Is(err, ErrNotFound):
		return nil
	case err != nil:
		return err
	}
	d.Entitlements = &doc
	return nil
}

func staffOrgIntentsTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, d *StaffOrgDetail) error {
	rows, err := tx.Query(ctx,
		`SELECT verb, state, attempts, coalesce(last_error_class, ''), next_attempt_at, created_at, done_at
		   FROM sbci_staff_org_intents($1::uuid)`, id.String())
	if err != nil {
		return fmt.Errorf("list intents: %w", err)
	}
	defer rows.Close()
	d.Intents = []StaffOrgIntent{}
	for rows.Next() {
		var in StaffOrgIntent
		var attempts int32
		if err := rows.Scan(&in.Verb, &in.State, &attempts, &in.LastErrorClass, &in.NextAttemptAt, &in.CreatedAt, &in.DoneAt); err != nil {
			return fmt.Errorf("scan intent: %w", err)
		}
		in.Attempts = int(attempts)
		d.Intents = append(d.Intents, in)
	}
	return rows.Err()
}

func staffOrgDeletionTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, d *StaffOrgDetail) error {
	var del StaffOrgDeletion
	var blocked *string
	err := tx.QueryRow(ctx,
		`SELECT state, blocked_reason, created_at, updated_at, done_at FROM sbci_staff_org_deletion($1::uuid)`, id.String()).
		Scan(&del.State, &blocked, &del.CreatedAt, &del.UpdatedAt, &del.DoneAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("read deletion: %w", err)
	}
	del.BlockedReason = derefString(blocked)
	d.Deletion = &del
	return nil
}

// scanStaffSignedDoc scans one (version, key_id, issued_at, issued_by, body)
// row; ErrNotFound when there is none.
func scanStaffSignedDoc(row pgx.Row) (StaffSignedDoc, error) {
	var doc StaffSignedDoc
	var body []byte
	err := row.Scan(&doc.Version, &doc.KeyID, &doc.IssuedAt, &doc.IssuedBy, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return StaffSignedDoc{}, ErrNotFound
	}
	if err != nil {
		return StaffSignedDoc{}, fmt.Errorf("read signed document: %w", err)
	}
	doc.BodyBytes = len(body)
	if json.Valid(body) {
		doc.Body = body
	}
	return doc, nil
}

func derefInt32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// StaffActionFilter narrows a read of the staff action log. Zero fields do not
// filter.
type StaffActionFilter struct {
	// Limit is 1..500 (out of range means 100).
	Limit int
	// OrgID keeps the rows about one org.
	OrgID string
	// Verb keeps one verb (a staffauth.Verb).
	Verb string
	// Actor keeps one actor ("operator" or "staff:<id>").
	Actor string
	// Before keeps rows strictly older than it (the next page's cursor is the
	// last row's At).
	Before time.Time
}

// ListStaffActionsFiltered returns the newest entries of the action log that
// match f. An OrgID that is not a UUID matches nothing.
func (s *Store) ListStaffActionsFiltered(ctx context.Context, f StaffActionFilter) ([]StaffAction, error) {
	if f.Limit <= 0 || f.Limit > staffActionListMax {
		f.Limit = 100
	}
	out := []StaffAction{}
	where := []string{"true"}
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if org := strings.TrimSpace(f.OrgID); org != "" {
		id, err := uuid.Parse(org)
		if err != nil {
			return out, nil
		}
		add("org_id = $%d::uuid", id.String())
	}
	if v := strings.TrimSpace(f.Verb); v != "" {
		add("verb = $%d", v)
	}
	if a := strings.TrimSpace(f.Actor); a != "" {
		add("actor = $%d", a)
	}
	if !f.Before.IsZero() {
		add("at < $%d", f.Before)
	}
	args = append(args, f.Limit)
	q := `SELECT action_id::text, at, actor, verb, coalesce(subject_staff_id::text, ''),
	             coalesce(org_id::text, ''), coalesce(target, ''), detail, reason, result
	        FROM staff_actions WHERE ` + strings.Join(where, " AND ") +
		fmt.Sprintf(` ORDER BY at DESC, action_id DESC LIMIT $%d`, len(args))
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list actions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var a StaffAction
			var detail []byte
			if err := rows.Scan(&a.ActionID, &a.At, &a.Actor, &a.Verb, &a.SubjectStaffID, &a.OrgID, &a.Target, &detail, &a.Reason, &a.Result); err != nil {
				return fmt.Errorf("scan action: %w", err)
			}
			if len(detail) > 0 {
				a.Detail = detail
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListStaffActionsFiltered: %w", err)
	}
	return out, nil
}
