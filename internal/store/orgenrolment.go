package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Enrolment is the agent's singleton org_enrolment row (id = 1). It records
// which org this agent enrolled in and under which identity; the bearer and
// signing key themselves live in the OS keychain, not here — bearer_key_id is
// only the keychain service handle.
type Enrolment struct {
	OrgID        string
	OrgName      string
	OrgServerURL string
	UserID       string // SCIM user id
	UserEmail    string
	EnrolledAt   string // RFC3339
	BearerKeyID  string // keychain service handle (not the secret itself)
	// Tenancy is the enrolment class: "individual" (default/zero, BYO —
	// "Never server-forced" holds absolutely) or "managed" (org-provisioned,
	// opted into comprehensive admin control at enrolment). It is written only
	// here from the enrol response and read everywhere else; the empty string
	// is treated as "individual".
	Tenancy string
	// DisplayName and OnlineURL are the connection's name and online
	// dashboard address as `observer connect` learnt them from the cloud's
	// approval (agent migration 255). Read-only here: WriteEnrolment clears
	// them and SetEnrolmentConnection writes them. OnlineURL is for a button,
	// never for CLI text.
	DisplayName string
	OnlineURL   string
	// OwnerManaged is the enrol response's OwnerManaged: the organization is
	// the developer's own (a personal organization of one, managed by its
	// owner). Stored since agent migration 261: WriteEnrolment writes it (a
	// re-enrol overwrites it), LoadEnrolment reads it, and
	// SetEnrolmentOwnerManaged refreshes it from the push acknowledgment
	// (orgcontract.PushResponse.OwnerManaged) so a machine enrolled before
	// the column existed heals. It picks the enrolment's share-default row
	// and, on a managed enrolment, the owner audience of the managed-default
	// visibility table (govern.Grant.OwnerManaged). It grants no authority.
	OwnerManaged bool
	// SDKKeys is the enrol response's SDKKeys (orgcontract.SDKKeysMember,
	// SDKKeysAdminOnly, or "" when the server did not say), set IN MEMORY by
	// the enrolment that just ran so its SDK key hint can be worded. It is
	// NOT stored: WriteEnrolment ignores it and LoadEnrolment leaves it "".
	SDKKeys string
}

// IsManaged reports whether this enrolment opted into Enterprise-Managed
// Tenancy. Nil-safe: a nil Enrolment (not enrolled) is never managed. The
// canonical class strings live in internal/orgcontract (the wire package both
// the node and the org server share) so the two sides cannot drift.
func (e *Enrolment) IsManaged() bool {
	return e != nil && e.Tenancy == orgcontract.TenancyManaged
}

// WriteEnrolment upserts the singleton org_enrolment row. EnrolledAt defaults
// to now (UTC, RFC3339) when empty.
func (s *Store) WriteEnrolment(ctx context.Context, e Enrolment) error {
	if e.EnrolledAt == "" {
		e.EnrolledAt = time.Now().UTC().Format(time.RFC3339)
	}
	if e.Tenancy == "" {
		e.Tenancy = orgcontract.TenancyIndividual
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO org_enrolment
		   (id, org_id, org_name, org_server_url, user_id, user_email, enrolled_at, bearer_key_id, tenancy, owner_managed)
		 VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   org_id         = excluded.org_id,
		   org_name       = excluded.org_name,
		   org_server_url = excluded.org_server_url,
		   user_id        = excluded.user_id,
		   user_email     = excluded.user_email,
		   enrolled_at    = excluded.enrolled_at,
		   bearer_key_id  = excluded.bearer_key_id,
		   tenancy        = excluded.tenancy,
		   owner_managed  = excluded.owner_managed,
		   display_name   = '',
		   online_url     = ''`,
		e.OrgID, e.OrgName, e.OrgServerURL, e.UserID, e.UserEmail, e.EnrolledAt, e.BearerKeyID, e.Tenancy, boolInt(e.OwnerManaged))
	if err != nil {
		return fmt.Errorf("store.WriteEnrolment: %w", err)
	}
	return nil
}

// SetEnrolmentOrgName records a renamed organization's display name on the
// enrolment row (T-862: the org server carries its current name on every push
// acknowledgment). It changes nothing else, and only while the row still
// names orgID, so a late acknowledgment from an org this node has since left
// or replaced cannot relabel the new enrolment. It reports whether the name
// changed.
func (s *Store) SetEnrolmentOrgName(ctx context.Context, orgID, name string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE org_enrolment SET org_name = ? WHERE id = 1 AND org_id = ? AND org_name <> ?`,
		name, orgID, name)
	if err != nil {
		return false, fmt.Errorf("store.SetEnrolmentOrgName: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store.SetEnrolmentOrgName: %w", err)
	}
	return n > 0, nil
}

// SetEnrolmentOwnerManaged records whether the enrolment's organization is the
// developer's own, as the org server states it on a push acknowledgment
// (orgcontract.PushResponse.OwnerManaged). It changes nothing else, only
// while the row still names orgID (a late acknowledgment from an org this
// node has since left cannot relabel the new enrolment), and only when the
// value differs. It reports whether it changed.
func (s *Store) SetEnrolmentOwnerManaged(ctx context.Context, orgID string, ownerManaged bool) (bool, error) {
	v := boolInt(ownerManaged)
	res, err := s.db.ExecContext(ctx,
		`UPDATE org_enrolment SET owner_managed = ? WHERE id = 1 AND org_id = ? AND owner_managed <> ?`,
		v, orgID, v)
	if err != nil {
		return false, fmt.Errorf("store.SetEnrolmentOwnerManaged: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store.SetEnrolmentOwnerManaged: %w", err)
	}
	return n > 0, nil
}

// LoadEnrolment returns the singleton org_enrolment row, or (nil, nil) when the
// agent is not enrolled (no row, or a pre-028 schema with no table). The
// not-enrolled path is never an error — org mode being absent is the default.
func (s *Store) LoadEnrolment(ctx context.Context) (*Enrolment, error) {
	return loadEnrolment(ctx, s.db)
}

func loadEnrolment(ctx context.Context, q querier) (*Enrolment, error) {
	var e Enrolment
	var ownerManaged int64
	err := q.QueryRowContext(ctx,
		`SELECT org_id, org_name, org_server_url, user_id, user_email, enrolled_at, bearer_key_id, tenancy,
		        display_name, online_url, owner_managed
		   FROM org_enrolment WHERE id = 1`).
		Scan(&e.OrgID, &e.OrgName, &e.OrgServerURL, &e.UserID, &e.UserEmail, &e.EnrolledAt, &e.BearerKeyID, &e.Tenancy,
			&e.DisplayName, &e.OnlineURL, &ownerManaged)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store.LoadEnrolment: %w", err)
	}
	if e.Tenancy == "" {
		e.Tenancy = orgcontract.TenancyIndividual
	}
	e.OwnerManaged = ownerManaged != 0
	return &e, nil
}

// SetEnrolmentConnection records the connection's display name and online
// address on the enrolment in force (agent migration 255), only when that
// enrolment is still for orgID: a connect that lost a race to another
// enrolment writes nothing. It reports whether it wrote. The one writer of
// the two columns besides WriteEnrolment, which clears them.
func (s *Store) SetEnrolmentConnection(ctx context.Context, orgID, displayName, onlineURL string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE org_enrolment SET display_name = ?, online_url = ? WHERE id = 1 AND org_id = ?`,
		strings.TrimSpace(displayName), strings.TrimSpace(onlineURL), orgID)
	if err != nil {
		return false, fmt.Errorf("store.SetEnrolmentConnection: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store.SetEnrolmentConnection: rows: %w", err)
	}
	return n == 1, nil
}

// DeleteEnrolment removes the org_enrolment row (used by `observer unenroll`)
// and every piece of node-local state that belongs to the org being left:
//
//   - the push history (ClearLastPushState: the stored last-push payload,
//     the org_push_log rows and an open push breaker), since none of it
//     describes anything the node still does once unenrolled (T-373);
//   - every cached org document bound to the departing identity, through
//     ClearIdentityBoundDocs (identitydocs.go): the announcement banner, the
//     display, routing and AI tool policies, access grants and queued
//     requests, the intel cache, terms, outbox and consent, the org's prices
//     and budget, the guard bundle ETag and the org's update manifest. The
//     same table runs when orgclient.Enroll re-enrols into a different org
//     or as a different member, so the two paths cannot drift (T-393). Two
//     reasons recur: a departed org's document must not keep applying, and
//     its TOFU-pinned key or highest version must not refuse the next org's
//     documents as a "key CHANGED" attack or a downgrade.
//
// Absence is not an error. The push cursor in schema_meta is intentionally
// left intact: a later re-enrol reseeds it from CurrentMaxIDs, so activity
// in the unenrolled gap is never retroactively shared.
func (s *Store) DeleteEnrolment(ctx context.Context) error {
	// The org being left, read BEFORE the row goes, so the org-plane consent
	// and cache cleanup below can name it in the local audit.
	leaving, err := s.LoadEnrolment(ctx)
	if err != nil {
		return fmt.Errorf("store.DeleteEnrolment: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM org_enrolment WHERE id = 1`); err != nil {
		return fmt.Errorf("store.DeleteEnrolment: %w", err)
	}
	// One owner with the re-enrol path (orgclient.Enroll): before T-373 only
	// the payload went here, so an unenrolled node kept its org_push_log and
	// the dashboard kept reporting a last push to an org it had left.
	if err := s.ClearLastPushState(ctx); err != nil {
		return fmt.Errorf("store.DeleteEnrolment: %w", err)
	}
	// Stop re-send tracking (agent migration 140): without an org there is
	// nothing to converge, and the floors are what arm the change triggers.
	if err := s.clearPushTracking(ctx); err != nil {
		return fmt.Errorf("store.DeleteEnrolment: %w", err)
	}
	if err := s.ClearIdentityBoundDocs(ctx, leaving); err != nil {
		return fmt.Errorf("store.DeleteEnrolment: %w", err)
	}
	return nil
}
