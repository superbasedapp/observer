package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/entitlements"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// documents.go is the store seam of the signed documents (managed-SaaS M6.3,
// cloud migrations 0055-0056; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.5): the
// only SQL over org_entitlement_docs and availability_docs. Both are class S,
// so every statement runs in WithSystem. A document is stored exactly as the
// document signer returned it; the store re-applies the monotonic version
// rule (platformcontract.CheckDocumentVersion) under a transaction lock, so
// two concurrent writers cannot store versions out of order, and against the
// stream's version floor (cloud 0097, docfloor.go: a version the signer's
// record says it already signed is never stored after a restore). An entitlements
// body is also decoded and checked against the issuer's rules and its org
// before it is stored (ENTLWORK-1), so the table holds only documents a host
// would accept for that org.

// validIssuedBy mirrors the issued_by CHECK in 0055: "system" or
// "staff:" plus 1 to 64 of [A-Za-z0-9_-].
func validIssuedBy(v string) bool {
	if v == IssuedBySystem {
		return true
	}
	id, ok := strings.CutPrefix(v, "staff:")
	if !ok || id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// IssuedBySystem is the issued_by value of a document the control plane
// composed on its own.
const IssuedBySystem = "system"

// documentLockKey names the advisory lock that serialises one document
// stream (an org's entitlements, or the one availability stream).
func documentLockKey(kind platformcontract.DocumentKind, scope string) string {
	return "sbci-signed-doc:" + string(kind) + ":" + scope
}

// checkStoredDocument applies the shape rules before any SQL.
func checkStoredDocument(kind platformcontract.DocumentKind, scope string, version int64, body, sig []byte, keyID, issuedBy string) error {
	if _, err := platformcontract.DocumentSigningMessage(kind, scope, version, body); err != nil {
		return err
	}
	if len(sig) != 64 || len(keyID) != 43 {
		return errors.New("signature or key id has the wrong shape")
	}
	if !validIssuedBy(issuedBy) {
		return fmt.Errorf("issued_by %q is not system or staff:<id>", issuedBy)
	}
	return nil
}

// ErrEntitlementBody means an entitlements document's body is not one this
// control plane may store for the org: it does not decode, it breaks the
// issuer's rules (entitlements.Body.CheckIssuable), or it names another org.
var ErrEntitlementBody = errors.New("cloudserver/store: entitlements body refused")

// checkEntitlementBody applies the issuer's body rules before any SQL
// (ENTLWORK-1): the body decodes as an sbo-entitlements-body-v1 body, passes
// CheckIssuable (structural rules, this binary's vocabulary, the issued
// rules) and names orgID. The envelope signature is the caller's to verify
// (the worker verifies against the signer's published keys before it calls
// the store); the store holds no key.
func checkEntitlementBody(orgID string, body []byte) error {
	b, err := entitlements.Decode(body)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEntitlementBody, err)
	}
	if err := b.CheckIssuable(); err != nil {
		return fmt.Errorf("%w: %w", ErrEntitlementBody, err)
	}
	if b.Org != orgID {
		return fmt.Errorf("%w: body names org %q, not %q", ErrEntitlementBody, b.Org, orgID)
	}
	return nil
}

// InsertEntitlementDocument stores a signed entitlements document for orgID.
// The body must decode, pass the issuer's rules and name orgID
// (ErrEntitlementBody otherwise). A version not above the org's highest
// stored version is refused with an error wrapping
// platformcontract.ErrVersionNotNewer, and nothing is written.
func (s *Store) InsertEntitlementDocument(ctx context.Context, orgID string, doc platformcontract.EntitlementDocument, issuedBy string, issuedAt time.Time) error {
	if err := checkEntitlementDocument(orgID, doc, issuedBy); err != nil {
		return fmt.Errorf("cloudserver/store.InsertEntitlementDocument: %w", err)
	}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return insertEntitlementDocTx(ctx, tx, orgID, doc, issuedBy, issuedAt)
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.InsertEntitlementDocument: %w", err)
	}
	return nil
}

// IssueEntitlementDocument stores a signed entitlements document for orgID
// and enqueues its set_entitlements host-API intent in ONE transaction
// (design 4.5 "Process": the control-plane change and its intent commit
// together, or neither does). The document is checked exactly as
// InsertEntitlementDocument checks it; the intent must be a set_entitlements
// intent for the same org. It reports whether the intent was new (false: a
// row with its key already existed, which the deterministic key makes the
// same intent). A version not above the org's highest stored version is
// refused with an error wrapping platformcontract.ErrVersionNotNewer, and
// nothing is written.
func (s *Store) IssueEntitlementDocument(ctx context.Context, orgID string, doc platformcontract.EntitlementDocument, issuedBy string, issuedAt time.Time, intent OrgIntent) (bool, error) {
	if err := checkEntitlementDocument(orgID, doc, issuedBy); err != nil {
		return false, fmt.Errorf("cloudserver/store.IssueEntitlementDocument: %w", err)
	}
	if intent.OrgID != orgID || intent.Verb != OutboxSetEntitlements {
		return false, fmt.Errorf("cloudserver/store.IssueEntitlementDocument: %w: want a set_entitlements intent for the same org", ErrOrgIntentInvalid)
	}
	var enqueued bool
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := insertEntitlementDocTx(ctx, tx, orgID, doc, issuedBy, issuedAt); err != nil {
			return err
		}
		var err error
		enqueued, err = EnqueueOrgIntentTx(ctx, tx, intent)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.IssueEntitlementDocument: %w", err)
	}
	return enqueued, nil
}

// checkEntitlementDocument is the shape check plus the body check.
func checkEntitlementDocument(orgID string, doc platformcontract.EntitlementDocument, issuedBy string) error {
	if err := checkStoredDocument(platformcontract.KindEntitlements, orgID, doc.Version, doc.Body, doc.Signature, doc.KeyID, issuedBy); err != nil {
		return err
	}
	return checkEntitlementBody(orgID, doc.Body)
}

// insertEntitlementDocTx writes one document under the org's stream lock,
// re-applying the monotonic version rule against the higher of the stored
// maximum and the stream's version floor (cloud 0097, W16-D6: after a
// restore behind the signer's record, a version the signer already signed
// is never stored).
func insertEntitlementDocTx(ctx context.Context, tx pgx.Tx, orgID string, doc platformcontract.EntitlementDocument, issuedBy string, issuedAt time.Time) error {
	if err := lockDocumentStreamTx(ctx, tx, platformcontract.KindEntitlements, orgID); err != nil {
		return err
	}
	last, err := lastVersionTx(ctx, tx, platformcontract.KindEntitlements, orgID)
	if err != nil {
		return err
	}
	if err := platformcontract.CheckDocumentVersion(last, doc.Version); err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO org_entitlement_docs (org_id, version, body, signature, key_id, issued_at, issued_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		orgID, doc.Version, doc.Body, doc.Signature, doc.KeyID, issuedAt.UTC(), issuedBy)
	return err
}

// LatestEntitlementDocument returns the org's highest-version document, or
// ErrNotFound when none was issued.
func (s *Store) LatestEntitlementDocument(ctx context.Context, orgID string) (platformcontract.EntitlementDocument, error) {
	var d platformcontract.EntitlementDocument
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT version, body, signature, key_id FROM org_entitlement_docs
			  WHERE org_id = $1 ORDER BY version DESC LIMIT 1`, orgID).
			Scan(&d.Version, &d.Body, &d.Signature, &d.KeyID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return platformcontract.EntitlementDocument{}, ErrNotFound
	}
	if err != nil {
		return platformcontract.EntitlementDocument{}, fmt.Errorf("cloudserver/store.LatestEntitlementDocument: %w", err)
	}
	return d, nil
}

// InsertAvailabilityDocument stores a signed availability envelope. A version
// not above the highest stored one is refused with an error wrapping
// platformcontract.ErrVersionNotNewer, and nothing is written.
func (s *Store) InsertAvailabilityDocument(ctx context.Context, doc platformcontract.AvailabilityDocument, issuedBy string, issuedAt time.Time) error {
	if err := checkStoredDocument(platformcontract.KindAvailability, platformcontract.AvailabilityScope, doc.Version, doc.Body, doc.Signature, doc.KeyID, issuedBy); err != nil {
		return fmt.Errorf("cloudserver/store.InsertAvailabilityDocument: %w", err)
	}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return insertAvailabilityDocTx(ctx, tx, doc, issuedBy, issuedAt)
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.InsertAvailabilityDocument: %w", err)
	}
	return nil
}

// insertAvailabilityDocTx writes one envelope under the availability
// stream's lock, re-applying the monotonic version rule against the higher
// of the stored maximum and the stream's version floor. The caller has run
// checkStoredDocument.
func insertAvailabilityDocTx(ctx context.Context, tx pgx.Tx, doc platformcontract.AvailabilityDocument, issuedBy string, issuedAt time.Time) error {
	if err := lockDocumentStreamTx(ctx, tx, platformcontract.KindAvailability, platformcontract.AvailabilityScope); err != nil {
		return err
	}
	last, err := lastVersionTx(ctx, tx, platformcontract.KindAvailability, platformcontract.AvailabilityScope)
	if err != nil {
		return err
	}
	if err := platformcontract.CheckDocumentVersion(last, doc.Version); err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO availability_docs (version, body, signature, key_id, issued_at, issued_by)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		doc.Version, doc.Body, doc.Signature, doc.KeyID, issuedAt.UTC(), issuedBy)
	return err
}

// LatestAvailabilityDocument returns the highest-version envelope, or
// ErrNotFound when none was issued.
func (s *Store) LatestAvailabilityDocument(ctx context.Context) (platformcontract.AvailabilityDocument, error) {
	var d platformcontract.AvailabilityDocument
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT version, body, signature, key_id FROM availability_docs ORDER BY version DESC LIMIT 1`).
			Scan(&d.Version, &d.Body, &d.Signature, &d.KeyID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return platformcontract.AvailabilityDocument{}, ErrNotFound
	}
	if err != nil {
		return platformcontract.AvailabilityDocument{}, fmt.Errorf("cloudserver/store.LatestAvailabilityDocument: %w", err)
	}
	return d, nil
}
