package diag

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// grantintegrity.go — doctor's half of the Track C item 1 runtime grant
// re-verification (docs/plans/org-guardrail-control-wave-2026-09-21.md).
//
// The daemon re-verifies the stored grant on every identity refresh and
// resolves a tampered document to govern.StateGrantSignatureInvalid. doctor
// runs OUT of the daemon's process and cannot read that state, so it repeats
// the check here from the two rows involved — exactly the same relationship
// checkGovernance already has with the daemon's in-memory sidecar write
// error.
//
// internal/diag deliberately depends on neither internal/store nor
// internal/orgclient (the "keep diag standalone" discipline set by
// checkOrgEnrolment), so both rows are read with one raw SELECT each and the
// key-material row's path suffix is duplicated as a literal below.

// grantIntegrity is doctor's tri-state, mirroring govern.GrantIntegrity. It
// is a local copy for the same reason the SQL is local: diag does not import
// the daemon's packages.
type grantIntegrity string

const (
	grantIntegrityUnchecked grantIntegrity = "unchecked"
	grantIntegrityValid     grantIntegrity = "valid"
	grantIntegrityInvalid   grantIntegrity = "invalid"
)

// orgKeyMaterialSuffix duplicates orgclient.OrgKeyMaterialSuffix. ONE OWNER
// still applies: orgclient writes the row, this is a read-only mirror of its
// path convention, duplicated rather than imported to keep diag standalone
// (the api/policystate.go policyStateDirectiveClasses precedent).
const orgKeyMaterialSuffix = "#policy-key-material"

// checkStoredGrantIntegrity re-verifies the node's stored grant against the
// org distribution public key recorded at enrolment.
//
// It returns the tri-state plus a human detail line. Every "we cannot check"
// path — no grant, no key material, an unreadable row — is Unchecked, never
// Invalid: a node that legitimately holds no key material must not be
// reported as tampered with.
func checkStoredGrantIntegrity(ctx context.Context, database *sql.DB) (grantIntegrity, string) {
	if database == nil {
		return grantIntegrityUnchecked, ""
	}
	var (
		orgID, orgServerURL, keyPin string
		authorityJSON               string
		grantedAt, signedExpiresAt  string
		consentMode, consentActor   string
		signature                   string
		replacementGeneration       int64
	)
	err := database.QueryRowContext(ctx, `
		SELECT org_id, org_server_url, key_pin_sha256, authority_json,
		       granted_at, signed_expires_at, consent_mode, consent_actor,
		       signature, replacement_generation
		  FROM org_enrolment_grant ORDER BY generation DESC LIMIT 1`).
		Scan(&orgID, &orgServerURL, &keyPin, &authorityJSON, &grantedAt,
			&signedExpiresAt, &consentMode, &consentActor, &signature, &replacementGeneration)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return grantIntegrityUnchecked, ""
	case err != nil:
		return grantIntegrityUnchecked, "grant re-verification: could not read the grant row (" + err.Error() + ")"
	}

	pub, ok := loadOrgKeyMaterial(ctx, database, orgServerURL)
	if !ok {
		return grantIntegrityUnchecked,
			"grant re-verification: NOT CHECKED — this machine holds no organisation signing key material " +
				"(a pre-2026-09-13 enrolment, or a server that delivered no policy key). Re-enrol to record it."
	}

	doc := orgcontract.StoredGrantDocument{
		OrgID:                 orgID,
		OrgServerURL:          orgServerURL,
		KeyPinSHA256:          keyPin,
		Authority:             decodeAuthorityJSON(authorityJSON),
		GrantedAt:             normalizeStoredStamp(grantedAt),
		ExpiresAt:             normalizeStoredStamp(signedExpiresAt),
		ConsentMode:           consentMode,
		ConsentActor:          consentActor,
		Signature:             signature,
		ReplacementGeneration: replacementGeneration,
	}
	switch verr := orgcontract.VerifyStoredGrant(doc, pub); {
	case verr == nil:
		return grantIntegrityValid, "grant re-verification: signature verifies against the organisation key recorded at enrolment"
	case errors.Is(verr, orgcontract.ErrStoredGrantUncheckable):
		return grantIntegrityUnchecked, "grant re-verification: NOT CHECKED — no usable organisation key material"
	default:
		return grantIntegrityInvalid,
			"grant re-verification: FAILED — the stored grant is not the document this organisation signed (" + verr.Error() + ")"
	}
}

// loadOrgKeyMaterial reads the enrolment key-material row for orgURL and
// validates it against its own content hash, mirroring
// orgclient.materialFromStates: a self-contradicting row is ABSENT, not
// trusted.
func loadOrgKeyMaterial(ctx context.Context, database *sql.DB, orgURL string) (ed25519.PublicKey, bool) {
	if orgURL == "" {
		return nil, false
	}
	var version, contentHash string
	err := database.QueryRowContext(ctx, `
		SELECT version, content_hash FROM guard_policy_state
		 WHERE layer = 'org' AND path = ? ORDER BY id DESC LIMIT 1`, orgURL+orgKeyMaterialSuffix).
		Scan(&version, &contentHash)
	if err != nil {
		return nil, false
	}
	raw, derr := base64.StdEncoding.DecodeString(version)
	if derr != nil || len(raw) != ed25519.PublicKeySize {
		return nil, false
	}
	if orgcontract.PublicKeyPinHash(raw) != contentHash {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}

// decodeAuthorityJSON mirrors store.loadEnrolmentGrant's fail-safe decode: a
// corrupt list yields nothing rather than an error. A corrupt list will of
// course not verify, which is the correct loud answer.
func decodeAuthorityJSON(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// normalizeStoredStamp re-renders a stored RFC3339 timestamp in the exact
// spelling the signer used (UTC, second resolution), matching
// store.formatGrantTime. An unparseable or empty value renders empty, which
// is what an absent wire field signed as.
func normalizeStoredStamp(raw string) string {
	if raw == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return t.UTC().Format(time.RFC3339)
}
