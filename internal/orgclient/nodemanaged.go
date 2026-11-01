package orgclient

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/grantverify"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// nodemanaged.go: the ONE node-side answer to "is this node managed?"
// (operator ruling P-204, OSH-R-013). A node is managed when its enrolment
// is managed (store.Enrolment.IsManaged, the enrolment token's class), OR
// when its own org switched from teams to enterprise and the node holds that
// org's verified, org-signed managed-consent grant for the current
// enrolment. The decision itself is govern.GrantIsManaged over facts read
// here; every node gate on managed BEHAVIOUR asks this. The org server
// serves such a node as managed on every managed endpoint too (operator
// ruling P-205, internal/orgserver/membertenancy), so machine binding and
// identity, the change key, exec seal, managed integrity and org intel ask
// it as well; only a question about the enrolment token's own class (what
// was just redeemed at enrolment time) still reads IsManaged.

// managedOnlyCode is the error code an org server answers (403) on a route
// that serves managed nodes only, when it does not serve this node as one.
const managedOnlyCode = "managed_only"

// NodeManaged loads the enrolment and answers NodeManagedFor. Not enrolled
// is false with no error.
func NodeManaged(ctx context.Context, st *store.Store) (bool, error) {
	if st == nil {
		return false, nil
	}
	enr, err := st.LoadEnrolment(ctx)
	if err != nil {
		return false, fmt.Errorf("orgclient.NodeManaged: %w", err)
	}
	return NodeManagedFor(ctx, st, enr)
}

// NodeManagedFor answers for an enrolment the caller already holds. A
// managed enrolment is managed without reading the grant; otherwise the
// current enrolment's stored grant decides (govern.GrantIsManaged): it must
// be for this enrolment's generation, unexpired, and its stored copy must
// not fail re-verification under the org key recorded for this org.
func NodeManagedFor(ctx context.Context, st *store.Store, enr *store.Enrolment) (bool, error) {
	if enr == nil {
		return false, nil
	}
	if enr.IsManaged() {
		return true, nil
	}
	if st == nil {
		return false, nil
	}
	orgURL := strings.TrimRight(strings.TrimSpace(enr.OrgServerURL), "/")
	key := OrgKey(orgURL, enr.OrgID)
	row, ok, err := st.LoadEnrolmentGrant(ctx, key)
	if err != nil {
		return false, fmt.Errorf("orgclient.NodeManagedFor: grant: %w", err)
	}
	if !ok {
		return false, nil
	}
	if gen, gok, gerr := st.LoadEnrolmentGeneration(ctx, key); gerr != nil {
		return false, fmt.Errorf("orgclient.NodeManagedFor: generation: %w", gerr)
	} else if gok && (gen.Tombstoned || gen.Generation != row.Generation) {
		return false, nil // a grant for an earlier enrolment is no authority
	}
	if !row.ExpiresAt.IsZero() && time.Now().UTC().After(row.ExpiresAt) {
		return false, nil
	}
	integrity, _ := StoredGrantIntegrity(ctx, st, enr.OrgServerURL, enr.Tenancy, row)
	return govern.GrantIsManaged(&govern.Grant{
		OrgID: row.OrgID, ConsentMode: row.ConsentMode, Authority: row.Authority,
		Tenancy: enr.Tenancy, EnrolmentOrgID: enr.OrgID,
		ReplacementGeneration: row.ReplacementGeneration, Integrity: integrity,
	}), nil
}

// StoredGrantIntegrity re-verifies a stored grant against the org
// distribution public key this node recorded for orgURL. Every path that
// means "cannot check" (no key material, an unreadable pin store) returns
// Unchecked, never Invalid. It is the one owner of that check; the cmd
// boundary's identity loader calls it too.
func StoredGrantIntegrity(ctx context.Context, st *store.Store, orgURL, tenancy string, row store.EnrolmentGrant) (govern.GrantIntegrity, govern.ConsentEvidence) {
	pub, ok, err := OrgPolicyPublicKeyFor(ctx, st, orgURL)
	if err != nil || !ok {
		return govern.GrantIntegrityUnchecked, govern.ConsentEvidenceUnverified
	}
	return StoredGrantIntegrityWith(row, tenancy, pub)
}

// StoredGrantIntegrityWith is the pure half of StoredGrantIntegrity: the
// stored row against a given key. Which expiry is verified matters: the
// SignedExpiresAt the organization signed, since renewal moves the working
// expires_at and leaves the signature untouched.
func StoredGrantIntegrityWith(row store.EnrolmentGrant, tenancy string, pub ed25519.PublicKey) (govern.GrantIntegrity, govern.ConsentEvidence) {
	return grantverify.Verify(orgcontract.StoredGrantDocument{
		OrgID:                 row.OrgID,
		OrgServerURL:          row.OrgServerURL,
		KeyPinSHA256:          row.KeyPinSHA256,
		Authority:             row.Authority,
		GrantedAt:             formatStoredGrantTime(row.GrantedAt),
		ExpiresAt:             formatStoredGrantTime(row.SignedExpiresAt),
		ConsentMode:           row.ConsentMode,
		ConsentActor:          row.ConsentActor,
		Signature:             row.Signature,
		ReplacementGeneration: row.ReplacementGeneration,
		InitialComponents:     row.InitialComponents,
		InitialProof:          row.InitialComponentsProof,
	}, tenancy, pub)
}

// formatStoredGrantTime renders a stored grant timestamp back into the exact
// RFC3339 spelling the signer used (every mint site formats
// now.UTC().Format(time.RFC3339)); the zero time renders empty.
func formatStoredGrantTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
