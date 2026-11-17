package hostapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// Verb is a mutating host-API verb as it is queued in the org outbox. The
// values equal internal/cloudserver/store's OrgOutboxVerb values and the SQL
// CHECK on org_outbox.verb (pinned by a hostclient test).
type Verb string

// The outbox verbs, in contract order.
const (
	VerbCreateTenant      Verb = "create_tenant"
	VerbSetState          Verb = "set_state"
	VerbSetEntitlements   Verb = "set_entitlements"
	VerbMembersDeactivate Verb = "members_deactivate"
	VerbEvict             Verb = "evict"
)

// KnownVerbs returns every Verb in contract order.
func KnownVerbs() []Verb {
	return []Verb{VerbCreateTenant, VerbSetState, VerbSetEntitlements, VerbMembersDeactivate, VerbEvict}
}

// Intent is one host-API intent ready to be written to the org outbox in the
// same transaction as the control-plane change that caused it.
type Intent struct {
	// OrgID is the org (and tenant) the intent concerns.
	OrgID string
	// Verb is the host-API verb.
	Verb Verb
	// IdempotencyKey is the outbox row key: unique across the outbox, the
	// same on every retry, and, for the verbs whose contract request carries
	// one, the key sent to the host.
	IdempotencyKey string
	// LifecycleGen is the generation a state or evict intent carries (0 for
	// the other verbs).
	LifecycleGen int64
	// Payload is the verb's payload JSON (see the payload types below).
	Payload json.RawMessage
}

// Payload types: what the outbox row carries. None holds a secret or an
// email; the create payload's owner identity and first entitlement document
// are resolved when the request is built (CreateExtras).

// CreatePayload is the create_tenant payload (the shape M6.1a's
// provisioning transaction already writes).
type CreatePayload struct {
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
}

// StatePayload is the set_state payload; the generation is the row's
// LifecycleGen.
type StatePayload struct {
	TenantID string         `json:"tenant_id"`
	State    pc.TenantState `json:"state"`
}

// EntitlementsPayload is the set_entitlements payload: the signed document,
// which is not a secret.
type EntitlementsPayload struct {
	TenantID string                 `json:"tenant_id"`
	Document pc.EntitlementDocument `json:"document"`
}

// DeactivatePayload is the members_deactivate payload; the request's
// idempotency key is the row's key.
type DeactivatePayload struct {
	TenantID string `json:"tenant_id"`
	Sub      string `json:"sub"`
}

// EvictPayload is the evict payload; the generation is the row's
// LifecycleGen.
type EvictPayload struct {
	TenantID string `json:"tenant_id"`
}

// ErrBadIntent means an intent's fields cannot form a valid outbox row.
var ErrBadIntent = errors.New("hostapi: bad intent")

// Idempotency key namespaces. A key is deterministic in the intent's
// identity, so the same intent enqueued twice is one row and a different
// intent never shares a key. create_tenant's key is the bare org id, the key
// M6.1a's provisioning transaction already uses (design 4.1).
const (
	keyPrefixState        = "state:"
	keyPrefixEntitlements = "entitlements:"
	keyPrefixDeactivate   = "deact:"
	keyPrefixEvict        = "evict:"
	// KeyPrefixReconcile starts every correction the reconciler enqueues,
	// so a correction never collides with the intent it repeats.
	KeyPrefixReconcile = "reconcile:"
)

// CreateTenantIntent is the create_tenant intent for orgID with display name.
func CreateTenantIntent(orgID, name string) (Intent, error) {
	if err := needAll(orgID, name); err != nil {
		return Intent{}, fmt.Errorf("hostapi.CreateTenantIntent: %w", err)
	}
	return newIntent(orgID, VerbCreateTenant, orgID, 0, CreatePayload{TenantID: orgID, Name: name})
}

// SetStateIntent is the set_state intent moving orgID to state at generation
// gen. Its key names the generation and the state.
func SetStateIntent(orgID string, state pc.TenantState, gen int64) (Intent, error) {
	if err := needAll(orgID); err != nil || !state.Valid() || gen < 0 {
		return Intent{}, fmt.Errorf("hostapi.SetStateIntent: %w", ErrBadIntent)
	}
	key := keyPrefixState + orgID + ":" + strconv.FormatInt(gen, 10) + ":" + string(state)
	return newIntent(orgID, VerbSetState, key, gen, StatePayload{TenantID: orgID, State: state})
}

// SetEntitlementsIntent is the set_entitlements intent pushing doc to orgID.
// Its key names the document version.
func SetEntitlementsIntent(orgID string, doc pc.EntitlementDocument) (Intent, error) {
	if err := needAll(orgID); err != nil || doc.Validate() != nil {
		return Intent{}, fmt.Errorf("hostapi.SetEntitlementsIntent: %w", ErrBadIntent)
	}
	key := keyPrefixEntitlements + orgID + ":" + strconv.FormatInt(doc.Version, 10)
	return newIntent(orgID, VerbSetEntitlements, key, 0, EntitlementsPayload{TenantID: orgID, Document: doc})
}

// DeactivateMemberIntent is the members_deactivate intent for the WorkOS sub
// in orgID, keyed deact:<org>:<sub> (design 4.10 step 3).
func DeactivateMemberIntent(orgID, sub string) (Intent, error) {
	if err := needAll(orgID, sub); err != nil {
		return Intent{}, fmt.Errorf("hostapi.DeactivateMemberIntent: %w", err)
	}
	return newIntent(orgID, VerbMembersDeactivate, keyPrefixDeactivate+orgID+":"+sub, 0,
		DeactivatePayload{TenantID: orgID, Sub: sub})
}

// EvictIntent is the evict intent for orgID at generation gen.
func EvictIntent(orgID string, gen int64) (Intent, error) {
	if err := needAll(orgID); err != nil || gen < 0 {
		return Intent{}, fmt.Errorf("hostapi.EvictIntent: %w", ErrBadIntent)
	}
	key := keyPrefixEvict + orgID + ":" + strconv.FormatInt(gen, 10)
	return newIntent(orgID, VerbEvict, key, gen, EvictPayload{TenantID: orgID})
}

// AsCorrection returns the intent re-keyed as a reconciler correction:
// KeyPrefixReconcile plus the original key. The original row (acked, failed
// or open) is untouched, and the reconciler's own repeat of the same
// correction is still one row. create_tenant is the exception: its key is
// the org id on every path, so a correction never creates a second tenant
// create.
func (in Intent) AsCorrection() Intent {
	if in.Verb == VerbCreateTenant {
		return in
	}
	in.IdempotencyKey = KeyPrefixReconcile + in.IdempotencyKey
	return in
}

func newIntent(orgID string, v Verb, key string, gen int64, payload any) (Intent, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Intent{}, fmt.Errorf("hostapi.newIntent: %w", err)
	}
	return Intent{OrgID: orgID, Verb: v, IdempotencyKey: key, LifecycleGen: gen, Payload: raw}, nil
}

// needAll fails when any value is blank or carries a key separator-hostile
// character (a newline).
func needAll(vs ...string) error {
	for _, v := range vs {
		if strings.TrimSpace(v) == "" || strings.ContainsAny(v, "\r\n") {
			return ErrBadIntent
		}
	}
	return nil
}
