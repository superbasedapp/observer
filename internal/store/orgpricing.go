package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The node's PERSISTED copy of the org's signed price document
// (docs/plans/enterprise-pricing-and-admin-assistant-plan-2026-09-08.md §3.3,
// wave W2; agent migration 106 org_pricing_cache).
//
// WHY IT IS PERSISTED AT ALL, when the sibling budget rail keeps its document
// in memory: a budget is re-derived from whatever is in force at the moment a
// request is scanned, so a daemon that restarts and has not polled yet simply
// runs its own looser numbers for one cycle and then tightens. A PRICE is
// different in kind — api_turns.cost_usd is stamped at CAPTURE and there is no
// retroactive re-pricing in this arc (ruling R8 / gap PRICE-REPRICE-1). Every
// turn a restarted daemon prices before its first successful poll is
// permanently wrong, and the budget those dollars are enforced against is
// permanently wrong with it. A cap the node merely declines to tighten for one
// cycle is recoverable; a dollar figure written into a row is not.
//
// ONE WRITER, and it is SaveOrgPricing. Every non-200 path on the fetch ladder
// deliberately writes NOTHING: a 404, a 401, a 5xx or an unverifiable body all
// leave this row exactly as it was, which is what makes "only a SIGNED body
// may ever empty a node's table" (plan §3.3 / N1) true by construction rather
// than by discipline. The consequence is worth stating: the `state` column
// records the state OF THE STORED DOCUMENT, not the outcome of the last poll.
// The last poll's outcome is live, in-memory posture — a restart legitimately
// forgets it, and inventing a durable home for it here would make a stale
// "unreachable" outlive the outage that caused it.

// OrgPricingCache is the stored document plus the provenance a later reader
// needs to decide whether to trust it.
type OrgPricingCache struct {
	// Witness identifies the exact body_json value observed by this read.
	// Known absence is distinct from an unavailable read; a present witness
	// covers the complete signed envelope and enrollment binding written by the
	// fenced save.
	Witness OrgPricingWitness
	// Have is false when the node has never accepted a signed document. The
	// row itself always exists (migration 106 seeds it), so this is the
	// difference between "no document" and a zero-valued one — a distinction
	// a caller must not have to infer from Version == 0.
	Have bool
	// Version is the applied document's org_pricing_version. It is the
	// replay floor: a body whose version is LOWER than this is refused
	// unless the org's signing key changed.
	Version int64
	// KeyFingerprint identifies the TOFU-pinned org key that verified the
	// stored body (orgcontract.PublicKeyPinHash's value). It exists so a
	// later key ROTATION is diagnosable rather than merely fatal: a version
	// that went backwards under a NEW key is a legitimate lineage restart,
	// and under the SAME key it is a replay.
	KeyFingerprint string
	// Body is the accepted document's body. This is the org's own signed
	// content coming BACK — never node data going out.
	Body orgcontract.PricingPolicyBody
	// Document is the complete signed envelope. It is retained so a cold
	// restore can verify the body against the current enrollment's org and
	// signing key before putting rates back into the live engine.
	Document orgcontract.PricingPolicyDoc
	// Binding identifies the exact enrollment epoch that accepted Document.
	// Empty means a legacy, unbound row; managed pricing restore treats it as
	// absent and waits for a fresh fetch.
	Binding string
	// FetchedAt is when the 200 that produced this row landed.
	FetchedAt time.Time
	// State is the ladder outcome that produced the STORED body: verified or
	// no_pricing. See the file header for why no other value reaches here.
	State string
}

// OrgPricingWitness identifies one durable org_pricing_cache document state.
// ETag and fetched_at are transport metadata and are intentionally excluded;
// the exact stored envelope is the authority that must match a live pricing
// table before a bounded process-control operation runs.
type OrgPricingWitness struct {
	Known   bool
	Present bool
	SHA256  string
}

// Valid reports whether the witness represents a known present or absent row.
func (w OrgPricingWitness) Valid() bool {
	return w.Known && ((!w.Present && w.SHA256 == "") || (w.Present && w.SHA256 != ""))
}

func orgPricingWitness(blob string) OrgPricingWitness {
	if strings.TrimSpace(blob) == "" {
		return OrgPricingWitness{Known: true}
	}
	sum := sha256.Sum256([]byte(blob))
	return OrgPricingWitness{Known: true, Present: true, SHA256: fmt.Sprintf("%x", sum[:])}
}

// loadOrgPricingWitness reads only the durable body_json witness. It accepts a
// querier so the intervention fence can perform the read on its pinned
// transaction connection, keeping the witness comparison inside the same
// BEGIN IMMEDIATE boundary as enrollment and budget authority.
func loadOrgPricingWitness(ctx context.Context, q querier) (OrgPricingWitness, error) {
	var blob string
	err := q.QueryRowContext(ctx, `SELECT body_json FROM org_pricing_cache WHERE id = 1`).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return OrgPricingWitness{Known: true}, nil
	}
	if err != nil {
		return OrgPricingWitness{}, fmt.Errorf("store.loadOrgPricingWitness: %w", err)
	}
	return orgPricingWitness(blob), nil
}

// ErrOrgPricingIdentityChanged means a pricing response lost its enrollment
// generation fence before it could mutate the cache.
var ErrOrgPricingIdentityChanged = errors.New("org pricing enrollment identity changed")

const storedOrgPricingFormat = 1

type storedOrgPricingDocument struct {
	Format   int                          `json:"format"`
	Binding  string                       `json:"binding"`
	Document orgcontract.PricingPolicyDoc `json:"document"`
}

// SaveOrgPricing persists one VERIFIED document. It is the ONE writer of
// org_pricing_cache.
//
// It takes the whole doc rather than a pre-marshalled blob so the bytes stored
// are the bytes this process verified: re-serialising at a second site is how
// a stored document quietly stops matching the signature that admitted it.
//
// A document with NO ROWS is a legitimate save, not a delete: the org has
// signed "we have negotiated nothing", and storing that (with state
// no_pricing) is what lets a restarted daemon know the difference between
// "the org said none" and "we have never asked".
func (s *Store) SaveOrgPricing(ctx context.Context, doc orgcontract.PricingPolicyDoc, keyFingerprint, state string, identities ...OrgBudgetIdentity) error {
	_, err := s.SaveOrgPricingWithWitness(ctx, doc, keyFingerprint, state, identities...)
	return err
}

// SaveOrgPricingWithWitness persists one verified pricing document and returns
// the exact durable witness produced from the same bytes. A bound save returns
// ErrOrgPricingIdentityChanged when the enrollment/generation predicate no
// longer matches; the witness is then zero and must not authorize a live
// process-control operation.
func (s *Store) SaveOrgPricingWithWitness(ctx context.Context, doc orgcontract.PricingPolicyDoc, keyFingerprint, state string, identities ...OrgBudgetIdentity) (OrgPricingWitness, error) {
	if len(identities) > 1 {
		return OrgPricingWitness{}, fmt.Errorf("store.SaveOrgPricing: %w: one identity allowed", ErrOrgPricingIdentityChanged)
	}
	var identity OrgBudgetIdentity
	if len(identities) == 1 {
		identity = identities[0]
		if strings.TrimSpace(identity.Binding) == "" || strings.TrimSpace(identity.OrgKey) == "" {
			return OrgPricingWitness{}, fmt.Errorf("store.SaveOrgPricing: %w: binding required", ErrOrgPricingIdentityChanged)
		}
	}
	blob, err := json.Marshal(storedOrgPricingDocument{
		Format: storedOrgPricingFormat, Binding: identity.Binding, Document: doc,
	})
	if err != nil {
		return OrgPricingWitness{}, fmt.Errorf("store.SaveOrgPricing: marshal: %w", err)
	}
	witness := orgPricingWitness(string(blob))
	var result sql.Result
	if len(identities) == 1 {
		result, err = s.db.ExecContext(ctx, `
UPDATE org_pricing_cache
   SET version = ?, org_key_fingerprint = ?, body_json = ?, fetched_at = ?, state = ?
 WHERE id = 1
   AND EXISTS (
       SELECT 1 FROM org_enrolment e
        WHERE e.id = 1
          AND e.org_id = ? AND e.org_server_url = ?
          AND e.user_id = ? AND e.enrolled_at = ?
   )
   AND (
       (? > 0 AND EXISTS (
           SELECT 1 FROM org_enrolment_generation g
            WHERE g.org_key = ? AND g.generation = ? AND g.tombstoned = 0
       ))
       OR
       (? = 0 AND NOT EXISTS (
           SELECT 1 FROM org_enrolment_generation g WHERE g.org_key = ?
       ))
   )`,
			doc.Version, strings.TrimSpace(keyFingerprint), string(blob),
			time.Now().UTC().Format(time.RFC3339), strings.TrimSpace(state),
			identity.OrgID, identity.OrgServerURL, identity.UserID, identity.EnrolledAt,
			identity.Generation, identity.OrgKey, identity.Generation,
			identity.Generation, identity.OrgKey)
	} else {
		// Keep the historical helper contract for tests and advisory/local
		// callers that seed a cache row without an enrollment. Such a row is
		// deliberately unbound and cannot be restored by the managed pricing
		// rail; production fetches always supply the identity above.
		result, err = s.db.ExecContext(ctx, `
UPDATE org_pricing_cache
   SET version = ?, org_key_fingerprint = ?, body_json = ?, fetched_at = ?, state = ?
 WHERE id = 1`,
			doc.Version, strings.TrimSpace(keyFingerprint), string(blob),
			time.Now().UTC().Format(time.RFC3339), strings.TrimSpace(state))
	}
	if err != nil {
		return OrgPricingWitness{}, fmt.Errorf("store.SaveOrgPricing: %w", err)
	}
	if len(identities) == 1 {
		n, err := result.RowsAffected()
		if err != nil {
			return OrgPricingWitness{}, fmt.Errorf("store.SaveOrgPricing: rows affected: %w", err)
		}
		if n != 1 {
			return OrgPricingWitness{}, fmt.Errorf("store.SaveOrgPricing: %w", ErrOrgPricingIdentityChanged)
		}
	}
	return witness, nil
}

// LoadOrgPricing reads the stored document.
//
// A MISSING ROW is not an error: migration 106 seeds one, but a store built
// against a database that predates it (or a hand-built test handle) must
// degrade to "no document" rather than failing a daemon's start.
//
// A body that will NOT PARSE is reported as an error WITH an empty cache, and
// every caller treats an error here as an absence and logs it. Both halves
// matter: the empty cache means the engine falls back to the seed table (the
// fail-open direction — the fail-closed direction on a price rail is pricing
// at zero), and the error means a corrupted blob is not silently
// indistinguishable from a node that has never enrolled.
func (s *Store) LoadOrgPricing(ctx context.Context) (OrgPricingCache, error) {
	var (
		out       OrgPricingCache
		blob      string
		fetchedAt string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT version, org_key_fingerprint, body_json, fetched_at, state
  FROM org_pricing_cache WHERE id = 1`).
		Scan(&out.Version, &out.KeyFingerprint, &blob, &fetchedAt, &out.State)
	if errors.Is(err, sql.ErrNoRows) {
		return OrgPricingCache{Witness: OrgPricingWitness{Known: true}}, nil
	}
	if err != nil {
		return OrgPricingCache{}, fmt.Errorf("store.LoadOrgPricing: %w", err)
	}
	if strings.TrimSpace(blob) == "" {
		// The seeded row, untouched: the node has never accepted a document.
		out.Witness = OrgPricingWitness{Known: true}
		return out, nil
	}
	out.Witness = orgPricingWitness(blob)
	var stored storedOrgPricingDocument
	if uerr := json.Unmarshal([]byte(blob), &stored); uerr != nil {
		return out, fmt.Errorf("store.LoadOrgPricing: decode stored document: %w", uerr)
	}
	doc := stored.Document
	if stored.Format != storedOrgPricingFormat {
		// Rows written before enrollment binding stored the signed document
		// directly. Preserve read compatibility while exposing an empty binding
		// so managed restore can reject the legacy provenance.
		if uerr := json.Unmarshal([]byte(blob), &doc); uerr != nil {
			return out, fmt.Errorf("store.LoadOrgPricing: decode legacy stored document: %w", uerr)
		}
		stored.Binding = ""
	}
	out.Body = doc.PricingPolicyBody
	out.Document = doc
	out.Binding = stored.Binding
	out.Have = true
	if t, terr := time.Parse(time.RFC3339, fetchedAt); terr == nil {
		out.FetchedAt = t
	}
	return out, nil
}
