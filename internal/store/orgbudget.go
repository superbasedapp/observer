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

// The node's persisted copy of the ORG's signed per-caller BUDGET document
// (agent migration 119; org-observer fundamentals plan 2026-09-13, finding
// H3). It is the 106_org_pricing_cache seam, one rail over, and the file
// header of that migration explains the shared shape.
//
// WHY IT EXISTS, stated once here because it is the whole reason the budget
// rail stopped being memory-only: under ruling R2 a MANAGED node holding
// enforce.budget may not run without a verified org budget. With the document
// in memory only, every restart started from "no verified body ever", which is
// either a BLOCK (nothing gets through until the first poll — and during an
// org outage, indefinitely) or, before the node learns it is required, a
// window of UNCAPPED and UNARMED operation that a developer can re-open at
// will by restarting the daemon. Persisting the last verified body makes a
// restart continue where the process left off.
//
// ONE WRITER (SaveOrgBudget) and one reader (LoadOrgBudget), exactly like the
// pricing pair: every non-200 path on the fetch ladder writes nothing, which
// is what makes "only a SIGNED body may ever replace a node's cap" true by
// construction rather than by discipline.

// OrgBudgetCache is the stored document plus the provenance a later reader
// needs to decide whether to trust it.
type OrgBudgetCache struct {
	// Witness identifies the exact body_json value observed by this read. It is
	// available even when the stored document is malformed, so a fail-closed
	// intervention can be fenced to the corrupt/absent state without reviving a
	// previously parsed numeric cap.
	Witness OrgBudgetWitness
	// Have is false when the node has never accepted a signed document. The
	// row itself always exists (migration 119 seeds it), so this is the
	// difference between "no document" and a zero-valued one.
	Have bool
	// Version is the applied document's budget-policy version — the replay
	// floor a later fetch compares against.
	Version int64
	// ETag is the server's strong validator for the stored document, so a
	// restarted daemon's FIRST request can still be conditional.
	ETag string
	// KeyFingerprint identifies the TOFU-pinned org key that verified the
	// stored body (orgcontract.PublicKeyPinHash's value).
	KeyFingerprint string
	// Binding identifies the exact enrolment epoch that accepted Document.
	// Empty means a legacy, unbound row; managed consumers must not restore it.
	Binding string
	// Document retains the signed envelope so a cold reader can reverify it
	// against the current enrolment subject before restoring the body.
	Document orgcontract.BudgetPolicyDoc
	// Body is the accepted document's body — the org's own signed content
	// coming BACK, never node data going out. A body whose Empty() reports
	// true is the SIGNED EXPLICIT NONE and is a legitimate stored value.
	Body orgcontract.BudgetPolicyBody
	// FetchedAt is when the 200 that produced this row landed.
	FetchedAt time.Time
}

// OrgBudgetWitness identifies one durable org_budget_cache document state.
// Known absence is distinct from an unavailable read. For a present document,
// SHA256 covers the exact body_json bytes, including the signed body, subject
// resolution and enrollment binding, while deliberately excluding ETag and
// fetched_at transport noise.
type OrgBudgetWitness struct {
	Known   bool
	Present bool
	SHA256  string
}

// Valid reports whether the witness can fence a process-control operation.
func (w OrgBudgetWitness) Valid() bool {
	return w.Known && ((!w.Present && w.SHA256 == "") || (w.Present && w.SHA256 != ""))
}

func orgBudgetWitness(blob string) OrgBudgetWitness {
	if strings.TrimSpace(blob) == "" {
		return OrgBudgetWitness{Known: true}
	}
	sum := sha256.Sum256([]byte(blob))
	return OrgBudgetWitness{Known: true, Present: true, SHA256: fmt.Sprintf("%x", sum[:])}
}

func loadOrgBudgetWitness(ctx context.Context, q querier) (OrgBudgetWitness, error) {
	var blob string
	err := q.QueryRowContext(ctx, `SELECT body_json FROM org_budget_cache WHERE id = 1`).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return OrgBudgetWitness{Known: true}, nil
	}
	if err != nil {
		return OrgBudgetWitness{}, fmt.Errorf("store.loadOrgBudgetWitness: %w", err)
	}
	return orgBudgetWitness(blob), nil
}

// OrgBudgetIdentity is the exact enrollment epoch allowed to replace or clear
// the singleton budget cache. The database predicate checks every plain field
// as well as the durable generation; Binding is the opaque value persisted for
// consumers that must compare a later authority read with this publication.
type OrgBudgetIdentity struct {
	OrgKey       string
	OrgID        string
	OrgServerURL string
	UserID       string
	EnrolledAt   string
	Generation   int64
	Binding      string
}

// ErrOrgBudgetIdentityChanged means a budget response lost its enrollment
// generation fence before it could mutate the cache.
var ErrOrgBudgetIdentityChanged = errors.New("org budget enrollment identity changed")

const storedOrgBudgetFormat = 1

type storedOrgBudgetDocument struct {
	Format   int                         `json:"format"`
	Binding  string                      `json:"binding"`
	Document orgcontract.BudgetPolicyDoc `json:"document"`
}

// SaveOrgBudget persists one VERIFIED document. It is the ONE writer of
// org_budget_cache.
//
// It takes the whole doc rather than a pre-marshalled blob so the bytes stored
// are the bytes this process verified: re-serialising at a second site is how
// a stored document quietly stops matching the signature that admitted it.
func (s *Store) SaveOrgBudget(ctx context.Context, doc orgcontract.BudgetPolicyDoc, etag, keyFingerprint string, identity OrgBudgetIdentity) error {
	_, err := s.SaveOrgBudgetWithWitness(ctx, doc, etag, keyFingerprint, identity)
	return err
}

// SaveOrgBudgetWithWitness persists one verified document and returns the
// exact durable witness produced from the same canonical bytes written.
func (s *Store) SaveOrgBudgetWithWitness(ctx context.Context, doc orgcontract.BudgetPolicyDoc, etag, keyFingerprint string, identity OrgBudgetIdentity) (OrgBudgetWitness, error) {
	if strings.TrimSpace(identity.Binding) == "" || strings.TrimSpace(identity.OrgKey) == "" {
		return OrgBudgetWitness{}, fmt.Errorf("store.SaveOrgBudget: %w: binding required", ErrOrgBudgetIdentityChanged)
	}
	blob, err := json.Marshal(storedOrgBudgetDocument{
		Format: storedOrgBudgetFormat, Binding: identity.Binding, Document: doc,
	})
	if err != nil {
		return OrgBudgetWitness{}, fmt.Errorf("store.SaveOrgBudget: marshal: %w", err)
	}
	witness := orgBudgetWitness(string(blob))
	result, err := s.db.ExecContext(ctx, `
UPDATE org_budget_cache
   SET version = ?, etag = ?, org_key_fingerprint = ?, body_json = ?, fetched_at = ?
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
		doc.Version, strings.TrimSpace(etag), strings.TrimSpace(keyFingerprint),
		string(blob), time.Now().UTC().Format(time.RFC3339),
		identity.OrgID, identity.OrgServerURL, identity.UserID, identity.EnrolledAt,
		identity.Generation, identity.OrgKey, identity.Generation,
		identity.Generation, identity.OrgKey)
	if err != nil {
		return OrgBudgetWitness{}, fmt.Errorf("store.SaveOrgBudget: %w", err)
	}
	if n, err := result.RowsAffected(); err != nil {
		return OrgBudgetWitness{}, fmt.Errorf("store.SaveOrgBudget: rows affected: %w", err)
	} else if n != 1 {
		return OrgBudgetWitness{}, fmt.Errorf("store.SaveOrgBudget: %w", ErrOrgBudgetIdentityChanged)
	}
	return witness, nil
}

// ClearOrgBudgetForIdentity clears the document only while identity remains
// the current enrollment epoch. It prevents a late 404 for a prior member
// from deleting a freshly accepted budget for the replacement member.
func (s *Store) ClearOrgBudgetForIdentity(ctx context.Context, identity OrgBudgetIdentity) error {
	_, err := s.ClearOrgBudgetForIdentityWithWitness(ctx, identity)
	return err
}

// ClearOrgBudgetForIdentityWithWitness clears the document under the identity
// fence and returns the known-absence witness created by that same write.
func (s *Store) ClearOrgBudgetForIdentityWithWitness(ctx context.Context, identity OrgBudgetIdentity) (OrgBudgetWitness, error) {
	result, err := s.db.ExecContext(ctx, `
UPDATE org_budget_cache
   SET version = 0, etag = '', org_key_fingerprint = '', body_json = '', fetched_at = ''
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
   )`, identity.OrgID, identity.OrgServerURL, identity.UserID, identity.EnrolledAt,
		identity.Generation, identity.OrgKey, identity.Generation,
		identity.Generation, identity.OrgKey)
	if err != nil {
		return OrgBudgetWitness{}, fmt.Errorf("store.ClearOrgBudgetForIdentity: %w", err)
	}
	if n, err := result.RowsAffected(); err != nil {
		return OrgBudgetWitness{}, fmt.Errorf("store.ClearOrgBudgetForIdentity: rows affected: %w", err)
	} else if n != 1 {
		return OrgBudgetWitness{}, fmt.Errorf("store.ClearOrgBudgetForIdentity: %w", ErrOrgBudgetIdentityChanged)
	}
	return OrgBudgetWitness{Known: true}, nil
}

// ClearOrgBudget drops the stored document. It is called on exactly the two
// signals that mean "this node holds no org budget any more": an unenrol, and
// a server that answers the rail with an explicit not-found for this caller.
//
// It is deliberately NOT called on any transport or verification failure —
// those keep the stored body, which is the whole point of storing it.
func (s *Store) ClearOrgBudget(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
UPDATE org_budget_cache
   SET version = 0, etag = '', org_key_fingerprint = '', body_json = '', fetched_at = ''
 WHERE id = 1`); err != nil {
		return fmt.Errorf("store.ClearOrgBudget: %w", err)
	}
	return nil
}

// LoadOrgBudget reads the stored document.
//
// A MISSING ROW is not an error: migration 119 seeds one, but a store built
// against a database that predates it (or a hand-built test handle) must
// degrade to "no document" rather than failing a daemon's start.
//
// A body that will NOT PARSE is reported as an error WITH an empty cache. The
// caller treats that as an absence and logs it — which on a node that REQUIRES
// an org budget means arming the block, the fail-closed direction, because a
// corrupted cap is not a cap.
func (s *Store) LoadOrgBudget(ctx context.Context) (OrgBudgetCache, error) {
	var (
		out       OrgBudgetCache
		blob      string
		fetchedAt string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT version, etag, org_key_fingerprint, body_json, fetched_at
  FROM org_budget_cache WHERE id = 1`).
		Scan(&out.Version, &out.ETag, &out.KeyFingerprint, &blob, &fetchedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return OrgBudgetCache{Witness: OrgBudgetWitness{Known: true}}, nil
	}
	if err != nil {
		return OrgBudgetCache{}, fmt.Errorf("store.LoadOrgBudget: %w", err)
	}
	out.Witness = orgBudgetWitness(blob)
	if strings.TrimSpace(blob) == "" {
		// The seeded row, untouched: the node has never accepted a document.
		return out, nil
	}
	var stored storedOrgBudgetDocument
	if err := json.Unmarshal([]byte(blob), &stored); err != nil {
		return out, fmt.Errorf("store.LoadOrgBudget: decode stored document: %w", err)
	}
	doc := stored.Document
	if stored.Format != storedOrgBudgetFormat {
		// Backward compatibility for rows written before enrollment binding was
		// persisted. The caller receives the signed document but an empty
		// Binding, so managed code can require a live refetch before restoring.
		if err := json.Unmarshal([]byte(blob), &doc); err != nil {
			return out, fmt.Errorf("store.LoadOrgBudget: decode legacy stored document: %w", err)
		}
		stored.Binding = ""
	}
	out.Body = doc.BudgetPolicyBody
	out.Document = doc
	out.Binding = stored.Binding
	out.Have = true
	if t, terr := time.Parse(time.RFC3339, fetchedAt); terr == nil {
		out.FetchedAt = t
	}
	return out, nil
}
