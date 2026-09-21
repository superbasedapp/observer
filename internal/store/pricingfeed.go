package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

// The STANDALONE node's PERSISTED copy of the public pricing feed
// (docs/plans/pricing-sync-tokenomics-to-platform-plan-2026-09-11.md §C.3,
// Wave N; agent migration 113 pricing_feed_cache).
//
// It is the sibling of orgpricing.go for the non-enrolled case: orgpricing.go
// caches the ORG's signed document (enrolled nodes), this caches the PUBLIC
// feed's signed document (standalone nodes). Both exist for the same reason —
// api_turns.cost_usd is stamped at CAPTURE and there is no retroactive
// re-pricing (ruling R8 / gap PRICE-REPRICE-1), so a restart must not silently
// drop the node to seed prices while it waits for the next (opt-in) poll.
//
// ONE WRITER, and it is SavePricingFeed. Every non-verified path in the sync
// ladder (cmd/observer/pricing.go) deliberately writes NOTHING, which is what
// makes "only a SIGNED body may ever empty this table" true by construction.
//
// NODE-LOCAL by table name: pricing_feed_cache is in the forbidden set walked
// by tests/invariant/privacy_test.go, so internal/store/orgpush.go must never
// reference it. This file is deliberately the only place the table name appears
// in internal/store. The body is the PUBLISHER's own signed document coming
// BACK to the node, never node data going out.

// PricingFeedCache is the stored feed envelope plus the provenance a later
// reader needs to decide whether to trust it and whether a newer body is a
// replay.
type PricingFeedCache struct {
	// Have is false when the node has never accepted a signed feed. The row
	// itself always exists (migration 113 seeds it), so this is the difference
	// between "no feed" and a zero-valued one — a distinction a caller must not
	// have to infer from Version == 0.
	Have bool
	// Version is the applied feed's feed_version. It is the replay floor: a body
	// whose version is LOWER than this is refused unless the signing key
	// changed.
	Version int64
	// KeyID identifies the compiled vendor key that verified the stored body
	// (pricingfeed.PricingFeedKeyIDV1 or a rotation-slot id). Recorded so a
	// later key rotation is diagnosable rather than merely fatal.
	KeyID string
	// Digest is the envelope's content digest — the If-None-Match / ETag
	// substrate for the next poll.
	Digest string
	// Envelope is the whole accepted, verified feed document. The engine
	// composes its rows (and economics) from here on a cold start.
	Envelope pricingfeed.Envelope
	// FetchedAt is when the verified 200 that produced this row landed.
	FetchedAt time.Time
	// State is the ladder outcome that produced the STORED body. See the file
	// header for why no non-verified value reaches here.
	State string
}

// SavePricingFeed persists one VERIFIED feed envelope. It is the ONE writer of
// pricing_feed_cache.
//
// It takes the whole envelope rather than a pre-marshalled blob so the bytes
// stored are the bytes this process verified: re-serialising at a second site
// is how a stored document quietly stops matching the signature that admitted
// it. The caller is responsible for having verified env against the compiled
// key set before calling — this seam performs no verification, it only durably
// records what the ladder already accepted.
func (s *Store) SavePricingFeed(ctx context.Context, env pricingfeed.Envelope, state string) error {
	return s.SavePricingFeedRaw(ctx, env, nil, state)
}

// SavePricingFeedRaw persists one VERIFIED feed envelope, storing rawEnvelope
// VERBATIM as body_json when it is supplied.
//
// rawEnvelope is the exact bytes the fetch path decoded and verified (the HTTP
// response body). Persisting them unchanged is what makes graceful degradation
// true across a restart: LoadPricingFeed decodes body_json back into an
// Envelope, and Envelope.UnmarshalJSON repopulates its unexported rawRows from
// whatever bytes were stored. Keeping the received bytes means a row field this
// build does not model (a future addition) rides through into rawRows, so
// pricingfeed.Verify digests/signs over the same bytes the publisher did rather
// than a typed re-marshal that dropped the unknown field and tripped
// ErrDigestMismatch — the whole-table revert to seed the N1 finding named
// (docs/plans/peak-off-peak-phase2-3-implementation-plan-2026-09-21.md §R2).
//
// A nil (or invalid) rawEnvelope falls back to a typed marshal of env, which is
// lossless for the fields this build knows and correct for programmatic callers
// that have no wire bytes to preserve. The version/key_id/digest columns are
// always taken from the typed env (which was decoded from those same bytes), so
// the provenance columns never disagree with the stored body.
func (s *Store) SavePricingFeedRaw(ctx context.Context, env pricingfeed.Envelope, rawEnvelope []byte, state string) error {
	blob, err := pricingFeedBodyBytes(env, rawEnvelope)
	if err != nil {
		return fmt.Errorf("store.SavePricingFeed: marshal: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
UPDATE pricing_feed_cache
   SET version = ?, key_id = ?, digest = ?, body_json = ?, fetched_at = ?, state = ?
 WHERE id = 1`,
		env.FeedVersion, strings.TrimSpace(env.KeyID), strings.TrimSpace(env.Digest),
		string(blob), time.Now().UTC().Format(time.RFC3339), strings.TrimSpace(state))
	if err != nil {
		return fmt.Errorf("store.SavePricingFeed: %w", err)
	}
	return nil
}

// pricingFeedBodyBytes chooses the bytes stored in body_json. The verbatim
// received envelope is used when supplied and valid (preserving a field this
// build does not model); otherwise a typed marshal of env is used, which is
// lossless for the fields it knows. Invalid raw bytes are ignored rather than
// trusted — marshalling an invalid json.RawMessage would fail the whole save,
// and the typed fallback is the honest degrade.
func pricingFeedBodyBytes(env pricingfeed.Envelope, rawEnvelope []byte) ([]byte, error) {
	if len(rawEnvelope) > 0 && json.Valid(rawEnvelope) {
		return rawEnvelope, nil
	}
	return json.Marshal(env)
}

// LoadPricingFeed reads the stored feed envelope.
//
// A MISSING ROW is not an error: migration 113 seeds one, but a store built
// against a database that predates it (or a hand-built test handle) must
// degrade to "no feed" rather than failing a daemon's start. A body that will
// NOT PARSE is reported as an error WITH an empty cache, and every caller
// treats an error here as an absence and logs it — the empty cache means the
// engine falls back to the seed table (the fail-open direction; the fail-closed
// direction on a price table is pricing at zero).
func (s *Store) LoadPricingFeed(ctx context.Context) (PricingFeedCache, error) {
	var (
		out       PricingFeedCache
		blob      string
		fetchedAt string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT version, key_id, digest, body_json, fetched_at, state
  FROM pricing_feed_cache WHERE id = 1`).
		Scan(&out.Version, &out.KeyID, &out.Digest, &blob, &fetchedAt, &out.State)
	if errors.Is(err, sql.ErrNoRows) {
		return PricingFeedCache{}, nil
	}
	if err != nil {
		return PricingFeedCache{}, fmt.Errorf("store.LoadPricingFeed: %w", err)
	}
	if strings.TrimSpace(blob) == "" {
		// The seeded row, untouched: the node has never accepted a feed.
		return PricingFeedCache{}, nil
	}
	var env pricingfeed.Envelope
	if uerr := json.Unmarshal([]byte(blob), &env); uerr != nil {
		return PricingFeedCache{}, fmt.Errorf("store.LoadPricingFeed: decode stored envelope: %w", uerr)
	}
	out.Envelope = env
	out.Have = true
	if t, terr := time.Parse(time.RFC3339, fetchedAt); terr == nil {
		out.FetchedAt = t
	}
	return out, nil
}
