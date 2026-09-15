package pricingfeed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalRows renders the deterministic signing/digest bytes for a feed's
// rows.
//
// encoding/json's rendering IS the canonical form here, and that is a property
// of the SHAPE, not a hope — the same reasoning as orgcontract.canonicalPricingBody:
// Row has NO map anywhere, its (embedded) field order is fixed by the struct
// declaration, and the only ordering degree of freedom is the slice order,
// which this function pins by sorting on the model id. So a publisher that
// emits the rows in any order, and a verifier that decoded them in that order,
// sign and digest identical bytes.
//
// The *float64,omitempty rate fields keep this property across the nil-vs-
// quoted-zero distinction: a nil rate renders as nothing, a &0.0 renders as
// `0`, both deterministically — so a "not quoted" row and a "quoted free" row
// canonicalise to DIFFERENT bytes, which is exactly what they are.
//
// It does NOT mutate the caller's slice: it sorts a shallow copy.
func CanonicalRows(rows []Row) ([]byte, error) {
	sorted := make([]Row, len(rows))
	copy(sorted, rows)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Model < sorted[j].Model
	})
	raw, err := json.Marshal(sorted)
	if err != nil {
		return nil, fmt.Errorf("pricingfeed.CanonicalRows: %w", err)
	}
	return raw, nil
}

// Digest is the sha256 hex of CanonicalRows(rows) — the envelope's Digest field
// and the ETag substrate (§A). Hashing the CANONICAL rows (not the received
// byte order) means two publishes of the same prices in a different row order
// share a digest, so the node's If-None-Match short-circuits correctly.
func Digest(rows []Row) (string, error) {
	canonical, err := CanonicalRows(rows)
	if err != nil {
		return "", err
	}
	return digestOf(canonical), nil
}

// digestOf is the sha256 hex of already-canonicalised bytes. Verify uses it to
// avoid re-marshaling the rows a second time after it has the canonical form.
func digestOf(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}
