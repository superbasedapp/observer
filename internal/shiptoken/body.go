package shiptoken

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// MaxBodyBytes caps a ship-token batch, compressed and inflated alike: the
// org push route's own cap, so an envelope the flush sized for one route fits
// the other.
const MaxBodyBytes = 32 << 20

// ErrTooLarge is returned by DecodeBody for a body over the cap.
var ErrTooLarge = errors.New("shiptoken: body exceeds size limit")

// ErrBadEnvelope is returned by DecodeBody for a body that is not a push
// envelope (bad gzip, bad JSON, an unsupported encoding).
var ErrBadEnvelope = errors.New("shiptoken: invalid push envelope")

// DecodeBody decodes a ship-token batch body: the org push envelope as JSON,
// optionally gzipped (Content-Encoding "gzip", or "identity" / empty). raw is
// the body as read, already capped by the caller at max+1 bytes.
func DecodeBody(raw []byte, contentEncoding string, max int) (orgcontract.PushEnvelope, error) {
	var env orgcontract.PushEnvelope
	if len(raw) > max {
		return env, ErrTooLarge
	}
	var r io.Reader = bytes.NewReader(raw)
	switch strings.ToLower(strings.TrimSpace(contentEncoding)) {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return env, ErrBadEnvelope
		}
		defer func() { _ = zr.Close() }()
		r = zr
	default:
		return env, ErrBadEnvelope
	}
	decoded, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return env, ErrBadEnvelope
	}
	if len(decoded) > max {
		return env, ErrTooLarge
	}
	if err := json.Unmarshal(decoded, &env); err != nil {
		return env, ErrBadEnvelope
	}
	return env, nil
}

// Receipt is the 200 body both destinations answer an accepted batch with.
// AcceptedRows is the field the flush reads (internal/cloudsessionnet); the
// rest says what the destination did with the batch.
type Receipt struct {
	AcceptedRows int64 `json:"accepted_rows"`
	DedupedRows  int64 `json:"deduped_rows"`
	// AdmittedRows counts the rows that passed the admission table.
	AdmittedRows int `json:"admitted_rows"`
	// DroppedRows counts, per envelope family, the rows the admission table
	// dropped (a sandbox may not land them). Omitted when nothing dropped.
	DroppedRows map[string]int `json:"dropped_rows,omitempty"`
	// Execution counts session rows per execution-location outcome
	// (ResolveExecution).
	Execution map[string]int `json:"execution,omitempty"`
	// NextCursor echoes the envelope's cursor_to.
	NextCursor int64 `json:"next_cursor"`
	// TokenExpiresAt is the presenting token's expiry (RFC 3339), so a
	// flush can warn before it lapses.
	TokenExpiresAt string `json:"token_expires_at"`
	// TokenRowsRemaining is what is left of the token's volume cap after
	// this batch (CA-D18); omitted by a destination that applies none.
	TokenRowsRemaining *int64 `json:"token_rows_remaining,omitempty"`
	// Environment echoes the token's cloud environment label (CA-D18).
	Environment string `json:"environment,omitempty"`
	// SkippedSessions counts, per SessionOwnership reason, the sessions the
	// node destination refused to write because the token did not create
	// them (ledger CLOUDSESS-8); their rows are in DroppedRows. Omitted when
	// none, and by the org destination, which keys sessions per member.
	SkippedSessions map[string]int `json:"skipped_sessions,omitempty"`
}
