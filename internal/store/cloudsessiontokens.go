package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/shiptoken"
)

// Node-minted cloud-session ship tokens (agent migration 244, cloud-agents
// arc lane CA-B3, decision CA-D8). This file is the ONE owner of
// cloud_session_ship_tokens: the individual destination of Rail S. The token
// rules live in the pure internal/shiptoken package. The table is
// NODE-LOCAL and pinned out of the org push by tests/invariant/privacy_test.go.

// CloudSessionShipToken is one node ship-token row. TokenHash never leaves
// the node.
type CloudSessionShipToken struct {
	TokenID    string
	TokenHash  string
	Label      string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
	LastUsedAt time.Time
	UseCount   int64
}

// Status is the row's status at now.
func (t CloudSessionShipToken) Status(now time.Time) string {
	return shiptoken.StatusAt(now, t.ExpiresAt, t.RevokedAt)
}

// ErrShipTokenNotFound is returned when no node ship token matches.
var ErrShipTokenNotFound = errors.New("store: cloud-session ship token not found")

func shipStamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func shipParse(s sql.NullString) time.Time {
	if !s.Valid || strings.TrimSpace(s.String) == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// InsertCloudSessionShipToken stores a freshly minted token.
func (s *Store) InsertCloudSessionShipToken(ctx context.Context, t CloudSessionShipToken) error {
	if !shiptoken.ValidID(t.TokenID) || len(t.TokenHash) != 64 || !shiptoken.ValidLabel(t.Label) {
		return errors.New("store.InsertCloudSessionShipToken: invalid token row")
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO cloud_session_ship_tokens (token_id, token_hash, label, created_at, expires_at, use_count)
VALUES (?, ?, ?, ?, ?, 0)`,
		t.TokenID, t.TokenHash, t.Label, shipStamp(t.CreatedAt), shipStamp(t.ExpiresAt)); err != nil {
		return fmt.Errorf("store.InsertCloudSessionShipToken: %w", err)
	}
	return nil
}

const shipCols = `token_id, token_hash, label, created_at, expires_at, revoked_at, last_used_at, use_count`

func scanShipToken(row interface{ Scan(...any) error }) (CloudSessionShipToken, error) {
	var t CloudSessionShipToken
	var created, expires, revoked, used sql.NullString
	if err := row.Scan(&t.TokenID, &t.TokenHash, &t.Label, &created, &expires, &revoked, &used, &t.UseCount); err != nil {
		return CloudSessionShipToken{}, err
	}
	t.CreatedAt, t.ExpiresAt, t.RevokedAt, t.LastUsedAt = shipParse(created), shipParse(expires), shipParse(revoked), shipParse(used)
	return t, nil
}

// CloudSessionShipTokenByHash looks a presented token up by its digest.
func (s *Store) CloudSessionShipTokenByHash(ctx context.Context, hash string) (CloudSessionShipToken, error) {
	t, err := scanShipToken(s.db.QueryRowContext(ctx,
		`SELECT `+shipCols+` FROM cloud_session_ship_tokens WHERE token_hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return CloudSessionShipToken{}, ErrShipTokenNotFound
	}
	if err != nil {
		return CloudSessionShipToken{}, fmt.Errorf("store.CloudSessionShipTokenByHash: %w", err)
	}
	return t, nil
}

// ListCloudSessionShipTokens returns the node's ship tokens, newest first,
// at most 200: a DISPLAY list for the settings page and `token list`. No
// decision reads it (a long mint/revoke history could push an active token
// past the cap); the active checks use activeCloudSessionShipTokens.
func (s *Store) ListCloudSessionShipTokens(ctx context.Context) ([]CloudSessionShipToken, error) {
	return s.queryShipTokens(ctx, "store.ListCloudSessionShipTokens",
		`SELECT `+shipCols+` FROM cloud_session_ship_tokens ORDER BY created_at DESC, token_id DESC LIMIT 200`)
}

// activeCloudSessionShipTokens returns EVERY token active at now, newest
// first, with no row cap: the one read behind the route gate, the
// per-environment lookup and the mint cap. SQL keeps the unrevoked rows
// whose expiry second is not before now's (expires_at is RFC 3339 UTC, so
// its first 19 bytes are a fixed-width, sortable second; a whole-string
// comparison is not, because the fractional part is trimmed), and Status
// settles the sub-second edge.
func (s *Store) activeCloudSessionShipTokens(ctx context.Context, now time.Time) ([]CloudSessionShipToken, error) {
	ts, err := s.queryShipTokens(ctx, "store.activeCloudSessionShipTokens",
		`SELECT `+shipCols+` FROM cloud_session_ship_tokens
		  WHERE revoked_at IS NULL AND substr(expires_at, 1, 19) >= ?
		  ORDER BY created_at DESC, token_id DESC`,
		now.UTC().Format("2006-01-02T15:04:05"))
	if err != nil {
		return nil, err
	}
	out := ts[:0]
	for _, t := range ts {
		if t.Status(now) == shiptoken.StatusActive {
			out = append(out, t)
		}
	}
	return out, nil
}

// queryShipTokens runs one token select and scans every row.
func (s *Store) queryShipTokens(ctx context.Context, op, query string, args ...any) ([]CloudSessionShipToken, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()
	out := []CloudSessionShipToken{}
	for rows.Next() {
		t, err := scanShipToken(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// HasActiveCloudSessionShipToken reports whether any token is active at now:
// the node ingest route exists only while one is.
func (s *Store) HasActiveCloudSessionShipToken(ctx context.Context, now time.Time) (bool, error) {
	ts, err := s.activeCloudSessionShipTokens(ctx, now)
	if err != nil {
		return false, err
	}
	return len(ts) > 0, nil
}

// RevokeCloudSessionShipToken revokes one token. It reports false when the
// token was already revoked; ErrShipTokenNotFound when no token has the id.
func (s *Store) RevokeCloudSessionShipToken(ctx context.Context, tokenID string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE cloud_session_ship_tokens SET revoked_at = ? WHERE token_id = ? AND revoked_at IS NULL`,
		shipStamp(now), tokenID)
	if err != nil {
		return false, fmt.Errorf("store.RevokeCloudSessionShipToken: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	var one int
	err = s.db.QueryRowContext(ctx, `SELECT 1 FROM cloud_session_ship_tokens WHERE token_id = ?`, tokenID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrShipTokenNotFound
	}
	if err != nil {
		return false, fmt.Errorf("store.RevokeCloudSessionShipToken: %w", err)
	}
	return false, nil
}

// ActiveCloudSessionShipTokenForEnvironment returns the node's active token
// for a cloud environment label (shiptoken.EnvironmentKey comparison), if
// any: since decision CA-D18 the node holds at most one live token per
// environment.
func (s *Store) ActiveCloudSessionShipTokenForEnvironment(ctx context.Context, label string, now time.Time) (CloudSessionShipToken, bool, error) {
	ts, err := s.activeCloudSessionShipTokens(ctx, now)
	if err != nil {
		return CloudSessionShipToken{}, false, err
	}
	key := shiptoken.EnvironmentKey(label)
	for _, t := range ts {
		if t.Status(now) == shiptoken.StatusActive && shiptoken.EnvironmentKey(t.Label) == key {
			return t, true, nil
		}
	}
	return CloudSessionShipToken{}, false, nil
}

// ActiveCloudSessionShipToken resolves a presented secret to an ACTIVE node
// ship token, or ok=false (malformed, unknown, expired or revoked). It is
// the check the node's OTLP receiver runs for a cloud environment's
// exporter (CLOUDTEL-1, decision CA-D18), so the receiver never handles the
// token table itself.
func (s *Store) ActiveCloudSessionShipToken(ctx context.Context, secret string, now time.Time) (CloudSessionShipToken, bool, error) {
	tok, err := shiptoken.Parse(secret)
	if err != nil {
		return CloudSessionShipToken{}, false, nil
	}
	t, err := s.CloudSessionShipTokenByHash(ctx, shiptoken.Hash(tok))
	if errors.Is(err, ErrShipTokenNotFound) {
		return CloudSessionShipToken{}, false, nil
	}
	if err != nil {
		return CloudSessionShipToken{}, false, err
	}
	if t.Status(now) != shiptoken.StatusActive {
		return CloudSessionShipToken{}, false, nil
	}
	return t, true, nil
}

// TouchCloudSessionShipToken records one accepted batch on a token.
func (s *Store) TouchCloudSessionShipToken(ctx context.Context, tokenID string, now time.Time) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE cloud_session_ship_tokens SET last_used_at = ?, use_count = use_count + 1 WHERE token_id = ?`,
		shipStamp(now), tokenID); err != nil {
		return fmt.Errorf("store.TouchCloudSessionShipToken: %w", err)
	}
	return nil
}

// MaxActiveCloudSessionShipTokens bounds how many live tokens the node holds.
const MaxActiveCloudSessionShipTokens = 20

// Mint refusals (MintCloudSessionShipToken). Each is a caller error the
// surfaces map to 400 / 409.
var (
	ErrShipTokenBadLabel = fmt.Errorf("label must name the cloud environment the token is for, at most %d printable characters", shiptoken.MaxLabelRunes)
	ErrShipTokenTooMany  = fmt.Errorf("this node already holds %d active ship tokens; revoke one first", MaxActiveCloudSessionShipTokens)
)

// ShipTokenEnvironmentHeldError refuses a second active token for one cloud
// environment (decision CA-D18).
type ShipTokenEnvironmentHeldError struct{ Held CloudSessionShipToken }

func (e ShipTokenEnvironmentHeldError) Error() string {
	return fmt.Sprintf("cloud environment %q already has an active ship token (%s, expires %s); revoke it first",
		e.Held.Label, e.Held.TokenID, e.Held.ExpiresAt.Format(time.RFC3339))
}

// MintedCloudSessionShipToken is a fresh node token: the secret is returned
// exactly once and never stored.
type MintedCloudSessionShipToken struct {
	Secret string
	Token  CloudSessionShipToken
}

// MintCloudSessionShipToken is the ONE node mint rule set, shared by the
// dashboard route and `observer cloud-session token mint`: the label names a
// cloud environment (required), the environment holds no other active token,
// the node holds fewer than MaxActiveCloudSessionShipTokens, and the
// lifetime goes through shiptoken.ClampLifetime (short by default). rand is
// crypto/rand.Reader in production.
func (s *Store) MintCloudSessionShipToken(ctx context.Context, rand io.Reader, label string, ttl time.Duration, now time.Time) (MintedCloudSessionShipToken, error) {
	if !shiptoken.ValidEnvironmentLabel(label) {
		return MintedCloudSessionShipToken{}, ErrShipTokenBadLabel
	}
	label = strings.TrimSpace(label)
	ts, err := s.activeCloudSessionShipTokens(ctx, now)
	if err != nil {
		return MintedCloudSessionShipToken{}, err
	}
	active := 0
	key := shiptoken.EnvironmentKey(label)
	for _, t := range ts {
		if t.Status(now) != shiptoken.StatusActive {
			continue
		}
		if shiptoken.EnvironmentKey(t.Label) == key {
			return MintedCloudSessionShipToken{}, ShipTokenEnvironmentHeldError{Held: t}
		}
		active++
	}
	if active >= MaxActiveCloudSessionShipTokens {
		return MintedCloudSessionShipToken{}, ErrShipTokenTooMany
	}
	m, err := shiptoken.Generate(rand)
	if err != nil {
		return MintedCloudSessionShipToken{}, err
	}
	tok := CloudSessionShipToken{
		TokenID: m.ID, TokenHash: m.Hash, Label: label, CreatedAt: now,
		ExpiresAt: now.Add(shiptoken.ClampLifetime(ttl)),
	}
	if err := s.InsertCloudSessionShipToken(ctx, tok); err != nil {
		return MintedCloudSessionShipToken{}, err
	}
	return MintedCloudSessionShipToken{Secret: m.Token, Token: tok}, nil
}
