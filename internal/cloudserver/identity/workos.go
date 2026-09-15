package identity

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// WorkOSVerifier is the PRODUCTION identity verifier: it validates a WorkOS
// User Management / AuthKit access token (a JWT) into a stable (provider,
// subject) identity. WorkOS remains the sole refresh authority — this verifier
// only VALIDATES an access token the node already holds (obtained via the PKCE
// loopback broker); it never mints or refreshes anything.
//
// Validation (all must hold, else ErrInvalidToken):
//   - signature verifies against a key from the WorkOS JWKS, selected by `kid`;
//   - the signing algorithm is RS256 (WorkOS signs access tokens with RS256) —
//     `alg:none` and HMAC confusion are refused up front via WithValidMethods;
//   - `iss` equals https://api.workos.com/user_management/<client_id> (the
//     issuer WorkOS stamps on AuthKit access tokens — verified against a live
//     staging token 2026-09-01; override with WithIssuer for a custom AuthKit
//     domain, where WorkOS stamps the domain as issuer instead);
//   - the `client_id` claim equals the configured WORKOS_CLIENT_ID (WorkOS
//     access tokens carry no `aud`, so client_id IS the audience binding —
//     without it a token minted for a DIFFERENT WorkOS client would validate);
//   - `exp` is present and not passed, `iat`/`nbf` are sane (jwt validates);
//   - `sub` (the user id) is non-empty.
//
// The JWKS is fetched lazily, cached, and re-fetched on a cache miss (unknown
// kid ⇒ key rotation) and after a TTL, so key rotation is handled without a
// restart. All JWKS state is behind a mutex.
type WorkOSVerifier struct {
	clientID string
	issuer   string
	jwksURL  string
	http     *http.Client
	ttl      time.Duration
	now      func() time.Time

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	// missCooldown / recentMisses bound how often an UNKNOWN kid may trigger a
	// fresh JWKS fetch, independent of the normal TTL (§10 "JWKS key rotation
	// mid-flight" / "must not thrash"). A kid is attacker-influenced — it
	// comes from the unverified JWT header — so without this a flood of
	// tokens carrying a bogus kid would drive one HTTP fetch to the provider
	// PER REQUEST (a miss always looks stale, since staleness is keyed on
	// fetchedAt, not on the kid). See keyForKID.
	//
	// P3-a: this used to be a single lastMissKID/lastMissAt pair, which
	// bounded a REPEATED probe of the identical bogus kid but was defeated
	// completely by an attacker ALTERNATING between two (or more) bogus
	// kids — kid A never matched kid B's cooldown record (or vice versa), so
	// every single probe re-triggered a fetch regardless of how tight the
	// cooldown window was. recentMisses tracks each kid's own last-miss
	// instant independently, bounded to jwksMissMapCap entries (evicting the
	// single oldest on overflow) so an attacker cycling through many DISTINCT
	// bogus kids cannot grow it without limit either.
	missCooldown time.Duration
	recentMisses map[string]time.Time
}

// jwksMissMapCap bounds recentMisses' size (P3-a). Misses are already
// frequency-bounded by missCooldown itself, so a linear scan to evict the
// single oldest entry on overflow is fine — this path is never hot.
const jwksMissMapCap = 64

// WorkOSOption configures a WorkOSVerifier (test seams for the JWKS URL, HTTP
// client, TTL, and clock; production uses the defaults).
type WorkOSOption func(*WorkOSVerifier)

// WithJWKSURL overrides the JWKS URL (tests point it at a local mock).
func WithJWKSURL(u string) WorkOSOption { return func(v *WorkOSVerifier) { v.jwksURL = u } }

// WithIssuer overrides the expected `iss` claim. Needed only when the WorkOS
// environment uses a custom AuthKit domain (WorkOS then stamps that domain as
// the issuer instead of the api.workos.com/user_management/<client_id> default).
func WithIssuer(iss string) WorkOSOption { return func(v *WorkOSVerifier) { v.issuer = iss } }

// WithHTTPClient overrides the HTTP client used to fetch the JWKS.
func WithHTTPClient(c *http.Client) WorkOSOption { return func(v *WorkOSVerifier) { v.http = c } }

// WithJWKSCacheTTL overrides the JWKS cache TTL.
func WithJWKSCacheTTL(d time.Duration) WorkOSOption { return func(v *WorkOSVerifier) { v.ttl = d } }

// WithClock overrides the clock (tests pin a fixed instant).
func WithClock(f func() time.Time) WorkOSOption { return func(v *WorkOSVerifier) { v.now = f } }

// WithJWKSMissCooldown overrides how long a repeat MISS on the SAME kid must
// wait before it triggers another JWKS fetch (default jwksDefaultMissCooldown).
// Production has no reason to change this; it exists so a test can shrink or
// zero it without waiting on a real clock.
func WithJWKSMissCooldown(d time.Duration) WorkOSOption {
	return func(v *WorkOSVerifier) { v.missCooldown = d }
}

// jwksDefaultMissCooldown is the production default for WithJWKSMissCooldown.
const jwksDefaultMissCooldown = 5 * time.Second

// NewWorkOSVerifier builds the production verifier for a WorkOS client id
// (e.g. "client_01H..."). It performs NO network I/O — the JWKS is fetched
// lazily on the first Verify.
func NewWorkOSVerifier(clientID string, opts ...WorkOSOption) (*WorkOSVerifier, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, fmt.Errorf("cloudserver/identity: WorkOS client id is empty")
	}
	v := &WorkOSVerifier{
		clientID:     clientID,
		issuer:       "https://api.workos.com/user_management/" + clientID,
		jwksURL:      "https://api.workos.com/sso/jwks/" + clientID,
		http:         &http.Client{Timeout: 10 * time.Second},
		ttl:          1 * time.Hour,
		now:          time.Now,
		missCooldown: jwksDefaultMissCooldown,
	}
	for _, o := range opts {
		o(v)
	}
	return v, nil
}

// Provider returns "workos" — the same label as the placeholder, so a production
// cutover never re-namespaces existing identity links.
func (v *WorkOSVerifier) Provider() string { return "workos" }

// Verify validates the raw WorkOS access token and returns the identity.
func (v *WorkOSVerifier) Verify(ctx context.Context, rawToken string) (Identity, error) {
	if strings.TrimSpace(rawToken) == "" {
		return Identity{}, fmt.Errorf("%w: empty token", ErrInvalidToken)
	}

	keyfunc := func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("%w: token has no kid", ErrInvalidToken)
		}
		key, err := v.keyForKID(ctx, kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	claims := jwt.MapClaims{}
	// WithValidMethods pins RS256, refusing alg:none and HMAC key-confusion.
	// jwt/v4's built-in exp/nbf validation uses a package-global clock we cannot
	// inject per-verifier, so WithoutClaimsValidation disables it and we validate
	// exp/nbf below against v.now (test-injectable, no global mutation).
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithoutClaimsValidation(),
	)
	if _, err := parser.ParseWithClaims(rawToken, claims, keyfunc); err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	now := v.now()
	// exp MUST be present and not passed (a token with no exp would otherwise be
	// treated as non-expiring).
	exp, ok := numericClaim(claims, "exp")
	if !ok {
		return Identity{}, fmt.Errorf("%w: token has no exp", ErrInvalidToken)
	}
	if !now.Before(time.Unix(exp, 0)) {
		return Identity{}, fmt.Errorf("%w: token expired", ErrInvalidToken)
	}
	// nbf, when present, must not be in the future.
	if nbf, ok := numericClaim(claims, "nbf"); ok && now.Before(time.Unix(nbf, 0)) {
		return Identity{}, fmt.Errorf("%w: token not yet valid", ErrInvalidToken)
	}
	// Issuer.
	if iss, _ := claims["iss"].(string); iss != v.issuer {
		return Identity{}, fmt.Errorf("%w: issuer %q, want %q", ErrInvalidToken, iss, v.issuer)
	}
	// client_id is the audience binding (WorkOS access tokens carry no aud).
	if cid, _ := claims["client_id"].(string); cid != v.clientID {
		return Identity{}, fmt.Errorf("%w: client_id claim does not match the configured client", ErrInvalidToken)
	}
	sub, _ := claims["sub"].(string)
	if strings.TrimSpace(sub) == "" {
		return Identity{}, fmt.Errorf("%w: empty subject", ErrInvalidToken)
	}
	id := Identity{Provider: "workos", Subject: sub}
	if email, ok := claims["email"].(string); ok {
		id.Email = strings.TrimSpace(email)
	}
	return id, nil
}

// numericClaim reads a numeric JWT claim (seconds since epoch) as int64,
// accepting the float64 the JSON decoder produces by default and a json.Number
// fallback. Returns ok=false when the claim is absent or non-numeric.
func numericClaim(claims jwt.MapClaims, key string) (int64, bool) {
	switch v := claims[key].(type) {
	case float64:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	default:
		return 0, false
	}
}

// keyForKID returns the cached RSA key for kid, refreshing the JWKS on a cache
// miss (rotation) or when the cache is empty/stale.
//
// A MISS is bounded separately from ordinary staleness (§10 "JWKS key rotation
// mid-flight" / "must not thrash"): the first time a given kid is unknown, it
// always triggers a fetch — that is how rotation is ever picked up at all —
// but a REPEAT miss on the SAME kid within missCooldown reuses that attempt's
// outcome instead of hitting the provider again. A kid comes from the
// unverified JWT header, so without this bound an attacker who can present
// tokens with an arbitrary bogus kid could drive one JWKS fetch per request.
// The bound is per-KID (recentMisses, P3-a), not a single global slot, so a
// genuinely rotating key (a DIFFERENT unknown kid) is never held back by an
// unrelated kid's cooldown — and an attacker ALTERNATING between two or more
// bogus kids can no longer defeat the cooldown by never repeating the same
// one twice in a row.
func (v *WorkOSVerifier) keyForKID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	stale := v.keys == nil || v.now().Sub(v.fetchedAt) > v.ttl
	lastMiss, wasMissed := v.recentMisses[kid]
	onCooldown := !ok && wasMissed && v.now().Sub(lastMiss) < v.missCooldown
	v.mu.RUnlock()
	if ok && !stale {
		return key, nil
	}
	if onCooldown {
		return nil, fmt.Errorf("%w: no JWKS key for kid %q (a refetch for this kid was already attempted recently)", ErrInvalidToken, kid)
	}
	if !ok {
		v.recordMiss(kid)
	}
	// Miss or stale ⇒ refetch (rotation or first use).
	if err := v.refreshJWKS(ctx); err != nil {
		// If the refresh failed but we still hold the key from a prior fetch, use
		// it rather than failing closed on a transient JWKS outage.
		if ok {
			return key, nil
		}
		return nil, err
	}
	v.mu.RLock()
	key, ok = v.keys[kid]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: no JWKS key for kid %q", ErrInvalidToken, kid)
	}
	return key, nil
}

// recordMiss stamps kid's most recent miss instant, evicting the single
// oldest tracked kid when at capacity (jwksMissMapCap, P3-a) so an attacker
// cycling through an unbounded number of DISTINCT bogus kids cannot grow
// this map without limit.
func (v *WorkOSVerifier) recordMiss(kid string) {
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.recentMisses == nil {
		v.recentMisses = make(map[string]time.Time, jwksMissMapCap)
	}
	if _, exists := v.recentMisses[kid]; !exists && len(v.recentMisses) >= jwksMissMapCap {
		var oldestKID string
		var oldestAt time.Time
		first := true
		for k, t := range v.recentMisses {
			if first || t.Before(oldestAt) {
				oldestKID, oldestAt, first = k, t, false
			}
		}
		delete(v.recentMisses, oldestKID)
	}
	v.recentMisses[kid] = now
}

// jwk is one JSON Web Key (RSA) from the JWKS response.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// refreshJWKS fetches and parses the JWKS into the key cache.
func (v *WorkOSVerifier) refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("cloudserver/identity: build JWKS request: %w", err)
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("cloudserver/identity: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cloudserver/identity: JWKS endpoint returned %d", resp.StatusCode)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("cloudserver/identity: decode JWKS: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		if k.Alg != "" && k.Alg != "RS256" {
			continue // we only accept RS256
		}
		pub, err := rsaPublicKeyFromJWK(k)
		if err != nil {
			continue // skip a malformed key rather than failing the whole set
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("cloudserver/identity: JWKS contained no usable RSA keys")
	}
	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = v.now()
	v.mu.Unlock()
	return nil
}

// rsaPublicKeyFromJWK reconstructs an RSA public key from a JWK's base64url
// modulus (n) and exponent (e).
func rsaPublicKeyFromJWK(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, fmt.Errorf("empty modulus or exponent")
	}
	// e is a big-endian unsigned integer, left-pad to 8 bytes for binary.BigEndian.
	var eb [8]byte
	copy(eb[8-len(eBytes):], eBytes)
	e := binary.BigEndian.Uint64(eb[:])
	if e == 0 {
		return nil, fmt.Errorf("zero exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e),
	}, nil
}
