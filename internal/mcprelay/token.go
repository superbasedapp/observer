package mcprelay

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentid"
	"github.com/marmutapp/superbased-observer/internal/dpop"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// KeyStore is the `agent-access-key` keychain slot accessor
// (orgclient.AgentAccessKeyStore satisfies it; internal/orgclient/
// agentaccess_register.go is the one owner of that slot - the relay never
// reads a key file). Only the read half is needed here: the relay never
// writes the slot.
type KeyStore interface {
	LoadAgentAccessKey() (orgclient.AgentAccessKey, error)
}

// ActorSpec is what the node asserts about itself in every sbo-actor+jwt
// (agentid.ActorClaims, doc3 §4.3): the values come from the P1
// registration (orgclient.AgentAccessRegistration) and the enrolment.
type ActorSpec struct {
	// NodeID is the assertion's iss (the node id; the machine fingerprint
	// when the node has no other id).
	NodeID string
	// CredentialID is the registered per-device credential id (sub).
	CredentialID string
	// MemberID / MachineFP / CredGen are the registered binding the STS
	// re-checks on every exchange (R2).
	MemberID  string
	MachineFP string
	CredGen   int64
	// Agent is the product client id the relay serves (e.g.
	// "agent:claude-code"); empty means no product claim.
	Agent string
}

// TokenClientConfig configures a TokenClient.
type TokenClientConfig struct {
	// TokenEndpoint is the org STS token endpoint as the STS names it
	// (https://<issuer>/oauth2/token): the actor assertion's aud and the
	// token-endpoint proof's htu.
	TokenEndpoint string
	// TokenURL is where the endpoint is DIALLED when it differs from
	// TokenEndpoint (an internal hostname, a test listener); "" =
	// TokenEndpoint.
	TokenURL string
	// Keys is the agent-access-key slot.
	Keys KeyStore
	// SubjectToken loads the enrolment bearer (the subject_token). It is a
	// function so the bearer store stays the orgclient's (never copied).
	SubjectToken func(ctx context.Context) (string, error)
	// Actor is the node's actor-assertion identity.
	Actor ActorSpec
	// HTTP performs the exchange. The composition root builds it through
	// internal/mcpegress so every upstream dial is policy-guarded (§12.2).
	HTTP *http.Client
	// Now is the clock (nil -> time.Now).
	Now func() time.Time
	// EarlyRefresh re-exchanges when less than this remains of a cached
	// token's lifetime (zero -> DefaultEarlyRefresh).
	EarlyRefresh time.Duration
	// ExpirySkew is the clock-skew margin before a cached token's real
	// expiry at which the relay stops presenting it (doc3 §10 "STS down":
	// tokens EXPIRE -> fail closed). While an early refresh fails because
	// the STS is unavailable, the still-valid cached token keeps serving
	// until ExpiresAt - ExpirySkew (zero or out of range ->
	// DefaultExpirySkew; capped at MaxExpirySkew).
	ExpirySkew time.Duration
	// ActorLifetime is the actor assertion's exp - iat (zero ->
	// DefaultActorLifetime; capped at agentid.MaxActorLifetime).
	ActorLifetime time.Duration
	// Log receives diagnostics - never token material.
	Log *slog.Logger
}

// Token-client defaults.
const (
	// DefaultEarlyRefresh is the refresh lead time.
	DefaultEarlyRefresh = 30 * time.Second
	// DefaultActorLifetime is the actor assertion lifetime.
	DefaultActorLifetime = 30 * time.Second
	// DefaultExpirySkew is the clock-skew margin before real expiry.
	DefaultExpirySkew = 5 * time.Second
	// MaxExpirySkew bounds ExpirySkew (a larger margin would re-open the
	// "fails closed long before expiry" gap Lane CHAOS Q2 closed).
	MaxExpirySkew = 5 * time.Second
	// refreshBackoffBase / refreshBackoffMax bound the retry cadence of a
	// failing early refresh while a still-valid cached token serves.
	refreshBackoffBase = time.Second
	refreshBackoffMax  = 10 * time.Second
	// maxTokenResponseBytes caps the token response body.
	maxTokenResponseBytes = 64 << 10
)

// Token-client errors.
var (
	// ErrExchangeRefused: the STS refused the exchange (a 4xx OAuth error);
	// the wrapped ExchangeError carries the closed error code.
	ErrExchangeRefused = errors.New("mcprelay: the STS refused the token exchange")
	// ErrSTSUnavailable: the STS could not be reached or answered 5xx.
	ErrSTSUnavailable = errors.New("mcprelay: the STS is unavailable")
	// ErrNoAgentAccessKey: the keychain slot holds no agent-access key
	// (run `observer org enroll` / agent-access registration first).
	ErrNoAgentAccessKey = errors.New("mcprelay: no agent-access key registered on this node")
)

// ExchangeError is a typed STS refusal.
type ExchangeError struct {
	Status int
	Code   string
}

// Error implements error.
func (e *ExchangeError) Error() string {
	return fmt.Sprintf("mcprelay: token exchange refused: %d %s", e.Status, e.Code)
}

// Is makes every *ExchangeError match ErrExchangeRefused.
func (e *ExchangeError) Is(target error) bool { return target == ErrExchangeRefused }

// AccessToken is one minted at+jwt held IN MEMORY ONLY. Value is never
// written anywhere by this package and never logged; the signer it is bound
// to (cnf.jkt) rides along so per-request proofs use exactly that key.
type AccessToken struct {
	Value     string
	ExpiresAt time.Time
	// JKT is the RFC 7638 thumbprint of the DPoP key the token is bound to.
	JKT string
	// Attestation is the client attestation the token was minted with.
	Attestation string

	signer crypto.Signer
	alg    string
}

// Valid reports whether the token is usable at now with lead time to spare.
func (t AccessToken) Valid(now time.Time, lead time.Duration) bool {
	return t.Value != "" && now.Add(lead).Before(t.ExpiresAt)
}

// TokenClient is the RFC 8693 exchange client + DPoP proof signer over the
// node's agent-access key (doc3 §12.3). Tokens are cached per (resource,
// attestation) in memory, refreshed early, and dropped by Invalidate (the
// rotate-and-retry path on a 401 invalid_token).
type TokenClient struct {
	cfg TokenClientConfig

	mu    sync.Mutex
	cache map[string]AccessToken
	retry map[string]refreshBackoff // failing early refreshes, per cache key
	nonce string                    // the last DPoP-Nonce the STS issued
}

// refreshBackoff is the retry state of a failing early refresh: the number
// of consecutive unavailable exchanges and when the next one may run.
type refreshBackoff struct {
	failures int
	next     time.Time
}

// backoffAfter returns the wait after the n-th consecutive failure
// (1s, 2s, 4s, 8s, then 10s).
func backoffAfter(n int) time.Duration {
	d := refreshBackoffBase
	for i := 1; i < n && d < refreshBackoffMax; i++ {
		d *= 2
	}
	if d > refreshBackoffMax {
		d = refreshBackoffMax
	}
	return d
}

// NewTokenClient validates cfg and returns the client.
func NewTokenClient(cfg TokenClientConfig) (*TokenClient, error) {
	if _, err := dpop.CanonicalHTU(cfg.TokenEndpoint); err != nil {
		return nil, fmt.Errorf("mcprelay.NewTokenClient: token endpoint: %w", err)
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = cfg.TokenEndpoint
	} else if _, err := dpop.CanonicalHTU(cfg.TokenURL); err != nil {
		return nil, fmt.Errorf("mcprelay.NewTokenClient: token url: %w", err)
	}
	if cfg.Keys == nil {
		return nil, errors.New("mcprelay.NewTokenClient: Keys (the agent-access-key slot) is required")
	}
	if cfg.SubjectToken == nil {
		return nil, errors.New("mcprelay.NewTokenClient: SubjectToken loader is required")
	}
	if cfg.HTTP == nil {
		return nil, errors.New("mcprelay.NewTokenClient: HTTP client is required (build it through internal/mcpegress)")
	}
	if cfg.Actor.CredentialID == "" || cfg.Actor.MemberID == "" || cfg.Actor.MachineFP == "" {
		return nil, errors.New("mcprelay.NewTokenClient: Actor.CredentialID, MemberID and MachineFP are required")
	}
	if cfg.Actor.NodeID == "" {
		cfg.Actor.NodeID = cfg.Actor.MachineFP
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.EarlyRefresh <= 0 {
		cfg.EarlyRefresh = DefaultEarlyRefresh
	}
	if cfg.ActorLifetime <= 0 || cfg.ActorLifetime > agentid.MaxActorLifetime {
		cfg.ActorLifetime = DefaultActorLifetime
	}
	if cfg.ExpirySkew <= 0 || cfg.ExpirySkew > MaxExpirySkew {
		cfg.ExpirySkew = DefaultExpirySkew
	}
	return &TokenClient{cfg: cfg, cache: map[string]AccessToken{}, retry: map[string]refreshBackoff{}}, nil
}

func (c *TokenClient) log() *slog.Logger {
	if c.cfg.Log != nil {
		return c.cfg.Log
	}
	return slog.Default()
}

func cacheKey(resource, attestation, project string) string {
	return resource + "\x00" + attestation + "\x00" + project
}

// Token returns a valid access token for resource (the vserver URI the
// token's aud must equal exactly) minted with the given client attestation,
// exchanging a fresh one when the cache is empty or within EarlyRefresh of
// expiry. The token carries no project context (TokenFor with "").
func (c *TokenClient) Token(ctx context.Context, resource, attestation string) (AccessToken, error) {
	return c.TokenFor(ctx, resource, attestation, "")
}

// TokenFor is Token for a call made in a RELAY-ATTESTED project context
// (P11(e), R10.9): projectHash (from the relay's own ProjectResolver, never
// a caller-supplied value) is signed into the actor assertion's
// sbo_project_hash and the STS copies it into the at+jwt. Tokens are cached
// per (resource, attestation, project), so a session in project A never
// reuses a token attested for project B. "" = no project context.
//
// STS outage (doc3 §10 "STS down", Lane CHAOS Q2): when an early refresh
// fails because the STS is UNAVAILABLE (ErrSTSUnavailable), the cached token
// keeps serving while it is valid with ExpirySkew to spare, and the refresh
// is retried with backoff (1s doubling to 10s) instead of on every call. The
// relay fails closed only at real expiry minus the skew. A REFUSAL
// (ErrExchangeRefused - revoked credential, stale generation) evicts the
// cached token and fails closed at once.
func (c *TokenClient) TokenFor(ctx context.Context, resource, attestation, projectHash string) (AccessToken, error) {
	if projectHash != "" && !agentid.ValidProjectHash(projectHash) {
		return AccessToken{}, errors.New("mcprelay.TokenClient.TokenFor: malformed project hash")
	}
	if resource == "" {
		return AccessToken{}, errors.New("mcprelay.TokenClient.Token: resource required")
	}
	if attestation == "" {
		attestation = agentid.AttestConfigured.String()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := cacheKey(resource, attestation, projectHash)
	now := c.cfg.Now()
	cached, ok := c.cache[key]
	if ok && cached.Valid(now, c.cfg.EarlyRefresh) {
		return cached, nil
	}
	// usable: the cached token may still be presented (valid past the skew).
	usable := ok && cached.Valid(now, c.cfg.ExpirySkew)
	if b, backingOff := c.retry[key]; usable && backingOff && now.Before(b.next) {
		return cached, nil
	}
	t, err := c.exchange(ctx, resource, attestation, projectHash)
	if err != nil {
		if usable && errors.Is(err, ErrSTSUnavailable) {
			b := c.retry[key]
			b.failures++
			wait := backoffAfter(b.failures)
			b.next = now.Add(wait)
			c.retry[key] = b
			c.log().Warn("mcprelay: early token refresh failed; serving the still-valid cached token",
				"resource", resource, "attestation", attestation, "failures", b.failures,
				"retry_in", wait.String(), "expires_in", cached.ExpiresAt.Sub(now).Round(time.Second).String(), "err", err)
			return cached, nil
		}
		if errors.Is(err, ErrExchangeRefused) {
			// The STS actively refused: never keep presenting the old token.
			delete(c.cache, key)
		}
		delete(c.retry, key)
		return AccessToken{}, err
	}
	c.cache[key] = t
	delete(c.retry, key)
	return t, nil
}

// Invalidate drops the cached token for (resource, attestation) so the next
// Token call re-exchanges - the first half of rotate-and-retry.
func (c *TokenClient) Invalidate(resource, attestation string) {
	c.InvalidateFor(resource, attestation, "")
}

// InvalidateFor is Invalidate for a TokenFor cache entry (P11(e)).
func (c *TokenClient) InvalidateFor(resource, attestation, projectHash string) {
	if attestation == "" {
		attestation = agentid.AttestConfigured.String()
	}
	c.mu.Lock()
	key := cacheKey(resource, attestation, projectHash)
	delete(c.cache, key)
	delete(c.retry, key)
	c.mu.Unlock()
}

// Proof signs a resource-profile DPoP proof for one request with the key
// tok is bound to: htm/htu of the request, ath over tok, and the relay's
// sbo_corr correlation claim (R11.8) when corr is set.
func (c *TokenClient) Proof(tok AccessToken, htm, htu string, corr *dpop.Correlation) (string, error) {
	if tok.signer == nil {
		return "", errors.New("mcprelay.TokenClient.Proof: token carries no signer")
	}
	p, err := dpop.CreateWith(tok.signer, tok.alg, dpop.Claims{HTM: htm, HTU: htu, ATH: dpop.ATH(tok.Value), Corr: corr}, c.cfg.Now(), nil)
	if err != nil {
		return "", fmt.Errorf("mcprelay.TokenClient.Proof: %w", err)
	}
	return p, nil
}

// loadKey reads the agent-access key from the slot and wraps it as an
// agentid.Signer (kid = thumbprint).
func (c *TokenClient) loadKey() (orgclient.AgentAccessKey, agentid.Signer, string, error) {
	k, err := c.cfg.Keys.LoadAgentAccessKey()
	if errors.Is(err, orgclient.ErrNoSecret) {
		return orgclient.AgentAccessKey{}, nil, "", ErrNoAgentAccessKey
	}
	if err != nil {
		return orgclient.AgentAccessKey{}, nil, "", fmt.Errorf("mcprelay: load agent-access key: %w", err)
	}
	s, err := agentid.NewKeySigner(k.Signer, "")
	if err != nil {
		return orgclient.AgentAccessKey{}, nil, "", fmt.Errorf("mcprelay: agent-access key: %w", err)
	}
	_, jwk := s.PublicJWK()
	jkt, err := jwk.Thumbprint()
	if err != nil {
		return orgclient.AgentAccessKey{}, nil, "", fmt.Errorf("mcprelay: agent-access key: %w", err)
	}
	return k, s, jkt, nil
}

// actorAssertion mints a fresh single-use sbo-actor+jwt; projectHash is the
// relay-attested sbo_project_hash ("" = none).
func (c *TokenClient) actorAssertion(s agentid.Signer, attestation, projectHash string, now time.Time) (string, error) {
	jti, err := randomID()
	if err != nil {
		return "", err
	}
	claims := agentid.ActorClaims{
		Iss: c.cfg.Actor.NodeID, Sub: c.cfg.Actor.CredentialID, Aud: c.cfg.TokenEndpoint, Jti: jti,
		Iat: now.Unix(), Exp: now.Add(c.cfg.ActorLifetime).Unix(),
		SboMember: c.cfg.Actor.MemberID, SboMachineFP: c.cfg.Actor.MachineFP, SboCredGen: c.cfg.Actor.CredGen,
		SboAgent: c.cfg.Actor.Agent, SboClientAttestation: attestation,
		SboProjectHash: projectHash,
	}
	return agentid.CreateActorAssertion(s, claims)
}

// tokenResponse is the RFC 6749 §5.1 success body.
type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
}

// exchange runs one RFC 8693 token exchange (c.mu held). A use_dpop_nonce
// challenge is answered once with the issued nonce.
func (c *TokenClient) exchange(ctx context.Context, resource, attestation, projectHash string) (AccessToken, error) {
	subject, err := c.cfg.SubjectToken(ctx)
	if err != nil {
		return AccessToken{}, fmt.Errorf("mcprelay: load enrolment bearer: %w", err)
	}
	if subject == "" {
		return AccessToken{}, errors.New("mcprelay: no enrolment bearer (the node is not enrolled)")
	}
	key, signer, jkt, err := c.loadKey()
	if err != nil {
		return AccessToken{}, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		now := c.cfg.Now()
		actor, err := c.actorAssertion(signer, attestation, projectHash, now)
		if err != nil {
			return AccessToken{}, fmt.Errorf("mcprelay: actor assertion: %w", err)
		}
		proof, err := dpop.CreateWith(key.Signer, key.Alg, dpop.Claims{HTM: http.MethodPost, HTU: c.cfg.TokenEndpoint, Nonce: c.nonce}, now, nil)
		if err != nil {
			return AccessToken{}, fmt.Errorf("mcprelay: token-endpoint proof: %w", err)
		}
		form := url.Values{
			"grant_type":           {agentid.GrantTypeTokenExchange},
			"subject_token":        {subject},
			"subject_token_type":   {agentid.TokenTypeAccessToken},
			"actor_token":          {actor},
			"actor_token_type":     {agentid.TokenTypeJWT},
			"resource":             {resource},
			"requested_token_type": {agentid.TokenTypeAccessToken},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return AccessToken{}, fmt.Errorf("mcprelay: token request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("DPoP", proof)
		resp, err := c.cfg.HTTP.Do(req)
		if err != nil {
			// ErrSTSUnavailable is the sole classification: the transport cause
			// (which may wrap a context cancellation) is text only, so the
			// fallback ladder keyed on ErrSTSUnavailable/ErrExchangeRefused and
			// the wrapper's context.Canceled check cannot be crossed.
			return AccessToken{}, fmt.Errorf("%w: %v", ErrSTSUnavailable, err) //nolint:errorlint // single-sentinel classification; cause deliberately not in the chain
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
		_ = resp.Body.Close()
		if n := resp.Header.Get("DPoP-Nonce"); n != "" {
			c.nonce = n
		}
		if resp.StatusCode == http.StatusOK {
			var tr tokenResponse
			if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
				return AccessToken{}, fmt.Errorf("%w: malformed token response", ErrSTSUnavailable)
			}
			if !strings.EqualFold(tr.TokenType, "DPoP") {
				// R9.1: the relay always mints DPoP-bound tokens; a bearer
				// answer means the STS did not bind the proof - refuse it.
				return AccessToken{}, fmt.Errorf("%w: token_type %q is not DPoP", ErrExchangeRefused, tr.TokenType)
			}
			ttl := time.Duration(tr.ExpiresIn) * time.Second
			if ttl <= 0 {
				ttl = time.Minute
			}
			c.log().Debug("mcprelay: access token minted", "resource", resource, "attestation", attestation, "expires_in_s", tr.ExpiresIn, "jkt", jkt)
			return AccessToken{Value: tr.AccessToken, ExpiresAt: now.Add(ttl), JKT: jkt, Attestation: attestation, signer: key.Signer, alg: key.Alg}, nil
		}
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == string(agentid.OAuthUseDPoPNonce) && attempt == 0 && c.nonce != "" {
			continue // one retry with the issued nonce
		}
		if resp.StatusCode >= 500 || e.Error == string(agentid.OAuthUnavailable) {
			return AccessToken{}, fmt.Errorf("%w: %d %s", ErrSTSUnavailable, resp.StatusCode, e.Error)
		}
		return AccessToken{}, &ExchangeError{Status: resp.StatusCode, Code: e.Error}
	}
	return AccessToken{}, fmt.Errorf("%w: nonce challenge not satisfied", ErrExchangeRefused)
}

// randomID returns 16 random bytes, base64url.
func randomID() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(randReader, b[:]); err != nil {
		return "", fmt.Errorf("mcprelay: random id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
