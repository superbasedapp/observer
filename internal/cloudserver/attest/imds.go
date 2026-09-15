package attest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultIMDSEndpoint is the well-known Azure Instance Metadata Service token
// endpoint, reachable only from inside an Azure VM/Container App network
// namespace (link-local, never routable off-box).
const (
	defaultIMDSEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"
	imdsAPIVersion      = "2018-02-01"
	// tokenRefreshSkew is how long before the reported expiry a cached token is
	// treated as stale, so a caller never hands out a token that expires
	// mid-request.
	tokenRefreshSkew = 5 * time.Minute
)

// ManagedIdentityTokenSource mints bearer tokens from Azure IMDS — the
// managed-identity credential for a Container App or VM, with NO secret in
// code, config, or Key Vault (gap 5.1: the production ContentLogging ARM
// canary needs a real, non-operator-attested credential; this is that
// credential's source). It caches the token per audience until
// tokenRefreshSkew before the reported expiry.
type ManagedIdentityTokenSource struct {
	// Endpoint overrides the IMDS token endpoint. "" -> the real IMDS URL. Tests
	// inject an httptest.Server URL here — IMDS itself is unreachable off an
	// Azure host, so this field is what makes the source testable at all.
	Endpoint string
	// ClientID selects a user-assigned managed identity. "" -> the system-
	// assigned identity (or the host's sole identity, if only one is attached).
	ClientID string
	// HTTPClient performs the request. nil -> a 5s-timeout default.
	HTTPClient *http.Client
	// Now returns the current time. nil -> time.Now — a test seam.
	Now func() time.Time

	mu    sync.Mutex
	cache map[string]cachedToken
}

type cachedToken struct {
	value     string
	expiresAt time.Time
}

var _ TokenSource = (*ManagedIdentityTokenSource)(nil)

// Token returns a cached or freshly minted bearer token scoped to audience
// (the ARM resource audience the ContentLogging canary reads). Concurrent
// callers for the same audience may each mint once under a cache miss — IMDS
// tokens are cheap and idempotent to request, so this trades a rare duplicate
// call for a simpler lock (no per-audience singleflight).
func (m *ManagedIdentityTokenSource) Token(ctx context.Context, audience string) (string, error) {
	audience = strings.TrimSpace(audience)
	if audience == "" {
		return "", errors.New("attest: ManagedIdentityTokenSource.Token: empty audience")
	}
	now := m.now()

	m.mu.Lock()
	if m.cache != nil {
		if c, ok := m.cache[audience]; ok && now.Before(c.expiresAt) {
			m.mu.Unlock()
			return c.value, nil
		}
	}
	m.mu.Unlock()

	value, expiresAt, err := m.fetch(ctx, audience, now)
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	if m.cache == nil {
		m.cache = make(map[string]cachedToken)
	}
	m.cache[audience] = cachedToken{value: value, expiresAt: expiresAt}
	m.mu.Unlock()

	return value, nil
}

func (m *ManagedIdentityTokenSource) fetch(ctx context.Context, audience string, now time.Time) (string, time.Time, error) {
	endpoint := m.Endpoint
	if endpoint == "" {
		endpoint = defaultIMDSEndpoint
	}
	q := url.Values{}
	q.Set("api-version", imdsAPIVersion)
	q.Set("resource", audience)
	if cid := strings.TrimSpace(m.ClientID); cid != "" {
		q.Set("client_id", cid)
	}
	reqURL := endpoint + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("attest: build IMDS request: %w", err)
	}
	// The IMDS contract: every request must carry this header, and IMDS refuses
	// any request that doesn't (a defense against SSRF from outside the host).
	req.Header.Set("Metadata", "true")

	client := m.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("attest: IMDS unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", time.Time{}, fmt.Errorf("attest: IMDS status %d", resp.StatusCode)
	}

	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresOn   string `json:"expires_on"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", time.Time{}, fmt.Errorf("attest: decode IMDS response: %w", err)
	}
	token := strings.TrimSpace(body.AccessToken)
	if token == "" {
		return "", time.Time{}, errors.New("attest: IMDS response carried no access_token")
	}

	expiresAt := now.Add(10 * time.Minute) // conservative fallback if expires_on is absent/unparseable
	if body.ExpiresOn != "" {
		if secs, err := strconv.ParseInt(strings.TrimSpace(body.ExpiresOn), 10, 64); err == nil {
			expiresAt = time.Unix(secs, 0)
		}
	}
	cacheUntil := expiresAt.Add(-tokenRefreshSkew)
	if cacheUntil.Before(now) {
		// The token is already inside its refresh skew (or IMDS reported a
		// near-immediate expiry) — don't cache it, but still hand it back for
		// this one call.
		cacheUntil = now
	}
	return token, cacheUntil, nil
}

func (m *ManagedIdentityTokenSource) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}
