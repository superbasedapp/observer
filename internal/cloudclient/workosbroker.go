package cloudclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcred"
)

// WorkOS User Management (AuthKit) endpoints. The token exchange uses PKCE with
// NO client secret, so only the PUBLIC client id is needed on the node — the
// WorkOS API key stays server-side. Overridable for tests.
const (
	defaultWorkOSAuthorizeURL = "https://api.workos.com/user_management/authorize"
	//nolint:gosec // G101 false positive: a public WorkOS endpoint URL, not a credential.
	defaultWorkOSTokenURL = "https://api.workos.com/user_management/authenticate"
)

// WorkOSEndpoints locates the WorkOS authorize + token endpoints. The zero value
// resolves to the production defaults; tests point them at a mock server.
type WorkOSEndpoints struct {
	AuthorizeURL string
	TokenURL     string
}

func (e WorkOSEndpoints) authorize() string {
	if e.AuthorizeURL != "" {
		return e.AuthorizeURL
	}
	return defaultWorkOSAuthorizeURL
}

func (e WorkOSEndpoints) token() string {
	if e.TokenURL != "" {
		return e.TokenURL
	}
	return defaultWorkOSTokenURL
}

// PKCE holds a generated code verifier + its S256 challenge (RFC 7636). The
// verifier stays on the node; the challenge goes in the authorize URL; the
// verifier is presented at code exchange to prove the same client that started
// the flow is finishing it.
type PKCE struct {
	Verifier  string
	Challenge string
}

// GeneratePKCE creates a fresh code verifier (32 random bytes ⇒ 43-char
// base64url) and its SHA-256 challenge.
func GeneratePKCE() (PKCE, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return PKCE{}, fmt.Errorf("cloudclient.GeneratePKCE: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

// RandomState returns an opaque CSRF/state value for the authorize round-trip.
func RandomState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cloudclient.RandomState: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// WorkOSAuthorizeURL builds the AuthKit authorization URL the CLI opens in the
// user's browser. redirectURI is the loopback callback the CLI is listening on.
func WorkOSAuthorizeURL(ep WorkOSEndpoints, clientID, redirectURI, challenge, state string) (string, error) {
	u, err := url.Parse(ep.authorize())
	if err != nil {
		return "", fmt.Errorf("cloudclient.WorkOSAuthorizeURL: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("provider", "authkit")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// workosTokenResponse is the subset of the WorkOS authenticate response the node
// needs. WorkOS returns the authenticated user + an access token (JWT) + a
// refresh token; refresh tokens may be rotated on use, so a replacement is
// always read back.
type workosTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// exchangeWorkOSToken POSTs a token request (authorization_code or refresh_token
// grant) to the WorkOS authenticate endpoint and returns the tokens. No client
// secret is sent (PKCE public client).
func exchangeWorkOSToken(ctx context.Context, httpc *http.Client, ep WorkOSEndpoints, form url.Values) (workosTokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.token(), strings.NewReader(form.Encode()))
	if err != nil {
		return workosTokenResponse{}, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpc.Do(req)
	if err != nil {
		return workosTokenResponse{}, fmt.Errorf("workos token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return workosTokenResponse{}, fmt.Errorf("workos token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out workosTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return workosTokenResponse{}, fmt.Errorf("decode workos token response: %w", err)
	}
	if out.AccessToken == "" {
		return workosTokenResponse{}, fmt.Errorf("workos token response carried no access_token")
	}
	return out, nil
}

// WorkOSExchangeCode completes the PKCE flow: it exchanges the authorization
// code (with the code verifier) for tokens and PERSISTS the refresh token in the
// credential store. It returns the access token for immediate use. Used by
// `observer cloud login`.
func WorkOSExchangeCode(ctx context.Context, httpc *http.Client, ep WorkOSEndpoints, cred cloudcred.Store, clientID, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"code_verifier": {verifier},
	}
	tok, err := exchangeWorkOSToken(ctx, httpc, ep, form)
	if err != nil {
		return "", fmt.Errorf("cloudclient.WorkOSExchangeCode: %w", err)
	}
	if tok.RefreshToken != "" {
		if err := cred.SaveWorkOSRefresh(tok.RefreshToken); err != nil {
			return "", fmt.Errorf("cloudclient.WorkOSExchangeCode: persist refresh: %w", err)
		}
	}
	return tok.AccessToken, nil
}

// WorkOSBroker implements CloudIdentityBroker for production: it returns a valid
// WorkOS access token, refreshing through WorkOS (the sole refresh authority)
// when the cached token is near expiry. Login (the PKCE flow) is orchestrated by
// the CLI, which persists the refresh token this broker then rotates.
type WorkOSBroker struct {
	clientID string
	cred     cloudcred.Store
	ep       WorkOSEndpoints
	http     *http.Client
	now      func() time.Time
	leeway   time.Duration

	mu          sync.Mutex
	accessToken string
	accessExp   time.Time
}

// WorkOSBrokerOption configures a WorkOSBroker (test seams).
type WorkOSBrokerOption func(*WorkOSBroker)

// WithWorkOSEndpoints overrides the WorkOS endpoints (tests).
func WithWorkOSEndpoints(ep WorkOSEndpoints) WorkOSBrokerOption {
	return func(b *WorkOSBroker) { b.ep = ep }
}

// WithWorkOSHTTPClient overrides the HTTP client.
func WithWorkOSHTTPClient(c *http.Client) WorkOSBrokerOption {
	return func(b *WorkOSBroker) { b.http = c }
}

// WithWorkOSClock overrides the clock (tests).
func WithWorkOSClock(f func() time.Time) WorkOSBrokerOption {
	return func(b *WorkOSBroker) { b.now = f }
}

// NewWorkOSBroker builds a production broker over the credential store. It makes
// no network call until AccessToken is first invoked.
func NewWorkOSBroker(clientID string, cred cloudcred.Store, opts ...WorkOSBrokerOption) (*WorkOSBroker, error) {
	if strings.TrimSpace(clientID) == "" {
		return nil, fmt.Errorf("cloudclient.NewWorkOSBroker: empty client id")
	}
	if cred == nil {
		return nil, fmt.Errorf("cloudclient.NewWorkOSBroker: nil credential store")
	}
	b := &WorkOSBroker{
		clientID: clientID,
		cred:     cred,
		http:     &http.Client{Timeout: 15 * time.Second},
		now:      time.Now,
		leeway:   60 * time.Second,
	}
	for _, o := range opts {
		o(b)
	}
	return b, nil
}

// AccessToken returns a currently-valid WorkOS access token, refreshing via the
// stored refresh token when the cached token is missing or within the leeway of
// expiry. ErrNoIdentity (⇒ "run observer cloud login") when no refresh token is
// stored. It never retries transport errors — an identity failure is not a
// transport failure.
func (b *WorkOSBroker) AccessToken(ctx context.Context) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.accessToken != "" && b.now().Add(b.leeway).Before(b.accessExp) {
		return b.accessToken, nil
	}
	refresh, err := b.cred.LoadWorkOSRefresh()
	if errors.Is(err, cloudcred.ErrNotFound) {
		return "", ErrNoIdentity
	}
	if err != nil {
		return "", fmt.Errorf("cloudclient.WorkOSBroker: load refresh: %w", err)
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {b.clientID},
		"refresh_token": {refresh},
	}
	tok, err := exchangeWorkOSToken(ctx, b.http, b.ep, form)
	if err != nil {
		return "", fmt.Errorf("cloudclient.WorkOSBroker: refresh: %w", err)
	}
	// Refresh tokens rotate on use — persist the replacement so the next refresh
	// works. WorkOS returns an empty refresh only if rotation is disabled; keep
	// the existing one in that case.
	if tok.RefreshToken != "" && tok.RefreshToken != refresh {
		if err := b.cred.SaveWorkOSRefresh(tok.RefreshToken); err != nil {
			return "", fmt.Errorf("cloudclient.WorkOSBroker: persist rotated refresh: %w", err)
		}
	}
	b.accessToken = tok.AccessToken
	b.accessExp = accessTokenExpiry(tok.AccessToken, b.now())
	return b.accessToken, nil
}

// accessTokenExpiry reads the exp claim from a JWT WITHOUT verifying it — the
// node only needs to know WHEN to refresh; the SERVER verifies the signature.
// Falls back to now+5m when the token is opaque or carries no exp, so a broker
// still refreshes on a sane cadence.
func accessTokenExpiry(token string, now time.Time) time.Time {
	fallback := now.Add(5 * time.Minute)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fallback
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fallback
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return fallback
	}
	return time.Unix(claims.Exp, 0)
}
