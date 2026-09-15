package cloudgateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudclient"
	"github.com/marmutapp/superbased-observer/internal/cloudcred"
)

// Options configures a Gateway. Every dependency is explicit: this package
// reads no environment variable and no config file, so a caller can never be
// surprised about which endpoint or which credential store it ended up using.
type Options struct {
	// Grants is the consent source. Nil is permitted (bootstrap-only commands
	// such as `status` and `logout` need no consent read) and makes every
	// FEATURE send fail closed with ErrNoConsentSource.
	Grants GrantStore
	// CredDir roots the credential store's file fallback (the observer dir).
	// Ignored when Cred is supplied.
	CredDir string
	// Cred overrides the credential store. Tests supply a fake; production
	// leaves it nil and gets cloudcred.OpenForHost(CredDir, host-of-BaseURL).
	Cred cloudcred.Store
	// BaseURL is the cloud service origin. Empty means "not configured": the
	// gateway still opens (credential inspection and local clears work) and
	// every network method returns ErrNoBaseURL.
	BaseURL string
	// DevToken is a WorkOS access token for the local-testing stub broker. It is
	// held in memory and never persisted.
	DevToken string
	// WorkOSClientID is the PUBLIC WorkOS client id used for the production
	// broker and the PKCE sign-in flow. Empty disables the production broker.
	WorkOSClientID string
	// HTTPClient, MaxRetries and Backoff are passed through to the network
	// client (tests pin them; production leaves them zero).
	HTTPClient *http.Client
	MaxRetries int
	Backoff    func(attempt int) time.Duration
	// Logger is used for credential-backend diagnostics; nil means slog.Default.
	Logger *slog.Logger
	// Now returns the current time, for grant expiry. Nil means time.Now.
	Now func() time.Time
	// OnTokenHealed, when non-nil, is invoked each time an expired API token
	// was transparently re-exchanged through the persisted sign-in (the network
	// client's one-shot self-heal). It receives no token; callers use it to
	// tell the user the heal happened.
	OnTokenHealed func()
}

// Gateway is the consent-gated egress seam. It holds no goroutines and makes no
// network call until a Bootstrap* or Feature* method is invoked.
type Gateway struct {
	grants GrantStore
	cred   cloudcred.Store
	opts   Options
	now    func() time.Time

	// The network client is built LAZILY, on first use. That is not an
	// optimization: constructing it loads-or-CREATES the device signing key, so
	// an eager build would make a read-only command (`observer cloud status`)
	// mint a credential as a side effect and then report it as present. Nothing
	// that only inspects local state should change local state.
	clientOnce sync.Once
	client     *cloudclient.Client
	clientErr  error
}

// Open constructs a Gateway. It opens the credential store — scoped to the
// host of opts.BaseURL, so a node that switches cloud estates (staging vs.
// production) does not carry one estate's API token/WorkOS refresh into the
// other (the device signing key stays shared; see cloudcred.OpenForHost) —
// but creates no device key, builds no network client, and performs no
// network I/O.
func Open(opts Options) (*Gateway, error) {
	cred := opts.Cred
	if cred == nil {
		cred = cloudcred.OpenForHost(opts.CredDir, hostFromBaseURL(opts.BaseURL), opts.Logger)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Gateway{grants: opts.Grants, cred: cred, opts: opts, now: now}, nil
}

// hostFromBaseURL derives the bare, lower-cased host cloudcred.OpenForHost
// scopes credentials to, from a cloud base URL. An empty base URL or one
// that fails to parse falls back to "" — cloudcred's legacy single-slot
// scope — rather than failing Open: an unconfigured gateway still serves
// local credential inspection (Configured()/BaseURL() already report the
// missing base URL, and every network method returns ErrNoBaseURL).
func hostFromBaseURL(baseURL string) string {
	if baseURL == "" {
		return ""
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// network returns the lazily-built client, or ErrNoBaseURL when the gateway is
// unconfigured. A construction failure is cached: it is deterministic (a bad
// broker configuration, an unreadable credential store), so retrying it per call
// would only repeat the same error more expensively.
func (g *Gateway) network() (*cloudclient.Client, error) {
	if g.opts.BaseURL == "" {
		return nil, ErrNoBaseURL
	}
	g.clientOnce.Do(func() {
		broker, err := resolveBroker(g.cred, g.opts.DevToken, g.opts.WorkOSClientID)
		if err != nil {
			g.clientErr = err
			return
		}
		client, err := cloudclient.New(cloudclient.Options{
			BaseURL:       g.opts.BaseURL,
			Cred:          g.cred,
			Broker:        broker,
			HTTPClient:    g.opts.HTTPClient,
			MaxRetries:    g.opts.MaxRetries,
			Backoff:       g.opts.Backoff,
			Logger:        g.opts.Logger,
			OnTokenHealed: g.opts.OnTokenHealed,
		})
		if err != nil {
			g.clientErr = fmt.Errorf("cloudgateway: build cloud client: %w", err)
			return
		}
		g.client = client
	})
	if g.clientErr != nil {
		return nil, g.clientErr
	}
	return g.client, nil
}

// resolveBroker picks the identity broker for the device-token exchange: the
// dev stub when a dev token is supplied (in-memory, never stored), else the
// production WorkOS broker when a client id is configured, else nil (Exchange
// then reports that there is no identity to exchange).
func resolveBroker(cred cloudcred.Store, devToken, workosClientID string) (cloudclient.CloudIdentityBroker, error) {
	if devToken != "" {
		return &cloudclient.StubBroker{Token: devToken}, nil
	}
	if workosClientID == "" {
		return nil, nil
	}
	broker, err := cloudclient.NewWorkOSBroker(workosClientID, cred)
	if err != nil {
		return nil, fmt.Errorf("cloudgateway.Open: build WorkOS broker: %w", err)
	}
	return broker, nil
}

// --- local, no-network inspection -------------------------------------------

// Configured reports whether a cloud base URL is set (and therefore whether any
// network method can run at all).
func (g *Gateway) Configured() bool { return g.opts.BaseURL != "" }

// BaseURL returns the configured cloud origin, or "" when unconfigured.
func (g *Gateway) BaseURL() string { return g.opts.BaseURL }

// CredentialBackend names the active credential store ("keychain", "file", or
// "unavailable").
func (g *Gateway) CredentialBackend() string { return g.cred.Backend() }

// CredentialDiagnostic returns a human-readable degraded-security warning, or
// "" when the backend is OS-backed.
func (g *Gateway) CredentialDiagnostic() string { return g.cred.SecurityDiagnostic() }

// DeviceKeyPresent reports whether a device signing key has been created.
func (g *Gateway) DeviceKeyPresent() bool {
	_, err := g.cred.LoadDeviceKey()
	return err == nil
}

// APITokenPresent reports whether a device-bound API token has been exchanged.
func (g *Gateway) APITokenPresent() bool {
	_, err := g.cred.LoadAPIToken()
	return err == nil
}

// WorkOSSignInPresent reports whether persisted WorkOS refresh material — a
// sign-in — is stored. It is what the API-token self-heal re-exchanges through
// when the short-lived token ages out: with it present an expired token heals
// on the next `observer cloud` call; without it (never signed in with WorkOS,
// or a --dev-token session, which stores none) an expired token needs a new
// `observer cloud login`. No network call.
func (g *Gateway) WorkOSSignInPresent() bool {
	_, err := g.cred.LoadWorkOSRefresh()
	return err == nil
}

// ClearCredentials removes the stored device key, API token and WorkOS refresh
// material. It is purely local: signing out of your own machine must work
// offline, so this never touches the network.
func (g *Gateway) ClearCredentials() error {
	if err := g.cred.Clear(); err != nil {
		return fmt.Errorf("cloudgateway.ClearCredentials: %w", err)
	}
	return nil
}

// DeviceThumbprint returns the RFC 7638 thumbprint of the device key — the
// node-local account pseudonym a consent receipt binds. It makes no network
// call, but it does load-or-create the device key.
func (g *Gateway) DeviceThumbprint() (string, error) {
	c, err := g.network()
	if err != nil {
		return "", err
	}
	return c.DeviceThumbprint(), nil
}

// UploadEndpoint returns the immutable absolute URL session evidence is POSTed
// to, for the receipt's endpoint binding (FD1). No network call.
func (g *Gateway) UploadEndpoint() (string, error) {
	c, err := g.network()
	if err != nil {
		return "", err
	}
	return c.UploadEndpoint(), nil
}

// StructuralEndpoint returns the immutable absolute URL structural snapshots
// are POSTed to, for the standing receipt's endpoint binding. No network call.
func (g *Gateway) StructuralEndpoint() (string, error) {
	c, err := g.network()
	if err != nil {
		return "", err
	}
	return c.StructuralEndpoint(), nil
}

// CommunityEndpoint returns the immutable absolute URL community contributions
// are POSTed to, for the standing receipt's endpoint binding (Sol review F2/F3
// — a community grant must bind the endpoint community egress actually uses,
// not the structural one). No network call.
func (g *Gateway) CommunityEndpoint() (string, error) {
	c, err := g.network()
	if err != nil {
		return "", err
	}
	return c.CommunityEndpoint(), nil
}

// --- bootstrap lane ---------------------------------------------------------
//
// These are the `account_device_operations` purpose: authorized by the user's
// own sign-in ACTION, never by a stored grant (R2 disposition F10). They are
// named Bootstrap* so an ungated call is visible as such at every call site.

// BootstrapExchange performs the device-token exchange: it obtains a WorkOS
// access token from the broker, signs the server's nonce with the device key,
// and stores the resulting short-lived device-bound API token. This IS the
// sign-in action, so it needs no grant.
func (g *Gateway) BootstrapExchange(ctx context.Context) error {
	c, err := g.network()
	if err != nil {
		return err
	}
	return c.Exchange(ctx)
}

// BootstrapLogout revokes this device's API token server-side. Callers treat
// every failure as non-blocking and clear local credentials regardless.
func (g *Gateway) BootstrapLogout(ctx context.Context) error {
	c, err := g.network()
	if err != nil {
		return err
	}
	return c.Logout(ctx)
}

// BootstrapRequestDeletion asks the hosted service to delete the authenticated
// account. Deleting the account you signed into is an account-device operation,
// not a feature disclosure — it sends no session-derived data at all.
func (g *Gateway) BootstrapRequestDeletion(ctx context.Context) (cloudclient.DeletionResponse, error) {
	c, err := g.network()
	if err != nil {
		return cloudclient.DeletionResponse{}, err
	}
	return c.RequestDeletion(ctx)
}

// --- bootstrap sign-in helpers (no network of their own) ---------------------

// GeneratePKCE mints a PKCE verifier/challenge pair for the loopback sign-in
// flow. Local computation only.
func (g *Gateway) GeneratePKCE() (cloudclient.PKCE, error) { return cloudclient.GeneratePKCE() }

// RandomState mints the CSRF state value for the loopback sign-in flow.
func (g *Gateway) RandomState() (string, error) { return cloudclient.RandomState() }

// AuthorizeURL builds the WorkOS AuthKit authorize URL for the loopback flow.
// Local computation only.
func (g *Gateway) AuthorizeURL(clientID, redirectURI, challenge, state string) (string, error) {
	return cloudclient.WorkOSAuthorizeURL(cloudclient.WorkOSEndpoints{}, clientID, redirectURI, challenge, state)
}

// BootstrapExchangeWorkOSCode exchanges a PKCE authorization code with WorkOS
// (no client secret) and persists the rotating refresh material. This is the
// OAuth leg of the sign-in action — bootstrap egress, to the identity provider
// rather than to the cloud service.
func (g *Gateway) BootstrapExchangeWorkOSCode(ctx context.Context, clientID, code, verifier string) error {
	_, err := cloudclient.WorkOSExchangeCode(ctx, http.DefaultClient, cloudclient.WorkOSEndpoints{},
		g.cred, clientID, code, verifier)
	return err
}

// --- error classification ---------------------------------------------------

// ErrSignInExpired is returned (wrapped) by any authenticated feature or
// bootstrap call whose API token the server rejected AND whose one-shot
// self-heal — a re-exchange through the persisted WorkOS sign-in, the same
// bootstrap path `observer cloud login` ends with — could not mint a
// replacement. The recovery is a new sign-in. It is the network lane's own
// sentinel, re-exported so callers classify it with errors.Is without importing
// the lane; a caller MUST treat it as a credential state (retryable after
// login), never as the server rejecting the item that happened to hit it.
var ErrSignInExpired = cloudclient.ErrSignInExpired

// HTTPStatus reports the HTTP status a cloud API error carried, if any. It
// exists so a caller can classify retryable vs terminal outcomes without naming
// (and therefore importing) the network lane's error type — which is what keeps
// the egress import pin narrow.
func HTTPStatus(err error) (int, bool) {
	var apiErr *cloudclient.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode, true
	}
	return 0, false
}

// HTTPErrorDetail is what a cloud API refusal carried, decoded from the
// service's `{"code": ..., "error": ...}` body. Extra is every OTHER top-level
// string field the body had (e.g. a 409 cross_device_conflict's
// owner_device_hint / next_window recovery hints), so a caller can print a
// recovery action without this package naming every server field.
type HTTPErrorDetail struct {
	StatusCode int
	Code       string
	Message    string
	Extra      map[string]string
}

// HTTPError decodes a cloud API error. ok is false for a non-API error (a
// transport fault, a local refusal). A body that is not JSON yields the raw
// body as Message with an empty Code — the caller still gets the status.
func HTTPError(err error) (HTTPErrorDetail, bool) {
	var apiErr *cloudclient.APIError
	if !errors.As(err, &apiErr) {
		return HTTPErrorDetail{}, false
	}
	d := HTTPErrorDetail{StatusCode: apiErr.StatusCode, Message: apiErr.Body}
	var raw map[string]any
	if json.Unmarshal([]byte(apiErr.Body), &raw) != nil {
		return d, true
	}
	d.Extra = map[string]string{}
	for k, v := range raw {
		str, isStr := v.(string)
		if !isStr {
			continue
		}
		switch k {
		case "code":
			d.Code = str
		case "error":
			d.Message = str
		default:
			d.Extra[k] = str
		}
	}
	return d, true
}
