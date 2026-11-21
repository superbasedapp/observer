package hostclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// Sender defaults.
const (
	// DefaultTimeout bounds one request, connection to last body byte.
	DefaultTimeout = 30 * time.Second
	// DefaultMaxResponseBytes bounds an answer body; a longer one is not
	// verified.
	DefaultMaxResponseBytes = 1 << 20
)

// RequestSigner signs the host-API signing input with the control plane's
// request key. Custody of the key is decided elsewhere (the document signer,
// design 3.3); Sign receives platformcontract.SigningInput bytes and returns
// the raw 64-byte Ed25519 signature.
type RequestSigner struct {
	// KeyID names the key; the host pins it.
	KeyID string
	// Sign signs one signing input.
	Sign func(ctx context.Context, signingInput []byte) ([]byte, error)
}

// Ed25519Signer is a RequestSigner over an in-process private key (tests, and
// a signer process's own use).
func Ed25519Signer(keyID string, priv ed25519.PrivateKey) RequestSigner {
	key := append(ed25519.PrivateKey(nil), priv...)
	sign := func(_ context.Context, in []byte) ([]byte, error) {
		if len(key) != ed25519.PrivateKeySize {
			return nil, errors.New("hostclient.Ed25519Signer: not an ed25519 private key")
		}
		return ed25519.Sign(key, in), nil
	}
	return RequestSigner{KeyID: keyID, Sign: sign}
}

// Host is one tenant host as the control plane knows it.
type Host struct {
	// ID is the host id stored in orgs.host_id.
	ID string
	// BaseURL is the host's private origin, "https://<private address or
	// name>:<port>", with no path, query or user info.
	BaseURL string
	// ResponseKeys pins the host's response signing keys by key id (two are
	// valid during a rotation).
	ResponseKeys map[string]ed25519.PublicKey
}

func (h Host) validate() error {
	u, err := url.Parse(h.BaseURL)
	switch {
	case strings.TrimSpace(h.ID) == "":
		return errors.New("host id is empty")
	case err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("host %s: BaseURL must be https://host[:port] with no path", h.ID)
	case len(h.ResponseKeys) == 0:
		return fmt.Errorf("host %s: no response key pinned", h.ID)
	}
	for id, k := range h.ResponseKeys {
		if strings.TrimSpace(id) == "" || len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("host %s: response key %q is not a named ed25519 public key", h.ID, id)
		}
	}
	return nil
}

// target builds the request URL for r on h.
func (h Host) target(r hostapi.Request) (*url.URL, error) {
	u, err := url.Parse(h.BaseURL)
	if err != nil {
		return nil, err
	}
	u.Path, u.RawPath, u.RawQuery = r.Path, "", r.RawQuery
	return u, nil
}

// Directory resolves host ids and places new tenants.
type Directory interface {
	// Host returns the host with id.
	Host(id string) (Host, bool)
	// Place chooses the host a new tenant for orgID goes to.
	Place(ctx context.Context, orgID string) (string, error)
}

// StaticDirectory is a fixed host list that places every new tenant on one
// host. Hosts are validated at construction.
type StaticDirectory struct {
	hosts   map[string]Host
	placeOn string
}

// NewStaticDirectory returns a directory of hosts that places new tenants on
// placeOn, which must be one of them.
func NewStaticDirectory(hosts []Host, placeOn string) (*StaticDirectory, error) {
	d := &StaticDirectory{hosts: make(map[string]Host, len(hosts)), placeOn: placeOn}
	for _, h := range hosts {
		if err := h.validate(); err != nil {
			return nil, fmt.Errorf("hostclient.NewStaticDirectory: %w", err)
		}
		if _, dup := d.hosts[h.ID]; dup {
			return nil, fmt.Errorf("hostclient.NewStaticDirectory: duplicate host %s", h.ID)
		}
		d.hosts[h.ID] = h
	}
	if _, ok := d.hosts[placeOn]; !ok {
		return nil, fmt.Errorf("hostclient.NewStaticDirectory: placement host %q is not listed", placeOn)
	}
	return d, nil
}

// Host implements Directory.
func (d *StaticDirectory) Host(id string) (Host, bool) {
	h, ok := d.hosts[id]
	return h, ok
}

// Place implements Directory.
func (d *StaticDirectory) Place(context.Context, string) (string, error) { return d.placeOn, nil }

// PrivateAddress is the default dial filter (design 4.6: the host API runs
// over the private network only): RFC 1918 and RFC 4193 addresses.
func PrivateAddress(a netip.Addr) bool { return a.Unmap().IsPrivate() }

// SenderConfig configures a Sender. TLS and Signer are required.
type SenderConfig struct {
	// TLS is the mTLS client configuration: RootCAs is the platform CA and a
	// client certificate is set (Certificates or GetClientCertificate).
	TLS *tls.Config
	// Signer signs every request.
	Signer RequestSigner
	// Now is the clock (nil: time.Now).
	Now func() time.Time
	// Nonce mints a request nonce (nil: 16 random bytes, hex).
	Nonce func() (string, error)
	// Timeout bounds one request (0: DefaultTimeout).
	Timeout time.Duration
	// MaxResponseBytes bounds an answer body (0: DefaultMaxResponseBytes).
	MaxResponseBytes int64
	// AllowAddress filters every resolved address before it is dialled
	// (nil: PrivateAddress).
	AllowAddress func(netip.Addr) bool
}

// Sender sends signed host-API requests and verifies the answers.
type Sender struct {
	client  *http.Client
	signer  RequestSigner
	now     func() time.Time
	nonce   func() (string, error)
	timeout time.Duration
	maxBody int64
}

// errAddressRefused is the dial filter's refusal.
var errAddressRefused = errors.New("hostclient: refusing to dial a non-private address")

// NewSender builds a Sender.
func NewSender(cfg SenderConfig) (*Sender, error) {
	switch {
	case cfg.TLS == nil || (len(cfg.TLS.Certificates) == 0 && cfg.TLS.GetClientCertificate == nil):
		return nil, errors.New("hostclient.NewSender: a TLS config with a client certificate is required (mTLS)")
	case strings.TrimSpace(cfg.Signer.KeyID) == "" || strings.ContainsAny(cfg.Signer.KeyID, "\r\n") || cfg.Signer.Sign == nil:
		return nil, errors.New("hostclient.NewSender: a signer with a single-line key id is required")
	}
	s := &Sender{signer: cfg.Signer, now: cfg.Now, nonce: cfg.Nonce, timeout: cfg.Timeout, maxBody: cfg.MaxResponseBytes}
	if s.now == nil {
		s.now = time.Now
	}
	if s.nonce == nil {
		s.nonce = randomNonce
	}
	if s.timeout <= 0 {
		s.timeout = DefaultTimeout
	}
	if s.maxBody <= 0 {
		s.maxBody = DefaultMaxResponseBytes
	}
	allow := cfg.AllowAddress
	if allow == nil {
		allow = PrivateAddress
	}
	tc := cfg.TLS.Clone()
	if tc.MinVersion < tls.VersionTLS12 {
		tc.MinVersion = tls.VersionTLS12
	}
	// Control runs after name resolution, on the exact address being dialled,
	// so a name that resolves (or rebinds) to a public address is refused.
	control := func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || !allow(ap.Addr().Unmap()) {
			return errAddressRefused
		}
		return nil
	}
	dialer := &net.Dialer{Timeout: s.timeout, Control: control}
	s.client = &http.Client{
		Transport: &http.Transport{
			Proxy:               nil, // never an environment proxy on the private network
			DialContext:         dialer.DialContext,
			TLSClientConfig:     tc,
			TLSHandshakeTimeout: s.timeout,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 4,
		},
		Timeout:       s.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return s, nil
}

// Timeout is the per-request bound (the dispatcher's lease must outlast it).
func (s *Sender) Timeout() time.Duration { return s.timeout }

func randomNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("hostclient.randomNonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Send signs r, sends it to h and verifies the answer. Every attempt mints a
// new nonce, so a retry is always a new request (the idempotency key, when
// the verb has one, is in the body and unchanged).
func (s *Sender) Send(ctx context.Context, h Host, r hostapi.Request) hostapi.Answer {
	u, err := h.target(r)
	if err != nil {
		return hostapi.Answer{Kind: hostapi.AnswerNotSent, Reason: "url"}
	}
	target := pc.SigningTarget(u.EscapedPath(), u.RawQuery)
	nonce, err := s.nonce()
	if err != nil || nonce == "" {
		return hostapi.Answer{Kind: hostapi.AnswerNotSent, Reason: "nonce"}
	}
	env := pc.Envelope{KeyID: s.signer.KeyID, Timestamp: s.now().Unix(), Nonce: nonce, BodyDigest: pc.BodyDigest(r.Body)}
	in, err := pc.SigningInput(r.Method, target, env)
	if err != nil {
		return hostapi.Answer{Kind: hostapi.AnswerNotSent, Reason: "sign"}
	}
	sig, err := s.signer.Sign(ctx, in)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return hostapi.Answer{Kind: hostapi.AnswerNotSent, Reason: "sign"}
	}
	env.Signature = base64.StdEncoding.EncodeToString(sig)
	req, err := http.NewRequestWithContext(ctx, r.Method, u.String(), bytes.NewReader(r.Body))
	if err != nil {
		return hostapi.Answer{Kind: hostapi.AnswerNotSent, Reason: "request"}
	}
	for _, p := range env.HeaderPairs() {
		req.Header.Set(p[0], p[1])
	}
	if len(r.Body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return hostapi.Answer{Kind: hostapi.AnswerTransport, Reason: transportReason(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBody+1))
	if err != nil {
		return hostapi.Answer{Kind: hostapi.AnswerTransport, Reason: "read", HTTPStatus: resp.StatusCode}
	}
	if int64(len(body)) > s.maxBody {
		return hostapi.Answer{Kind: hostapi.AnswerUnverified, Reason: "too_large", HTTPStatus: resp.StatusCode}
	}
	a := s.verify(h, resp.Header.Get, nonce, r.Method, target, body)
	a.HTTPStatus = resp.StatusCode
	return a
}

// verify checks the response envelope against h's pinned keys.
func (s *Sender) verify(h Host, get func(string) string, nonce, method, target string, body []byte) hostapi.Answer {
	env, err := pc.ParseEnvelopeHeaders(get)
	if err != nil {
		return hostapi.Answer{Kind: hostapi.AnswerUnverified, Reason: unsignedReason(body)}
	}
	pub, ok := h.ResponseKeys[env.KeyID]
	if !ok {
		return hostapi.Answer{Kind: hostapi.AnswerUnverified, Reason: "unknown_key"}
	}
	if err := env.VerifyResponse(pub, nonce, method, target, body, s.now()); err != nil {
		return hostapi.Answer{Kind: hostapi.AnswerUnverified, Reason: verifyReason(err)}
	}
	return hostapi.Answer{Kind: hostapi.AnswerVerified, Body: body}
}

// verifyErrors maps a VerifyResponse error to its reason, walked top-down;
// an error matching no row is a signature failure.
var verifyErrors = []struct {
	err    error
	reason string
}{
	{pc.ErrNonceMismatch, "nonce"},
	{pc.ErrStale, "stale"},
	{pc.ErrDigestMismatch, "digest"},
	{pc.ErrBadSignature, "signature"},
}

func verifyReason(err error) string {
	for _, row := range verifyErrors {
		if errors.Is(err, row.err) {
			return row.reason
		}
	}
	return "signature"
}

// unsignedReason is "unsigned", plus the refusal code an unsigned body names
// when it is one of the contract's codes (a host refuses before
// authentication without signing). The code is a diagnosis for the operator
// only; it is never trusted to decide anything.
func unsignedReason(body []byte) string {
	var r pc.ErrorResponse
	if json.Unmarshal(body, &r) == nil && r.Code.Valid() {
		return "unsigned:" + string(r.Code)
	}
	return "unsigned"
}

// transportReasons maps a transport error to its reason, walked top-down.
var transportReasons = []struct {
	match  func(error) bool
	reason string
}{
	{func(err error) bool { return errors.Is(err, errAddressRefused) }, "address_refused"},
	{func(err error) bool { return errors.Is(err, context.Canceled) }, "canceled"},
	{isTimeout, "timeout"},
	{isCertError, "tls"},
	{func(error) bool { return true }, "request"},
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

func isCertError(err error) bool {
	var ce *tls.CertificateVerificationError
	return errors.As(err, &ce)
}

func transportReason(err error) string {
	for _, row := range transportReasons {
		if row.match(err) {
			return row.reason
		}
	}
	return "request"
}
