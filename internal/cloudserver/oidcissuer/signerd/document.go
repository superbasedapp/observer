package signerd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// document.go is the DOCUMENT signer (managed-SaaS M6.3; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.3, 4.5):
// `observer-cloud signer document serve` on the worker VM, its own Linux user,
// holding the Ed25519 keys for entitlements documents, the availability
// envelope and host-API request signing. Same process model as the OIDC
// signer (a unix socket, one allowed peer uid by SO_PEERCRED, one JSON line
// each way), but a different process with different keys on a different VM.
//
// # Protocol (version 1), at most 256 KiB a line
//
//	-> {"v":1,"op":"keys"}
//	<- {"v":1,"keys":[{"purpose":"entitlements","key_id":"...","public":"<b64>","signing":true}, ...]}
//
//	-> {"v":1,"op":"sign_document","kind":"entitlements","scope":"<org id>","version":7,"body":"<b64>"}
//	<- {"v":1,"signature":"<b64>","key_id":"..."}
//
//	-> {"v":1,"op":"sign_request","method":"PUT","target":"/platform/v1/...","nonce":"...","body_digest":"<hex>","timestamp":1700000000}
//	<- {"v":1,"envelope":{"key_id":...,"timestamp":...,"nonce":...,"body_digest":...,"signature":...}}
//
//	<- {"v":1,"error":"version_not_newer"|"refused"|"no_key"|"bad_request"|"peer_refused"|"internal"}
//
// What the signer enforces, whoever asks: the kind's domain tag and scope
// (platformcontract.DocumentSigningMessage), a body it can check (an
// entitlements body is one JSON object; an availability body decodes strictly
// into platformcontract.AvailabilityBody and passes Validate), and the
// monotonic version per (kind, scope), recorded durably BEFORE the signature
// leaves the process. A host-API request it signs only inside the replay
// window of its own clock, under /platform/v1, with a well-formed digest.

// maxDocMessage bounds one document-signer line: a base64 body of
// platformcontract.MaxDocumentBody bytes plus the framing.
const maxDocMessage = 256 << 10

// Document-signer response error codes (with ErrBadRequestCode,
// ErrPeerRefusedCode and ErrInternalCode).
const (
	ErrVersionNotNewerCode = "version_not_newer"
	ErrRefusedCode         = "refused"
	ErrNoKeyCode           = "no_key"
)

// Purpose names one of the document signer's keys.
type Purpose string

// Key purposes.
const (
	// PurposeEntitlements signs sbo-entitlements-v1 documents.
	PurposeEntitlements Purpose = "entitlements"
	// PurposeAvailability signs sbo-availability-v1 envelopes.
	PurposeAvailability Purpose = "availability"
	// PurposeHostAPI signs host-API request envelopes.
	PurposeHostAPI Purpose = "host-api"
)

// Document signer errors.
var (
	// ErrDocumentRefused means the kind, scope, body or request is not one
	// the signer will sign.
	ErrDocumentRefused = errors.New("signerd: document refused")
	// ErrNoKey means the signer holds no key for that purpose.
	ErrNoKey = errors.New("signerd: no key for that purpose")
)

// DocumentKeys are the keys the document signer loads, per purpose. The
// first key of each list signs; any later key is published only (the
// rollover window: hosts pin both ids before the second starts signing).
type DocumentKeys struct {
	Entitlements []ed25519.PrivateKey
	Availability []ed25519.PrivateKey
	HostAPI      []ed25519.PrivateKey
}

// PublishedKey is a public key the signer holds.
type PublishedKey struct {
	Purpose Purpose `json:"purpose"`
	KeyID   string  `json:"key_id"`
	Public  []byte  `json:"public"`
	Signing bool    `json:"signing"`
}

// SignedDocument is what the signer returns for a document.
type SignedDocument struct {
	Signature []byte
	KeyID     string
}

// documentKindRow is one row of the kind table: which key signs it and how
// its body is checked.
type documentKindRow struct {
	kind      platformcontract.DocumentKind
	purpose   Purpose
	checkBody func([]byte) error
}

func documentKindRows() []documentKindRow {
	return []documentKindRow{
		{kind: platformcontract.KindEntitlements, purpose: PurposeEntitlements, checkBody: checkEntitlementsBody},
		{kind: platformcontract.KindAvailability, purpose: PurposeAvailability, checkBody: checkAvailabilityBody},
	}
}

// checkEntitlementsBody accepts one JSON object. The schema is M7b.1's.
func checkEntitlementsBody(body []byte) error {
	if t := bytes.TrimSpace(body); len(t) == 0 || t[0] != '{' || !json.Valid(body) {
		return errors.New("entitlements body is not one JSON object")
	}
	return nil
}

// checkAvailabilityBody decodes strictly (no unknown field, no trailing data)
// and validates the three sections.
func checkAvailabilityBody(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var b platformcontract.AvailabilityBody
	if err := dec.Decode(&b); err != nil {
		return fmt.Errorf("availability body: %w", err)
	}
	if dec.More() {
		return errors.New("availability body: trailing data")
	}
	return b.Validate()
}

// DocumentSigner holds the document keys and the version record, and applies
// the rules above. It is safe for concurrent use; signing is serialised so
// the version check and its durable record are one step.
type DocumentSigner struct {
	keys     map[Purpose][]ed25519.PrivateKey
	versions VersionStore
	now      func() time.Time
	mu       sync.Mutex
}

// NewDocumentSigner checks the keys (entitlements and availability required,
// host-API optional, no key used for two purposes) and returns a signer.
func NewDocumentSigner(keys DocumentKeys, versions VersionStore, now func() time.Time) (*DocumentSigner, error) {
	if versions == nil {
		return nil, errors.New("signerd.NewDocumentSigner: no version store")
	}
	if now == nil {
		now = time.Now
	}
	byPurpose := map[Purpose][]ed25519.PrivateKey{
		PurposeEntitlements: keys.Entitlements,
		PurposeAvailability: keys.Availability,
		PurposeHostAPI:      keys.HostAPI,
	}
	if len(keys.Entitlements) == 0 || len(keys.Availability) == 0 {
		return nil, errors.New("signerd.NewDocumentSigner: an entitlements key and an availability key are required")
	}
	seen := map[string]Purpose{}
	for p, ks := range byPurpose {
		for _, k := range ks {
			if len(k) != ed25519.PrivateKeySize {
				return nil, fmt.Errorf("signerd.NewDocumentSigner: a %s key is not an Ed25519 key", p)
			}
			id := platformcontract.DocumentKeyID(publicOf(k))
			if other, dup := seen[id]; dup {
				return nil, fmt.Errorf("signerd.NewDocumentSigner: key %s is loaded for both %s and %s; each purpose needs its own key", id, other, p)
			}
			seen[id] = p
		}
	}
	return &DocumentSigner{keys: byPurpose, versions: versions, now: now}, nil
}

func publicOf(k ed25519.PrivateKey) ed25519.PublicKey {
	pub, _ := k.Public().(ed25519.PublicKey)
	return pub
}

// PublicKeys lists every key the signer holds, in purpose order.
func (d *DocumentSigner) PublicKeys() []PublishedKey {
	var out []PublishedKey
	for _, p := range []Purpose{PurposeEntitlements, PurposeAvailability, PurposeHostAPI} {
		for i, k := range d.keys[p] {
			pub := publicOf(k)
			out = append(out, PublishedKey{Purpose: p, KeyID: platformcontract.DocumentKeyID(pub), Public: append([]byte(nil), pub...), Signing: i == 0})
		}
	}
	return out
}

// SignDocument signs a document of kind for scope at version. It refuses an
// unknown kind, a bad scope or body (ErrDocumentRefused) and a version not
// above the last it signed for (kind, scope) (platformcontract
// ErrVersionNotNewer). The new version is committed durably before the
// signature is returned; a failed commit returns no signature.
func (d *DocumentSigner) SignDocument(kind platformcontract.DocumentKind, scope string, version int64, body []byte) (SignedDocument, error) {
	var row documentKindRow
	found := false
	for _, r := range documentKindRows() {
		if r.kind == kind {
			row, found = r, true
			break
		}
	}
	if !found {
		return SignedDocument{}, fmt.Errorf("signerd.SignDocument: kind %q: %w", kind, ErrDocumentRefused)
	}
	if _, err := platformcontract.DocumentSigningMessage(kind, scope, version, body); err != nil {
		return SignedDocument{}, fmt.Errorf("signerd.SignDocument: %w: %w", ErrDocumentRefused, err)
	}
	if err := row.checkBody(body); err != nil {
		return SignedDocument{}, fmt.Errorf("signerd.SignDocument: %w: %w", ErrDocumentRefused, err)
	}
	keys := d.keys[row.purpose]
	if len(keys) == 0 {
		return SignedDocument{}, fmt.Errorf("signerd.SignDocument: %w", ErrNoKey)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	last, err := d.versions.Last(kind, scope)
	if err != nil {
		return SignedDocument{}, fmt.Errorf("signerd.SignDocument: %w", err)
	}
	if err := platformcontract.CheckDocumentVersion(last, version); err != nil {
		return SignedDocument{}, fmt.Errorf("signerd.SignDocument: %w", err)
	}
	sig, keyID, err := platformcontract.SignDocument(keys[0], kind, scope, version, body)
	if err != nil {
		return SignedDocument{}, fmt.Errorf("signerd.SignDocument: %w", err)
	}
	if err := d.versions.Commit(kind, scope, version); err != nil {
		return SignedDocument{}, fmt.Errorf("signerd.SignDocument: record version: %w", err)
	}
	return SignedDocument{Signature: sig, KeyID: keyID}, nil
}

// requestMethods are the HTTP methods the host API uses.
func requestMethods() []string { return []string{"GET", "POST", "PUT"} }

// SignRequest signs a host-API request envelope with the host-API key. The
// timestamp must be inside platformcontract.ReplayWindow of the signer's own
// clock, the target under platformcontract.BasePath, the digest 64 lowercase
// hex characters and the nonce 1 to 128 characters with no space.
func (d *DocumentSigner) SignRequest(method, target, nonce, bodyDigest string, timestamp int64) (platformcontract.Envelope, error) {
	keys := d.keys[PurposeHostAPI]
	if len(keys) == 0 {
		return platformcontract.Envelope{}, fmt.Errorf("signerd.SignRequest: %w", ErrNoKey)
	}
	if err := checkRequest(method, target, nonce, bodyDigest); err != nil {
		return platformcontract.Envelope{}, fmt.Errorf("signerd.SignRequest: %w: %w", ErrDocumentRefused, err)
	}
	e := platformcontract.Envelope{
		KeyID: platformcontract.DocumentKeyID(publicOf(keys[0])), Timestamp: timestamp,
		Nonce: nonce, BodyDigest: bodyDigest,
	}
	if err := e.CheckFreshness(d.now()); err != nil {
		return platformcontract.Envelope{}, fmt.Errorf("signerd.SignRequest: %w: %w", ErrDocumentRefused, err)
	}
	in, err := platformcontract.SigningInput(method, target, e)
	if err != nil {
		return platformcontract.Envelope{}, fmt.Errorf("signerd.SignRequest: %w: %w", ErrDocumentRefused, err)
	}
	e.Signature = b64std(ed25519.Sign(keys[0], in))
	return e, nil
}

func b64std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func checkRequest(method, target, nonce, bodyDigest string) error {
	ok := false
	for _, m := range requestMethods() {
		ok = ok || m == method
	}
	switch {
	case !ok:
		return fmt.Errorf("method %q", method)
	case !strings.HasPrefix(target, platformcontract.BasePath+"/"):
		return fmt.Errorf("target %q is not under %s", target, platformcontract.BasePath)
	case nonce == "" || len(nonce) > 128 || strings.ContainsAny(nonce, " \t\r\n"):
		return errors.New("nonce")
	}
	if raw, err := hex.DecodeString(bodyDigest); err != nil || len(raw) != 32 || strings.ToLower(bodyDigest) != bodyDigest {
		return errors.New("body digest")
	}
	return nil
}

// docRequest is one document-signer request line.
type docRequest struct {
	V          int    `json:"v"`
	Op         string `json:"op"`
	Kind       string `json:"kind,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Version    int64  `json:"version,omitempty"`
	Body       []byte `json:"body,omitempty"`
	Method     string `json:"method,omitempty"`
	Target     string `json:"target,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	BodyDigest string `json:"body_digest,omitempty"`
	Timestamp  int64  `json:"timestamp,omitempty"`
}

// docResponse is one document-signer response line.
type docResponse struct {
	V         int                        `json:"v"`
	Signature []byte                     `json:"signature,omitempty"`
	KeyID     string                     `json:"key_id,omitempty"`
	Envelope  *platformcontract.Envelope `json:"envelope,omitempty"`
	Keys      []PublishedKey             `json:"keys,omitempty"`
	Error     string                     `json:"error,omitempty"`
}

// docErrorCode maps a signer error to its wire code.
func docErrorCode(err error) string {
	switch {
	case errors.Is(err, platformcontract.ErrVersionNotNewer):
		return ErrVersionNotNewerCode
	case errors.Is(err, ErrDocumentRefused):
		return ErrRefusedCode
	case errors.Is(err, ErrNoKey):
		return ErrNoKeyCode
	default:
		return ErrInternalCode
	}
}

// docOp is one row of the document-signer operation table.
type docOp struct {
	name string
	run  func(d *DocumentSigner, req docRequest) docResponse
}

func docOps() []docOp {
	return []docOp{
		{name: "keys", run: func(d *DocumentSigner, _ docRequest) docResponse {
			return docResponse{V: ProtocolVersion, Keys: d.PublicKeys()}
		}},
		{name: "sign_document", run: func(d *DocumentSigner, req docRequest) docResponse {
			s, err := d.SignDocument(platformcontract.DocumentKind(req.Kind), req.Scope, req.Version, req.Body)
			if err != nil {
				return docResponse{V: ProtocolVersion, Error: docErrorCode(err)}
			}
			return docResponse{V: ProtocolVersion, Signature: s.Signature, KeyID: s.KeyID}
		}},
		{name: "sign_request", run: func(d *DocumentSigner, req docRequest) docResponse {
			e, err := d.SignRequest(req.Method, req.Target, req.Nonce, req.BodyDigest, req.Timestamp)
			if err != nil {
				return docResponse{V: ProtocolVersion, Error: docErrorCode(err)}
			}
			return docResponse{V: ProtocolVersion, Envelope: &e}
		}},
	}
}

// DocumentServer serves a DocumentSigner over a listener, to one peer uid.
type DocumentServer struct {
	// Signer holds the keys and applies the rules.
	Signer *DocumentSigner
	// AllowUID is the only peer uid served (the worker's).
	AllowUID int
	// PeerUID returns a connection's peer uid; nil means SO_PEERCRED.
	PeerUID func(net.Conn) (int, error)
	// Logger receives one line per request (op, kind, scope, version, key
	// id, outcome); never a body. nil means slog.Default().
	Logger *slog.Logger
	// Timeout bounds one connection; zero means five seconds.
	Timeout time.Duration
}

// Serve accepts connections on ln until ctx is done or ln fails.
func (s *DocumentServer) Serve(ctx context.Context, ln net.Listener) error {
	if s.Signer == nil {
		return errors.New("signerd.DocumentServer.Serve: no signer")
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("signerd.DocumentServer.Serve: accept: %w", err)
		}
		go s.handle(conn)
	}
}

func (s *DocumentServer) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *DocumentServer) handle(conn net.Conn) {
	defer conn.Close()
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	peer := s.PeerUID
	if peer == nil {
		peer = PeerCredUID
	}
	uid, err := peer(conn)
	if err != nil || uid != s.AllowUID {
		s.logger().Warn("signerd: document signer refused a peer", "uid", uid, "err", err)
		_, _ = readLineLimit(conn, maxDocMessage)
		writeJSONLine(conn, docResponse{V: ProtocolVersion, Error: ErrPeerRefusedCode})
		return
	}
	resp := docResponse{V: ProtocolVersion, Error: ErrBadRequestCode}
	req, err := readDocRequest(conn)
	if err == nil && req.V == ProtocolVersion {
		for _, o := range docOps() {
			if o.name == req.Op {
				resp = o.run(s.Signer, req)
				break
			}
		}
	}
	outcome := resp.Error
	if outcome == "" {
		outcome = "ok"
	}
	s.logger().Info("signerd: document signer request", "op", req.Op, "kind", req.Kind, "scope", req.Scope,
		"version", req.Version, "key_id", resp.KeyID, "outcome", outcome)
	writeJSONLine(conn, resp)
}

func readDocRequest(conn net.Conn) (docRequest, error) {
	line, err := readLineLimit(conn, maxDocMessage)
	if err != nil {
		return docRequest{}, err
	}
	var req docRequest
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return docRequest{}, fmt.Errorf("signerd: decode request: %w", err)
	}
	if dec.More() {
		return docRequest{}, errors.New("signerd: trailing data after the request")
	}
	return req, nil
}

func writeJSONLine(conn net.Conn, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(b, '\n'))
}

// DocumentClient talks to a document signer over its socket. The worker
// holds one.
type DocumentClient struct {
	// Network is "unix" in production ("tcp" only in tests).
	Network string
	// Address is the socket path (or a test address).
	Address string
	// Timeout bounds one call; zero means five seconds.
	Timeout time.Duration
}

// NewDocumentUnixClient returns a client for the socket at path.
func NewDocumentUnixClient(path string) *DocumentClient {
	return &DocumentClient{Network: "unix", Address: path}
}

// PublicKeys asks the signer for its public keys.
func (c *DocumentClient) PublicKeys(ctx context.Context) ([]PublishedKey, error) {
	resp, err := c.call(ctx, docRequest{V: ProtocolVersion, Op: "keys"})
	if err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

// SignDocument asks the signer to sign a document.
func (c *DocumentClient) SignDocument(ctx context.Context, kind platformcontract.DocumentKind, scope string, version int64, body []byte) (SignedDocument, error) {
	resp, err := c.call(ctx, docRequest{V: ProtocolVersion, Op: "sign_document", Kind: string(kind), Scope: scope, Version: version, Body: body})
	if err != nil {
		return SignedDocument{}, err
	}
	if len(resp.Signature) != ed25519.SignatureSize || resp.KeyID == "" {
		return SignedDocument{}, errors.New("signerd.DocumentClient.SignDocument: malformed response")
	}
	return SignedDocument{Signature: resp.Signature, KeyID: resp.KeyID}, nil
}

// SignRequest asks the signer to sign a host-API request envelope.
func (c *DocumentClient) SignRequest(ctx context.Context, method, target, nonce, bodyDigest string, timestamp int64) (platformcontract.Envelope, error) {
	resp, err := c.call(ctx, docRequest{
		V: ProtocolVersion, Op: "sign_request", Method: method, Target: target,
		Nonce: nonce, BodyDigest: bodyDigest, Timestamp: timestamp,
	})
	if err != nil {
		return platformcontract.Envelope{}, err
	}
	if resp.Envelope == nil {
		return platformcontract.Envelope{}, errors.New("signerd.DocumentClient.SignRequest: malformed response")
	}
	return *resp.Envelope, nil
}

func (c *DocumentClient) call(ctx context.Context, req docRequest) (docResponse, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	network := c.Network
	if network == "" {
		network = "unix"
	}
	var dl net.Dialer
	conn, err := dl.DialContext(ctx, network, c.Address)
	if err != nil {
		return docResponse{}, fmt.Errorf("signerd.DocumentClient: dial: %w", err)
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	b, err := json.Marshal(req)
	if err != nil {
		return docResponse{}, fmt.Errorf("signerd.DocumentClient: encode: %w", err)
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return docResponse{}, fmt.Errorf("signerd.DocumentClient: write: %w", err)
	}
	line, err := readLineLimit(conn, maxDocMessage)
	if err != nil {
		return docResponse{}, fmt.Errorf("signerd.DocumentClient: %w", err)
	}
	var resp docResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return docResponse{}, fmt.Errorf("signerd.DocumentClient: decode: %w", err)
	}
	return resp, docClientError(resp.Error)
}

// docClientError maps a wire error code back to the error a caller tests
// with errors.Is.
func docClientError(code string) error {
	rows := []struct {
		code string
		err  error
	}{
		{"", nil},
		{ErrVersionNotNewerCode, platformcontract.ErrVersionNotNewer},
		{ErrRefusedCode, ErrDocumentRefused},
		{ErrNoKeyCode, ErrNoKey},
		{ErrPeerRefusedCode, ErrPeerRefused},
	}
	for _, r := range rows {
		if r.code == code {
			if r.err == nil {
				return nil
			}
			return fmt.Errorf("signerd.DocumentClient: %w", r.err)
		}
	}
	return fmt.Errorf("signerd.DocumentClient: signer answered %s", code)
}
