package hostclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// hostKnobs shape the scripted host's answer.
type hostKnobs struct {
	body     []byte
	unsigned bool
	keyID    string             // "" = host-r1
	signWith ed25519.PrivateKey // nil = responseKey
	nonce    string             // "" = echo the request nonce
	at       time.Time          // zero = testNow
	tamper   bool               // change the body after signing
}

// scriptedHost verifies every request envelope against the control plane's
// request key (so the test proves the Sender signs correctly) and answers per
// knobs. It records each request nonce.
type scriptedHost struct {
	k      hostKnobs
	mu     sync.Mutex
	nonces []string
}

func (h *scriptedHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	target := pc.SigningTarget(r.URL.EscapedPath(), r.URL.RawQuery)
	env, err := pc.ParseEnvelopeHeaders(r.Header.Get)
	if err != nil || env.KeyID != "cp-1" || env.Verify(pub(requestKey), r.Method, target, body, testNow) != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"bad_signature"}`))
		return
	}
	h.mu.Lock()
	h.nonces = append(h.nonces, env.Nonce)
	h.mu.Unlock()
	out := h.k.body
	if !h.k.unsigned {
		keyID, signWith, nonce, at := "host-r1", responseKey, env.Nonce, testNow
		if h.k.keyID != "" {
			keyID = h.k.keyID
		}
		if h.k.signWith != nil {
			signWith = h.k.signWith
		}
		if h.k.nonce != "" {
			nonce = h.k.nonce
		}
		if !h.k.at.IsZero() {
			at = h.k.at
		}
		renv, err := pc.NewResponseEnvelope(signWith, keyID, nonce, r.Method, target, out, at)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		for _, p := range renv.HeaderPairs() {
			w.Header().Set(p[0], p[1])
		}
	}
	if h.k.tamper {
		out = append(append([]byte(nil), out...), ' ')
	}
	_, _ = w.Write(out)
}

func startScripted(t *testing.T, k hostKnobs) (*scriptedHost, *tls.Config, string) {
	t.Helper()
	h := &scriptedHost{k: k}
	srv := httptest.NewUnstartedServer(h)
	tc := startMTLS(t, srv, newPKI(t))
	return h, tc, srv.URL
}

func evictRequest(t *testing.T) hostapi.Request {
	t.Helper()
	in := must(t)(hostapi.EvictIntent(orgA, 2))
	r, err := hostapi.Build(hostapi.Queued{OrgID: in.OrgID, Verb: in.Verb, IdempotencyKey: in.IdempotencyKey, LifecycleGen: 2, Payload: in.Payload}, hostapi.CreateExtras{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestSenderVerification is one case per way an answer can fail to verify,
// plus the verified case: only a body signed by a pinned response key, over
// this request, echoing this request's nonce, fresh and unmodified, is
// AnswerVerified.
func TestSenderVerification(t *testing.T) {
	t.Parallel()
	ok := []byte(`{"evicted":true}`)
	cases := []struct {
		name   string
		k      hostKnobs
		kind   hostapi.AnswerKind
		reason string
	}{
		{"verified", hostKnobs{body: ok}, hostapi.AnswerVerified, ""},
		{"unsigned", hostKnobs{body: []byte(`{"code":"unknown_key"}`), unsigned: true}, hostapi.AnswerUnverified, "unsigned:unknown_key"},
		{"unsigned free text", hostKnobs{body: []byte(`oops`), unsigned: true}, hostapi.AnswerUnverified, "unsigned"},
		{"unknown key id", hostKnobs{body: ok, keyID: "host-r9"}, hostapi.AnswerUnverified, "unknown_key"},
		{"nonce not echoed", hostKnobs{body: ok, nonce: "someone-elses"}, hostapi.AnswerUnverified, "nonce"},
		{"stale", hostKnobs{body: ok, at: testNow.Add(-pc.ReplayWindow - time.Second)}, hostapi.AnswerUnverified, "stale"},
		{"body changed", hostKnobs{body: ok, tamper: true}, hostapi.AnswerUnverified, "digest"},
		{"wrong signer", hostKnobs{body: ok, signWith: key("impostor")}, hostapi.AnswerUnverified, "signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, tlsc, url := startScripted(t, tc.k)
			a := newSender(t, tlsc, nil).Send(context.Background(), hostAt(url), evictRequest(t))
			if a.Kind != tc.kind || a.Reason != tc.reason {
				t.Fatalf("Send = kind %d reason %q, want kind %d reason %q", a.Kind, a.Reason, tc.kind, tc.reason)
			}
			if len(h.nonces) != 1 {
				t.Fatalf("host verified %d requests, want 1 (the Sender's envelope must verify)", len(h.nonces))
			}
			if tc.kind == hostapi.AnswerVerified && string(a.Body) != string(ok) {
				t.Fatalf("verified body = %q", a.Body)
			}
		})
	}
}

// TestSenderOversizedAnswer: a body over the limit is never verified.
func TestSenderOversizedAnswer(t *testing.T) {
	t.Parallel()
	_, tlsc, url := startScripted(t, hostKnobs{body: []byte(`{"evicted":true,"pad":"` + strings.Repeat("x", 200) + `"}`)})
	s := newSender(t, tlsc, func(c *hostclient.SenderConfig) { c.MaxResponseBytes = 64 })
	if a := s.Send(context.Background(), hostAt(url), evictRequest(t)); a.Kind != hostapi.AnswerUnverified || a.Reason != "too_large" {
		t.Fatalf("Send = %+v", a)
	}
}

// TestSenderNewNonceEveryAttempt: a retry is a new request (platformcontract
// "replayed": a retry carries a new nonce).
func TestSenderNewNonceEveryAttempt(t *testing.T) {
	t.Parallel()
	h, tlsc, url := startScripted(t, hostKnobs{body: []byte(`{"evicted":false}`)})
	s := newSender(t, tlsc, nil)
	for range 2 {
		if a := s.Send(context.Background(), hostAt(url), evictRequest(t)); a.Kind != hostapi.AnswerVerified {
			t.Fatalf("Send = %+v", a)
		}
	}
	if len(h.nonces) != 2 || h.nonces[0] == h.nonces[1] {
		t.Fatalf("nonces = %v, want two different", h.nonces)
	}
}

// TestSenderRefusesPublicAddress: the default dial filter allows private
// addresses only; the loopback test server is refused before any byte is sent.
func TestSenderRefusesPublicAddress(t *testing.T) {
	t.Parallel()
	h, tlsc, url := startScripted(t, hostKnobs{body: []byte(`{}`)})
	s := newSender(t, tlsc, func(c *hostclient.SenderConfig) { c.AllowAddress = nil })
	a := s.Send(context.Background(), hostAt(url), evictRequest(t))
	if a.Kind != hostapi.AnswerTransport || a.Reason != "address_refused" {
		t.Fatalf("Send = %+v, want transport address_refused", a)
	}
	if len(h.nonces) != 0 {
		t.Fatal("the request reached the host")
	}
}

// TestSenderRequiresClientCertificate: the host's mTLS refuses a client with
// no certificate (the Sender cannot even be built without one).
func TestSenderRequiresClientCertificate(t *testing.T) {
	t.Parallel()
	_, tlsc, url := startScripted(t, hostKnobs{body: []byte(`{}`)})
	noCert := tlsc.Clone()
	noCert.Certificates = nil
	if _, err := hostclient.NewSender(hostclient.SenderConfig{TLS: noCert, Signer: hostclient.Ed25519Signer("cp-1", requestKey)}); err == nil {
		t.Fatal("NewSender accepted a TLS config with no client certificate")
	}
	// A client certificate from another CA is refused by the host's handshake.
	other := tlsc.Clone()
	other.Certificates = []tls.Certificate{newPKI(t).client}
	a := newSender(t, other, nil).Send(context.Background(), hostAt(url), evictRequest(t))
	if a.Kind != hostapi.AnswerTransport {
		t.Fatalf("Send with a foreign client certificate = %+v, want a transport failure", a)
	}
}

// TestSenderConfigAndHostValidation covers the constructor refusals.
func TestSenderConfigAndHostValidation(t *testing.T) {
	t.Parallel()
	tlsc := &tls.Config{Certificates: []tls.Certificate{newPKI(t).client}, MinVersion: tls.VersionTLS12}
	if _, err := hostclient.NewSender(hostclient.SenderConfig{TLS: tlsc, Signer: hostclient.RequestSigner{KeyID: "a\nb", Sign: hostclient.Ed25519Signer("x", requestKey).Sign}}); err == nil {
		t.Error("NewSender accepted a multi-line key id")
	}
	if _, err := hostclient.NewSender(hostclient.SenderConfig{TLS: tlsc}); err == nil {
		t.Error("NewSender accepted no signer")
	}
	keys := map[string]ed25519.PublicKey{"r": pub(responseKey)}
	bad := []hostclient.Host{
		{ID: "", BaseURL: "https://10.0.0.1:8443", ResponseKeys: keys},
		{ID: "h", BaseURL: "http://10.0.0.1:8443", ResponseKeys: keys},
		{ID: "h", BaseURL: "https://10.0.0.1:8443/prefix", ResponseKeys: keys},
		{ID: "h", BaseURL: "https://u:p@10.0.0.1:8443", ResponseKeys: keys},
		{ID: "h", BaseURL: "https://10.0.0.1:8443"},
		{ID: "h", BaseURL: "https://10.0.0.1:8443", ResponseKeys: map[string]ed25519.PublicKey{"r": {1, 2}}},
	}
	for i, h := range bad {
		if _, err := hostclient.NewStaticDirectory([]hostclient.Host{h}, h.ID); err == nil {
			t.Errorf("host %d accepted: %+v", i, h)
		}
	}
	good := hostclient.Host{ID: "h", BaseURL: "https://10.0.0.1:8443", ResponseKeys: keys}
	if _, err := hostclient.NewStaticDirectory([]hostclient.Host{good}, "other"); err == nil {
		t.Error("placement on an unlisted host accepted")
	}
	if _, err := hostclient.NewStaticDirectory([]hostclient.Host{good, good}, "h"); err == nil {
		t.Error("duplicate host accepted")
	}
	if !hostclient.PrivateAddress(mustAddr(t, "10.1.2.3")) || hostclient.PrivateAddress(mustAddr(t, "8.8.8.8")) || hostclient.PrivateAddress(mustAddr(t, "127.0.0.1")) {
		t.Error("PrivateAddress misclassifies")
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
