package cloudclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/attachgrant"
	"github.com/marmutapp/superbased-observer/internal/cloudcred"
	"github.com/marmutapp/superbased-observer/internal/cloudpop"
)

// connectTestServer serves the two connect routes. The create handler
// records the device key; poll answers are scripted per call.
type connectTestServer struct {
	t       *testing.T
	pub     string
	created connectCreateWire
	polls   []string // response bodies, in order; the last repeats
	status  int      // non-zero: every poll answers this status
	calls   int
}

func (s *connectTestServer) mux(srvURL func() string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/connect/requests", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get(headerPoP) != "" {
			s.t.Errorf("create carried credentials")
		}
		if err := json.NewDecoder(r.Body).Decode(&s.created); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		s.pub = s.created.DevicePublicKey
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, ConnectRequest{
			RequestID: "req-1", UserCode: "KTRW-4821",
			ApproveURL: srvURL() + "/connect/req-1", VerifyURL: srvURL() + "/connect",
			ExpiresIn: 900, Interval: 3,
		})
	})
	mux.HandleFunc("GET /v1/connect/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			s.t.Errorf("poll carried a bearer")
		}
		raw, err := base64.RawURLEncoding.DecodeString(s.pub)
		if err != nil {
			s.t.Fatalf("decode pub: %v", err)
		}
		if _, err := cloudpop.Verify(r.Header.Get(headerPoP), cloudpop.VerifyParams{
			ExpectedMethod:          r.Method,
			ExpectedURL:             "http://" + r.Host + r.URL.Path,
			ExpectedThumbprint:      cloudpop.Thumbprint(raw),
			ExpectedAccessTokenHash: cloudpop.HashAccessToken(r.PathValue("id")),
			Now:                     time.Unix(1_800_000_000, 0),
			MaxAge:                  2 * time.Minute,
			MaxSkew:                 time.Minute,
		}); err != nil {
			s.t.Errorf("poll proof: %v", err)
		}
		if s.status != 0 {
			w.WriteHeader(s.status)
			return
		}
		i := s.calls
		if i >= len(s.polls) {
			i = len(s.polls) - 1
		}
		s.calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(s.polls[i]))
	})
	return mux
}

func newConnectTestClient(t *testing.T, s *connectTestServer) (*Client, cloudcred.Store) {
	t.Helper()
	var srv *httptest.Server
	srv = startServer(t, s.mux(func() string { return srv.URL }))
	return newTestClient(t, srv.URL, "")
}

func TestConnectRequestCreateAndApprove(t *testing.T) {
	s := &connectTestServer{t: t, polls: []string{
		`{"status":"pending","target":null,"consent_receipt_id":""}`,
		`{"status":"approved","target":{"org_id":"org-9","slug":"acme","kind":"team","display_name":"Acme","share_level":"full"},` +
			`"consent_receipt_id":"rcpt-1","api_token":"sbo_api_from_connect","enrol_code":"ENROL-ONE-TIME"}`,
	}}
	c, cred := newConnectTestClient(t, s)
	ctx := context.Background()
	req, err := c.CreateConnectRequest(ctx, ConnectRequestInput{MachineName: "laptop", OS: "linux", Arch: "amd64", ObserverVersion: "1.2.3", TargetHint: "acme"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if req.UserCode != "KTRW-4821" || s.created.TargetHint != "acme" || s.created.MachineName != "laptop" {
		t.Fatalf("req=%+v created=%+v", req, s.created)
	}
	if s.created.DevicePublicKey != b64.EncodeToString(c.DevicePublicKey()) {
		t.Fatal("create did not carry this device's key")
	}
	st, err := c.PollConnectRequest(ctx, req.RequestID)
	if err != nil || st.Status != ConnectPending || st.SignedIn {
		t.Fatalf("first poll = %+v, %v", st, err)
	}
	st, err = c.PollConnectRequest(ctx, req.RequestID)
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if st.Status != ConnectApproved || !st.SignedIn || st.Target == nil || st.Target.Slug != "acme" || st.ConsentReceiptID != "rcpt-1" {
		t.Fatalf("approved = %+v", st)
	}
	if st.EnrolCode != "ENROL-ONE-TIME" {
		t.Fatalf("enrol code not handed over")
	}
	if tok, err := cred.LoadAPIToken(); err != nil || tok != "sbo_api_from_connect" {
		t.Fatalf("api token not stored: %q %v", tok, err)
	}
	// The enrol code never serializes.
	b, _ := json.Marshal(st)
	if strings.Contains(string(b), "ENROL-ONE-TIME") || strings.Contains(string(b), "sbo_api_from_connect") {
		t.Fatalf("a credential serialized: %s", b)
	}
}

func TestConnectRequestNotNowSignsInWithoutTarget(t *testing.T) {
	s := &connectTestServer{t: t, polls: []string{`{"status":"approved","target":null,"consent_receipt_id":"","api_token":"tok"}`}}
	c, _ := newConnectTestClient(t, s)
	if _, err := c.CreateConnectRequest(context.Background(), ConnectRequestInput{}); err != nil {
		t.Fatal(err)
	}
	st, err := c.PollConnectRequest(context.Background(), "req-1")
	if err != nil || st.Target != nil || !st.SignedIn {
		t.Fatalf("not now = %+v, %v", st, err)
	}
}

func TestConnectPollStatusErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{
		{http.StatusNotFound, ErrConnectRequestGone},
		{http.StatusGone, ErrConnectRequestGone},
		{http.StatusTooManyRequests, ErrConnectSlowDown},
	} {
		s := &connectTestServer{t: t, status: tc.status}
		c, _ := newConnectTestClient(t, s)
		if _, err := c.CreateConnectRequest(context.Background(), ConnectRequestInput{}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.PollConnectRequest(context.Background(), "req-1"); !errors.Is(err, tc.want) {
			t.Fatalf("status %d: err = %v, want %v", tc.status, err, tc.want)
		}
	}
}

func TestConnectPollRefusesInvalidAnswers(t *testing.T) {
	for _, body := range []string{
		`{"status":"weird"}`,
		`{"status":"approved","target":{"org_id":"","slug":"a","kind":"team","share_level":"full"}}`,
		`{"status":"approved","target":{"org_id":"o","slug":"a","kind":"org","share_level":"full"}}`,
		`{"status":"approved","target":{"org_id":"o","slug":"a","kind":"team","share_level":"everything"}}`,
		`{"status":"approved","target":{"org_id":"o","slug":"a","kind":"team","share_level":"full","server_url":"http://a.example.test"}}`,
		`{"status":"approved","target":{"org_id":"o","slug":"a","kind":"team","share_level":"full","server_url":"https://evil.example.test"}}`,
	} {
		s := &connectTestServer{t: t, polls: []string{body}}
		c, cred := newConnectTestClient(t, s)
		if _, err := c.CreateConnectRequest(context.Background(), ConnectRequestInput{}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.PollConnectRequest(context.Background(), "req-1"); err == nil {
			t.Fatalf("accepted %s", body)
		}
		if _, err := cred.LoadAPIToken(); err == nil {
			t.Fatalf("a refused answer stored a token: %s", body)
		}
	}
}

func TestConnectRequestURLsMustBeOnTheCloudOrigin(t *testing.T) {
	cases := map[string]bool{
		"http://127.0.0.1:1/connect/x":    false, // different port is a different origin
		"https://cloud.example.test/x":    false,
		"javascript:alert(1)":             false,
		"":                                false,
		"http://127.0.0.1:8443/connect/x": true,
	}
	for raw, ok := range cases {
		err := sameOrigin("http://127.0.0.1:8443", raw)
		if (err == nil) != ok {
			t.Errorf("sameOrigin(%q) = %v, want ok=%t", raw, err, ok)
		}
	}
	if err := sameOrigin("http://cloud.example.test", "http://cloud.example.test/connect"); err == nil {
		t.Error("plain http off loopback accepted")
	}
	for _, code := range []string{"KTRW-4821", "ABCD"} {
		if !validUserCode(code) {
			t.Errorf("valid code %q refused", code)
		}
	}
	for _, code := range []string{"", "abc", "KTRW 4821", "<script>", strings.Repeat("A", 17)} {
		if validUserCode(code) {
			t.Errorf("bad code %q accepted", code)
		}
	}
}

// TestAttachGrantThumbprintMatchesCloudPoP pins that the attach grant's RFC
// 7638 thumbprint (internal/attachgrant, which the org server verifies with
// and which may not link the cloud's proof package) equals cloudpop's, which
// the cloud stores for every connect request and binds API tokens to.
func TestAttachGrantThumbprintMatchesCloudPoP(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := attachgrant.Thumbprint(pub), cloudpop.Thumbprint(pub); got != want {
		t.Fatalf("attachgrant.Thumbprint = %s, cloudpop.Thumbprint = %s", got, want)
	}
}

// TestConnectRequestContractASignInAndAttachGrant: contract A nests the
// delivered sign-in under "sign_in" and carries the attach grant beside it.
// Both are taken (the token stored, the grant handed over unserialized), and
// the device proof the client signs for the grant verifies against this
// device's key.
func TestConnectRequestContractASignInAndAttachGrant(t *testing.T) {
	s := &connectTestServer{t: t, polls: []string{
		`{"status":"approved","target":{"org_id":"org-9","slug":"acme","kind":"team","display_name":"Acme","share_level":"full"},` +
			`"consent_receipt_id":"rcpt-1","interval":3,"sign_in":{"api_token":"sbo_api_nested","account_id":"acct","device_id":"dev","thumbprint":"tp","expires_at":"2026-12-17T10:00:00Z"},` +
			`"attach_grant":"sbag1.payload.sig"}`,
	}}
	c, cred := newConnectTestClient(t, s)
	if _, err := c.CreateConnectRequest(context.Background(), ConnectRequestInput{}); err != nil {
		t.Fatal(err)
	}
	st, err := c.PollConnectRequest(context.Background(), "req-1")
	if err != nil || !st.SignedIn || st.AttachGrant != "sbag1.payload.sig" {
		t.Fatalf("approved = %+v, %v", st, err)
	}
	if tok, err := cred.LoadAPIToken(); err != nil || tok != "sbo_api_nested" {
		t.Fatalf("nested api token not stored: %q %v", tok, err)
	}
	if b, _ := json.Marshal(st); strings.Contains(string(b), "sbag1") {
		t.Fatalf("the grant serialized: %s", b)
	}
	agent := b64.EncodeToString(make([]byte, 32))
	p, err := c.AttachProof(st.AttachGrant, agent)
	if err != nil {
		t.Fatal(err)
	}
	claims := attachgrant.Claims{DeviceThumbprint: attachgrant.Thumbprint(c.DevicePublicKey())}
	if err := attachgrant.VerifyProof(claims, p, st.AttachGrant, agent); err != nil {
		t.Fatalf("the proof does not verify against this device key: %v", err)
	}
}

// TestConnectRequestGrantBesideNotNowIsDropped: a grant with no target has
// nowhere to attach and is not handed over.
func TestConnectRequestGrantBesideNotNowIsDropped(t *testing.T) {
	s := &connectTestServer{t: t, polls: []string{`{"status":"approved","target":null,"sign_in":{"api_token":"tok"},"attach_grant":"sbag1.x.y"}`}}
	c, _ := newConnectTestClient(t, s)
	if _, err := c.CreateConnectRequest(context.Background(), ConnectRequestInput{}); err != nil {
		t.Fatal(err)
	}
	st, err := c.PollConnectRequest(context.Background(), "req-1")
	if err != nil || !st.SignedIn || st.AttachGrant != "" {
		t.Fatalf("not now = %+v, %v", st, err)
	}
}
