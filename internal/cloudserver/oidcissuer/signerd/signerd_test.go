package signerd_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
)

const (
	testIssuer = "https://app.example/oauth2"
	org        = "0b5c3f1e-2d4a-4c6b-9e8f-1a2b3c4d5e6f"
	serveUID   = 1001
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// serve starts a signer over a loopback TCP listener whose every peer
// reports peerUID (SO_PEERCRED is Linux-only; peercred_linux_test.go proves
// the real check). It returns a client for it.
func serve(t *testing.T, key *rsa.PrivateKey, now func() time.Time, peerUID int) *signerd.Client {
	t.Helper()
	local, err := oidcissuer.NewLocalSigner(testIssuer, []*rsa.PrivateKey{key}, now)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := &signerd.Server{
		Signer: local, AllowUID: serveUID, Logger: quiet(),
		PeerUID: func(net.Conn) (int, error) { return peerUID, nil },
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return &signerd.Client{Network: "tcp", Address: ln.Addr().String()}
}

func goodClaims(now time.Time) oidcissuer.Claims {
	return oidcissuer.Claims{
		Iss: testIssuer, Sub: "user_alice", Aud: "org:" + org, Iat: now.Unix(), Exp: now.Unix() + 300, AuthTime: now.Unix() - 60,
		Jti: strings.Repeat("j", 32), Nonce: "n", Org: org, Email: "alice@example.com", EmailVerified: true,
	}
}

func TestSignerProtocolSignsAndRefuses(t *testing.T) {
	t.Parallel()
	clock := oidctest.NewClock(time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC))
	key := oidctest.NewKey(t)
	c := serve(t, key, clock.Now, serveUID)
	ctx := context.Background()

	keys, err := c.PublicKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].KID != oidcissuer.Thumbprint(&key.PublicKey) {
		t.Fatalf("PublicKeys = %+v, %v", keys, err)
	}
	tok, err := c.Sign(ctx, keys[0].KID, goodClaims(clock.Now()))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got, err := oidcissuer.VerifyRS256(tok, keys[0].JWK); err != nil || got.Org != org {
		t.Fatalf("signed token does not verify: %v", err)
	}

	for name, mutate := range map[string]func(*oidcissuer.Claims){
		"foreign issuer":     func(c *oidcissuer.Claims) { c.Iss = "https://evil.example/oauth2" },
		"wrong audience":     func(c *oidcissuer.Claims) { c.Aud = "org:1c6d4f2a-3e5b-4d7c-8f9a-2b3c4d5e6f70" },
		"six-minute token":   func(c *oidcissuer.Claims) { c.Exp = c.Iat + 360 },
		"no jti":             func(c *oidcissuer.Claims) { c.Jti = "" },
		"stale iat":          func(c *oidcissuer.Claims) { c.Iat -= 600; c.Exp = c.Iat + 300 },
		"unverified email":   func(c *oidcissuer.Claims) { c.EmailVerified = false },
		"exp before iat":     func(c *oidcissuer.Claims) { c.Exp = c.Iat - 1 },
		"non-uuid org claim": func(c *oidcissuer.Claims) { c.Org, c.Aud = "acme", "org:acme" },
	} {
		claims := goodClaims(clock.Now())
		mutate(&claims)
		if _, err := c.Sign(ctx, keys[0].KID, claims); !errors.Is(err, oidcissuer.ErrClaimsRefused) {
			t.Errorf("%s: Sign = %v, want ErrClaimsRefused", name, err)
		}
	}
	if _, err := c.Sign(ctx, "some-other-kid", goodClaims(clock.Now())); !errors.Is(err, oidcissuer.ErrClaimsRefused) {
		t.Errorf("unheld kid: %v", err)
	}
}

// raw sends one raw line and returns the raw response line.
func raw(t *testing.T, addr, line string) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return strings.TrimSpace(resp)
}

func TestSignerProtocolRejectsMalformedRequests(t *testing.T) {
	t.Parallel()
	clock := oidctest.NewClock(time.Now().UTC())
	key := oidctest.NewKey(t)
	c := serve(t, key, clock.Now, serveUID)
	kid := oidcissuer.Thumbprint(&key.PublicKey)
	cases := map[string]string{
		"unknown claim": `{"v":1,"op":"sign","kid":"` + kid + `","claims":{"iss":"` + testIssuer + `","admin":true}}`,
		"unknown field": `{"v":1,"op":"keys","alg":"none"}`,
		"wrong version": `{"v":2,"op":"keys"}`,
		"unknown op":    `{"v":1,"op":"decrypt"}`,
		"no claims":     `{"v":1,"op":"sign","kid":"` + kid + `"}`,
		"not json":      `sign please`,
		"two objects":   `{"v":1,"op":"keys"}{"v":1,"op":"keys"}`,
	}
	for name, line := range cases {
		if got := raw(t, c.Address, line); got != `{"v":1,"error":"bad_request"}` {
			t.Errorf("%s: response %s, want bad_request", name, got)
		}
	}
	// An oversized request is refused: answered bad_request, or (when the
	// unread tail resets the connection first) not answered at all.
	if got, err := rawMaybe(c.Address, strings.Repeat("x", 70<<10)); err == nil && got != `{"v":1,"error":"bad_request"}` {
		t.Errorf("oversized: %s", got)
	}
}

// rawMaybe is raw without failing the test on a connection error.
func rawMaybe(addr, line string) (string, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(line + "\n")); err != nil {
		return "", err
	}
	resp, err := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSpace(resp), err
}

func TestSignerRefusesOtherPeers(t *testing.T) {
	t.Parallel()
	clock := oidctest.NewClock(time.Now().UTC())
	key := oidctest.NewKey(t)
	c := serve(t, key, clock.Now, serveUID+1)
	if _, err := c.PublicKeys(context.Background()); !errors.Is(err, signerd.ErrPeerRefused) {
		t.Fatalf("PublicKeys from a foreign uid = %v, want ErrPeerRefused", err)
	}
	if _, err := c.Sign(context.Background(), oidcissuer.Thumbprint(&key.PublicKey), goodClaims(clock.Now())); !errors.Is(err, signerd.ErrPeerRefused) {
		t.Fatalf("Sign from a foreign uid = %v, want ErrPeerRefused", err)
	}
}

func TestSignerOutageIsAnError(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	c := &signerd.Client{Network: "tcp", Address: addr, Timeout: time.Second}
	if _, err := c.PublicKeys(context.Background()); err == nil {
		t.Fatal("a dead signer answered")
	}
}

func writePEM(t *testing.T, dir, name, typ string, der []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadPrivateKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key := oidctest.NewKey(t)
	p8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		writePEM(t, dir, "pkcs8.pem", "PRIVATE KEY", p8, 0o600),
		writePEM(t, dir, "pkcs1.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), 0o600),
	} {
		got, err := signerd.LoadPrivateKey(p)
		if err != nil || got.N.Cmp(key.N) != 0 {
			t.Errorf("LoadPrivateKey(%s) = %v", filepath.Base(p), err)
		}
	}
	small, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signerd.LoadPrivateKey(writePEM(t, dir, "small.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(small), 0o600)); err == nil {
		t.Error("a 2048-bit key was loaded")
	}
	if _, err := signerd.LoadPrivateKey(writePEM(t, dir, "enc.pem", "ENCRYPTED PRIVATE KEY", []byte("x"), 0o600)); err == nil {
		t.Error("an encrypted PEM was loaded")
	}
	if runtime.GOOS != "windows" {
		if _, err := signerd.LoadPrivateKey(writePEM(t, dir, "open.pem", "PRIVATE KEY", p8, 0o644)); err == nil {
			t.Error("a world-readable key was loaded")
		}
	}

	out := filepath.Join(dir, "gen.pem")
	jwk, err := signerd.GenerateKeyFile(out)
	if err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	got, err := signerd.LoadPrivateKey(out)
	if err != nil || oidcissuer.Thumbprint(&got.PublicKey) != jwk.Kid {
		t.Fatalf("generated key reloads as %v", err)
	}
	if _, err := signerd.GenerateKeyFile(out); err == nil {
		t.Error("GenerateKeyFile overwrote an existing key")
	}
}

func TestCredentialKeyPathRefusesTraversal(t *testing.T) {
	t.Parallel()
	if got := signerd.CredentialKeyPath(t.TempDir(), "../x"); got != "" {
		t.Errorf("CredentialKeyPath(../x) = %q", got)
	}
}
