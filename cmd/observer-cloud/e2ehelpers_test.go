package main

// Test helpers shared by the host API worker and tenant create end-to-end
// tests. They live apart from hostapiworker_e2e_test.go because that file
// imports the private org server and the public release drops it
// (scripts/release.sh PRIVATE_PACKAGE_IMPORT_RE sweep), while
// tenantcreate_e2e_test.go stays public and needs them.

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
)

// testClock is a settable clock shared by the worker, the signer and the
// host, so a test can move past a retry's backoff without sleeping.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// testPKI writes a platform CA, a host server certificate for 127.0.0.1 and
// a worker client certificate, and returns the file paths and the server's
// TLS configuration.
func testPKI(t *testing.T, dir string) (caFile, certFile, keyFile string, server *tls.Config) {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	caKey := newKey()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test platform CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, cn string, usage x509.ExtKeyUsage, ip net.IP) ([]byte, *ecdsa.PrivateKey) {
		k := newKey()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		}
		if ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, k
	}
	srvDER, srvKey := issue(2, "tenant host", x509.ExtKeyUsageServerAuth, net.ParseIP("127.0.0.1"))
	cliDER, cliKey := issue(3, "observer-cloud worker", x509.ExtKeyUsageClientAuth, nil)
	write := func(name string, blocks ...*pem.Block) string {
		var out []byte
		for _, b := range blocks {
			out = append(out, pem.EncodeToMemory(b)...)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, out, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cliKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile = write("ca.pem", &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certFile = write("client.pem", &pem.Block{Type: "CERTIFICATE", Bytes: cliDER})
	keyFile = write("client.key", &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	server = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12,
	}
	return caFile, certFile, keyFile, server
}

// startDocSigner runs the real document signer on a loopback listener (the
// peer-uid check is the injected allow; production uses SO_PEERCRED on a
// unix socket) and returns a client for it.
func startDocSigner(t *testing.T, dir string, clock *testClock, ent, avail, hostAPI ed25519.PrivateKey) *signerd.DocumentClient {
	t.Helper()
	state := filepath.Join(dir, "versions.json")
	if err := signerd.CreateVersionFile(state); err != nil {
		t.Fatal(err)
	}
	versions, err := signerd.OpenFileVersions(state)
	if err != nil {
		t.Fatal(err)
	}
	ds, err := signerd.NewDocumentSigner(signerd.DocumentKeys{
		Entitlements: []ed25519.PrivateKey{ent}, Availability: []ed25519.PrivateKey{avail}, HostAPI: []ed25519.PrivateKey{hostAPI},
	}, versions, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &signerd.DocumentServer{
		Signer: ds, AllowUID: 4242, PeerUID: func(net.Conn) (int, error) { return 4242, nil },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	go func() { _ = srv.Serve(ctx, ln) }()
	return &signerd.DocumentClient{Network: "tcp", Address: ln.Addr().String()}
}

type outboxRow struct {
	state, errClass string
}

func readOutbox(t *testing.T, pool *pgxpool.Pool, key string) outboxRow {
	t.Helper()
	var r outboxRow
	if err := pool.QueryRow(context.Background(),
		`SELECT state, coalesce(last_error_class, '') FROM org_outbox WHERE idempotency_key = $1`, key).Scan(&r.state, &r.errClass); err != nil {
		t.Fatalf("read outbox row %s: %v", key, err)
	}
	return r
}
