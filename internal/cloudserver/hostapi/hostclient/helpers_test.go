package hostclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net/http/httptest"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// helpers_test.go holds what every hostclient test shares: keys, the test
// clock, mTLS material, an in-memory outbox store and a scripted transport.
// The end-to-end test against the real host handler lives in e2e_test.go,
// which imports the private org server (dropped from the public tree by the
// release script's private-import sweep); nothing here does.

const (
	orgA = "aaaaaaaa-0000-4000-8000-000000000001"
	orgB = "bbbbbbbb-0000-4000-8000-000000000002"
)

// testNow is the fixed test clock.
var testNow = time.Unix(1_800_000_000, 0).UTC()

func fixedNow() time.Time { return testNow }

func key(seed string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(seed))
	return ed25519.NewKeyFromSeed(s[:])
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

var (
	requestKey  = key("control-plane-request")
	responseKey = key("host-response")
)

// allowLoopback lets the tests dial httptest servers on 127.0.0.1.
func allowLoopback(a netip.Addr) bool { return a.IsLoopback() }

// pki is a throwaway platform CA with one client certificate.
type pki struct {
	pool   *x509.CertPool
	caDER  []byte
	client tls.Certificate
}

func newPKI(t *testing.T) pki {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test platform CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cli := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "observer-cloud worker"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cli, caCert, &cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pki{pool: pool, caDER: caDER, client: tls.Certificate{Certificate: [][]byte{cliDER}, PrivateKey: cliKey}}
}

// startMTLS starts srv requiring a client certificate from p's CA, and
// returns the client TLS config that trusts the server.
func startMTLS(t *testing.T, srv *httptest.Server, p pki) *tls.Config {
	t.Helper()
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.pool, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{p.client}, MinVersion: tls.VersionTLS12}
}

// tlsConfigWith is a client config presenting p's client certificate.
func tlsConfigWith(p pki) *tls.Config {
	return &tls.Config{RootCAs: p.pool, Certificates: []tls.Certificate{p.client}, MinVersion: tls.VersionTLS12}
}

func newSender(t *testing.T, tc *tls.Config, mutate func(*hostclient.SenderConfig)) *hostclient.Sender {
	t.Helper()
	cfg := hostclient.SenderConfig{
		TLS: tc, Signer: hostclient.Ed25519Signer("cp-1", requestKey), Now: fixedNow,
		AllowAddress: allowLoopback, Timeout: 5 * time.Second,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := hostclient.NewSender(cfg)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	return s
}

func hostAt(url string) hostclient.Host {
	return hostclient.Host{ID: "host-1", BaseURL: url, ResponseKeys: map[string]ed25519.PublicKey{"host-r1": pub(responseKey)}}
}

func directory(t *testing.T, hosts ...hostclient.Host) *hostclient.StaticDirectory {
	t.Helper()
	d, err := hostclient.NewStaticDirectory(hosts, hosts[0].ID)
	if err != nil {
		t.Fatalf("NewStaticDirectory: %v", err)
	}
	return d
}

// memRow is one in-memory outbox row.
type memRow struct {
	store.ClaimedOrgIntent
	seq        int
	state      string
	nextAt     time.Time
	errClass   string
	hostState  string
	hostGen    int64
	leaseUntil time.Time
}

// memStore is an in-memory OutboxStore and ReconcileStore with the claim rule
// of the SQL seam (per-org order, due time, live lease). It is test scaffolding;
// the real claim's concurrency proof is the store's live test.
type memStore struct {
	mu        sync.Mutex
	rows      []*memRow
	orgs      map[string]*store.OrgReconcileView
	findings  map[string][]store.OrgReconcileFinding // org -> open findings
	lease     int
	recordErr error
	applied   []store.OrgReconcileUpdate
}

func newMemStore() *memStore {
	return &memStore{orgs: map[string]*store.OrgReconcileView{}, findings: map[string][]store.OrgReconcileFinding{}}
}

func (m *memStore) addOrg(v store.OrgReconcileView) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := v
	m.orgs[v.OrgID] = &cp
}

// enqueue mirrors EnqueueOrgIntentTx: idempotent on the key.
func (m *memStore) enqueue(in hostapi.Intent) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enqueueLocked(store.OrgIntent{
		OrgID: in.OrgID, Verb: store.OrgOutboxVerb(in.Verb), IdempotencyKey: in.IdempotencyKey,
		LifecycleGen: in.LifecycleGen, Payload: in.Payload,
	})
}

func (m *memStore) enqueueLocked(in store.OrgIntent) bool {
	for _, r := range m.rows {
		if r.IdempotencyKey == in.IdempotencyKey {
			return false
		}
	}
	m.rows = append(m.rows, &memRow{
		ClaimedOrgIntent: store.ClaimedOrgIntent{
			OutboxID: in.IdempotencyKey, OrgID: in.OrgID, Verb: in.Verb, IdempotencyKey: in.IdempotencyKey,
			LifecycleGen: in.LifecycleGen, Payload: in.Payload,
		},
		seq: len(m.rows) + 1, state: "pending", nextAt: testNow.Add(-time.Second),
	})
	return true
}

func (m *memStore) row(key string) memRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.IdempotencyKey == key {
			return *r
		}
	}
	return memRow{}
}

// due puts a row back to pending and due now (a lost ack, a requeue).
func (m *memStore) due(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.IdempotencyKey == key {
			r.state, r.nextAt, r.leaseUntil, r.LeaseToken = "pending", testNow.Add(-time.Second), time.Time{}, ""
		}
	}
}

func open(state string) bool { return state == "pending" || state == "sent" }

func (m *memStore) ClaimOrgOutbox(_ context.Context, c store.OrgOutboxClaim) ([]store.ClaimedOrgIntent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.ClaimedOrgIntent
	for _, r := range m.rows {
		if len(out) == c.Limit {
			break
		}
		if !open(r.state) || r.nextAt.After(c.Now) || r.leaseUntil.After(c.Now) || m.olderOpenLocked(r) {
			continue
		}
		m.lease++
		r.state, r.Attempts, r.LeaseToken = "sent", r.Attempts+1, fmt.Sprintf("lease-%d", m.lease)
		r.leaseUntil = c.Now.Add(c.LeaseTTL)
		if v, ok := m.orgs[r.OrgID]; ok {
			r.HostID = v.HostID
		}
		out = append(out, r.ClaimedOrgIntent)
	}
	return out, nil
}

func (m *memStore) olderOpenLocked(r *memRow) bool {
	for _, e := range m.rows {
		if e.OrgID == r.OrgID && e.seq < r.seq && open(e.state) {
			return true
		}
	}
	return false
}

func (m *memStore) AssignOrgHost(_ context.Context, orgID, hostID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.orgs[orgID]
	if !ok {
		return "", store.ErrNotFound
	}
	if v.HostID == "" {
		v.HostID = hostID
	}
	return v.HostID, nil
}

func (m *memStore) RecordOrgOutboxOutcome(_ context.Context, o store.OrgOutboxOutcome) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recordErr != nil {
		return m.recordErr
	}
	for _, r := range m.rows {
		if r.OutboxID != o.OutboxID || r.LeaseToken != o.LeaseToken || r.state != "sent" {
			continue
		}
		r.LeaseToken, r.leaseUntil = "", time.Time{}
		switch o.Result {
		case store.OutboxResultAcked:
			r.state, r.errClass, r.hostState, r.hostGen = "acked", "", o.HostState, o.HostGen
			if v, ok := m.orgs[r.OrgID]; ok && o.AdoptCreate && o.HostState != "" && v.Status == string(pc.StateProvisioning) {
				v.Status, v.LifecycleGen = o.HostState, max(v.LifecycleGen, o.HostGen)
			}
		case store.OutboxResultRetry:
			r.state, r.nextAt, r.errClass = "pending", o.NextAttemptAt, o.ErrorClass
		default:
			r.state, r.errClass = "failed", o.ErrorClass
		}
		return nil
	}
	return store.ErrOrgOutboxLeaseLost
}

func (m *memStore) ListOrgsForReconcile(_ context.Context, after string, limit int) ([]store.OrgReconcileView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.orgs))
	for id := range m.orgs {
		if id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var out []store.OrgReconcileView
	for _, id := range ids {
		if len(out) == limit {
			break
		}
		v := *m.orgs[id]
		v.OpenIntent = false
		for _, r := range m.rows {
			v.OpenIntent = v.OpenIntent || (r.OrgID == id && open(r.state))
		}
		out = append(out, v)
	}
	return out, nil
}

func (m *memStore) ApplyOrgReconcile(_ context.Context, u store.OrgReconcileUpdate) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applied = append(m.applied, u)
	enq := false
	if u.Correction != nil {
		enq = m.enqueueLocked(*u.Correction)
	}
	m.findings[u.OrgID] = u.Findings
	return enq, nil
}

// scripted is a Transport that answers from a function and records requests.
type scripted struct {
	mu     sync.Mutex
	answer func(h hostclient.Host, r hostapi.Request) hostapi.Answer
	sent   []hostapi.Request
}

func (s *scripted) Send(_ context.Context, h hostclient.Host, r hostapi.Request) hostapi.Answer {
	s.mu.Lock()
	s.sent = append(s.sent, r)
	s.mu.Unlock()
	return s.answer(h, r)
}

func (s *scripted) requests() []hostapi.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]hostapi.Request(nil), s.sent...)
}

// resolver is a CreateResolver with a fixed answer.
type resolver struct{ err error }

func (r resolver) ResolveCreate(context.Context, string) (hostapi.CreateExtras, error) {
	if r.err != nil {
		return hostapi.CreateExtras{}, r.err
	}
	return hostapi.CreateExtras{
		OwnerSub: "user_owner", OwnerEmail: "owner@example.test",
		Entitlements: pc.EntitlementDocument{Version: 1, Body: []byte("doc"), Signature: []byte("sig"), KeyID: "ent-1"},
	}, nil
}

var errBoom = errors.New("boom")

// must unwraps an intent constructor's result: must(t)(hostapi.EvictIntent(...)).
func must(t *testing.T) func(hostapi.Intent, error) hostapi.Intent {
	return func(in hostapi.Intent, err error) hostapi.Intent {
		t.Helper()
		if err != nil {
			t.Fatalf("intent: %v", err)
		}
		return in
	}
}
