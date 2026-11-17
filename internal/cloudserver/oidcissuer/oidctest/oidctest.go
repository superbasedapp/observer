package oidctest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
)

// MemStore is an in-memory oidcissuer.Store. Two Issuers sharing one MemStore
// behave like two replicas sharing one database: no state is in an Issuer.
type MemStore struct {
	mu        sync.Mutex
	clients   map[string]oidcissuer.Client
	members   map[string]oidcissuer.Member // key accountID|orgID
	codes     map[string]*memCode
	keys      map[string]oidcissuer.SigningKey
	issued    map[string]oidcissuer.Issuance
	mirrors   map[string][]byte
	subSeen   map[string]time.Time // key orgID|sub
	failIssue error
	failStore error
}

type memCode struct {
	rec      oidcissuer.CodeRecord
	consumed bool
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{
		clients: map[string]oidcissuer.Client{}, members: map[string]oidcissuer.Member{},
		codes: map[string]*memCode{}, keys: map[string]oidcissuer.SigningKey{},
		issued: map[string]oidcissuer.Issuance{}, mirrors: map[string][]byte{}, subSeen: map[string]time.Time{},
	}
}

// AddClient registers c.
func (m *MemStore) AddClient(c oidcissuer.Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[c.ClientID] = c
}

// SetMember records what Member returns for (accountID, orgID).
func (m *MemStore) SetMember(accountID, orgID string, mem oidcissuer.Member) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.members[accountID+"|"+orgID] = mem
}

// SetKey stores (or replaces) a signing key row.
func (m *MemStore) SetKey(k oidcissuer.SigningKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[k.KID] = k
}

// FailRecordIssuance makes RecordIssuance fail with err (nil to clear),
// standing in for a failed audit-mirror insert.
func (m *MemStore) FailRecordIssuance(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failIssue = err
}

// FailAll makes every method fail with err (nil to clear): a database outage.
func (m *MemStore) FailAll(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failStore = err
}

// Issued returns the recorded issuances, ordered by jti.
func (m *MemStore) Issued() []oidcissuer.Issuance {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]oidcissuer.Issuance, 0, len(m.issued))
	for _, v := range m.issued {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JTI < out[j].JTI })
	return out
}

// Mirror returns the audit-mirror payload recorded for jti.
func (m *MemStore) Mirror(jti string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.mirrors[jti]
	return b, ok
}

// SubSeen reports whether (orgID, sub) was recorded.
func (m *MemStore) SubSeen(orgID, sub string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.subSeen[orgID+"|"+sub]
	return ok
}

// Codes returns the number of stored codes.
func (m *MemStore) Codes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.codes)
}

// Client implements oidcissuer.Store.
func (m *MemStore) Client(_ context.Context, id string) (oidcissuer.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return oidcissuer.Client{}, m.failStore
	}
	c, ok := m.clients[id]
	if !ok {
		return oidcissuer.Client{}, oidcissuer.ErrNotFound
	}
	return c, nil
}

// Member implements oidcissuer.Store.
func (m *MemStore) Member(_ context.Context, accountID, orgID string) (oidcissuer.Member, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return oidcissuer.Member{}, m.failStore
	}
	return m.members[accountID+"|"+orgID], nil
}

// PutCode implements oidcissuer.Store.
func (m *MemStore) PutCode(_ context.Context, c oidcissuer.CodeRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return m.failStore
	}
	if _, dup := m.codes[c.CodeHash]; dup {
		return errors.New("oidctest: duplicate code")
	}
	m.codes[c.CodeHash] = &memCode{rec: c}
	return nil
}

// ConsumeCode implements oidcissuer.Store with the database's conditional
// update: unknown, consumed or expired is ErrNotFound, and a consumed code
// stays consumed.
func (m *MemStore) ConsumeCode(_ context.Context, hash string, now time.Time) (oidcissuer.CodeRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return oidcissuer.CodeRecord{}, m.failStore
	}
	c, ok := m.codes[hash]
	if !ok || c.consumed || !now.Before(c.rec.ExpiresAt) {
		return oidcissuer.CodeRecord{}, oidcissuer.ErrNotFound
	}
	c.consumed = true
	return c.rec, nil
}

// SigningKeys implements oidcissuer.Store.
func (m *MemStore) SigningKeys(context.Context) ([]oidcissuer.SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return nil, m.failStore
	}
	out := make([]oidcissuer.SigningKey, 0, len(m.keys))
	for _, k := range m.keys {
		if k.Status != oidcissuer.KeyRetired {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KID < out[j].KID })
	return out, nil
}

// StageSigningKeys implements oidcissuer.Store.
func (m *MemStore) StageSigningKeys(_ context.Context, vmID string, keys []oidcissuer.PublicKey, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return m.failStore
	}
	for _, k := range keys {
		if _, ok := m.keys[k.KID]; ok {
			continue
		}
		m.keys[k.KID] = oidcissuer.SigningKey{KID: k.KID, Alg: oidcissuer.AlgRS256, JWK: k.JWK, VMID: vmID, Status: oidcissuer.KeyStaged}
	}
	return nil
}

// RecordIssuance implements oidcissuer.Store: the issued row, the sub-seen
// row and the mirror row all land, or none does.
func (m *MemStore) RecordIssuance(_ context.Context, iss oidcissuer.Issuance) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failStore != nil {
		return m.failStore
	}
	if m.failIssue != nil {
		return m.failIssue
	}
	if _, dup := m.issued[iss.JTI]; dup {
		return fmt.Errorf("oidctest: jti %s already issued", iss.JTI)
	}
	m.issued[iss.JTI] = iss
	m.mirrors[iss.JTI] = append([]byte(nil), iss.MirrorPayload...)
	m.subSeen[iss.OrgID+"|"+iss.Sub] = iss.IssuedAt
	return nil
}

// NewKey generates an RSA key of oidcissuer.MinRSABits bits.
func NewKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, oidcissuer.MinRSABits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

// ActiveKey returns the active signing-key row for key, published and usable
// since notBefore.
func ActiveKey(key *rsa.PrivateKey, vmID string, notBefore time.Time) oidcissuer.SigningKey {
	jwk := oidcissuer.PublicJWK(&key.PublicKey)
	return oidcissuer.SigningKey{KID: jwk.Kid, Alg: oidcissuer.AlgRS256, JWK: jwk, VMID: vmID, Status: oidcissuer.KeyActive, NotBefore: notBefore}
}

// Clock is a settable test clock.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock returns a clock at t.
func NewClock(t time.Time) *Clock { return &Clock{t: t} }

// Now returns the clock's time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}
