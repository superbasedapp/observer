package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// memStaffStore is an in-memory staffStore for the HTTP-layer tests that
// run without Postgres. It mirrors the store's rules that the routes depend
// on (single-use ceremonies and codes, the conditional counter update,
// revocation of the prior session); the store's own tests (store/staff_test.go)
// prove the real thing against Postgres.
type memStaffStore struct {
	mu          sync.Mutex
	users       map[string]store.StaffUser
	enrolments  map[string]*memEnrolment
	ceremonies  map[string]*memCeremony
	credentials map[string]*memCredential
	sessions    map[string]*memSession
	actions     []store.StaffAction
	inputs      map[string]store.AvailabilityInputRow
}

type memEnrolment struct {
	staffID string
	expires time.Time
	used    bool
}

type memCeremony struct {
	c        store.StaffCeremony
	expires  time.Time
	consumed bool
}

type memCredential struct {
	staffID string
	cred    staffauth.StoredCredential
	revoked bool
}

type memSession struct {
	p       store.StaffPrincipal
	revoked bool
}

func newMemStaffStore() *memStaffStore {
	return &memStaffStore{
		users: map[string]store.StaffUser{}, enrolments: map[string]*memEnrolment{},
		ceremonies: map[string]*memCeremony{}, credentials: map[string]*memCredential{},
		sessions: map[string]*memSession{}, inputs: map[string]store.AvailabilityInputRow{},
	}
}

func memHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// addStaff creates a staff member and returns a raw enrolment code for it.
func (m *memStaffStore) addStaff(id string, role staffauth.Role, code string, expires time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[id] = store.StaffUser{StaffID: id, DisplayName: "Staff " + id[:4], Role: role, Status: "active"}
	m.enrolments[memHash(code)] = &memEnrolment{staffID: id, expires: expires}
}

func (m *memStaffStore) log(actor string, verb staffauth.Verb, target, reason, result string, at time.Time) {
	m.actions = append(m.actions, store.StaffAction{At: at, Actor: actor, Verb: string(verb), Target: target, Reason: reason, Result: result})
}

// passkeyCapRefused mirrors the store's cap (staffPasskeyCapTx): at
// staffauth.MaxActivePasskeys unrevoked passkeys it logs a refused
// credential.registered row and reports true. The caller holds m.mu.
func (m *memStaffStore) passkeyCapRefused(staffID string, now time.Time) bool {
	active := 0
	for _, c := range m.credentials {
		if c.staffID == staffID && !c.revoked {
			active++
		}
	}
	if staffauth.CheckPasskeyCap(active) == nil {
		return false
	}
	m.log(staffauth.Actor(staffID), staffauth.VerbCredentialRegistered, "passkey-limit", "passkey registration refused", "refused", now)
	return true
}

func (m *memStaffStore) BeginStaffRegistration(_ context.Context, rawCode, rawCeremony string, challenge []byte, now time.Time) (store.StaffRegistrationStart, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.enrolments[memHash(rawCode)]
	if !ok || e.used || !e.expires.After(now) || m.users[e.staffID].Status != "active" {
		return store.StaffRegistrationStart{}, store.ErrStaffEnrolmentInvalid
	}
	if m.passkeyCapRefused(e.staffID, now) {
		return store.StaffRegistrationStart{}, staffauth.ErrPasskeyLimit
	}
	m.ceremonies[memHash(rawCeremony)] = &memCeremony{
		c:       store.StaffCeremony{Kind: store.StaffCeremonyRegister, Challenge: challenge, StaffID: e.staffID, EnrolmentHash: memHash(rawCode)},
		expires: now.Add(store.StaffCeremonyTTL),
	}
	return store.StaffRegistrationStart{Staff: m.users[e.staffID], ExistingCredentialIDs: [][]byte{}}, nil
}

func (m *memStaffStore) BeginStaffAssertion(_ context.Context, rawCeremony string, challenge []byte, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ceremonies[memHash(rawCeremony)] = &memCeremony{
		c: store.StaffCeremony{Kind: store.StaffCeremonyAssert, Challenge: challenge}, expires: now.Add(store.StaffCeremonyTTL),
	}
	return nil
}

func (m *memStaffStore) ConsumeStaffCeremony(_ context.Context, rawCeremony string, kind store.StaffCeremonyKind, now time.Time) (store.StaffCeremony, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.ceremonies[memHash(rawCeremony)]
	if !ok || c.consumed || c.c.Kind != kind || !c.expires.After(now) {
		return store.StaffCeremony{}, store.ErrStaffCeremonyInvalid
	}
	c.consumed = true
	return c.c, nil
}

func (m *memStaffStore) RegisterStaffCredential(_ context.Context, c store.StaffCeremony, cred staffauth.NewCredential, _ string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.enrolments[c.EnrolmentHash]
	if !ok || e.used || !e.expires.After(now) || e.staffID != c.StaffID {
		return store.ErrStaffEnrolmentInvalid
	}
	if m.passkeyCapRefused(c.StaffID, now) {
		return staffauth.ErrPasskeyLimit
	}
	if _, dup := m.credentials[string(cred.ID)]; dup {
		return store.ErrStaffCredentialExists
	}
	e.used = true
	stored := staffauth.StoredCredential{
		ID: cred.ID, PublicKey: cred.PublicKey, SignCount: cred.SignCount, UserHandle: store.StaffUserHandle(c.StaffID),
	}
	m.credentials[string(cred.ID)] = &memCredential{staffID: c.StaffID, cred: stored}
	m.log(staffauth.Actor(c.StaffID), staffauth.VerbCredentialRegistered, "", "registered", "ok", now)
	return nil
}

func (m *memStaffStore) StaffCredentialForAssertion(_ context.Context, id []byte) (staffauth.StoredCredential, store.StaffUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.credentials[string(id)]
	if !ok || c.revoked || m.users[c.staffID].Status != "active" {
		return staffauth.StoredCredential{}, store.StaffUser{}, store.ErrNotFound
	}
	return c.cred, m.users[c.staffID], nil
}

func (m *memStaffStore) StartStaffSession(_ context.Context, in store.StartStaffSessionInput) (store.StaffSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.credentials[string(in.CredentialID)]
	if !ok || c.revoked || c.staffID != in.StaffID || c.cred.SignCount != in.StoredSignCount {
		return store.StaffSession{}, store.ErrStaffCredentialStale
	}
	c.cred.SignCount = in.NewSignCount
	if s, ok := m.sessions[memHash(in.PriorRawSession)]; ok {
		s.revoked = true
	}
	raw := hex.EncodeToString(bytes.Repeat([]byte{byte(len(m.sessions) + 1)}, 16)) + "-" + in.StaffID[:8]
	csrf := "csrf-" + raw
	u := m.users[in.StaffID]
	expires := in.Now.Add(in.TTL)
	principal := store.StaffPrincipal{
		StaffID: u.StaffID, DisplayName: u.DisplayName, Role: u.Role, CSRFHash: memHash(csrf),
		AssertedAt: in.Now, ExpiresAt: expires,
	}
	m.sessions[memHash(raw)] = &memSession{p: principal}
	m.log(staffauth.Actor(in.StaffID), staffauth.VerbSessionStarted, "", "assertion", "ok", in.Now)
	return store.StaffSession{StaffID: u.StaffID, Role: u.Role, RawSession: raw, RawCSRF: csrf, ExpiresAt: expires}, nil
}

func (m *memStaffStore) IntrospectStaffSession(_ context.Context, raw string, now time.Time, _ time.Duration) (store.StaffPrincipal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[memHash(raw)]
	if !ok || s.revoked || !s.p.ExpiresAt.After(now) {
		return store.StaffPrincipal{}, store.ErrStaffSessionInvalid
	}
	return s.p, nil
}

func (m *memStaffStore) EndStaffSession(_ context.Context, staffID, raw string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[memHash(raw)]
	if !ok || s.revoked || s.p.StaffID != staffID {
		return store.ErrStaffSessionInvalid
	}
	s.revoked = true
	m.log(staffauth.Actor(staffID), staffauth.VerbSessionEnded, "", "signed out", "ok", now)
	return nil
}

func (m *memStaffStore) RecordStaffRefusal(_ context.Context, staffID string, action staffauth.Action, code string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.log(staffauth.Actor(staffID), staffauth.VerbActionRefused, string(action), code, "refused", now)
	return nil
}

func (m *memStaffStore) ListStaffActions(context.Context, int) ([]store.StaffAction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.StaffAction{}, m.actions...), nil
}

func (m *memStaffStore) ListAvailabilityInputs(context.Context) ([]store.AvailabilityInputRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []store.AvailabilityInputRow{}
	for _, r := range m.inputs {
		out = append(out, r)
	}
	return out, nil
}

func (m *memStaffStore) SetAvailabilityInput(_ context.Context, staffID string, in staffauth.AvailabilityInput, reason string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inputs[string(in.Section)+"/"+in.Key] = store.AvailabilityInputRow{
		Section: string(in.Section), Key: in.Key, Value: json.RawMessage(in.Value), Reason: reason, Author: staffauth.Actor(staffID), UpdatedAt: now,
	}
	m.log(staffauth.Actor(staffID), staffauth.VerbAvailabilitySet, string(in.Section)+"/"+in.Key, reason, "ok", now)
	return nil
}

func (m *memStaffStore) DeleteAvailabilityInput(_ context.Context, staffID string, section staffauth.Section, key, reason string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := string(section) + "/" + key
	if _, ok := m.inputs[k]; !ok {
		return store.ErrNotFound
	}
	delete(m.inputs, k)
	m.log(staffauth.Actor(staffID), staffauth.VerbAvailabilityDeleted, k, reason, "ok", now)
	return nil
}
