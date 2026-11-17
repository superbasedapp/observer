package oidctest

import (
	"context"
	"fmt"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
)

// MemSupport is the in-memory support seam (oidcissuer.SupportCodeStore and
// SupportTokenStore) over a MemStore: support codes live in the MemStore's
// own code map, so its ConsumeCode redeems them as the database's does.
type MemSupport struct {
	*MemStore
	mu      sync.Mutex
	staff   map[string]bool
	orgs    map[string]oidcissuer.SupportTarget
	issued  map[string]oidcissuer.SupportIssuance
	failRec error
}

// NewMemSupport returns a support seam over m.
func NewMemSupport(m *MemStore) *MemSupport {
	return &MemSupport{
		MemStore: m, staff: map[string]bool{}, orgs: map[string]oidcissuer.SupportTarget{},
		issued: map[string]oidcissuer.SupportIssuance{},
	}
}

// SetStaff marks a staff member active or not.
func (s *MemSupport) SetStaff(staffID string, active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.staff[staffID] = active
}

// SetOrg sets an org's status and platform rail.
func (s *MemSupport) SetOrg(orgID, status string, rail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgs[orgID] = oidcissuer.SupportTarget{OrgStatus: status, RailEnabled: rail}
}

// FailRecord makes RecordSupportIssuance fail with err.
func (s *MemSupport) FailRecord(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failRec = err
}

// SupportIssued returns the recorded support issuances.
func (s *MemSupport) SupportIssued() []oidcissuer.SupportIssuance {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]oidcissuer.SupportIssuance, 0, len(s.issued))
	for _, i := range s.issued {
		out = append(out, i)
	}
	return out
}

// PutSupportCode implements oidcissuer.SupportCodeStore.
func (s *MemSupport) PutSupportCode(ctx context.Context, c oidcissuer.CodeRecord) error {
	if !c.Support {
		return fmt.Errorf("oidctest: PutSupportCode given a member code")
	}
	return s.MemStore.PutCode(ctx, c)
}

// SupportTarget implements oidcissuer.SupportTokenStore.
func (s *MemSupport) SupportTarget(_ context.Context, staffID, orgID string) (oidcissuer.SupportTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.orgs[orgID]
	t.StaffActive = s.staff[staffID]
	return t, nil
}

// RecordSupportIssuance implements oidcissuer.SupportTokenStore.
func (s *MemSupport) RecordSupportIssuance(_ context.Context, iss oidcissuer.SupportIssuance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failRec != nil {
		return s.failRec
	}
	if _, dup := s.issued[iss.JTI]; dup {
		return fmt.Errorf("oidctest: support jti %s already issued", iss.JTI)
	}
	s.issued[iss.JTI] = iss
	return nil
}
